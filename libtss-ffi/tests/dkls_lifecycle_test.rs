//! FFI-level tests for DKLs23 complete refresh (tss_refresh_new_dkls) and key
//! import (tss_dkls_split_key).

mod common;

use common::*;
use libtss_ffi::handles::{tss_handle_group_key, tss_handle_verifying_share};
use libtss_ffi::memory::tss_handle_free;
use libtss_ffi::session::{tss_refresh_new_dkls, tss_refresh_next, tss_session_free};
use libtss_ffi::types::*;

const SUITE_SECP256R1_ECDSA: u8 = 7;

fn group_key(handle: TssHandle) -> Vec<u8> {
    let mut out = TssBuffer::empty();
    assert_eq!(tss_handle_group_key(handle, &mut out), TSS_OK);
    take_buffer(&mut out)
}

fn verifying_share(handle: TssHandle) -> Vec<u8> {
    let mut out = TssBuffer::empty();
    assert_eq!(tss_handle_verifying_share(handle, &mut out), TSS_OK);
    take_buffer(&mut out)
}

fn refresh(keys: &[TssHandle], session_id: &[u8]) -> Vec<TssHandle> {
    let n = keys.len();
    let mut sessions = Vec::new();
    let mut pending = Vec::new();
    for key in keys {
        let mut session = 0;
        let mut messages = TssBuffer::empty();
        assert_eq!(
            tss_refresh_new_dkls(
                *key,
                session_id.as_ptr(),
                session_id.len(),
                &mut session,
                &mut messages
            ),
            TSS_OK
        );
        sessions.push(session);
        pending.push(take_buffer(&mut messages));
    }

    let mut refreshed = vec![0; n];
    for _ in 0..3 {
        let routed = route_messages(&pending, n);
        pending = vec![Vec::new(); n];
        for (i, session) in sessions.iter().enumerate() {
            let mut key = 0;
            let mut package = TssBuffer::empty();
            let mut messages = TssBuffer::empty();
            let mut complete = false;
            assert_eq!(
                tss_refresh_next(
                    *session,
                    slice(&routed[i]),
                    &mut key,
                    &mut package,
                    &mut messages,
                    &mut complete
                ),
                TSS_OK
            );
            if complete {
                refreshed[i] = key;
                let _ = take_buffer(&mut package);
            }
            pending[i] = take_buffer(&mut messages);
        }
    }
    for session in sessions {
        tss_session_free(session);
    }
    assert!(
        refreshed.iter().all(|&key| key != 0),
        "refresh did not complete"
    );
    refreshed
}

#[test]
fn dkls_refresh_keeps_key_and_signs() {
    for suite in [SUITE_SECP256K1_ECDSA, SUITE_SECP256R1_ECDSA] {
        let keys = run_dkg(suite, 3, 2);
        let refreshed = refresh(&keys, b"ffi-refresh-1");
        for (old, new) in keys.iter().zip(&refreshed) {
            assert_eq!(group_key(*old), group_key(*new));
            assert_ne!(verifying_share(*old), verifying_share(*new));
        }
        let signature = run_dkls_sign(&refreshed[..2], &[3u8; 32]);
        assert_eq!(signature.len(), 64);
        for key in keys.into_iter().chain(refreshed) {
            tss_handle_free(key);
        }
    }
}

#[test]
fn dkls_refresh_requires_session_id() {
    let keys = run_dkg(SUITE_SECP256K1_ECDSA, 2, 2);
    let mut session = 0;
    let mut messages = TssBuffer::empty();
    assert_eq!(
        tss_refresh_new_dkls(keys[0], std::ptr::null(), 0, &mut session, &mut messages),
        TSS_ERR_INVALID_CONFIG
    );
    for key in keys {
        tss_handle_free(key);
    }
}

fn split(suite: u8, secret: &[u8], chain_code: &[u8]) -> Result<Vec<TssHandle>, TssStatus> {
    let mut handles = [0u64; 3];
    let mut count = 0usize;
    let mut package = TssBuffer::empty();
    let status = libtss_ffi::dkls_ops::tss_dkls_split_key(
        suite,
        slice(secret),
        slice(chain_code),
        3,
        2,
        handles.as_mut_ptr(),
        &mut count,
        &mut package,
    );
    if status != TSS_OK {
        return Err(status);
    }
    let _ = take_buffer(&mut package);
    Ok(handles[..count].to_vec())
}

#[test]
fn dkls_split_key_imports_refreshes_and_signs() {
    for suite in [SUITE_SECP256K1_ECDSA, SUITE_SECP256R1_ECDSA] {
        let keys = split(suite, &[0x42; 32], &[0x17; 32]).unwrap();
        assert_eq!(keys.len(), 3);
        let refreshed = refresh(&keys, b"ffi-after-import");
        assert_eq!(group_key(keys[0]), group_key(refreshed[0]));
        assert_eq!(run_dkls_sign(&refreshed[..2], &[4u8; 32]).len(), 64);
        for key in keys.into_iter().chain(refreshed) {
            tss_handle_free(key);
        }
    }
}

#[test]
fn dkls_split_key_rejects_invalid_input() {
    assert_eq!(
        split(SUITE_SECP256K1_ECDSA, &[0; 32], &[]).unwrap_err(),
        TSS_ERR_INVALID_CONFIG
    );
    assert_eq!(
        split(SUITE_SECP256K1_ECDSA, &[1; 32], &[0; 31]).unwrap_err(),
        TSS_ERR_INVALID_CONFIG
    );
    assert_eq!(
        split(SUITE_ED25519, &[1; 32], &[]).unwrap_err(),
        TSS_ERR_PROTO_MISMATCH
    );
}
