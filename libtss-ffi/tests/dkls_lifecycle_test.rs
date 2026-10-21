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

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

// BOLT 3, Appendix E: Key Derivation Test Vectors.
const BOLT3_BASE_SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const BOLT3_PER_COMMITMENT_SECRET: &str =
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
const BOLT3_PER_COMMITMENT_POINT: &str =
    "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486";
const BOLT3_LOCAL_PUBLIC_KEY: &str =
    "0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5";
const BOLT3_REVOCATION_PUBLIC_KEY: &str =
    "02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0";

fn package_key(package: &[u8]) -> Vec<u8> {
    libtss::PublicKeyPackage::deserialize(package)
        .unwrap()
        .verifying_key()
        .to_vec()
}

#[test]
fn bolt3_derivations_through_the_c_api() {
    use libtss_ffi::dkls_ops::*;
    use libtss_ffi::handles::tss_handle_pubkey_package;

    let keys = split(SUITE_SECP256K1_ECDSA, &hex(BOLT3_BASE_SECRET), &[]).unwrap();
    let point = hex(BOLT3_PER_COMMITMENT_POINT);
    let secret = hex(BOLT3_PER_COMMITMENT_SECRET);

    let mut derived = Vec::new();
    let mut revocation = Vec::new();
    for key in &keys {
        let mut out = 0;
        assert_eq!(tss_bolt3_derive(*key, slice(&point), &mut out), TSS_OK);
        derived.push(out);
        assert_eq!(
            tss_bolt3_derive_revocation(*key, slice(&point), slice(&secret), &mut out),
            TSS_OK
        );
        revocation.push(out);
    }
    assert_eq!(group_key(derived[0]), hex(BOLT3_LOCAL_PUBLIC_KEY));
    assert_eq!(group_key(revocation[0]), hex(BOLT3_REVOCATION_PUBLIC_KEY));
    assert_eq!(run_dkls_sign(&derived[..2], &[5u8; 32]).len(), 64);

    let mut package = TssBuffer::empty();
    assert_eq!(tss_handle_pubkey_package(keys[0], &mut package), TSS_OK);
    let package = take_buffer(&mut package);
    let mut out = TssBuffer::empty();
    assert_eq!(
        tss_bolt3_derive_pubkey_package(slice(&package), slice(&point), &mut out),
        TSS_OK
    );
    assert_eq!(
        package_key(&take_buffer(&mut out)),
        hex(BOLT3_LOCAL_PUBLIC_KEY)
    );
    assert_eq!(
        tss_bolt3_derive_revocation_pubkey_package(slice(&package), slice(&point), &mut out),
        TSS_OK
    );
    assert_eq!(
        package_key(&take_buffer(&mut out)),
        hex(BOLT3_REVOCATION_PUBLIC_KEY)
    );

    let mut out = 0;
    assert_eq!(
        tss_bolt3_derive_revocation(keys[0], slice(&point), slice(&[1u8; 32]), &mut out),
        TSS_ERR_TWEAK
    );
    for key in keys.into_iter().chain(derived).chain(revocation) {
        tss_handle_free(key);
    }
}

#[test]
fn handle_getters_reset_the_out_buffer_on_error() {
    use libtss_ffi::handles::{tss_handle_chain_code, tss_handle_pubkey_package};

    for getter in [
        tss_handle_chain_code,
        tss_handle_group_key,
        tss_handle_verifying_share,
        tss_handle_pubkey_package,
    ] {
        let mut out = TssBuffer {
            data: std::ptr::NonNull::dangling().as_ptr(),
            len: 7,
        };
        assert_ne!(getter(0xdead_beef, &mut out), TSS_OK);
        assert!(out.data.is_null());
        assert_eq!(out.len, 0);
    }
}
