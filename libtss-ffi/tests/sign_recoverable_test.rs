//! `tss_sign_next_recoverable` reports the recovery identifier of DKLs23
//! signatures and `TSS_NO_RECOVERY_ID` for FROST signatures.

mod common;

use common::{route_messages, run_dkg, slice, take_buffer, SUITE_ED25519, SUITE_SECP256K1_ECDSA};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use libtss_ffi::handles::tss_handle_group_key;
use libtss_ffi::memory::tss_handle_free;
use libtss_ffi::session::{tss_session_free, tss_sign_new};
use libtss_ffi::sign_recoverable::{tss_sign_next_recoverable, TSS_NO_RECOVERY_ID};
use libtss_ffi::types::{TssBuffer, TssHandle, TSS_OK};

fn sign_recoverable(keys: &[TssHandle], message: &[u8]) -> (Vec<u8>, u8) {
    let n = keys.len();
    let ids: Vec<u16> = (1..=n as u16).collect();
    let sign_id = b"ffi-recoverable-sign";
    let mut sessions = Vec::new();
    let mut pending = vec![Vec::new(); n];
    for (i, key) in keys.iter().enumerate() {
        let counterparties: Vec<u16> = ids.iter().copied().filter(|&id| id != ids[i]).collect();
        let mut session = 0;
        let mut out = TssBuffer::empty();
        assert_eq!(
            tss_sign_new(
                *key,
                slice(message),
                counterparties.as_ptr(),
                counterparties.len(),
                sign_id.as_ptr(),
                sign_id.len(),
                &mut session,
                &mut out,
            ),
            TSS_OK
        );
        sessions.push(session);
        pending[i] = take_buffer(&mut out);
    }
    for _ in 0..8 {
        let routed = route_messages(&pending, n);
        pending = vec![Vec::new(); n];
        for (i, session) in sessions.iter().enumerate() {
            let mut signature = TssBuffer::empty();
            let mut recovery_id = 0u8;
            let mut next = TssBuffer::empty();
            let mut complete = false;
            assert_eq!(
                tss_sign_next_recoverable(
                    *session,
                    slice(&routed[i]),
                    &mut signature,
                    &mut recovery_id,
                    &mut next,
                    &mut complete,
                ),
                TSS_OK
            );
            if complete {
                let sig = take_buffer(&mut signature);
                for s in &sessions {
                    tss_session_free(*s);
                }
                return (sig, recovery_id);
            }
            assert_eq!(recovery_id, TSS_NO_RECOVERY_ID);
            pending[i] = take_buffer(&mut next);
        }
    }
    panic!("signing did not complete");
}

#[test]
fn dkls_signature_carries_recovery_id() {
    let keys = run_dkg(SUITE_SECP256K1_ECDSA, 2, 2);
    let hash = [0x5au8; 32];
    let (sig, recovery_id) = sign_recoverable(&keys, &hash);
    assert_eq!(sig.len(), 64);
    assert!(recovery_id <= 1, "recovery id {recovery_id}");

    let mut group_key = TssBuffer::empty();
    assert_eq!(tss_handle_group_key(keys[0], &mut group_key), TSS_OK);
    let group_key = take_buffer(&mut group_key);
    let recovered = VerifyingKey::recover_from_prehash(
        &hash,
        &K256Signature::from_slice(&sig).unwrap(),
        RecoveryId::from_byte(recovery_id).unwrap(),
    )
    .unwrap();
    assert_eq!(recovered.to_sec1_point(true).as_bytes(), &group_key[..]);
    for key in keys {
        tss_handle_free(key);
    }
}

#[test]
fn frost_signature_has_no_recovery_id() {
    let keys = run_dkg(SUITE_ED25519, 2, 2);
    let (sig, recovery_id) = sign_recoverable(&keys, b"message");
    assert_eq!(sig.len(), 64);
    assert_eq!(recovery_id, TSS_NO_RECOVERY_ID);
    for key in keys {
        tss_handle_free(key);
    }
}

#[test]
fn null_recovery_id_pointer_is_rejected() {
    let mut signature = TssBuffer::empty();
    let mut next = TssBuffer::empty();
    let mut complete = false;
    assert_ne!(
        tss_sign_next_recoverable(
            1,
            slice(&[]),
            &mut signature,
            std::ptr::null_mut(),
            &mut next,
            &mut complete,
        ),
        TSS_OK
    );
}
