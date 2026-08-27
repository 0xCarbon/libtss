//! Shared FFI-level protocol driver for integration tests: runs a complete DKG
//! (and, for DKLs23, a signing session) purely through the C ABI, routing the
//! TLV message blobs between parties the way a host application would.
#![allow(dead_code)]

use std::ptr;

use libtss_ffi::memory::tss_buffer_free;
use libtss_ffi::messages::{tss_message_at, tss_message_build, tss_message_count};
use libtss_ffi::session::{
    tss_dkg_new, tss_dkg_next, tss_session_free, tss_sign_new, tss_sign_next,
};
use libtss_ffi::types::{TssBuffer, TssHandle, TssSlice, TSS_OK};

pub const SUITE_SECP256K1_TAPROOT: u8 = 0;
pub const SUITE_ED25519: u8 = 2;
pub const SUITE_SECP256K1_ECDSA: u8 = 6;

pub fn slice(bytes: &[u8]) -> TssSlice {
    TssSlice {
        data: bytes.as_ptr(),
        len: bytes.len(),
    }
}

pub fn take_buffer(buf: &mut TssBuffer) -> Vec<u8> {
    if buf.data.is_null() {
        return Vec::new();
    }
    let out = unsafe { std::slice::from_raw_parts(buf.data, buf.len) }.to_vec();
    tss_buffer_free(buf as *mut TssBuffer);
    out
}

/// Route TLV-encoded messages: for each recipient, build a TLV blob containing
/// only messages addressed to them (direct or broadcast from other senders).
pub fn route_messages(per_party_msgs: &[Vec<u8>], participants: usize) -> Vec<Vec<u8>> {
    let mut routed = vec![Vec::<u8>::new(); participants];

    for (sender_idx, blob) in per_party_msgs.iter().enumerate() {
        if blob.is_empty() {
            continue;
        }
        let s = slice(blob);
        let count = tss_message_count(s);

        for i in 0..count {
            let mut from: u16 = 0;
            let mut to: u16 = 0;
            let mut data = TssSlice {
                data: ptr::null(),
                len: 0,
            };
            assert_eq!(tss_message_at(s, i, &mut from, &mut to, &mut data), TSS_OK);

            let recipients: Vec<usize> = if to != 0 {
                vec![(to - 1) as usize]
            } else {
                (0..participants).filter(|&r| r != sender_idx).collect()
            };

            for recip_idx in recipients {
                let mut buf = if routed[recip_idx].is_empty() {
                    TssBuffer::empty()
                } else {
                    TssBuffer::from_vec(std::mem::take(&mut routed[recip_idx]))
                };
                assert_eq!(
                    tss_message_build(&mut buf, from, to, data.data, data.len),
                    TSS_OK
                );
                routed[recip_idx] = take_buffer(&mut buf);
            }
        }
    }
    routed
}

/// Run a full DKG through the FFI and return one key share handle per party.
pub fn run_dkg(suite: u8, participants: u16, min_signers: u16) -> Vec<TssHandle> {
    let n = participants as usize;
    let mut sessions = Vec::new();
    let mut pending = vec![Vec::new(); n];
    let mut keys = vec![0u64; n];
    let session_id = b"ffi-test-session-id";

    for self_id in 1..=participants {
        let mut session = 0;
        let mut messages = TssBuffer::empty();
        assert_eq!(
            tss_dkg_new(
                suite,
                self_id,
                participants,
                min_signers,
                session_id.as_ptr(),
                session_id.len(),
                &mut session,
                &mut messages,
            ),
            TSS_OK,
        );
        sessions.push(session);
        pending[(self_id - 1) as usize] = take_buffer(&mut messages);
    }

    for _ in 0..8 {
        if keys.iter().all(|h| *h != 0) {
            break;
        }

        let routed = route_messages(&pending, n);
        pending = vec![Vec::new(); n];

        for (index, session) in sessions.iter().enumerate() {
            if keys[index] != 0 {
                continue;
            }

            let mut key_share = 0;
            let mut pubkey_package = TssBuffer::empty();
            let mut out_messages = TssBuffer::empty();
            let mut complete = false;
            assert_eq!(
                tss_dkg_next(
                    *session,
                    slice(&routed[index]),
                    &mut key_share,
                    &mut pubkey_package,
                    &mut out_messages,
                    &mut complete,
                ),
                TSS_OK,
            );

            let _ = take_buffer(&mut pubkey_package);
            if complete {
                keys[index] = key_share;
                let _ = take_buffer(&mut out_messages);
            } else {
                pending[index] = take_buffer(&mut out_messages);
            }
        }
    }

    assert!(keys.iter().all(|h| *h != 0), "DKG did not complete");
    for session in sessions {
        tss_session_free(session);
    }
    keys
}

/// Run a DKLs23 signing session over `message_hash` with the given key shares
/// (all of them sign; `keys[i]` must belong to party `i + 1`) and return the
/// 64-byte `r || s` signature.
pub fn run_dkls_sign(keys: &[TssHandle], message_hash: &[u8]) -> Vec<u8> {
    let n = keys.len();
    let mut sessions = Vec::new();
    let mut pending = vec![Vec::new(); n];
    let signer_ids: Vec<u16> = (1..=n as u16).collect();
    let sign_id = b"ffi-test-sign-id";

    for (i, key) in keys.iter().enumerate() {
        let counterparties: Vec<u16> = signer_ids
            .iter()
            .copied()
            .filter(|&id| id != signer_ids[i])
            .collect();
        let mut session = 0;
        let mut out_messages = TssBuffer::empty();
        assert_eq!(
            tss_sign_new(
                *key,
                slice(message_hash),
                counterparties.as_ptr(),
                counterparties.len(),
                sign_id.as_ptr(),
                sign_id.len(),
                &mut session,
                &mut out_messages,
            ),
            TSS_OK,
        );
        sessions.push(session);
        pending[i] = take_buffer(&mut out_messages);
    }

    for _ in 0..8 {
        let routed = route_messages(&pending, n);
        pending = vec![Vec::new(); n];

        for (i, session) in sessions.iter().enumerate() {
            let mut signature = TssBuffer::empty();
            let mut next_messages = TssBuffer::empty();
            let mut complete = false;
            assert_eq!(
                tss_sign_next(
                    *session,
                    slice(&routed[i]),
                    &mut signature,
                    &mut next_messages,
                    &mut complete,
                ),
                TSS_OK,
            );

            if complete {
                let sig = take_buffer(&mut signature);
                let _ = take_buffer(&mut next_messages);
                for s in &sessions {
                    tss_session_free(*s);
                }
                return sig;
            }

            pending[i] = take_buffer(&mut next_messages);
            let _ = take_buffer(&mut signature);
        }
    }

    panic!("signing did not complete");
}
