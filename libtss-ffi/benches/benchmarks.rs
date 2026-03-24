use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use libtss_ffi::handles::{tss_handle_export, tss_handle_import};
use libtss_ffi::memory::{tss_buffer_free, tss_handle_free};
use libtss_ffi::messages::{tss_message_at, tss_message_build, tss_message_count};
use libtss_ffi::session::{
    tss_dkg_new, tss_dkg_next, tss_session_free, tss_sign_new, tss_sign_next,
};
use libtss_ffi::types::{TssBuffer, TssHandle, TssSlice, TSS_OK};
use std::ptr;

const SUITE_ED25519: u8 = 2; // Ciphersuite::Ed25519 (FROST)
const SUITE_SECP256K1_ECDSA: u8 = 6; // Ciphersuite::Secp256k1ECDSA (DKLs23)

fn slice(bytes: &[u8]) -> TssSlice {
    TssSlice {
        data: bytes.as_ptr(),
        len: bytes.len(),
    }
}

fn take_buffer(buf: &mut TssBuffer) -> Vec<u8> {
    if buf.data.is_null() {
        return Vec::new();
    }
    let out = unsafe { std::slice::from_raw_parts(buf.data, buf.len) }.to_vec();
    tss_buffer_free(buf as *mut TssBuffer);
    out
}

/// Route TLV-encoded messages: for each recipient, build a TLV blob containing
/// only messages addressed to them (direct or broadcast from other senders).
fn route_messages(per_party_msgs: &[Vec<u8>], participants: usize) -> Vec<Vec<u8>> {
    let mut routed = vec![Vec::<u8>::new(); participants];

    for (sender_idx, blob) in per_party_msgs.iter().enumerate() {
        if blob.is_empty() {
            continue;
        }
        let s = TssSlice {
            data: blob.as_ptr(),
            len: blob.len(),
        };
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

fn run_dkg(suite: u8, participants: u16, min_signers: u16) -> Vec<TssHandle> {
    let n = participants as usize;
    let mut sessions = Vec::new();
    let mut pending = vec![Vec::new(); n];
    let mut keys = vec![0u64; n];

    // DKLs23 requires a session_id; FROST ignores it
    let session_id = b"bench-session-id";

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

            if complete {
                keys[index] = key_share;
                let _ = take_buffer(&mut pubkey_package);
                let _ = take_buffer(&mut out_messages);
            } else {
                pending[index] = take_buffer(&mut out_messages);
                let _ = take_buffer(&mut pubkey_package);
            }
        }
    }

    assert!(keys.iter().all(|h| *h != 0), "DKG did not complete");
    for session in sessions {
        tss_session_free(session);
    }
    keys
}

fn run_frost_dkg(participants: u16, min_signers: u16) -> Vec<TssHandle> {
    run_dkg(SUITE_ED25519, participants, min_signers)
}

fn run_dkls_dkg(participants: u16, min_signers: u16) -> Vec<TssHandle> {
    run_dkg(SUITE_SECP256K1_ECDSA, participants, min_signers)
}

/// Run a full FROST sign with `min_signers` parties (uses first `min_signers` keys).
fn run_frost_sign(keys: &[TssHandle], min_signers: usize, message: &[u8]) -> Vec<u8> {
    let n = min_signers;
    let mut sessions = Vec::new();
    let mut pending = vec![Vec::new(); n];

    for i in 0..n {
        let mut session = 0;
        let mut out_messages = TssBuffer::empty();
        assert_eq!(
            tss_sign_new(
                keys[i],
                slice(message),
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut session,
                &mut out_messages,
            ),
            TSS_OK,
        );
        sessions.push(session);
        pending[i] = take_buffer(&mut out_messages);
    }

    for _ in 0..4 {
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
                for (j, s) in sessions.iter().enumerate() {
                    if j != i {
                        tss_session_free(*s);
                    }
                }
                return sig;
            }

            pending[i] = take_buffer(&mut next_messages);
            let _ = take_buffer(&mut signature);
        }
    }

    panic!("signing did not complete");
}

/// Data captured after FROST round 1 (commit) for benchmarking round 2 in isolation.
struct FrostRound1State {
    sessions: Vec<TssHandle>,
    routed_commitments: Vec<Vec<u8>>,
}

/// Run FROST sign round 1 (commit) for all signers, return state for round 2.
fn frost_sign_round1(keys: &[TssHandle], min_signers: usize, message: &[u8]) -> FrostRound1State {
    let n = min_signers;
    let mut sessions = Vec::new();
    let mut pending = vec![Vec::new(); n];

    for i in 0..n {
        let mut session = 0;
        let mut out_messages = TssBuffer::empty();
        assert_eq!(
            tss_sign_new(
                keys[i],
                slice(message),
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut session,
                &mut out_messages,
            ),
            TSS_OK,
        );
        sessions.push(session);
        pending[i] = take_buffer(&mut out_messages);
    }

    let routed_commitments = route_messages(&pending, n);
    FrostRound1State {
        sessions,
        routed_commitments,
    }
}

/// Run a full DKLs23 sign with the given keys. DKLs requires a 32-byte hash,
/// counterparty list, and a sign_id.
fn run_dkls_sign(keys: &[TssHandle], min_signers: usize, msg_hash: &[u8; 32]) -> Vec<u8> {
    let n = min_signers;
    let mut sessions = Vec::new();
    let mut pending = vec![Vec::new(); n];

    // Build counterparty list for each signer: all other signers in the set
    let signer_ids: Vec<u16> = (1..=n as u16).collect();
    let sign_id = b"bench-sign-id";

    for i in 0..n {
        let mut session = 0;
        let mut out_messages = TssBuffer::empty();
        let counterparties: Vec<u16> = signer_ids
            .iter()
            .copied()
            .filter(|&id| id != signer_ids[i])
            .collect();
        assert_eq!(
            tss_sign_new(
                keys[i],
                slice(msg_hash),
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
                for (j, s) in sessions.iter().enumerate() {
                    if j != i {
                        tss_session_free(*s);
                    }
                }
                return sig;
            }

            pending[i] = take_buffer(&mut next_messages);
            let _ = take_buffer(&mut signature);
        }
    }

    panic!("DKLs signing did not complete");
}

// ---------------------------------------------------------------------------
// FROST benchmarks
// ---------------------------------------------------------------------------

fn bench_frost_dkg_2of3(c: &mut Criterion) {
    c.bench_function("frost_dkg_2of3", |b| {
        b.iter(|| {
            let keys = run_frost_dkg(3, 2);
            for k in keys {
                tss_handle_free(k);
            }
        })
    });
}

fn bench_frost_sign_2of3(c: &mut Criterion) {
    let keys = run_frost_dkg(3, 2);
    c.bench_function("frost_sign_2of3", |b| {
        b.iter(|| {
            let _ = run_frost_sign(&keys, 2, black_box(b"frost sign"));
        })
    });
}

fn bench_frost_commit(c: &mut Criterion) {
    let keys = run_frost_dkg(3, 2);
    c.bench_function("frost_commit", |b| {
        b.iter_batched(
            || Vec::from("commit".as_bytes()),
            |message| {
                let mut session = 0;
                let mut out_messages = TssBuffer::empty();
                assert_eq!(
                    tss_sign_new(
                        keys[0],
                        slice(&message),
                        ptr::null(),
                        0,
                        ptr::null(),
                        0,
                        &mut session,
                        &mut out_messages,
                    ),
                    TSS_OK
                );
                let _ = take_buffer(&mut out_messages);
                tss_session_free(session);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_frost_sign_share(c: &mut Criterion) {
    let keys = run_frost_dkg(3, 2);
    c.bench_function("frost_sign_share", |b| {
        b.iter_batched(
            || frost_sign_round1(&keys, 2, b"bench sign share"),
            |state| {
                // Bench round 2 only (sign share generation) for participant 0
                let mut signature = TssBuffer::empty();
                let mut next_messages = TssBuffer::empty();
                let mut complete = false;
                assert_eq!(
                    tss_sign_next(
                        state.sessions[0],
                        slice(&state.routed_commitments[0]),
                        &mut signature,
                        &mut next_messages,
                        &mut complete,
                    ),
                    TSS_OK,
                );
                let _ = take_buffer(&mut signature);
                let _ = take_buffer(&mut next_messages);
                for s in &state.sessions {
                    tss_session_free(*s);
                }
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_frost_aggregate(c: &mut Criterion) {
    // Use the Rust API directly: frost_aggregate is a standalone function
    use libtss::frost::frost_aggregate;
    use libtss::{Ciphersuite, ThresholdConfig};

    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    let (handles, pubkey_pkg) = libtss::frost::frost_generate_with_dealer(&config).unwrap();
    let msg = b"bench aggregate";

    // Run round 1 (commit) for first 2 signers
    // frost_commit returns (nonce_bytes, commitment_message)
    let (nonces, commitments): (Vec<_>, Vec<_>) = handles[..2]
        .iter()
        .map(|h| libtss::frost::frost_commit(h).unwrap())
        .unzip();

    // Run round 2 (sign) for first 2 signers
    let shares: Vec<_> = handles[..2]
        .iter()
        .zip(nonces.iter())
        .map(|(h, nonce)| libtss::frost::frost_sign(h, nonce, &commitments, msg).unwrap())
        .collect();

    c.bench_function("frost_aggregate", |b| {
        b.iter(|| {
            let _ = frost_aggregate(
                black_box(msg),
                black_box(&commitments),
                black_box(&shares),
                black_box(&pubkey_pkg),
            )
            .unwrap();
        })
    });
}

// ---------------------------------------------------------------------------
// DKLs23 benchmarks
// ---------------------------------------------------------------------------

fn bench_dkls_dkg_2of2(c: &mut Criterion) {
    c.bench_function("dkls_dkg_2of2", |b| {
        b.iter(|| {
            let keys = run_dkls_dkg(2, 2);
            for k in keys {
                tss_handle_free(k);
            }
        })
    });
}

fn bench_dkls_sign_2of2(c: &mut Criterion) {
    let keys = run_dkls_dkg(2, 2);
    let msg_hash = [0xABu8; 32];
    c.bench_function("dkls_sign_2of2", |b| {
        b.iter(|| {
            let _ = run_dkls_sign(&keys, 2, black_box(&msg_hash));
        })
    });
}

// ---------------------------------------------------------------------------
// Key management benchmarks
// ---------------------------------------------------------------------------

fn bench_derive_child(c: &mut Criterion) {
    // DKG via FFI to get a Secp256k1Taproot key in the global registry,
    // then use KeyShareHandle::from_registry_id for derive_child.
    const SUITE_SECP256K1_TR: u8 = 0; // Ciphersuite::Secp256k1Taproot
    let keys = run_dkg(SUITE_SECP256K1_TR, 3, 2);
    let handle = libtss::KeyShareHandle::from_registry_id(keys[0]).unwrap();

    c.bench_function("derive_child", |b| {
        b.iter(|| {
            let child = libtss::derive_child(black_box(&handle), black_box(0)).unwrap();
            drop(child);
        })
    });
    // Leak handle so it doesn't free the registry entry (keys are still in use)
    std::mem::forget(handle);
}

fn bench_export_import(c: &mut Criterion) {
    let keys = run_frost_dkg(3, 2);
    c.bench_function("export_import", |b| {
        b.iter(|| {
            let mut exported = TssBuffer::empty();
            assert_eq!(tss_handle_export(keys[0], &mut exported), TSS_OK);
            let bytes = take_buffer(&mut exported);
            let mut imported = 0;
            assert_eq!(
                tss_handle_import(bytes.as_ptr(), bytes.len(), SUITE_ED25519, &mut imported),
                TSS_OK
            );
            tss_handle_free(imported);
        })
    });
}

fn bench_ffi_call_overhead(c: &mut Criterion) {
    c.bench_function("ffi_call_overhead", |b| {
        b.iter(|| {
            black_box(libtss_ffi::tss_version());
        })
    });
}

criterion_group!(
    frost,
    bench_frost_dkg_2of3,
    bench_frost_sign_2of3,
    bench_frost_commit,
    bench_frost_sign_share,
    bench_frost_aggregate,
);
criterion_group!(dkls, bench_dkls_dkg_2of2, bench_dkls_sign_2of2,);
criterion_group!(keyops, bench_derive_child, bench_export_import);
criterion_group!(ffi_overhead, bench_ffi_call_overhead);
criterion_main!(frost, dkls, keyops, ffi_overhead);
