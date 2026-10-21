//! DKLs23 key lifecycle through the unified API: complete refresh and key import.

use std::collections::BTreeMap;

use k256::elliptic_curve::sec1::ToSec1Point;
use libtss::dkls_import::dkls_split_key;
use libtss::session::dkg::{DkgOutput, DkgSession};
use libtss::session::refresh::{RefreshOutput, RefreshSession};
use libtss::session::sign::{SignOutput, SignSession};
use libtss::types::{Ciphersuite, Identifier, ThresholdConfig};
use libtss::{KeyShareHandle, Message, TssError};

const SUITES: [Ciphersuite; 2] = [Ciphersuite::Secp256k1ECDSA, Ciphersuite::Secp256r1ECDSA];

fn id(value: u16) -> Identifier {
    Identifier::new(value).unwrap()
}

fn route(
    outputs: &BTreeMap<Identifier, Vec<Message>>,
    recipients: &[Identifier],
) -> BTreeMap<Identifier, Vec<Message>> {
    let mut routed: BTreeMap<Identifier, Vec<Message>> =
        recipients.iter().map(|&r| (r, Vec::new())).collect();
    for (&sender, messages) in outputs {
        for msg in messages {
            match msg.to {
                Some(to) => routed.get_mut(&to).unwrap().push(msg.clone()),
                None => {
                    for &r in recipients {
                        if r != sender {
                            routed.get_mut(&r).unwrap().push(msg.clone());
                        }
                    }
                }
            }
        }
    }
    routed
}

fn dkg(suite: Ciphersuite) -> BTreeMap<Identifier, KeyShareHandle> {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite,
    };
    let parties: Vec<_> = (1..=3).map(id).collect();
    let mut sessions = BTreeMap::new();
    let mut out = BTreeMap::new();
    for &p in &parties {
        let session_id: Option<&[u8]> = match suite {
            Ciphersuite::Secp256k1ECDSA | Ciphersuite::Secp256r1ECDSA => Some(b"refresh-test-dkg"),
            _ => None,
        };
        let (session, msgs) = DkgSession::new(&config, p, session_id).unwrap();
        sessions.insert(p, session);
        out.insert(p, msgs);
    }
    let mut shares = BTreeMap::new();
    while shares.is_empty() {
        let routed = route(&out, &parties);
        out = BTreeMap::new();
        for &p in &parties {
            match sessions.get_mut(&p).unwrap().next(&routed[&p]).unwrap() {
                DkgOutput::Continue(msgs) => {
                    out.insert(p, msgs);
                }
                DkgOutput::Complete { key_share, .. } => {
                    shares.insert(p, key_share);
                }
            }
        }
    }
    shares
}

/// Runs a complete refresh with each party's own session id.
fn refresh(
    shares: &BTreeMap<Identifier, KeyShareHandle>,
    session_ids: &BTreeMap<Identifier, &[u8]>,
) -> Result<BTreeMap<Identifier, KeyShareHandle>, TssError> {
    let parties: Vec<_> = shares.keys().copied().collect();
    let mut sessions = BTreeMap::new();
    let mut out = BTreeMap::new();
    for &p in &parties {
        let (session, msgs) = RefreshSession::new_dkls(&shares[&p], session_ids[&p])?;
        sessions.insert(p, session);
        out.insert(p, msgs);
    }
    let mut refreshed = BTreeMap::new();
    while refreshed.is_empty() {
        let routed = route(&out, &parties);
        out = BTreeMap::new();
        for &p in &parties {
            match sessions.get_mut(&p).unwrap().next(&routed[&p])? {
                RefreshOutput::Continue(msgs) => {
                    out.insert(p, msgs);
                }
                RefreshOutput::Complete { key_share, .. } => {
                    refreshed.insert(p, key_share);
                }
            }
        }
    }
    Ok(refreshed)
}

fn sign(
    suite: Ciphersuite,
    shares: &BTreeMap<Identifier, &KeyShareHandle>,
    hash: [u8; 32],
) -> Result<Vec<u8>, TssError> {
    let signers: Vec<_> = shares.keys().copied().collect();
    let mut sessions = BTreeMap::new();
    let mut out = BTreeMap::new();
    for &p in &signers {
        let counterparties: Vec<_> = signers.iter().copied().filter(|&x| x != p).collect();
        let (session, msgs) = match suite {
            Ciphersuite::Secp256k1ECDSA => {
                SignSession::new_dkls(shares[&p], vec![9; 32], &counterparties, hash)
            }
            _ => SignSession::new_dkls_r1(shares[&p], vec![9; 32], &counterparties, hash),
        }?;
        sessions.insert(p, session);
        out.insert(p, msgs);
    }
    loop {
        let routed = route(&out, &signers);
        out = BTreeMap::new();
        for &p in &signers {
            match sessions.get_mut(&p).unwrap().next(&routed[&p])? {
                SignOutput::Continue(msgs) => {
                    out.insert(p, msgs);
                }
                SignOutput::Complete(signature) => return Ok(signature.as_bytes().to_vec()),
            }
        }
    }
}

fn verifies(suite: Ciphersuite, group_key: &[u8], hash: &[u8; 32], signature: &[u8]) -> bool {
    match suite {
        Ciphersuite::Secp256k1ECDSA => {
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(group_key).unwrap();
            let signature = k256::ecdsa::Signature::from_slice(signature).unwrap();
            key.verify_prehash(hash, &signature).is_ok()
        }
        _ => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(group_key).unwrap();
            let signature = p256::ecdsa::Signature::from_slice(signature).unwrap();
            key.verify_prehash(hash, &signature).is_ok()
        }
    }
}

fn same_id(parties: &[Identifier], sid: &'static [u8]) -> BTreeMap<Identifier, &'static [u8]> {
    parties.iter().map(|&p| (p, sid)).collect()
}

#[test]
fn refresh_keeps_the_key_and_moves_every_share() {
    for suite in SUITES {
        let shares = dkg(suite);
        let parties: Vec<_> = shares.keys().copied().collect();
        let refreshed = refresh(&shares, &same_id(&parties, b"refresh-1")).unwrap();

        let group_key = shares[&id(1)].group_verifying_key();
        for p in &parties {
            assert_eq!(refreshed[p].group_verifying_key(), group_key);
            assert_ne!(refreshed[p].verifying_share(), shares[p].verifying_share());
            assert_eq!(
                refreshed[p].chain_code().unwrap(),
                shares[p].chain_code().unwrap()
            );
            assert_eq!(
                refreshed[p].public_key_package(),
                refreshed[&id(1)].public_key_package()
            );
        }

        let hash = [5u8; 32];
        let signers = BTreeMap::from([(id(1), &refreshed[&id(1)]), (id(3), &refreshed[&id(3)])]);
        let signature = sign(suite, &signers, hash).unwrap();
        assert!(verifies(suite, &group_key, &hash, &signature), "{suite:?}");
    }
}

#[test]
fn refreshed_and_stale_shares_do_not_sign_together() {
    for suite in SUITES {
        let shares = dkg(suite);
        let parties: Vec<_> = shares.keys().copied().collect();
        let refreshed = refresh(&shares, &same_id(&parties, b"refresh-1")).unwrap();

        let mixed = BTreeMap::from([(id(1), &refreshed[&id(1)]), (id(2), &shares[&id(2)])]);
        assert!(sign(suite, &mixed, [5u8; 32]).is_err(), "{suite:?}");
    }
}

#[test]
fn refresh_aborts_when_session_ids_differ() {
    for suite in SUITES {
        let shares = dkg(suite);
        let session_ids: BTreeMap<_, &[u8]> = BTreeMap::from([
            (id(1), b"refresh-a".as_slice()),
            (id(2), b"refresh-a".as_slice()),
            (id(3), b"refresh-b".as_slice()),
        ]);
        assert!(refresh(&shares, &session_ids).is_err(), "{suite:?}");
    }
}

#[test]
fn refresh_rejects_empty_session_id_and_other_suites() {
    let shares = dkg(Ciphersuite::Secp256k1ECDSA);
    assert!(matches!(
        RefreshSession::new_dkls(&shares[&id(1)], b""),
        Err(TssError::InvalidConfig(_))
    ));

    let frost = dkg(Ciphersuite::Ed25519);
    assert!(matches!(
        RefreshSession::new_dkls(&frost[&id(1)], b"refresh-1"),
        Err(TssError::ProtocolMismatch)
    ));
}

fn handles_by_id(handles: Vec<KeyShareHandle>) -> BTreeMap<Identifier, KeyShareHandle> {
    handles.into_iter().map(|h| (h.identifier(), h)).collect()
}

fn import(
    suite: Ciphersuite,
    secret: &[u8],
    chain_code: Option<&[u8]>,
) -> BTreeMap<Identifier, KeyShareHandle> {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite,
    };
    let (handles, public_keys) = dkls_split_key(&config, secret, chain_code).unwrap();
    assert_eq!(handles.len(), 3);
    for handle in &handles {
        assert_eq!(handle.public_key_package(), &public_keys);
    }
    handles_by_id(handles)
}

fn public_key(suite: Ciphersuite, secret: &[u8]) -> Vec<u8> {
    match suite {
        Ciphersuite::Secp256k1ECDSA => k256::SecretKey::from_slice(secret)
            .unwrap()
            .public_key()
            .to_sec1_bytes()
            .to_vec(),
        _ => p256::SecretKey::from_slice(secret)
            .unwrap()
            .public_key()
            .to_sec1_bytes()
            .to_vec(),
    }
}

fn compressed(suite: Ciphersuite, sec1: &[u8]) -> Vec<u8> {
    match suite {
        Ciphersuite::Secp256k1ECDSA => k256::PublicKey::from_sec1_bytes(sec1)
            .unwrap()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec(),
        _ => p256::PublicKey::from_sec1_bytes(sec1)
            .unwrap()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec(),
    }
}

#[test]
fn imported_key_keeps_its_public_key_and_chain_code_and_signs() {
    let secret = [0x42u8; 32];
    let chain_code = [0x17u8; 32];
    for suite in SUITES {
        let shares = import(suite, &secret, Some(&chain_code));
        let group_key = shares[&id(1)].group_verifying_key();
        assert_eq!(
            compressed(suite, &group_key),
            compressed(suite, &public_key(suite, &secret))
        );
        for share in shares.values() {
            assert_eq!(share.chain_code().unwrap(), chain_code);
        }

        let hash = [8u8; 32];
        let signers = BTreeMap::from([(id(2), &shares[&id(2)]), (id(3), &shares[&id(3)])]);
        let signature = sign(suite, &signers, hash).unwrap();
        assert!(verifies(suite, &group_key, &hash, &signature), "{suite:?}");

        // The recommended follow-up refresh keeps the key.
        let parties: Vec<_> = shares.keys().copied().collect();
        let refreshed = refresh(&shares, &same_id(&parties, b"after-import")).unwrap();
        let signers = BTreeMap::from([(id(1), &refreshed[&id(1)]), (id(2), &refreshed[&id(2)])]);
        let signature = sign(suite, &signers, hash).unwrap();
        assert!(verifies(suite, &group_key, &hash, &signature), "{suite:?}");
    }
}

#[test]
fn two_imports_of_one_key_do_not_sign_together() {
    for suite in SUITES {
        let first = import(suite, &[0x42u8; 32], None);
        let second = import(suite, &[0x42u8; 32], None);
        let mixed = BTreeMap::from([(id(1), &first[&id(1)]), (id(2), &second[&id(2)])]);
        assert!(sign(suite, &mixed, [8u8; 32]).is_err(), "{suite:?}");
    }
}

#[test]
fn import_rejects_invalid_input() {
    let config = |suite| ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite,
    };
    let k1 = config(Ciphersuite::Secp256k1ECDSA);
    let invalid = |result: Result<_, TssError>| matches!(result, Err(TssError::InvalidConfig(_)));

    assert!(invalid(dkls_split_key(&k1, &[0u8; 32], None)));
    assert!(invalid(dkls_split_key(&k1, &[1u8; 31], None)));
    assert!(invalid(dkls_split_key(&k1, &[0xffu8; 32], None)));
    assert!(invalid(dkls_split_key(&k1, &[1u8; 32], Some(&[0u8; 31]))));
    assert!(invalid(dkls_split_key(
        &ThresholdConfig {
            min_signers: 1,
            ..k1.clone()
        },
        &[1u8; 32],
        None
    )));
    assert!(matches!(
        dkls_split_key(&config(Ciphersuite::Ed25519), &[1u8; 32], None),
        Err(TssError::ProtocolMismatch)
    ));
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

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn bolt3_derivations_match_the_bolt3_vectors_and_sign() {
    use libtss::bolt3;

    let suite = Ciphersuite::Secp256k1ECDSA;
    let base = import(suite, &hex(BOLT3_BASE_SECRET), None);
    let point = hex(BOLT3_PER_COMMITMENT_POINT);
    let hash = [6u8; 32];

    let derived: BTreeMap<_, _> = base
        .iter()
        .map(|(id, share)| (*id, bolt3::bolt3_derive(share, &point).unwrap()))
        .collect();
    let local_key = derived[&id(1)].group_verifying_key();
    assert_eq!(local_key, hex(BOLT3_LOCAL_PUBLIC_KEY));
    assert_eq!(
        &bolt3::bolt3_derive_public_keys(base[&id(1)].public_key_package(), &point).unwrap(),
        derived[&id(1)].public_key_package()
    );
    let signers = BTreeMap::from([(id(1), &derived[&id(1)]), (id(3), &derived[&id(3)])]);
    assert!(verifies(
        suite,
        &local_key,
        &hash,
        &sign(suite, &signers, hash).unwrap()
    ));

    let secret = hex(BOLT3_PER_COMMITMENT_SECRET);
    let revocation: BTreeMap<_, _> = base
        .iter()
        .map(|(id, share)| {
            let key = bolt3::bolt3_derive_revocation(share, &point, &secret).unwrap();
            (*id, key)
        })
        .collect();
    let revocation_key = revocation[&id(1)].group_verifying_key();
    assert_eq!(revocation_key, hex(BOLT3_REVOCATION_PUBLIC_KEY));
    assert_eq!(
        &bolt3::bolt3_derive_revocation_public_keys(base[&id(1)].public_key_package(), &point)
            .unwrap(),
        revocation[&id(1)].public_key_package()
    );
    let signers = BTreeMap::from([(id(2), &revocation[&id(2)]), (id(3), &revocation[&id(3)])]);
    assert!(verifies(
        suite,
        &revocation_key,
        &hash,
        &sign(suite, &signers, hash).unwrap()
    ));
}

#[test]
fn bolt3_rejects_invalid_input() {
    use libtss::bolt3;

    let base = import(Ciphersuite::Secp256k1ECDSA, &hex(BOLT3_BASE_SECRET), None);
    let share = &base[&id(1)];
    let point = hex(BOLT3_PER_COMMITMENT_POINT);
    assert!(matches!(
        bolt3::bolt3_derive(share, &point[..32]),
        Err(TssError::InvalidConfig(_))
    ));
    assert!(matches!(
        bolt3::bolt3_derive_revocation(share, &point, &[1u8; 32]),
        Err(TssError::TweakError(_))
    ));
    assert!(matches!(
        bolt3::bolt3_derive_revocation(share, &point, &[1u8; 31]),
        Err(TssError::InvalidConfig(_))
    ));

    let r1 = import(Ciphersuite::Secp256r1ECDSA, &[0x42u8; 32], None);
    assert!(matches!(
        bolt3::bolt3_derive(&r1[&id(1)], &point),
        Err(TssError::ProtocolMismatch)
    ));
}

/// Shares exported by libtss before the DKLs23 0.6 upgrade still import,
/// sign and refresh.
#[test]
fn shares_exported_before_the_upgrade_import_sign_and_refresh() {
    for (suite, prefix) in [
        (Ciphersuite::Secp256k1ECDSA, "k1"),
        (Ciphersuite::Secp256r1ECDSA, "r1"),
    ] {
        let shares: BTreeMap<_, _> = (1..=3)
            .map(|p| {
                let path = format!(
                    "{}/tests/fixtures/dkls23-0.4/{prefix}-{p}.bin",
                    env!("CARGO_MANIFEST_DIR")
                );
                let data = std::fs::read(path).unwrap();
                (id(p), libtss::import_key_share(&data, suite).unwrap())
            })
            .collect();
        let group_key = shares[&id(1)].group_verifying_key();
        let hash = [3u8; 32];
        let signers = BTreeMap::from([(id(1), &shares[&id(1)]), (id(3), &shares[&id(3)])]);
        assert!(verifies(
            suite,
            &group_key,
            &hash,
            &sign(suite, &signers, hash).unwrap()
        ));

        let parties: Vec<_> = shares.keys().copied().collect();
        let refreshed = refresh(&shares, &same_id(&parties, b"after-upgrade")).unwrap();
        let signers = BTreeMap::from([(id(2), &refreshed[&id(2)]), (id(3), &refreshed[&id(3)])]);
        assert!(verifies(
            suite,
            &group_key,
            &hash,
            &sign(suite, &signers, hash).unwrap()
        ));
    }
}

/// A tampered proof commitment aborts the refresh, names the sender, bans
/// no one, and ends the session.
#[test]
fn refresh_with_a_tampered_proof_names_the_sender_and_ends() {
    let shares = dkg(Ciphersuite::Secp256k1ECDSA);
    let parties: Vec<_> = shares.keys().copied().collect();
    let mut sessions = BTreeMap::new();
    let mut out = BTreeMap::new();
    for &p in &parties {
        let (session, msgs) = RefreshSession::new_dkls(&shares[&p], b"tampered").unwrap();
        sessions.insert(p, session);
        out.insert(p, msgs);
    }
    // Round 1 -> round-2 messages.
    let routed = route(&out, &parties);
    for &p in &parties {
        match sessions.get_mut(&p).unwrap().next(&routed[&p]).unwrap() {
            RefreshOutput::Continue(msgs) => {
                out.insert(p, msgs);
            }
            _ => panic!("expected Continue"),
        }
    }
    // Party 2's broadcast proof commitment ends with the commitment bytes.
    let broadcast = out
        .get_mut(&id(2))
        .unwrap()
        .iter_mut()
        .find(|m| m.to.is_none())
        .unwrap();
    *broadcast.data.last_mut().unwrap() ^= 1;
    // Round 2 -> round-3 messages, then round 3 verifies the proofs.
    let routed = route(&out, &parties);
    for &p in &parties {
        if let RefreshOutput::Continue(msgs) =
            sessions.get_mut(&p).unwrap().next(&routed[&p]).unwrap()
        {
            out.insert(p, msgs);
        }
    }
    let routed = route(&out, &parties);
    let session = sessions.get_mut(&id(1)).unwrap();
    match session.next(&routed[&id(1)]) {
        Err(TssError::Abort { culprits, ban, .. }) => {
            assert_eq!(culprits, vec![id(2)]);
            assert_eq!(ban, None);
        }
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("a tampered proof must abort"),
    }
    assert!(session.is_complete());
    assert!(matches!(
        session.next(&routed[&id(1)]),
        Err(TssError::SessionComplete)
    ));
}

#[test]
fn bolt3_package_derivation_requires_indices_one_to_n() {
    let base = import(Ciphersuite::Secp256k1ECDSA, &hex(BOLT3_BASE_SECRET), None);
    let package = base[&id(1)].public_key_package();
    let gapped: BTreeMap<_, _> = [1, 3]
        .into_iter()
        .map(|i| (id(i), package.verifying_share(id(i)).unwrap().to_vec()))
        .collect();
    let gapped = libtss::PublicKeyPackage::new(
        Ciphersuite::Secp256k1ECDSA,
        package.verifying_key().to_vec(),
        gapped,
        2,
    );
    assert!(matches!(
        libtss::bolt3::bolt3_derive_public_keys(&gapped, &hex(BOLT3_PER_COMMITMENT_POINT)),
        Err(TssError::InvalidIdentifier)
    ));
}
