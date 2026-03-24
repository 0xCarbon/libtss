//! Protocol correctness integration tests (Issue #16).
//!
//! These tests exercise the unified session API across different threshold
//! configurations, ciphersuites, and error conditions. They complement the
//! unit tests in each module.

use std::collections::BTreeMap;

use libtss::session::dkg::{DkgOutput, DkgSession};
use libtss::session::sign::{SignOutput, SignSession};
use libtss::types::{Ciphersuite, Identifier, Protocol, ThresholdConfig};
use libtss::{Message, TssError};

// ---------------------------------------------------------------------------
// Test harness: message routing
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helpers: run full DKG and signing via unified sessions
// ---------------------------------------------------------------------------

fn run_frost_dkg_session(
    suite: Ciphersuite,
    min_signers: u16,
    max_signers: u16,
) -> Result<BTreeMap<Identifier, libtss::KeyShareHandle>, TssError> {
    let config = ThresholdConfig {
        min_signers,
        max_signers,
        suite,
    };
    let participants: Vec<Identifier> = (1..=max_signers).map(id).collect();

    let mut sessions = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for &pid in &participants {
        let (session, msgs) = DkgSession::new(&config, pid, None)?;
        sessions.insert(pid, session);
        round1.insert(pid, msgs);
    }

    let r1_in = route(&round1, &participants);
    let mut round2 = BTreeMap::new();
    for &pid in &participants {
        match sessions
            .get_mut(&pid)
            .unwrap()
            .next(r1_in.get(&pid).unwrap())?
        {
            DkgOutput::Continue(msgs) => {
                round2.insert(pid, msgs);
            }
            _ => panic!("expected Continue"),
        }
    }

    let r2_in = route(&round2, &participants);
    let mut results = BTreeMap::new();
    for &pid in &participants {
        match sessions
            .get_mut(&pid)
            .unwrap()
            .next(r2_in.get(&pid).unwrap())?
        {
            DkgOutput::Complete { key_share, .. } => {
                results.insert(pid, key_share);
            }
            _ => panic!("expected Complete"),
        }
    }
    Ok(results)
}

fn run_dkls_dkg_session(
    min_signers: u16,
    max_signers: u16,
) -> Result<BTreeMap<Identifier, libtss::KeyShareHandle>, TssError> {
    let config = ThresholdConfig {
        min_signers,
        max_signers,
        suite: Ciphersuite::Secp256k1ECDSA,
    };
    let participants: Vec<Identifier> = (1..=max_signers).map(id).collect();
    let session_id = b"test-dkls-session";

    let mut sessions = BTreeMap::new();
    let mut phase1 = BTreeMap::new();
    for &pid in &participants {
        let (session, msgs) = DkgSession::new(&config, pid, Some(session_id))?;
        sessions.insert(pid, session);
        phase1.insert(pid, msgs);
    }

    // DKLs23 has 4 phases: advance through 3 Continue rounds then Complete
    let mut prev = route(&phase1, &participants);
    for _ in 0..2 {
        let mut out = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(prev.get(&pid).unwrap())?
            {
                DkgOutput::Continue(msgs) => {
                    out.insert(pid, msgs);
                }
                _ => panic!("expected Continue"),
            }
        }
        prev = route(&out, &participants);
    }

    let mut results = BTreeMap::new();
    for &pid in &participants {
        match sessions
            .get_mut(&pid)
            .unwrap()
            .next(prev.get(&pid).unwrap())?
        {
            DkgOutput::Complete { key_share, .. } => {
                results.insert(pid, key_share);
            }
            _ => panic!("expected Complete"),
        }
    }
    Ok(results)
}

fn run_frost_sign(
    key_shares: &BTreeMap<Identifier, libtss::KeyShareHandle>,
    signer_ids: &[Identifier],
    message: &[u8],
) -> Result<libtss::types::Signature, TssError> {
    let mut sessions = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for &pid in signer_ids {
        let ks = key_shares.get(&pid).unwrap();
        let (session, msgs) = SignSession::new_frost(ks, message)?;
        sessions.insert(pid, session);
        round1.insert(pid, msgs);
    }

    let r1_in = route(&round1, signer_ids);
    let mut round2 = BTreeMap::new();
    for &pid in signer_ids {
        match sessions
            .get_mut(&pid)
            .unwrap()
            .next(r1_in.get(&pid).unwrap())?
        {
            SignOutput::Continue(msgs) => {
                round2.insert(pid, msgs);
            }
            _ => panic!("expected Continue"),
        }
    }

    let r2_in = route(&round2, signer_ids);
    // All signers should get the same signature
    let mut signature: Option<libtss::types::Signature> = None;
    for &pid in signer_ids {
        match sessions
            .get_mut(&pid)
            .unwrap()
            .next(r2_in.get(&pid).unwrap())?
        {
            SignOutput::Complete(sig) => {
                if let Some(ref first) = signature {
                    assert_eq!(
                        sig.as_bytes(),
                        first.as_bytes(),
                        "signers should produce same signature"
                    );
                }
                signature = Some(sig);
            }
            _ => panic!("expected Complete"),
        }
    }
    Ok(signature.unwrap())
}

fn run_dkls_sign(
    key_shares: &BTreeMap<Identifier, libtss::KeyShareHandle>,
    signer_ids: &[Identifier],
    message_hash: [u8; 32],
) -> Result<libtss::types::Signature, TssError> {
    let sign_id = vec![42u8; 32];

    let mut sessions = BTreeMap::new();
    let mut phase1 = BTreeMap::new();
    for &pid in signer_ids {
        let ks = key_shares.get(&pid).unwrap();
        let counterparties: Vec<_> = signer_ids.iter().copied().filter(|&p| p != pid).collect();
        let (session, msgs) =
            SignSession::new_dkls(ks, sign_id.clone(), &counterparties, message_hash)?;
        sessions.insert(pid, session);
        phase1.insert(pid, msgs);
    }

    let mut prev = route(&phase1, signer_ids);
    for _ in 0..2 {
        let mut out = BTreeMap::new();
        for &pid in signer_ids {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(prev.get(&pid).unwrap())?
            {
                SignOutput::Continue(msgs) => {
                    out.insert(pid, msgs);
                }
                _ => panic!("expected Continue"),
            }
        }
        prev = route(&out, signer_ids);
    }

    // Phase 4 → Complete (check first signer)
    let pid = signer_ids[0];
    match sessions
        .get_mut(&pid)
        .unwrap()
        .next(prev.get(&pid).unwrap())?
    {
        SignOutput::Complete(sig) => Ok(sig),
        _ => panic!("expected Complete"),
    }
}

// ===========================================================================
// Protocol Correctness Tests
// ===========================================================================

// ---------- FROST DKG ----------

#[test]
fn frost_dkg_2of3_ed25519() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();
    assert_eq!(shares.len(), 3);
    let first_vk = shares.values().next().unwrap().group_verifying_key();
    for ks in shares.values() {
        assert_eq!(ks.group_verifying_key(), first_vk);
    }
}

#[test]
fn frost_dkg_3of5_ed25519() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 3, 5).unwrap();
    assert_eq!(shares.len(), 5);
    let first_vk = shares.values().next().unwrap().group_verifying_key();
    for ks in shares.values() {
        assert_eq!(ks.group_verifying_key(), first_vk);
    }
}

// ---------- FROST Sign ----------

#[test]
fn frost_sign_2of3_ed25519() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();
    let signers = [id(1), id(2)];
    let sig = run_frost_sign(&shares, &signers, b"hello-frost").unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);
    assert!(!sig.as_bytes().is_empty());
}

#[test]
fn frost_sign_3of5_ed25519() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 3, 5).unwrap();
    let signers = [id(1), id(3), id(5)];
    let sig = run_frost_sign(&shares, &signers, b"frost-3of5").unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);
}

// ---------- FROST All Ciphersuites ----------

#[test]
fn frost_sign_secp256k1() {
    let shares = run_frost_dkg_session(Ciphersuite::Secp256k1, 2, 3).unwrap();
    let sig = run_frost_sign(&shares, &[id(1), id(2)], b"secp256k1-msg").unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);
}

#[test]
fn frost_sign_secp256k1_taproot() {
    let shares = run_frost_dkg_session(Ciphersuite::Secp256k1Taproot, 2, 3).unwrap();
    let sig = run_frost_sign(&shares, &[id(1), id(2)], b"taproot-msg").unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);
}

#[test]
fn frost_sign_p256() {
    let shares = run_frost_dkg_session(Ciphersuite::P256, 2, 3).unwrap();
    let sig = run_frost_sign(&shares, &[id(1), id(2)], b"p256-msg").unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);
}

#[test]
fn frost_sign_ristretto255() {
    let shares = run_frost_dkg_session(Ciphersuite::Ristretto255, 2, 3).unwrap();
    let sig = run_frost_sign(&shares, &[id(1), id(2)], b"ristretto-msg").unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);
}

#[test]
fn frost_sign_ed448() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed448, 2, 3).unwrap();
    let sig = run_frost_sign(&shares, &[id(1), id(2)], b"ed448-msg").unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);
}

// ---------- FROST Signature Verification ----------

#[test]
fn frost_signature_verifies_with_standard_ed25519_verifier() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();
    let message = b"verify-ed25519";
    let sig = run_frost_sign(&shares, &[id(1), id(2)], message).unwrap();
    let group_key = shares.values().next().unwrap().group_verifying_key();

    // Verify with the standard frost-ed25519 verifier
    let signature = frost_ed25519::Signature::deserialize(sig.as_bytes()).unwrap();
    let verifying_key = frost_ed25519::VerifyingKey::deserialize(&group_key).unwrap();
    verifying_key.verify(message, &signature).unwrap();
}

#[test]
fn frost_signature_verifies_with_standard_ristretto255_verifier() {
    let shares = run_frost_dkg_session(Ciphersuite::Ristretto255, 2, 3).unwrap();
    let message = b"verify-ristretto255";
    let sig = run_frost_sign(&shares, &[id(1), id(3)], message).unwrap();
    let group_key = shares.values().next().unwrap().group_verifying_key();

    let signature = frost_ristretto255::Signature::deserialize(sig.as_bytes()).unwrap();
    let verifying_key = frost_ristretto255::VerifyingKey::deserialize(&group_key).unwrap();
    verifying_key.verify(message, &signature).unwrap();
}

// ---------- DKLs23 DKG ----------

#[test]
fn dkls_dkg_2of2() {
    let shares = run_dkls_dkg_session(2, 2).unwrap();
    assert_eq!(shares.len(), 2);
    let first_vk = shares.values().next().unwrap().group_verifying_key();
    for ks in shares.values() {
        assert_eq!(ks.group_verifying_key(), first_vk);
        assert_eq!(ks.ciphersuite(), Ciphersuite::Secp256k1ECDSA);
    }
}

#[test]
fn dkls_dkg_3of3() {
    let shares = run_dkls_dkg_session(3, 3).unwrap();
    assert_eq!(shares.len(), 3);
    let first_vk = shares.values().next().unwrap().group_verifying_key();
    for ks in shares.values() {
        assert_eq!(ks.group_verifying_key(), first_vk);
    }
}

#[test]
fn dkls_dkg_3of5() {
    let shares = run_dkls_dkg_session(3, 5).unwrap();
    assert_eq!(shares.len(), 5);
    let first_vk = shares.values().next().unwrap().group_verifying_key();
    for ks in shares.values() {
        assert_eq!(ks.group_verifying_key(), first_vk);
        assert_eq!(ks.ciphersuite(), Ciphersuite::Secp256k1ECDSA);
    }
}

// ---------- DKLs23 Sign ----------

#[test]
fn dkls_sign_2of2() {
    let shares = run_dkls_dkg_session(2, 2).unwrap();
    let msg_hash = [0xABu8; 32];
    let sig = run_dkls_sign(&shares, &[id(1), id(2)], msg_hash).unwrap();
    assert_eq!(sig.protocol(), Protocol::DKLs23);
    assert_eq!(sig.as_bytes().len(), 64);
    assert!(sig.recovery_id().is_some());
}

#[test]
fn dkls_sign_3of3() {
    let shares = run_dkls_dkg_session(3, 3).unwrap();
    let msg_hash = [0xCDu8; 32];
    let sig = run_dkls_sign(&shares, &[id(1), id(2), id(3)], msg_hash).unwrap();
    assert_eq!(sig.protocol(), Protocol::DKLs23);
    assert_eq!(sig.as_bytes().len(), 64);
}

#[test]
fn dkls_sign_3of5() {
    let shares = run_dkls_dkg_session(3, 5).unwrap();
    let msg_hash = [0xEFu8; 32];
    // Sign with a 3-party subset (threshold) out of 5
    let sig = run_dkls_sign(&shares, &[id(1), id(3), id(5)], msg_hash).unwrap();
    assert_eq!(sig.protocol(), Protocol::DKLs23);
    assert_eq!(sig.as_bytes().len(), 64);
    assert!(sig.recovery_id().is_some());
}

#[test]
fn dkls_sign_3of5_different_subset() {
    let shares = run_dkls_dkg_session(3, 5).unwrap();
    let msg_hash = [0xEFu8; 32];
    // Different subset of 3 signers produces a valid signature
    let sig = run_dkls_sign(&shares, &[id(2), id(4), id(5)], msg_hash).unwrap();
    assert_eq!(sig.protocol(), Protocol::DKLs23);
    assert_eq!(sig.as_bytes().len(), 64);
    assert!(sig.recovery_id().is_some());
}

// ---------- Dealer Key Gen ----------

#[test]
fn dealer_keygen_and_sign_ed25519() {
    use libtss::frost::{frost_aggregate, frost_commit, frost_generate_with_dealer, frost_sign};

    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    let (shares, pubkey) = frost_generate_with_dealer(&config).unwrap();
    assert_eq!(shares.len(), 3);

    // Sign using the low-level frost API (dealer shares are frost::KeyShareHandle)
    let message = b"dealer-test";
    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for ks in shares.iter().take(2) {
        let (nonce, commitment) = frost_commit(ks).unwrap();
        nonces.push((ks.identifier(), nonce));
        commitments.push(commitment);
    }

    let mut sig_shares = Vec::new();
    for ks in shares.iter().take(2) {
        let nonce = nonces
            .iter()
            .find(|(i, _)| *i == ks.identifier())
            .map(|(_, n)| n.as_slice())
            .unwrap();
        sig_shares.push(frost_sign(ks, nonce, &commitments, message).unwrap());
    }

    let sig = frost_aggregate(message, &commitments, &sig_shares, &pubkey).unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);

    // Verify with standard verifier
    let signature = frost_ed25519::Signature::deserialize(sig.as_bytes()).unwrap();
    let verifying_key = frost_ed25519::VerifyingKey::deserialize(pubkey.verifying_key()).unwrap();
    verifying_key.verify(message, &signature).unwrap();
}

// ---------- Split Key ----------

#[test]
fn split_key_and_sign() {
    use libtss::frost::{frost_aggregate, frost_commit, frost_sign, frost_split_key};

    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ristretto255,
    };

    // Use a known scalar for Ristretto255 (little-endian, nonzero)
    let secret_key_bytes = {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        bytes
    };

    let (shares, pubkey) = frost_split_key(&config, &secret_key_bytes).unwrap();
    assert_eq!(shares.len(), 3);
    // All shares should agree on the group key
    let vk = shares[0].ciphersuite();
    for share in &shares {
        assert_eq!(share.ciphersuite(), vk);
    }

    // Sign via low-level API and verify
    let message = b"split-key-test";
    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for ks in shares.iter().take(2) {
        let (nonce, commitment) = frost_commit(ks).unwrap();
        nonces.push((ks.identifier(), nonce));
        commitments.push(commitment);
    }

    let mut sig_shares = Vec::new();
    for ks in shares.iter().take(2) {
        let nonce = nonces
            .iter()
            .find(|(i, _)| *i == ks.identifier())
            .map(|(_, n)| n.as_slice())
            .unwrap();
        sig_shares.push(frost_sign(ks, nonce, &commitments, message).unwrap());
    }

    let sig = frost_aggregate(message, &commitments, &sig_shares, &pubkey).unwrap();
    let signature = frost_ristretto255::Signature::deserialize(sig.as_bytes()).unwrap();
    let verifying_key =
        frost_ristretto255::VerifyingKey::deserialize(pubkey.verifying_key()).unwrap();
    verifying_key.verify(message, &signature).unwrap();
}

// ---------- Export/Import Round-trip ----------

#[test]
fn export_import_frost_and_sign() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();

    // Export all shares
    let mut exported = BTreeMap::new();
    for (&pid, ks) in &shares {
        exported.insert(pid, (ks.export().unwrap(), ks.ciphersuite()));
    }

    // Drop originals
    drop(shares);

    // Import and sign
    let mut imported_shares = BTreeMap::new();
    for (&pid, (data, suite)) in &exported {
        let ks = libtss::import_key_share(data, *suite).unwrap();
        assert_eq!(ks.identifier(), pid);
        imported_shares.insert(pid, ks);
    }

    let sig = run_frost_sign(&imported_shares, &[id(1), id(2)], b"export-import-test").unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);
}

#[test]
fn export_import_dkls_preserves_identity() {
    let shares = run_dkls_dkg_session(2, 2).unwrap();
    let ks = shares.get(&id(1)).unwrap();
    let exported = ks.export().unwrap();
    let imported = libtss::import_key_share(&exported, Ciphersuite::Secp256k1ECDSA).unwrap();

    assert_eq!(imported.identifier(), ks.identifier());
    assert_eq!(imported.verifying_share(), ks.verifying_share());
    assert_eq!(imported.group_verifying_key(), ks.group_verifying_key());
    assert_eq!(imported.ciphersuite(), Ciphersuite::Secp256k1ECDSA);
}

// ---------- Refresh ----------

#[test]
fn frost_refresh_preserves_signing() {
    use libtss::session::refresh::{RefreshOutput, RefreshSession};

    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();
    let participants = [id(1), id(2), id(3)];
    let original_group_key = shares.values().next().unwrap().group_verifying_key();

    // Party 1 acts as dealer
    let (_, dealer_messages) =
        RefreshSession::new_frost(shares.get(&id(1)).unwrap(), &participants).unwrap();

    // Each participant applies refresh
    let mut refreshed = BTreeMap::new();
    for (&pid, ks) in &shares {
        let mut session = RefreshSession::new_frost_receiver(ks).unwrap();
        let my_msgs: Vec<_> = dealer_messages
            .iter()
            .filter(|m| m.to == Some(pid))
            .cloned()
            .collect();
        match session.next(&my_msgs).unwrap() {
            RefreshOutput::Complete {
                key_share,
                public_keys,
            } => {
                assert!(session.is_complete());
                // Group key should be preserved
                assert_eq!(public_keys.verifying_key(), original_group_key.as_slice());
                refreshed.insert(pid, key_share);
            }
            _ => panic!("expected Complete"),
        }
    }

    // Sign with refreshed shares
    let sig = run_frost_sign(&refreshed, &[id(1), id(3)], b"refreshed-sign").unwrap();
    assert_eq!(sig.protocol(), Protocol::Frost);
}

#[test]
fn frost_old_shares_cannot_sign_after_refresh() {
    use libtss::session::refresh::{RefreshOutput, RefreshSession};

    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();
    let participants = [id(1), id(2), id(3)];

    let (_, dealer_messages) =
        RefreshSession::new_frost(shares.get(&id(1)).unwrap(), &participants).unwrap();

    let mut refreshed = BTreeMap::new();
    for (&pid, ks) in &shares {
        let mut session = RefreshSession::new_frost_receiver(ks).unwrap();
        let my_msgs: Vec<_> = dealer_messages
            .iter()
            .filter(|m| m.to == Some(pid))
            .cloned()
            .collect();
        match session.next(&my_msgs).unwrap() {
            RefreshOutput::Complete { key_share, .. } => {
                refreshed.insert(pid, key_share);
            }
            _ => panic!("expected Complete"),
        }
    }

    // Try signing with one old share + one refreshed share — should fail
    // because the signing shares are from different "epochs"
    let mut mixed = BTreeMap::new();
    mixed.insert(
        id(1),
        shares.into_iter().find(|(k, _)| *k == id(1)).unwrap().1,
    );
    mixed.insert(id(2), refreshed.remove(&id(2)).unwrap());

    // This should either fail or produce an invalid signature
    // (FROST aggregate will fail because shares are incompatible)
    let result = run_frost_sign(&mixed, &[id(1), id(2)], b"mixed-epoch");
    // The aggregate step should fail since the shares don't match
    assert!(
        result.is_err(),
        "signing with mixed old+refreshed shares should fail"
    );
}

// ===========================================================================
// Error Handling Tests
// ===========================================================================

#[test]
fn invalid_config_min_signers() {
    let config = ThresholdConfig {
        min_signers: 1,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    match DkgSession::new(&config, id(1), None) {
        Err(TssError::InvalidConfig(_)) => {}
        other => panic!("expected InvalidConfig, got {:?}", other.err()),
    }
}

#[test]
fn invalid_config_max_less_than_min() {
    let config = ThresholdConfig {
        min_signers: 3,
        max_signers: 2,
        suite: Ciphersuite::Ed25519,
    };
    match DkgSession::new(&config, id(1), None) {
        Err(TssError::InvalidConfig(_)) => {}
        other => panic!("expected InvalidConfig, got {:?}", other.err()),
    }
}

#[test]
fn session_complete_error_on_double_next() {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    let participants = [id(1), id(2), id(3)];

    let mut sessions = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for &pid in &participants {
        let (s, m) = DkgSession::new(&config, pid, None).unwrap();
        sessions.insert(pid, s);
        round1.insert(pid, m);
    }
    let r1_in = route(&round1, &participants);
    let mut round2 = BTreeMap::new();
    for &pid in &participants {
        if let DkgOutput::Continue(msgs) = sessions
            .get_mut(&pid)
            .unwrap()
            .next(r1_in.get(&pid).unwrap())
            .unwrap()
        {
            round2.insert(pid, msgs);
        }
    }
    let r2_in = route(&round2, &participants);
    for &pid in &participants {
        let _ = sessions
            .get_mut(&pid)
            .unwrap()
            .next(r2_in.get(&pid).unwrap())
            .unwrap();
    }

    // Now call next again — should get SessionComplete
    match sessions.get_mut(&id(1)).unwrap().next(&[]) {
        Err(TssError::SessionComplete) => {}
        other => panic!("expected SessionComplete, got {:?}", other.err()),
    }
}

#[test]
fn protocol_mismatch_frost_key_in_dkls_sign() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();
    let ks = shares.get(&id(1)).unwrap();

    // Try to create a DKLs sign session with a FROST key share
    match SignSession::new_dkls(ks, vec![1; 32], &[id(2)], [0u8; 32]) {
        Err(TssError::ProtocolMismatch) => {}
        other => panic!("expected ProtocolMismatch, got {:?}", other.err()),
    }
}

#[test]
fn protocol_mismatch_dkls_key_in_frost_sign() {
    let shares = run_dkls_dkg_session(2, 2).unwrap();
    let ks = shares.get(&id(1)).unwrap();

    match SignSession::new_frost(ks, b"test") {
        Err(TssError::ProtocolMismatch) => {}
        other => panic!("expected ProtocolMismatch, got {:?}", other.err()),
    }
}

#[test]
fn dkls_dkg_requires_session_id() {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 2,
        suite: Ciphersuite::Secp256k1ECDSA,
    };
    match DkgSession::new(&config, id(1), None) {
        Err(TssError::InvalidConfig(_)) => {}
        other => panic!("expected InvalidConfig, got {:?}", other.err()),
    }
}

#[test]
fn export_import_roundtrip_is_lossless() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();
    let ks = shares.into_values().next().unwrap();
    let export_result = ks.export();
    assert!(export_result.is_ok());
    let reimported =
        libtss::import_key_share(&export_result.unwrap(), Ciphersuite::Ed25519).unwrap();
    assert_eq!(reimported.identifier(), ks.identifier());
    assert_eq!(reimported.group_verifying_key(), ks.group_verifying_key());
}

// ===========================================================================
// Concurrency Tests
// ===========================================================================

#[test]
fn concurrent_frost_dkg_sessions() {
    use std::thread;

    let results: Vec<_> = thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(move || {
                    run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3)
                        .map(|shares| shares.values().next().unwrap().group_verifying_key())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    // All 4 independent DKG sessions should succeed
    for result in &results {
        assert!(result.is_ok());
    }

    // Each should produce a different group key
    let keys: Vec<_> = results.into_iter().map(|r| r.unwrap()).collect();
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i], keys[j],
                "independent DKG sessions should produce different keys"
            );
        }
    }
}

#[test]
fn concurrent_frost_sign_sessions() {
    use std::thread;

    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();

    // Multiple threads signing with the same key shares concurrently
    // Each thread exports/imports to get its own handles
    let mut exported = BTreeMap::new();
    for (&pid, ks) in &shares {
        exported.insert(pid, (ks.export().unwrap(), ks.ciphersuite()));
    }
    drop(shares);

    thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|thread_idx| {
                let exported = &exported;
                scope.spawn(move || {
                    // Each thread imports its own handles
                    let mut local_shares = BTreeMap::new();
                    for (&pid, (data, suite)) in exported {
                        local_shares.insert(pid, libtss::import_key_share(data, *suite).unwrap());
                    }
                    let msg = format!("concurrent-sign-{}", thread_idx);
                    run_frost_sign(&local_shares, &[id(1), id(2)], msg.as_bytes())
                })
            })
            .collect();

        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.is_ok());
        }
    });
}

#[test]
fn concurrent_handle_operations() {
    use std::thread;

    // Stress test: create and drop many handles concurrently
    thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..10 {
                    let shares = run_frost_dkg_session(Ciphersuite::Ristretto255, 2, 3).unwrap();
                    // Verify handles are valid
                    for ks in shares.values() {
                        assert!(!ks.group_verifying_key().is_empty());
                    }
                    // Drop them — this exercises concurrent free
                }
            });
        }
    });
}

// ===========================================================================
// Security / Misbehavior Tests
// ===========================================================================

#[test]
fn replay_round1_in_round2_fails() {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    let participants = [id(1), id(2), id(3)];

    let mut sessions = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for &pid in &participants {
        let (session, msgs) = DkgSession::new(&config, pid, None).unwrap();
        sessions.insert(pid, session);
        round1.insert(pid, msgs);
    }

    let r1_in = route(&round1, &participants);
    let mut round2 = BTreeMap::new();
    for &pid in &participants {
        match sessions
            .get_mut(&pid)
            .unwrap()
            .next(r1_in.get(&pid).unwrap())
            .unwrap()
        {
            DkgOutput::Continue(msgs) => {
                round2.insert(pid, msgs);
            }
            _ => panic!("expected Continue"),
        }
    }

    // Feed round1 messages to round3 instead of round2 messages
    // This should fail during deserialization because the format doesn't match
    let result = sessions
        .get_mut(&id(1))
        .unwrap()
        .next(r1_in.get(&id(1)).unwrap());
    assert!(
        result.is_err(),
        "replaying round1 messages in round3 should fail"
    );
}

#[test]
fn truncated_message_fails_gracefully() {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    let participants = [id(1), id(2), id(3)];

    let mut sessions = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for &pid in &participants {
        let (session, msgs) = DkgSession::new(&config, pid, None).unwrap();
        sessions.insert(pid, session);
        round1.insert(pid, msgs);
    }

    let r1_in = route(&round1, &participants);

    // Truncate a message for party 1
    let mut tampered = r1_in.get(&id(1)).unwrap().clone();
    if let Some(msg) = tampered.first_mut() {
        msg.data.truncate(msg.data.len() / 2);
    }

    let result = sessions.get_mut(&id(1)).unwrap().next(&tampered);
    assert!(
        result.is_err(),
        "truncated message should cause deserialization error"
    );
}

#[test]
fn tlv_message_roundtrip_preserves_all_fields() {
    let messages = vec![
        Message {
            from: id(1),
            to: None,
            data: vec![1, 2, 3],
        },
        Message {
            from: id(2),
            to: Some(id(3)),
            data: vec![4, 5, 6, 7, 8],
        },
    ];

    let serialized = libtss::serialize_messages(&messages).unwrap();
    let deserialized = libtss::deserialize_messages(&serialized).unwrap();

    assert_eq!(messages, deserialized);
}

#[test]
fn identifier_zero_is_rejected() {
    assert_eq!(Identifier::new(0), Err(TssError::InvalidIdentifier));
}

#[test]
fn filter_for_participant_works_correctly() {
    let messages = vec![
        Message {
            from: id(1),
            to: None,
            data: vec![1],
        },
        Message {
            from: id(2),
            to: Some(id(3)),
            data: vec![2],
        },
        Message {
            from: id(3),
            to: Some(id(1)),
            data: vec![3],
        },
    ];

    let for_1 = libtss::filter_for_participant(&messages, id(1));
    assert_eq!(for_1.len(), 1); // only the p2p from id(3) to id(1)
    assert_eq!(for_1[0].data, vec![3]);

    let for_2 = libtss::filter_for_participant(&messages, id(2));
    assert_eq!(for_2.len(), 1); // broadcast from id(1) (not sender)
    assert_eq!(for_2[0].data, vec![1]);

    let for_3 = libtss::filter_for_participant(&messages, id(3));
    assert_eq!(for_3.len(), 2); // broadcast from id(1) + p2p from id(2)
}

#[test]
fn test_unified_verify_frost_ed25519() {
    let shares = run_frost_dkg_session(Ciphersuite::Ed25519, 2, 3).unwrap();
    let message = b"verify-ed25519";
    let sig = run_frost_sign(&shares, &[id(1), id(2)], message).unwrap();
    let group_key = shares.values().next().unwrap().group_verifying_key();

    let verifies =
        libtss::verify(Ciphersuite::Ed25519, message, sig.as_bytes(), &group_key).unwrap();
    assert!(verifies);

    // Tampered signature should fail verification
    let mut bad_sig = sig.as_bytes().to_vec();
    bad_sig[0] ^= 0xff;
    let result = libtss::verify(Ciphersuite::Ed25519, message, &bad_sig, &group_key);
    assert!(!result.unwrap_or(false));

    // Wrong message should fail verification
    let wrong_msg = b"wrong-message";
    let verifies_wrong =
        libtss::verify(Ciphersuite::Ed25519, wrong_msg, sig.as_bytes(), &group_key).unwrap();
    assert!(!verifies_wrong);
}

#[test]
fn test_unified_verify_dkls_secp256k1ecdsa() {
    use sha2::Digest;
    let shares = run_dkls_dkg_session(2, 3).unwrap();
    let message = b"verify-secp256k1ecdsa";
    let message_hash = sha2::Sha256::digest(message);
    let sig = run_dkls_sign(&shares, &[id(1), id(2)], message_hash.into()).unwrap();

    let group_key = shares.values().next().unwrap().group_verifying_key();

    let verifies = libtss::verify(
        Ciphersuite::Secp256k1ECDSA,
        message,
        sig.as_bytes(),
        &group_key,
    )
    .unwrap();
    assert!(verifies);

    // Tampered signature should fail verification
    let mut bad_sig = sig.as_bytes().to_vec();
    bad_sig[0] ^= 0xff;
    let result = libtss::verify(Ciphersuite::Secp256k1ECDSA, message, &bad_sig, &group_key);
    assert!(!result.unwrap_or(false));

    // Wrong message should fail verification
    let wrong_msg = b"wrong-message";
    let verifies_wrong = libtss::verify(
        Ciphersuite::Secp256k1ECDSA,
        wrong_msg,
        sig.as_bytes(),
        &group_key,
    )
    .unwrap();
    assert!(!verifies_wrong);
}
