//! End-to-end: a 3-of-5 DKLs23 group loses party 2's share, three survivors
//! repair it into a hollow share, a complete refresh across all five parties
//! turns it back into a signing share, and quorums with and without the
//! original survivors sign under the unchanged group key.

use std::collections::BTreeMap;

use libtss::session::dkg::{DkgOutput, DkgSession};
use libtss::session::refresh::{RefreshOutput, RefreshSession};
use libtss::session::sign::{SignOutput, SignSession};
use libtss::types::{Ciphersuite, Identifier, ThresholdConfig};
use libtss::{repair_assemble, repair_helper_term, KeyShareHandle, Message, TssError};
use sha2::Digest;

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

fn run_dkg(threshold: u16, share_count: u16) -> BTreeMap<Identifier, KeyShareHandle> {
    let config = ThresholdConfig {
        min_signers: threshold,
        max_signers: share_count,
        suite: Ciphersuite::Secp256k1ECDSA,
    };
    let participants: Vec<Identifier> = (1..=share_count).map(id).collect();
    let mut sessions = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    for &pid in &participants {
        let (session, messages) = DkgSession::new(&config, pid, Some(b"e2e-dkg")).unwrap();
        sessions.insert(pid, session);
        outputs.insert(pid, messages);
    }

    let mut shares = BTreeMap::new();
    while shares.len() < participants.len() {
        let inputs = route(&outputs, &participants);
        outputs = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(inputs.get(&pid).unwrap())
                .unwrap()
            {
                DkgOutput::Continue(messages) => {
                    outputs.insert(pid, messages);
                }
                DkgOutput::Complete { key_share, .. } => {
                    shares.insert(pid, key_share);
                }
            }
        }
    }
    shares
}

fn run_refresh(
    shares: &BTreeMap<Identifier, KeyShareHandle>,
    session_id: &[u8],
) -> BTreeMap<Identifier, KeyShareHandle> {
    let participants: Vec<Identifier> = shares.keys().copied().collect();
    let mut sessions = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    for &pid in &participants {
        let (session, messages) = RefreshSession::new_dkls(&shares[&pid], session_id).unwrap();
        sessions.insert(pid, session);
        outputs.insert(pid, messages);
    }

    let mut refreshed = BTreeMap::new();
    while refreshed.len() < participants.len() {
        let inputs = route(&outputs, &participants);
        outputs = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(inputs.get(&pid).unwrap())
                .unwrap()
            {
                RefreshOutput::Continue(messages) => {
                    outputs.insert(pid, messages);
                }
                RefreshOutput::Complete { key_share, .. } => {
                    refreshed.insert(pid, key_share);
                }
            }
        }
    }
    refreshed
}

fn run_sign(
    shares: &BTreeMap<Identifier, KeyShareHandle>,
    signers: &[Identifier],
    message: &[u8],
) -> Result<Vec<u8>, TssError> {
    let hash: [u8; 32] = sha2::Sha256::digest(message).into();
    let mut sessions = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    for &pid in signers {
        let counterparties: Vec<Identifier> =
            signers.iter().copied().filter(|c| *c != pid).collect();
        let (session, messages) =
            SignSession::new_dkls(&shares[&pid], b"e2e-sign".to_vec(), &counterparties, hash)?;
        sessions.insert(pid, session);
        outputs.insert(pid, messages);
    }

    loop {
        let inputs = route(&outputs, signers);
        outputs = BTreeMap::new();
        for &pid in signers {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(inputs.get(&pid).unwrap())?
            {
                SignOutput::Continue(messages) => {
                    outputs.insert(pid, messages);
                }
                SignOutput::Complete(signature) => return Ok(signature.as_bytes().to_vec()),
            }
        }
    }
}

#[test]
fn repair_then_refresh_restores_a_signing_group() {
    let original = run_dkg(3, 5);
    let group_key = original[&id(1)].group_verifying_key();
    let chain_code = original[&id(1)].chain_code().unwrap();
    let lost_verifying_share = original[&id(2)].verifying_share();

    let mut survivors = original;
    survivors.remove(&id(2));

    let helpers = [id(1), id(3), id(4)];
    let repair_sid = b"e2e-repair-sid";
    let terms: Vec<_> = helpers
        .iter()
        .map(|helper| repair_helper_term(&survivors[helper], &helpers, id(2), repair_sid).unwrap())
        .collect();
    let term_slices: Vec<&[u8]> = terms.iter().map(|term| term.as_slice()).collect();
    let hollow = repair_assemble(
        Ciphersuite::Secp256k1ECDSA,
        survivors[&id(1)].public_key_package(),
        &chain_code,
        id(2),
        &term_slices,
        repair_sid,
    )
    .unwrap();

    assert_eq!(hollow.identifier(), id(2));
    assert_eq!(hollow.verifying_share(), lost_verifying_share);
    assert_eq!(hollow.group_verifying_key(), group_key);

    let mut pre_refresh = survivors;
    pre_refresh.insert(id(2), hollow);
    assert_eq!(
        run_sign(&pre_refresh, &[id(1), id(2), id(3)], b"before refresh").unwrap_err(),
        TssError::InvalidShare
    );

    let refreshed = run_refresh(&pre_refresh, b"e2e-refresh-sid");

    for (pid, share) in &refreshed {
        assert_eq!(share.identifier(), *pid);
        assert_eq!(share.group_verifying_key(), group_key);
        assert_eq!(share.chain_code().unwrap(), chain_code);
        assert_ne!(share.verifying_share(), pre_refresh[pid].verifying_share());
    }

    let message = b"after refresh";
    for signers in [[id(1), id(2), id(3)], [id(2), id(4), id(5)]] {
        let signature = run_sign(&refreshed, &signers, message).unwrap();
        assert!(
            libtss::verify(Ciphersuite::Secp256k1ECDSA, message, &signature, &group_key).unwrap(),
            "quorum {signers:?} must sign under the original group key"
        );
    }
}
