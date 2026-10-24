//! DKLs23 payloads carry their own sender/receiver fields. These tests change
//! those fields (or inject messages from parties outside the session) while
//! keeping the envelope `from`, and check that every honest receiver rejects
//! the message and blames the envelope sender, for DKG, signing and refresh
//! on both curves.

use std::collections::BTreeMap;

use dkls23_secp256k1::curve::DklsCurve;
use dkls23_secp256k1::protocols::dkg::{
    BroadcastDerivationPhase3to4, ProofCommitment, TransmitInitMulPhase3to4,
    TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23_secp256k1::protocols::messages::MessageTag;
use dkls23_secp256k1::protocols::signing::{TransmitPhase1to2, TransmitPhase2to3};
use dkls23_secp256k1::protocols::{Parameters, PartyIndex};

use crate::keyshare::{self, KeyShareHandle};
use crate::message::Message;
use crate::session::dkg::{DkgOutput, DkgSession};
use crate::session::refresh::{RefreshOutput, RefreshSession};
use crate::session::sign::{SignOutput, SignSession};
use crate::types::{Ciphersuite, Identifier, ThresholdConfig};
use crate::TssError;

type K1 = k256::Secp256k1;
type R1 = p256::NistP256;

fn id(value: u16) -> Identifier {
    Identifier::new(value).unwrap()
}

fn index(value: u8) -> PartyIndex {
    PartyIndex::new(value).unwrap()
}

/// One protocol step: `Some(messages)` to continue, `None` when complete.
type Step<'a> = Box<dyn FnMut(&[Message]) -> Result<Option<Vec<Message>>, TssError> + 'a>;
type Tamper<'a> = dyn Fn(usize, Identifier, &mut Vec<Message>) + 'a;

/// Runs a protocol, letting `tamper` rewrite each party's outgoing messages
/// per round (1 = the constructor's messages). Stops after the first round in
/// which any party fails and returns each party's error from that round.
fn run(
    parties: Vec<(Identifier, Vec<Message>, Step<'_>)>,
    tamper: &Tamper<'_>,
) -> BTreeMap<Identifier, TssError> {
    let ids: Vec<Identifier> = parties.iter().map(|(pid, _, _)| *pid).collect();
    let mut steps: BTreeMap<Identifier, Step<'_>> = BTreeMap::new();
    let mut outgoing: BTreeMap<Identifier, Vec<Message>> = BTreeMap::new();
    for (pid, messages, step) in parties {
        steps.insert(pid, step);
        outgoing.insert(pid, messages);
    }

    let mut round = 1;
    loop {
        let mut all: Vec<Message> = Vec::new();
        for (&pid, messages) in outgoing.iter_mut() {
            tamper(round, pid, messages);
            all.append(messages);
        }

        let mut errors = BTreeMap::new();
        let mut next_out = BTreeMap::new();
        let mut complete = 0;
        for &pid in &ids {
            let received: Vec<Message> = all
                .iter()
                .filter(|m| m.for_participant(pid))
                .cloned()
                .collect();
            match steps.get_mut(&pid).unwrap()(&received) {
                Ok(Some(messages)) => {
                    next_out.insert(pid, messages);
                }
                Ok(None) => complete += 1,
                Err(err) => {
                    errors.insert(pid, err);
                }
            }
        }
        if !errors.is_empty() || complete == ids.len() {
            return errors;
        }
        assert_eq!(complete, 0, "parties completed in different rounds");
        outgoing = next_out;
        round += 1;
    }
}

/// Rewrites every `T` frame in `data` with `edit`; returns whether one was found.
fn rewrite_frames<T: MessageTag>(data: &mut Vec<u8>, edit: &dyn Fn(&mut T)) -> bool {
    let mut out = Vec::with_capacity(data.len());
    let mut found = false;
    let mut offset = 0;
    while offset < data.len() {
        let tag = data[offset];
        let len = u32::from_be_bytes(data[offset + 1..offset + 5].try_into().unwrap()) as usize;
        let frame = &data[offset..offset + 5 + len];
        if tag == T::TAG {
            let mut value: T = postcard::from_bytes(&frame[5..]).unwrap();
            edit(&mut value);
            let payload = postcard::to_allocvec(&value).unwrap();
            out.push(tag);
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(&payload);
            found = true;
        } else {
            out.extend_from_slice(frame);
        }
        offset += 5 + len;
    }
    *data = out;
    found
}

/// A tamper hook that edits the `T` payloads `from` sends in `round`.
fn edit<T: MessageTag + 'static>(
    round: usize,
    from: Identifier,
    edit: impl Fn(&mut T) + 'static,
) -> Box<Tamper<'static>> {
    Box::new(move |r, pid, messages: &mut Vec<Message>| {
        if r != round || pid != from {
            return;
        }
        let mut found = false;
        for message in messages.iter_mut() {
            found |= rewrite_frames::<T>(&mut message.data, &edit);
        }
        assert!(found, "no frame to tamper with in round {round}");
    })
}

/// Expects every party other than `culprit` to fail, blaming `culprit`.
fn assert_blamed(errors: &BTreeMap<Identifier, TssError>, honest: &[Identifier], culprit: u16) {
    for pid in honest {
        match errors.get(pid) {
            Some(TssError::Abort { culprits, .. }) => {
                assert_eq!(culprits, &[id(culprit)], "party {pid:?}: {:?}", errors[pid]);
            }
            other => panic!("party {pid:?}: expected abort blaming {culprit}, got {other:?}"),
        }
    }
}

fn dkg_parties(suite: Ciphersuite) -> Vec<(Identifier, Vec<Message>, Step<'static>)> {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite,
    };
    [id(1), id(2), id(3)]
        .into_iter()
        .map(|pid| {
            let (mut session, messages) =
                DkgSession::new(&config, pid, Some(b"identity-dkg")).unwrap();
            let step: Step<'static> = Box::new(move |rx: &[Message]| match session.next(rx)? {
                DkgOutput::Continue(m) => Ok(Some(m)),
                DkgOutput::Complete { .. } => Ok(None),
            });
            (pid, messages, step)
        })
        .collect()
}

fn dkg_cases<C: DklsCurve>(suite: Ciphersuite)
where
    ProofCommitment<C>: MessageTag + 'static,
    TransmitInitMulPhase3to4<C>: MessageTag + 'static,
{
    // Each DKG run is slow in debug builds, so the cases cover each round and
    // each kind of identity field rather than every payload type. The
    // untampered flow is covered by the session tests.
    let honest = [id(1), id(2)];
    let cases: Vec<Box<Tamper<'static>>> = vec![
        edit::<ProofCommitment<C>>(2, id(3), |m| m.index = index(2)),
        edit::<TransmitInitZeroSharePhase2to4>(2, id(3), |m| {
            m.parties.receiver = index(3);
        }),
        edit::<BroadcastDerivationPhase3to4>(3, id(3), |m| m.sender_index = index(2)),
        edit::<TransmitInitMulPhase3to4<C>>(3, id(3), |m| m.parties.sender = index(2)),
    ];
    for tamper in cases {
        let errors = run(dkg_parties(suite), tamper.as_ref());
        assert_blamed(&errors, &honest, 3);
    }

    // A party outside the group cannot inject messages.
    let errors = run(dkg_parties(suite), &|round, pid, messages| {
        if round == 2 && pid == id(3) {
            let mut extra = messages[0].clone();
            extra.from = id(4);
            messages.push(extra);
        }
    });
    assert_blamed(&errors, &[id(1), id(2), id(3)], 4);
}

#[test]
fn dkg_payload_identities_secp256k1() {
    dkg_cases::<K1>(Ciphersuite::Secp256k1ECDSA);
}

#[test]
fn dkg_payload_identities_secp256r1() {
    dkg_cases::<R1>(Ciphersuite::Secp256r1ECDSA);
}

fn key_shares(suite: Ciphersuite) -> Vec<KeyShareHandle> {
    let parameters = Parameters::new(2, 3).unwrap();
    match suite {
        Ciphersuite::Secp256k1ECDSA => {
            let (parties, package) = dkls23_secp256k1::protocols::re_key::re_key(
                &parameters,
                b"identity",
                &k256::Scalar::from(21u64),
                Some([4u8; 32]),
                dkls23_secp256k1::compute_eth_address,
            );
            parties
                .into_iter()
                .map(|party| keyshare::from_dkls_dkg(party, package.clone()).unwrap())
                .collect()
        }
        Ciphersuite::Secp256r1ECDSA => {
            let (parties, package) = dkls23_secp256r1::protocols::re_key::re_key(
                &parameters,
                b"identity",
                &p256::Scalar::from(21u64),
                Some([4u8; 32]),
                dkls23_secp256r1::compute_neo3_address,
            );
            parties
                .into_iter()
                .map(|party| keyshare::from_dkls_r1_dkg(party, package.clone()).unwrap())
                .collect()
        }
        _ => unreachable!(),
    }
}

fn sign_parties(
    shares: &[KeyShareHandle],
    signers: &[Identifier],
) -> Vec<(Identifier, Vec<Message>, Step<'static>)> {
    signers
        .iter()
        .map(|&pid| {
            let share = shares.iter().find(|s| s.identifier() == pid).unwrap();
            let counterparties: Vec<_> = signers.iter().copied().filter(|&p| p != pid).collect();
            let hash = [9u8; 32];
            let (mut session, messages) = match share.ciphersuite() {
                Ciphersuite::Secp256k1ECDSA => {
                    SignSession::new_dkls(share, vec![1; 32], &counterparties, hash)
                }
                _ => SignSession::new_dkls_r1(share, vec![1; 32], &counterparties, hash),
            }
            .unwrap();
            let step: Step<'static> = Box::new(move |rx: &[Message]| match session.next(rx)? {
                SignOutput::Continue(m) => Ok(Some(m)),
                SignOutput::Complete(_) => Ok(None),
            });
            (pid, messages, step)
        })
        .collect()
}

fn sign_cases<C: DklsCurve>(suite: Ciphersuite)
where
    TransmitPhase2to3<C>: MessageTag + 'static,
{
    let shares = key_shares(suite);
    let signers = [id(1), id(2)];
    assert!(run(sign_parties(&shares, &signers), &|_, _, _| {}).is_empty());

    let cases: Vec<Box<Tamper<'static>>> = vec![
        // Signer 2's payloads claim to come from party 3.
        edit::<TransmitPhase1to2>(1, id(2), |m| m.parties.sender = index(3)),
        edit::<TransmitPhase1to2>(1, id(2), |m| m.parties.receiver = index(3)),
        edit::<TransmitPhase2to3<C>>(2, id(2), |m| m.parties.sender = index(3)),
        edit::<TransmitPhase2to3<C>>(2, id(2), |m| m.parties.receiver = index(2)),
    ];
    for tamper in cases {
        let errors = run(sign_parties(&shares, &signers), tamper.as_ref());
        assert_blamed(&errors, &[id(1)], 2);
    }

    // A non-signer's messages are rejected in every round, including the
    // final broadcasts that are summed into the signature.
    for round in 1..=3 {
        let errors = run(sign_parties(&shares, &signers), &|r, pid, messages| {
            if r == round && pid == id(2) {
                let mut extra = messages[0].clone();
                extra.from = id(3);
                messages.push(extra);
            }
        });
        // Rounds 1 and 2 are point-to-point (to signer 1); round 3 is a broadcast.
        let receivers: &[Identifier] = if round == 3 { &signers } else { &signers[..1] };
        assert_blamed(&errors, receivers, 3);
    }

    // A missing counterparty broadcast is an error, not a smaller sum.
    let errors = run(sign_parties(&shares, &signers), &|round, pid, messages| {
        if round == 3 && pid == id(2) {
            messages.clear();
        }
    });
    assert!(matches!(
        errors.get(&id(1)),
        Some(TssError::DeserializeFailed(_))
    ));
}

#[test]
fn sign_payload_identities_secp256k1() {
    sign_cases::<K1>(Ciphersuite::Secp256k1ECDSA);
}

#[test]
fn sign_payload_identities_secp256r1() {
    sign_cases::<R1>(Ciphersuite::Secp256r1ECDSA);
}

fn refresh_parties(shares: &[KeyShareHandle]) -> Vec<(Identifier, Vec<Message>, Step<'_>)> {
    shares
        .iter()
        .map(|share| {
            let (mut session, messages) =
                RefreshSession::new_dkls(share, b"identity-refresh").unwrap();
            let step: Step<'_> = Box::new(move |rx: &[Message]| match session.next(rx)? {
                RefreshOutput::Continue(m) => Ok(Some(m)),
                RefreshOutput::Complete { .. } => Ok(None),
            });
            (share.identifier(), messages, step)
        })
        .collect()
}

fn refresh_cases<C: DklsCurve>(suite: Ciphersuite)
where
    ProofCommitment<C>: MessageTag + 'static,
    TransmitInitMulPhase3to4<C>: MessageTag + 'static,
{
    let shares = key_shares(suite);
    let honest = [id(1), id(2)];
    let cases: Vec<Box<Tamper<'static>>> = vec![
        edit::<ProofCommitment<C>>(2, id(3), |m| m.index = index(2)),
        edit::<TransmitInitZeroSharePhase3to4>(3, id(3), |m| m.parties.receiver = index(3)),
    ];
    for tamper in cases {
        let errors = run(refresh_parties(&shares), tamper.as_ref());
        assert_blamed(&errors, &honest, 3);
    }
}

#[test]
fn refresh_payload_identities_secp256k1() {
    refresh_cases::<K1>(Ciphersuite::Secp256k1ECDSA);
}

#[test]
fn refresh_payload_identities_secp256r1() {
    refresh_cases::<R1>(Ciphersuite::Secp256r1ECDSA);
}
