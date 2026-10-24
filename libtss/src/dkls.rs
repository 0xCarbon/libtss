use std::collections::BTreeMap;

use dkls23_secp256k1::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, TransmitInitZeroSharePhase2to4,
    TransmitInitZeroSharePhase3to4,
};
use dkls23_secp256k1::protocols::messages::{MessageTag, PhaseInput};
use dkls23_secp256k1::protocols::signature::EcdsaSignature;
use dkls23_secp256k1::protocols::signing::SignData;
use dkls23_secp256k1::protocols::{
    Abort, AbortKind, AbortReason, Parameters, PartiesMessage, PartyIndex,
};
use dkls23_secp256k1::{Party, PublicKeyPackage as DklsPublicKeyPackage};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::Scalar;
use zeroize::Zeroizing;

type Secp256k1 = k256::Secp256k1;
type DkgSession = dkls23_secp256k1::DkgSession<Secp256k1>;
type SignSession<'a> = dkls23_secp256k1::SignSession<'a, Secp256k1>;
type ProofCommitment = dkls23_secp256k1::protocols::dkg::ProofCommitment<Secp256k1>;
type TransmitPhase1to2 = dkls23_secp256k1::protocols::signing::TransmitPhase1to2;
type TransmitPhase2to3 = dkls23_secp256k1::protocols::signing::TransmitPhase2to3<Secp256k1>;
type Broadcast3to4 = dkls23_secp256k1::protocols::signing::Broadcast3to4<Secp256k1>;
type TransmitInitMulPhase3to4 =
    dkls23_secp256k1::protocols::dkg::TransmitInitMulPhase3to4<Secp256k1>;

use crate::dkls_messages::{
    scalar_from_message, scalar_to_message, Outgoing, SecretInput, SecretScalars,
};
use crate::error::TssError;
use crate::message::Message;
use crate::types::{
    Ciphersuite, Identifier, Protocol, PublicKeyPackage as UnifiedPublicKeyPackage, Signature,
};

pub struct DklsDkgState {
    pub(crate) session: DkgSession,
    pub(crate) self_id: Identifier,
    pub(crate) share_count: u8,
    pub(crate) self_fragment: Option<Zeroizing<Scalar>>,
    pub(crate) self_proof_commitment: Option<ProofCommitment>,
    pub(crate) self_bip_phase2: Option<BroadcastDerivationPhase2to4>,
    pub(crate) self_bip_phase3: Option<BroadcastDerivationPhase3to4>,
    pub(crate) phase2_input: Option<SecretInput>,
}

pub struct DklsSignState<'a> {
    pub(crate) session: SignSession<'a>,
    pub(crate) self_id: Identifier,
    pub(crate) counterparties: Vec<u8>,
    pub(crate) self_broadcast: Option<Broadcast3to4>,
}

pub(crate) fn identifier_to_party_index(id: Identifier) -> Result<PartyIndex, TssError> {
    let value = u8::try_from(id.as_u16()).map_err(|_| TssError::InvalidIdentifier)?;
    PartyIndex::new(value).map_err(|_| TssError::InvalidIdentifier)
}

pub(crate) fn identifier_to_session_party_index(
    id: Identifier,
    share_count: u8,
) -> Result<PartyIndex, TssError> {
    let index = identifier_to_party_index(id)?;
    if index.as_u8() > share_count {
        return Err(TssError::InvalidIdentifier);
    }
    Ok(index)
}

pub(crate) fn party_index_to_identifier(index: PartyIndex) -> Result<Identifier, TssError> {
    Identifier::new(u16::from(index.as_u8()))
}

/// The counterparty a recoverable abort accuses, if any. `Abort.index` is
/// the party reporting the abort, never the culprit. Local-state errors and
/// session mismatches accuse no one.
pub(crate) fn accused(reason: &AbortReason) -> Option<PartyIndex> {
    match reason {
        AbortReason::ProofVerificationFailed { counterparty, .. }
        | AbortReason::CommitmentMismatch { counterparty, .. }
        | AbortReason::TrivialInstancePoint { counterparty, .. }
        | AbortReason::OtConsistencyCheckFailed { counterparty, .. }
        | AbortReason::MultiplicationVerificationFailed { counterparty, .. }
        | AbortReason::GammaUInconsistency { counterparty, .. }
        | AbortReason::ZeroShareDecommitFailed { counterparty, .. } => Some(*counterparty),
        AbortReason::ChainCodeCommitmentFailed { party, .. }
        | AbortReason::MissingMessageFromParty { party, .. } => Some(*party),
        AbortReason::UnexpectedSender { sender, .. }
        | AbortReason::DuplicateSender { sender, .. } => Some(*sender),
        _ => None,
    }
}

pub(crate) fn abort_to_error(abort: Abort) -> TssError {
    match abort.kind {
        AbortKind::Recoverable => TssError::Abort {
            culprits: accused(&abort.reason)
                .and_then(|index| party_index_to_identifier(index).ok())
                .into_iter()
                .collect(),
            message: abort.description(),
            ban: None,
        },
        AbortKind::BanCounterparty(counterparty) => {
            let ban = party_index_to_identifier(counterparty).ok();
            TssError::Abort {
                culprits: ban.into_iter().collect(),
                message: abort.description(),
                ban,
            }
        }
    }
}

/// An error blaming `sender` (the authenticated envelope sender) for a
/// message it should not have sent.
fn sender_error(sender: u8, message: &str) -> TssError {
    match Identifier::new(u16::from(sender)) {
        Ok(id) => identifier_error(id, message),
        Err(_) => TssError::Abort {
            culprits: Vec::new(),
            message: format!("party {sender}: {message}"),
            ban: None,
        },
    }
}

/// An abort naming `sender` (the authenticated envelope sender).
pub(crate) fn identifier_error(sender: Identifier, message: &str) -> TssError {
    TssError::Abort {
        culprits: vec![sender],
        message: format!("party {}: {message}", sender.as_u16()),
        ban: None,
    }
}

/// Whether `message` is for `self_id` and from another party. Messages for
/// other receivers and this party's own messages echoed back by the
/// transport are skipped.
pub(crate) fn is_inbound(message: &Message, self_id: Identifier) -> bool {
    message.from != self_id && message.to.is_none_or(|receiver| receiver == self_id)
}

/// The zero-based position of the sender of a phase-1 fragment addressed to
/// `self_id`, or `None` for a message to skip. A sender outside
/// `1..=share_count` is an abort naming it.
pub(crate) fn fragment_sender(
    message: &Message,
    self_id: Identifier,
    share_count: u8,
) -> Result<Option<usize>, TssError> {
    if message.to != Some(self_id) || message.from == self_id {
        return Ok(None);
    }
    let index = identifier_to_session_party_index(message.from, share_count)
        .map_err(|_| identifier_error(message.from, "unexpected sender"))?;
    Ok(Some(usize::from(index.as_u8() - 1)))
}

/// Every party in `1..=share_count` except `self_index`.
pub(crate) fn other_parties(share_count: u8, self_index: PartyIndex) -> Vec<u8> {
    (1..=share_count)
        .filter(|&party| party != self_index.as_u8())
        .collect()
}

/// Checks a payload's internal sender and receiver against the authenticated
/// envelope sender and the local party.
pub(crate) fn check_parties(
    parties: &PartiesMessage,
    sender: u8,
    receiver: PartyIndex,
) -> Result<(), TssError> {
    if parties.sender.as_u8() != sender || parties.receiver != receiver {
        return Err(sender_error(
            sender,
            "payload sender or receiver does not match the message envelope",
        ));
    }
    Ok(())
}

/// Checks a payload's internal party index against the authenticated
/// envelope sender.
pub(crate) fn check_sender_index(index: PartyIndex, sender: u8) -> Result<(), TssError> {
    if index.as_u8() != sender {
        return Err(sender_error(
            sender,
            "payload party index does not match the message envelope",
        ));
    }
    Ok(())
}

/// Groups the messages for `self_id` by sender. Every broadcast and every
/// message addressed to `self_id` must come from one of `expected`
/// (`from` is the authenticated sender); any other sender is an abort naming
/// it. Messages for other receivers and this party's own messages echoed
/// back by the transport are ignored.
pub(crate) fn messages_to_phase_input(
    messages: &[Message],
    self_id: Identifier,
    expected: &[u8],
) -> Result<SecretInput, TssError> {
    let mut inbound = Vec::new();
    for message in messages.iter().filter(|m| is_inbound(m, self_id)) {
        let sender = u8::try_from(message.from.as_u16())
            .ok()
            .filter(|sender| expected.contains(sender))
            .ok_or_else(|| identifier_error(message.from, "unexpected sender"))?;
        inbound.push((sender, message));
    }
    Ok(SecretInput::collect(inbound.into_iter()))
}

pub(crate) fn message_error(error: impl std::fmt::Display) -> TssError {
    TssError::DeserializeFailed(error.to_string())
}

pub(crate) fn phase_input_broadcast<T: MessageTag>(
    input: &PhaseInput,
    sender: u8,
) -> Result<T, TssError> {
    input.get_broadcast(sender).map_err(message_error)
}

pub(crate) fn phase_input_p2p<T: MessageTag>(
    input: &PhaseInput,
    sender: u8,
) -> Result<T, TssError> {
    input.get_p2p(sender).map_err(message_error)
}

fn point_to_bytes(point: &k256::AffinePoint) -> Vec<u8> {
    point.to_sec1_point(true).as_ref().to_vec()
}

pub fn convert_public_key_package(
    package: &DklsPublicKeyPackage,
) -> Result<UnifiedPublicKeyPackage, TssError> {
    let mut verifying_shares = BTreeMap::new();
    for party in 1..=package.share_count() {
        let party_index = PartyIndex::new(party).map_err(|_| TssError::InvalidIdentifier)?;
        let identifier = party_index_to_identifier(party_index)?;
        let share = package
            .verifying_share(party_index)
            .ok_or_else(|| TssError::DeserializeFailed("missing verifying share".into()))?;
        verifying_shares.insert(identifier, point_to_bytes(share));
    }

    Ok(UnifiedPublicKeyPackage::new(
        Ciphersuite::Secp256k1ECDSA,
        point_to_bytes(package.verifying_key()),
        verifying_shares,
        u16::from(package.threshold()),
    ))
}

pub fn convert_signature(signature: EcdsaSignature) -> Signature {
    Signature::new(
        Protocol::DKLs23,
        signature.to_bytes().to_vec(),
        Some(signature.recovery_id),
    )
}

pub fn dkls_dkg_phase1(
    threshold: u16,
    share_count: u16,
    self_id: Identifier,
    session_id: Vec<u8>,
) -> Result<(DklsDkgState, Vec<Message>), TssError> {
    if threshold < 2 || threshold > share_count {
        return Err(TssError::InvalidConfig(
            "threshold must be at least 2 and at most share_count".into(),
        ));
    }

    let threshold = u8::try_from(threshold)
        .map_err(|_| TssError::InvalidConfig("threshold exceeds DKLs23 limits".into()))?;
    let share_count = u8::try_from(share_count)
        .map_err(|_| TssError::InvalidConfig("share_count exceeds DKLs23 limits".into()))?;
    let self_index = identifier_to_session_party_index(self_id, share_count)?;
    let parameters = Parameters::new(threshold, share_count)
        .map_err(|_| TssError::InvalidConfig("invalid DKLs23 parameters".into()))?;
    let session = DkgSession::new(parameters, self_index, session_id);
    let fragments = SecretScalars(session.phase1());
    let self_position = usize::from(self_index.as_u8() - 1);
    let self_fragment: Scalar = fragments.0[self_position];
    let mut messages = Vec::with_capacity(usize::from(share_count.saturating_sub(1)));

    for (index, fragment) in fragments.0.iter().enumerate() {
        let receiver = u16::try_from(index + 1)
            .map_err(|_| TssError::InvalidIdentifier)
            .and_then(Identifier::new)?;
        if receiver == self_id {
            continue;
        }
        messages.push(Message {
            from: self_id,
            to: Some(receiver),
            data: scalar_to_message::<Secp256k1>(fragment),
        });
    }

    Ok((
        DklsDkgState {
            session,
            self_id,
            share_count,
            self_fragment: Some(Zeroizing::new(self_fragment)),
            self_proof_commitment: None,
            self_bip_phase2: None,
            self_bip_phase3: None,
            phase2_input: None,
        },
        messages,
    ))
}

pub fn dkls_dkg_phase2(
    state: &mut DklsDkgState,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let self_index = identifier_to_session_party_index(state.self_id, state.share_count)?;
    let self_position = usize::from(self_index.as_u8() - 1);
    let mut fragments = SecretScalars(vec![Scalar::ZERO; usize::from(state.share_count)]);
    fragments.0[self_position] = *state
        .self_fragment
        .take()
        .ok_or(TssError::SessionComplete)?;
    let mut seen = vec![false; usize::from(state.share_count)];
    seen[self_position] = true;

    for message in received {
        let Some(sender) = fragment_sender(message, state.self_id, state.share_count)? else {
            continue;
        };
        if seen[sender] {
            return Err(TssError::DeserializeFailed(
                "duplicate DKG fragment from sender".into(),
            ));
        }
        fragments.0[sender] = scalar_from_message::<Secp256k1>(&message.data)?;
        seen[sender] = true;
    }

    if seen.iter().any(|present| !present) {
        return Err(TssError::DeserializeFailed(
            "missing DKG fragment for phase2".into(),
        ));
    }

    let (proof_commitment, zero_transmit, bip_broadcast) =
        state.session.phase2(&fragments.0).map_err(abort_to_error)?;
    let mut output = Outgoing::new();
    output
        .add_broadcast(&proof_commitment)
        .map_err(message_error)?;
    output
        .add_broadcast(&bip_broadcast)
        .map_err(message_error)?;
    for message in &zero_transmit {
        output
            .add_p2p(message.parties.receiver.as_u8(), message)
            .map_err(message_error)?;
    }

    state.self_proof_commitment = Some(proof_commitment);
    state.self_bip_phase2 = Some(bip_broadcast);

    output.into_messages(state.self_id)
}

pub fn dkls_dkg_phase3(
    state: &mut DklsDkgState,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let self_index = identifier_to_session_party_index(state.self_id, state.share_count)?;
    let phase2_input = messages_to_phase_input(
        received,
        state.self_id,
        &other_parties(state.share_count, self_index),
    )?;
    let (zero_transmit, mul_transmit, bip_broadcast) =
        state.session.phase3().map_err(abort_to_error)?;
    let mut output = Outgoing::new();
    output
        .add_broadcast(&bip_broadcast)
        .map_err(message_error)?;
    for message in &zero_transmit {
        output
            .add_p2p(message.parties.receiver.as_u8(), message)
            .map_err(message_error)?;
    }
    for message in &mul_transmit {
        output
            .add_p2p(message.parties.receiver.as_u8(), message)
            .map_err(message_error)?;
    }

    state.phase2_input = Some(phase2_input);
    state.self_bip_phase3 = Some(bip_broadcast);

    output.into_messages(state.self_id)
}

pub fn dkls_dkg_phase4(
    mut state: DklsDkgState,
    received: &[Message],
) -> Result<(Party, DklsPublicKeyPackage, UnifiedPublicKeyPackage), TssError> {
    let phase2_input = state.phase2_input.take().ok_or(TssError::SessionComplete)?;
    let self_index = identifier_to_party_index(state.self_id)?;
    let phase3_input = messages_to_phase_input(
        received,
        state.self_id,
        &other_parties(state.share_count, self_index),
    )?;

    let mut proofs_commitments = vec![state
        .self_proof_commitment
        .take()
        .ok_or(TssError::SessionComplete)?];
    let mut zero_received_phase2 = Vec::new();
    let mut zero_received_phase3 = Vec::new();
    let mut mul_received = Vec::new();
    let mut bip_received_phase2 = BTreeMap::from([(
        self_index,
        state
            .self_bip_phase2
            .take()
            .ok_or(TssError::SessionComplete)?,
    )]);
    let mut bip_received_phase3 = BTreeMap::from([(
        self_index,
        state
            .self_bip_phase3
            .take()
            .ok_or(TssError::SessionComplete)?,
    )]);

    for sender in 1..=state.share_count {
        if sender == self_index.as_u8() {
            continue;
        }
        let sender_index = PartyIndex::new(sender).map_err(|_| TssError::InvalidIdentifier)?;
        let proof = phase_input_broadcast::<ProofCommitment>(&phase2_input, sender)?;
        check_sender_index(proof.index, sender)?;
        proofs_commitments.push(proof);
        let zero2 = phase_input_p2p::<TransmitInitZeroSharePhase2to4>(&phase2_input, sender)?;
        check_parties(&zero2.parties, sender, self_index)?;
        zero_received_phase2.push(zero2);
        let zero3 = phase_input_p2p::<TransmitInitZeroSharePhase3to4>(&phase3_input, sender)?;
        check_parties(&zero3.parties, sender, self_index)?;
        zero_received_phase3.push(zero3);
        let mul = phase_input_p2p::<TransmitInitMulPhase3to4>(&phase3_input, sender)?;
        check_parties(&mul.parties, sender, self_index)?;
        mul_received.push(mul);
        let bip2 = phase_input_broadcast::<BroadcastDerivationPhase2to4>(&phase2_input, sender)?;
        check_sender_index(bip2.sender_index, sender)?;
        bip_received_phase2.insert(sender_index, bip2);
        let bip3 = phase_input_broadcast::<BroadcastDerivationPhase3to4>(&phase3_input, sender)?;
        check_sender_index(bip3.sender_index, sender)?;
        bip_received_phase3.insert(sender_index, bip3);
    }

    let (party, package) = state
        .session
        .phase4(
            &proofs_commitments,
            &zero_received_phase2,
            &zero_received_phase3,
            &mul_received,
            &bip_received_phase2,
            &bip_received_phase3,
            dkls23_secp256k1::compute_eth_address,
        )
        .map_err(abort_to_error)?;

    let unified = convert_public_key_package(&package)?;
    Ok((party, package, unified))
}

pub fn dkls_sign_new<'a>(
    party: &'a Party,
    sign_id: Vec<u8>,
    counterparties: &[Identifier],
    message_hash: [u8; 32],
) -> Result<(DklsSignState<'a>, Vec<Message>), TssError> {
    let mut converted_counterparties = Vec::with_capacity(counterparties.len());
    for counterparty in counterparties {
        converted_counterparties.push(identifier_to_party_index(*counterparty)?);
    }
    let counterparty_indices = converted_counterparties
        .iter()
        .map(PartyIndex::as_u8)
        .collect();

    let (session, phase1_messages) = SignSession::new(
        party,
        SignData {
            sign_id,
            counterparties: converted_counterparties,
            message_hash,
        },
    )
    .map_err(abort_to_error)?;
    let self_id = party_index_to_identifier(party.party_index)?;
    let mut output = Outgoing::new();
    for message in &phase1_messages {
        output
            .add_p2p(message.parties.receiver.as_u8(), message)
            .map_err(message_error)?;
    }

    Ok((
        DklsSignState {
            session,
            self_id,
            counterparties: counterparty_indices,
            self_broadcast: None,
        },
        output.into_messages(self_id)?,
    ))
}

pub fn dkls_sign_phase2(
    state: &mut DklsSignState<'_>,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let input = messages_to_phase_input(received, state.self_id, &state.counterparties)?;
    let self_index = identifier_to_party_index(state.self_id)?;
    let mut decoded = Vec::with_capacity(state.counterparties.len());
    for &sender in &state.counterparties {
        let message = phase_input_p2p::<TransmitPhase1to2>(&input, sender)?;
        check_parties(&message.parties, sender, self_index)?;
        decoded.push(message);
    }

    let phase2_messages = state.session.phase2(&decoded).map_err(abort_to_error)?;
    let mut output = Outgoing::new();
    for message in &phase2_messages {
        output
            .add_p2p(message.parties.receiver.as_u8(), message)
            .map_err(message_error)?;
    }

    output.into_messages(state.self_id)
}

pub fn dkls_sign_phase3(
    state: &mut DklsSignState<'_>,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let input = messages_to_phase_input(received, state.self_id, &state.counterparties)?;
    let self_index = identifier_to_party_index(state.self_id)?;
    let mut decoded = Vec::with_capacity(state.counterparties.len());
    for &sender in &state.counterparties {
        let message = phase_input_p2p::<TransmitPhase2to3>(&input, sender)?;
        check_parties(&message.parties, sender, self_index)?;
        decoded.push(message);
    }

    let broadcast = state.session.phase3(&decoded).map_err(abort_to_error)?;
    let mut output = Outgoing::new();
    output.add_broadcast(&broadcast).map_err(message_error)?;
    state.self_broadcast = Some(broadcast);

    output.into_messages(state.self_id)
}

pub fn dkls_sign_phase4(
    mut state: DklsSignState<'_>,
    received: &[Message],
) -> Result<Signature, TssError> {
    let input = messages_to_phase_input(received, state.self_id, &state.counterparties)?;
    let mut broadcasts = vec![state
        .self_broadcast
        .take()
        .ok_or(TssError::SessionComplete)?];
    for &sender in &state.counterparties {
        broadcasts.push(phase_input_broadcast::<Broadcast3to4>(&input, sender)?);
    }

    let signature = state
        .session
        .phase4(&broadcasts, true)
        .map_err(abort_to_error)?;
    Ok(convert_signature(signature))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use dkls23_secp256k1::protocols::signing::verify_ecdsa_signature;
    use dkls23_secp256k1::protocols::{AbortReason, PartyIndex};
    use dkls23_secp256k1::utilities::hashes::tagged_hash;

    use super::*;

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn id(value: u16) -> Identifier {
        Identifier::new(value).unwrap()
    }

    fn route_messages(
        outputs: &BTreeMap<Identifier, Vec<Message>>,
        recipients: &[Identifier],
    ) -> BTreeMap<Identifier, Vec<Message>> {
        let mut routed: BTreeMap<Identifier, Vec<Message>> = recipients
            .iter()
            .copied()
            .map(|recipient| (recipient, Vec::new()))
            .collect();

        for (&sender, messages) in outputs {
            for message in messages {
                match message.to {
                    Some(to) => routed.get_mut(&to).unwrap().push(message.clone()),
                    None => {
                        for &recipient in recipients {
                            if recipient != sender {
                                routed.get_mut(&recipient).unwrap().push(message.clone());
                            }
                        }
                    }
                }
            }
        }

        routed
    }

    #[test]
    fn test_abort_to_error_maps_recoverable_and_ban_abort() {
        let recoverable = Abort::recoverable(
            PartyIndex::new(1).unwrap(),
            AbortReason::PhaseCalledOutOfOrder {
                phase: "phase2 called before phase1".into(),
            },
        );
        let banned = Abort::ban(
            PartyIndex::new(2).unwrap(),
            PartyIndex::new(1).unwrap(),
            AbortReason::OtConsistencyCheckFailed {
                counterparty: PartyIndex::new(1).unwrap(),
            },
        );

        let recoverable = abort_to_error(recoverable);
        let banned = abort_to_error(banned);

        // The reporting party (index 1) is not a culprit.
        assert_eq!(
            recoverable,
            TssError::Abort {
                culprits: vec![],
                message: "phase2 called before phase1".into(),
                ban: None,
            }
        );
        let accusing = abort_to_error(Abort::recoverable(
            PartyIndex::new(1).unwrap(),
            AbortReason::ProofVerificationFailed {
                counterparty: PartyIndex::new(2).unwrap(),
            },
        ));
        assert!(
            matches!(accusing, TssError::Abort { culprits, ban: None, .. } if culprits == vec![id(2)])
        );
        assert_eq!(
            banned,
            TssError::Abort {
                culprits: vec![id(1)],
                message: "OT consistency check failed for party 1".into(),
                ban: Some(id(1)),
            }
        );
    }

    #[test]
    fn test_messages_to_phase_input_groups_by_sender_and_ignores_other_receivers() {
        let messages = vec![
            Message {
                from: id(1),
                to: None,
                data: vec![1, 2],
            },
            Message {
                from: id(1),
                to: None,
                data: vec![3],
            },
            Message {
                from: id(2),
                to: Some(id(3)),
                data: vec![4, 5],
            },
            Message {
                from: id(2),
                to: Some(id(1)),
                data: vec![6],
            },
        ];

        let input = messages_to_phase_input(&messages, id(3), &[1, 2]).unwrap();

        assert_eq!(input.broadcasts.get(&1).unwrap(), &vec![1, 2, 3]);
        assert_eq!(input.p2p.get(&2).unwrap(), &vec![4, 5]);
        assert!(!input.p2p.contains_key(&1));
    }

    #[test]
    fn test_messages_to_phase_input_rejects_unexpected_senders() {
        let broadcast_from = |from: u16| Message {
            from: id(from),
            to: None,
            data: vec![1],
        };
        // Sender outside the expected set, including identifiers above 255.
        for from in [4, 300] {
            let err = messages_to_phase_input(&[broadcast_from(from)], id(3), &[1, 2])
                .expect_err("unexpected sender must be rejected");
            assert!(matches!(
                err,
                TssError::Abort { ref culprits, .. } if culprits == &[id(from)]
            ));
        }
        // The receiver's own broadcast, echoed back, is skipped.
        let input = messages_to_phase_input(&[broadcast_from(3)], id(3), &[1, 2]).unwrap();
        assert!(input.broadcasts.is_empty());
        // A message for another receiver is ignored, whoever sent it.
        for from in [4, 300] {
            let other = Message {
                from: id(from),
                to: Some(id(1)),
                data: vec![1],
            };
            assert!(messages_to_phase_input(&[other], id(3), &[1, 2]).is_ok());
        }
    }

    #[test]
    fn test_dkg_wrapper_full_flow() {
        let threshold = 3;
        let share_count = 3;
        let session_id = vec![7u8; 32];
        let participants = [id(1), id(2), id(3)];

        let mut states = BTreeMap::new();
        let mut phase1_outputs = BTreeMap::new();
        for self_id in participants {
            let (state, messages) =
                dkls_dkg_phase1(threshold, share_count, self_id, session_id.clone()).unwrap();
            states.insert(self_id, state);
            phase1_outputs.insert(self_id, messages);
        }

        let phase1_inputs = route_messages(&phase1_outputs, &participants);

        let mut phase2_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_dkg_phase2(
                states.get_mut(&self_id).unwrap(),
                phase1_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            phase2_outputs.insert(self_id, output);
        }

        let phase2_inputs = route_messages(&phase2_outputs, &participants);

        let mut phase3_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_dkg_phase3(
                states.get_mut(&self_id).unwrap(),
                phase2_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            phase3_outputs.insert(self_id, output);
        }

        let phase3_inputs = route_messages(&phase3_outputs, &participants);

        let mut parties = BTreeMap::new();
        let mut packages = BTreeMap::new();
        for self_id in participants {
            let state = states.remove(&self_id).unwrap();
            let (party, _, package) =
                dkls_dkg_phase4(state, phase3_inputs.get(&self_id).unwrap()).unwrap();
            parties.insert(self_id, party);
            packages.insert(self_id, package);
        }

        let first_party = parties.get(&id(1)).unwrap();
        let first_package = packages.get(&id(1)).unwrap();
        for self_id in participants {
            assert_eq!(parties.get(&self_id).unwrap().pk, first_party.pk);
            assert_eq!(
                packages.get(&self_id).unwrap().verifying_key(),
                first_package.verifying_key()
            );
            assert_eq!(packages.get(&self_id).unwrap().min_signers(), threshold);
        }
    }

    #[test]
    fn test_dkg_phase1_rejects_self_id_outside_share_count() {
        assert!(matches!(
            dkls_dkg_phase1(2, 3, id(4), vec![7u8; 32]),
            Err(TssError::InvalidIdentifier)
        ));
    }

    #[test]
    fn test_dkg_phase2_ignores_messages_for_other_recipients() {
        let threshold = 3;
        let share_count = 3;
        let session_id = vec![7u8; 32];
        let participants = [id(1), id(2), id(3)];

        let mut states = BTreeMap::new();
        let mut phase1_outputs = BTreeMap::new();
        for self_id in participants {
            let (state, messages) =
                dkls_dkg_phase1(threshold, share_count, self_id, session_id.clone()).unwrap();
            states.insert(self_id, state);
            phase1_outputs.insert(self_id, messages);
        }

        let mut phase1_inputs = route_messages(&phase1_outputs, &participants);
        phase1_inputs.get_mut(&id(1)).unwrap().push(Message {
            from: id(2),
            to: Some(id(3)),
            data: vec![9; 32],
        });

        let output = dkls_dkg_phase2(
            states.get_mut(&id(1)).unwrap(),
            phase1_inputs.get(&id(1)).unwrap(),
        )
        .unwrap();

        assert_eq!(output.len(), 4);
    }

    #[test]
    fn test_dkg_phase2_rejects_sender_outside_share_count() {
        let session_id = vec![7u8; 32];
        let (_, mut messages) = dkls_dkg_phase1(2, 2, id(1), session_id.clone()).unwrap();
        let (mut state, _) = dkls_dkg_phase1(2, 2, id(2), session_id).unwrap();
        messages.push(Message {
            from: id(3),
            to: Some(id(2)),
            data: vec![9; 32],
        });

        let error = dkls_dkg_phase2(&mut state, &messages).unwrap_err();

        assert!(matches!(
            error,
            TssError::Abort { ref culprits, .. } if culprits == &[id(3)]
        ));
    }

    #[test]
    fn test_dkg_phase2_names_sender_above_255_and_skips_echoes() {
        let session_id = vec![7u8; 32];
        let (_, messages) = dkls_dkg_phase1(2, 2, id(1), session_id.clone()).unwrap();
        let (mut state, own) = dkls_dkg_phase1(2, 2, id(2), session_id.clone()).unwrap();
        let mut with_echo = messages.clone();
        with_echo.extend(own);
        with_echo.push(Message {
            from: id(2),
            to: Some(id(2)),
            data: vec![9; 32],
        });
        with_echo.push(Message {
            from: id(300),
            to: Some(id(1)),
            data: vec![9; 32],
        });
        assert!(dkls_dkg_phase2(&mut state, &with_echo).is_ok());

        let (mut state, _) = dkls_dkg_phase1(2, 2, id(2), session_id).unwrap();
        let mut forged = messages;
        forged.push(Message {
            from: id(300),
            to: Some(id(2)),
            data: vec![9; 32],
        });
        let error = dkls_dkg_phase2(&mut state, &forged).unwrap_err();
        assert!(matches!(
            error,
            TssError::Abort { ref culprits, .. } if culprits == &[id(300)]
        ));
    }

    #[test]
    fn test_sign_wrapper_full_flow_after_dkg() {
        let threshold = 3;
        let share_count = 3;
        let session_id = vec![9u8; 32];
        let participants = [id(1), id(2), id(3)];

        let mut states = BTreeMap::new();
        let mut phase1_outputs = BTreeMap::new();
        for self_id in participants {
            let (state, messages) =
                dkls_dkg_phase1(threshold, share_count, self_id, session_id.clone()).unwrap();
            states.insert(self_id, state);
            phase1_outputs.insert(self_id, messages);
        }

        let phase1_inputs = route_messages(&phase1_outputs, &participants);

        let mut phase2_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_dkg_phase2(
                states.get_mut(&self_id).unwrap(),
                phase1_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            phase2_outputs.insert(self_id, output);
        }

        let phase2_inputs = route_messages(&phase2_outputs, &participants);

        let mut phase3_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_dkg_phase3(
                states.get_mut(&self_id).unwrap(),
                phase2_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            phase3_outputs.insert(self_id, output);
        }

        let phase3_inputs = route_messages(&phase3_outputs, &participants);

        let mut parties = BTreeMap::new();
        for self_id in participants {
            let state = states.remove(&self_id).unwrap();
            let (party, _, _) =
                dkls_dkg_phase4(state, phase3_inputs.get(&self_id).unwrap()).unwrap();
            parties.insert(self_id, party);
        }

        let sign_id = vec![3u8; 32];
        let message_hash = tagged_hash(b"libtss-test", &[b"message"]);

        let mut sign_states = BTreeMap::new();
        let mut sign1_outputs = BTreeMap::new();
        for self_id in participants {
            let counterparties: Vec<_> = participants
                .iter()
                .copied()
                .filter(|candidate| *candidate != self_id)
                .collect();
            let (state, messages) = dkls_sign_new(
                parties.get(&self_id).unwrap(),
                sign_id.clone(),
                &counterparties,
                message_hash,
            )
            .unwrap();
            sign_states.insert(self_id, state);
            sign1_outputs.insert(self_id, messages);
        }

        let sign1_inputs = route_messages(&sign1_outputs, &participants);

        let mut sign2_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_sign_phase2(
                sign_states.get_mut(&self_id).unwrap(),
                sign1_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            sign2_outputs.insert(self_id, output);
        }

        let sign2_inputs = route_messages(&sign2_outputs, &participants);

        let mut sign3_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_sign_phase3(
                sign_states.get_mut(&self_id).unwrap(),
                sign2_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            sign3_outputs.insert(self_id, output);
        }

        let sign3_inputs = route_messages(&sign3_outputs, &participants);

        let signature = dkls_sign_phase4(
            sign_states.remove(&id(1)).unwrap(),
            sign3_inputs.get(&id(1)).unwrap(),
        )
        .unwrap();

        assert_eq!(signature.protocol(), Protocol::DKLs23);
        assert_eq!(signature.as_bytes().len(), 64);
        assert!(signature.recovery_id().is_some());
        assert!(verify_ecdsa_signature::<k256::Secp256k1>(
            &message_hash,
            &parties.get(&id(1)).unwrap().pk,
            &encode_hex(&signature.as_bytes()[..32]),
            &encode_hex(&signature.as_bytes()[32..]),
        ));
    }
}
