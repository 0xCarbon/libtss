use std::collections::BTreeMap;

use dkls23_secp256r1::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, ProofCommitment,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23_secp256r1::protocols::dkg_session::DkgSession;
use dkls23_secp256r1::protocols::messages::{MessageTag, PhaseInput, PhaseOutput};
use dkls23_secp256r1::protocols::sign_session::SignSession;
use dkls23_secp256r1::protocols::signature::EcdsaSignature;
use dkls23_secp256r1::protocols::signing::{
    Broadcast3to4, SignData, TransmitPhase1to2, TransmitPhase2to3,
};
use dkls23_secp256r1::protocols::{
    Abort, AbortKind, Parameters, PartyIndex, PublicKeyPackage as DklsPublicKeyPackage,
};
use dkls23_secp256r1::Party;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::PrimeField;
use p256::Scalar;

use crate::error::TssError;
use crate::message::Message;
use crate::types::{
    Ciphersuite, Identifier, Protocol, PublicKeyPackage as UnifiedPublicKeyPackage, Signature,
};

type R1 = p256::NistP256;

pub struct DklsR1DkgState {
    pub(crate) session: DkgSession<R1>,
    pub(crate) self_id: Identifier,
    pub(crate) share_count: u8,
    pub(crate) self_fragment: Option<Scalar>,
    pub(crate) self_proof_commitment: Option<ProofCommitment<R1>>,
    pub(crate) self_bip_phase2: Option<BroadcastDerivationPhase2to4>,
    pub(crate) self_bip_phase3: Option<BroadcastDerivationPhase3to4>,
    pub(crate) phase2_input: Option<PhaseInput>,
}

pub struct DklsR1SignState<'a> {
    pub(crate) session: SignSession<'a, R1>,
    pub(crate) self_id: Identifier,
    pub(crate) self_broadcast: Option<Broadcast3to4<R1>>,
}

fn identifier_to_party_index(id: Identifier) -> Result<PartyIndex, TssError> {
    let value = u8::try_from(id.as_u16()).map_err(|_| TssError::InvalidIdentifier)?;
    PartyIndex::new(value).map_err(|_| TssError::InvalidIdentifier)
}

fn identifier_to_session_party_index(
    id: Identifier,
    share_count: u8,
) -> Result<PartyIndex, TssError> {
    let index = identifier_to_party_index(id)?;
    if index.as_u8() > share_count {
        return Err(TssError::InvalidIdentifier);
    }
    Ok(index)
}

fn party_index_to_identifier(index: PartyIndex) -> Result<Identifier, TssError> {
    Identifier::new(u16::from(index.as_u8()))
}

fn abort_to_error(abort: Abort) -> TssError {
    match abort.kind {
        AbortKind::Recoverable => TssError::Abort {
            culprits: party_index_to_identifier(abort.index).into_iter().collect(),
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

fn phase_output_to_messages(
    output: &PhaseOutput,
    from: Identifier,
) -> Result<Vec<Message>, TssError> {
    let mut messages = Vec::with_capacity(output.broadcasts.len() + output.p2p.len());

    for data in &output.broadcasts {
        messages.push(Message {
            from,
            to: None,
            data: data.clone(),
        });
    }

    for (&receiver, data) in &output.p2p {
        messages.push(Message {
            from,
            to: Some(Identifier::new(u16::from(receiver))?),
            data: data.clone(),
        });
    }

    Ok(messages)
}

fn messages_to_phase_input(
    messages: &[Message],
    self_id: Identifier,
) -> Result<PhaseInput, TssError> {
    let mut input = PhaseInput {
        broadcasts: BTreeMap::new(),
        p2p: BTreeMap::new(),
    };

    for message in messages {
        let sender =
            u8::try_from(message.from.as_u16()).map_err(|_| TssError::InvalidIdentifier)?;
        match message.to {
            None => input
                .broadcasts
                .entry(sender)
                .or_default()
                .extend_from_slice(&message.data),
            Some(receiver) if receiver == self_id => input
                .p2p
                .entry(sender)
                .or_default()
                .extend_from_slice(&message.data),
            Some(_) => {}
        }
    }

    Ok(input)
}

fn message_error(error: impl std::fmt::Display) -> TssError {
    TssError::DeserializeFailed(error.to_string())
}

fn phase_input_broadcast<T: MessageTag>(input: &PhaseInput, sender: u8) -> Result<T, TssError> {
    input.get_broadcast(sender).map_err(message_error)
}

fn phase_input_p2p<T: MessageTag>(input: &PhaseInput, sender: u8) -> Result<T, TssError> {
    input.get_p2p(sender).map_err(message_error)
}

fn scalar_from_message(data: &[u8]) -> Result<Scalar, TssError> {
    let bytes: [u8; 32] = data
        .try_into()
        .map_err(|_| TssError::DeserializeFailed("invalid scalar fragment length".into()))?;

    Option::<Scalar>::from(Scalar::from_repr(bytes.into()))
        .ok_or_else(|| TssError::DeserializeFailed("invalid scalar fragment encoding".into()))
}

fn point_to_bytes(point: &p256::AffinePoint) -> Vec<u8> {
    point.to_sec1_point(true).as_ref().to_vec()
}

pub fn convert_public_key_package(
    package: &DklsPublicKeyPackage<R1>,
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
        Ciphersuite::Secp256r1ECDSA,
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

pub fn dkls_r1_dkg_phase1(
    threshold: u16,
    share_count: u16,
    self_id: Identifier,
    session_id: Vec<u8>,
) -> Result<(DklsR1DkgState, Vec<Message>), TssError> {
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
    let parameters = Parameters {
        threshold,
        share_count,
    };
    let session = DkgSession::new(parameters, self_index, session_id);
    let fragments = session.phase1();
    let self_position = usize::from(self_index.as_u8() - 1);
    let self_fragment: Scalar = fragments[self_position];
    let mut messages = Vec::with_capacity(usize::from(share_count.saturating_sub(1)));

    for (index, fragment) in fragments.into_iter().enumerate() {
        let receiver = u16::try_from(index + 1)
            .map_err(|_| TssError::InvalidIdentifier)
            .and_then(Identifier::new)?;
        if receiver == self_id {
            continue;
        }
        messages.push(Message {
            from: self_id,
            to: Some(receiver),
            data: fragment.to_bytes().to_vec(),
        });
    }

    Ok((
        DklsR1DkgState {
            session,
            self_id,
            share_count,
            self_fragment: Some(self_fragment),
            self_proof_commitment: None,
            self_bip_phase2: None,
            self_bip_phase3: None,
            phase2_input: None,
        },
        messages,
    ))
}

pub fn dkls_r1_dkg_phase2(
    state: &mut DklsR1DkgState,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let self_index = identifier_to_session_party_index(state.self_id, state.share_count)?;
    let self_position = usize::from(self_index.as_u8() - 1);
    let self_fragment = state
        .self_fragment
        .take()
        .ok_or(TssError::SessionComplete)?;
    let mut fragments = vec![Scalar::ZERO; usize::from(state.share_count)];
    fragments[self_position] = self_fragment;
    let mut seen = vec![false; usize::from(state.share_count)];
    seen[self_position] = true;

    for message in received {
        if message.to != Some(state.self_id) {
            continue;
        }

        let sender = usize::from(
            identifier_to_session_party_index(message.from, state.share_count)?.as_u8() - 1,
        );
        if seen[sender] {
            return Err(TssError::DeserializeFailed(
                "duplicate DKG fragment from sender".into(),
            ));
        }
        fragments[sender] = scalar_from_message(&message.data)?;
        seen[sender] = true;
    }

    if seen.iter().any(|present| !present) {
        return Err(TssError::DeserializeFailed(
            "missing DKG fragment for phase2".into(),
        ));
    }

    let (proof_commitment, zero_transmit, bip_broadcast) =
        state.session.phase2(&fragments).map_err(abort_to_error)?;
    let mut output = PhaseOutput::new();
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

    phase_output_to_messages(&output, state.self_id)
}

pub fn dkls_r1_dkg_phase3(
    state: &mut DklsR1DkgState,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let phase2_input = messages_to_phase_input(received, state.self_id)?;
    let (zero_transmit, mul_transmit, bip_broadcast) =
        state.session.phase3().map_err(abort_to_error)?;
    let mut output = PhaseOutput::new();
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

    phase_output_to_messages(&output, state.self_id)
}

pub fn dkls_r1_dkg_phase4(
    mut state: DklsR1DkgState,
    received: &[Message],
) -> Result<(Party, DklsPublicKeyPackage<R1>, UnifiedPublicKeyPackage), TssError> {
    let phase2_input = state.phase2_input.take().ok_or(TssError::SessionComplete)?;
    let phase3_input = messages_to_phase_input(received, state.self_id)?;
    let self_index = identifier_to_party_index(state.self_id)?;

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
        proofs_commitments.push(phase_input_broadcast::<ProofCommitment<R1>>(
            &phase2_input,
            sender,
        )?);
        zero_received_phase2.push(phase_input_p2p::<TransmitInitZeroSharePhase2to4>(
            &phase2_input,
            sender,
        )?);
        zero_received_phase3.push(phase_input_p2p::<TransmitInitZeroSharePhase3to4>(
            &phase3_input,
            sender,
        )?);
        mul_received.push(phase_input_p2p::<TransmitInitMulPhase3to4<R1>>(
            &phase3_input,
            sender,
        )?);
        bip_received_phase2.insert(
            sender_index,
            phase_input_broadcast::<BroadcastDerivationPhase2to4>(&phase2_input, sender)?,
        );
        bip_received_phase3.insert(
            sender_index,
            phase_input_broadcast::<BroadcastDerivationPhase3to4>(&phase3_input, sender)?,
        );
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
            dkls23_secp256r1::compute_neo3_address,
        )
        .map_err(abort_to_error)?;

    let unified = convert_public_key_package(&package)?;
    Ok((party, package, unified))
}

pub fn dkls_r1_sign_new<'a>(
    party: &'a Party,
    sign_id: Vec<u8>,
    counterparties: &[Identifier],
    message_hash: [u8; 32],
) -> Result<(DklsR1SignState<'a>, Vec<Message>), TssError> {
    let mut converted_counterparties = Vec::with_capacity(counterparties.len());
    for counterparty in counterparties {
        converted_counterparties.push(identifier_to_party_index(*counterparty)?);
    }

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
    let mut output = PhaseOutput::new();
    for message in &phase1_messages {
        output
            .add_p2p(message.parties.receiver.as_u8(), message)
            .map_err(message_error)?;
    }

    Ok((
        DklsR1SignState {
            session,
            self_id,
            self_broadcast: None,
        },
        phase_output_to_messages(&output, self_id)?,
    ))
}

pub fn dkls_r1_sign_phase2(
    state: &mut DklsR1SignState<'_>,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let input = messages_to_phase_input(received, state.self_id)?;
    let mut decoded = Vec::with_capacity(input.p2p.len());
    for &sender in input.p2p.keys() {
        decoded.push(phase_input_p2p::<TransmitPhase1to2>(&input, sender)?);
    }

    let phase2_messages = state.session.phase2(&decoded).map_err(abort_to_error)?;
    let mut output = PhaseOutput::new();
    for message in &phase2_messages {
        output
            .add_p2p(message.parties.receiver.as_u8(), message)
            .map_err(message_error)?;
    }

    phase_output_to_messages(&output, state.self_id)
}

pub fn dkls_r1_sign_phase3(
    state: &mut DklsR1SignState<'_>,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let input = messages_to_phase_input(received, state.self_id)?;
    let mut decoded = Vec::with_capacity(input.p2p.len());
    for &sender in input.p2p.keys() {
        decoded.push(phase_input_p2p::<TransmitPhase2to3<R1>>(&input, sender)?);
    }

    let broadcast = state.session.phase3(&decoded).map_err(abort_to_error)?;
    let mut output = PhaseOutput::new();
    output.add_broadcast(&broadcast).map_err(message_error)?;
    state.self_broadcast = Some(broadcast);

    phase_output_to_messages(&output, state.self_id)
}

pub fn dkls_r1_sign_phase4(
    mut state: DklsR1SignState<'_>,
    received: &[Message],
) -> Result<Signature, TssError> {
    let input = messages_to_phase_input(received, state.self_id)?;
    let mut broadcasts = vec![state
        .self_broadcast
        .take()
        .ok_or(TssError::SessionComplete)?];
    for &sender in input.broadcasts.keys() {
        broadcasts.push(phase_input_broadcast::<Broadcast3to4<R1>>(&input, sender)?);
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

    use dkls23_secp256r1::protocols::signing::verify_ecdsa_signature;
    use dkls23_secp256r1::utilities::hashes::tagged_hash;

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
    fn test_dkg_wrapper_full_flow_r1() {
        let threshold = 3;
        let share_count = 3;
        let session_id = vec![7u8; 32];
        let participants = [id(1), id(2), id(3)];

        let mut states = BTreeMap::new();
        let mut phase1_outputs = BTreeMap::new();
        for self_id in participants {
            let (state, messages) =
                dkls_r1_dkg_phase1(threshold, share_count, self_id, session_id.clone()).unwrap();
            states.insert(self_id, state);
            phase1_outputs.insert(self_id, messages);
        }

        let phase1_inputs = route_messages(&phase1_outputs, &participants);

        let mut phase2_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_r1_dkg_phase2(
                states.get_mut(&self_id).unwrap(),
                phase1_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            phase2_outputs.insert(self_id, output);
        }

        let phase2_inputs = route_messages(&phase2_outputs, &participants);

        let mut phase3_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_r1_dkg_phase3(
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
                dkls_r1_dkg_phase4(state, phase3_inputs.get(&self_id).unwrap()).unwrap();
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
    fn test_sign_wrapper_full_flow_r1_after_dkg() {
        let threshold = 3;
        let share_count = 3;
        let session_id = vec![9u8; 32];
        let participants = [id(1), id(2), id(3)];

        let mut states = BTreeMap::new();
        let mut phase1_outputs = BTreeMap::new();
        for self_id in participants {
            let (state, messages) =
                dkls_r1_dkg_phase1(threshold, share_count, self_id, session_id.clone()).unwrap();
            states.insert(self_id, state);
            phase1_outputs.insert(self_id, messages);
        }

        let phase1_inputs = route_messages(&phase1_outputs, &participants);

        let mut phase2_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_r1_dkg_phase2(
                states.get_mut(&self_id).unwrap(),
                phase1_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            phase2_outputs.insert(self_id, output);
        }

        let phase2_inputs = route_messages(&phase2_outputs, &participants);

        let mut phase3_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_r1_dkg_phase3(
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
                dkls_r1_dkg_phase4(state, phase3_inputs.get(&self_id).unwrap()).unwrap();
            parties.insert(self_id, party);
        }

        let sign_id = vec![3u8; 32];
        let message_hash = tagged_hash(b"libtss-test", &[b"r1-message"]);

        let mut sign_states = BTreeMap::new();
        let mut sign1_outputs = BTreeMap::new();
        for self_id in participants {
            let counterparties: Vec<_> = participants
                .iter()
                .copied()
                .filter(|candidate| *candidate != self_id)
                .collect();
            let (state, messages) = dkls_r1_sign_new(
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
            let output = dkls_r1_sign_phase2(
                sign_states.get_mut(&self_id).unwrap(),
                sign1_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            sign2_outputs.insert(self_id, output);
        }

        let sign2_inputs = route_messages(&sign2_outputs, &participants);

        let mut sign3_outputs = BTreeMap::new();
        for self_id in participants {
            let output = dkls_r1_sign_phase3(
                sign_states.get_mut(&self_id).unwrap(),
                sign2_inputs.get(&self_id).unwrap(),
            )
            .unwrap();
            sign3_outputs.insert(self_id, output);
        }

        let sign3_inputs = route_messages(&sign3_outputs, &participants);

        let signature = dkls_r1_sign_phase4(
            sign_states.remove(&id(1)).unwrap(),
            sign3_inputs.get(&id(1)).unwrap(),
        )
        .unwrap();

        assert_eq!(signature.protocol(), Protocol::DKLs23);
        assert_eq!(signature.as_bytes().len(), 64);
        assert!(signature.recovery_id().is_some());
        assert!(verify_ecdsa_signature::<p256::NistP256>(
            &message_hash,
            &parties.get(&id(1)).unwrap().pk,
            &encode_hex(&signature.as_bytes()[..32]),
            &encode_hex(&signature.as_bytes()[32..]),
        ));
    }
}
