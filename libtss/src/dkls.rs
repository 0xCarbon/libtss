use std::collections::BTreeMap;

use dkls23_secp256k1::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, KeepInitMulPhase3to4,
    KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, TransmitInitZeroSharePhase2to4,
    TransmitInitZeroSharePhase3to4,
};
use dkls23_secp256k1::protocols::messages::{MessageTag, PhaseInput, PhaseOutput};
use dkls23_secp256k1::protocols::signature::EcdsaSignature;
use dkls23_secp256k1::protocols::signing::SignData;
use dkls23_secp256k1::protocols::{Abort, AbortKind, Parameters, PartyIndex};
use dkls23_secp256k1::{Party, PublicKeyPackage as DklsPublicKeyPackage};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use zeroize::Zeroize;

type Secp256k1 = k256::Secp256k1;
type DkgSession = dkls23_secp256k1::DkgSession<Secp256k1>;
type SignSession<'a> = dkls23_secp256k1::SignSession<'a, Secp256k1>;
type ProofCommitment = dkls23_secp256k1::protocols::dkg::ProofCommitment<Secp256k1>;
type TransmitPhase1to2 = dkls23_secp256k1::protocols::signing::TransmitPhase1to2;
type TransmitPhase2to3 = dkls23_secp256k1::protocols::signing::TransmitPhase2to3<Secp256k1>;
type Broadcast3to4 = dkls23_secp256k1::protocols::signing::Broadcast3to4<Secp256k1>;
type TransmitInitMulPhase3to4 =
    dkls23_secp256k1::protocols::dkg::TransmitInitMulPhase3to4<Secp256k1>;

use crate::error::TssError;
use crate::message::Message;
use crate::types::{
    Ciphersuite, Identifier, Protocol, PublicKeyPackage as UnifiedPublicKeyPackage, Signature,
};

pub struct DklsDkgState {
    pub(crate) session: DkgSession,
    pub(crate) self_id: Identifier,
    pub(crate) share_count: u8,
    pub(crate) self_fragment: Option<Scalar>,
    pub(crate) self_proof_commitment: Option<ProofCommitment>,
    pub(crate) self_bip_phase2: Option<BroadcastDerivationPhase2to4>,
    pub(crate) self_bip_phase3: Option<BroadcastDerivationPhase3to4>,
    pub(crate) phase2_input: Option<PhaseInput>,
}

pub struct DklsSignState<'a> {
    pub(crate) session: SignSession<'a>,
    pub(crate) self_id: Identifier,
    pub(crate) self_broadcast: Option<Broadcast3to4>,
}

/// Per-party state of a DKLs23 complete refresh, carried between the three
/// message rounds until `dkls_refresh_phase4` consumes it.
///
/// The refresh re-runs DKG with a zero-constant polynomial, so it keeps the
/// same zero-share and multiplication initialisation material DKG does, plus
/// the original party and public key package the correction is applied to.
pub struct DklsRefreshState {
    pub(crate) party: Party,
    pub(crate) pubkey: DklsPublicKeyPackage,
    pub(crate) refresh_sid: Vec<u8>,
    pub(crate) self_id: Identifier,
    pub(crate) share_count: u8,
    pub(crate) self_fragment: Option<Scalar>,
    pub(crate) correction_value: Option<Scalar>,
    pub(crate) self_proof_commitment: Option<ProofCommitment>,
    pub(crate) zero_kept_2to3: Option<BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>>,
    pub(crate) zero_kept_3to4: Option<BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4>>,
    pub(crate) mul_kept_3to4: Option<BTreeMap<PartyIndex, KeepInitMulPhase3to4<Secp256k1>>>,
    pub(crate) phase2_input: Option<PhaseInput>,
}

impl Drop for DklsRefreshState {
    fn drop(&mut self) {
        self.refresh_sid.zeroize();
        if let Some(fragment) = self.self_fragment.as_mut() {
            fragment.zeroize();
        }
        if let Some(correction) = self.correction_value.as_mut() {
            correction.zeroize();
        }
        if let Some(kept) = self.zero_kept_2to3.as_mut() {
            for value in kept.values_mut() {
                value.seed.zeroize();
                value.salt.zeroize();
            }
        }
        if let Some(kept) = self.zero_kept_3to4.as_mut() {
            for value in kept.values_mut() {
                value.seed.zeroize();
            }
        }
        if let Some(kept) = self.mul_kept_3to4.as_mut() {
            for value in kept.values_mut() {
                value.ot_sender.s.zeroize();
                value.ot_receiver.seed.zeroize();
                value.nonce.zeroize();
                value.vec_r.zeroize();
                value.correlation.zeroize();
            }
        }
    }
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

pub(crate) fn scalar_from_message(data: &[u8]) -> Result<Scalar, TssError> {
    let bytes: [u8; 32] = data
        .try_into()
        .map_err(|_| TssError::DeserializeFailed("invalid scalar fragment length".into()))?;

    Option::<Scalar>::from(Scalar::from_repr(bytes.into()))
        .ok_or_else(|| TssError::DeserializeFailed("invalid scalar fragment encoding".into()))
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
    let (self_fragment, messages) = fragment_messages(session.phase1(), self_id, self_index)?;

    Ok((
        DklsDkgState {
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

fn fragment_messages(
    fragments: Vec<Scalar>,
    self_id: Identifier,
    self_index: PartyIndex,
) -> Result<(Scalar, Vec<Message>), TssError> {
    let self_position = usize::from(self_index.as_u8() - 1);
    let self_fragment: Scalar = fragments[self_position];
    let mut messages = Vec::with_capacity(fragments.len().saturating_sub(1));

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

    Ok((self_fragment, messages))
}

fn collect_fragments(
    self_id: Identifier,
    share_count: u8,
    self_fragment: Scalar,
    received: &[Message],
) -> Result<Vec<Scalar>, TssError> {
    let self_index = identifier_to_session_party_index(self_id, share_count)?;
    let self_position = usize::from(self_index.as_u8() - 1);
    let mut fragments: Vec<Scalar> = vec![Scalar::ZERO; usize::from(share_count)];
    fragments[self_position] = self_fragment;
    let mut seen = vec![false; usize::from(share_count)];
    seen[self_position] = true;

    for message in received {
        if message.to != Some(self_id) {
            continue;
        }

        let sender =
            usize::from(identifier_to_session_party_index(message.from, share_count)?.as_u8() - 1);
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

    Ok(fragments)
}

pub fn dkls_dkg_phase2(
    state: &mut DklsDkgState,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let self_fragment = state
        .self_fragment
        .take()
        .ok_or(TssError::SessionComplete)?;
    let fragments = collect_fragments(state.self_id, state.share_count, self_fragment, received)?;

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

pub fn dkls_dkg_phase3(
    state: &mut DklsDkgState,
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

pub fn dkls_dkg_phase4(
    mut state: DklsDkgState,
    received: &[Message],
) -> Result<(Party, DklsPublicKeyPackage, UnifiedPublicKeyPackage), TssError> {
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
        proofs_commitments.push(phase_input_broadcast::<ProofCommitment>(
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
        mul_received.push(phase_input_p2p::<TransmitInitMulPhase3to4>(
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
            dkls23_secp256k1::compute_eth_address,
        )
        .map_err(abort_to_error)?;

    let unified = convert_public_key_package(&package)?;
    Ok((party, package, unified))
}

/// Start a DKLs23 complete refresh for `party`, producing the round-1 fragments.
///
/// `refresh_sid` becomes the refreshed party's session id, so every party of
/// the group must refresh under the same fresh id: shares from different
/// refresh generations salt signing differently and can never co-sign.
pub fn dkls_refresh_phase1(
    party: Party,
    pubkey: DklsPublicKeyPackage,
    refresh_sid: &[u8],
) -> Result<(DklsRefreshState, Vec<Message>), TssError> {
    if refresh_sid.is_empty() {
        return Err(TssError::InvalidConfig(
            "refresh session_id must not be empty".into(),
        ));
    }
    if party.parameters.share_count != pubkey.share_count()
        || party.parameters.threshold != pubkey.threshold()
    {
        return Err(TssError::InvalidConfig(
            "party parameters do not match the public key package".into(),
        ));
    }

    let self_id = party_index_to_identifier(party.party_index)?;
    let share_count = party.parameters.share_count;
    let (self_fragment, messages) =
        fragment_messages(party.refresh_complete_phase1(), self_id, party.party_index)?;

    Ok((
        DklsRefreshState {
            party,
            pubkey,
            refresh_sid: refresh_sid.to_vec(),
            self_id,
            share_count,
            self_fragment: Some(self_fragment),
            correction_value: None,
            self_proof_commitment: None,
            zero_kept_2to3: None,
            zero_kept_3to4: None,
            mul_kept_3to4: None,
            phase2_input: None,
        },
        messages,
    ))
}

pub fn dkls_refresh_phase2(
    state: &mut DklsRefreshState,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let self_fragment = state
        .self_fragment
        .take()
        .ok_or(TssError::SessionComplete)?;
    let fragments = collect_fragments(state.self_id, state.share_count, self_fragment, received)?;

    let (correction_value, proof_commitment, zero_kept, zero_transmit) = state
        .party
        .refresh_complete_phase2(&state.refresh_sid, &fragments);
    let mut output = PhaseOutput::new();
    output
        .add_broadcast(&proof_commitment)
        .map_err(message_error)?;
    for message in &zero_transmit {
        output
            .add_p2p(message.parties.receiver.as_u8(), message)
            .map_err(message_error)?;
    }

    state.correction_value = Some(correction_value);
    state.self_proof_commitment = Some(proof_commitment);
    state.zero_kept_2to3 = Some(zero_kept);

    phase_output_to_messages(&output, state.self_id)
}

pub fn dkls_refresh_phase3(
    state: &mut DklsRefreshState,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let phase2_input = messages_to_phase_input(received, state.self_id)?;
    let mut zero_kept_2to3 = state
        .zero_kept_2to3
        .take()
        .ok_or(TssError::SessionComplete)?;
    let (zero_kept_3to4, zero_transmit, mul_kept, mul_transmit) = state
        .party
        .refresh_complete_phase3(&state.refresh_sid, &zero_kept_2to3);
    for kept in zero_kept_2to3.values_mut() {
        kept.seed.zeroize();
        kept.salt.zeroize();
    }

    let mut output = PhaseOutput::new();
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
    state.zero_kept_3to4 = Some(zero_kept_3to4);
    state.mul_kept_3to4 = Some(mul_kept);

    phase_output_to_messages(&output, state.self_id)
}

/// Finish a DKLs23 complete refresh: rebuild the OT state, apply the share
/// correction and derive the refreshed public key package.
///
/// dkls23's `refresh_complete_phase4` returns only the refreshed `Party`; the
/// package is recomputed here from the broadcast proof commitments, because
/// every verifying share moves by its party's correction point while the group
/// key stays put. The result is self-checked against the new party before it
/// is returned, so a package that disagrees with the share fails closed.
pub fn dkls_refresh_phase4(
    mut state: DklsRefreshState,
    received: &[Message],
) -> Result<(Party, DklsPublicKeyPackage, UnifiedPublicKeyPackage), TssError> {
    let phase2_input = state.phase2_input.take().ok_or(TssError::SessionComplete)?;
    let phase3_input = messages_to_phase_input(received, state.self_id)?;
    let self_index = identifier_to_party_index(state.self_id)?;
    let correction_value = state
        .correction_value
        .take()
        .ok_or(TssError::SessionComplete)?;
    let zero_kept = state
        .zero_kept_3to4
        .take()
        .ok_or(TssError::SessionComplete)?;
    let mul_kept = state
        .mul_kept_3to4
        .take()
        .ok_or(TssError::SessionComplete)?;

    let mut proofs_commitments = vec![state
        .self_proof_commitment
        .take()
        .ok_or(TssError::SessionComplete)?];
    let mut zero_received_phase2 = Vec::new();
    let mut zero_received_phase3 = Vec::new();
    let mut mul_received = Vec::new();

    for sender in 1..=state.share_count {
        if sender == self_index.as_u8() {
            continue;
        }
        proofs_commitments.push(phase_input_broadcast::<ProofCommitment>(
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
        mul_received.push(phase_input_p2p::<TransmitInitMulPhase3to4>(
            &phase3_input,
            sender,
        )?);
    }

    let party = state
        .party
        .refresh_complete_phase4(
            &state.refresh_sid,
            &correction_value,
            &proofs_commitments,
            &zero_kept,
            &zero_received_phase2,
            &zero_received_phase3,
            &mul_kept,
            &mul_received,
        )
        .map_err(abort_to_error)?;

    let package = refresh_public_key_package(&state.pubkey, &proofs_commitments)?;
    let expected_share = (ProjectivePoint::GENERATOR * party.poly_point).to_affine();
    if package.verifying_share(party.party_index) != Some(&expected_share)
        || party.pk != *package.verifying_key()
    {
        return Err(TssError::InvalidShare);
    }

    let unified = convert_public_key_package(&package)?;
    Ok((party, package, unified))
}

/// Apply the refresh corrections to a public key package.
///
/// Each party's proof commitment carries `G * correction_j`; the refreshed
/// verifying share is the old one moved by that point. The group key is
/// unchanged because the corrections are shares of zero, which
/// `refresh_complete_phase4` has already verified.
pub(crate) fn refresh_public_key_package(
    old: &DklsPublicKeyPackage,
    proofs_commitments: &[ProofCommitment],
) -> Result<DklsPublicKeyPackage, TssError> {
    let share_count = old.share_count();
    if proofs_commitments.len() != usize::from(share_count) {
        return Err(TssError::InvalidConfig(
            "refresh needs one proof commitment per party".into(),
        ));
    }

    let mut verifying_shares: BTreeMap<PartyIndex, AffinePoint> = BTreeMap::new();
    for proof_commitment in proofs_commitments {
        let index = proof_commitment.index;
        if index.as_u8() > share_count {
            return Err(TssError::InvalidIdentifier);
        }
        let old_share = old
            .verifying_share(index)
            .ok_or_else(|| TssError::DeserializeFailed("missing verifying share".into()))?;
        let refreshed = (ProjectivePoint::from(*old_share)
            + ProjectivePoint::from(proof_commitment.proof.point))
        .to_affine();
        if verifying_shares.insert(index, refreshed).is_some() {
            return Err(TssError::InvalidConfig(
                "duplicate proof commitment for party".into(),
            ));
        }
    }

    let parameters = Parameters::new(old.threshold(), share_count)
        .map_err(|_| TssError::InvalidConfig("invalid DKLs23 parameters".into()))?;
    Ok(DklsPublicKeyPackage::new(
        *old.verifying_key(),
        verifying_shares,
        parameters,
    ))
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
        DklsSignState {
            session,
            self_id,
            self_broadcast: None,
        },
        phase_output_to_messages(&output, self_id)?,
    ))
}

pub fn dkls_sign_phase2(
    state: &mut DklsSignState<'_>,
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

pub fn dkls_sign_phase3(
    state: &mut DklsSignState<'_>,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let input = messages_to_phase_input(received, state.self_id)?;
    let mut decoded = Vec::with_capacity(input.p2p.len());
    for &sender in input.p2p.keys() {
        decoded.push(phase_input_p2p::<TransmitPhase2to3>(&input, sender)?);
    }

    let broadcast = state.session.phase3(&decoded).map_err(abort_to_error)?;
    let mut output = PhaseOutput::new();
    output.add_broadcast(&broadcast).map_err(message_error)?;
    state.self_broadcast = Some(broadcast);

    phase_output_to_messages(&output, state.self_id)
}

pub fn dkls_sign_phase4(
    mut state: DklsSignState<'_>,
    received: &[Message],
) -> Result<Signature, TssError> {
    let input = messages_to_phase_input(received, state.self_id)?;
    let mut broadcasts = vec![state
        .self_broadcast
        .take()
        .ok_or(TssError::SessionComplete)?];
    for &sender in input.broadcasts.keys() {
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

    use dkls23_secp256k1::protocols::messages::PhaseOutput;
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

        assert_eq!(
            recoverable,
            TssError::Abort {
                culprits: vec![id(1)],
                message: "phase2 called before phase1".into(),
                ban: None,
            }
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
    fn test_phase_output_to_messages_preserves_routing() {
        let mut output = PhaseOutput::new();
        output.broadcasts.push(vec![1, 2, 3]);
        output.broadcasts.push(vec![4, 5]);
        output.p2p.insert(2, vec![9, 9]);
        output.p2p.insert(3, vec![8, 8, 8]);

        let messages = phase_output_to_messages(&output, id(1)).unwrap();

        assert_eq!(messages.len(), 4);
        assert!(messages.contains(&Message {
            from: id(1),
            to: None,
            data: vec![1, 2, 3],
        }));
        assert!(messages.contains(&Message {
            from: id(1),
            to: None,
            data: vec![4, 5],
        }));
        assert!(messages.contains(&Message {
            from: id(1),
            to: Some(id(2)),
            data: vec![9, 9],
        }));
        assert!(messages.contains(&Message {
            from: id(1),
            to: Some(id(3)),
            data: vec![8, 8, 8],
        }));
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

        let input = messages_to_phase_input(&messages, id(3)).unwrap();

        assert_eq!(input.broadcasts.get(&1).unwrap(), &vec![1, 2, 3]);
        assert_eq!(input.p2p.get(&2).unwrap(), &vec![4, 5]);
        assert!(!input.p2p.contains_key(&1));
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

    fn synthetic_package(shares: &[Scalar]) -> DklsPublicKeyPackage {
        let mut verifying_shares = BTreeMap::new();
        let mut secret = Scalar::ZERO;
        for (position, share) in shares.iter().enumerate() {
            let index = PartyIndex::new(u8::try_from(position + 1).unwrap()).unwrap();
            verifying_shares.insert(index, (ProjectivePoint::GENERATOR * share).to_affine());
            secret += share;
        }
        DklsPublicKeyPackage::new(
            (ProjectivePoint::GENERATOR * secret).to_affine(),
            verifying_shares,
            Parameters::new(2, u8::try_from(shares.len()).unwrap()).unwrap(),
        )
    }

    fn synthetic_proof(index: u8, correction: Scalar) -> ProofCommitment {
        ProofCommitment {
            index: PartyIndex::new(index).unwrap(),
            proof: dkls23_secp256k1::utilities::proofs::DLogProof {
                point: (ProjectivePoint::GENERATOR * correction).to_affine(),
                rand_commitments: Vec::new(),
                proofs: Vec::new(),
            },
            commitment: [0u8; 32],
        }
    }

    #[test]
    fn refresh_public_key_package_adds_correction_points() {
        let shares = [Scalar::from(5u64), Scalar::from(8u64), Scalar::from(13u64)];
        let corrections = [Scalar::from(3u64), Scalar::from(21u64), Scalar::from(34u64)];
        let old = synthetic_package(&shares);
        let proofs: Vec<ProofCommitment> = corrections
            .iter()
            .enumerate()
            .map(|(position, correction)| {
                synthetic_proof(u8::try_from(position + 1).unwrap(), *correction)
            })
            .collect();

        let refreshed = refresh_public_key_package(&old, &proofs).unwrap();

        assert_eq!(refreshed.verifying_key(), old.verifying_key());
        assert_eq!(refreshed.threshold(), old.threshold());
        assert_eq!(refreshed.share_count(), old.share_count());
        for (position, (share, correction)) in shares.iter().zip(&corrections).enumerate() {
            let index = PartyIndex::new(u8::try_from(position + 1).unwrap()).unwrap();
            assert_eq!(
                refreshed.verifying_share(index).unwrap(),
                &(ProjectivePoint::GENERATOR * (share + correction)).to_affine()
            );
        }
    }

    #[test]
    fn refresh_public_key_package_rejects_wrong_proof_sets() {
        let old = synthetic_package(&[Scalar::from(5u64), Scalar::from(8u64)]);

        assert!(matches!(
            refresh_public_key_package(&old, &[synthetic_proof(1, Scalar::ONE)]),
            Err(TssError::InvalidConfig(_))
        ));
        assert!(matches!(
            refresh_public_key_package(
                &old,
                &[
                    synthetic_proof(1, Scalar::ONE),
                    synthetic_proof(1, Scalar::ONE)
                ]
            ),
            Err(TssError::InvalidConfig(_))
        ));
        assert_eq!(
            refresh_public_key_package(
                &old,
                &[
                    synthetic_proof(1, Scalar::ONE),
                    synthetic_proof(3, Scalar::ONE)
                ]
            )
            .unwrap_err(),
            TssError::InvalidIdentifier
        );
    }

    #[test]
    fn test_refresh_phase1_rejects_empty_session_id_and_shape_mismatch() {
        let threshold = 2;
        let share_count = 2;
        let session_id = vec![7u8; 32];
        let participants = [id(1), id(2)];

        let mut states = BTreeMap::new();
        let mut outputs = BTreeMap::new();
        for self_id in participants {
            let (state, messages) =
                dkls_dkg_phase1(threshold, share_count, self_id, session_id.clone()).unwrap();
            states.insert(self_id, state);
            outputs.insert(self_id, messages);
        }
        for phase in [dkls_dkg_phase2, dkls_dkg_phase3] {
            let inputs = route_messages(&outputs, &participants);
            outputs = BTreeMap::new();
            for self_id in participants {
                let output = phase(
                    states.get_mut(&self_id).unwrap(),
                    inputs.get(&self_id).unwrap(),
                )
                .unwrap();
                outputs.insert(self_id, output);
            }
        }
        let inputs = route_messages(&outputs, &participants);
        let (party, package, _) =
            dkls_dkg_phase4(states.remove(&id(1)).unwrap(), inputs.get(&id(1)).unwrap()).unwrap();

        assert!(matches!(
            dkls_refresh_phase1(party.clone(), package.clone(), b""),
            Err(TssError::InvalidConfig(_))
        ));
        let other_shape = synthetic_package(&[Scalar::ONE, Scalar::ONE, Scalar::ONE]);
        assert!(matches!(
            dkls_refresh_phase1(party, other_shape, b"sid"),
            Err(TssError::InvalidConfig(_))
        ));
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

        assert_eq!(error, TssError::InvalidIdentifier);
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
