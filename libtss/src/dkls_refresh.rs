//! DKLs23 complete refresh, shared by the secp256k1 and secp256r1 suites.
//!
//! A complete refresh re-runs DKG with a zero-constant polynomial: every
//! share moves by a share of zero, the group key stays the same, and the
//! pairwise OT and zero-share state is generated from scratch. All `n`
//! parties take part.

use std::collections::BTreeMap;

use dkls23_secp256k1::curve::DklsCurve;
use dkls23_secp256k1::protocols::dkg::{
    KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23_secp256k1::protocols::messages::{PhaseInput, PhaseOutput};
use dkls23_secp256k1::protocols::{Party, PartyIndex, PublicKeyPackage};
use k256::elliptic_curve::ff::{Field, PrimeField};
use k256::elliptic_curve::group::{Curve, Group};
use zeroize::Zeroize;

use crate::dkls::{
    abort_to_error, identifier_to_party_index, identifier_to_session_party_index, message_error,
    messages_to_phase_input, party_index_to_identifier, phase_input_broadcast, phase_input_p2p,
    phase_output_to_messages,
};
use crate::error::TssError;
use crate::message::Message;
use crate::types::Identifier;

/// A DKLs23 curve whose scalars and points serialize, as message framing
/// requires (both supported curves qualify with DKLs23's `serde` feature).
pub trait RefreshCurve:
    DklsCurve<
    Scalar: serde::Serialize + serde::de::DeserializeOwned + Zeroize,
    AffinePoint: serde::Serialize + serde::de::DeserializeOwned,
>
{
}

impl<C> RefreshCurve for C where
    C: DklsCurve<
        Scalar: serde::Serialize + serde::de::DeserializeOwned + Zeroize,
        AffinePoint: serde::Serialize + serde::de::DeserializeOwned,
    >
{
}

/// Per-party state of a DKLs23 complete refresh, carried between the three
/// message rounds until [`phase4`] consumes it.
pub struct DklsRefreshState<C: RefreshCurve> {
    party: Party<C>,
    pubkey: PublicKeyPackage<C>,
    refresh_sid: Vec<u8>,
    self_id: Identifier,
    share_count: u8,
    self_fragment: Option<C::Scalar>,
    correction_value: Option<C::Scalar>,
    self_proof_commitment: Option<ProofCommitment<C>>,
    zero_kept_2to3: Option<BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>>,
    zero_kept_3to4: Option<BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4>>,
    mul_kept_3to4: Option<BTreeMap<PartyIndex, KeepInitMulPhase3to4<C>>>,
    phase2_input: Option<PhaseInput>,
}

impl<C: RefreshCurve> Drop for DklsRefreshState<C> {
    fn drop(&mut self) {
        if let Some(fragment) = self.self_fragment.as_mut() {
            fragment.zeroize();
        }
        if let Some(correction) = self.correction_value.as_mut() {
            correction.zeroize();
        }
        if let Some(kept) = self.zero_kept_2to3.as_mut() {
            zeroize_zero_kept_2to3(kept);
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
                value.vec_r.iter_mut().for_each(Zeroize::zeroize);
                value.correlation.zeroize();
            }
        }
    }
}

/// Secret scalars wiped on every exit path.
struct SecretScalars<S: Zeroize>(Vec<S>);

impl<S: Zeroize> Drop for SecretScalars<S> {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(Zeroize::zeroize);
    }
}

fn zeroize_zero_kept_2to3(kept: &mut BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>) {
    for value in kept.values_mut() {
        value.seed.zeroize();
        value.salt.zeroize();
    }
}

fn scalar_to_message<C: DklsCurve>(scalar: &C::Scalar) -> Vec<u8> {
    let repr = scalar.to_repr();
    let bytes: &[u8] = repr.as_ref();
    bytes.to_vec()
}

fn scalar_from_message<C: DklsCurve>(data: &[u8]) -> Result<C::Scalar, TssError> {
    let mut repr = <C::Scalar as PrimeField>::Repr::default();
    let expected_len = AsRef::<[u8]>::as_ref(&repr).len();
    if data.len() != expected_len {
        return Err(TssError::DeserializeFailed(
            "invalid scalar fragment length".into(),
        ));
    }
    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(data);
    let scalar = Option::<C::Scalar>::from(C::Scalar::from_repr(repr));
    AsMut::<[u8]>::as_mut(&mut repr).zeroize();
    scalar.ok_or_else(|| TssError::DeserializeFailed("invalid scalar fragment encoding".into()))
}

/// Start a complete refresh of `party`, producing the round-1 fragments.
///
/// Every party of the group must refresh together under the same fresh
/// `refresh_sid`. The refreshed share's session id is derived from the
/// previous one, `refresh_sid` and the round-2 commitments, so shares from
/// different refreshes (or attempts) cannot sign together.
pub fn phase1<C: RefreshCurve>(
    party: Party<C>,
    pubkey: PublicKeyPackage<C>,
    refresh_sid: &[u8],
) -> Result<(DklsRefreshState<C>, Vec<Message>), TssError> {
    if refresh_sid.is_empty() {
        return Err(TssError::InvalidConfig(
            "refresh session_id must not be empty".into(),
        ));
    }
    if party.parameters.share_count != pubkey.share_count()
        || party.parameters.threshold != pubkey.threshold()
        || party.pk != *pubkey.verifying_key()
    {
        return Err(TssError::InvalidConfig(
            "key share does not match its public key package".into(),
        ));
    }

    let self_id = party_index_to_identifier(party.party_index)?;
    let share_count = party.parameters.share_count;
    let self_position = usize::from(party.party_index.as_u8() - 1);
    let fragments = SecretScalars(party.refresh_complete_phase1());
    let self_fragment = fragments.0[self_position];
    let mut messages = Vec::with_capacity(fragments.0.len().saturating_sub(1));
    for (position, fragment) in fragments.0.iter().enumerate() {
        if position == self_position {
            continue;
        }
        let receiver = u16::try_from(position + 1)
            .map_err(|_| TssError::InvalidIdentifier)
            .and_then(Identifier::new)?;
        messages.push(Message {
            from: self_id,
            to: Some(receiver),
            data: scalar_to_message::<C>(fragment),
        });
    }

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

pub fn phase2<C: RefreshCurve>(
    state: &mut DklsRefreshState<C>,
    received: &[Message],
) -> Result<Vec<Message>, TssError> {
    let mut fragments = SecretScalars(vec![C::Scalar::ZERO; usize::from(state.share_count)]);
    let self_index = identifier_to_session_party_index(state.self_id, state.share_count)?;
    let self_position = usize::from(self_index.as_u8() - 1);
    fragments.0[self_position] = state
        .self_fragment
        .take()
        .ok_or(TssError::SessionComplete)?;
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
                "duplicate refresh fragment from sender".into(),
            ));
        }
        fragments.0[sender] = scalar_from_message::<C>(&message.data)?;
        seen[sender] = true;
    }
    if seen.iter().any(|present| !present) {
        return Err(TssError::DeserializeFailed(
            "missing refresh fragment for phase2".into(),
        ));
    }

    let (correction_value, proof_commitment, zero_kept, zero_transmit) = state
        .party
        .refresh_complete_phase2(&state.refresh_sid, &fragments.0);
    drop(fragments);

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

pub fn phase3<C: RefreshCurve>(
    state: &mut DklsRefreshState<C>,
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
    zeroize_zero_kept_2to3(&mut zero_kept_2to3);

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

/// Finish the refresh: verify every party's commitment, rebuild the OT and
/// zero-share state, apply the share correction and refresh the public key
/// package.
///
/// The package is updated with [`PublicKeyPackage::refresh`], which verifies
/// every proof commitment. The result is checked against the refreshed share
/// before it is returned.
pub fn phase4<C: RefreshCurve>(
    mut state: DklsRefreshState<C>,
    received: &[Message],
) -> Result<(Party<C>, PublicKeyPackage<C>), TssError> {
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
    for sender in 1..=state.share_count {
        if sender == self_index.as_u8() {
            continue;
        }
        proofs_commitments.push(phase_input_broadcast::<ProofCommitment<C>>(
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
        mul_received.push(phase_input_p2p::<TransmitInitMulPhase3to4<C>>(
            &phase3_input,
            sender,
        )?);
    }

    let correction_value = state
        .correction_value
        .as_ref()
        .ok_or(TssError::SessionComplete)?;
    let zero_kept = state
        .zero_kept_3to4
        .as_ref()
        .ok_or(TssError::SessionComplete)?;
    let mul_kept = state
        .mul_kept_3to4
        .as_ref()
        .ok_or(TssError::SessionComplete)?;
    let party = state
        .party
        .refresh_complete_phase4(
            &state.refresh_sid,
            correction_value,
            &proofs_commitments,
            zero_kept,
            &zero_received_phase2,
            &zero_received_phase3,
            mul_kept,
            &mul_received,
        )
        .map_err(abort_to_error)?;

    let package = state
        .pubkey
        .refresh(&state.refresh_sid, &proofs_commitments)
        .map_err(|reason| TssError::Abort {
            culprits: crate::dkls::accused(&reason)
                .and_then(|index| party_index_to_identifier(index).ok())
                .into_iter()
                .collect(),
            message: reason.to_string(),
            ban: None,
        })?;
    let expected_share = (C::ProjectivePoint::generator() * party.poly_point).to_affine();
    if package.verifying_share(party.party_index) != Some(&expected_share)
        || party.pk != *package.verifying_key()
    {
        return Err(TssError::InvalidShare);
    }

    Ok((party, package))
}
