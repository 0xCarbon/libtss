//! DKLs23 round payload buffers that keep confidential bytes out of freed
//! memory.
//!
//! The upstream `PhaseOutput` grows its buffers while encoding and the
//! upstream `PhaseInput` has no zeroizing destructor, so libtss builds the
//! same framed byte streams itself: every frame and every per-sender stream is
//! allocated once at its final size, outgoing payloads move into their
//! [`Message`]s without a copy, and incoming streams are wiped on drop.

use std::collections::BTreeMap;
use std::ops::Deref;

use dkls23_secp256k1::curve::DklsCurve;
use dkls23_secp256k1::protocols::messages::{MessageError, MessageTag, PhaseInput};
use k256::elliptic_curve::ff::PrimeField;
use zeroize::{Zeroize, Zeroizing};

use crate::error::TssError;
use crate::message::Message;
use crate::types::Identifier;

/// Tag byte plus big-endian `u32` payload length, as in the upstream framing.
const FRAME_HEADER_LEN: usize = 5;

/// Encodes `message` as one `[tag][len][postcard payload]` frame in a buffer
/// allocated once at its exact size.
fn encode_frame<T: MessageTag>(message: &T) -> Result<Vec<u8>, MessageError> {
    let serialization = |e: postcard::Error| MessageError::Serialization(e.to_string());
    let size = postcard::serialize_with_flavor::<T, _, usize>(
        message,
        postcard::ser_flavors::Size::default(),
    )
    .map_err(serialization)?;
    let len = u32::try_from(size)
        .map_err(|_| MessageError::Serialization("payload exceeds u32::MAX".into()))?;
    let mut frame = Zeroizing::new(vec![0u8; FRAME_HEADER_LEN + size]);
    frame[0] = T::TAG;
    frame[1..FRAME_HEADER_LEN].copy_from_slice(&len.to_be_bytes());
    let written = postcard::to_slice(message, &mut frame[FRAME_HEADER_LEN..])
        .map_err(serialization)?
        .len();
    if written != size {
        return Err(MessageError::Serialization(
            "serialized size mismatch".into(),
        ));
    }
    Ok(std::mem::take(&mut *frame))
}

/// Concatenates `parts` into one buffer of the exact total size and wipes
/// the parts.
fn concat_wiped(parts: Vec<Zeroizing<Vec<u8>>>) -> Vec<u8> {
    if parts.len() == 1 {
        let mut parts = parts;
        return std::mem::take(&mut *parts[0]);
    }
    let mut out = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in &parts {
        out.extend_from_slice(part);
    }
    out
}

/// Outgoing payloads of one round, replacing the upstream `PhaseOutput`.
#[derive(Default)]
pub(crate) struct Outgoing {
    broadcasts: Vec<Vec<u8>>,
    p2p: BTreeMap<u8, Vec<Zeroizing<Vec<u8>>>>,
}

impl Outgoing {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_broadcast<T: MessageTag>(&mut self, message: &T) -> Result<(), MessageError> {
        self.broadcasts.push(encode_frame(message)?);
        Ok(())
    }

    pub(crate) fn add_p2p<T: MessageTag>(
        &mut self,
        receiver: u8,
        message: &T,
    ) -> Result<(), MessageError> {
        self.p2p
            .entry(receiver)
            .or_default()
            .push(Zeroizing::new(encode_frame(message)?));
        Ok(())
    }

    /// One broadcast message per broadcast frame and one point-to-point
    /// message per receiver holding that receiver's frames in order.
    pub(crate) fn into_messages(self, from: Identifier) -> Result<Vec<Message>, TssError> {
        let mut messages = Vec::with_capacity(self.broadcasts.len() + self.p2p.len());
        for data in self.broadcasts {
            messages.push(Message {
                from,
                to: None,
                data,
            });
        }
        for (receiver, frames) in self.p2p {
            let to = Identifier::new(u16::from(receiver))?;
            messages.push(Message {
                from,
                to: Some(to),
                data: concat_wiped(frames),
            });
        }
        Ok(messages)
    }
}

/// Incoming payloads of one round grouped by sender, wiped on drop.
pub(crate) struct SecretInput(PhaseInput);

impl SecretInput {
    /// Groups `messages` (already filtered and checked) by sender, allocating
    /// each sender's stream once at its final size.
    pub(crate) fn collect<'a>(messages: impl Iterator<Item = (u8, &'a Message)> + Clone) -> Self {
        let mut sizes: BTreeMap<(bool, u8), usize> = BTreeMap::new();
        for (sender, message) in messages.clone() {
            *sizes.entry((message.to.is_none(), sender)).or_default() += message.data.len();
        }
        let mut input = Self(PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::new(),
        });
        for (sender, message) in messages {
            let map = if message.to.is_none() {
                &mut input.0.broadcasts
            } else {
                &mut input.0.p2p
            };
            map.entry(sender)
                .or_insert_with(|| Vec::with_capacity(sizes[&(message.to.is_none(), sender)]))
                .extend_from_slice(&message.data);
        }
        input
    }
}

impl std::fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretInput")
            .field("broadcast_senders", &self.0.broadcasts.keys())
            .field("p2p_senders", &self.0.p2p.keys())
            .finish_non_exhaustive()
    }
}

impl Deref for SecretInput {
    type Target = PhaseInput;

    fn deref(&self) -> &PhaseInput {
        &self.0
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        for stream in self.0.broadcasts.values_mut() {
            stream.zeroize();
        }
        for stream in self.0.p2p.values_mut() {
            stream.zeroize();
        }
    }
}

/// Secret scalars wiped on every exit path.
pub(crate) struct SecretScalars<S: Zeroize>(pub(crate) Vec<S>);

impl<S: Zeroize> Drop for SecretScalars<S> {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(Zeroize::zeroize);
    }
}

/// The canonical encoding of a secret scalar; the temporary representation is
/// wiped.
pub(crate) fn scalar_to_message<C: DklsCurve>(scalar: &C::Scalar) -> Vec<u8> {
    let mut repr = scalar.to_repr();
    let bytes = AsRef::<[u8]>::as_ref(&repr).to_vec();
    AsMut::<[u8]>::as_mut(&mut repr).zeroize();
    bytes
}

/// Decodes a secret scalar; the temporary representation is wiped.
pub(crate) fn scalar_from_message<C: DklsCurve>(data: &[u8]) -> Result<C::Scalar, TssError> {
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

#[cfg(test)]
mod tests {
    use dkls23_secp256k1::protocols::dkg::BroadcastDerivationPhase2to4;
    use dkls23_secp256k1::protocols::messages::PhaseOutput;
    use dkls23_secp256k1::protocols::PartyIndex;

    use super::*;

    fn broadcast(sender: u8) -> BroadcastDerivationPhase2to4 {
        BroadcastDerivationPhase2to4 {
            sender_index: PartyIndex::new(sender).unwrap(),
            cc_commitment: [sender; 32],
        }
    }

    #[test]
    fn frames_match_the_upstream_encoding() {
        let mut ours = Outgoing::new();
        let mut upstream = PhaseOutput::new();
        for sender in [1, 2] {
            ours.add_broadcast(&broadcast(sender)).unwrap();
            upstream.add_broadcast(&broadcast(sender)).unwrap();
            ours.add_p2p(3, &broadcast(sender)).unwrap();
            upstream.add_p2p(3, &broadcast(sender)).unwrap();
        }
        let from = Identifier::new(1).unwrap();
        let messages = ours.into_messages(from).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].data, upstream.broadcasts[0]);
        assert_eq!(messages[1].data, upstream.broadcasts[1]);
        assert_eq!(messages[2].to, Some(Identifier::new(3).unwrap()));
        assert_eq!(messages[2].data, upstream.p2p[&3]);
        assert_eq!(messages[2].data.len(), messages[2].data.capacity());
    }

    #[test]
    fn input_streams_round_trip() {
        let mut output = Outgoing::new();
        output.add_broadcast(&broadcast(2)).unwrap();
        output.add_p2p(1, &broadcast(2)).unwrap();
        let messages = output.into_messages(Identifier::new(2).unwrap()).unwrap();
        let input = SecretInput::collect(messages.iter().map(|m| (2u8, m)));
        let decoded: BroadcastDerivationPhase2to4 = input.get_broadcast(2).unwrap();
        assert_eq!(decoded.cc_commitment, [2; 32]);
        let decoded: BroadcastDerivationPhase2to4 = input.get_p2p(2).unwrap();
        assert_eq!(decoded.cc_commitment, [2; 32]);
        assert_eq!(input.p2p[&2].len(), input.p2p[&2].capacity());
    }
}
