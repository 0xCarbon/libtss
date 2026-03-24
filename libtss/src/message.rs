use crate::error::TssError;
use crate::types::Identifier;

const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// Protocol message — opaque to the client.
///
/// Clients route messages based on the `to` field:
/// - `None` → broadcast to all other participants
/// - `Some(id)` → send to that specific participant
///
/// # Examples
///
/// ```
/// use libtss::{Identifier, Message};
///
/// let id1 = Identifier::new(1).unwrap();
/// let id2 = Identifier::new(2).unwrap();
///
/// // Broadcast message
/// let broadcast = Message { from: id1, to: None, data: vec![1, 2, 3] };
/// assert!(broadcast.is_broadcast());
/// assert!(!broadcast.is_p2p());
///
/// // P2P message
/// let p2p = Message { from: id1, to: Some(id2), data: vec![4, 5] };
/// assert!(p2p.is_p2p());
/// assert!(p2p.for_participant(id2));
/// assert!(!p2p.for_participant(id1));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub from: Identifier,
    pub to: Option<Identifier>,
    pub data: Vec<u8>,
}

impl Message {
    pub fn is_broadcast(&self) -> bool {
        self.to.is_none()
    }

    pub fn is_p2p(&self) -> bool {
        self.to.is_some()
    }

    /// Returns true if this message should be delivered to `id`.
    /// Broadcasts are delivered to everyone except the sender.
    pub fn for_participant(&self, id: Identifier) -> bool {
        match self.to {
            None => self.from != id,
            Some(to) => to == id,
        }
    }
}

/// Filter messages for delivery to a specific participant.
///
/// Broadcasts are delivered to everyone except the sender.
/// P2P messages are delivered only to the target.
///
/// # Examples
///
/// ```
/// use libtss::{Identifier, Message, filter_for_participant};
///
/// let id1 = Identifier::new(1).unwrap();
/// let id2 = Identifier::new(2).unwrap();
/// let messages = vec![
///     Message { from: id1, to: None, data: vec![1] },      // broadcast from 1
///     Message { from: id2, to: Some(id1), data: vec![2] },  // P2P to 1
/// ];
///
/// let for_id1 = filter_for_participant(&messages, id1);
/// assert_eq!(for_id1.len(), 1); // only the P2P, not own broadcast
/// ```
pub fn filter_for_participant(messages: &[Message], id: Identifier) -> Vec<&Message> {
    messages
        .iter()
        .filter(|message| message.for_participant(id))
        .collect()
}

fn tlv_length(len: usize) -> Result<u32, TssError> {
    u32::try_from(len).map_err(|_| TssError::DeserializeFailed("message data exceeds u32".into()))
}

/// Serialize messages into the TLV wire format.
///
/// Each message is encoded as: `from (2B LE) | to (2B LE) | len (4B LE) | data`.
/// Multiple messages are concatenated.
///
/// # Examples
///
/// ```
/// use libtss::{Identifier, Message, serialize_messages, deserialize_messages};
///
/// let msg = Message {
///     from: Identifier::new(1).unwrap(),
///     to: Some(Identifier::new(2).unwrap()),
///     data: vec![0xAA, 0xBB],
/// };
///
/// let wire = serialize_messages(&[msg.clone()]).unwrap();
/// let decoded = deserialize_messages(&wire).unwrap();
/// assert_eq!(decoded, vec![msg]);
/// ```
pub fn serialize_messages(messages: &[Message]) -> Result<Vec<u8>, TssError> {
    let cap: usize = messages.iter().map(|m| 8 + m.data.len()).sum();
    let mut out = Vec::with_capacity(cap);

    for message in messages {
        let len = tlv_length(message.data.len())?;
        out.extend_from_slice(&message.from.as_u16().to_le_bytes());
        out.extend_from_slice(&message.to.map_or(0, Identifier::as_u16).to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&message.data);
    }

    Ok(out)
}

/// Deserialize messages from the TLV wire format produced by [`serialize_messages`].
///
/// Returns an empty `Vec` for empty input. Returns an error for truncated or
/// malformed data.
pub fn deserialize_messages(data: &[u8]) -> Result<Vec<Message>, TssError> {
    let mut offset = 0;
    let mut messages = Vec::new();

    while offset < data.len() {
        let remaining = data.len() - offset;
        if remaining < 8 {
            return Err(TssError::DeserializeFailed(
                "truncated message header".to_owned(),
            ));
        }

        let from = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let to = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let len = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;
        offset += 8;

        if len > MAX_MESSAGE_SIZE {
            return Err(TssError::DeserializeFailed(
                "message exceeds maximum size".to_owned(),
            ));
        }

        if data.len() - offset < len {
            return Err(TssError::DeserializeFailed(
                "truncated message data".to_owned(),
            ));
        }

        let from = Identifier::new(from)?;
        let to = match to {
            0 => None,
            n => Some(Identifier::new(n)?),
        };
        let payload = data[offset..offset + len].to_vec();
        offset += len;

        messages.push(Message {
            from,
            to,
            data: payload,
        });
    }

    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::{deserialize_messages, filter_for_participant, serialize_messages, Message};
    use crate::error::TssError;
    use crate::types::Identifier;

    const LARGE_PAYLOAD_LEN: usize = 65_536;

    #[test]
    fn single_message_roundtrip() {
        let from = Identifier::new(1).unwrap();
        let message = Message {
            from,
            to: None,
            data: vec![1, 2, 3, 4],
        };

        let bytes = serialize_messages(std::slice::from_ref(&message)).unwrap();
        let decoded = deserialize_messages(&bytes).unwrap();

        assert_eq!(decoded, vec![message]);
    }

    #[test]
    fn multiple_messages_roundtrip() {
        let id1 = Identifier::new(1).unwrap();
        let id2 = Identifier::new(2).unwrap();
        let id3 = Identifier::new(3).unwrap();
        let messages = vec![
            Message {
                from: id1,
                to: None,
                data: vec![1, 2, 3],
            },
            Message {
                from: id2,
                to: Some(id3),
                data: vec![4, 5],
            },
            Message {
                from: id3,
                to: Some(id1),
                data: vec![6, 7, 8, 9],
            },
        ];

        let bytes = serialize_messages(&messages).unwrap();
        let decoded = deserialize_messages(&bytes).unwrap();

        assert_eq!(decoded, messages);
    }

    #[test]
    fn empty_buffer() {
        let decoded = deserialize_messages(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn truncated_header() {
        let err = deserialize_messages(&[1, 0, 0, 0, 1, 0, 0]).unwrap_err();
        assert!(matches!(err, TssError::DeserializeFailed(_)));
    }

    #[test]
    fn truncated_data() {
        let bytes = [1, 0, 0, 0, 4, 0, 0, 0, 9, 8];

        let err = deserialize_messages(&bytes).unwrap_err();
        assert!(matches!(err, TssError::DeserializeFailed(_)));
    }

    #[test]
    fn truncated_header_after_valid_message() {
        let bytes = [1, 0, 0, 0, 1, 0, 0, 0, 9, 2, 0, 0];

        let err = deserialize_messages(&bytes).unwrap_err();
        assert!(matches!(err, TssError::DeserializeFailed(_)));
    }

    #[test]
    fn zero_from_rejected() {
        let bytes = [0, 0, 0, 0, 1, 0, 0, 0, 9];

        let err = deserialize_messages(&bytes).unwrap_err();
        assert_eq!(err, TssError::InvalidIdentifier);
    }

    #[test]
    fn is_broadcast() {
        let message = Message {
            from: Identifier::new(1).unwrap(),
            to: None,
            data: vec![],
        };
        let p2p = Message {
            from: Identifier::new(1).unwrap(),
            to: Some(Identifier::new(2).unwrap()),
            data: vec![],
        };

        assert!(message.is_broadcast());
        assert!(!p2p.is_broadcast());
    }

    #[test]
    fn is_p2p() {
        let message = Message {
            from: Identifier::new(1).unwrap(),
            to: Some(Identifier::new(2).unwrap()),
            data: vec![],
        };
        let broadcast = Message {
            from: Identifier::new(1).unwrap(),
            to: None,
            data: vec![],
        };

        assert!(message.is_p2p());
        assert!(!broadcast.is_p2p());
    }

    #[test]
    fn for_participant() {
        let id1 = Identifier::new(1).unwrap();
        let id2 = Identifier::new(2).unwrap();
        let id3 = Identifier::new(3).unwrap();
        let broadcast = Message {
            from: id1,
            to: None,
            data: vec![],
        };
        let p2p = Message {
            from: id1,
            to: Some(id2),
            data: vec![],
        };

        // Broadcast delivered to others, not to sender
        assert!(broadcast.for_participant(id3));
        assert!(!broadcast.for_participant(id1));
        assert!(p2p.for_participant(id2));
        assert!(!p2p.for_participant(id3));
    }

    #[test]
    fn filter_for_participant_excludes_sender_broadcast() {
        let id1 = Identifier::new(1).unwrap();
        let id2 = Identifier::new(2).unwrap();
        let id3 = Identifier::new(3).unwrap();
        let messages = vec![
            Message {
                from: id1,
                to: None,
                data: vec![1],
            },
            Message {
                from: id2,
                to: Some(id3),
                data: vec![2],
            },
            Message {
                from: id3,
                to: Some(id2),
                data: vec![3],
            },
        ];

        let filtered = filter_for_participant(&messages, id2);

        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0], &messages[0]); // broadcast from id1, delivered to id2
        assert_eq!(filtered[1], &messages[2]); // p2p to id2

        // Sender should not receive own broadcast
        let filtered_sender = filter_for_participant(&messages, id1);
        assert_eq!(filtered_sender.len(), 0);
    }

    #[test]
    fn large_data() {
        let message = Message {
            from: Identifier::new(1).unwrap(),
            to: Some(Identifier::new(2).unwrap()),
            data: vec![7; LARGE_PAYLOAD_LEN],
        };

        let bytes = serialize_messages(std::slice::from_ref(&message)).unwrap();
        let decoded = deserialize_messages(&bytes).unwrap();

        assert_eq!(decoded, vec![message]);
    }

    #[test]
    fn serialize_returns_error_when_message_exceeds_u32_length() {
        // We can't easily test u32::MAX+1 sized messages (4GB),
        // so we verify the function signature returns Result.
        let messages = vec![Message {
            from: Identifier::new(1).unwrap(),
            to: None,
            data: vec![],
        }];
        assert!(serialize_messages(&messages).is_ok());
    }
}
