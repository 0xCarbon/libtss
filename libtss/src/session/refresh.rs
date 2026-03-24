use crate::frost::{frost_apply_refresh, frost_refresh_with_dealer};
use crate::keyshare::{self, KeyShareHandle};
use crate::message::Message;
use crate::types::{Identifier, Protocol, PublicKeyPackage};
use crate::TssError;

pub enum RefreshOutput {
    Continue(Vec<Message>),
    Complete {
        key_share: KeyShareHandle,
        public_keys: PublicKeyPackage,
    },
}

enum RefreshInner {
    FrostApply {
        key_share: crate::frost::KeyShareHandle,
    },
    Complete,
}

pub struct RefreshSession {
    inner: RefreshInner,
    round: u8,
}

impl RefreshSession {
    /// Create a FROST refresh session (dealer role).
    ///
    /// The dealer calls this to compute and distribute refresh shares.
    /// Each outgoing P2P message contains both the refresh data and the
    /// refreshed public key package, so receivers are self-contained.
    /// The returned session can apply the dealer's own refresh via `next()`.
    pub fn new_frost(
        key_share: &KeyShareHandle,
        participants: &[Identifier],
    ) -> Result<(Self, Vec<Message>), TssError> {
        if key_share.ciphersuite().protocol() != Protocol::Frost {
            return Err(TssError::ProtocolMismatch);
        }

        let frost_key = keyshare::to_frost_handle(key_share)?;
        let pubkey_package = key_share.public_key_package().clone();
        let self_id = key_share.identifier();

        let (refresh_data, refreshed_pubkey) =
            frost_refresh_with_dealer(&pubkey_package, participants)?;

        // Serialize refreshed pubkey once for bundling into messages
        let pubkey_bytes = refreshed_pubkey.serialize()?;

        // Package refresh data as P2P messages: [pubkey_len:u32 LE][pubkey][refresh_data]
        let mut messages = Vec::with_capacity(refresh_data.len());
        for (recipient, data) in &refresh_data {
            let mut msg_data = Vec::with_capacity(4 + pubkey_bytes.len() + data.len());
            msg_data.extend_from_slice(&(pubkey_bytes.len() as u32).to_le_bytes());
            msg_data.extend_from_slice(&pubkey_bytes);
            msg_data.extend_from_slice(data);
            messages.push(Message {
                from: self_id,
                to: Some(*recipient),
                data: msg_data,
            });
        }

        Ok((
            Self {
                inner: RefreshInner::FrostApply {
                    key_share: frost_key,
                },
                round: 1,
            },
            messages,
        ))
    }

    /// Create a receive-only FROST refresh session (non-dealer participants).
    ///
    /// The participant calls `next()` with the message received from the dealer.
    /// The refreshed public key package is extracted from the message.
    pub fn new_frost_receiver(key_share: &KeyShareHandle) -> Result<Self, TssError> {
        if key_share.ciphersuite().protocol() != Protocol::Frost {
            return Err(TssError::ProtocolMismatch);
        }

        let frost_key = keyshare::to_frost_handle(key_share)?;
        Ok(Self {
            inner: RefreshInner::FrostApply {
                key_share: frost_key,
            },
            round: 1,
        })
    }

    /// Apply received refresh data. Called by each participant after receiving
    /// the refresh share from the dealer.
    pub fn next(&mut self, received: &[Message]) -> Result<RefreshOutput, TssError> {
        let state = std::mem::replace(&mut self.inner, RefreshInner::Complete);
        match state {
            RefreshInner::Complete => Err(TssError::SessionComplete),
            RefreshInner::FrostApply { key_share } => {
                let msg = received.first().ok_or_else(|| {
                    TssError::DeserializeFailed("no refresh data received".into())
                })?;

                // Parse message: [pubkey_len:u32 LE][pubkey_bytes][refresh_data]
                if msg.data.len() < 4 {
                    return Err(TssError::DeserializeFailed(
                        "refresh message too short".into(),
                    ));
                }
                let len_bytes: [u8; 4] = msg.data[..4].try_into().map_err(|_| {
                    TssError::DeserializeFailed(
                        "refresh message too short for length prefix".into(),
                    )
                })?;
                let pubkey_len = u32::from_le_bytes(len_bytes) as usize;
                if msg.data.len() < 4 + pubkey_len {
                    return Err(TssError::DeserializeFailed(
                        "refresh message truncated".into(),
                    ));
                }
                let pubkey_package = PublicKeyPackage::deserialize(&msg.data[4..4 + pubkey_len])?;
                let refresh_data = &msg.data[4 + pubkey_len..];

                let refreshed = frost_apply_refresh(&key_share, refresh_data)?;
                let registry_handle = keyshare::from_frost_dkg(refreshed, &pubkey_package)?;
                self.round = 2;
                Ok(RefreshOutput::Complete {
                    key_share: registry_handle,
                    public_keys: pubkey_package,
                })
            }
        }
    }

    pub fn round(&self) -> u8 {
        self.round
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.inner, RefreshInner::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{frost_aggregate, frost_commit, frost_generate_with_dealer, frost_sign};
    use crate::keyshare;
    use crate::types::{Ciphersuite, ThresholdConfig};

    fn id(value: u16) -> Identifier {
        Identifier::new(value).unwrap()
    }

    #[test]
    fn frost_refresh_and_sign() -> Result<(), TssError> {
        let suite = Ciphersuite::Ed25519;
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite,
        };
        let participants = [id(1), id(2), id(3)];

        // Generate initial shares with dealer
        let (frost_shares, pubkey) = frost_generate_with_dealer(&config)?;

        // Convert to registry handles
        let mut key_shares = Vec::new();
        for share in frost_shares {
            let handle = keyshare::from_frost_dkg(share, &pubkey)?;
            key_shares.push(handle);
        }

        // Party 1 acts as refresh dealer — generate messages once
        let (_dealer_session, dealer_messages) =
            RefreshSession::new_frost(&key_shares[0], &participants)?;
        assert_eq!(dealer_messages.len(), 3);

        // Each participant applies their refresh using the same dealer messages
        let mut refreshed = Vec::new();
        for ks in &key_shares {
            let mut session = RefreshSession::new_frost_receiver(ks)?;
            let my_msg: Vec<_> = dealer_messages
                .iter()
                .filter(|m| m.to == Some(ks.identifier()))
                .cloned()
                .collect();
            match session.next(&my_msg)? {
                RefreshOutput::Complete {
                    key_share,
                    public_keys,
                } => {
                    assert!(session.is_complete());
                    refreshed.push((key_share, public_keys));
                }
                _ => panic!("expected Complete"),
            }
        }

        // Verify refreshed shares can sign
        let signers = [&refreshed[0].0, &refreshed[1].0];
        let message = b"refreshed-sign";

        let frost_key0 = keyshare::to_frost_handle(signers[0])?;
        let frost_key1 = keyshare::to_frost_handle(signers[1])?;

        let (nonce0, comm0) = frost_commit(&frost_key0)?;
        let (nonce1, comm1) = frost_commit(&frost_key1)?;
        let commitments = vec![comm0, comm1];

        let share0 = frost_sign(&frost_key0, &nonce0, &commitments, message)?;
        let share1 = frost_sign(&frost_key1, &nonce1, &commitments, message)?;

        let sig = frost_aggregate(message, &commitments, &[share0, share1], &refreshed[0].1)?;
        assert_eq!(sig.protocol(), Protocol::Frost);

        Ok(())
    }
}
