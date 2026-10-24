use zeroize::Zeroize;

use crate::dkls_refresh::{self, DklsRefreshState};
use crate::frost::{
    frost_apply_refresh, frost_refresh_with_dealer, frost_verify_refreshed_package,
};
use crate::keyshare::{self, KeyShareHandle};
use crate::message::Message;
use crate::types::{Ciphersuite, Identifier, Protocol, PublicKeyPackage};
use crate::TssError;

/// Applies a FROST dealer refresh share after checking the refreshed public
/// key package against the current one (see
/// [`frost_verify_refreshed_package`]); the refreshed share must match this
/// party's verifying share in the new package.
pub fn apply_verified_frost_refresh(
    key_share: &crate::frost::KeyShareHandle,
    self_id: Identifier,
    current: &PublicKeyPackage,
    refreshed: &PublicKeyPackage,
    refresh_data: &[u8],
) -> Result<KeyShareHandle, TssError> {
    frost_verify_refreshed_package(self_id, current, refreshed, refresh_data)?;
    let applied = frost_apply_refresh(key_share, refresh_data)?;
    let handle = keyshare::from_frost_dkg(applied, refreshed)?;
    if refreshed.verifying_share(self_id) != Some(handle.verifying_share().as_slice()) {
        return Err(TssError::InvalidShare);
    }
    Ok(handle)
}

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
        self_id: Identifier,
        dealer: Identifier,
        public_keys: PublicKeyPackage,
    },
    Dkls(Box<Option<DklsRefreshState<k256::Secp256k1>>>),
    DklsR1(Box<Option<DklsRefreshState<p256::NistP256>>>),
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

        let (mut refresh_data, refreshed_pubkey) =
            frost_refresh_with_dealer(&pubkey_package, participants)?;

        // Serialize refreshed pubkey once for bundling into messages
        let pubkey_bytes = refreshed_pubkey.serialize()?;

        // Package refresh data as P2P messages: [pubkey_len:u32 LE][pubkey][refresh_data]
        let mut messages = Vec::with_capacity(refresh_data.len());
        for (recipient, data) in refresh_data.iter_mut() {
            let mut msg_data = Vec::with_capacity(4 + pubkey_bytes.len() + data.len());
            msg_data.extend_from_slice(&(pubkey_bytes.len() as u32).to_le_bytes());
            msg_data.extend_from_slice(&pubkey_bytes);
            msg_data.extend_from_slice(data);
            data.zeroize();
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
                    self_id,
                    dealer: self_id,
                    public_keys: pubkey_package,
                },
                round: 1,
            },
            messages,
        ))
    }

    /// Create a receive-only FROST refresh session (non-dealer participants).
    ///
    /// The participant calls `next()` with the dealer's messages; exactly one
    /// must be addressed to it, and its `from` must equal `dealer`. The caller
    /// must authenticate the transport so that `from` is reliable.
    ///
    /// The refreshed public key package is taken from that message and is
    /// checked against this party's current package: the group key and
    /// `min_signers` are unchanged, its identifiers are a subset of the current
    /// ones, and every verifying share moved by the dealer's committed
    /// zero-constant polynomial. The dealer is trusted: it learns nothing about
    /// the signing key, but it chooses the refresh polynomial and could keep
    /// parties out of the refreshed group or hand different parties shares of
    /// different polynomials, so receivers should only accept a refresh from a
    /// dealer they already trust with that role.
    pub fn new_frost_receiver(
        key_share: &KeyShareHandle,
        dealer: Identifier,
    ) -> Result<Self, TssError> {
        if key_share.ciphersuite().protocol() != Protocol::Frost {
            return Err(TssError::ProtocolMismatch);
        }
        if key_share
            .public_key_package()
            .verifying_share(dealer)
            .is_none()
        {
            return Err(TssError::InvalidIdentifier);
        }

        let frost_key = keyshare::to_frost_handle(key_share)?;
        Ok(Self {
            inner: RefreshInner::FrostApply {
                key_share: frost_key,
                self_id: key_share.identifier(),
                dealer,
                public_keys: key_share.public_key_package().clone(),
            },
            round: 1,
        })
    }

    /// Create a DKLs23 complete refresh session (secp256k1 or secp256r1).
    ///
    /// All `n` parties of the group run it together under the same fresh
    /// `session_id`. Every share moves by a share of zero, the group key stays
    /// the same, and the pairwise OT and zero-share state is generated from
    /// scratch. `next()` is called three times; the input handle stays valid
    /// and the completed session returns a new one. Refreshed shares sign only
    /// with shares from the same refresh. A failed round ends the session
    /// (`is_complete()` then returns true); start a new refresh.
    pub fn new_dkls(
        key_share: &KeyShareHandle,
        session_id: &[u8],
    ) -> Result<(Self, Vec<Message>), TssError> {
        let (inner, messages) = match key_share.ciphersuite() {
            Ciphersuite::Secp256k1ECDSA => {
                let (state, messages) = dkls_refresh::phase1(
                    keyshare::clone_dkls_party(key_share)?,
                    keyshare::clone_dkls_pubkey(key_share)?,
                    session_id,
                )?;
                (RefreshInner::Dkls(Box::new(Some(state))), messages)
            }
            Ciphersuite::Secp256r1ECDSA => {
                let (state, messages) = dkls_refresh::phase1(
                    keyshare::clone_dkls_r1_party(key_share)?,
                    keyshare::clone_dkls_r1_pubkey(key_share)?,
                    session_id,
                )?;
                (RefreshInner::DklsR1(Box::new(Some(state))), messages)
            }
            _ => return Err(TssError::ProtocolMismatch),
        };
        Ok((Self { inner, round: 1 }, messages))
    }

    /// Advance the refresh with the messages received for this round.
    pub fn next(&mut self, received: &[Message]) -> Result<RefreshOutput, TssError> {
        match &mut self.inner {
            RefreshInner::Dkls(state) => {
                let round = self.round;
                let output = next_dkls(state, round, received, |party, package| {
                    let public_keys = crate::dkls::convert_public_key_package(&package)?;
                    Ok((keyshare::from_dkls_dkg(party, package)?, public_keys))
                });
                self.advance(output)
            }
            RefreshInner::DklsR1(state) => {
                let round = self.round;
                let output = next_dkls(state, round, received, |party, package| {
                    let public_keys = crate::dkls_r1::convert_public_key_package(&package)?;
                    Ok((keyshare::from_dkls_r1_dkg(party, package)?, public_keys))
                });
                self.advance(output)
            }
            _ => self.next_frost(received),
        }
    }

    /// A failed or final round ends the session.
    fn advance(
        &mut self,
        output: Result<RefreshOutput, TssError>,
    ) -> Result<RefreshOutput, TssError> {
        if !matches!(output, Ok(RefreshOutput::Continue(_))) {
            self.inner = RefreshInner::Complete;
        }
        let output = output?;
        self.round += 1;
        Ok(output)
    }

    /// Apply received refresh data. Called by each participant after receiving
    /// the refresh share from the dealer.
    fn next_frost(&mut self, received: &[Message]) -> Result<RefreshOutput, TssError> {
        let state = std::mem::replace(&mut self.inner, RefreshInner::Complete);
        match state {
            RefreshInner::Complete => Err(TssError::SessionComplete),
            RefreshInner::Dkls(_) | RefreshInner::DklsR1(_) => Err(TssError::ProtocolMismatch),
            RefreshInner::FrostApply {
                key_share,
                self_id,
                dealer,
                public_keys,
            } => {
                let addressed: Vec<&Message> =
                    received.iter().filter(|m| m.to == Some(self_id)).collect();
                let mut culprits: Vec<Identifier> = addressed
                    .iter()
                    .map(|m| m.from)
                    .filter(|&from| from != dealer)
                    .collect();
                culprits.sort_unstable();
                culprits.dedup();
                if !culprits.is_empty() {
                    return Err(TssError::Abort {
                        message: format!(
                            "refresh message not from the dealer (parties {:?})",
                            culprits.iter().map(|c| c.as_u16()).collect::<Vec<_>>()
                        ),
                        culprits,
                        ban: None,
                    });
                }
                let msg = match addressed.as_slice() {
                    [msg] => *msg,
                    [] => {
                        return Err(TssError::DeserializeFailed(
                            "no refresh data addressed to this party".into(),
                        ))
                    }
                    _ => {
                        return Err(TssError::InvalidConfig(
                            "more than one refresh message from the dealer".into(),
                        ))
                    }
                };

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
                let body = &msg.data[4..];
                let pubkey_len = usize::try_from(u32::from_le_bytes(len_bytes))
                    .ok()
                    .filter(|&len| len <= body.len())
                    .ok_or_else(|| {
                        TssError::DeserializeFailed("refresh message truncated".into())
                    })?;
                let (pubkey_bytes, refresh_data) = body.split_at(pubkey_len);
                let pubkey_package = PublicKeyPackage::deserialize(pubkey_bytes)?;
                let registry_handle = apply_verified_frost_refresh(
                    &key_share,
                    self_id,
                    &public_keys,
                    &pubkey_package,
                    refresh_data,
                )?;
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

/// One round of a DKLs23 refresh. A failed round consumes the state, so a
/// refresh is never resumed after an error.
fn next_dkls<C: dkls_refresh::RefreshCurve>(
    state: &mut Option<DklsRefreshState<C>>,
    round: u8,
    received: &[Message],
    finish: impl FnOnce(
        dkls23_secp256k1::protocols::Party<C>,
        dkls23_secp256k1::protocols::PublicKeyPackage<C>,
    ) -> Result<(KeyShareHandle, PublicKeyPackage), TssError>,
) -> Result<RefreshOutput, TssError> {
    let mut current = state.take().ok_or(TssError::SessionComplete)?;
    match round {
        1 | 2 => {
            let messages = if round == 1 {
                dkls_refresh::phase2(&mut current, received)?
            } else {
                dkls_refresh::phase3(&mut current, received)?
            };
            *state = Some(current);
            Ok(RefreshOutput::Continue(messages))
        }
        3 => {
            let (party, package) = dkls_refresh::phase4(current, received)?;
            let (key_share, public_keys) = finish(party, package)?;
            Ok(RefreshOutput::Complete {
                key_share,
                public_keys,
            })
        }
        _ => Err(TssError::SessionComplete),
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
            let mut session = RefreshSession::new_frost_receiver(ks, id(1))?;
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

        let share0 = frost_sign(&frost_key0, nonce0, &commitments, message)?;
        let share1 = frost_sign(&frost_key1, nonce1, &commitments, message)?;

        let sig = frost_aggregate(message, &commitments, &[share0, share1], &refreshed[0].1)?;
        assert_eq!(sig.protocol(), Protocol::Frost);

        Ok(())
    }

    #[test]
    fn frost_subset_refresh_then_sign() -> Result<(), TssError> {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Ed25519,
        };
        let (frost_shares, pubkey) = frost_generate_with_dealer(&config)?;
        let key_shares = frost_shares
            .into_iter()
            .map(|share| keyshare::from_frost_dkg(share, &pubkey))
            .collect::<Result<Vec<_>, _>>()?;

        // Refresh only parties 1 and 3 (a sparse identifier set).
        let subset = [id(1), id(3)];
        let (_dealer, dealer_messages) = RefreshSession::new_frost(&key_shares[0], &subset)?;
        assert_eq!(dealer_messages.len(), 2);

        let mut refreshed = Vec::new();
        for ks in key_shares
            .iter()
            .filter(|ks| subset.contains(&ks.identifier()))
        {
            let mut session = RefreshSession::new_frost_receiver(ks, id(1))?;
            let mine: Vec<_> = dealer_messages
                .iter()
                .filter(|m| m.to == Some(ks.identifier()))
                .cloned()
                .collect();
            match session.next(&mine)? {
                RefreshOutput::Complete {
                    key_share,
                    public_keys,
                } => {
                    assert_eq!(key_share.identifier(), ks.identifier());
                    assert!(public_keys.verifying_share(id(3)).is_some());
                    refreshed.push((key_share, public_keys));
                }
                _ => panic!("expected Complete"),
            }
        }

        let message = b"subset-refresh-sign";
        let key1 = keyshare::to_frost_handle(&refreshed[0].0)?;
        let key3 = keyshare::to_frost_handle(&refreshed[1].0)?;
        let (nonce1, comm1) = frost_commit(&key1)?;
        let (nonce3, comm3) = frost_commit(&key3)?;
        let commitments = vec![comm1, comm3];
        let share1 = frost_sign(&key1, nonce1, &commitments, message)?;
        let share3 = frost_sign(&key3, nonce3, &commitments, message)?;
        let sig = frost_aggregate(message, &commitments, &[share1, share3], &refreshed[0].1)?;
        assert!(crate::verify(
            Ciphersuite::Ed25519,
            message,
            sig.as_bytes(),
            pubkey.verifying_key()
        )?);
        Ok(())
    }

    #[test]
    fn frost_refresh_rejects_max_length_prefix() -> Result<(), TssError> {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Ed25519,
        };
        let (frost_shares, pubkey) = frost_generate_with_dealer(&config)?;
        let ks = keyshare::from_frost_dkg(frost_shares.into_iter().next().unwrap(), &pubkey)?;
        for prefix in [u32::MAX, u32::MAX - 3, 5] {
            let mut session = RefreshSession::new_frost_receiver(&ks, id(2))?;
            let mut data = prefix.to_le_bytes().to_vec();
            data.extend_from_slice(&[0u8; 4]);
            let message = Message {
                from: id(2),
                to: Some(ks.identifier()),
                data,
            };
            assert!(matches!(
                session.next(&[message]),
                Err(TssError::DeserializeFailed(_))
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod receiver_checks {
    use std::collections::BTreeMap;

    use super::*;
    use crate::frost::frost_generate_with_dealer;
    use crate::types::ThresholdConfig;

    fn id(value: u16) -> Identifier {
        Identifier::new(value).unwrap()
    }

    struct Setup {
        shares: Vec<KeyShareHandle>,
        messages: Vec<Message>,
    }

    fn setup(participants: &[u16]) -> Setup {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 4,
            suite: Ciphersuite::Ed25519,
        };
        let (frost_shares, pubkey) = frost_generate_with_dealer(&config).unwrap();
        let shares = frost_shares
            .into_iter()
            .map(|share| keyshare::from_frost_dkg(share, &pubkey))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let participants: Vec<_> = participants.iter().map(|&p| id(p)).collect();
        let (_, messages) = RefreshSession::new_frost(&shares[0], &participants).unwrap();
        Setup { shares, messages }
    }

    fn split(data: &[u8]) -> (PublicKeyPackage, Vec<u8>) {
        let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        (
            PublicKeyPackage::deserialize(&data[4..4 + len]).unwrap(),
            data[4 + len..].to_vec(),
        )
    }

    fn join(package: &PublicKeyPackage, refresh: &[u8]) -> Vec<u8> {
        let bytes = package.serialize().unwrap();
        let mut data = (bytes.len() as u32).to_le_bytes().to_vec();
        data.extend_from_slice(&bytes);
        data.extend_from_slice(refresh);
        data
    }

    /// Message for `to`, with the bundled package rewritten by `edit`.
    fn tampered(
        setup: &Setup,
        to: u16,
        edit: impl FnOnce(&mut BTreeMap<Identifier, Vec<u8>>, &mut u16),
    ) -> Message {
        let mut message = setup
            .messages
            .iter()
            .find(|m| m.to == Some(id(to)))
            .unwrap()
            .clone();
        let (package, refresh) = split(&message.data);
        let mut shares = package.verifying_shares().clone();
        let mut min_signers = package.min_signers();
        edit(&mut shares, &mut min_signers);
        let package = PublicKeyPackage::new(
            package.suite(),
            package.verifying_key().to_vec(),
            shares,
            min_signers,
        );
        message.data = join(&package, &refresh);
        message
    }

    fn receive(share: &KeyShareHandle, message: Message) -> Result<RefreshOutput, TssError> {
        RefreshSession::new_frost_receiver(share, id(1))?.next(&[message])
    }

    #[test]
    fn honest_refresh_accepted() {
        let setup = setup(&[1, 2, 3, 4]);
        let message = tampered(&setup, 2, |_, _| {});
        assert!(matches!(
            receive(&setup.shares[1], message),
            Ok(RefreshOutput::Complete { .. })
        ));
    }

    #[test]
    fn rejects_message_from_non_dealer() {
        let setup = setup(&[1, 2, 3, 4]);
        let mut message = tampered(&setup, 2, |_, _| {});
        message.from = id(3);
        match receive(&setup.shares[1], message) {
            Err(TssError::Abort { culprits, .. }) => assert_eq!(culprits, vec![id(3)]),
            other => panic!("expected Abort, got {:?}", other.err()),
        }
    }

    #[test]
    fn names_a_non_dealer_sender_next_to_the_dealer_message() {
        let setup = setup(&[1, 2, 3, 4]);
        let honest = tampered(&setup, 2, |_, _| {});
        let mut stray = honest.clone();
        stray.from = id(3);
        let result = RefreshSession::new_frost_receiver(&setup.shares[1], id(1))
            .unwrap()
            .next(&[honest, stray]);
        match result {
            Err(TssError::Abort { culprits, .. }) => assert_eq!(culprits, vec![id(3)]),
            other => panic!("expected Abort, got {:?}", other.err()),
        }
    }

    #[test]
    fn rejects_dealer_outside_group() {
        let setup = setup(&[1, 2, 3, 4]);
        assert!(matches!(
            RefreshSession::new_frost_receiver(&setup.shares[1], id(9)),
            Err(TssError::InvalidIdentifier)
        ));
    }

    #[test]
    fn rejects_swapped_verifying_shares() {
        let setup = setup(&[1, 2, 3, 4]);
        // Swapping two other parties' shares keeps the group key and this
        // party's own share.
        let message = tampered(&setup, 2, |shares, _| {
            let three = shares[&id(3)].clone();
            let four = shares.insert(id(4), three).unwrap();
            shares.insert(id(3), four);
        });
        assert_eq!(
            receive(&setup.shares[1], message).err(),
            Some(TssError::InvalidShare)
        );
        // Swapping this party's share with another one.
        let message = tampered(&setup, 2, |shares, _| {
            let two = shares[&id(2)].clone();
            let three = shares.insert(id(3), two).unwrap();
            shares.insert(id(2), three);
        });
        assert_eq!(
            receive(&setup.shares[1], message).err(),
            Some(TssError::InvalidShare)
        );
    }

    #[test]
    fn rejects_other_party_share_replaced() {
        let setup = setup(&[1, 2, 3, 4]);
        let old = setup.shares[0].public_key_package().clone();
        let message = tampered(&setup, 2, |shares, _| {
            shares.insert(id(3), old.verifying_share(id(3)).unwrap().to_vec());
        });
        assert_eq!(
            receive(&setup.shares[1], message).err(),
            Some(TssError::InvalidShare)
        );
    }

    #[test]
    fn rejects_changed_min_signers() {
        let setup = setup(&[1, 2, 3, 4]);
        let message = tampered(&setup, 2, |_, min_signers| *min_signers = 3);
        assert_eq!(
            receive(&setup.shares[1], message).err(),
            Some(TssError::InvalidShare)
        );
    }

    #[test]
    fn rejects_identifier_outside_old_group() {
        let setup = setup(&[1, 2, 3]);
        let message = tampered(&setup, 2, |shares, _| {
            let three = shares[&id(3)].clone();
            shares.insert(id(7), three);
        });
        assert_eq!(
            receive(&setup.shares[1], message).err(),
            Some(TssError::InvalidShare)
        );
    }

    #[test]
    fn rejects_package_without_receiver() {
        let setup = setup(&[1, 2, 3, 4]);
        let message = tampered(&setup, 2, |shares, _| {
            shares.remove(&id(2));
        });
        assert_eq!(
            receive(&setup.shares[1], message).err(),
            Some(TssError::InvalidShare)
        );
    }

    #[test]
    fn rejects_share_for_another_party() {
        let setup = setup(&[1, 2, 3, 4]);
        let mut message = tampered(&setup, 3, |_, _| {});
        message.to = Some(id(2));
        assert_eq!(
            receive(&setup.shares[1], message).err(),
            Some(TssError::InvalidShare)
        );
    }

    #[test]
    fn sparse_refresh_accepted() {
        let setup = setup(&[1, 2, 4]);
        let message = tampered(&setup, 4, |_, _| {});
        assert!(matches!(
            receive(&setup.shares[3], message),
            Ok(RefreshOutput::Complete { .. })
        ));
    }
}
