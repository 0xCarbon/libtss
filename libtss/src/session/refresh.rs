use crate::dkls::{
    dkls_refresh_phase1, dkls_refresh_phase2, dkls_refresh_phase3, dkls_refresh_phase4,
    DklsRefreshState,
};
use crate::frost::{frost_apply_refresh, frost_refresh_with_dealer};
use crate::keyshare::{self, KeyShareHandle};
use crate::message::Message;
use crate::types::{Ciphersuite, Identifier, Protocol, PublicKeyPackage};
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
    Dkls(Box<Option<DklsRefreshState>>),
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

    /// Create a DKLs23 complete refresh session for a secp256k1 key share.
    ///
    /// All `n` parties of the group must run this together under the same
    /// fresh `session_id`: the refreshed shares are salted with it and cannot
    /// co-sign with shares from any other generation. The refresh rebuilds
    /// the OT and zero-share state from scratch, which is what turns a hollow
    /// share produced by [`repair_assemble`](crate::repair_assemble) into a
    /// signing one. Three message rounds follow (`next()` is called three
    /// times); the input handle stays valid and the output is a new one.
    pub fn new_dkls(
        key_share: &KeyShareHandle,
        session_id: &[u8],
    ) -> Result<(Self, Vec<Message>), TssError> {
        if key_share.ciphersuite() != Ciphersuite::Secp256k1ECDSA {
            return Err(TssError::ProtocolMismatch);
        }

        let party = keyshare::clone_dkls_party(key_share)?;
        let pubkey = keyshare::clone_dkls_pubkey(key_share)?;
        let (state, messages) = dkls_refresh_phase1(party, pubkey, session_id)?;

        Ok((
            Self {
                inner: RefreshInner::Dkls(Box::new(Some(state))),
                round: 1,
            },
            messages,
        ))
    }

    /// Advance the refresh with the messages received for this round.
    pub fn next(&mut self, received: &[Message]) -> Result<RefreshOutput, TssError> {
        match &mut self.inner {
            RefreshInner::Complete => Err(TssError::SessionComplete),
            RefreshInner::FrostApply { .. } => self.next_frost_apply(received),
            RefreshInner::Dkls(_) => self.next_dkls(received),
        }
    }

    fn next_dkls(&mut self, received: &[Message]) -> Result<RefreshOutput, TssError> {
        let dkls_ref = match &mut self.inner {
            RefreshInner::Dkls(state) => &mut **state,
            _ => return Err(TssError::ProtocolMismatch),
        };

        match self.round {
            1 => {
                let state = dkls_ref.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls_refresh_phase2(state, received)?;
                self.round = 2;
                Ok(RefreshOutput::Continue(messages))
            }
            2 => {
                let state = dkls_ref.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls_refresh_phase3(state, received)?;
                self.round = 3;
                Ok(RefreshOutput::Continue(messages))
            }
            3 => {
                let state = dkls_ref.take().ok_or(TssError::SessionComplete)?;
                let (party, dkls_pubkey, public_keys) = dkls_refresh_phase4(state, received)?;
                let key_share = keyshare::from_dkls_dkg(party, dkls_pubkey)?;
                self.inner = RefreshInner::Complete;
                self.round = 4;
                Ok(RefreshOutput::Complete {
                    key_share,
                    public_keys,
                })
            }
            _ => Err(TssError::SessionComplete),
        }
    }

    fn next_frost_apply(&mut self, received: &[Message]) -> Result<RefreshOutput, TssError> {
        let state = std::mem::replace(&mut self.inner, RefreshInner::Complete);
        match state {
            RefreshInner::Complete | RefreshInner::Dkls(_) => Err(TssError::ProtocolMismatch),
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

    pub fn num_rounds(&self) -> u8 {
        match &self.inner {
            RefreshInner::FrostApply { .. } => 1,
            RefreshInner::Dkls(_) => 4,
            RefreshInner::Complete => 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.inner, RefreshInner::Complete)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::frost::{frost_aggregate, frost_commit, frost_generate_with_dealer, frost_sign};
    use crate::keyshare;
    use crate::session::dkg::{DkgOutput, DkgSession};
    use crate::types::ThresholdConfig;

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

    fn run_dkls_dkg(threshold: u16, share_count: u16) -> BTreeMap<Identifier, KeyShareHandle> {
        let config = ThresholdConfig {
            min_signers: threshold,
            max_signers: share_count,
            suite: Ciphersuite::Secp256k1ECDSA,
        };
        let participants: Vec<Identifier> = (1..=share_count).map(id).collect();
        let mut sessions = BTreeMap::new();
        let mut outputs = BTreeMap::new();
        for &pid in &participants {
            let (session, messages) = DkgSession::new(&config, pid, Some(b"refresh-dkg")).unwrap();
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

    fn run_dkls_refresh(
        shares: &BTreeMap<Identifier, KeyShareHandle>,
        sids: &BTreeMap<Identifier, &[u8]>,
    ) -> Result<BTreeMap<Identifier, (KeyShareHandle, PublicKeyPackage)>, TssError> {
        let participants: Vec<Identifier> = shares.keys().copied().collect();
        let mut sessions = BTreeMap::new();
        let mut outputs = BTreeMap::new();
        for &pid in &participants {
            let (session, messages) = RefreshSession::new_dkls(&shares[&pid], sids[&pid])?;
            assert_eq!(session.round(), 1);
            assert_eq!(session.num_rounds(), 4);
            sessions.insert(pid, session);
            outputs.insert(pid, messages);
        }

        let mut refreshed = BTreeMap::new();
        for _ in 0..3 {
            let inputs = route(&outputs, &participants);
            outputs = BTreeMap::new();
            for &pid in &participants {
                match sessions
                    .get_mut(&pid)
                    .unwrap()
                    .next(inputs.get(&pid).unwrap())?
                {
                    RefreshOutput::Continue(messages) => {
                        outputs.insert(pid, messages);
                    }
                    RefreshOutput::Complete {
                        key_share,
                        public_keys,
                    } => {
                        refreshed.insert(pid, (key_share, public_keys));
                    }
                }
            }
        }
        assert_eq!(refreshed.len(), participants.len());
        for session in sessions.values() {
            assert!(session.is_complete());
            assert_eq!(session.round(), 4);
        }
        Ok(refreshed)
    }

    #[test]
    fn dkls_refresh_session_keeps_group_key_and_moves_shares() -> Result<(), TssError> {
        let shares = run_dkls_dkg(2, 3);
        let sids: BTreeMap<Identifier, &[u8]> = shares
            .keys()
            .map(|&pid| (pid, b"refresh-sid".as_slice()))
            .collect();

        let refreshed = run_dkls_refresh(&shares, &sids)?;

        let reference = &refreshed[&id(1)].1;
        for (pid, (key_share, public_keys)) in &refreshed {
            assert_eq!(public_keys, reference);
            assert_eq!(key_share.identifier(), *pid);
            assert_eq!(
                key_share.group_verifying_key(),
                shares[pid].group_verifying_key()
            );
            assert_eq!(key_share.chain_code()?, shares[pid].chain_code()?);
            assert_ne!(key_share.verifying_share(), shares[pid].verifying_share());
            assert_eq!(
                Some(key_share.verifying_share().as_slice()),
                public_keys.verifying_share(*pid)
            );
            assert_eq!(key_share.public_key_package(), public_keys);
        }
        assert_eq!(
            shares[&id(1)].identifier(),
            id(1),
            "input handle stays valid"
        );

        Ok(())
    }

    #[test]
    fn dkls_refresh_rejects_wrong_suite_and_empty_session_id() {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Ed25519,
        };
        let (frost_shares, pubkey) = frost_generate_with_dealer(&config).unwrap();
        let frost_share =
            keyshare::from_frost_dkg(frost_shares.into_iter().next().unwrap(), &pubkey).unwrap();
        assert!(matches!(
            RefreshSession::new_dkls(&frost_share, b"sid"),
            Err(TssError::ProtocolMismatch)
        ));

        let shares = run_dkls_dkg(2, 2);
        assert!(matches!(
            RefreshSession::new_dkls(&shares[&id(1)], b""),
            Err(TssError::InvalidConfig(_))
        ));
        assert!(matches!(
            RefreshSession::new_frost_receiver(&shares[&id(1)]),
            Err(TssError::ProtocolMismatch)
        ));
    }

    #[test]
    fn dkls_refresh_mixed_session_ids_abort() {
        let shares = run_dkls_dkg(2, 3);
        let mut sids: BTreeMap<Identifier, &[u8]> = shares
            .keys()
            .map(|&pid| (pid, b"refresh-sid".as_slice()))
            .collect();
        sids.insert(id(3), b"other-sid");

        assert!(matches!(
            run_dkls_refresh(&shares, &sids),
            Err(TssError::Abort { .. })
        ));
    }
}
