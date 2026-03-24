use dkls23_secp256k1::Party;
use zeroize::Zeroizing;

use crate::dkls::{self, DklsSignState};
use crate::dkls_r1;
use crate::frost::{frost_aggregate, frost_commit, frost_sign};
use crate::keyshare::{self, KeyShareHandle};
use crate::message::Message;
use crate::types::{Ciphersuite, Identifier, Protocol, PublicKeyPackage, Signature};
use crate::TssError;

pub enum SignOutput {
    Continue(Vec<Message>),
    Complete(Signature),
}

enum SignInner {
    Frost(FrostSignState),
    Dkls(Box<DklsSignWrapper>),
    DklsR1(Box<DklsR1SignWrapper>),
    Complete,
}

struct FrostSignState {
    frost_key: crate::frost::KeyShareHandle,
    pubkey_package: PublicKeyPackage,
    msg: Vec<u8>,
    phase: Option<FrostSignPhase>,
}

enum FrostSignPhase {
    AwaitCommitments {
        nonces: Zeroizing<Vec<u8>>,
        own_commitment: Message,
    },
    AwaitShares {
        commitments: Vec<Message>,
        own_share: Message,
    },
}

struct DklsSignWrapper {
    // SAFETY: `state` borrows from `party`. Drop order (declaration order) ensures
    // `state` is dropped before `party`. `party` is Box-allocated on the heap
    // and is never moved or replaced after construction.
    state: Option<DklsSignState<'static>>,
    #[allow(dead_code)] // Keeps Party alive as drop anchor for state's borrow
    party: Box<Party>,
}

impl DklsSignWrapper {
    fn new(
        party: Party,
        sign_id: Vec<u8>,
        counterparties: &[Identifier],
        message_hash: [u8; 32],
    ) -> Result<(Self, Vec<Message>), TssError> {
        let party = Box::new(party);
        // SAFETY: party is heap-allocated in a Box that outlives state.
        // State is dropped before party (Rust drops fields in declaration order).
        // The Box is never moved or replaced after this point.
        let party_static: &'static Party = unsafe { &*(&*party as *const Party) };
        let (state, messages) =
            dkls::dkls_sign_new(party_static, sign_id, counterparties, message_hash)?;
        Ok((
            Self {
                state: Some(state),
                party,
            },
            messages,
        ))
    }
}

struct DklsR1SignWrapper {
    // SAFETY: `state` borrows from `party`. Drop order (declaration order) ensures
    // `state` is dropped before `party`. `party` is Box-allocated on the heap
    // and is never moved or replaced after construction.
    state: Option<dkls_r1::DklsR1SignState<'static>>,
    #[allow(dead_code)] // Keeps Party alive as drop anchor for state's borrow
    party: Box<dkls23_secp256r1::Party>,
}

impl DklsR1SignWrapper {
    fn new(
        party: dkls23_secp256r1::Party,
        sign_id: Vec<u8>,
        counterparties: &[Identifier],
        message_hash: [u8; 32],
    ) -> Result<(Self, Vec<Message>), TssError> {
        let party = Box::new(party);
        // SAFETY: party is heap-allocated in a Box that outlives state.
        // State is dropped before party (Rust drops fields in declaration order).
        // The Box is never moved or replaced after this point.
        let party_static: &'static dkls23_secp256r1::Party =
            unsafe { &*(&*party as *const dkls23_secp256r1::Party) };
        let (state, messages) =
            dkls_r1::dkls_r1_sign_new(party_static, sign_id, counterparties, message_hash)?;
        Ok((
            Self {
                state: Some(state),
                party,
            },
            messages,
        ))
    }
}

pub struct SignSession {
    inner: SignInner,
    round: u8,
}

impl SignSession {
    /// Create a FROST signing session.
    pub fn new_frost(
        key_share: &KeyShareHandle,
        msg: &[u8],
    ) -> Result<(Self, Vec<Message>), TssError> {
        if key_share.ciphersuite().protocol() != Protocol::Frost {
            return Err(TssError::ProtocolMismatch);
        }

        let frost_key = keyshare::to_frost_handle(key_share)?;
        let pubkey_package = key_share.public_key_package().clone();
        let (nonces, commitment) = frost_commit(&frost_key)?;

        Ok((
            Self {
                inner: SignInner::Frost(FrostSignState {
                    frost_key,
                    pubkey_package,
                    msg: msg.to_vec(),
                    phase: Some(FrostSignPhase::AwaitCommitments {
                        nonces,
                        own_commitment: commitment.clone(),
                    }),
                }),
                round: 1,
            },
            vec![commitment],
        ))
    }

    /// Create a DKLs23 secp256k1 signing session.
    pub fn new_dkls(
        key_share: &KeyShareHandle,
        sign_id: Vec<u8>,
        counterparties: &[Identifier],
        message_hash: [u8; 32],
    ) -> Result<(Self, Vec<Message>), TssError> {
        if key_share.ciphersuite() != Ciphersuite::Secp256k1ECDSA {
            return Err(TssError::ProtocolMismatch);
        }

        let party = keyshare::clone_dkls_party(key_share)?;
        let (wrapper, messages) =
            DklsSignWrapper::new(party, sign_id, counterparties, message_hash)?;

        Ok((
            Self {
                inner: SignInner::Dkls(Box::new(wrapper)),
                round: 1,
            },
            messages,
        ))
    }

    /// Create a DKLs23 secp256r1 signing session.
    pub fn new_dkls_r1(
        key_share: &KeyShareHandle,
        sign_id: Vec<u8>,
        counterparties: &[Identifier],
        message_hash: [u8; 32],
    ) -> Result<(Self, Vec<Message>), TssError> {
        if key_share.ciphersuite() != Ciphersuite::Secp256r1ECDSA {
            return Err(TssError::ProtocolMismatch);
        }

        let party = keyshare::clone_dkls_r1_party(key_share)?;
        let (wrapper, messages) =
            DklsR1SignWrapper::new(party, sign_id, counterparties, message_hash)?;

        Ok((
            Self {
                inner: SignInner::DklsR1(Box::new(wrapper)),
                round: 1,
            },
            messages,
        ))
    }

    pub fn next(&mut self, received: &[Message]) -> Result<SignOutput, TssError> {
        match &mut self.inner {
            SignInner::Complete => Err(TssError::SessionComplete),
            SignInner::Frost(_) => self.next_frost(received),
            SignInner::Dkls(_) => self.next_dkls(received),
            SignInner::DklsR1(_) => self.next_dkls_r1(received),
        }
    }

    fn next_frost(&mut self, received: &[Message]) -> Result<SignOutput, TssError> {
        let state = match &mut self.inner {
            SignInner::Frost(s) => s,
            _ => return Err(TssError::ProtocolMismatch),
        };

        let phase = state.phase.take().ok_or(TssError::SessionComplete)?;
        match phase {
            FrostSignPhase::AwaitCommitments {
                nonces,
                own_commitment,
            } => {
                let mut all_commitments = vec![own_commitment];
                all_commitments.extend_from_slice(received);
                let share = frost_sign(&state.frost_key, &nonces, &all_commitments, &state.msg)?;
                state.phase = Some(FrostSignPhase::AwaitShares {
                    commitments: all_commitments,
                    own_share: share.clone(),
                });
                self.round = 2;
                Ok(SignOutput::Continue(vec![share]))
            }
            FrostSignPhase::AwaitShares {
                commitments,
                own_share,
            } => {
                let mut all_shares = vec![own_share];
                all_shares.extend_from_slice(received);
                let signature =
                    frost_aggregate(&state.msg, &commitments, &all_shares, &state.pubkey_package)?;
                self.inner = SignInner::Complete;
                self.round = 3;
                Ok(SignOutput::Complete(signature))
            }
        }
    }

    fn next_dkls(&mut self, received: &[Message]) -> Result<SignOutput, TssError> {
        let wrapper = match &mut self.inner {
            SignInner::Dkls(w) => w,
            _ => return Err(TssError::ProtocolMismatch),
        };

        match self.round {
            1 => {
                let state = wrapper.state.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls::dkls_sign_phase2(state, received)?;
                self.round = 2;
                Ok(SignOutput::Continue(messages))
            }
            2 => {
                let state = wrapper.state.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls::dkls_sign_phase3(state, received)?;
                self.round = 3;
                Ok(SignOutput::Continue(messages))
            }
            3 => {
                let state = wrapper.state.take().ok_or(TssError::SessionComplete)?;
                let signature = dkls::dkls_sign_phase4(state, received)?;
                self.inner = SignInner::Complete;
                self.round = 4;
                Ok(SignOutput::Complete(signature))
            }
            _ => Err(TssError::SessionComplete),
        }
    }

    fn next_dkls_r1(&mut self, received: &[Message]) -> Result<SignOutput, TssError> {
        let wrapper = match &mut self.inner {
            SignInner::DklsR1(w) => w,
            _ => return Err(TssError::ProtocolMismatch),
        };

        match self.round {
            1 => {
                let state = wrapper.state.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls_r1::dkls_r1_sign_phase2(state, received)?;
                self.round = 2;
                Ok(SignOutput::Continue(messages))
            }
            2 => {
                let state = wrapper.state.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls_r1::dkls_r1_sign_phase3(state, received)?;
                self.round = 3;
                Ok(SignOutput::Continue(messages))
            }
            3 => {
                let state = wrapper.state.take().ok_or(TssError::SessionComplete)?;
                let signature = dkls_r1::dkls_r1_sign_phase4(state, received)?;
                self.inner = SignInner::Complete;
                self.round = 4;
                Ok(SignOutput::Complete(signature))
            }
            _ => Err(TssError::SessionComplete),
        }
    }

    pub fn round(&self) -> u8 {
        self.round
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.inner, SignInner::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::dkg::{DkgOutput, DkgSession};
    use crate::types::{Ciphersuite, ThresholdConfig};
    use std::collections::BTreeMap;

    fn id(value: u16) -> Identifier {
        Identifier::new(value).unwrap()
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

    fn run_frost_dkg(
        suite: Ciphersuite,
    ) -> Result<BTreeMap<Identifier, (KeyShareHandle, PublicKeyPackage)>, TssError> {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite,
        };
        let participants = [id(1), id(2), id(3)];

        let mut sessions = BTreeMap::new();
        let mut round1 = BTreeMap::new();
        for &pid in &participants {
            let (session, msgs) = DkgSession::new(&config, pid, None)?;
            sessions.insert(pid, session);
            round1.insert(pid, msgs);
        }

        let r1_in = route(&round1, &participants);
        let mut round2 = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(r1_in.get(&pid).unwrap())?
            {
                DkgOutput::Continue(msgs) => {
                    round2.insert(pid, msgs);
                }
                _ => panic!("expected Continue"),
            }
        }

        let r2_in = route(&round2, &participants);
        let mut results = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(r2_in.get(&pid).unwrap())?
            {
                DkgOutput::Complete {
                    key_share,
                    public_keys,
                } => {
                    results.insert(pid, (key_share, public_keys));
                }
                _ => panic!("expected Complete"),
            }
        }
        Ok(results)
    }

    #[test]
    fn frost_sign_session_ed25519() -> Result<(), TssError> {
        let dkg_results = run_frost_dkg(Ciphersuite::Ed25519)?;
        let participants = [id(1), id(2)];
        let message = b"hello-frost-session";

        let mut sessions = BTreeMap::new();
        let mut round1 = BTreeMap::new();
        for &pid in &participants {
            let (ks, _) = dkg_results.get(&pid).unwrap();
            let (session, msgs) = SignSession::new_frost(ks, message)?;
            sessions.insert(pid, session);
            round1.insert(pid, msgs);
        }

        let r1_in = route(&round1, &participants);
        let mut round2 = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(r1_in.get(&pid).unwrap())?
            {
                SignOutput::Continue(msgs) => {
                    round2.insert(pid, msgs);
                }
                _ => panic!("expected Continue"),
            }
        }

        let r2_in = route(&round2, &participants);
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(r2_in.get(&pid).unwrap())?
            {
                SignOutput::Complete(sig) => {
                    assert_eq!(sig.protocol(), Protocol::Frost);
                    assert!(!sig.as_bytes().is_empty());
                }
                _ => panic!("expected Complete"),
            }
        }

        Ok(())
    }

    #[test]
    fn dkls_sign_session_full_flow() -> Result<(), TssError> {
        use dkls23_secp256k1::utilities::hashes::tagged_hash;

        let config = ThresholdConfig {
            min_signers: 3,
            max_signers: 3,
            suite: Ciphersuite::Secp256k1ECDSA,
        };
        let participants = [id(1), id(2), id(3)];
        let session_id = b"dkg-session";

        // Run DKG
        let mut dkg_sessions = BTreeMap::new();
        let mut dkg_r1 = BTreeMap::new();
        for &pid in &participants {
            let (s, m) = DkgSession::new(&config, pid, Some(session_id))?;
            dkg_sessions.insert(pid, s);
            dkg_r1.insert(pid, m);
        }

        let mut prev = route(&dkg_r1, &participants);
        for _round in 0..2 {
            let mut out = BTreeMap::new();
            for &pid in &participants {
                match dkg_sessions
                    .get_mut(&pid)
                    .unwrap()
                    .next(prev.get(&pid).unwrap())?
                {
                    DkgOutput::Continue(msgs) => {
                        out.insert(pid, msgs);
                    }
                    _ => panic!("expected Continue"),
                }
            }
            prev = route(&out, &participants);
        }

        let mut dkg_results = BTreeMap::new();
        for &pid in &participants {
            match dkg_sessions
                .get_mut(&pid)
                .unwrap()
                .next(prev.get(&pid).unwrap())?
            {
                DkgOutput::Complete {
                    key_share,
                    public_keys,
                } => {
                    dkg_results.insert(pid, (key_share, public_keys));
                }
                _ => panic!("expected Complete"),
            }
        }

        // Run Sign
        let sign_id = vec![5u8; 32];
        let message_hash = tagged_hash(b"libtss-test", &[b"sign-session"]);

        let mut sign_sessions = BTreeMap::new();
        let mut sign_r1 = BTreeMap::new();
        for &pid in &participants {
            let (ks, _) = dkg_results.get(&pid).unwrap();
            let counterparties: Vec<_> =
                participants.iter().copied().filter(|&p| p != pid).collect();
            let (session, msgs) =
                SignSession::new_dkls(ks, sign_id.clone(), &counterparties, message_hash)?;
            sign_sessions.insert(pid, session);
            sign_r1.insert(pid, msgs);
        }

        let mut prev = route(&sign_r1, &participants);
        for _round in 0..2 {
            let mut out = BTreeMap::new();
            for &pid in &participants {
                match sign_sessions
                    .get_mut(&pid)
                    .unwrap()
                    .next(prev.get(&pid).unwrap())?
                {
                    SignOutput::Continue(msgs) => {
                        out.insert(pid, msgs);
                    }
                    _ => panic!("expected Continue"),
                }
            }
            prev = route(&out, &participants);
        }

        // Phase 4 → Complete
        let pid = participants[0];
        match sign_sessions
            .get_mut(&pid)
            .unwrap()
            .next(prev.get(&pid).unwrap())?
        {
            SignOutput::Complete(sig) => {
                assert_eq!(sig.protocol(), Protocol::DKLs23);
                assert_eq!(sig.as_bytes().len(), 64);
                assert!(sig.recovery_id().is_some());
            }
            _ => panic!("expected Complete"),
        }

        Ok(())
    }
}
