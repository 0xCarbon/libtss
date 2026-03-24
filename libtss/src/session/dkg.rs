use zeroize::Zeroizing;

use crate::dkls::{
    dkls_dkg_phase1, dkls_dkg_phase2, dkls_dkg_phase3, dkls_dkg_phase4, DklsDkgState,
};
use crate::dkls_r1::{self, DklsR1DkgState};
use crate::frost::{frost_dkg_part1, frost_dkg_part2, frost_dkg_part3};
use crate::keyshare::{self, KeyShareHandle};
use crate::message::Message;
use crate::types::{Ciphersuite, Identifier, Protocol, PublicKeyPackage, ThresholdConfig};
use crate::TssError;

pub enum DkgOutput {
    Continue(Vec<Message>),
    Complete {
        key_share: KeyShareHandle,
        public_keys: PublicKeyPackage,
    },
}

enum FrostDkgState {
    AwaitRound2 {
        suite: Ciphersuite,
        round1_secret: Zeroizing<Vec<u8>>,
    },
    AwaitRound3 {
        suite: Ciphersuite,
        round2_secret: Zeroizing<Vec<u8>>,
        round1_messages: Vec<Message>,
    },
}

enum DkgInner {
    Frost(FrostDkgState),
    Dkls(Box<Option<DklsDkgState>>),
    DklsR1(Box<Option<DklsR1DkgState>>),
    Complete,
}

pub struct DkgSession {
    inner: DkgInner,
    round: u8,
}

impl DkgSession {
    pub fn new(
        config: &ThresholdConfig,
        self_id: Identifier,
        session_id: Option<&[u8]>,
    ) -> Result<(Self, Vec<Message>), TssError> {
        config.validate()?;

        match config.suite.protocol() {
            Protocol::Frost => {
                let (round1_secret, messages) = frost_dkg_part1(config, self_id)?;
                Ok((
                    Self {
                        inner: DkgInner::Frost(FrostDkgState::AwaitRound2 {
                            suite: config.suite,
                            round1_secret,
                        }),
                        round: 1,
                    },
                    messages,
                ))
            }
            Protocol::DKLs23 => {
                let session_id = session_id.ok_or_else(|| {
                    TssError::InvalidConfig("session_id is required for DKLs23".into())
                })?;
                match config.suite {
                    Ciphersuite::Secp256r1ECDSA => {
                        let (state, messages) = dkls_r1::dkls_r1_dkg_phase1(
                            config.min_signers,
                            config.max_signers,
                            self_id,
                            session_id.to_vec(),
                        )?;
                        Ok((
                            Self {
                                inner: DkgInner::DklsR1(Box::new(Some(state))),
                                round: 1,
                            },
                            messages,
                        ))
                    }
                    _ => {
                        let (state, messages) = dkls_dkg_phase1(
                            config.min_signers,
                            config.max_signers,
                            self_id,
                            session_id.to_vec(),
                        )?;
                        Ok((
                            Self {
                                inner: DkgInner::Dkls(Box::new(Some(state))),
                                round: 1,
                            },
                            messages,
                        ))
                    }
                }
            }
        }
    }

    pub fn next(&mut self, received: &[Message]) -> Result<DkgOutput, TssError> {
        match &mut self.inner {
            DkgInner::Complete => Err(TssError::SessionComplete),
            DkgInner::Frost(_) => self.next_frost(received),
            DkgInner::Dkls(_) => self.next_dkls(received),
            DkgInner::DklsR1(_) => self.next_dkls_r1(received),
        }
    }

    fn next_frost(&mut self, received: &[Message]) -> Result<DkgOutput, TssError> {
        let state = std::mem::replace(&mut self.inner, DkgInner::Complete);
        match state {
            DkgInner::Frost(FrostDkgState::AwaitRound2 {
                suite,
                round1_secret,
            }) => {
                let (round2_secret, messages) = frost_dkg_part2(suite, &round1_secret, received)?;
                self.inner = DkgInner::Frost(FrostDkgState::AwaitRound3 {
                    suite,
                    round2_secret,
                    round1_messages: received.to_vec(),
                });
                self.round = 2;
                Ok(DkgOutput::Continue(messages))
            }
            DkgInner::Frost(FrostDkgState::AwaitRound3 {
                suite,
                round2_secret,
                round1_messages,
            }) => {
                let (frost_key_share, public_keys) =
                    frost_dkg_part3(suite, &round2_secret, &round1_messages, received)?;
                let key_share = keyshare::from_frost_dkg(frost_key_share, &public_keys)?;
                self.inner = DkgInner::Complete;
                self.round = 3;
                Ok(DkgOutput::Complete {
                    key_share,
                    public_keys,
                })
            }
            _ => Err(TssError::ProtocolMismatch),
        }
    }

    fn next_dkls(&mut self, received: &[Message]) -> Result<DkgOutput, TssError> {
        let dkls_ref = match &mut self.inner {
            DkgInner::Dkls(state) => &mut **state,
            _ => return Err(TssError::ProtocolMismatch),
        };

        match self.round {
            1 => {
                let state = dkls_ref.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls_dkg_phase2(state, received)?;
                self.round = 2;
                Ok(DkgOutput::Continue(messages))
            }
            2 => {
                let state = dkls_ref.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls_dkg_phase3(state, received)?;
                self.round = 3;
                Ok(DkgOutput::Continue(messages))
            }
            3 => {
                let state = dkls_ref.take().ok_or(TssError::SessionComplete)?;
                let (party, dkls_pubkey, public_keys) = dkls_dkg_phase4(state, received)?;
                let key_share = keyshare::from_dkls_dkg(party, dkls_pubkey)?;
                self.inner = DkgInner::Complete;
                self.round = 4;
                Ok(DkgOutput::Complete {
                    key_share,
                    public_keys,
                })
            }
            _ => Err(TssError::SessionComplete),
        }
    }

    fn next_dkls_r1(&mut self, received: &[Message]) -> Result<DkgOutput, TssError> {
        let dkls_ref = match &mut self.inner {
            DkgInner::DklsR1(state) => &mut **state,
            _ => return Err(TssError::ProtocolMismatch),
        };

        match self.round {
            1 => {
                let state = dkls_ref.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls_r1::dkls_r1_dkg_phase2(state, received)?;
                self.round = 2;
                Ok(DkgOutput::Continue(messages))
            }
            2 => {
                let state = dkls_ref.as_mut().ok_or(TssError::SessionComplete)?;
                let messages = dkls_r1::dkls_r1_dkg_phase3(state, received)?;
                self.round = 3;
                Ok(DkgOutput::Continue(messages))
            }
            3 => {
                let state = dkls_ref.take().ok_or(TssError::SessionComplete)?;
                let (party, dkls_pubkey, public_keys) =
                    dkls_r1::dkls_r1_dkg_phase4(state, received)?;
                let key_share = keyshare::from_dkls_r1_dkg(party, dkls_pubkey)?;
                self.inner = DkgInner::Complete;
                self.round = 4;
                Ok(DkgOutput::Complete {
                    key_share,
                    public_keys,
                })
            }
            _ => Err(TssError::SessionComplete),
        }
    }

    pub fn round(&self) -> u8 {
        self.round
    }

    pub fn num_rounds(&self) -> u8 {
        match &self.inner {
            DkgInner::Frost(_) => 3,
            DkgInner::Dkls(_) | DkgInner::DklsR1(_) => 4,
            DkgInner::Complete => 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.inner, DkgInner::Complete)
    }

    pub fn protocol(&self) -> Protocol {
        match &self.inner {
            DkgInner::Frost(_) | DkgInner::Complete => Protocol::Frost,
            DkgInner::Dkls(_) | DkgInner::DklsR1(_) => Protocol::DKLs23,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn frost_dkg_session_ed25519() -> Result<(), TssError> {
        let suite = Ciphersuite::Ed25519;
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite,
        };
        let participants = [id(1), id(2), id(3)];

        let mut sessions = BTreeMap::new();
        let mut round1_outputs = BTreeMap::new();
        for &pid in &participants {
            let (session, messages) = DkgSession::new(&config, pid, None)?;
            sessions.insert(pid, session);
            round1_outputs.insert(pid, messages);
        }

        let round1_inputs = route(&round1_outputs, &participants);

        let mut round2_outputs = BTreeMap::new();
        for &pid in &participants {
            let session = sessions.get_mut(&pid).unwrap();
            match session.next(round1_inputs.get(&pid).unwrap())? {
                DkgOutput::Continue(messages) => {
                    round2_outputs.insert(pid, messages);
                }
                _ => panic!("expected Continue"),
            }
        }

        let round2_inputs = route(&round2_outputs, &participants);

        let mut results = Vec::new();
        for &pid in &participants {
            let session = sessions.get_mut(&pid).unwrap();
            match session.next(round2_inputs.get(&pid).unwrap())? {
                DkgOutput::Complete {
                    key_share,
                    public_keys,
                } => {
                    assert!(session.is_complete());
                    results.push((key_share, public_keys));
                }
                _ => panic!("expected Complete"),
            }
        }

        // All parties should derive the same group key
        let first_vk = results[0].1.verifying_key();
        for (_, pubkey) in &results[1..] {
            assert_eq!(pubkey.verifying_key(), first_vk);
        }

        // Verify session complete error
        let session = sessions.get_mut(&participants[0]).unwrap();
        assert!(matches!(session.next(&[]), Err(TssError::SessionComplete)));

        Ok(())
    }

    #[test]
    fn dkls_dkg_session_requires_session_id() {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Secp256k1ECDSA,
        };
        assert!(matches!(
            DkgSession::new(&config, id(1), None),
            Err(TssError::InvalidConfig(_))
        ));
    }

    #[test]
    fn dkls_dkg_session_full_flow() -> Result<(), TssError> {
        let config = ThresholdConfig {
            min_signers: 3,
            max_signers: 3,
            suite: Ciphersuite::Secp256k1ECDSA,
        };
        let participants = [id(1), id(2), id(3)];
        let session_id = b"test-session";

        let mut sessions = BTreeMap::new();
        let mut phase1_outputs = BTreeMap::new();
        for &pid in &participants {
            let (session, messages) = DkgSession::new(&config, pid, Some(session_id))?;
            sessions.insert(pid, session);
            phase1_outputs.insert(pid, messages);
        }

        let phase1_inputs = route(&phase1_outputs, &participants);

        let mut phase2_outputs = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(phase1_inputs.get(&pid).unwrap())?
            {
                DkgOutput::Continue(messages) => {
                    phase2_outputs.insert(pid, messages);
                }
                _ => panic!("expected Continue after phase1"),
            }
        }

        let phase2_inputs = route(&phase2_outputs, &participants);

        let mut phase3_outputs = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(phase2_inputs.get(&pid).unwrap())?
            {
                DkgOutput::Continue(messages) => {
                    phase3_outputs.insert(pid, messages);
                }
                _ => panic!("expected Continue after phase2"),
            }
        }

        let phase3_inputs = route(&phase3_outputs, &participants);

        let mut results = Vec::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(phase3_inputs.get(&pid).unwrap())?
            {
                DkgOutput::Complete {
                    key_share,
                    public_keys,
                } => results.push((key_share, public_keys)),
                _ => panic!("expected Complete after phase3"),
            }
        }

        // All parties derive the same group key
        let first_vk = results[0].1.verifying_key();
        for (_, pubkey) in &results[1..] {
            assert_eq!(pubkey.verifying_key(), first_vk);
        }

        Ok(())
    }
}
