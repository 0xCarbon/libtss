//! Tokio `mpsc` routing helpers for the reference TSS example.
//!
//! Each party pushes exactly one batched payload per destination and round,
//! including empty batches. That avoids timing races around channel draining.

use std::collections::{BTreeMap, HashMap};

use tokio::sync::mpsc;

use crate::{
    encryption::{
        channel_pair_from_shared_secret, derive_shared_secret, generate_keypair, P2PChannel,
    },
    Identifier, Message, TssError,
};

pub type RoundMessages = Vec<Message>;

#[derive(Debug)]
pub struct PartyRouter {
    self_id: Identifier,
    peers: BTreeMap<Identifier, mpsc::Sender<RoundMessages>>,
    inbox: mpsc::Receiver<RoundMessages>,
}

impl PartyRouter {
    pub fn self_id(&self) -> Identifier {
        self.self_id
    }

    pub fn participant_ids(&self) -> Vec<Identifier> {
        let mut ids = Vec::with_capacity(self.peers.len() + 1);
        ids.push(self.self_id);
        ids.extend(self.peers.keys().copied());
        ids.sort_unstable();
        ids
    }

    pub async fn send(&self, messages: Vec<Message>) -> Result<(), TssError> {
        let mut batches: BTreeMap<Identifier, RoundMessages> = self
            .peers
            .keys()
            .copied()
            .map(|peer| (peer, Vec::new()))
            .collect();

        for message in messages {
            match message.to {
                None => {
                    for batch in batches.values_mut() {
                        batch.push(message.clone());
                    }
                }
                Some(target) => {
                    let batch = batches.get_mut(&target).ok_or_else(|| {
                        TssError::Protocol(format!(
                            "party {} attempted to route to unknown peer {}",
                            self.self_id, target
                        ))
                    })?;
                    batch.push(message);
                }
            }
        }

        for (peer_id, sender) in &self.peers {
            let round_payload = batches.remove(peer_id).unwrap_or_default();
            sender.send(round_payload).await.map_err(|_| {
                TssError::ChannelClosed(format!(
                    "party {} could not send to peer {}",
                    self.self_id, peer_id
                ))
            })?;
        }

        Ok(())
    }

    pub async fn receive_from_all_peers(&mut self) -> Result<Vec<Message>, TssError> {
        let mut messages = Vec::new();

        for _ in 0..self.peers.len() {
            let batch = self.inbox.recv().await.ok_or_else(|| {
                TssError::ChannelClosed(format!(
                    "party {} lost its router inbox before the round completed",
                    self.self_id
                ))
            })?;
            messages.extend(batch);
        }

        // Stable sort by sender only — preserves the original per-sender
        // ordering so that counter-based nonces in encrypted channels stay
        // in sync.
        messages.sort_by_key(|m| m.from);

        Ok(messages)
    }
}

pub fn create_routers(ids: &[Identifier]) -> HashMap<Identifier, PartyRouter> {
    let mut senders = HashMap::new();
    let mut inboxes = HashMap::new();

    for &id in ids {
        let (sender, receiver) = mpsc::channel(32);
        senders.insert(id, sender);
        inboxes.insert(id, receiver);
    }

    ids.iter()
        .copied()
        .map(|id| {
            let peers = senders
                .iter()
                .filter(|(peer_id, _)| **peer_id != id)
                .map(|(&peer_id, sender)| (peer_id, sender.clone()))
                .collect();

            let router = PartyRouter {
                self_id: id,
                peers,
                inbox: inboxes
                    .remove(&id)
                    .expect("receiver exists for every party"),
            };

            (id, router)
        })
        .collect()
}

#[derive(Debug)]
pub struct EncryptedRouter {
    inner: PartyRouter,
    peer_channels: HashMap<Identifier, (P2PChannel, P2PChannel)>,
}

impl EncryptedRouter {
    pub fn participant_ids(&self) -> Vec<Identifier> {
        self.inner.participant_ids()
    }

    pub fn self_id(&self) -> Identifier {
        self.inner.self_id()
    }

    pub async fn send(&mut self, messages: Vec<Message>) -> Result<(), TssError> {
        let mut encrypted = Vec::with_capacity(messages.len());
        let self_id = self.self_id();

        for mut message in messages {
            if let Some(target) = message.to {
                let (send_channel, _) = self.peer_channels.get_mut(&target).ok_or_else(|| {
                    TssError::Protocol(format!(
                        "party {} has no encrypted channel for peer {}",
                        self_id, target
                    ))
                })?;

                message.data = send_channel
                    .encrypt(&message.data)
                    .map_err(|_| TssError::Encryption("p2p encrypt failed".into()))?;
            }
            encrypted.push(message);
        }

        self.inner.send(encrypted).await
    }

    pub async fn receive_from_all_peers(&mut self) -> Result<Vec<Message>, TssError> {
        let mut messages = self.inner.receive_from_all_peers().await?;
        let self_id = self.self_id();

        for message in &mut messages {
            if message.to == Some(self_id) {
                let (_, recv_channel) =
                    self.peer_channels.get_mut(&message.from).ok_or_else(|| {
                        TssError::Protocol(format!(
                            "party {} has no receive channel for peer {}",
                            self_id, message.from
                        ))
                    })?;

                message.data = recv_channel
                    .decrypt(&message.data)
                    .map_err(|_| TssError::Encryption("p2p decrypt failed".into()))?;
            }
        }

        Ok(messages)
    }
}

pub fn create_encrypted_routers(
    ids: &[Identifier],
) -> Result<HashMap<Identifier, EncryptedRouter>, TssError> {
    let mut routers = create_routers(ids);
    let mut peer_channels: HashMap<Identifier, HashMap<Identifier, (P2PChannel, P2PChannel)>> =
        ids.iter().copied().map(|id| (id, HashMap::new())).collect();

    for left_index in 0..ids.len() {
        for right_index in (left_index + 1)..ids.len() {
            let left = ids[left_index];
            let right = ids[right_index];

            let (left_secret, left_public) = generate_keypair();
            let (right_secret, right_public) = generate_keypair();
            let left_shared = derive_shared_secret(left_secret, &right_public);
            let right_shared = derive_shared_secret(right_secret, &left_public);

            if left_shared != right_shared {
                return Err(TssError::Encryption(format!(
                    "mismatched shared secret for parties {} and {}",
                    left, right
                )));
            }

            let left_pair = channel_pair_from_shared_secret(left_shared, true)?;
            let right_pair = channel_pair_from_shared_secret(right_shared, false)?;

            peer_channels
                .get_mut(&left)
                .expect("left channel map exists")
                .insert(right, left_pair);
            peer_channels
                .get_mut(&right)
                .expect("right channel map exists")
                .insert(left, right_pair);
        }
    }

    ids.iter()
        .copied()
        .map(|id| {
            let inner = routers
                .remove(&id)
                .expect("plain router exists for every encrypted party");
            let channels = peer_channels
                .remove(&id)
                .expect("channel map exists for every encrypted party");

            Ok((
                id,
                EncryptedRouter {
                    inner,
                    peer_channels: channels,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{create_encrypted_routers, create_routers};
    use crate::{Identifier, Message};

    fn ids() -> Vec<Identifier> {
        vec![
            Identifier::new(1).unwrap(),
            Identifier::new(2).unwrap(),
            Identifier::new(3).unwrap(),
        ]
    }

    #[tokio::test]
    async fn broadcast_reaches_all_peers() {
        let ids = ids();
        let mut routers = create_routers(&ids);

        let router1 = routers.remove(&ids[0]).unwrap();
        let mut router2 = routers.remove(&ids[1]).unwrap();
        let mut router3 = routers.remove(&ids[2]).unwrap();

        router1
            .send(vec![Message {
                from: ids[0],
                to: None,
                data: b"broadcast".to_vec(),
            }])
            .await
            .unwrap();
        router2.send(Vec::new()).await.unwrap();
        router3.send(Vec::new()).await.unwrap();

        let received2 = router2.receive_from_all_peers().await.unwrap();
        let received3 = router3.receive_from_all_peers().await.unwrap();

        assert_eq!(received2.len(), 1);
        assert_eq!(received3.len(), 1);
        assert_eq!(received2[0].data, b"broadcast");
        assert_eq!(received3[0].data, b"broadcast");
    }

    #[tokio::test]
    async fn p2p_reaches_only_target() {
        let ids = ids();
        let mut routers = create_routers(&ids);

        let router1 = routers.remove(&ids[0]).unwrap();
        let mut router2 = routers.remove(&ids[1]).unwrap();
        let mut router3 = routers.remove(&ids[2]).unwrap();

        router1
            .send(vec![Message {
                from: ids[0],
                to: Some(ids[1]),
                data: b"secret".to_vec(),
            }])
            .await
            .unwrap();
        router2.send(Vec::new()).await.unwrap();
        router3.send(Vec::new()).await.unwrap();

        let received2 = router2.receive_from_all_peers().await.unwrap();
        let received3 = router3.receive_from_all_peers().await.unwrap();

        assert_eq!(received2.len(), 1);
        assert_eq!(received2[0].data, b"secret");
        assert!(received3.is_empty());
    }

    #[tokio::test]
    async fn encrypted_router_round_trip() {
        let ids = ids();
        let mut routers = create_encrypted_routers(&ids).unwrap();

        let mut router1 = routers.remove(&ids[0]).unwrap();
        let mut router2 = routers.remove(&ids[1]).unwrap();
        let mut router3 = routers.remove(&ids[2]).unwrap();

        router1
            .send(vec![Message {
                from: ids[0],
                to: Some(ids[1]),
                data: b"ciphertext".to_vec(),
            }])
            .await
            .unwrap();
        router2.send(Vec::new()).await.unwrap();
        router3.send(Vec::new()).await.unwrap();

        let received2 = router2.receive_from_all_peers().await.unwrap();
        let received3 = router3.receive_from_all_peers().await.unwrap();

        assert_eq!(received2[0].data, b"ciphertext");
        assert!(received3.is_empty());
    }
}
