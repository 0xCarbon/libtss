//! P2P channel encryption helpers for the reference example.
//!
//! This is a small, testable X25519 + ChaCha20-Poly1305 transport shim used by
//! the DKLs23-style demo. It is deliberately in-process and reference-oriented.

use std::fmt;

use chacha20poly1305::{
    aead::{Aead, Error as AeadError, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::TssError;

const NONCE_LEN: usize = 12;

#[derive(Clone)]
pub struct P2PChannel {
    cipher: ChaCha20Poly1305,
    direction: u8,
    counter: u64,
}

impl fmt::Debug for P2PChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("P2PChannel")
            .field("direction", &self.direction)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl P2PChannel {
    pub fn from_shared_secret(shared_secret: [u8; 32], direction: u8) -> Result<Self, TssError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&shared_secret)
            .map_err(|_| TssError::Encryption("invalid shared secret length".into()))?;

        Ok(Self {
            cipher,
            direction,
            counter: 0,
        })
    }

    #[cfg(test)]
    pub fn direction(&self) -> u8 {
        self.direction
    }

    pub fn current_nonce(&self) -> [u8; NONCE_LEN] {
        nonce_bytes(self.direction, self.counter)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = Nonce::from(self.current_nonce());
        let ciphertext = self.cipher.encrypt(&nonce, plaintext)?;
        self.counter = self.counter.saturating_add(1);
        Ok(ciphertext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = Nonce::from(self.current_nonce());
        let plaintext = self.cipher.decrypt(&nonce, ciphertext)?;
        self.counter = self.counter.saturating_add(1);
        Ok(plaintext)
    }
}

pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn derive_shared_secret(our_secret: EphemeralSecret, their_public: &PublicKey) -> [u8; 32] {
    our_secret.diffie_hellman(their_public).to_bytes()
}

pub fn channel_pair_from_shared_secret(
    shared_secret: [u8; 32],
    initiator: bool,
) -> Result<(P2PChannel, P2PChannel), TssError> {
    let send_direction = if initiator { 0 } else { 1 };
    let recv_direction = send_direction ^ 1;

    Ok((
        P2PChannel::from_shared_secret(shared_secret, send_direction)?,
        P2PChannel::from_shared_secret(shared_secret, recv_direction)?,
    ))
}

fn nonce_bytes(direction: u8, counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[0] = direction;
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::{
        channel_pair_from_shared_secret, derive_shared_secret, generate_keypair, P2PChannel,
    };

    fn pair() -> (P2PChannel, P2PChannel) {
        let (alice_secret, alice_public) = generate_keypair();
        let (bob_secret, bob_public) = generate_keypair();
        let alice_shared = derive_shared_secret(alice_secret, &bob_public);
        let bob_shared = derive_shared_secret(bob_secret, &alice_public);

        assert_eq!(alice_shared, bob_shared);

        let (alice_send, _) = channel_pair_from_shared_secret(alice_shared, true).unwrap();
        let (_, bob_recv) = channel_pair_from_shared_secret(bob_shared, false).unwrap();
        (alice_send, bob_recv)
    }

    #[test]
    fn round_trip() {
        let (mut alice_send, mut bob_recv) = pair();
        let ciphertext = alice_send.encrypt(b"hello world").unwrap();
        let plaintext = bob_recv.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, b"hello world");
    }

    #[test]
    fn wrong_key_fails() {
        let (mut alice_send, _) = pair();
        let (eve_secret, eve_public) = generate_keypair();
        let (mallory_secret, mallory_public) = generate_keypair();
        let eve_shared = derive_shared_secret(eve_secret, &mallory_public);
        let mallory_shared = derive_shared_secret(mallory_secret, &eve_public);

        assert_eq!(eve_shared, mallory_shared);

        let (_, mut wrong_recv) = channel_pair_from_shared_secret(eve_shared, false).unwrap();
        let ciphertext = alice_send.encrypt(b"private").unwrap();
        assert!(wrong_recv.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn nonce_direction_isolation() {
        let shared = [7_u8; 32];
        let (initiator_send, initiator_recv) =
            channel_pair_from_shared_secret(shared, true).unwrap();
        let (responder_send, responder_recv) =
            channel_pair_from_shared_secret(shared, false).unwrap();

        assert_eq!(initiator_send.direction(), 0);
        assert_eq!(responder_send.direction(), 1);
        assert_eq!(initiator_recv.direction(), 1);
        assert_eq!(responder_recv.direction(), 0);
        assert_ne!(
            initiator_send.current_nonce(),
            responder_send.current_nonce()
        );
    }

    #[test]
    fn multiple_messages_advance_nonce() {
        let (mut alice_send, mut bob_recv) = pair();
        let first = alice_send.encrypt(b"first").unwrap();
        let second = alice_send.encrypt(b"second").unwrap();

        assert_ne!(first, second);
        assert_eq!(bob_recv.decrypt(&first).unwrap(), b"first");
        assert_eq!(bob_recv.decrypt(&second).unwrap(), b"second");
    }
}
