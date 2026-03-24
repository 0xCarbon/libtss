use crate::error::TssError;
use crate::types::Ciphersuite;

/// Verify a signature against a message and public key.
///
/// Works for all ciphersuites — both FROST (Schnorr) and DKLs23 (ECDSA).
///
/// For FROST suites, `message` is the original message (the FROST verifier handles hashing).
/// For ECDSA suites (DKLs23), `message` is the raw message — it will be SHA-256 hashed
/// internally, consistent with ECDSA convention.
///
/// # Examples
///
/// ```
/// use libtss::{Ciphersuite, ThresholdConfig};
///
/// // Generate a key pair via trusted dealer and sign
/// let config = ThresholdConfig {
///     min_signers: 2,
///     max_signers: 3,
///     suite: Ciphersuite::Ed25519,
/// };
/// let (shares, pubkey) = libtss::frost::frost_generate_with_dealer(&config).unwrap();
/// let group_key = pubkey.verifying_key().to_vec();
///
/// // Verification requires a real threshold signature; see integration tests
/// // for full DKG → sign → verify examples.
/// ```
pub fn verify(
    suite: Ciphersuite,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, TssError> {
    match suite {
        Ciphersuite::Secp256k1Taproot => {
            let vk = frost_secp256k1_tr::VerifyingKey::deserialize(public_key)
                .map_err(|_| TssError::DeserializeFailed("invalid public key".into()))?;
            let sig = frost_secp256k1_tr::Signature::deserialize(signature)
                .map_err(|_| TssError::InvalidSignature)?;
            Ok(vk.verify(message, &sig).is_ok())
        }
        Ciphersuite::Secp256k1 => {
            let vk = frost_secp256k1::VerifyingKey::deserialize(public_key)
                .map_err(|_| TssError::DeserializeFailed("invalid public key".into()))?;
            let sig = frost_secp256k1::Signature::deserialize(signature)
                .map_err(|_| TssError::InvalidSignature)?;
            Ok(vk.verify(message, &sig).is_ok())
        }
        Ciphersuite::Ed25519 => {
            let vk = frost_ed25519::VerifyingKey::deserialize(public_key)
                .map_err(|_| TssError::DeserializeFailed("invalid public key".into()))?;
            let sig = frost_ed25519::Signature::deserialize(signature)
                .map_err(|_| TssError::InvalidSignature)?;
            Ok(vk.verify(message, &sig).is_ok())
        }
        Ciphersuite::P256 => {
            let vk = frost_p256::VerifyingKey::deserialize(public_key)
                .map_err(|_| TssError::DeserializeFailed("invalid public key".into()))?;
            let sig = frost_p256::Signature::deserialize(signature)
                .map_err(|_| TssError::InvalidSignature)?;
            Ok(vk.verify(message, &sig).is_ok())
        }
        Ciphersuite::Ristretto255 => {
            let vk = frost_ristretto255::VerifyingKey::deserialize(public_key)
                .map_err(|_| TssError::DeserializeFailed("invalid public key".into()))?;
            let sig = frost_ristretto255::Signature::deserialize(signature)
                .map_err(|_| TssError::InvalidSignature)?;
            Ok(vk.verify(message, &sig).is_ok())
        }
        Ciphersuite::Ed448 => {
            let vk = frost_ed448::VerifyingKey::deserialize(public_key)
                .map_err(|_| TssError::DeserializeFailed("invalid public key".into()))?;
            let sig = frost_ed448::Signature::deserialize(signature)
                .map_err(|_| TssError::InvalidSignature)?;
            Ok(vk.verify(message, &sig).is_ok())
        }
        Ciphersuite::Secp256k1ECDSA => {
            use k256::ecdsa::signature::Verifier;
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| TssError::DeserializeFailed("invalid public key".into()))?;
            let sig = k256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| TssError::InvalidSignature)?;
            Ok(vk.verify(message, &sig).is_ok())
        }
        Ciphersuite::Secp256r1ECDSA => {
            use p256::ecdsa::signature::Verifier;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| TssError::DeserializeFailed("invalid public key".into()))?;
            let sig = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| TssError::InvalidSignature)?;
            Ok(vk.verify(message, &sig).is_ok())
        }
    }
}
