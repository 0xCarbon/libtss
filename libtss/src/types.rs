use std::collections::BTreeMap;
use std::fmt;

use crate::error::TssError;

/// Threshold signing protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// RFC 9591 threshold Schnorr signatures.
    Frost = 0,
    /// DKLs23 threshold ECDSA.
    DKLs23 = 1,
}

/// Ciphersuite identifier (curve + hash).
///
/// # Examples
///
/// ```
/// use libtss::Ciphersuite;
///
/// // Convert from u8 discriminant
/// let suite = Ciphersuite::try_from(2u8).unwrap();
/// assert_eq!(suite, Ciphersuite::Ed25519);
///
/// // Query protocol and sizes
/// assert_eq!(suite.protocol(), libtss::Protocol::Frost);
/// assert_eq!(suite.scalar_size(), 32);
///
/// // Invalid discriminant
/// assert!(Ciphersuite::try_from(99u8).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ciphersuite {
    Secp256k1Taproot = 0,
    Secp256k1 = 1,
    Ed25519 = 2,
    P256 = 3,
    Ristretto255 = 4,
    Ed448 = 5,
    Secp256k1ECDSA = 6,
    Secp256r1ECDSA = 7,
}

impl TryFrom<u8> for Ciphersuite {
    type Error = TssError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Secp256k1Taproot),
            1 => Ok(Self::Secp256k1),
            2 => Ok(Self::Ed25519),
            3 => Ok(Self::P256),
            4 => Ok(Self::Ristretto255),
            5 => Ok(Self::Ed448),
            6 => Ok(Self::Secp256k1ECDSA),
            7 => Ok(Self::Secp256r1ECDSA),
            _ => Err(TssError::DeserializeFailed("unknown ciphersuite".into())),
        }
    }
}

const DEFAULT_SCALAR_SIZE: usize = 32;
const ED448_SCALAR_SIZE: usize = 57;
const COMPRESSED_POINT_SIZE: usize = 33;

impl Ciphersuite {
    pub fn protocol(self) -> Protocol {
        match self {
            Self::Secp256k1ECDSA | Self::Secp256r1ECDSA => Protocol::DKLs23,
            _ => Protocol::Frost,
        }
    }

    /// Size of a scalar element in bytes for this ciphersuite.
    pub fn scalar_size(self) -> usize {
        match self {
            Self::Ed448 => ED448_SCALAR_SIZE,
            _ => DEFAULT_SCALAR_SIZE,
        }
    }

    /// Size of a group element in bytes for this ciphersuite.
    pub fn element_size(self) -> usize {
        match self {
            Self::Ed25519 | Self::Ristretto255 => DEFAULT_SCALAR_SIZE,
            Self::Ed448 => ED448_SCALAR_SIZE,
            Self::Secp256k1Taproot
            | Self::Secp256k1
            | Self::P256
            | Self::Secp256k1ECDSA
            | Self::Secp256r1ECDSA => COMPRESSED_POINT_SIZE,
        }
    }
}

/// Threshold (t, n) parameters for a signing group.
///
/// # Examples
///
/// ```
/// use libtss::{ThresholdConfig, Ciphersuite};
///
/// let config = ThresholdConfig {
///     min_signers: 2,
///     max_signers: 3,
///     suite: Ciphersuite::Ed25519,
/// };
/// assert!(config.validate().is_ok());
///
/// // min_signers must be >= 2
/// let bad = ThresholdConfig { min_signers: 1, ..config.clone() };
/// assert!(bad.validate().is_err());
/// ```
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    pub min_signers: u16,
    pub max_signers: u16,
    pub suite: Ciphersuite,
}

impl ThresholdConfig {
    pub fn validate(&self) -> Result<(), TssError> {
        if self.min_signers < 2 {
            return Err(TssError::InvalidConfig("min_signers must be >= 2".into()));
        }
        if self.max_signers < self.min_signers {
            return Err(TssError::InvalidConfig(
                "max_signers must be >= min_signers".into(),
            ));
        }
        Ok(())
    }
}

/// Participant identifier. Non-zero, 1-based index.
///
/// # Examples
///
/// ```
/// use libtss::Identifier;
///
/// let id = Identifier::new(1).unwrap();
/// assert_eq!(id.as_u16(), 1);
///
/// // Zero is rejected
/// assert!(Identifier::new(0).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identifier(u16);

impl Identifier {
    pub fn new(index: u16) -> Result<Self, TssError> {
        if index == 0 {
            return Err(TssError::InvalidIdentifier);
        }
        Ok(Self(index))
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Threshold signature (indistinguishable from single-signer).
///
/// # Examples
///
/// ```
/// use libtss::{Protocol, Signature};
///
/// // FROST Schnorr signature (no recovery ID)
/// let sig = Signature::new(Protocol::Frost, vec![0u8; 64], None);
/// assert_eq!(sig.as_bytes().len(), 64);
/// assert_eq!(sig.recovery_id(), None);
/// assert_eq!(sig.protocol(), Protocol::Frost);
///
/// // DKLs23 ECDSA signature (with recovery ID)
/// let ecdsa = Signature::new(Protocol::DKLs23, vec![0u8; 64], Some(0));
/// assert_eq!(ecdsa.recovery_id(), Some(0));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    protocol: Protocol,
    data: Vec<u8>,
    recovery_id: Option<u8>,
}

impl Signature {
    pub fn new(protocol: Protocol, data: Vec<u8>, recovery_id: Option<u8>) -> Self {
        Self {
            protocol,
            data,
            recovery_id,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn recovery_id(&self) -> Option<u8> {
        self.recovery_id
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

/// Group public key and per-participant verification shares.
///
/// All public information — safe to share freely. Serializes to a compact
/// binary format via [`serialize`](Self::serialize) /
/// [`deserialize`](Self::deserialize).
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use libtss::{PublicKeyPackage, Ciphersuite, Identifier};
///
/// let mut shares = BTreeMap::new();
/// shares.insert(Identifier::new(1).unwrap(), vec![10, 20]);
/// shares.insert(Identifier::new(2).unwrap(), vec![30, 40]);
///
/// let pkg = PublicKeyPackage::new(Ciphersuite::Ed25519, vec![1, 2, 3], shares, 2);
///
/// // Round-trip serialization
/// let bytes = pkg.serialize().unwrap();
/// let decoded = PublicKeyPackage::deserialize(&bytes).unwrap();
/// assert_eq!(pkg, decoded);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyPackage {
    suite: Ciphersuite,
    verifying_key: Vec<u8>,
    verifying_shares: BTreeMap<Identifier, Vec<u8>>,
    min_signers: u16,
}

impl PublicKeyPackage {
    pub fn new(
        suite: Ciphersuite,
        verifying_key: Vec<u8>,
        verifying_shares: BTreeMap<Identifier, Vec<u8>>,
        min_signers: u16,
    ) -> Self {
        Self {
            suite,
            verifying_key,
            verifying_shares,
            min_signers,
        }
    }

    pub fn suite(&self) -> Ciphersuite {
        self.suite
    }

    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying_key
    }

    pub fn verifying_share(&self, id: Identifier) -> Option<&[u8]> {
        self.verifying_shares.get(&id).map(Vec::as_slice)
    }

    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Serialize to a binary format.
    /// Format: suite(1) + min_signers(2 LE) + vk_len(4 LE) + vk + share_count(2 LE)
    ///         + [id(2 LE) + share_len(4 LE) + share_data] ...
    pub fn serialize(&self) -> Result<Vec<u8>, TssError> {
        let mut buf = Vec::new();
        buf.push(self.suite as u8);
        buf.extend_from_slice(&self.min_signers.to_le_bytes());
        buf.extend_from_slice(&(self.verifying_key.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.verifying_key);
        buf.extend_from_slice(&(self.verifying_shares.len() as u16).to_le_bytes());
        for (id, share) in &self.verifying_shares {
            buf.extend_from_slice(&id.as_u16().to_le_bytes());
            buf.extend_from_slice(&(share.len() as u32).to_le_bytes());
            buf.extend_from_slice(share);
        }
        Ok(buf)
    }

    /// Deserialize from binary format produced by `serialize()`.
    pub fn deserialize(data: &[u8]) -> Result<Self, TssError> {
        if data.len() < 7 {
            return Err(TssError::DeserializeFailed(
                "PublicKeyPackage too short".into(),
            ));
        }
        let suite = Ciphersuite::try_from(data[0])?;
        let min_signers = u16::from_le_bytes([data[1], data[2]]);
        let vk_len = u32::from_le_bytes([data[3], data[4], data[5], data[6]]) as usize;
        let mut pos = 7;
        if pos + vk_len > data.len() {
            return Err(TssError::DeserializeFailed(
                "truncated verifying key".into(),
            ));
        }
        let verifying_key = data[pos..pos + vk_len].to_vec();
        pos += vk_len;
        if pos + 2 > data.len() {
            return Err(TssError::DeserializeFailed("truncated share count".into()));
        }
        let share_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let mut verifying_shares = BTreeMap::new();
        for _ in 0..share_count {
            if pos + 6 > data.len() {
                return Err(TssError::DeserializeFailed("truncated share header".into()));
            }
            let id = Identifier::new(u16::from_le_bytes([data[pos], data[pos + 1]]))?;
            let slen =
                u32::from_le_bytes([data[pos + 2], data[pos + 3], data[pos + 4], data[pos + 5]])
                    as usize;
            pos += 6;
            if pos + slen > data.len() {
                return Err(TssError::DeserializeFailed("truncated share data".into()));
            }
            if verifying_shares
                .insert(id, data[pos..pos + slen].to_vec())
                .is_some()
            {
                return Err(TssError::DeserializeFailed(
                    "duplicate identifier in verifying shares".into(),
                ));
            }
            pos += slen;
        }
        if pos != data.len() {
            return Err(TssError::DeserializeFailed(
                "trailing bytes after PublicKeyPackage".into(),
            ));
        }
        Ok(Self {
            suite,
            verifying_key,
            verifying_shares,
            min_signers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_zero_fails() {
        assert_eq!(Identifier::new(0), Err(TssError::InvalidIdentifier));
    }

    #[test]
    fn identifier_valid() {
        assert!(Identifier::new(1).is_ok());
        assert!(Identifier::new(u16::MAX).is_ok());
    }

    #[test]
    fn identifier_roundtrip() {
        assert_eq!(Identifier::new(5).unwrap().as_u16(), 5);
    }

    #[test]
    fn threshold_config_valid() {
        let cfg = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Ed25519,
        };

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn threshold_config_min_too_low() {
        let cfg = ThresholdConfig {
            min_signers: 1,
            max_signers: 3,
            suite: Ciphersuite::Ed25519,
        };

        assert_eq!(
            cfg.validate(),
            Err(TssError::InvalidConfig("min_signers must be >= 2".into()))
        );
    }

    #[test]
    fn threshold_config_max_less_than_min() {
        let cfg = ThresholdConfig {
            min_signers: 3,
            max_signers: 2,
            suite: Ciphersuite::Ed25519,
        };

        assert_eq!(
            cfg.validate(),
            Err(TssError::InvalidConfig(
                "max_signers must be >= min_signers".into()
            ))
        );
    }

    #[test]
    fn ciphersuite_protocol_mapping() {
        assert_eq!(Ciphersuite::Secp256k1Taproot.protocol(), Protocol::Frost);
        assert_eq!(Ciphersuite::Secp256k1.protocol(), Protocol::Frost);
        assert_eq!(Ciphersuite::Ed25519.protocol(), Protocol::Frost);
        assert_eq!(Ciphersuite::P256.protocol(), Protocol::Frost);
        assert_eq!(Ciphersuite::Ristretto255.protocol(), Protocol::Frost);
        assert_eq!(Ciphersuite::Ed448.protocol(), Protocol::Frost);
        assert_eq!(Ciphersuite::Secp256k1ECDSA.protocol(), Protocol::DKLs23);
        assert_eq!(Ciphersuite::Secp256r1ECDSA.protocol(), Protocol::DKLs23);
    }

    #[test]
    fn ciphersuite_sizes() {
        assert_eq!(Ciphersuite::Ed448.scalar_size(), 57);
        assert_eq!(Ciphersuite::Secp256k1.scalar_size(), 32);
        assert_eq!(Ciphersuite::Secp256k1.element_size(), 33);
        assert_eq!(Ciphersuite::Ed25519.element_size(), 32);
    }

    #[test]
    fn ciphersuite_try_from_roundtrip() {
        for disc in 0u8..=7 {
            let suite = Ciphersuite::try_from(disc).unwrap();
            assert_eq!(suite as u8, disc);
        }
        assert!(Ciphersuite::try_from(8).is_err());
        assert!(Ciphersuite::try_from(255).is_err());
    }

    #[test]
    fn public_key_package_roundtrip() {
        let mut shares = BTreeMap::new();
        shares.insert(Identifier::new(1).unwrap(), vec![10, 20, 30]);
        shares.insert(Identifier::new(2).unwrap(), vec![40, 50, 60]);

        let pkg = PublicKeyPackage::new(Ciphersuite::Ed25519, vec![1, 2, 3, 4], shares, 2);

        let serialized = pkg.serialize().unwrap();
        let deserialized = PublicKeyPackage::deserialize(&serialized).unwrap();
        assert_eq!(pkg, deserialized);
    }

    #[test]
    fn public_key_package_rejects_trailing_bytes() {
        let pkg = PublicKeyPackage::new(Ciphersuite::Secp256k1, vec![1, 2, 3], BTreeMap::new(), 2);
        let mut data = pkg.serialize().unwrap();
        data.push(0xFF);
        assert!(PublicKeyPackage::deserialize(&data).is_err());
    }

    #[test]
    fn public_key_package_rejects_truncated() {
        assert!(PublicKeyPackage::deserialize(&[]).is_err());
        assert!(PublicKeyPackage::deserialize(&[0, 0, 2]).is_err());
    }
}
