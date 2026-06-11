use std::collections::BTreeMap;

use dkls23_secp256k1::protocols::PartyIndex;
use dkls23_secp256k1::{Party, PublicKeyPackage as DklsPublicKeyPackage};
use frost_core as frost;
use frost_ed25519::keys::{
    KeyPackage as FrostEd25519KeyPackage, PublicKeyPackage as FrostEd25519PublicKeyPackage,
};
use frost_ed448::keys::{
    KeyPackage as FrostEd448KeyPackage, PublicKeyPackage as FrostEd448PublicKeyPackage,
};
use frost_p256::keys::{
    KeyPackage as FrostP256KeyPackage, PublicKeyPackage as FrostP256PublicKeyPackage,
};
use frost_ristretto255::keys::{
    KeyPackage as FrostRistretto255KeyPackage,
    PublicKeyPackage as FrostRistretto255PublicKeyPackage,
};
use frost_secp256k1::keys::{
    KeyPackage as FrostSecp256k1KeyPackage, PublicKeyPackage as FrostSecp256k1PublicKeyPackage,
};
use frost_secp256k1_tr::keys::{
    KeyPackage as FrostSecp256k1TrKeyPackage, PublicKeyPackage as FrostSecp256k1TrPublicKeyPackage,
};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::ProjectivePoint;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    handle::{CAT_DKLS_KEY, CAT_DKLS_R1_KEY, CAT_FROST_KEY, REGISTRY},
    Ciphersuite, Identifier, PublicKeyPackage, TssError,
};

const EXPORT_MAGIC: &[u8; 4] = b"LTSS";
const EXPORT_HEADER_SIZE: usize = 8;
const EXPORT_CHECKSUM_SIZE: usize = 32;
const MIN_EXPORT_SIZE: usize = EXPORT_HEADER_SIZE + EXPORT_CHECKSUM_SIZE;

// SAFETY: All secret-bearing fields in these variants implement ZeroizeOnDrop
// (FROST KeyPackage via derive, DKLs23 Party via manual impl). When the enum
// is dropped, Rust drops each field, triggering automatic zeroization of secrets.
#[allow(clippy::large_enum_variant)]
pub(crate) enum KeyShareInner {
    FrostSecp256k1Tr(FrostSecp256k1TrKeyPackage, FrostSecp256k1TrPublicKeyPackage),
    FrostSecp256k1(FrostSecp256k1KeyPackage, FrostSecp256k1PublicKeyPackage),
    FrostEd25519(FrostEd25519KeyPackage, FrostEd25519PublicKeyPackage),
    FrostP256(FrostP256KeyPackage, FrostP256PublicKeyPackage),
    FrostRistretto255(
        FrostRistretto255KeyPackage,
        FrostRistretto255PublicKeyPackage,
    ),
    FrostEd448(FrostEd448KeyPackage, FrostEd448PublicKeyPackage),
    DKLs23(Party, DklsPublicKeyPackage),
    DKLs23Secp256r1(dkls23_secp256r1::Party, dkls23_secp256r1::PublicKeyPackage),
}

#[derive(Debug)]
pub struct KeyShareHandle {
    pub(crate) id: u64,
    suite: Ciphersuite,
    identifier: Identifier,
    verifying_share: Vec<u8>,
    public_key_package: PublicKeyPackage,
}

impl KeyShareHandle {
    pub(crate) fn new(inner: KeyShareInner) -> Result<Self, TssError> {
        let KeyShareDescription {
            category,
            suite,
            identifier,
            verifying_share,
            public_key_package,
        } = describe_key_share(&inner)?;
        let id = REGISTRY.insert(category, inner);

        Ok(Self {
            id,
            suite,
            identifier,
            verifying_share,
            public_key_package,
        })
    }

    pub fn handle_id(&self) -> u64 {
        self.id
    }

    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    pub fn verifying_share(&self) -> Vec<u8> {
        self.verifying_share.clone()
    }

    pub fn group_verifying_key(&self) -> Vec<u8> {
        self.public_key_package.verifying_key().to_vec()
    }

    /// Return the 32-byte BIP-32 chain code this share derives children with.
    ///
    /// For DKLs23 it is the chain code established at DKG time (the value
    /// `derive_child` mixes into the HMAC); for FROST it is
    /// `SHA-256(group verifying key)`, matching the deterministic chain code
    /// `derive.rs` uses. The chain code is public material: callers wrap it with
    /// the group key into a BIP-32 xpub so off-MPC pubkey derivation matches the
    /// child shares each party derives locally.
    pub fn chain_code(&self) -> Result<Vec<u8>, TssError> {
        REGISTRY.with::<KeyShareInner, _>(self.id, |inner| -> Result<Vec<u8>, TssError> {
            Ok(match inner {
                KeyShareInner::DKLs23(party, _) => party.derivation_data.chain_code.to_vec(),
                KeyShareInner::DKLs23Secp256r1(party, _) => {
                    party.derivation_data.chain_code.to_vec()
                }
                _ => Sha256::digest(self.public_key_package.verifying_key()).to_vec(),
            })
        })?
    }

    pub fn ciphersuite(&self) -> Ciphersuite {
        self.suite
    }

    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }

    /// Export the key share as a serialized byte blob.
    ///
    /// **Security:** The returned bytes contain unencrypted secret key material.
    /// The caller MUST encrypt the output before persisting to disk or
    /// transmitting over a network. Use an authenticated encryption scheme
    /// (e.g. AES-256-GCM) with a key derived from a user passphrase or
    /// secure enclave.
    pub fn export(&self) -> Result<Vec<u8>, TssError> {
        let payload: Zeroizing<Vec<u8>> = REGISTRY
            .with::<KeyShareInner, _>(self.id, serialize_key_share)??
            .into();
        Ok(wrap_export(self.suite, &payload))
    }

    /// Reconstruct a `KeyShareHandle` from an existing registry ID.
    ///
    /// The returned handle will free the registry entry when dropped. Use
    /// `ManuallyDrop` if the caller does not own the entry (e.g. FFI layer
    /// where the C caller still holds the handle).
    pub fn from_registry_id(id: u64) -> Result<Self, TssError> {
        let (suite, identifier, verifying_share, public_key_package) = REGISTRY
            .with::<KeyShareInner, _>(id, |inner| -> Result<_, TssError> {
                let desc = describe_key_share(inner)?;
                Ok((
                    desc.suite,
                    desc.identifier,
                    desc.verifying_share,
                    desc.public_key_package,
                ))
            })??;
        Ok(Self {
            id,
            suite,
            identifier,
            verifying_share,
            public_key_package,
        })
    }
}

/// Create a KeyShareHandle from a frost::KeyShareHandle (DKG output) and a unified PublicKeyPackage.
pub fn from_frost_dkg(
    frost_handle: crate::frost::KeyShareHandle,
    pubkey: &PublicKeyPackage,
) -> Result<KeyShareHandle, TssError> {
    let (suite, bytes) = frost_handle.into_parts();
    let bytes = Zeroizing::new(bytes);
    let inner = match suite {
        Ciphersuite::Secp256k1Taproot => {
            let kp = FrostSecp256k1TrKeyPackage::deserialize(&bytes).map_err(TssError::from)?;
            let pk = crate::frost::libtss_pubkey_to_frost::<frost_secp256k1_tr::Secp256K1Sha256TR>(
                suite, pubkey,
            )?;
            KeyShareInner::FrostSecp256k1Tr(kp, pk)
        }
        Ciphersuite::Secp256k1 => {
            let kp = FrostSecp256k1KeyPackage::deserialize(&bytes).map_err(TssError::from)?;
            let pk = crate::frost::libtss_pubkey_to_frost::<frost_secp256k1::Secp256K1Sha256>(
                suite, pubkey,
            )?;
            KeyShareInner::FrostSecp256k1(kp, pk)
        }
        Ciphersuite::Ed25519 => {
            let kp = FrostEd25519KeyPackage::deserialize(&bytes).map_err(TssError::from)?;
            let pk = crate::frost::libtss_pubkey_to_frost::<frost_ed25519::Ed25519Sha512>(
                suite, pubkey,
            )?;
            KeyShareInner::FrostEd25519(kp, pk)
        }
        Ciphersuite::P256 => {
            let kp = FrostP256KeyPackage::deserialize(&bytes).map_err(TssError::from)?;
            let pk = crate::frost::libtss_pubkey_to_frost::<frost_p256::P256Sha256>(suite, pubkey)?;
            KeyShareInner::FrostP256(kp, pk)
        }
        Ciphersuite::Ristretto255 => {
            let kp = FrostRistretto255KeyPackage::deserialize(&bytes).map_err(TssError::from)?;
            let pk = crate::frost::libtss_pubkey_to_frost::<frost_ristretto255::Ristretto255Sha512>(
                suite, pubkey,
            )?;
            KeyShareInner::FrostRistretto255(kp, pk)
        }
        Ciphersuite::Ed448 => {
            let kp = FrostEd448KeyPackage::deserialize(&bytes).map_err(TssError::from)?;
            let pk =
                crate::frost::libtss_pubkey_to_frost::<frost_ed448::Ed448Shake256>(suite, pubkey)?;
            KeyShareInner::FrostEd448(kp, pk)
        }
        Ciphersuite::Secp256k1ECDSA | Ciphersuite::Secp256r1ECDSA => {
            return Err(TssError::ProtocolMismatch)
        }
    };
    KeyShareHandle::new(inner)
}

/// Create a KeyShareHandle from DKLs23 secp256k1 DKG output.
pub(crate) fn from_dkls_dkg(
    party: Party,
    dkls_pubkey: DklsPublicKeyPackage,
) -> Result<KeyShareHandle, TssError> {
    KeyShareHandle::new(KeyShareInner::DKLs23(party, dkls_pubkey))
}

/// Create a KeyShareHandle from DKLs23 secp256r1 DKG output.
pub(crate) fn from_dkls_r1_dkg(
    party: dkls23_secp256r1::Party,
    dkls_pubkey: dkls23_secp256r1::PublicKeyPackage,
) -> Result<KeyShareHandle, TssError> {
    KeyShareHandle::new(KeyShareInner::DKLs23Secp256r1(party, dkls_pubkey))
}

/// Extract a frost::KeyShareHandle from a registry-based handle (serializes the key package).
pub fn to_frost_handle(handle: &KeyShareHandle) -> Result<crate::frost::KeyShareHandle, TssError> {
    let bytes =
        REGISTRY.with::<KeyShareInner, _>(handle.id, |inner| -> Result<Vec<u8>, TssError> {
            macro_rules! ser {
                ($kp:expr) => {
                    $kp.serialize().map_err(TssError::from)
                };
            }
            match inner {
                KeyShareInner::FrostSecp256k1Tr(kp, _) => ser!(kp),
                KeyShareInner::FrostSecp256k1(kp, _) => ser!(kp),
                KeyShareInner::FrostEd25519(kp, _) => ser!(kp),
                KeyShareInner::FrostP256(kp, _) => ser!(kp),
                KeyShareInner::FrostRistretto255(kp, _) => ser!(kp),
                KeyShareInner::FrostEd448(kp, _) => ser!(kp),
                KeyShareInner::DKLs23(..) | KeyShareInner::DKLs23Secp256r1(..) => {
                    Err(TssError::ProtocolMismatch)
                }
            }
        })??;
    Ok(crate::frost::KeyShareHandle::from_parts(
        handle.ciphersuite(),
        handle.identifier(),
        bytes,
    ))
}

/// Clone the DKLs23 secp256k1 Party from a registry-based handle.
pub(crate) fn clone_dkls_party(handle: &KeyShareHandle) -> Result<Party, TssError> {
    REGISTRY.with::<KeyShareInner, _>(handle.id, |inner| match inner {
        KeyShareInner::DKLs23(party, _) => Ok(party.clone()),
        _ => Err(TssError::ProtocolMismatch),
    })?
}

/// Clone the DKLs23 secp256k1 PublicKeyPackage from a registry-based handle.
pub(crate) fn clone_dkls_pubkey(handle: &KeyShareHandle) -> Result<DklsPublicKeyPackage, TssError> {
    REGISTRY.with::<KeyShareInner, _>(handle.id, |inner| match inner {
        KeyShareInner::DKLs23(_, pubkey) => Ok(pubkey.clone()),
        _ => Err(TssError::ProtocolMismatch),
    })?
}

/// Clone the DKLs23 secp256r1 Party from a registry-based handle.
pub(crate) fn clone_dkls_r1_party(
    handle: &KeyShareHandle,
) -> Result<dkls23_secp256r1::Party, TssError> {
    REGISTRY.with::<KeyShareInner, _>(handle.id, |inner| match inner {
        KeyShareInner::DKLs23Secp256r1(party, _) => Ok(party.clone()),
        _ => Err(TssError::ProtocolMismatch),
    })?
}

/// Clone the DKLs23 secp256r1 PublicKeyPackage from a registry-based handle.
pub(crate) fn clone_dkls_r1_pubkey(
    handle: &KeyShareHandle,
) -> Result<dkls23_secp256r1::PublicKeyPackage, TssError> {
    REGISTRY.with::<KeyShareInner, _>(handle.id, |inner| match inner {
        KeyShareInner::DKLs23Secp256r1(_, pubkey) => Ok(pubkey.clone()),
        _ => Err(TssError::ProtocolMismatch),
    })?
}

/// Create a KeyShareHandle from FROST Taproot key package and public key package (for derivation).
pub(crate) fn from_frost_taproot_derived(
    key_package: FrostSecp256k1TrKeyPackage,
    public_keys: FrostSecp256k1TrPublicKeyPackage,
) -> Result<KeyShareHandle, TssError> {
    KeyShareHandle::new(KeyShareInner::FrostSecp256k1Tr(key_package, public_keys))
}

/// Clone the FROST Secp256k1 Taproot key package and public key package from registry.
pub(crate) fn clone_frost_taproot(
    handle: &KeyShareHandle,
) -> Result<(FrostSecp256k1TrKeyPackage, FrostSecp256k1TrPublicKeyPackage), TssError> {
    REGISTRY.with::<KeyShareInner, _>(handle.id, |inner| match inner {
        KeyShareInner::FrostSecp256k1Tr(kp, pk) => Ok((kp.clone(), pk.clone())),
        _ => Err(TssError::ProtocolMismatch),
    })?
}

impl Drop for KeyShareHandle {
    fn drop(&mut self) {
        REGISTRY.free(self.id);
    }
}

pub fn import_key_share(data: &[u8], suite: Ciphersuite) -> Result<KeyShareHandle, TssError> {
    if data.len() < MIN_EXPORT_SIZE {
        return Err(TssError::DeserializeFailed(
            "key share export too short".into(),
        ));
    }

    let header = &data[..EXPORT_HEADER_SIZE];
    let payload = &data[EXPORT_HEADER_SIZE..data.len() - EXPORT_CHECKSUM_SIZE];
    let checksum = &data[data.len() - EXPORT_CHECKSUM_SIZE..];

    if &header[..4] != EXPORT_MAGIC {
        return Err(TssError::DeserializeFailed("invalid export magic".into()));
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != 1 {
        return Err(TssError::DeserializeFailed(
            "unsupported export version".into(),
        ));
    }

    if header[6] != suite.protocol() as u8 || header[7] != suite as u8 {
        return Err(TssError::ProtocolMismatch);
    }

    let expected = export_checksum(header, payload);
    if checksum.ct_eq(expected.as_slice()).unwrap_u8() != 1 {
        return Err(TssError::DeserializeFailed("checksum mismatch".into()));
    }

    let inner = match suite {
        Ciphersuite::Secp256k1Taproot => {
            let (key_package, public_keys): (
                FrostSecp256k1TrKeyPackage,
                FrostSecp256k1TrPublicKeyPackage,
            ) = postcard::from_bytes(payload)?;
            KeyShareInner::FrostSecp256k1Tr(key_package, public_keys)
        }
        Ciphersuite::Secp256k1 => {
            let (key_package, public_keys): (
                FrostSecp256k1KeyPackage,
                FrostSecp256k1PublicKeyPackage,
            ) = postcard::from_bytes(payload)?;
            KeyShareInner::FrostSecp256k1(key_package, public_keys)
        }
        Ciphersuite::Ed25519 => {
            let (key_package, public_keys): (FrostEd25519KeyPackage, FrostEd25519PublicKeyPackage) =
                postcard::from_bytes(payload)?;
            KeyShareInner::FrostEd25519(key_package, public_keys)
        }
        Ciphersuite::P256 => {
            let (key_package, public_keys): (FrostP256KeyPackage, FrostP256PublicKeyPackage) =
                postcard::from_bytes(payload)?;
            KeyShareInner::FrostP256(key_package, public_keys)
        }
        Ciphersuite::Ristretto255 => {
            let (key_package, public_keys): (
                FrostRistretto255KeyPackage,
                FrostRistretto255PublicKeyPackage,
            ) = postcard::from_bytes(payload)?;
            KeyShareInner::FrostRistretto255(key_package, public_keys)
        }
        Ciphersuite::Ed448 => {
            let (key_package, public_keys): (FrostEd448KeyPackage, FrostEd448PublicKeyPackage) =
                postcard::from_bytes(payload)?;
            KeyShareInner::FrostEd448(key_package, public_keys)
        }
        Ciphersuite::Secp256k1ECDSA => {
            let (party, public_keys): (Party, DklsPublicKeyPackage) =
                postcard::from_bytes(payload)?;
            KeyShareInner::DKLs23(party, public_keys)
        }
        Ciphersuite::Secp256r1ECDSA => {
            let (party, public_keys): (
                dkls23_secp256r1::Party,
                dkls23_secp256r1::PublicKeyPackage,
            ) = postcard::from_bytes(payload)?;
            KeyShareInner::DKLs23Secp256r1(party, public_keys)
        }
    };

    KeyShareHandle::new(inner)
}

struct KeyShareDescription {
    category: u8,
    suite: Ciphersuite,
    identifier: Identifier,
    verifying_share: Vec<u8>,
    public_key_package: PublicKeyPackage,
}

fn describe_key_share(inner: &KeyShareInner) -> Result<KeyShareDescription, TssError> {
    match inner {
        KeyShareInner::FrostSecp256k1Tr(key_package, public_keys) => {
            describe_frost_key_share(Ciphersuite::Secp256k1Taproot, key_package, public_keys).map(
                |(identifier, verifying_share, public_key_package)| KeyShareDescription {
                    category: CAT_FROST_KEY,
                    suite: Ciphersuite::Secp256k1Taproot,
                    identifier,
                    verifying_share,
                    public_key_package,
                },
            )
        }
        KeyShareInner::FrostSecp256k1(key_package, public_keys) => {
            describe_frost_key_share(Ciphersuite::Secp256k1, key_package, public_keys).map(
                |(identifier, verifying_share, public_key_package)| KeyShareDescription {
                    category: CAT_FROST_KEY,
                    suite: Ciphersuite::Secp256k1,
                    identifier,
                    verifying_share,
                    public_key_package,
                },
            )
        }
        KeyShareInner::FrostEd25519(key_package, public_keys) => {
            describe_frost_key_share(Ciphersuite::Ed25519, key_package, public_keys).map(
                |(identifier, verifying_share, public_key_package)| KeyShareDescription {
                    category: CAT_FROST_KEY,
                    suite: Ciphersuite::Ed25519,
                    identifier,
                    verifying_share,
                    public_key_package,
                },
            )
        }
        KeyShareInner::FrostP256(key_package, public_keys) => {
            describe_frost_key_share(Ciphersuite::P256, key_package, public_keys).map(
                |(identifier, verifying_share, public_key_package)| KeyShareDescription {
                    category: CAT_FROST_KEY,
                    suite: Ciphersuite::P256,
                    identifier,
                    verifying_share,
                    public_key_package,
                },
            )
        }
        KeyShareInner::FrostRistretto255(key_package, public_keys) => {
            describe_frost_key_share(Ciphersuite::Ristretto255, key_package, public_keys).map(
                |(identifier, verifying_share, public_key_package)| KeyShareDescription {
                    category: CAT_FROST_KEY,
                    suite: Ciphersuite::Ristretto255,
                    identifier,
                    verifying_share,
                    public_key_package,
                },
            )
        }
        KeyShareInner::FrostEd448(key_package, public_keys) => {
            describe_frost_key_share(Ciphersuite::Ed448, key_package, public_keys).map(
                |(identifier, verifying_share, public_key_package)| KeyShareDescription {
                    category: CAT_FROST_KEY,
                    suite: Ciphersuite::Ed448,
                    identifier,
                    verifying_share,
                    public_key_package,
                },
            )
        }
        KeyShareInner::DKLs23(party, public_keys) => describe_dkls_key_share_k1(party, public_keys)
            .map(
                |(identifier, verifying_share, public_key_package)| KeyShareDescription {
                    category: CAT_DKLS_KEY,
                    suite: Ciphersuite::Secp256k1ECDSA,
                    identifier,
                    verifying_share,
                    public_key_package,
                },
            ),
        KeyShareInner::DKLs23Secp256r1(party, public_keys) => {
            describe_dkls_key_share_r1(party, public_keys).map(
                |(identifier, verifying_share, public_key_package)| KeyShareDescription {
                    category: CAT_DKLS_R1_KEY,
                    suite: Ciphersuite::Secp256r1ECDSA,
                    identifier,
                    verifying_share,
                    public_key_package,
                },
            )
        }
    }
}

fn describe_frost_key_share<C>(
    suite: Ciphersuite,
    key_package: &frost::keys::KeyPackage<C>,
    public_keys: &frost::keys::PublicKeyPackage<C>,
) -> Result<(Identifier, Vec<u8>, PublicKeyPackage), TssError>
where
    C: frost::Ciphersuite,
{
    let max_signers = public_keys.max_signers();
    let identifier = frost_identifier_to_identifier(key_package.identifier(), max_signers)?;
    // Derive the verifying share from the signing share (always authoritative).
    // Note: frost-core's refresh_share() updates signing_share but not the cached
    // verifying_share in KeyPackage, so we cannot rely on key_package.verifying_share().
    let derived_verifying_share =
        frost::keys::VerifyingShare::<C>::from(*key_package.signing_share())
            .serialize()
            .map_err(frost_error)?;

    let public_key_share = public_keys
        .verifying_shares()
        .get(key_package.identifier())
        .ok_or_else(|| inconsistent_key_share("public package missing participant share"))?
        .serialize()
        .map_err(frost_error)?;
    if derived_verifying_share != public_key_share {
        return Err(inconsistent_key_share(
            "secret share does not match public verifying share",
        ));
    }

    let key_package_group_key = key_package
        .verifying_key()
        .serialize()
        .map_err(frost_error)?;
    let public_group_key = public_keys
        .verifying_key()
        .serialize()
        .map_err(frost_error)?;
    if key_package_group_key != public_group_key {
        return Err(inconsistent_key_share(
            "group verifying key does not match public package",
        ));
    }

    let min_signers = public_keys
        .min_signers()
        .unwrap_or(*key_package.min_signers());
    if min_signers != *key_package.min_signers() {
        return Err(inconsistent_key_share(
            "minimum signer count does not match public package",
        ));
    }

    let mut verifying_shares = BTreeMap::new();
    for (frost_identifier, verifying_share) in public_keys.verifying_shares() {
        let identifier = frost_identifier_to_identifier(frost_identifier, max_signers)?;
        verifying_shares.insert(
            identifier,
            verifying_share.serialize().map_err(frost_error)?,
        );
    }

    Ok((
        identifier,
        public_key_share,
        PublicKeyPackage::new(suite, public_group_key, verifying_shares, min_signers),
    ))
}

fn describe_dkls_key_share_k1(
    party: &Party,
    public_keys: &DklsPublicKeyPackage,
) -> Result<(Identifier, Vec<u8>, PublicKeyPackage), TssError> {
    let identifier = Identifier::new(u16::from(party.party_index.as_u8()))?;
    let expected = (ProjectivePoint::GENERATOR * party.poly_point).to_affine();
    let actual = public_keys
        .verifying_share(party.party_index)
        .ok_or(TssError::InvalidShare)?;
    if &expected != actual {
        return Err(inconsistent_key_share(
            "secret share does not match public verifying share",
        ));
    }
    if party.pk != *public_keys.verifying_key() {
        return Err(inconsistent_key_share(
            "group verifying key does not match public package",
        ));
    }
    Ok((
        identifier,
        actual.to_sec1_point(true).as_bytes().to_vec(),
        describe_dkls_pubkey_k1(public_keys)?,
    ))
}

fn describe_dkls_key_share_r1(
    party: &dkls23_secp256r1::Party,
    public_keys: &dkls23_secp256r1::PublicKeyPackage,
) -> Result<(Identifier, Vec<u8>, PublicKeyPackage), TssError> {
    use p256::elliptic_curve::sec1::ToSec1Point;

    let identifier = Identifier::new(u16::from(party.party_index.as_u8()))?;
    let expected = (p256::AffinePoint::GENERATOR * party.poly_point).to_affine();
    let actual = public_keys
        .verifying_share(party.party_index)
        .ok_or(TssError::InvalidShare)?;
    if &expected != actual {
        return Err(inconsistent_key_share(
            "secret share does not match public verifying share",
        ));
    }
    if party.pk != *public_keys.verifying_key() {
        return Err(inconsistent_key_share(
            "group verifying key does not match public package",
        ));
    }
    Ok((
        identifier,
        actual.to_sec1_point(true).as_bytes().to_vec(),
        describe_dkls_pubkey_r1(public_keys)?,
    ))
}

fn inconsistent_key_share(message: &'static str) -> TssError {
    TssError::DeserializeFailed(message.into())
}

fn describe_dkls_pubkey_k1(
    public_keys: &DklsPublicKeyPackage,
) -> Result<PublicKeyPackage, TssError> {
    let mut verifying_shares = BTreeMap::new();
    for index in 1..=public_keys.share_count() {
        let party = PartyIndex::new(index).map_err(|_| TssError::InvalidIdentifier)?;
        let identifier = Identifier::new(u16::from(index))?;
        let share = public_keys
            .verifying_share(party)
            .ok_or(TssError::InvalidShare)?
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();
        verifying_shares.insert(identifier, share);
    }
    Ok(PublicKeyPackage::new(
        Ciphersuite::Secp256k1ECDSA,
        public_keys
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec(),
        verifying_shares,
        u16::from(public_keys.threshold()),
    ))
}

fn describe_dkls_pubkey_r1(
    public_keys: &dkls23_secp256r1::PublicKeyPackage,
) -> Result<PublicKeyPackage, TssError> {
    use p256::elliptic_curve::sec1::ToSec1Point;

    let mut verifying_shares = BTreeMap::new();
    for index in 1..=public_keys.share_count() {
        let party = PartyIndex::new(index).map_err(|_| TssError::InvalidIdentifier)?;
        let identifier = Identifier::new(u16::from(index))?;
        let share = public_keys
            .verifying_share(party)
            .ok_or(TssError::InvalidShare)?
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();
        verifying_shares.insert(identifier, share);
    }
    Ok(PublicKeyPackage::new(
        Ciphersuite::Secp256r1ECDSA,
        public_keys
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec(),
        verifying_shares,
        u16::from(public_keys.threshold()),
    ))
}

fn frost_identifier_to_identifier<C>(
    identifier: &frost::Identifier<C>,
    max_signers: u16,
) -> Result<Identifier, TssError>
where
    C: frost::Ciphersuite,
{
    for candidate in 1..=max_signers {
        let frost_identifier = frost::Identifier::<C>::try_from(candidate).map_err(frost_error)?;
        if &frost_identifier == identifier {
            return Identifier::new(candidate);
        }
    }
    Err(TssError::InvalidIdentifier)
}

fn serialize_key_share(inner: &KeyShareInner) -> Result<Vec<u8>, TssError> {
    match inner {
        KeyShareInner::FrostSecp256k1Tr(key_package, public_keys) => {
            postcard::to_allocvec(&(key_package, public_keys)).map_err(Into::into)
        }
        KeyShareInner::FrostSecp256k1(key_package, public_keys) => {
            postcard::to_allocvec(&(key_package, public_keys)).map_err(Into::into)
        }
        KeyShareInner::FrostEd25519(key_package, public_keys) => {
            postcard::to_allocvec(&(key_package, public_keys)).map_err(Into::into)
        }
        KeyShareInner::FrostP256(key_package, public_keys) => {
            postcard::to_allocvec(&(key_package, public_keys)).map_err(Into::into)
        }
        KeyShareInner::FrostRistretto255(key_package, public_keys) => {
            postcard::to_allocvec(&(key_package, public_keys)).map_err(Into::into)
        }
        KeyShareInner::FrostEd448(key_package, public_keys) => {
            postcard::to_allocvec(&(key_package, public_keys)).map_err(Into::into)
        }
        KeyShareInner::DKLs23(party, public_keys) => {
            postcard::to_allocvec(&(party, public_keys)).map_err(Into::into)
        }
        KeyShareInner::DKLs23Secp256r1(party, public_keys) => {
            postcard::to_allocvec(&(party, public_keys)).map_err(Into::into)
        }
    }
}

fn wrap_export(suite: Ciphersuite, payload: &[u8]) -> Vec<u8> {
    let mut output = build_header(suite).to_vec();
    output.extend_from_slice(payload);
    output.extend_from_slice(&export_checksum(&output[..8], payload));
    output
}

fn build_header(suite: Ciphersuite) -> [u8; 8] {
    let mut header = [0u8; EXPORT_HEADER_SIZE];
    header[..4].copy_from_slice(EXPORT_MAGIC);
    header[4..6].copy_from_slice(&1u16.to_le_bytes());
    header[6] = suite.protocol() as u8;
    header[7] = suite as u8;
    header
}

fn export_checksum(header: &[u8], payload: &[u8]) -> [u8; EXPORT_CHECKSUM_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(header);
    hasher.update(payload);
    hasher.finalize().into()
}

fn frost_error<C>(err: frost::Error<C>) -> TssError
where
    C: frost::Ciphersuite,
{
    TssError::DeserializeFailed(err.to_string())
}

#[cfg(test)]
mod tests {
    use dkls23_secp256k1::protocols::{re_key::re_key, Parameters, PartyIndex};
    use dkls23_secp256k1::Party;
    use frost_secp256k1_tr::{
        keys,
        rand_core::{CryptoRng, RngCore},
    };
    use k256::{elliptic_curve::sec1::ToSec1Point, AffinePoint, Scalar};

    use super::{import_key_share, wrap_export, KeyShareHandle, KeyShareInner};
    use crate::{handle::REGISTRY, Ciphersuite, Identifier, TssError};

    const XORSHIFT_A: u64 = 13;
    const XORSHIFT_B: u64 = 7;
    const XORSHIFT_C: u64 = 17;
    #[derive(Clone)]

    struct TestRng(u64);

    impl TestRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << XORSHIFT_A;
            self.0 ^= self.0 >> XORSHIFT_B;
            self.0 ^= self.0 << XORSHIFT_C;
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap();
        }

        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), frost_secp256k1_tr::rand_core::Error> {
            let mut filled = 0;
            while filled < dest.len() {
                let bytes = self.next_u64().to_le_bytes();
                let remaining = dest.len() - filled;
                let count = remaining.min(bytes.len());
                dest[filled..filled + count].copy_from_slice(&bytes[..count]);
                filled += count;
            }
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    fn sample_frost_handle() -> KeyShareHandle {
        let mut rng = TestRng::new(0x1234_5678_9abc_def0);
        let (shares, public_keys) =
            keys::generate_with_dealer(3, 2, keys::IdentifierList::Default, &mut rng).unwrap();
        let (identifier, share) = shares.into_iter().next().unwrap();
        let key_package = keys::KeyPackage::try_from(share).unwrap();

        let _ = identifier;

        KeyShareHandle::new(KeyShareInner::FrostSecp256k1Tr(key_package, public_keys)).unwrap()
    }

    fn sample_dkls_handle() -> KeyShareHandle {
        let parameters = Parameters::new(2, 2).unwrap();
        let secret_key = Scalar::from(7u64);
        let (parties, public_keys) = re_key(
            &parameters,
            b"test-session",
            &secret_key,
            None,
            dkls23_secp256k1::compute_eth_address,
        );

        KeyShareHandle::new(KeyShareInner::DKLs23(
            parties.into_iter().next().unwrap(),
            public_keys,
        ))
        .unwrap()
    }

    #[test]
    fn keyshare_accessors_frost() {
        let handle = sample_frost_handle();

        assert_eq!(handle.ciphersuite(), Ciphersuite::Secp256k1Taproot);
        assert!(handle.identifier().as_u16() > 0);
        assert!(!handle.verifying_share().is_empty());
        assert!(!handle.group_verifying_key().is_empty());
        assert_eq!(
            handle
                .public_key_package()
                .verifying_share(handle.identifier())
                .unwrap(),
            handle.verifying_share().as_slice()
        );
    }

    #[test]
    fn keyshare_accessors_dkls() {
        let handle = sample_dkls_handle();

        assert_eq!(handle.ciphersuite(), Ciphersuite::Secp256k1ECDSA);
        assert!(handle.identifier().as_u16() > 0);
        assert!(!handle.verifying_share().is_empty());
        assert!(!handle.group_verifying_key().is_empty());
        assert_eq!(
            handle
                .public_key_package()
                .verifying_share(handle.identifier())
                .unwrap(),
            handle.verifying_share().as_slice()
        );
    }

    #[test]
    fn keyshare_export_import_roundtrip_frost() {
        let handle = sample_frost_handle();

        let exported = handle.export().unwrap();
        let imported = import_key_share(&exported, Ciphersuite::Secp256k1Taproot).unwrap();

        assert_eq!(imported.identifier(), handle.identifier());
        assert_eq!(imported.verifying_share(), handle.verifying_share());
        assert_eq!(imported.group_verifying_key(), handle.group_verifying_key());
        assert_eq!(imported.ciphersuite(), handle.ciphersuite());
    }

    #[test]
    fn keyshare_export_import_roundtrip_dkls() {
        let handle = sample_dkls_handle();

        let exported = handle.export().unwrap();
        let imported = import_key_share(&exported, Ciphersuite::Secp256k1ECDSA).unwrap();

        assert_eq!(imported.identifier(), handle.identifier());
        assert_eq!(imported.verifying_share(), handle.verifying_share());
        assert_eq!(imported.group_verifying_key(), handle.group_verifying_key());
        assert_eq!(imported.ciphersuite(), handle.ciphersuite());
    }

    #[test]
    fn keyshare_drop_frees_registry() {
        let handle = sample_frost_handle();
        let id = handle.id;

        drop(handle);

        assert_eq!(
            REGISTRY
                .with::<super::KeyShareInner, _>(id, |_| ())
                .unwrap_err(),
            TssError::HandleInvalid
        );
    }

    #[test]
    fn keyshare_import_invalid_checksum() {
        let handle = sample_frost_handle();
        let mut exported = handle.export().unwrap();
        let last = exported.len() - 1;
        exported[last] ^= 0x01;

        assert_eq!(
            import_key_share(&exported, Ciphersuite::Secp256k1Taproot).unwrap_err(),
            TssError::DeserializeFailed("checksum mismatch".into())
        );
    }

    #[test]
    fn keyshare_import_wrong_suite() {
        let handle = sample_frost_handle();
        let exported = handle.export().unwrap();

        assert_eq!(
            import_key_share(&exported, Ciphersuite::Secp256k1ECDSA).unwrap_err(),
            TssError::ProtocolMismatch
        );
    }

    #[test]
    fn frost_fixture_matches_upstream_bytes() {
        let mut rng = TestRng::new(0x0ddc_0ffe_e123_4567);
        let (shares, public_keys) =
            keys::generate_with_dealer(3, 2, keys::IdentifierList::Default, &mut rng).unwrap();
        let (identifier, share) = shares.into_iter().next().unwrap();
        let key_package = keys::KeyPackage::try_from(share).unwrap();
        let handle = KeyShareHandle::new(KeyShareInner::FrostSecp256k1Tr(
            key_package.clone(),
            public_keys.clone(),
        ))
        .unwrap();
        let expected_id = handle.identifier();
        let expected_share = key_package.verifying_share().serialize().unwrap();
        let expected_group = public_keys.verifying_key().serialize().unwrap();

        assert_eq!(identifier.serialize(), key_package.identifier().serialize());
        assert_eq!(handle.identifier(), expected_id);
        assert_eq!(handle.verifying_share(), expected_share);
        assert_eq!(handle.group_verifying_key(), expected_group);
    }

    #[test]
    fn dkls_fixture_matches_upstream_bytes() {
        let parameters = Parameters::new(2, 2).unwrap();
        let secret_key = Scalar::from(11u64);
        let (parties, public_keys) = re_key(
            &parameters,
            b"fixture",
            &secret_key,
            None,
            dkls23_secp256k1::compute_eth_address,
        );
        let party = parties.into_iter().next().unwrap();
        let handle =
            KeyShareHandle::new(KeyShareInner::DKLs23(party.clone(), public_keys.clone())).unwrap();
        let expected_id = Identifier::new(u16::from(party.party_index.as_u8())).unwrap();
        let expected_share = public_keys
            .verifying_share(PartyIndex::new(party.party_index.as_u8()).unwrap())
            .unwrap()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();
        let expected_group = public_keys
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();

        assert_eq!(handle.identifier(), expected_id);
        assert_eq!(handle.verifying_share(), expected_share);
        assert_eq!(handle.group_verifying_key(), expected_group);
    }

    #[test]
    fn keyshare_import_rejects_inconsistent_frost_public_share() {
        let mut rng = TestRng::new(0x1234_5678_9abc_def0);
        let (shares, _public_keys) =
            keys::generate_with_dealer(3, 2, keys::IdentifierList::Default, &mut rng).unwrap();
        let (_, share) = shares.into_iter().next().unwrap();
        let key_package = keys::KeyPackage::try_from(share).unwrap();

        let mut other_rng = TestRng::new(0x0ddc_0ffe_e123_4567);
        let (_, tampered_public_keys) =
            keys::generate_with_dealer(3, 2, keys::IdentifierList::Default, &mut other_rng)
                .unwrap();

        let payload = postcard::to_allocvec(&(key_package, tampered_public_keys)).unwrap();
        let exported = wrap_export(Ciphersuite::Secp256k1Taproot, &payload);

        assert_eq!(
            import_key_share(&exported, Ciphersuite::Secp256k1Taproot).unwrap_err(),
            TssError::DeserializeFailed(
                "secret share does not match public verifying share".into()
            )
        );
    }

    #[test]
    fn keyshare_import_rejects_tampered_frost_signing_share() {
        let mut rng = TestRng::new(0x1234_5678_9abc_def0);
        let (shares, public_keys) =
            keys::generate_with_dealer(3, 2, keys::IdentifierList::Default, &mut rng).unwrap();
        let (_, share) = shares.into_iter().next().unwrap();
        let key_package = keys::KeyPackage::try_from(share).unwrap();

        let mut other_rng = TestRng::new(0x0ddc_0ffe_e123_4567);
        let (other_shares, _) =
            keys::generate_with_dealer(3, 2, keys::IdentifierList::Default, &mut other_rng)
                .unwrap();
        let (_, other_share) = other_shares.into_iter().next().unwrap();
        let other_key_package = keys::KeyPackage::try_from(other_share).unwrap();

        let tampered_key_package = keys::KeyPackage::new(
            *key_package.identifier(),
            *other_key_package.signing_share(),
            *key_package.verifying_share(),
            *key_package.verifying_key(),
            *key_package.min_signers(),
        );

        let payload = postcard::to_allocvec(&(tampered_key_package, public_keys)).unwrap();
        let exported = wrap_export(Ciphersuite::Secp256k1Taproot, &payload);

        assert_eq!(
            import_key_share(&exported, Ciphersuite::Secp256k1Taproot).unwrap_err(),
            TssError::DeserializeFailed(
                "secret share does not match public verifying share".into()
            )
        );
    }

    #[test]
    fn keyshare_import_rejects_tampered_dkls_poly_point() {
        let parameters = Parameters::new(2, 2).unwrap();
        let secret_key = Scalar::from(7u64);
        let (parties, public_keys) = re_key(
            &parameters,
            b"test-session",
            &secret_key,
            None,
            dkls23_secp256k1::compute_eth_address,
        );
        let mut party: Party = parties.into_iter().next().unwrap();
        party.poly_point += Scalar::ONE;

        let payload = postcard::to_allocvec(&(party, public_keys)).unwrap();
        let exported = wrap_export(Ciphersuite::Secp256k1ECDSA, &payload);

        assert_eq!(
            import_key_share(&exported, Ciphersuite::Secp256k1ECDSA).unwrap_err(),
            TssError::DeserializeFailed(
                "secret share does not match public verifying share".into()
            )
        );
    }

    #[test]
    fn keyshare_import_rejects_tampered_dkls_group_key() {
        let parameters = Parameters::new(2, 2).unwrap();
        let secret_key = Scalar::from(7u64);
        let (parties, public_keys) = re_key(
            &parameters,
            b"test-session",
            &secret_key,
            None,
            dkls23_secp256k1::compute_eth_address,
        );
        let mut party: Party = parties.into_iter().next().unwrap();
        party.pk = AffinePoint::GENERATOR;

        let payload = postcard::to_allocvec(&(party, public_keys)).unwrap();
        let exported = wrap_export(Ciphersuite::Secp256k1ECDSA, &payload);

        assert_eq!(
            import_key_share(&exported, Ciphersuite::Secp256k1ECDSA).unwrap_err(),
            TssError::DeserializeFailed("group verifying key does not match public package".into())
        );
    }
}
