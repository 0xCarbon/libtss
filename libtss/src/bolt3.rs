//! BOLT 3 key derivation for DKLs23 secp256k1 key shares (Lightning).
//!
//! Lightning derives a key for every commitment from a base key and the
//! per-commitment point (BOLT 3, "Key Derivation"). Each party applies the
//! derivation to its own share; the tweak is computed from public points,
//! so no caller-chosen scalar reaches the shares.
//!
//! A derived share keeps the base share's pairwise OT state, so an abort that
//! bans a counterparty under a derived key applies to the base key and every
//! key derived from it.

use dkls23_secp256k1::protocols::bolt3::Bolt3Error;
use dkls23_secp256k1::protocols::{Parameters, PartyIndex};
use dkls23_secp256k1::PublicKeyPackage as DklsPublicKeyPackage;
use k256::elliptic_curve::ff::PrimeField;
use k256::{AffinePoint, PublicKey, Scalar};
use zeroize::Zeroize;

use crate::dkls::convert_public_key_package;
use crate::keyshare::{self, KeyShareHandle};
use crate::types::{Ciphersuite, PublicKeyPackage};
use crate::TssError;

/// Derive the key share for a commitment: `basepoint + SHA256(per_commitment_point || basepoint)·G`
/// (`localpubkey`, `local_htlcpubkey`, `remote_htlcpubkey`, `local_delayedpubkey`,
/// `remote_delayedpubkey`). With `option_static_remotekey`, `remotepubkey` is
/// the remote payment basepoint itself and is not derived.
///
/// `per_commitment_point` is a 33-byte compressed SEC1 point. Every party
/// derives with the same point. The input handle stays valid.
pub fn bolt3_derive(
    key_share: &KeyShareHandle,
    per_commitment_point: &[u8],
) -> Result<KeyShareHandle, TssError> {
    require_secp256k1(key_share.ciphersuite())?;
    let point = parse_point(per_commitment_point)?;
    let party = keyshare::clone_dkls_party(key_share)?;
    let package = keyshare::clone_dkls_pubkey(key_share)?;
    let derived = party
        .bolt3_derive(&point, dkls23_secp256k1::compute_eth_address)
        .map_err(bolt3_error)?;
    let derived_package = package.bolt3_derive(&point).map_err(bolt3_error)?;
    keyshare::from_dkls_dkg(derived, derived_package)
}

/// Derive the revocation key share for a commitment whose per-commitment
/// secret was revealed: `revocationpubkey` and its private key.
///
/// `per_commitment_secret` (32-byte big-endian scalar) must match
/// `per_commitment_point`. The input handle stays valid.
pub fn bolt3_derive_revocation(
    key_share: &KeyShareHandle,
    per_commitment_point: &[u8],
    per_commitment_secret: &[u8],
) -> Result<KeyShareHandle, TssError> {
    require_secp256k1(key_share.ciphersuite())?;
    let point = parse_point(per_commitment_point)?;
    let mut secret = parse_scalar(per_commitment_secret)?;
    let party = keyshare::clone_dkls_party(key_share)?;
    let package = keyshare::clone_dkls_pubkey(key_share)?;
    let derived =
        party.bolt3_derive_revocation(&point, &secret, dkls23_secp256k1::compute_eth_address);
    secret.zeroize();
    let derived = derived.map_err(bolt3_error)?;
    let derived_package = package
        .bolt3_derive_revocation(&point)
        .map_err(bolt3_error)?;
    keyshare::from_dkls_dkg(derived, derived_package)
}

/// [`bolt3_derive`] on a public key package: the derived group key and
/// verifying shares, without a share.
pub fn bolt3_derive_public_keys(
    package: &PublicKeyPackage,
    per_commitment_point: &[u8],
) -> Result<PublicKeyPackage, TssError> {
    let point = parse_point(per_commitment_point)?;
    let derived = to_dkls_package(package)?
        .bolt3_derive(&point)
        .map_err(bolt3_error)?;
    convert_public_key_package(&derived)
}

/// [`bolt3_derive_revocation`] on a public key package: the revocation
/// group key and verifying shares, without a share or the secret.
pub fn bolt3_derive_revocation_public_keys(
    package: &PublicKeyPackage,
    per_commitment_point: &[u8],
) -> Result<PublicKeyPackage, TssError> {
    let point = parse_point(per_commitment_point)?;
    let derived = to_dkls_package(package)?
        .bolt3_derive_revocation(&point)
        .map_err(bolt3_error)?;
    convert_public_key_package(&derived)
}

fn require_secp256k1(suite: Ciphersuite) -> Result<(), TssError> {
    if suite == Ciphersuite::Secp256k1ECDSA {
        Ok(())
    } else {
        Err(TssError::ProtocolMismatch)
    }
}

fn bolt3_error(error: Bolt3Error) -> TssError {
    TssError::TweakError(error.to_string())
}

fn parse_point(bytes: &[u8]) -> Result<AffinePoint, TssError> {
    if bytes.len() != 33 {
        return Err(TssError::InvalidConfig(
            "per-commitment point must be a 33-byte compressed point".into(),
        ));
    }
    PublicKey::from_sec1_bytes(bytes)
        .map(|key| *key.as_affine())
        .map_err(|_| TssError::InvalidConfig("invalid per-commitment point".into()))
}

fn parse_scalar(bytes: &[u8]) -> Result<Scalar, TssError> {
    let mut repr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TssError::InvalidConfig("per-commitment secret must be 32 bytes".into()))?;
    let scalar = Option::<Scalar>::from(Scalar::from_repr(repr.into()));
    repr.zeroize();
    scalar.ok_or_else(|| TssError::InvalidConfig("invalid per-commitment secret".into()))
}

fn to_dkls_package(package: &PublicKeyPackage) -> Result<DklsPublicKeyPackage, TssError> {
    require_secp256k1(package.suite())?;
    let point = |bytes: &[u8]| {
        PublicKey::from_sec1_bytes(bytes)
            .map(|key| *key.as_affine())
            .map_err(|_| TssError::DeserializeFailed("invalid public key package point".into()))
    };
    let verifying_shares = package
        .verifying_shares()
        .iter()
        .map(|(id, share)| {
            let index = u8::try_from(id.as_u16())
                .ok()
                .and_then(|i| PartyIndex::new(i).ok())
                .ok_or(TssError::InvalidIdentifier)?;
            Ok((index, point(share)?))
        })
        .collect::<Result<_, TssError>>()?;
    let expected: Vec<u16> = (1..=package.verifying_shares().len())
        .map(|i| u16::try_from(i).unwrap_or(u16::MAX))
        .collect();
    let actual: Vec<u16> = package
        .verifying_shares()
        .keys()
        .map(|id| id.as_u16())
        .collect();
    if actual != expected {
        return Err(TssError::InvalidIdentifier);
    }
    let threshold = u8::try_from(package.min_signers())
        .map_err(|_| TssError::InvalidConfig("threshold exceeds DKLs23 limits".into()))?;
    let share_count = u8::try_from(package.verifying_shares().len())
        .map_err(|_| TssError::InvalidConfig("share count exceeds DKLs23 limits".into()))?;
    let parameters = Parameters::new(threshold, share_count)
        .map_err(|_| TssError::InvalidConfig("invalid DKLs23 parameters".into()))?;
    Ok(DklsPublicKeyPackage::new(
        point(package.verifying_key())?,
        verifying_shares,
        parameters,
    ))
}
