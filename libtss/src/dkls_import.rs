//! Import an existing ECDSA key as DKLs23 shares (trusted dealer).
//!
//! The dealer holds the whole secret key, splits it with DKLs23's `re_key`
//! and hands each party its share. The group key, and so every address, is
//! the key's own. The dealer also generates every pairwise OT setup, so the
//! parties should run a complete refresh
//! ([`RefreshSession::new_dkls`](crate::RefreshSession::new_dkls)) once they
//! hold their shares, and the dealer must erase the key and the shares.

use dkls23_secp256k1::curve::DklsCurve;
use dkls23_secp256k1::protocols::re_key::re_key;
use dkls23_secp256k1::protocols::{Parameters, Party, PublicKeyPackage as DklsPublicKeyPackage};
use k256::elliptic_curve::ff::PrimeField;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::TssError;
use crate::keyshare::{self, KeyShareHandle};
use crate::types::{Ciphersuite, PublicKeyPackage, ThresholdConfig};

/// Split `secret_key` (32-byte big-endian scalar) into `config.max_signers`
/// DKLs23 shares with threshold `config.min_signers`.
///
/// `chain_code` (32 bytes) keeps an existing BIP-32 chain code, so derived
/// addresses match the key's previous wallet; `None` samples a new one.
///
/// # Errors
///
/// [`TssError::ProtocolMismatch`] for a non-DKLs23 suite and
/// [`TssError::InvalidConfig`] for invalid parameters, a chain code that is
/// not 32 bytes, or a secret key that is not a canonical non-zero scalar.
pub fn dkls_split_key(
    config: &ThresholdConfig,
    secret_key: &[u8],
    chain_code: Option<&[u8]>,
) -> Result<(Vec<KeyShareHandle>, PublicKeyPackage), TssError> {
    config.validate()?;
    let threshold = u8::try_from(config.min_signers)
        .map_err(|_| TssError::InvalidConfig("threshold exceeds DKLs23 limits".into()))?;
    let share_count = u8::try_from(config.max_signers)
        .map_err(|_| TssError::InvalidConfig("share_count exceeds DKLs23 limits".into()))?;
    let parameters = Parameters::new(threshold, share_count)
        .map_err(|_| TssError::InvalidConfig("invalid DKLs23 parameters".into()))?;
    let chain_code = chain_code
        .map(|code| {
            <[u8; 32]>::try_from(code)
                .map_err(|_| TssError::InvalidConfig("chain code must be 32 bytes".into()))
        })
        .transpose()?;

    match config.suite {
        Ciphersuite::Secp256k1ECDSA => {
            let (parties, package) = split::<k256::Secp256k1>(
                &parameters,
                secret_key,
                chain_code,
                dkls23_secp256k1::compute_eth_address,
            )?;
            let public_keys = crate::dkls::convert_public_key_package(&package)?;
            let handles = parties
                .into_iter()
                .map(|party| keyshare::from_dkls_dkg(party, package.clone()))
                .collect::<Result<_, _>>()?;
            Ok((handles, public_keys))
        }
        Ciphersuite::Secp256r1ECDSA => {
            let (parties, package) = split::<p256::NistP256>(
                &parameters,
                secret_key,
                chain_code,
                dkls23_secp256r1::compute_neo3_address,
            )?;
            let public_keys = crate::dkls_r1::convert_public_key_package(&package)?;
            let handles = parties
                .into_iter()
                .map(|party| keyshare::from_dkls_r1_dkg(party, package.clone()))
                .collect::<Result<_, _>>()?;
            Ok((handles, public_keys))
        }
        _ => Err(TssError::ProtocolMismatch),
    }
}

fn split<C: DklsCurve<Scalar: Zeroize>>(
    parameters: &Parameters,
    secret_key: &[u8],
    chain_code: Option<[u8; 32]>,
    address_fn: impl Fn(&C::AffinePoint) -> String,
) -> Result<(Vec<Party<C>>, DklsPublicKeyPackage<C>), TssError> {
    let invalid = || TssError::InvalidConfig("secret key must be a non-zero 32-byte scalar".into());
    let mut repr = <C::Scalar as PrimeField>::Repr::default();
    if secret_key.len() != AsRef::<[u8]>::as_ref(&repr).len() {
        return Err(invalid());
    }
    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(secret_key);
    let parsed = Option::<C::Scalar>::from(C::Scalar::from_repr(repr));
    AsMut::<[u8]>::as_mut(&mut repr).zeroize();
    let mut secret = parsed.ok_or_else(invalid)?;
    if bool::from(k256::elliptic_curve::ff::Field::is_zero(&secret)) {
        return Err(invalid());
    }

    // A fresh session id: shares from two imports of the same key never
    // share pairwise state.
    let mut session_id = [0u8; 32];
    OsRng.fill_bytes(&mut session_id);
    let result = re_key::<C>(parameters, &session_id, &secret, chain_code, address_fn);
    secret.zeroize();
    Ok(result)
}
