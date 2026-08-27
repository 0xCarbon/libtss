//! Scalar tweaks on DKLs23 key shares.
//!
//! BIP-32 [`derive_child`](crate::derive_child) applies an HMAC-derived
//! additive tweak. Lightning (LND) instead derives per-commitment keys from
//! caller-supplied scalars:
//!
//! - single tweak (additive):        `k' = k + t (mod n)`
//! - revocation / double tweak:      `k' = k * a (mod n)`, then an additive step
//!
//! The math lives in DKLs23 (`Party::tweak_add` / `tweak_mul` and the matching
//! `PublicKeyPackage` methods): the secret share, public key, derivation data
//! and address move with the map, as do the group key and every verifying
//! share, so a threshold set of tweaked shares signs under the tweaked group
//! key. OT correlations, zero-share seeds, multiplication state and the chain
//! code are reused unchanged. This module parses the scalar, picks the
//! address function for the ciphersuite and wraps the result in a new handle.
//! Every party must apply the same tweak before signing; a mismatch aborts
//! recoverably in signing phase 3.
//!
//! For BIP-341 Taproot tweaking of FROST shares see
//! [`frost_tweak_key_share`](crate::frost::frost_tweak_key_share).

use dkls23_secp256k1::curve::DklsCurve;
use dkls23_secp256k1::protocols::tweak::{scalar_from_be_bytes, TweakError};
use dkls23_secp256k1::protocols::{Party, PublicKeyPackage};

use crate::keyshare::{self, KeyShareHandle};
use crate::types::Ciphersuite;
use crate::TssError;

/// Return a key share whose secret is `secret + tweak (mod n)`.
///
/// `tweak` is a 32-byte big-endian scalar, reduced mod n (matching btcec's
/// `ModNScalar` and therefore LND's single-tweak convention). A zero tweak is
/// a no-op. Supported for `Secp256k1ECDSA` and `Secp256r1ECDSA` (DKLs23);
/// other ciphersuites return [`TssError::ProtocolMismatch`]. A tweak whose
/// result is the identity point returns [`TssError::TweakError`]; a scalar of
/// the wrong length returns [`TssError::InvalidConfig`]. The original key
/// share remains valid.
pub fn tweak_add(key_share: &KeyShareHandle, tweak: &[u8]) -> Result<KeyShareHandle, TssError> {
    apply(key_share, tweak, Tweak::Add)
}

/// Return a key share whose secret is `secret * factor (mod n)`.
///
/// `factor` is a 32-byte big-endian scalar, reduced mod n. It is the building
/// block of LND's revocation ("double") tweak. A factor that reduces to zero
/// would destroy the key and returns [`TssError::TweakError`]; a factor of one
/// is a no-op. Ciphersuite support and error mapping match [`tweak_add`].
pub fn tweak_mul(key_share: &KeyShareHandle, factor: &[u8]) -> Result<KeyShareHandle, TssError> {
    apply(key_share, factor, Tweak::Mul)
}

#[derive(Clone, Copy)]
enum Tweak {
    Add,
    Mul,
}

fn apply(
    key_share: &KeyShareHandle,
    scalar: &[u8],
    tweak: Tweak,
) -> Result<KeyShareHandle, TssError> {
    match key_share.ciphersuite() {
        Ciphersuite::Secp256k1ECDSA => {
            let scalar = scalar_from_be_bytes::<k256::Secp256k1>(scalar).map_err(tss_error)?;
            let (party, pubkey) = tweak_party(
                &keyshare::clone_dkls_party(key_share)?,
                &keyshare::clone_dkls_pubkey(key_share)?,
                tweak,
                &scalar,
                dkls23_secp256k1::compute_eth_address,
            )?;
            keyshare::from_dkls_dkg(party, pubkey)
        }
        Ciphersuite::Secp256r1ECDSA => {
            let scalar = scalar_from_be_bytes::<p256::NistP256>(scalar).map_err(tss_error)?;
            let (party, pubkey) = tweak_party(
                &keyshare::clone_dkls_r1_party(key_share)?,
                &keyshare::clone_dkls_r1_pubkey(key_share)?,
                tweak,
                &scalar,
                dkls23_secp256r1::compute_neo3_address,
            )?;
            keyshare::from_dkls_r1_dkg(party, pubkey)
        }
        _ => Err(TssError::ProtocolMismatch),
    }
}

fn tweak_party<C: DklsCurve>(
    party: &Party<C>,
    pubkey: &PublicKeyPackage<C>,
    tweak: Tweak,
    scalar: &C::Scalar,
    address_fn: impl Fn(&C::AffinePoint) -> String,
) -> Result<(Party<C>, PublicKeyPackage<C>), TssError> {
    match tweak {
        Tweak::Add => Ok((
            party.tweak_add(scalar, address_fn).map_err(tss_error)?,
            pubkey.tweak_add(scalar).map_err(tss_error)?,
        )),
        Tweak::Mul => Ok((
            party.tweak_mul(scalar, address_fn).map_err(tss_error)?,
            pubkey.tweak_mul(scalar).map_err(tss_error)?,
        )),
    }
}

fn tss_error(err: TweakError) -> TssError {
    match err {
        TweakError::InvalidScalarLength { .. } => TssError::InvalidConfig(err.to_string()),
        _ => TssError::TweakError(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{ethereum_address, neo3_address};
    use crate::Identifier;
    use dkls23_secp256k1::protocols::re_key::re_key;
    use dkls23_secp256k1::protocols::Parameters;
    use k256::elliptic_curve::sec1::ToSec1Point;
    use k256::{ProjectivePoint, PublicKey, Scalar};

    const SECRET: u64 = 15;
    const SHARE_COUNT: u16 = 3;

    fn dkls_handle() -> KeyShareHandle {
        let parameters = Parameters::new(2, SHARE_COUNT as u8).unwrap();
        let (parties, pubkeys) = re_key(
            &parameters,
            b"session",
            &Scalar::from(SECRET),
            Some([3u8; 32]),
            dkls23_secp256k1::compute_eth_address,
        );

        keyshare::from_dkls_dkg(parties[0].clone(), pubkeys).unwrap()
    }

    fn dkls_r1_handle() -> KeyShareHandle {
        let parameters = Parameters::new(2, SHARE_COUNT as u8).unwrap();
        let (parties, pubkeys) = dkls23_secp256r1::protocols::re_key::re_key(
            &parameters,
            b"session",
            &p256::Scalar::from(SECRET),
            Some([3u8; 32]),
            dkls23_secp256r1::compute_neo3_address,
        );

        keyshare::from_dkls_r1_dkg(parties[0].clone(), pubkeys).unwrap()
    }

    fn scalar_bytes(value: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn k1_point(compressed: &[u8]) -> ProjectivePoint {
        PublicKey::from_sec1_bytes(compressed)
            .unwrap()
            .to_projective()
    }

    fn compressed(point: ProjectivePoint) -> Vec<u8> {
        point.to_affine().to_sec1_point(true).as_bytes().to_vec()
    }

    #[test]
    fn tweak_add_k1_shifts_group_key_and_every_verifying_share() {
        let handle = dkls_handle();
        let tweaked = tweak_add(&handle, &scalar_bytes(7)).unwrap();
        let shift = ProjectivePoint::GENERATOR * Scalar::from(7u64);

        assert_eq!(tweaked.ciphersuite(), Ciphersuite::Secp256k1ECDSA);
        assert_eq!(tweaked.identifier(), handle.identifier());
        assert_eq!(
            tweaked.group_verifying_key(),
            compressed(k1_point(&handle.group_verifying_key()) + shift)
        );
        assert_eq!(
            tweaked.verifying_share(),
            compressed(k1_point(&handle.verifying_share()) + shift)
        );
        for index in 1..=SHARE_COUNT {
            let id = Identifier::new(index).unwrap();
            let before = handle.public_key_package().verifying_share(id).unwrap();
            let after = tweaked.public_key_package().verifying_share(id).unwrap();
            assert_eq!(after.to_vec(), compressed(k1_point(before) + shift));
        }
    }

    #[test]
    fn tweak_add_updates_ethereum_address() {
        let handle = dkls_handle();
        let tweaked = tweak_add(&handle, &scalar_bytes(7)).unwrap();
        let party = keyshare::clone_dkls_party(&tweaked).unwrap();

        assert_ne!(
            ethereum_address(&tweaked).unwrap(),
            ethereum_address(&handle).unwrap()
        );
        assert_eq!(
            ethereum_address(&tweaked).unwrap(),
            dkls23_secp256k1::compute_eth_address(&party.pk)
        );
        assert_eq!(
            party.pk.to_sec1_point(true).as_bytes(),
            tweaked.group_verifying_key().as_slice()
        );
    }

    #[test]
    fn tweak_add_r1_matches_expected_public_key() {
        use p256::elliptic_curve::sec1::ToSec1Point;

        let handle = dkls_r1_handle();
        let tweaked = tweak_add(&handle, &scalar_bytes(7)).unwrap();
        let expected = (p256::PublicKey::from_sec1_bytes(&handle.group_verifying_key())
            .unwrap()
            .to_projective()
            + p256::ProjectivePoint::GENERATOR * p256::Scalar::from(7u64))
        .to_affine();

        assert_eq!(tweaked.ciphersuite(), Ciphersuite::Secp256r1ECDSA);
        assert_eq!(
            tweaked.group_verifying_key(),
            expected.to_sec1_point(true).as_bytes()
        );
        assert_eq!(
            neo3_address(&tweaked).unwrap(),
            dkls23_secp256r1::compute_neo3_address(&expected)
        );
    }

    #[test]
    fn tweak_mul_zero_factor_rejected() {
        let handle = dkls_handle();
        assert!(matches!(
            tweak_mul(&handle, &scalar_bytes(0)),
            Err(TssError::TweakError(_))
        ));
        assert!(matches!(
            tweak_mul(&dkls_r1_handle(), &scalar_bytes(0)),
            Err(TssError::TweakError(_))
        ));
    }

    #[test]
    fn tweak_add_identity_result_rejected() {
        let handle = dkls_handle();
        assert!(matches!(
            tweak_add(&handle, &(-Scalar::from(SECRET)).to_bytes()),
            Err(TssError::TweakError(_))
        ));
    }

    #[test]
    fn tweak_rejects_wrong_length_scalar() {
        let handle = dkls_handle();
        assert!(matches!(
            tweak_add(&handle, &[1u8; 31]),
            Err(TssError::InvalidConfig(_))
        ));
        assert!(matches!(
            tweak_mul(&handle, &[1u8; 33]),
            Err(TssError::InvalidConfig(_))
        ));
        assert!(matches!(
            tweak_add(&dkls_r1_handle(), &[]),
            Err(TssError::InvalidConfig(_))
        ));
    }

    #[test]
    fn tweak_unsupported_suite_rejected() {
        for suite in [Ciphersuite::Secp256k1Taproot, Ciphersuite::Ed25519] {
            let config = crate::types::ThresholdConfig {
                min_signers: 2,
                max_signers: 3,
                suite,
            };
            let (shares, pubkey) = crate::frost::frost_generate_with_dealer(&config).unwrap();
            let handle =
                keyshare::from_frost_dkg(shares.into_iter().next().unwrap(), &pubkey).unwrap();

            assert!(matches!(
                tweak_add(&handle, &scalar_bytes(7)),
                Err(TssError::ProtocolMismatch)
            ));
            assert!(matches!(
                tweak_mul(&handle, &scalar_bytes(3)),
                Err(TssError::ProtocolMismatch)
            ));
        }
    }
}
