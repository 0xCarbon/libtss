use std::collections::BTreeMap;

use frost_secp256k1_tr as frost_tr;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::keyshare::{self, KeyShareHandle};
use crate::types::Ciphersuite;
use crate::TssError;

type HmacSha512 = Hmac<Sha512>;

/// Derive a child key share using non-hardened BIP-32 derivation.
///
/// Supports `Secp256k1ECDSA`, `Secp256r1ECDSA` (DKLs23) and
/// `Secp256k1Taproot` (FROST). Returns `ProtocolMismatch` for other
/// ciphersuites (e.g. Ed25519). The original key share remains valid.
///
/// # Examples
///
/// ```no_run
/// # use libtss::keyshare::KeyShareHandle;
/// # fn example(key_share: &KeyShareHandle) {
/// let child = libtss::derive_child(key_share, 0).unwrap();
/// assert_ne!(
///     child.group_verifying_key(),
///     key_share.group_verifying_key(),
/// );
/// # }
/// ```
pub fn derive_child(
    key_share: &KeyShareHandle,
    child_number: u32,
) -> Result<KeyShareHandle, TssError> {
    if child_number >= (1 << 31) {
        return Err(TssError::InvalidConfig(
            "child_number must be non-hardened (< 2^31)".into(),
        ));
    }

    match key_share.ciphersuite() {
        Ciphersuite::Secp256k1ECDSA => derive_dkls_child(key_share, child_number),
        Ciphersuite::Secp256r1ECDSA => derive_dkls_r1_child(key_share, child_number),
        Ciphersuite::Secp256k1Taproot => derive_frost_taproot_child(key_share, child_number),
        _ => Err(TssError::ProtocolMismatch),
    }
}

/// Derive a key share along a BIP-32 path (e.g. `"m/44/60/0/0"`).
///
/// Hardened derivation segments (e.g. `"m/44'/0'"`) are rejected.
/// All indices must be < 2^31.
pub fn derive_path(key_share: &KeyShareHandle, path: &str) -> Result<KeyShareHandle, TssError> {
    match key_share.ciphersuite() {
        Ciphersuite::Secp256k1ECDSA => derive_dkls_path(key_share, path),
        Ciphersuite::Secp256r1ECDSA => derive_dkls_r1_path(key_share, path),
        Ciphersuite::Secp256k1Taproot => {
            let segments = dkls23_secp256k1::protocols::derivation::parse_path(path)?;
            if segments.is_empty() {
                return Err(TssError::InvalidConfig(
                    "derivation path must contain at least one child index".into(),
                ));
            }
            let mut current = derive_child(key_share, segments[0])?;
            for &child_number in &segments[1..] {
                current = derive_child(&current, child_number)?;
            }
            Ok(current)
        }
        _ => Err(TssError::ProtocolMismatch),
    }
}

fn derive_dkls_child(
    key_share: &KeyShareHandle,
    child_number: u32,
) -> Result<KeyShareHandle, TssError> {
    let party = keyshare::clone_dkls_party(key_share)?;
    let pubkey = keyshare::clone_dkls_pubkey(key_share)?;

    let child_party = party.derive_child(child_number, dkls23_secp256k1::compute_eth_address)?;
    let child_pubkey = pubkey.derive_child(&party.derivation_data.chain_code, child_number)?;

    keyshare::from_dkls_dkg(child_party, child_pubkey)
}

fn derive_dkls_path(key_share: &KeyShareHandle, path: &str) -> Result<KeyShareHandle, TssError> {
    let party = keyshare::clone_dkls_party(key_share)?;
    let derived_party = party.derive_from_path(path, dkls23_secp256k1::compute_eth_address)?;

    let segments = dkls23_secp256k1::protocols::derivation::parse_path(path)?;
    let mut current_party = party;
    let mut pubkey = keyshare::clone_dkls_pubkey(key_share)?;
    for child_number in segments {
        pubkey = pubkey.derive_child(&current_party.derivation_data.chain_code, child_number)?;
        current_party =
            current_party.derive_child(child_number, dkls23_secp256k1::compute_eth_address)?;
    }

    keyshare::from_dkls_dkg(derived_party, pubkey)
}

fn derive_dkls_r1_child(
    key_share: &KeyShareHandle,
    child_number: u32,
) -> Result<KeyShareHandle, TssError> {
    let party = keyshare::clone_dkls_r1_party(key_share)?;
    let pubkey = keyshare::clone_dkls_r1_pubkey(key_share)?;

    let child_party = party.derive_child(child_number, dkls23_secp256r1::compute_neo3_address)?;
    let child_pubkey = pubkey.derive_child(&party.derivation_data.chain_code, child_number)?;

    keyshare::from_dkls_r1_dkg(child_party, child_pubkey)
}

fn derive_dkls_r1_path(key_share: &KeyShareHandle, path: &str) -> Result<KeyShareHandle, TssError> {
    let party = keyshare::clone_dkls_r1_party(key_share)?;
    let derived_party = party.derive_from_path(path, dkls23_secp256r1::compute_neo3_address)?;

    let segments = dkls23_secp256r1::protocols::derivation::parse_path(path)?;
    let mut current_party = party;
    let mut pubkey = keyshare::clone_dkls_r1_pubkey(key_share)?;
    for child_number in segments {
        pubkey = pubkey.derive_child(&current_party.derivation_data.chain_code, child_number)?;
        current_party =
            current_party.derive_child(child_number, dkls23_secp256r1::compute_neo3_address)?;
    }

    keyshare::from_dkls_r1_dkg(derived_party, pubkey)
}

fn derive_frost_taproot_child(
    key_share: &KeyShareHandle,
    child_number: u32,
) -> Result<KeyShareHandle, TssError> {
    use frost_tr::{Field, Group};

    // Clone data out of registry first to avoid deadlock (REGISTRY.with holds mutex;
    // from_frost_taproot_derived calls REGISTRY.insert which would deadlock).
    let (key_package, public_key_package) = keyshare::clone_frost_taproot(key_share)?;

    // For FROST Taproot BIP-32, we need a chain code. Use the group verifying key
    // as a deterministic chain code source (hash of the group key).
    let parent_pubkey = key_package.verifying_key().serialize().map_err(frost_err)?;

    // Derive chain code from the verifying key (deterministic)
    let chain_code = {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(&parent_pubkey);
        let mut cc = [0u8; 32];
        cc.copy_from_slice(&hash);
        cc
    };

    let mut mac = HmacSha512::new_from_slice(&chain_code)
        .map_err(|e| TssError::InvalidConfig(e.to_string()))?;
    mac.update(&parent_pubkey);
    mac.update(&child_number.to_be_bytes());
    let output = mac.finalize().into_bytes();

    let il = &output[..32];

    let tweak = frost_tr::Secp256K1ScalarField::deserialize(&<[u8; 32]>::try_from(il).unwrap())
        .map_err(frost_err)?;
    let tweak_point = frost_tr::Secp256K1Group::generator() * tweak;

    // Tweak signing share
    let signing_share_bytes = key_package.signing_share().serialize();
    let signing_share_scalar = frost_tr::Secp256K1ScalarField::deserialize(
        &<[u8; 32]>::try_from(signing_share_bytes.as_slice()).unwrap(),
    )
    .map_err(frost_err)?;
    let new_signing_share = frost_tr::keys::SigningShare::deserialize(
        &frost_tr::Secp256K1ScalarField::serialize(&(signing_share_scalar + tweak)),
    )
    .map_err(frost_err)?;

    // Tweak verifying share
    let vs_bytes = key_package
        .verifying_share()
        .serialize()
        .map_err(frost_err)?;
    let vs_point =
        frost_tr::Secp256K1Group::deserialize(&<[u8; 33]>::try_from(vs_bytes.as_slice()).unwrap())
            .map_err(frost_err)?;
    let new_verifying_share = frost_tr::keys::VerifyingShare::deserialize(
        &frost_tr::Secp256K1Group::serialize(&(vs_point + tweak_point)).map_err(frost_err)?,
    )
    .map_err(frost_err)?;

    // Tweak group verifying key
    let gk_bytes = key_package.verifying_key().serialize().map_err(frost_err)?;
    let gk_point =
        frost_tr::Secp256K1Group::deserialize(&<[u8; 33]>::try_from(gk_bytes.as_slice()).unwrap())
            .map_err(frost_err)?;
    let new_verifying_key = frost_tr::VerifyingKey::deserialize(
        &frost_tr::Secp256K1Group::serialize(&(gk_point + tweak_point)).map_err(frost_err)?,
    )
    .map_err(frost_err)?;

    let new_key_package = frost_tr::keys::KeyPackage::new(
        *key_package.identifier(),
        new_signing_share,
        new_verifying_share,
        new_verifying_key,
        *key_package.min_signers(),
    );

    // Tweak all verifying shares in public key package
    let mut verifying_shares = BTreeMap::new();
    for (identifier, share) in public_key_package.verifying_shares() {
        let share_bytes = share.serialize().map_err(frost_err)?;
        let point = frost_tr::Secp256K1Group::deserialize(
            &<[u8; 33]>::try_from(share_bytes.as_slice()).unwrap(),
        )
        .map_err(frost_err)?;
        let new_share = frost_tr::keys::VerifyingShare::deserialize(
            &frost_tr::Secp256K1Group::serialize(&(point + tweak_point)).map_err(frost_err)?,
        )
        .map_err(frost_err)?;
        verifying_shares.insert(*identifier, new_share);
    }

    // Tweak group key in public key package
    let pkg_gk_bytes = public_key_package
        .verifying_key()
        .serialize()
        .map_err(frost_err)?;
    let pkg_gk_point = frost_tr::Secp256K1Group::deserialize(
        &<[u8; 33]>::try_from(pkg_gk_bytes.as_slice()).unwrap(),
    )
    .map_err(frost_err)?;
    let new_pkg_verifying_key = frost_tr::VerifyingKey::deserialize(
        &frost_tr::Secp256K1Group::serialize(&(pkg_gk_point + tweak_point)).map_err(frost_err)?,
    )
    .map_err(frost_err)?;

    let new_public_key_package = frost_tr::keys::PublicKeyPackage::new(
        verifying_shares,
        new_pkg_verifying_key,
        public_key_package.min_signers(),
    );

    keyshare::from_frost_taproot_derived(new_key_package, new_public_key_package)
}

fn frost_err<E: std::fmt::Display>(err: E) -> TssError {
    TssError::DeserializeFailed(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dkls23_secp256k1::compute_eth_address;
    use dkls23_secp256k1::protocols::re_key::re_key;
    use dkls23_secp256k1::protocols::{Parameters, PartyIndex};
    use k256::elliptic_curve::sec1::ToSec1Point;
    use k256::{AffinePoint, Scalar};

    fn dkls_handle() -> KeyShareHandle {
        let parameters = Parameters::new(2, 3).unwrap();
        let secret = Scalar::from(7u64);
        let polynomial_coefficient = Scalar::from(11u64);
        let chain_code = [1u8; 32];
        let (mut parties, _) = re_key(
            &parameters,
            b"session",
            &secret,
            Some(chain_code),
            compute_eth_address,
        );
        let verifying_key = (AffinePoint::GENERATOR * secret).to_affine();
        let mut verifying_shares = BTreeMap::new();

        for (index, party) in parties.iter_mut().enumerate() {
            let x = Scalar::from((index + 1) as u64);
            let poly_point = secret + (polynomial_coefficient * x);
            party.poly_point = poly_point;
            party.pk = verifying_key;
            party.derivation_data.poly_point = poly_point;
            party.derivation_data.pk = verifying_key;
            party.derivation_data.chain_code = chain_code;
            party.address = compute_eth_address(&verifying_key);
            verifying_shares.insert(
                PartyIndex::new((index + 1) as u8).unwrap(),
                (AffinePoint::GENERATOR * poly_point).to_affine(),
            );
        }

        let pubkeys =
            dkls23_secp256k1::PublicKeyPackage::new(verifying_key, verifying_shares, parameters);

        keyshare::from_dkls_dkg(parties[0].clone(), pubkeys).unwrap()
    }

    fn frost_handle() -> KeyShareHandle {
        let rng = rand_core::OsRng;
        let (shares, pubkeys) = frost_tr::keys::generate_with_dealer(
            3,
            2,
            frost_tr::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();
        let share = shares.into_iter().next().unwrap().1;
        let key_package = frost_tr::keys::KeyPackage::try_from(share).unwrap();

        keyshare::from_frost_taproot_derived(key_package, pubkeys).unwrap()
    }

    #[test]
    fn dkls_child_derivation_matches_upstream() {
        let handle = dkls_handle();
        let child = derive_child(&handle, 7).unwrap();

        let party = keyshare::clone_dkls_party(&handle).unwrap();
        let upstream_child = party.derive_child(7, compute_eth_address).unwrap();

        assert_eq!(child.ciphersuite(), Ciphersuite::Secp256k1ECDSA);
        assert_eq!(
            child.group_verifying_key(),
            upstream_child.pk.to_sec1_point(true).as_bytes()
        );
    }

    #[test]
    fn dkls_path_derivation_matches_upstream() {
        let handle = dkls_handle();
        let child = derive_path(&handle, "m/44/60/0/0").unwrap();

        let party = keyshare::clone_dkls_party(&handle).unwrap();
        let upstream_child = party
            .derive_from_path("m/44/60/0/0", compute_eth_address)
            .unwrap();

        assert_eq!(child.ciphersuite(), Ciphersuite::Secp256k1ECDSA);
        assert_eq!(
            child.group_verifying_key(),
            upstream_child.pk.to_sec1_point(true).as_bytes()
        );
    }

    #[test]
    fn frost_child_derivation_changes_key() {
        let handle = frost_handle();
        let parent_key = handle.group_verifying_key();
        let child = derive_child(&handle, 1).unwrap();

        assert_eq!(child.ciphersuite(), Ciphersuite::Secp256k1Taproot);
        assert_ne!(child.group_verifying_key(), parent_key);
    }

    #[test]
    fn hardened_derivation_rejected() {
        let handle = dkls_handle();
        assert!(matches!(
            derive_child(&handle, 1 << 31),
            Err(TssError::InvalidConfig(_))
        ));
    }

    #[test]
    fn invalid_path_rejected() {
        let handle = frost_handle();
        assert!(derive_path(&handle, "m/1/2/3'").is_err());
    }

    #[test]
    fn unsupported_suite_rejected() {
        // Ed25519 doesn't support BIP-32
        let config = crate::types::ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Ed25519,
        };
        let (shares, pubkey) = crate::frost::frost_generate_with_dealer(&config).unwrap();
        let handle = keyshare::from_frost_dkg(shares.into_iter().next().unwrap(), &pubkey).unwrap();
        assert!(matches!(
            derive_child(&handle, 0),
            Err(TssError::ProtocolMismatch)
        ));
    }

    #[test]
    fn chain_code_dkls_exposes_dkg_value() {
        // dkls_handle seeds every party's derivation_data.chain_code with
        // [1u8; 32]; chain_code() must surface exactly that 32-byte value so an
        // off-MPC xpub can be built from it.
        let handle = dkls_handle();
        assert_eq!(handle.chain_code().unwrap(), vec![1u8; 32]);
    }

    #[test]
    fn chain_code_frost_is_sha256_of_group_key() {
        // FROST has no DKG chain code; derive.rs derives it as
        // SHA-256(group key), and chain_code() must report the same value.
        use sha2::{Digest, Sha256};
        let handle = frost_handle();
        let expected = Sha256::digest(handle.group_verifying_key()).to_vec();
        assert_eq!(handle.chain_code().unwrap(), expected);
    }
}
