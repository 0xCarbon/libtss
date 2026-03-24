use std::collections::BTreeMap;

use rand_core::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    message::Message,
    types::{Ciphersuite, Identifier, Protocol, PublicKeyPackage, Signature, ThresholdConfig},
    TssError,
};

macro_rules! dispatch_frost {
    ($suite:expr, |$c:ident| $body:expr) => {{
        match $suite {
            Ciphersuite::Secp256k1Taproot => {
                type $c = frost_secp256k1_tr::Secp256K1Sha256TR;
                $body
            }
            Ciphersuite::Secp256k1 => {
                type $c = frost_secp256k1::Secp256K1Sha256;
                $body
            }
            Ciphersuite::Ed25519 => {
                type $c = frost_ed25519::Ed25519Sha512;
                $body
            }
            Ciphersuite::P256 => {
                type $c = frost_p256::P256Sha256;
                $body
            }
            Ciphersuite::Ristretto255 => {
                type $c = frost_ristretto255::Ristretto255Sha512;
                $body
            }
            Ciphersuite::Ed448 => {
                type $c = frost_ed448::Ed448Shake256;
                $body
            }
            Ciphersuite::Secp256k1ECDSA | Ciphersuite::Secp256r1ECDSA => {
                Err(TssError::ProtocolMismatch)
            }
        }
    }};
}

type SerializedBytes = Vec<u8>;
type SerializedKeyPackages = Vec<(Identifier, SerializedBytes)>;

#[derive(Debug, Clone)]
pub struct KeyShareHandle {
    suite: Ciphersuite,
    identifier: Identifier,
    key_package_bytes: Vec<u8>,
}

impl KeyShareHandle {
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    pub fn ciphersuite(&self) -> Ciphersuite {
        self.suite
    }

    pub(crate) fn into_parts(self) -> (Ciphersuite, Vec<u8>) {
        let suite = self.suite;
        let mut this = std::mem::ManuallyDrop::new(self);
        let bytes = std::mem::take(&mut this.key_package_bytes);
        (suite, bytes)
    }

    pub(crate) fn from_parts(
        suite: Ciphersuite,
        identifier: Identifier,
        key_package_bytes: Vec<u8>,
    ) -> Self {
        Self {
            suite,
            identifier,
            key_package_bytes,
        }
    }
}

impl Drop for KeyShareHandle {
    fn drop(&mut self) {
        self.key_package_bytes.zeroize();
    }
}

fn validate_frost_config(config: &ThresholdConfig) -> Result<(), TssError> {
    config.validate()?;
    if config.suite.protocol() != Protocol::Frost {
        return Err(TssError::ProtocolMismatch);
    }
    Ok(())
}

fn key_share_handle_from_bytes(
    suite: Ciphersuite,
    key_package_bytes: Vec<u8>,
) -> Result<KeyShareHandle, TssError> {
    let identifier = dispatch_frost!(suite, |C| {
        let key_package = frost_core::keys::KeyPackage::<C>::deserialize(&key_package_bytes)
            .map_err(TssError::from)?;
        from_frost_id(suite, *key_package.identifier())
    })?;

    Ok(KeyShareHandle {
        suite,
        identifier,
        key_package_bytes,
    })
}

fn key_share_handles_from_serialized(
    suite: Ciphersuite,
    shares: SerializedKeyPackages,
) -> Result<Vec<KeyShareHandle>, TssError> {
    shares
        .into_iter()
        .map(|(identifier, key_package_bytes)| {
            let handle = key_share_handle_from_bytes(suite, key_package_bytes)?;
            if handle.identifier() != identifier {
                return Err(TssError::InvalidIdentifier);
            }
            Ok(handle)
        })
        .collect()
}

fn decode_identifier_bytes(bytes: &[u8], little_endian: bool) -> Result<Identifier, TssError> {
    if bytes.len() < 2 {
        return Err(TssError::InvalidIdentifier);
    }

    let value = if little_endian {
        if !bytes[2..].iter().all(|byte| *byte == 0) {
            return Err(TssError::InvalidIdentifier);
        }
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        if !bytes[..bytes.len() - 2].iter().all(|byte| *byte == 0) {
            return Err(TssError::InvalidIdentifier);
        }
        u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]])
    };

    Identifier::new(value)
}

fn identifier_from_frost_bytes(suite: Ciphersuite, bytes: &[u8]) -> Result<Identifier, TssError> {
    match suite {
        Ciphersuite::Ed25519 | Ciphersuite::Ristretto255 | Ciphersuite::Ed448 => {
            decode_identifier_bytes(bytes, true)
        }
        Ciphersuite::Secp256k1Taproot | Ciphersuite::Secp256k1 | Ciphersuite::P256 => {
            decode_identifier_bytes(bytes, false)
        }
        Ciphersuite::Secp256k1ECDSA | Ciphersuite::Secp256r1ECDSA => {
            Err(TssError::ProtocolMismatch)
        }
    }
}

fn parse_libtss_pubkey_shares(
    pkg: &PublicKeyPackage,
) -> Result<Vec<(Identifier, Vec<u8>)>, TssError> {
    let bytes = pkg.serialize()?;
    if bytes.len() < 9 {
        return Err(TssError::DeserializeFailed(
            "public key package too short".into(),
        ));
    }

    let vk_len = u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as usize;
    let mut pos = 7 + vk_len;
    if pos + 2 > bytes.len() {
        return Err(TssError::DeserializeFailed(
            "truncated public key package".into(),
        ));
    }

    let share_count = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;

    let mut shares = Vec::with_capacity(share_count);
    for _ in 0..share_count {
        if pos + 6 > bytes.len() {
            return Err(TssError::DeserializeFailed(
                "truncated public key share header".into(),
            ));
        }
        let id = Identifier::new(u16::from_le_bytes([bytes[pos], bytes[pos + 1]]))?;
        let len = u32::from_le_bytes([
            bytes[pos + 2],
            bytes[pos + 3],
            bytes[pos + 4],
            bytes[pos + 5],
        ]) as usize;
        pos += 6;
        if pos + len > bytes.len() {
            return Err(TssError::DeserializeFailed(
                "truncated public key share".into(),
            ));
        }
        shares.push((id, bytes[pos..pos + len].to_vec()));
        pos += len;
    }

    Ok(shares)
}

fn message_map<C, T, F>(
    messages: &[Message],
    mut deserialize: F,
) -> Result<BTreeMap<frost_core::Identifier<C>, T>, TssError>
where
    C: frost_core::Ciphersuite,
    F: FnMut(&[u8]) -> Result<T, frost_core::Error<C>>,
{
    let mut map = BTreeMap::new();
    for message in messages {
        let identifier = to_frost_id::<C>(message.from)?;
        let value = deserialize(&message.data).map_err(TssError::from)?;
        if map.insert(identifier, value).is_some() {
            return Err(TssError::InvalidConfig("duplicated identifier".into()));
        }
    }
    Ok(map)
}

fn serialize_signature<C: frost_core::Ciphersuite>(
    signature: frost_core::Signature<C>,
) -> Result<Signature, TssError> {
    Ok(Signature::new(
        Protocol::Frost,
        signature.serialize().map_err(TssError::from)?,
        None,
    ))
}

fn to_frost_id<C: frost_core::Ciphersuite>(
    id: Identifier,
) -> Result<frost_core::Identifier<C>, TssError> {
    frost_core::Identifier::<C>::try_from(id.as_u16()).map_err(TssError::from)
}

fn from_frost_id<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    id: frost_core::Identifier<C>,
) -> Result<Identifier, TssError> {
    identifier_from_frost_bytes(suite, &id.serialize())
}

fn frost_pubkey_to_libtss<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    pkg: &frost_core::keys::PublicKeyPackage<C>,
) -> Result<PublicKeyPackage, TssError> {
    let verifying_key = pkg.verifying_key().serialize().map_err(TssError::from)?;
    let mut verifying_shares = BTreeMap::new();
    for (id, share) in pkg.verifying_shares() {
        verifying_shares.insert(
            from_frost_id(suite, *id)?,
            share.serialize().map_err(TssError::from)?,
        );
    }
    let min_signers = pkg
        .min_signers()
        .ok_or_else(|| TssError::InvalidConfig("missing min_signers".into()))?;
    Ok(PublicKeyPackage::new(
        suite,
        verifying_key,
        verifying_shares,
        min_signers,
    ))
}

pub(crate) fn libtss_pubkey_to_frost<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    pkg: &PublicKeyPackage,
) -> Result<frost_core::keys::PublicKeyPackage<C>, TssError> {
    if pkg.suite() != suite {
        return Err(TssError::ProtocolMismatch);
    }

    let verifying_key =
        frost_core::VerifyingKey::<C>::deserialize(pkg.verifying_key()).map_err(TssError::from)?;
    let mut verifying_shares = BTreeMap::new();
    for (id, share) in parse_libtss_pubkey_shares(pkg)? {
        verifying_shares.insert(
            to_frost_id::<C>(id)?,
            frost_core::keys::VerifyingShare::<C>::deserialize(&share).map_err(TssError::from)?,
        );
    }

    Ok(frost_core::keys::PublicKeyPackage::new(
        verifying_shares,
        verifying_key,
        Some(pkg.min_signers()),
    ))
}

fn part1_inner<C: frost_core::Ciphersuite>(
    self_id: Identifier,
    max_signers: u16,
    min_signers: u16,
) -> Result<(Zeroizing<Vec<u8>>, Vec<Message>), TssError> {
    let identifier = to_frost_id::<C>(self_id)?;
    let (secret, package) =
        frost_core::keys::dkg::part1::<C, _>(identifier, max_signers, min_signers, OsRng)
            .map_err(TssError::from)?;
    Ok((
        Zeroizing::new(secret.serialize().map_err(TssError::from)?),
        vec![Message {
            from: self_id,
            to: None,
            data: package.serialize().map_err(TssError::from)?,
        }],
    ))
}

fn part2_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    round1_secret: &[u8],
    received: &[Message],
) -> Result<(Zeroizing<Vec<u8>>, Vec<Message>), TssError> {
    let secret = frost_core::keys::dkg::round1::SecretPackage::<C>::deserialize(round1_secret)
        .map_err(TssError::from)?;
    let self_id = from_frost_id(suite, *secret.identifier())?;
    let round1_packages = message_map(received, |bytes| {
        frost_core::keys::dkg::round1::Package::<C>::deserialize(bytes)
    })?;
    let (secret, packages) =
        frost_core::keys::dkg::part2::<C>(secret, &round1_packages).map_err(TssError::from)?;

    let mut messages = Vec::with_capacity(packages.len());
    for (recipient, package) in packages {
        messages.push(Message {
            from: self_id,
            to: Some(from_frost_id(suite, recipient)?),
            data: package.serialize().map_err(TssError::from)?,
        });
    }

    Ok((
        Zeroizing::new(secret.serialize().map_err(TssError::from)?),
        messages,
    ))
}

fn part3_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    round2_secret: &[u8],
    round1_messages: &[Message],
    round2_messages: &[Message],
) -> Result<(Vec<u8>, PublicKeyPackage), TssError> {
    let secret = frost_core::keys::dkg::round2::SecretPackage::<C>::deserialize(round2_secret)
        .map_err(TssError::from)?;
    let round1_packages = message_map(round1_messages, |bytes| {
        frost_core::keys::dkg::round1::Package::<C>::deserialize(bytes)
    })?;
    let round2_packages = message_map(round2_messages, |bytes| {
        frost_core::keys::dkg::round2::Package::<C>::deserialize(bytes)
    })?;
    let (key_package, public_key_package) =
        frost_core::keys::dkg::part3::<C>(&secret, &round1_packages, &round2_packages)
            .map_err(TssError::from)?;
    Ok((
        key_package.serialize().map_err(TssError::from)?,
        frost_pubkey_to_libtss(suite, &public_key_package)?,
    ))
}

fn commit_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    key_package_bytes: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Message), TssError> {
    let key_package = frost_core::keys::KeyPackage::<C>::deserialize(key_package_bytes)
        .map_err(TssError::from)?;
    let identifier = from_frost_id(suite, *key_package.identifier())?;
    let (nonces, commitments) =
        frost_core::round1::commit::<C, _>(key_package.signing_share(), &mut OsRng);
    Ok((
        Zeroizing::new(nonces.serialize().map_err(TssError::from)?),
        Message {
            from: identifier,
            to: None,
            data: commitments.serialize().map_err(TssError::from)?,
        },
    ))
}

fn sign_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    key_package_bytes: &[u8],
    nonces: &[u8],
    commitments: &[Message],
    msg: &[u8],
) -> Result<Message, TssError> {
    let key_package = frost_core::keys::KeyPackage::<C>::deserialize(key_package_bytes)
        .map_err(TssError::from)?;
    let identifier = from_frost_id(suite, *key_package.identifier())?;
    let nonces =
        frost_core::round1::SigningNonces::<C>::deserialize(nonces).map_err(TssError::from)?;
    let commitments = message_map(commitments, |bytes| {
        frost_core::round1::SigningCommitments::<C>::deserialize(bytes)
    })?;
    let signing_package = frost_core::SigningPackage::new(commitments, msg);
    let share = frost_core::round2::sign::<C>(&signing_package, &nonces, &key_package)
        .map_err(TssError::from)?;
    Ok(Message {
        from: identifier,
        to: None,
        data: share.serialize(),
    })
}

fn aggregate_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    commitments: &[Message],
    shares: &[Message],
    pubkey_package: &PublicKeyPackage,
    msg: &[u8],
) -> Result<Signature, TssError> {
    let commitments = message_map(commitments, |bytes| {
        frost_core::round1::SigningCommitments::<C>::deserialize(bytes)
    })?;
    let shares = message_map(shares, |bytes| {
        frost_core::round2::SignatureShare::<C>::deserialize(bytes)
    })?;
    let signing_package = frost_core::SigningPackage::new(commitments, msg);
    let public_key_package = libtss_pubkey_to_frost::<C>(suite, pubkey_package)?;
    let signature = frost_core::aggregate::<C>(&signing_package, &shares, &public_key_package)
        .map_err(TssError::from)?;
    serialize_signature(signature)
}

fn generate_with_dealer_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    max_signers: u16,
    min_signers: u16,
) -> Result<(SerializedKeyPackages, PublicKeyPackage), TssError> {
    let mut rng = OsRng;
    let (shares, public_key_package) = frost_core::keys::generate_with_dealer::<C, _>(
        max_signers,
        min_signers,
        frost_core::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(TssError::from)?;

    let mut key_packages = Vec::with_capacity(shares.len());
    for (id, share) in shares {
        let identifier = from_frost_id(suite, id)?;
        let key_package = frost_core::keys::KeyPackage::try_from(share).map_err(TssError::from)?;
        key_packages.push((identifier, key_package.serialize().map_err(TssError::from)?));
    }

    Ok((
        key_packages,
        frost_pubkey_to_libtss(suite, &public_key_package)?,
    ))
}

fn split_key_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    secret_key: &[u8],
    max_signers: u16,
    min_signers: u16,
) -> Result<(SerializedKeyPackages, PublicKeyPackage), TssError> {
    let secret = frost_core::SigningKey::<C>::deserialize(secret_key).map_err(TssError::from)?;
    let mut rng = OsRng;
    let (shares, public_key_package) = frost_core::keys::split::<C, _>(
        &secret,
        max_signers,
        min_signers,
        frost_core::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(TssError::from)?;

    let mut key_packages = Vec::with_capacity(shares.len());
    for (id, share) in shares {
        let identifier = from_frost_id(suite, id)?;
        let key_package = frost_core::keys::KeyPackage::try_from(share).map_err(TssError::from)?;
        key_packages.push((identifier, key_package.serialize().map_err(TssError::from)?));
    }

    Ok((
        key_packages,
        frost_pubkey_to_libtss(suite, &public_key_package)?,
    ))
}

fn repair_part1_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    key_package_bytes: &[u8],
    helpers: &[Identifier],
    participant: Identifier,
) -> Result<BTreeMap<Identifier, Vec<u8>>, TssError> {
    let key_package = frost_core::keys::KeyPackage::<C>::deserialize(key_package_bytes)
        .map_err(TssError::from)?;
    let helpers = helpers
        .iter()
        .copied()
        .map(to_frost_id::<C>)
        .collect::<Result<Vec<_>, _>>()?;
    let participant = to_frost_id::<C>(participant)?;
    let mut rng = OsRng;
    let deltas = frost_core::keys::repairable::repair_share_part1::<C, _>(
        &helpers,
        &key_package,
        &mut rng,
        participant,
    )
    .map_err(TssError::from)?;

    let mut output = BTreeMap::new();
    for (id, delta) in deltas {
        output.insert(from_frost_id(suite, id)?, delta.serialize());
    }
    Ok(output)
}

fn repair_part2_inner<C: frost_core::Ciphersuite>(deltas: &[Vec<u8>]) -> Result<Vec<u8>, TssError> {
    let deltas = deltas
        .iter()
        .map(|delta| {
            frost_core::keys::repairable::Delta::<C>::deserialize(delta).map_err(TssError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(frost_core::keys::repairable::repair_share_part2::<C>(&deltas).serialize())
}

fn repair_part3_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    sigmas: &[Vec<u8>],
    participant: Identifier,
    pubkey_package: &PublicKeyPackage,
) -> Result<Vec<u8>, TssError> {
    let sigmas = sigmas
        .iter()
        .map(|sigma| {
            frost_core::keys::repairable::Sigma::<C>::deserialize(sigma).map_err(TssError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let participant = to_frost_id::<C>(participant)?;
    let public_key_package = libtss_pubkey_to_frost::<C>(suite, pubkey_package)?;
    frost_core::keys::repairable::repair_share_part3::<C>(&sigmas, participant, &public_key_package)
        .map_err(TssError::from)?
        .serialize()
        .map_err(TssError::from)
}

fn refresh_with_dealer_inner<C: frost_core::Ciphersuite>(
    suite: Ciphersuite,
    pubkey_package: &PublicKeyPackage,
    participants: &[Identifier],
) -> Result<(SerializedKeyPackages, PublicKeyPackage), TssError> {
    let public_key_package = libtss_pubkey_to_frost::<C>(suite, pubkey_package)?;
    let participants = participants
        .iter()
        .copied()
        .map(to_frost_id::<C>)
        .collect::<Result<Vec<_>, _>>()?;
    let mut rng = OsRng;
    let (shares, refreshed_public_key_package) =
        frost_core::keys::refresh::compute_refreshing_shares::<C, _>(
            public_key_package,
            &participants,
            &mut rng,
        )
        .map_err(TssError::from)?;

    let shares = shares
        .into_iter()
        .map(|share| {
            Ok((
                from_frost_id(suite, *share.identifier())?,
                share.serialize().map_err(TssError::from)?,
            ))
        })
        .collect::<Result<Vec<_>, TssError>>()?;

    Ok((
        shares,
        frost_pubkey_to_libtss(suite, &refreshed_public_key_package)?,
    ))
}

fn apply_refresh_inner<C: frost_core::Ciphersuite>(
    key_package_bytes: &[u8],
    refresh_data: &[u8],
) -> Result<Vec<u8>, TssError> {
    let key_package = frost_core::keys::KeyPackage::<C>::deserialize(key_package_bytes)
        .map_err(TssError::from)?;
    let refresh_data =
        frost_core::keys::SecretShare::<C>::deserialize(refresh_data).map_err(TssError::from)?;
    frost_core::keys::refresh::refresh_share::<C>(refresh_data, &key_package)
        .map_err(TssError::from)?
        .serialize()
        .map_err(TssError::from)
}

pub fn frost_dkg_part1(
    config: &ThresholdConfig,
    self_id: Identifier,
) -> Result<(Zeroizing<Vec<u8>>, Vec<Message>), TssError> {
    validate_frost_config(config)?;
    dispatch_frost!(config.suite, |C| {
        part1_inner::<C>(self_id, config.max_signers, config.min_signers)
    })
}

pub fn frost_dkg_part2(
    suite: Ciphersuite,
    round1_secret: &[u8],
    received: &[Message],
) -> Result<(Zeroizing<Vec<u8>>, Vec<Message>), TssError> {
    dispatch_frost!(suite, |C| part2_inner::<C>(suite, round1_secret, received))
}

pub fn frost_dkg_part3(
    suite: Ciphersuite,
    round2_secret: &[u8],
    round1_messages: &[Message],
    round2_messages: &[Message],
) -> Result<(KeyShareHandle, PublicKeyPackage), TssError> {
    let (key_package, public_key_package) = dispatch_frost!(suite, |C| part3_inner::<C>(
        suite,
        round2_secret,
        round1_messages,
        round2_messages,
    ))?;
    Ok((
        key_share_handle_from_bytes(suite, key_package)?,
        public_key_package,
    ))
}

pub fn frost_commit(key_share: &KeyShareHandle) -> Result<(Zeroizing<Vec<u8>>, Message), TssError> {
    dispatch_frost!(key_share.suite, |C| {
        commit_inner::<C>(key_share.suite, &key_share.key_package_bytes)
    })
}

pub fn frost_sign(
    key_share: &KeyShareHandle,
    nonces: &[u8],
    commitments: &[Message],
    msg: &[u8],
) -> Result<Message, TssError> {
    dispatch_frost!(key_share.suite, |C| sign_inner::<C>(
        key_share.suite,
        &key_share.key_package_bytes,
        nonces,
        commitments,
        msg,
    ))
}

pub fn frost_aggregate(
    msg: &[u8],
    commitments: &[Message],
    shares: &[Message],
    pubkey_package: &PublicKeyPackage,
) -> Result<Signature, TssError> {
    dispatch_frost!(pubkey_package.suite(), |C| aggregate_inner::<C>(
        pubkey_package.suite(),
        commitments,
        shares,
        pubkey_package,
        msg,
    ))
}

/// Generate key shares via trusted dealer (for testing or migration).
///
/// Returns one [`KeyShareHandle`] per participant and the group
/// [`PublicKeyPackage`]. Only valid for FROST ciphersuites.
///
/// # Examples
///
/// ```
/// use libtss::{Ciphersuite, ThresholdConfig};
/// use libtss::frost::frost_generate_with_dealer;
///
/// let config = ThresholdConfig {
///     min_signers: 2,
///     max_signers: 3,
///     suite: Ciphersuite::Ed25519,
/// };
///
/// let (shares, pubkey_pkg) = frost_generate_with_dealer(&config).unwrap();
/// assert_eq!(shares.len(), 3);
/// assert_eq!(pubkey_pkg.min_signers(), 2);
/// assert!(!pubkey_pkg.verifying_key().is_empty());
/// ```
pub fn frost_generate_with_dealer(
    config: &ThresholdConfig,
) -> Result<(Vec<KeyShareHandle>, PublicKeyPackage), TssError> {
    validate_frost_config(config)?;
    let (shares, public_key_package) = dispatch_frost!(config.suite, |C| {
        generate_with_dealer_inner::<C>(config.suite, config.max_signers, config.min_signers)
    })?;
    Ok((
        key_share_handles_from_serialized(config.suite, shares)?,
        public_key_package,
    ))
}

pub fn frost_split_key(
    config: &ThresholdConfig,
    secret_key: &[u8],
) -> Result<(Vec<KeyShareHandle>, PublicKeyPackage), TssError> {
    validate_frost_config(config)?;
    let (shares, public_key_package) = dispatch_frost!(config.suite, |C| split_key_inner::<C>(
        config.suite,
        secret_key,
        config.max_signers,
        config.min_signers,
    ))?;
    Ok((
        key_share_handles_from_serialized(config.suite, shares)?,
        public_key_package,
    ))
}

pub fn frost_repair_part1(
    key_share: &KeyShareHandle,
    helpers: &[Identifier],
    participant: Identifier,
) -> Result<BTreeMap<Identifier, Vec<u8>>, TssError> {
    dispatch_frost!(key_share.suite, |C| repair_part1_inner::<C>(
        key_share.suite,
        &key_share.key_package_bytes,
        helpers,
        participant,
    ))
}

pub fn frost_repair_part2(suite: Ciphersuite, deltas: &[Vec<u8>]) -> Result<Vec<u8>, TssError> {
    dispatch_frost!(suite, |C| repair_part2_inner::<C>(deltas))
}

pub fn frost_repair_part3(
    suite: Ciphersuite,
    sigmas: &[Vec<u8>],
    participant: Identifier,
    pubkey_package: &PublicKeyPackage,
) -> Result<KeyShareHandle, TssError> {
    let key_package = dispatch_frost!(suite, |C| repair_part3_inner::<C>(
        suite,
        sigmas,
        participant,
        pubkey_package,
    ))?;
    key_share_handle_from_bytes(suite, key_package)
}

pub fn frost_refresh_with_dealer(
    pubkey_package: &PublicKeyPackage,
    participants: &[Identifier],
) -> Result<(BTreeMap<Identifier, Vec<u8>>, PublicKeyPackage), TssError> {
    let (shares, refreshed_public_key_package) = dispatch_frost!(pubkey_package.suite(), |C| {
        refresh_with_dealer_inner::<C>(pubkey_package.suite(), pubkey_package, participants)
    })?;
    Ok((shares.into_iter().collect(), refreshed_public_key_package))
}

pub fn frost_apply_refresh(
    key_share: &KeyShareHandle,
    refresh_data: &[u8],
) -> Result<KeyShareHandle, TssError> {
    let key_package = dispatch_frost!(key_share.suite, |C| {
        apply_refresh_inner::<C>(&key_share.key_package_bytes, refresh_data)
    })?;
    key_share_handle_from_bytes(key_share.suite, key_package)
}

pub fn frost_tweak_key_share(
    key_share: &KeyShareHandle,
    merkle_root: Option<&[u8]>,
) -> Result<(KeyShareHandle, u8), TssError> {
    use frost_secp256k1_tr::keys::{EvenY, Tweak};

    if key_share.suite != Ciphersuite::Secp256k1Taproot {
        return Err(TssError::ProtocolMismatch);
    }

    let key_package =
        frost_secp256k1_tr::keys::KeyPackage::deserialize(&key_share.key_package_bytes)
            .map_err(TssError::from)?;
    let key_package = key_package.tweak(merkle_root);
    let parity = if key_package.verifying_key().has_even_y() {
        0
    } else {
        1
    };
    Ok((
        key_share_handle_from_bytes(
            Ciphersuite::Secp256k1Taproot,
            key_package.serialize().map_err(TssError::from)?,
        )?,
        parity,
    ))
}

pub fn frost_tweak_pubkey_package(
    pubkey_package: &PublicKeyPackage,
    merkle_root: Option<&[u8]>,
) -> Result<(PublicKeyPackage, u8), TssError> {
    use frost_secp256k1_tr::keys::{EvenY, Tweak};

    let public_key_package = libtss_pubkey_to_frost::<frost_secp256k1_tr::Secp256K1Sha256TR>(
        Ciphersuite::Secp256k1Taproot,
        pubkey_package,
    )?;
    let public_key_package = public_key_package.tweak(merkle_root);
    let parity = if public_key_package.verifying_key().has_even_y() {
        0
    } else {
        1
    };
    Ok((
        frost_pubkey_to_libtss(Ciphersuite::Secp256k1Taproot, &public_key_package)?,
        parity,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use frost_secp256k1_tr::keys::EvenY;

    use super::*;

    fn ids() -> [Identifier; 3] {
        [
            Identifier::new(1).unwrap(),
            Identifier::new(2).unwrap(),
            Identifier::new(3).unwrap(),
        ]
    }

    fn config(suite: Ciphersuite) -> ThresholdConfig {
        ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite,
        }
    }

    #[test]
    fn test_dkg_and_sign_ed25519() -> Result<(), TssError> {
        let suite = Ciphersuite::Ed25519;
        let config = config(suite);
        let ids = ids();

        let mut round1_secret = Vec::new();
        let mut round1_messages = Vec::new();
        for id in ids {
            let (secret, mut messages) = frost_dkg_part1(&config, id)?;
            round1_secret.push((id, secret));
            round1_messages.push(messages.pop().expect("missing round1 message"));
        }

        let mut round2_secret = Vec::new();
        let mut round2_messages = Vec::new();
        for (id, secret) in &round1_secret {
            let received: Vec<_> = round1_messages
                .iter()
                .filter(|msg| msg.from != *id)
                .cloned()
                .collect();
            let (secret, messages) = frost_dkg_part2(suite, secret, &received)?;
            round2_secret.push((*id, secret));
            round2_messages.extend(messages);
        }

        let mut key_packages = Vec::new();
        let mut pubkeys = Vec::new();
        for (id, secret) in &round2_secret {
            let received_round1: Vec<_> = round1_messages
                .iter()
                .filter(|msg| msg.from != *id)
                .cloned()
                .collect();
            let received_round2: Vec<_> = round2_messages
                .iter()
                .filter(|msg| msg.to == Some(*id))
                .cloned()
                .collect();
            let (key_package, pubkey) =
                frost_dkg_part3(suite, secret, &received_round1, &received_round2)?;
            key_packages.push((*id, key_package));
            pubkeys.push(pubkey);
        }

        assert!(pubkeys
            .windows(2)
            .all(|window| window[0].verifying_key() == window[1].verifying_key()));

        let message = b"dkg-sign";
        let signer_ids = [ids[0], ids[1]];
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();

        for signer_id in signer_ids {
            let key_package = key_packages
                .iter()
                .find(|(id, _)| *id == signer_id)
                .map(|(_, key)| key)
                .expect("missing key package");
            let (nonce, commitment) = frost_commit(key_package)?;
            nonces.push((signer_id, nonce));
            commitments.push(commitment);
        }

        let mut shares = Vec::new();
        for signer_id in signer_ids {
            let key_package = key_packages
                .iter()
                .find(|(id, _)| *id == signer_id)
                .map(|(_, key)| key)
                .expect("missing key package");
            let nonce = nonces
                .iter()
                .find(|(id, _)| *id == signer_id)
                .map(|(_, nonce)| nonce.as_slice())
                .expect("missing nonce");
            shares.push(frost_sign(key_package, nonce, &commitments, message)?);
        }

        let signature = frost_aggregate(message, &commitments, &shares, &pubkeys[0])?;
        let signature =
            frost_ed25519::Signature::deserialize(signature.as_bytes()).expect("bad signature");
        let verifying_key = frost_ed25519::VerifyingKey::deserialize(pubkeys[0].verifying_key())
            .expect("bad verifying key");
        verifying_key
            .verify(message, &signature)
            .expect("signature should verify");

        Ok(())
    }

    #[test]
    fn test_generate_with_dealer() -> Result<(), TssError> {
        let suite = Ciphersuite::Ristretto255;
        let config = config(suite);
        let (shares, pubkey_package) = frost_generate_with_dealer(&config)?;
        assert_eq!(shares.len(), 3);

        let message = b"dealer-sign";
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for key_package in shares.iter().take(2) {
            let (nonce, commitment) = frost_commit(key_package)?;
            nonces.push((key_package.identifier(), nonce));
            commitments.push(commitment);
        }

        let mut signature_shares = Vec::new();
        for key_package in shares.iter().take(2) {
            let nonce = nonces
                .iter()
                .find(|(candidate, _)| *candidate == key_package.identifier())
                .map(|(_, nonce)| nonce.as_slice())
                .expect("missing nonce");
            signature_shares.push(frost_sign(key_package, nonce, &commitments, message)?);
        }

        let signature = frost_aggregate(message, &commitments, &signature_shares, &pubkey_package)?;
        let signature = frost_ristretto255::Signature::deserialize(signature.as_bytes())
            .expect("bad signature");
        let verifying_key =
            frost_ristretto255::VerifyingKey::deserialize(pubkey_package.verifying_key())
                .expect("bad verifying key");
        verifying_key
            .verify(message, &signature)
            .expect("signature should verify");

        Ok(())
    }

    #[test]
    fn test_identifier_roundtrip_and_error_mapping() -> Result<(), TssError> {
        for raw in [1u16, 2, 255, 1024, u16::MAX] {
            let id = Identifier::new(raw)?;
            let roundtrip = from_frost_id(
                Ciphersuite::Ed25519,
                to_frost_id::<frost_ed25519::Ed25519Sha512>(id)?,
            )?;
            assert_eq!(roundtrip.as_u16(), raw);
        }

        let mapped: TssError =
            frost_core::Error::<frost_ed25519::Ed25519Sha512>::InvalidMinSigners.into();
        assert!(matches!(mapped, TssError::InvalidConfig(_)));

        let culprit =
            frost_core::Identifier::<frost_ed25519::Ed25519Sha512>::try_from(7u16).unwrap();
        let mapped: TssError =
            frost_core::Error::<frost_ed25519::Ed25519Sha512>::InvalidSignatureShare {
                culprits: vec![culprit],
            }
            .into();
        assert!(matches!(
            mapped,
            TssError::Abort {
                culprits,
                ban: None,
                ..
            } if culprits.len() == 1 && culprits[0].as_u16() == 7
        ));

        Ok(())
    }

    #[test]
    fn test_repair_and_refresh() -> Result<(), TssError> {
        let suite = Ciphersuite::Ed25519;
        let config = config(suite);
        let ids = ids();
        let (shares, pubkey_package) = frost_generate_with_dealer(&config)?;
        let share_map: BTreeMap<_, _> = shares
            .into_iter()
            .map(|share| (share.identifier(), share))
            .collect();

        let helper_ids = [ids[0], ids[1]];
        let mut delta_sets = Vec::new();
        for helper_id in helper_ids {
            let deltas = frost_repair_part1(
                share_map.get(&helper_id).expect("missing helper share"),
                &helper_ids,
                ids[2],
            )?;
            delta_sets.push(deltas);
        }

        let mut sigmas = Vec::new();
        for helper_id in helper_ids {
            let deltas = delta_sets
                .iter()
                .map(|set| set.get(&helper_id).cloned().expect("missing delta"))
                .collect::<Vec<_>>();
            sigmas.push(frost_repair_part2(suite, &deltas)?);
        }

        let repaired = frost_repair_part3(suite, &sigmas, ids[2], &pubkey_package)?;

        let refresh_participants = ids.to_vec();
        let (refresh_data, refreshed_pubkey) =
            frost_refresh_with_dealer(&pubkey_package, &refresh_participants)?;
        assert_eq!(
            refreshed_pubkey.verifying_key(),
            pubkey_package.verifying_key()
        );

        let refreshed_one = frost_apply_refresh(
            share_map.get(&ids[0]).expect("missing share"),
            refresh_data
                .iter()
                .find(|(id, _)| **id == ids[0])
                .map(|(_, data)| data.as_slice())
                .expect("missing refresh share"),
        )?;
        let refreshed_three = frost_apply_refresh(
            &repaired,
            refresh_data
                .iter()
                .find(|(id, _)| **id == ids[2])
                .map(|(_, data)| data.as_slice())
                .expect("missing refresh share"),
        )?;

        let message = b"refresh-sign";
        let (nonce1, commitment1) = frost_commit(&refreshed_one)?;
        let (nonce3, commitment3) = frost_commit(&refreshed_three)?;
        let commitments = vec![commitment1, commitment3];
        let share1 = frost_sign(&refreshed_one, &nonce1, &commitments, message)?;
        let share3 = frost_sign(&refreshed_three, &nonce3, &commitments, message)?;
        let signature =
            frost_aggregate(message, &commitments, &[share1, share3], &refreshed_pubkey)?;
        let signature =
            frost_ed25519::Signature::deserialize(signature.as_bytes()).expect("bad signature");
        let verifying_key =
            frost_ed25519::VerifyingKey::deserialize(refreshed_pubkey.verifying_key())
                .expect("bad verifying key");
        verifying_key
            .verify(message, &signature)
            .expect("signature should verify");

        Ok(())
    }

    #[test]
    fn test_taproot_tweak() -> Result<(), TssError> {
        let suite = Ciphersuite::Secp256k1Taproot;
        let config = config(suite);
        let merkle_root = [12u8; 32];
        let (shares, pubkey_package) = frost_generate_with_dealer(&config)?;

        let (tweaked_one, _) = frost_tweak_key_share(&shares[0], Some(&merkle_root))?;
        let (tweaked_two, _) = frost_tweak_key_share(&shares[1], Some(&merkle_root))?;
        let (tweaked_pubkey, parity) =
            frost_tweak_pubkey_package(&pubkey_package, Some(&merkle_root))?;

        let message = b"taproot-sign";
        let (nonce_one, commitment_one) = frost_commit(&tweaked_one)?;
        let (nonce_two, commitment_two) = frost_commit(&tweaked_two)?;
        let commitments = vec![commitment_one, commitment_two];
        let share_one = frost_sign(&tweaked_one, &nonce_one, &commitments, message)?;
        let share_two = frost_sign(&tweaked_two, &nonce_two, &commitments, message)?;
        let signature = frost_aggregate(
            message,
            &commitments,
            &[share_one, share_two],
            &tweaked_pubkey,
        )?;

        let signature = frost_secp256k1_tr::Signature::deserialize(signature.as_bytes())
            .expect("bad signature");
        let verifying_key =
            frost_secp256k1_tr::VerifyingKey::deserialize(tweaked_pubkey.verifying_key())
                .expect("bad verifying key");
        verifying_key
            .verify(message, &signature)
            .expect("signature should verify");
        assert_eq!(parity, if verifying_key.has_even_y() { 0 } else { 1 });

        Ok(())
    }

    #[test]
    fn test_protocol_mismatch_rejected() {
        let id = Identifier::new(1).unwrap();
        let err = frost_dkg_part1(&config(Ciphersuite::Secp256k1ECDSA), id)
            .expect_err("ecdsa should be rejected");
        assert_eq!(err, TssError::ProtocolMismatch);
        let err = frost_generate_with_dealer(&config(Ciphersuite::Secp256k1ECDSA))
            .expect_err("ecdsa should be rejected");
        assert_eq!(err, TssError::ProtocolMismatch);
    }

    #[test]
    fn test_signature_protocol_is_frost() {
        let signature = Signature::new(Protocol::Frost, vec![1, 2, 3], None);
        assert_eq!(signature.protocol(), Protocol::Frost);
    }

    fn dealer_sign_roundtrip(suite: Ciphersuite) -> Result<(), TssError> {
        let config = config(suite);
        let (shares, pubkey_package) = frost_generate_with_dealer(&config)?;
        assert_eq!(shares.len(), 3);

        let message = b"suite-roundtrip";
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for key_package in shares.iter().take(2) {
            let (nonce, commitment) = frost_commit(key_package)?;
            nonces.push((key_package.identifier(), nonce));
            commitments.push(commitment);
        }

        let mut signature_shares = Vec::new();
        for key_package in shares.iter().take(2) {
            let nonce = nonces
                .iter()
                .find(|(id, _)| *id == key_package.identifier())
                .map(|(_, nonce)| nonce.as_slice())
                .expect("missing nonce");
            signature_shares.push(frost_sign(key_package, nonce, &commitments, message)?);
        }

        let _signature =
            frost_aggregate(message, &commitments, &signature_shares, &pubkey_package)?;
        Ok(())
    }

    #[test]
    fn test_dealer_sign_secp256k1() -> Result<(), TssError> {
        dealer_sign_roundtrip(Ciphersuite::Secp256k1)
    }

    #[test]
    fn test_dealer_sign_p256() -> Result<(), TssError> {
        dealer_sign_roundtrip(Ciphersuite::P256)
    }

    #[test]
    fn test_dealer_sign_ed448() -> Result<(), TssError> {
        dealer_sign_roundtrip(Ciphersuite::Ed448)
    }
}
