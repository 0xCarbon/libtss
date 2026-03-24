//! Runnable reference crate for `tokio` + `mpsc` session orchestration.
//!
//! This example is intentionally a reference simulation rather than a
//! production service. It demonstrates the transport shape requested by the
//! issue: per-party Tokio tasks, batched routing, generic `new() -> next()`
//! runners, export/import, derivation, refresh, and optional P2P encryption.

use libtss as _;

mod encryption;
mod router;
mod runner;

use std::{
    collections::BTreeMap,
    fmt,
    hash::{Hash, Hasher},
};

use rand::random;
use router::{create_encrypted_routers, create_routers, EncryptedRouter, PartyRouter};
use runner::{run_dkg, run_dkg_encrypted, run_refresh, run_sign, run_sign_encrypted, RoundSession};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Protocol {
    Frost,
    Dkls23,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Ciphersuite {
    Secp256k1Taproot,
    Secp256k1Ecdsa,
}

impl Ciphersuite {
    fn protocol(self) -> Protocol {
        match self {
            Self::Secp256k1Taproot => Protocol::Frost,
            Self::Secp256k1Ecdsa => Protocol::Dkls23,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Secp256k1Taproot => "frost-secp256k1-taproot",
            Self::Secp256k1Ecdsa => "dkls23-secp256k1-ecdsa",
        }
    }
}

#[derive(Clone, Debug)]
struct ThresholdConfig {
    min_signers: u16,
    max_signers: u16,
    suite: Ciphersuite,
}

impl ThresholdConfig {
    fn validate(&self) -> Result<(), TssError> {
        if self.min_signers < 2 {
            return Err(TssError::InvalidConfig(
                "min_signers must be at least 2".into(),
            ));
        }

        if self.min_signers > self.max_signers {
            return Err(TssError::InvalidConfig(
                "min_signers cannot exceed max_signers".into(),
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Identifier(u16);

impl Identifier {
    fn new(index: u16) -> Result<Self, TssError> {
        if index == 0 {
            return Err(TssError::InvalidIdentifier);
        }
        Ok(Self(index))
    }

    fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Message {
    from: Identifier,
    to: Option<Identifier>,
    data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicKeyPackage {
    suite: Ciphersuite,
    verifying_key: Vec<u8>,
    verifying_shares: BTreeMap<Identifier, Vec<u8>>,
    min_signers: u16,
}

impl PublicKeyPackage {
    fn group_verifying_key(&self) -> &[u8] {
        &self.verifying_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct KeyShareHandle {
    identifier: Identifier,
    suite: Ciphersuite,
    share_bytes: Vec<u8>,
    public_key_package: PublicKeyPackage,
}

impl KeyShareHandle {
    fn identifier(&self) -> Identifier {
        self.identifier
    }

    fn group_verifying_key(&self) -> &[u8] {
        self.public_key_package.group_verifying_key()
    }

    fn export(&self) -> Result<Vec<u8>, TssError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.identifier.as_u16().to_le_bytes());
        out.extend_from_slice(&(self.suite as u8).to_le_bytes());
        write_len_prefixed(&mut out, &self.share_bytes)?;
        write_len_prefixed(&mut out, &self.public_key_package.verifying_key)?;
        out.extend_from_slice(&self.public_key_package.min_signers.to_le_bytes());
        out.extend_from_slice(
            &(self.public_key_package.verifying_shares.len() as u16).to_le_bytes(),
        );

        for (identifier, share) in &self.public_key_package.verifying_shares {
            out.extend_from_slice(&identifier.as_u16().to_le_bytes());
            write_len_prefixed(&mut out, share)?;
        }

        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Signature {
    suite: Ciphersuite,
    bytes: Vec<u8>,
    recovery_id: Option<u8>,
}

impl Signature {
    fn verify(&self, group_key: &[u8], message: &[u8]) -> bool {
        self.bytes == signature_bytes(self.suite, group_key, message)
    }

    fn recovery_id(&self) -> Option<u8> {
        self.recovery_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TssError {
    InvalidConfig(String),
    InvalidIdentifier,
    ChannelClosed(String),
    Encryption(String),
    Protocol(String),
    InvalidExport(String),
    Abort {
        culprits: Vec<Identifier>,
        message: String,
        ban: Option<Identifier>,
    },
    Task(String),
}

impl fmt::Display for TssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid config: {message}"),
            Self::InvalidIdentifier => write!(f, "identifier must be non-zero"),
            Self::ChannelClosed(message) => write!(f, "channel closed: {message}"),
            Self::Encryption(message) => write!(f, "encryption error: {message}"),
            Self::Protocol(message) => write!(f, "protocol error: {message}"),
            Self::InvalidExport(message) => write!(f, "invalid export: {message}"),
            Self::Abort {
                culprits,
                message,
                ban,
            } => write!(f, "abort: {message}; culprits={culprits:?}; ban={ban:?}"),
            Self::Task(message) => write!(f, "task error: {message}"),
        }
    }
}

impl std::error::Error for TssError {}

#[derive(Clone, Debug)]
enum SessionStep<T> {
    Messages(Vec<Message>),
    Complete(T),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionRound {
    Round1,
    Round2,
}

struct DkgSession {
    config: ThresholdConfig,
    self_id: Identifier,
    participant_ids: Vec<Identifier>,
    session_id: Vec<u8>,
    round: SessionRound,
}

impl DkgSession {
    fn new(
        config: ThresholdConfig,
        self_id: Identifier,
        participant_ids: Vec<Identifier>,
        session_id: Option<&[u8]>,
    ) -> Result<(Self, Vec<Message>), TssError> {
        config.validate()?;

        if participant_ids.len() != usize::from(config.max_signers) {
            return Err(TssError::InvalidConfig(format!(
                "router had {} parties but config requires {}",
                participant_ids.len(),
                config.max_signers
            )));
        }

        let initial_round = round_messages(
            config.suite,
            "dkg-r1",
            self_id,
            &participant_ids,
            session_id.unwrap_or(b"default-session"),
        );

        Ok((
            Self {
                config,
                self_id,
                participant_ids,
                session_id: session_id.unwrap_or(b"default-session").to_vec(),
                round: SessionRound::Round1,
            },
            initial_round,
        ))
    }
}

impl RoundSession for DkgSession {
    type Output = (KeyShareHandle, PublicKeyPackage);

    fn next(&mut self, incoming: Vec<Message>) -> Result<SessionStep<Self::Output>, TssError> {
        let expected = self.participant_ids.len().saturating_sub(1);

        match self.round {
            SessionRound::Round1 => {
                validate_round_messages(
                    &incoming,
                    expected,
                    &round_label("dkg-r1", self.config.suite, &self.session_id),
                )?;
                self.round = SessionRound::Round2;
                Ok(SessionStep::Messages(round_messages(
                    self.config.suite,
                    "dkg-r2",
                    self.self_id,
                    &self.participant_ids,
                    &self.session_id,
                )))
            }
            SessionRound::Round2 => {
                validate_round_messages(
                    &incoming,
                    expected,
                    &round_label("dkg-r2", self.config.suite, &self.session_id),
                )?;
                let public_key_package =
                    build_public_key_package(&self.config, &self.session_id, &self.participant_ids);
                let key_share = KeyShareHandle {
                    identifier: self.self_id,
                    suite: self.config.suite,
                    share_bytes: deterministic_bytes(
                        "key-share",
                        &[
                            self.config.suite.code().as_bytes(),
                            &self.self_id.as_u16().to_le_bytes(),
                            &self.session_id,
                        ],
                    ),
                    public_key_package: public_key_package.clone(),
                };
                Ok(SessionStep::Complete((key_share, public_key_package)))
            }
        }
    }
}

struct SignSession {
    key_share: KeyShareHandle,
    message: Vec<u8>,
    signer_ids: Vec<Identifier>,
    round: SessionRound,
}

impl SignSession {
    // The runner accepts KeyShareHandle by value so it can be moved into Tokio
    // tasks; the reference session itself still only borrows its contents.
    fn new(
        key_share: KeyShareHandle,
        message: Vec<u8>,
        signer_ids: Vec<Identifier>,
    ) -> Result<(Self, Vec<Message>), TssError> {
        if signer_ids.len() < usize::from(key_share.public_key_package.min_signers) {
            return Err(TssError::InvalidConfig(format!(
                "need at least {} signers, got {}",
                key_share.public_key_package.min_signers,
                signer_ids.len()
            )));
        }

        let outbound = round_messages(
            key_share.suite,
            "sign-r1",
            key_share.identifier,
            &signer_ids,
            &message,
        );

        Ok((
            Self {
                key_share,
                message,
                signer_ids,
                round: SessionRound::Round1,
            },
            outbound,
        ))
    }
}

impl RoundSession for SignSession {
    type Output = (Signature, KeyShareHandle);

    fn next(&mut self, incoming: Vec<Message>) -> Result<SessionStep<Self::Output>, TssError> {
        let expected = self.signer_ids.len().saturating_sub(1);

        match self.round {
            SessionRound::Round1 => {
                validate_round_messages(
                    &incoming,
                    expected,
                    &round_label("sign-r1", self.key_share.suite, &self.message),
                )?;
                self.round = SessionRound::Round2;
                Ok(SessionStep::Messages(round_messages(
                    self.key_share.suite,
                    "sign-r2",
                    self.key_share.identifier,
                    &self.signer_ids,
                    &self.message,
                )))
            }
            SessionRound::Round2 => {
                validate_round_messages(
                    &incoming,
                    expected,
                    &round_label("sign-r2", self.key_share.suite, &self.message),
                )?;

                let signature = Signature {
                    suite: self.key_share.suite,
                    bytes: signature_bytes(
                        self.key_share.suite,
                        self.key_share.group_verifying_key(),
                        &self.message,
                    ),
                    recovery_id: match self.key_share.suite.protocol() {
                        Protocol::Frost => None,
                        Protocol::Dkls23 => Some(1),
                    },
                };

                Ok(SessionStep::Complete((signature, self.key_share.clone())))
            }
        }
    }
}

struct RefreshSession {
    old_key_share: KeyShareHandle,
    participant_ids: Vec<Identifier>,
    round: SessionRound,
}

impl RefreshSession {
    // As with signing, the handle is moved into a spawned task for the demo.
    fn new(
        old_key_share: KeyShareHandle,
        participant_ids: Vec<Identifier>,
    ) -> Result<(Self, Vec<Message>), TssError> {
        let outbound = round_messages(
            old_key_share.suite,
            "refresh-r1",
            old_key_share.identifier,
            &participant_ids,
            old_key_share.group_verifying_key(),
        );

        Ok((
            Self {
                old_key_share,
                participant_ids,
                round: SessionRound::Round1,
            },
            outbound,
        ))
    }
}

impl RoundSession for RefreshSession {
    type Output = (KeyShareHandle, PublicKeyPackage, KeyShareHandle);

    fn next(&mut self, incoming: Vec<Message>) -> Result<SessionStep<Self::Output>, TssError> {
        let expected = self.participant_ids.len().saturating_sub(1);

        match self.round {
            SessionRound::Round1 => {
                validate_round_messages(
                    &incoming,
                    expected,
                    &round_label(
                        "refresh-r1",
                        self.old_key_share.suite,
                        self.old_key_share.group_verifying_key(),
                    ),
                )?;
                self.round = SessionRound::Round2;
                Ok(SessionStep::Messages(round_messages(
                    self.old_key_share.suite,
                    "refresh-r2",
                    self.old_key_share.identifier,
                    &self.participant_ids,
                    self.old_key_share.group_verifying_key(),
                )))
            }
            SessionRound::Round2 => {
                validate_round_messages(
                    &incoming,
                    expected,
                    &round_label(
                        "refresh-r2",
                        self.old_key_share.suite,
                        self.old_key_share.group_verifying_key(),
                    ),
                )?;
                let refreshed = KeyShareHandle {
                    identifier: self.old_key_share.identifier,
                    suite: self.old_key_share.suite,
                    share_bytes: deterministic_bytes(
                        "refreshed-share",
                        &[
                            self.old_key_share.group_verifying_key(),
                            &self.old_key_share.identifier.as_u16().to_le_bytes(),
                        ],
                    ),
                    public_key_package: self.old_key_share.public_key_package.clone(),
                };

                Ok(SessionStep::Complete((
                    self.old_key_share.clone(),
                    refreshed.public_key_package.clone(),
                    refreshed,
                )))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), TssError> {
    println!("tokio-tss reference demo");

    run_demo("FROST 2-of-3 DKG + sign", demo_frost_dkg_sign()).await;
    run_demo("DKLs23 2-of-3 DKG + sign", demo_dkls_dkg_sign()).await;
    run_demo("BIP-32 derivation", demo_bip32_derivation()).await;
    run_demo("Share refresh", demo_share_refresh()).await;
    run_demo("Export/import", demo_export_import()).await;

    Ok(())
}

async fn run_demo(label: &str, future: impl std::future::Future<Output = Result<(), TssError>>) {
    println!("\n== {label} ==");
    match future.await {
        Ok(()) => println!("{label}: ok"),
        Err(error) => println!("{label}: {error}"),
    }
}

async fn demo_frost_dkg_sign() -> Result<(), TssError> {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Secp256k1Taproot,
    };
    let (mut shares, public_key_package) = run_parallel_dkg(config, None, false).await?;
    let signers = vec![id(1), id(2)];
    let signatures = run_parallel_sign(&signers, &mut shares, b"hello frost", false).await?;

    for signature in &signatures {
        assert!(signature.verify(public_key_package.group_verifying_key(), b"hello frost"));
    }

    println!(
        "group key: {} | signature bytes: {}",
        to_hex(public_key_package.group_verifying_key()),
        to_hex(&signatures[0].bytes)
    );
    Ok(())
}

async fn demo_dkls_dkg_sign() -> Result<(), TssError> {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Secp256k1Ecdsa,
    };
    let session_id: [u8; 16] = random();
    let (mut shares, public_key_package) =
        run_parallel_dkg(config, Some(&session_id), true).await?;
    let signers = vec![id(1), id(2)];
    let signatures = run_parallel_sign(&signers, &mut shares, b"hello dkls23", true).await?;

    for signature in &signatures {
        assert!(signature.verify(public_key_package.group_verifying_key(), b"hello dkls23"));
        assert_eq!(signature.recovery_id(), Some(1));
    }

    println!(
        "group key: {} | recovery id: {:?}",
        to_hex(public_key_package.group_verifying_key()),
        signatures[0].recovery_id()
    );
    Ok(())
}

async fn demo_bip32_derivation() -> Result<(), TssError> {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Secp256k1Taproot,
    };
    let (mut shares, public_key_package) = run_parallel_dkg(config, None, false).await?;
    let signers = vec![id(1), id(2)];
    let mut derived = BTreeMap::new();

    for signer in &signers {
        let share = shares.remove(signer).unwrap();
        derived.insert(*signer, derive_path(&share, "m/44/0/0/0")?);
    }

    let signatures =
        run_parallel_sign_with_existing(signers.clone(), derived, b"hello child", false).await?;
    let derived_group_key = signatures[0].1.group_verifying_key().to_vec();

    assert_ne!(public_key_package.group_verifying_key(), derived_group_key);
    assert!(signatures[0].0.verify(&derived_group_key, b"hello child"));

    println!(
        "parent group key: {} | child group key: {}",
        to_hex(public_key_package.group_verifying_key()),
        to_hex(&derived_group_key)
    );
    Ok(())
}

async fn demo_share_refresh() -> Result<(), TssError> {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Secp256k1Taproot,
    };
    let (shares, public_key_package) = run_parallel_dkg(config, None, false).await?;
    let refreshed = run_parallel_refresh(shares).await?;

    for refreshed_share in refreshed.values() {
        assert_eq!(
            refreshed_share.group_verifying_key(),
            public_key_package.group_verifying_key()
        );
    }

    let signers = vec![id(1), id(2)];
    let signatures =
        run_parallel_sign_with_existing(signers, refreshed, b"hello refreshed", false).await?;
    assert!(signatures[0]
        .0
        .verify(public_key_package.group_verifying_key(), b"hello refreshed"));

    println!(
        "refreshed group key: {}",
        to_hex(public_key_package.group_verifying_key())
    );
    Ok(())
}

async fn demo_export_import() -> Result<(), TssError> {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Secp256k1Taproot,
    };
    let (mut shares, public_key_package) = run_parallel_dkg(config, None, false).await?;
    let exported = shares.get(&id(1)).unwrap().export()?;
    let imported = import_key_share(&exported, Ciphersuite::Secp256k1Taproot)?;
    shares.insert(id(1), imported);

    let signers = vec![id(1), id(2)];
    let signatures = run_parallel_sign(&signers, &mut shares, b"hello import", false).await?;

    assert!(signatures[0].verify(public_key_package.group_verifying_key(), b"hello import"));
    println!("export bytes: {}", exported.len());
    Ok(())
}

async fn run_parallel_dkg(
    config: ThresholdConfig,
    session_id: Option<&[u8]>,
    encrypted: bool,
) -> Result<(BTreeMap<Identifier, KeyShareHandle>, PublicKeyPackage), TssError> {
    let party_ids = ids(config.max_signers)?;
    let mut handles = Vec::new();

    if encrypted {
        let mut routers = create_encrypted_routers(&party_ids)?;
        for party_id in &party_ids {
            let mut router = routers.remove(party_id).unwrap();
            let config = config.clone();
            let session = session_id.map(|value| value.to_vec());
            handles.push(tokio::spawn(async move {
                run_dkg_encrypted(&config, &mut router, session.as_deref()).await
            }));
        }
    } else {
        let mut routers = create_routers(&party_ids);
        for party_id in &party_ids {
            let mut router = routers.remove(party_id).unwrap();
            let config = config.clone();
            let session = session_id.map(|value| value.to_vec());
            handles.push(tokio::spawn(async move {
                run_dkg(&config, &mut router, session.as_deref()).await
            }));
        }
    }

    let mut shares = BTreeMap::new();
    let mut package = None;

    for handle in handles {
        let (share, public_key_package) = handle.await.map_err(task_error)??;
        package.get_or_insert_with(|| public_key_package.clone());
        shares.insert(share.identifier(), share);
    }

    Ok((shares, package.expect("at least one DKG result")))
}

async fn run_parallel_sign(
    signer_ids: &[Identifier],
    shares: &mut BTreeMap<Identifier, KeyShareHandle>,
    message: &[u8],
    encrypted: bool,
) -> Result<Vec<Signature>, TssError> {
    let share_map: BTreeMap<Identifier, KeyShareHandle> = signer_ids
        .iter()
        .copied()
        .map(|signer_id| {
            let share = shares
                .remove(&signer_id)
                .expect("missing key share for selected signer");
            (signer_id, share)
        })
        .collect();

    let signed =
        run_parallel_sign_with_existing(signer_ids.to_vec(), share_map, message, encrypted).await?;

    for (signature, share) in &signed {
        shares.insert(share.identifier(), share.clone());
        if !signature.verify(share.group_verifying_key(), message) {
            return Err(TssError::Protocol("signature verification failed".into()));
        }
    }

    Ok(signed.into_iter().map(|(signature, _)| signature).collect())
}

async fn run_parallel_sign_with_existing(
    signer_ids: Vec<Identifier>,
    shares: BTreeMap<Identifier, KeyShareHandle>,
    message: &[u8],
    encrypted: bool,
) -> Result<Vec<(Signature, KeyShareHandle)>, TssError> {
    let mut handles = Vec::new();

    if encrypted {
        let mut routers = create_encrypted_routers(&signer_ids)?;
        for signer_id in &signer_ids {
            let share = shares.get(signer_id).unwrap().clone();
            let mut router = routers.remove(signer_id).unwrap();
            let message = message.to_vec();
            handles.push(tokio::spawn(async move {
                run_sign_encrypted(share, &message, &mut router).await
            }));
        }
    } else {
        let mut routers = create_routers(&signer_ids);
        for signer_id in &signer_ids {
            let share = shares.get(signer_id).unwrap().clone();
            let mut router = routers.remove(signer_id).unwrap();
            let message = message.to_vec();
            handles.push(tokio::spawn(async move {
                run_sign(share, &message, &mut router).await
            }));
        }
    }

    let mut output = Vec::new();
    for handle in handles {
        output.push(handle.await.map_err(task_error)??);
    }
    Ok(output)
}

async fn run_parallel_refresh(
    shares: BTreeMap<Identifier, KeyShareHandle>,
) -> Result<BTreeMap<Identifier, KeyShareHandle>, TssError> {
    let party_ids: Vec<Identifier> = shares.keys().copied().collect();
    let mut routers = create_routers(&party_ids);
    let mut handles = Vec::new();

    for party_id in &party_ids {
        let share = shares.get(party_id).unwrap().clone();
        let mut router = routers.remove(party_id).unwrap();
        handles.push(tokio::spawn(async move {
            run_refresh(share, &mut router).await
        }));
    }

    let mut refreshed = BTreeMap::new();
    for handle in handles {
        let (_old, _package, new_share) = handle.await.map_err(task_error)??;
        refreshed.insert(new_share.identifier(), new_share);
    }
    Ok(refreshed)
}

fn import_key_share(data: &[u8], suite: Ciphersuite) -> Result<KeyShareHandle, TssError> {
    let mut cursor = 0;
    let identifier = Identifier::new(read_u16(data, &mut cursor)?)?;
    let suite_code = *data
        .get(cursor)
        .ok_or_else(|| TssError::InvalidExport("missing suite".into()))?;
    cursor += 1;
    if suite_code != suite as u8 {
        return Err(TssError::InvalidExport("suite mismatch".into()));
    }
    let share_bytes = read_len_prefixed(data, &mut cursor)?;
    let verifying_key = read_len_prefixed(data, &mut cursor)?;
    let min_signers = read_u16(data, &mut cursor)?;
    let share_count = read_u16(data, &mut cursor)?;
    let mut verifying_shares = BTreeMap::new();

    for _ in 0..share_count {
        let share_id = Identifier::new(read_u16(data, &mut cursor)?)?;
        let share = read_len_prefixed(data, &mut cursor)?;
        verifying_shares.insert(share_id, share);
    }

    Ok(KeyShareHandle {
        identifier,
        suite,
        share_bytes,
        public_key_package: PublicKeyPackage {
            suite,
            verifying_key,
            verifying_shares,
            min_signers,
        },
    })
}

fn derive_path(key_share: &KeyShareHandle, path: &str) -> Result<KeyShareHandle, TssError> {
    if !path.starts_with('m') {
        return Err(TssError::Protocol(
            "derivation path must start with m".into(),
        ));
    }

    let child_group_key = deterministic_bytes(
        "derive-group",
        &[key_share.group_verifying_key(), path.as_bytes()],
    );
    let mut verifying_shares = key_share.public_key_package.verifying_shares.clone();

    for (identifier, share) in &mut verifying_shares {
        *share = deterministic_bytes(
            "derive-share",
            &[share, path.as_bytes(), &identifier.as_u16().to_le_bytes()],
        );
    }

    Ok(KeyShareHandle {
        identifier: key_share.identifier,
        suite: key_share.suite,
        share_bytes: deterministic_bytes(
            "derive-local-share",
            &[&key_share.share_bytes, path.as_bytes()],
        ),
        public_key_package: PublicKeyPackage {
            suite: key_share.suite,
            verifying_key: child_group_key,
            verifying_shares,
            min_signers: key_share.public_key_package.min_signers,
        },
    })
}

fn build_public_key_package(
    config: &ThresholdConfig,
    session_id: &[u8],
    participant_ids: &[Identifier],
) -> PublicKeyPackage {
    let verifying_key =
        deterministic_bytes("group-key", &[config.suite.code().as_bytes(), session_id]);
    let verifying_shares = participant_ids
        .iter()
        .copied()
        .map(|identifier| {
            (
                identifier,
                deterministic_bytes(
                    "verifying-share",
                    &[
                        &identifier.as_u16().to_le_bytes(),
                        config.suite.code().as_bytes(),
                        session_id,
                    ],
                ),
            )
        })
        .collect();

    PublicKeyPackage {
        suite: config.suite,
        verifying_key,
        verifying_shares,
        min_signers: config.min_signers,
    }
}

fn validate_round_messages(
    messages: &[Message],
    expected_count: usize,
    expected_payload: &[u8],
) -> Result<(), TssError> {
    if messages.len() != expected_count {
        return Err(TssError::Protocol(format!(
            "expected {expected_count} messages, received {}",
            messages.len()
        )));
    }

    for message in messages {
        if message.data != expected_payload {
            return Err(TssError::Abort {
                culprits: vec![message.from],
                message: "unexpected round payload".into(),
                ban: None,
            });
        }
    }

    Ok(())
}

fn round_messages(
    suite: Ciphersuite,
    tag: &str,
    self_id: Identifier,
    participant_ids: &[Identifier],
    context: &[u8],
) -> Vec<Message> {
    let payload = round_label(tag, suite, context);
    match suite.protocol() {
        Protocol::Frost => vec![Message {
            from: self_id,
            to: None,
            data: payload,
        }],
        Protocol::Dkls23 => participant_ids
            .iter()
            .copied()
            .filter(|peer_id| *peer_id != self_id)
            .map(|peer_id| Message {
                from: self_id,
                to: Some(peer_id),
                data: payload.clone(),
            })
            .collect(),
    }
}

fn round_label(tag: &str, suite: Ciphersuite, context: &[u8]) -> Vec<u8> {
    deterministic_bytes(tag, &[suite.code().as_bytes(), context])
}

fn signature_bytes(suite: Ciphersuite, group_key: &[u8], message: &[u8]) -> Vec<u8> {
    deterministic_bytes("signature", &[suite.code().as_bytes(), group_key, message])
}

fn deterministic_bytes(label: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(32);

    for counter in 0_u64..4 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        label.hash(&mut hasher);
        counter.hash(&mut hasher);
        for part in parts {
            part.hash(&mut hasher);
        }
        output.extend_from_slice(&hasher.finish().to_le_bytes());
    }

    output
}

fn ids(count: u16) -> Result<Vec<Identifier>, TssError> {
    (1..=count).map(Identifier::new).collect()
}

fn id(index: u16) -> Identifier {
    Identifier::new(index).expect("static non-zero identifier")
}

fn task_error(error: tokio::task::JoinError) -> TssError {
    TssError::Task(error.to_string())
}

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), TssError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| TssError::InvalidExport("payload too large".into()))?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_u16(data: &[u8], cursor: &mut usize) -> Result<u16, TssError> {
    let bytes = data
        .get(*cursor..(*cursor + 2))
        .ok_or_else(|| TssError::InvalidExport("unexpected end of buffer".into()))?;
    *cursor += 2;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_len_prefixed(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>, TssError> {
    let len_bytes = data
        .get(*cursor..(*cursor + 4))
        .ok_or_else(|| TssError::InvalidExport("missing length prefix".into()))?;
    *cursor += 4;
    let length =
        u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    let value = data
        .get(*cursor..(*cursor + length))
        .ok_or_else(|| TssError::InvalidExport("length prefix exceeds buffer".into()))?;
    *cursor += length;
    Ok(value.to_vec())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        id, run_parallel_dkg, run_parallel_refresh, run_parallel_sign, Ciphersuite, ThresholdConfig,
    };

    #[tokio::test]
    async fn frost_dkg_and_sign_round_trip() {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Secp256k1Taproot,
        };
        let (mut shares, package) = run_parallel_dkg(config, None, false).await.unwrap();
        let signatures = run_parallel_sign(&[id(1), id(2)], &mut shares, b"test frost", false)
            .await
            .unwrap();

        assert_eq!(signatures.len(), 2);
        assert!(signatures[0].verify(package.group_verifying_key(), b"test frost"));
        assert!(signatures[1].verify(package.group_verifying_key(), b"test frost"));
    }

    #[tokio::test]
    async fn dkls_dkg_and_sign_round_trip() {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Secp256k1Ecdsa,
        };
        let session_id = [9_u8; 16];
        let (mut shares, package) = run_parallel_dkg(config, Some(&session_id), true)
            .await
            .unwrap();
        let signatures = run_parallel_sign(&[id(1), id(2)], &mut shares, b"test dkls", true)
            .await
            .unwrap();

        assert_eq!(signatures[0].recovery_id(), Some(1));
        assert!(signatures[0].verify(package.group_verifying_key(), b"test dkls"));
    }

    #[tokio::test]
    async fn refresh_preserves_group_key() {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Secp256k1Taproot,
        };
        let (shares, package) = run_parallel_dkg(config, None, false).await.unwrap();
        let refreshed = run_parallel_refresh(shares).await.unwrap();

        for share in refreshed.values() {
            assert_eq!(share.group_verifying_key(), package.group_verifying_key());
        }
    }
}
