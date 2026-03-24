use crate::types::Identifier;
use thiserror::Error;

/// Unified error type for the entire library.
///
/// Protocol aborts (FROST verification failures, DKLs23 `Abort` errors) are
/// represented as [`TssError::Abort`] with optional culprit and ban information.
///
/// # Examples
///
/// ```
/// use libtss::TssError;
///
/// let err = TssError::InvalidConfig("min_signers must be >= 2".into());
/// assert_eq!(err.to_string(), "invalid config: min_signers must be >= 2");
///
/// let err = TssError::InvalidIdentifier;
/// assert_eq!(err.to_string(), "invalid identifier");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TssError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid identifier")]
    InvalidIdentifier,
    #[error("invalid share")]
    InvalidShare,
    #[error("invalid commitment")]
    InvalidCommitment,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("nonce reuse")]
    NonceReuse,
    #[error("invalid handle")]
    HandleInvalid,
    #[error("protocol mismatch")]
    ProtocolMismatch,
    #[error("deserialize failed: {0}")]
    DeserializeFailed(String),
    #[error("tweak error: {0}")]
    TweakError(String),
    #[error("session complete")]
    SessionComplete,
    #[error("abort: {message}")]
    Abort {
        culprits: Vec<Identifier>,
        message: String,
        ban: Option<Identifier>,
    },
}

impl From<postcard::Error> for TssError {
    fn from(err: postcard::Error) -> Self {
        Self::DeserializeFailed(err.to_string())
    }
}

impl From<dkls23_secp256k1::protocols::derivation::ErrorDeriv> for TssError {
    fn from(err: dkls23_secp256k1::protocols::derivation::ErrorDeriv) -> Self {
        Self::InvalidConfig(err.description)
    }
}

impl<C: frost_core::Ciphersuite> From<frost_core::Error<C>> for TssError {
    fn from(err: frost_core::Error<C>) -> Self {
        use frost_core::Error;

        let mut message = err.to_string();
        match err {
            Error::InvalidMinSigners
            | Error::InvalidMaxSigners
            | Error::InvalidCoefficients
            | Error::DuplicatedIdentifier
            | Error::IncorrectNumberOfIdentifiers
            | Error::IncorrectNumberOfShares
            | Error::IncorrectNumberOfPackages
            | Error::IncorrectNumberOfCommitments => Self::InvalidConfig(message),
            Error::MalformedIdentifier
            | Error::UnknownIdentifier
            | Error::IdentifierDerivationNotSupported => Self::InvalidIdentifier,
            Error::DuplicatedShares | Error::InvalidCoefficient => Self::InvalidShare,
            Error::IdentityCommitment | Error::MissingCommitment | Error::IncorrectCommitment => {
                Self::InvalidCommitment
            }
            Error::MalformedSignature | Error::InvalidSignature => Self::InvalidSignature,
            Error::DKGNotSupported => Self::ProtocolMismatch,
            Error::InvalidSignatureShare { culprits } => {
                let culprits = map_frost_culprits(culprits, &mut message);
                Self::Abort {
                    culprits,
                    message,
                    ban: None,
                }
            }
            Error::InvalidSecretShare { culprit } => {
                let culprits = map_frost_culprits(culprit, &mut message);
                Self::Abort {
                    culprits,
                    message,
                    ban: None,
                }
            }
            Error::InvalidProofOfKnowledge { culprit } => {
                let culprits = map_frost_culprits(std::iter::once(culprit), &mut message);
                Self::Abort {
                    culprits,
                    message,
                    ban: None,
                }
            }
            _ => Self::DeserializeFailed(message),
        }
    }
}

fn map_frost_culprits<C, I>(culprits: I, message: &mut String) -> Vec<Identifier>
where
    C: frost_core::Ciphersuite,
    I: IntoIterator<Item = frost_core::Identifier<C>>,
{
    let mut mapped = Vec::new();
    for culprit in culprits {
        let Some(id) = frost_identifier_to_libtss(culprit) else {
            message.push_str(" (culprit identifier not representable as libtss Identifier)");
            return Vec::new();
        };
        mapped.push(id);
    }
    mapped
}

fn frost_identifier_to_libtss<C: frost_core::Ciphersuite>(
    id: frost_core::Identifier<C>,
) -> Option<Identifier> {
    let bytes = id.serialize();
    let le = (bytes.len() >= 2 && bytes[2..].iter().all(|byte| *byte == 0))
        .then(|| u16::from_le_bytes([bytes[0], bytes[1]]));
    let be = (bytes.len() >= 2 && bytes[..bytes.len() - 2].iter().all(|byte| *byte == 0))
        .then(|| u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]));
    le.or(be).and_then(|value| Identifier::new(value).ok())
}
