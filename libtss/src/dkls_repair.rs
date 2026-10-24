//! Repair of a lost DKLs23 key share (secp256k1 and secp256r1).
//!
//! Wraps DKLs23 `protocols::repair`. At least `min_signers` surviving parties
//! (the helpers) each send the lost party (the target) one message from
//! [`repair_helper_term`]; the target turns them into a share with
//! [`repair_assemble`]. The share has the group's key, but it cannot sign
//! until all `n` parties run a complete refresh
//! ([`RefreshSession::new_dkls`](crate::RefreshSession::new_dkls)), which also
//! replaces every pre-repair share.
//!
//! Requirements:
//!
//! - **Authenticate the target.** Repair hands the share of index `target` to
//!   whoever the helpers send their terms to. If the real party with that
//!   index still exists, an impostor gains a second share and the effective
//!   threshold drops by one.
//! - Send each term to the target only, over a confidential and
//!   authenticated channel. `repair_assemble` requires each term's helper to
//!   be the message's `from`, so `from` must be the authenticated sender.
//! - After the complete refresh, every party erases its pre-repair share
//!   (and backups): a refresh cannot revoke shares someone keeps.
//! - Repair applies to root shares, not to BIP-32-derived ones.

use dkls23_secp256k1::curve::DklsCurve;
use dkls23_secp256k1::protocols::repair::{self, RepairError, RepairTerm};
use dkls23_secp256k1::protocols::{Party, PartyIndex, PublicKeyPackage as DklsPublicKeyPackage};

use crate::dkls::{identifier_to_party_index, party_index_to_identifier};
use crate::dkls_package::to_dkls_package;
use crate::keyshare::{self, KeyShareHandle};
use crate::message::Message;
use crate::types::{Ciphersuite, Identifier, PublicKeyPackage};
use crate::TssError;

fn repair_error(error: RepairError) -> TssError {
    match error {
        RepairError::ShareMismatch | RepairError::InconsistentTerms => TssError::InvalidShare,
        other => TssError::InvalidConfig(other.to_string()),
    }
}

/// This helper's repair term for `target`, as a message to the target.
///
/// `helpers` is the helper set (any order, no duplicates, at least
/// `min_signers` parties including this one, not the target); every helper
/// must use the same set and `repair_id`. Send the message to the target
/// only. The input handle stays valid.
///
/// # Errors
///
/// [`TssError::ProtocolMismatch`] for a non-DKLs23 share,
/// [`TssError::InvalidIdentifier`] for an identifier above 255, and
/// [`TssError::InvalidConfig`] for an invalid request (empty `repair_id`,
/// duplicate or too few helpers, a helper set without this party or with the
/// target, a derived share, or a share without the pairwise state a helper
/// needs, such as a repaired share that has not been refreshed).
pub fn repair_helper_term(
    key_share: &KeyShareHandle,
    helpers: &[Identifier],
    target: Identifier,
    repair_id: &[u8],
) -> Result<Message, TssError> {
    let mut indices = helpers
        .iter()
        .map(|&helper| identifier_to_party_index(helper))
        .collect::<Result<Vec<PartyIndex>, _>>()?;
    indices.sort_unstable();
    if indices.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(TssError::InvalidConfig("duplicate helper".into()));
    }
    let target_index = identifier_to_party_index(target)?;
    let data = match key_share.ciphersuite() {
        Ciphersuite::Secp256k1ECDSA => term_bytes(
            &keyshare::clone_dkls_party(key_share)?,
            &indices,
            target_index,
            repair_id,
        )?,
        Ciphersuite::Secp256r1ECDSA => term_bytes(
            &keyshare::clone_dkls_r1_party(key_share)?,
            &indices,
            target_index,
            repair_id,
        )?,
        _ => return Err(TssError::ProtocolMismatch),
    };
    Ok(Message {
        from: key_share.identifier(),
        to: Some(target),
        data,
    })
}

fn term_bytes<C: DklsCurve>(
    party: &Party<C>,
    helpers: &[PartyIndex],
    target: PartyIndex,
    repair_id: &[u8],
) -> Result<Vec<u8>, TssError>
where
    RepairTerm<C>: serde::Serialize,
{
    let term = party
        .repair_term(helpers, target, repair_id)
        .map_err(repair_error)?;
    postcard::to_allocvec(&term).map_err(TssError::from)
}

/// Assembles the helpers' messages into the target's repaired share.
///
/// `public_keys` is the group's public key package as of the latest refresh,
/// obtained from an authenticated source: the repaired share takes its
/// threshold and the other parties' verifying shares from it. The package must
/// be consistent (its verifying shares and group key lie on one polynomial of
/// degree below `min_signers`). Only messages addressed to `target` are used;
/// each must come from the helper its term names. The result cannot sign
/// until all parties run a complete refresh.
///
/// # Errors
///
/// [`TssError::ProtocolMismatch`] for a non-DKLs23 suite or a package of
/// another suite, [`TssError::DeserializeFailed`] for a malformed term,
/// [`TssError::InvalidConfig`] for an invalid target, too few terms or a term
/// whose helper is not its sender, and [`TssError::InvalidShare`] for an
/// inconsistent package, duplicate helpers, terms that disagree on the
/// group's context, or terms that do not add up to the target's verifying
/// share.
pub fn repair_assemble(
    suite: Ciphersuite,
    public_keys: &PublicKeyPackage,
    target: Identifier,
    received: &[Message],
) -> Result<KeyShareHandle, TssError> {
    if public_keys.suite() != suite {
        return Err(TssError::ProtocolMismatch);
    }
    let target_index = identifier_to_party_index(target)?;
    match suite {
        Ciphersuite::Secp256k1ECDSA => {
            let package = to_dkls_package::<k256::Secp256k1>(public_keys)?;
            let party = assemble(
                &package,
                target_index,
                received,
                dkls23_secp256k1::compute_eth_address,
            )?;
            keyshare::from_dkls_dkg(party, package)
        }
        Ciphersuite::Secp256r1ECDSA => {
            let package = to_dkls_package::<p256::NistP256>(public_keys)?;
            let party = assemble(
                &package,
                target_index,
                received,
                dkls23_secp256r1::compute_neo3_address,
            )?;
            keyshare::from_dkls_r1_dkg(party, package)
        }
        _ => Err(TssError::ProtocolMismatch),
    }
}

fn assemble<C: DklsCurve>(
    package: &DklsPublicKeyPackage<C>,
    target: PartyIndex,
    received: &[Message],
    address_fn: impl Fn(&C::AffinePoint) -> String,
) -> Result<Party<C>, TssError>
where
    RepairTerm<C>: serde::de::DeserializeOwned,
{
    let target_id = party_index_to_identifier(target)?;
    let mut terms = Vec::new();
    for message in received.iter().filter(|m| m.to == Some(target_id)) {
        let (term, rest): (RepairTerm<C>, _) = postcard::take_from_bytes(&message.data)?;
        if !rest.is_empty() {
            return Err(TssError::DeserializeFailed(
                "trailing bytes after repair term".into(),
            ));
        }
        if party_index_to_identifier(term.helper)? != message.from {
            return Err(TssError::InvalidConfig(
                "repair term's helper is not its sender".into(),
            ));
        }
        terms.push(term);
    }
    repair::repair_assemble(package, target, &terms, address_fn).map_err(repair_error)
}
