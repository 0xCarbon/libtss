//! Share repair for DKLs23 secp256k1 key shares.
//!
//! A threshold of surviving parties (the *helpers*) rebuilds the share of a
//! party whose key material is lost (the *target*) without any of them
//! learning it. Each helper `i` contributes one term
//!
//! ```text
//! term_i = poly_point_i · λ_i(target) + mask_i
//! ```
//!
//! where `λ_i(target)` is the Lagrange coefficient interpolating the group's
//! secret polynomial at the target's index over the helper set, and the masks
//! are additive shares of zero drawn from the pairwise zero-share seeds the
//! helpers already hold from DKG ([`ZeroShare::compute`]). Only the sum of all
//! terms — which the target alone sees — equals `f(target)`; any proper subset
//! is uniformly random.
//!
//! The target assembles the terms into a *hollow* party: its secret share and
//! derivation data are correct, but it holds no zero-share seeds and no
//! two-party multiplication state, so it cannot sign
//! ([`SignSession::new_dkls`](crate::SignSession::new_dkls) refuses it). A
//! DKLs23 complete refresh across all `n` parties
//! ([`RefreshSession::new_dkls`](crate::RefreshSession::new_dkls)) rebuilds
//! that state and re-randomises every share while keeping the group key.
//!
//! Every gate fails closed: the assembled share must satisfy
//! `G · f(target) == verifying_share(target)` before a handle is created, so a
//! wrong helper set, a corrupted term or a mismatched session id yields
//! [`TssError::InvalidShare`] rather than an unusable share.

use std::collections::BTreeMap;

use dkls23_secp256k1::protocols::derivation::DerivData;
use dkls23_secp256k1::protocols::{
    Parameters, Party, PartyIndex, PublicKeyPackage as DklsPublicKeyPackage,
};
use dkls23_secp256k1::utilities::zero_shares::ZeroShare;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use zeroize::Zeroizing;

use crate::dkls::{identifier_to_party_index, scalar_from_message};
use crate::keyshare::{self, KeyShareHandle};
use crate::types::{Ciphersuite, Identifier, PublicKeyPackage};
use crate::TssError;

/// Domain separator prepended to the repair session id when deriving the
/// zero-share masks, keeping them disjoint from signing's zero shares even if
/// a repair id ever collided with a sign id.
pub const REPAIR_MASK_DOMAIN: &[u8] = b"libtss/dkls23-repair/v1";

const CHAIN_CODE_LEN: usize = 32;
const SCALAR_LEN: usize = 32;

/// Compute this helper's masked repair term for `target`.
///
/// `helpers` is the full helper set (including the caller, excluding the
/// target); every helper must pass the identical set and `repair_sid`, or the
/// masks do not cancel and assembly fails closed. Returns the 32-byte
/// big-endian scalar `poly_point · λ_self(target) + mask`.
///
/// Fails with [`TssError::InvalidShare`] if the caller lacks a zero-share seed
/// pair with any helper counterparty — a hollow (freshly repaired, not yet
/// refreshed) share, or one whose group membership does not cover the helper
/// set. `ZeroShare::compute` would silently skip such a counterparty and the
/// term would leave `poly_point · λ` unmasked, so it is refused instead.
pub fn repair_helper_term(
    key_share: &KeyShareHandle,
    helpers: &[Identifier],
    target: Identifier,
    repair_sid: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TssError> {
    if key_share.ciphersuite() != Ciphersuite::Secp256k1ECDSA {
        return Err(TssError::ProtocolMismatch);
    }
    if repair_sid.is_empty() {
        return Err(TssError::InvalidConfig(
            "repair session_id must not be empty".into(),
        ));
    }

    let party = keyshare::clone_dkls_party(key_share)?;
    let share_count = party.parameters.share_count;
    let self_id = key_share.identifier();
    let helper_indices = validate_helpers(helpers, target, self_id, &party.parameters)?;

    let counterparties: Vec<PartyIndex> = helper_indices
        .iter()
        .copied()
        .filter(|index| *index != party.party_index)
        .collect();
    for counterparty in &counterparties {
        let paired = party
            .zero_share
            .seeds
            .iter()
            .any(|pair| pair.index_counterparty == *counterparty);
        if !paired {
            return Err(TssError::InvalidShare);
        }
    }

    let target_index = identifier_to_party_index(target)?;
    if target_index.as_u8() > share_count {
        return Err(TssError::InvalidIdentifier);
    }

    let xs: Vec<Scalar> = helper_indices.iter().map(index_scalar).collect();
    let self_position = helper_indices
        .iter()
        .position(|index| *index == party.party_index)
        .ok_or_else(|| TssError::InvalidConfig("helpers must include this party".into()))?;
    let lambda = lagrange_coefficient(&xs, self_position, index_scalar(&target_index))?;

    let mask_sid = [REPAIR_MASK_DOMAIN, repair_sid].concat();
    let mask = party
        .zero_share
        .compute::<k256::Secp256k1>(&counterparties, &mask_sid);
    let term = Zeroizing::new(party.poly_point * lambda + mask);

    Ok(Zeroizing::new(term.to_bytes().to_vec()))
}

/// Assemble the helpers' terms into a hollow key share for `target`.
///
/// `pubkey_package` and `chain_code` are the group's public material as every
/// helper reports them; `terms` are the outputs of
/// [`repair_helper_term`] from at least `min_signers` helpers. The sum of the
/// terms must satisfy `G · sum == verifying_share(target)` or the call fails
/// with [`TssError::InvalidShare`] — no handle is created for a share that
/// does not match the group.
///
/// The returned share is hollow: it derives addresses and refreshes, but
/// signing with it is refused until a complete refresh has rebuilt its OT
/// state. `session_id` is recorded as the hollow party's session id and is
/// replaced by the refresh id on refresh.
pub fn repair_assemble(
    suite: Ciphersuite,
    pubkey_package: &PublicKeyPackage,
    chain_code: &[u8],
    target: Identifier,
    terms: &[&[u8]],
    session_id: &[u8],
) -> Result<KeyShareHandle, TssError> {
    if suite != Ciphersuite::Secp256k1ECDSA || pubkey_package.suite() != suite {
        return Err(TssError::ProtocolMismatch);
    }
    if session_id.is_empty() {
        return Err(TssError::InvalidConfig(
            "repair session_id must not be empty".into(),
        ));
    }
    let chain_code: [u8; CHAIN_CODE_LEN] = chain_code
        .try_into()
        .map_err(|_| TssError::InvalidConfig("chain code must be 32 bytes".into()))?;

    let (parameters, verifying_shares) = dkls_shares_from_package(pubkey_package)?;
    let target_index = identifier_to_party_index(target)?;
    let target_share = *verifying_shares
        .get(&target_index)
        .ok_or(TssError::InvalidIdentifier)?;

    if terms.len() < usize::from(parameters.threshold) {
        return Err(TssError::InvalidConfig(
            "repair needs at least threshold terms".into(),
        ));
    }
    let mut poly_point = Zeroizing::new(Scalar::ZERO);
    for term in terms {
        if term.len() != SCALAR_LEN {
            return Err(TssError::DeserializeFailed(
                "repair term must be a 32-byte scalar".into(),
            ));
        }
        *poly_point += scalar_from_message(term)?;
    }

    if (ProjectivePoint::GENERATOR * *poly_point).to_affine() != target_share {
        return Err(TssError::InvalidShare);
    }

    let verifying_key = point_from_bytes(pubkey_package.verifying_key())?;
    let package = DklsPublicKeyPackage::new(verifying_key, verifying_shares, parameters.clone());
    let party = Party {
        parameters,
        party_index: target_index,
        session_id: session_id.to_vec(),
        poly_point: *poly_point,
        pk: verifying_key,
        zero_share: ZeroShare::initialize(Vec::new()),
        mul_senders: BTreeMap::new(),
        mul_receivers: BTreeMap::new(),
        derivation_data: DerivData {
            depth: 0,
            child_number: 0,
            parent_fingerprint: [0; 4],
            poly_point: *poly_point,
            pk: verifying_key,
            chain_code,
        },
        address: dkls23_secp256k1::compute_eth_address(&verifying_key),
    };

    keyshare::from_dkls_dkg(party, package)
}

fn validate_helpers(
    helpers: &[Identifier],
    target: Identifier,
    self_id: Identifier,
    parameters: &Parameters,
) -> Result<Vec<PartyIndex>, TssError> {
    if helpers.len() < usize::from(parameters.threshold) {
        return Err(TssError::InvalidConfig(
            "repair needs at least threshold helpers".into(),
        ));
    }
    if !helpers.contains(&self_id) {
        return Err(TssError::InvalidConfig(
            "helpers must include this party".into(),
        ));
    }
    if helpers.contains(&target) {
        return Err(TssError::InvalidConfig(
            "helpers must not include the target".into(),
        ));
    }

    let mut indices = Vec::with_capacity(helpers.len());
    for helper in helpers {
        let index = identifier_to_party_index(*helper)?;
        if index.as_u8() > parameters.share_count {
            return Err(TssError::InvalidIdentifier);
        }
        if indices.contains(&index) {
            return Err(TssError::InvalidConfig("helpers must be distinct".into()));
        }
        indices.push(index);
    }

    Ok(indices)
}

fn index_scalar(index: &PartyIndex) -> Scalar {
    Scalar::from(u64::from(index.as_u8()))
}

/// Lagrange coefficient of the node at position `i` of `xs` when
/// interpolating at `x_target` over all of `xs`.
pub(crate) fn lagrange_coefficient(
    xs: &[Scalar],
    i: usize,
    x_target: Scalar,
) -> Result<Scalar, TssError> {
    let x_i = xs
        .get(i)
        .ok_or_else(|| TssError::InvalidConfig("node position out of range".into()))?;
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for (j, x_j) in xs.iter().enumerate() {
        if j == i {
            continue;
        }
        numerator *= x_target - x_j;
        denominator *= x_i - x_j;
    }
    let inverse = Option::<Scalar>::from(denominator.invert())
        .ok_or_else(|| TssError::InvalidConfig("helpers must be distinct".into()))?;

    Ok(numerator * inverse)
}

fn dkls_shares_from_package(
    package: &PublicKeyPackage,
) -> Result<(Parameters, BTreeMap<PartyIndex, AffinePoint>), TssError> {
    let share_count = u8::try_from(package.verifying_shares().len()).map_err(|_| {
        TssError::InvalidConfig("public key package exceeds DKLs23 share limit".into())
    })?;
    let threshold = u8::try_from(package.min_signers())
        .map_err(|_| TssError::InvalidConfig("threshold exceeds DKLs23 limits".into()))?;
    let parameters = Parameters::new(threshold, share_count)
        .map_err(|_| TssError::InvalidConfig("invalid DKLs23 parameters".into()))?;

    let mut verifying_shares = BTreeMap::new();
    for index in 1..=share_count {
        let identifier = Identifier::new(u16::from(index))?;
        let share = package.verifying_share(identifier).ok_or_else(|| {
            TssError::InvalidConfig("verifying shares must cover every party 1..=n".into())
        })?;
        let party_index = PartyIndex::new(index).map_err(|_| TssError::InvalidIdentifier)?;
        verifying_shares.insert(party_index, point_from_bytes(share)?);
    }

    Ok((parameters, verifying_shares))
}

fn point_from_bytes(bytes: &[u8]) -> Result<AffinePoint, TssError> {
    k256::PublicKey::from_sec1_bytes(bytes)
        .map(|public_key| *public_key.as_affine())
        .map_err(|_| TssError::DeserializeFailed("invalid secp256k1 point encoding".into()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::message::Message;
    use crate::session::dkg::{DkgOutput, DkgSession};
    use crate::session::sign::SignSession;
    use crate::types::ThresholdConfig;

    fn id(value: u16) -> Identifier {
        Identifier::new(value).unwrap()
    }

    fn route(
        outputs: &BTreeMap<Identifier, Vec<Message>>,
        recipients: &[Identifier],
    ) -> BTreeMap<Identifier, Vec<Message>> {
        let mut routed: BTreeMap<Identifier, Vec<Message>> =
            recipients.iter().map(|&r| (r, Vec::new())).collect();
        for (&sender, messages) in outputs {
            for msg in messages {
                match msg.to {
                    Some(to) => routed.get_mut(&to).unwrap().push(msg.clone()),
                    None => {
                        for &r in recipients {
                            if r != sender {
                                routed.get_mut(&r).unwrap().push(msg.clone());
                            }
                        }
                    }
                }
            }
        }
        routed
    }

    fn run_dkg(threshold: u16, share_count: u16) -> BTreeMap<Identifier, KeyShareHandle> {
        let config = ThresholdConfig {
            min_signers: threshold,
            max_signers: share_count,
            suite: Ciphersuite::Secp256k1ECDSA,
        };
        let participants: Vec<Identifier> = (1..=share_count).map(id).collect();
        let mut sessions = BTreeMap::new();
        let mut outputs = BTreeMap::new();
        for &pid in &participants {
            let (session, messages) = DkgSession::new(&config, pid, Some(b"repair-dkg")).unwrap();
            sessions.insert(pid, session);
            outputs.insert(pid, messages);
        }

        let mut shares = BTreeMap::new();
        while shares.len() < participants.len() {
            let inputs = route(&outputs, &participants);
            outputs = BTreeMap::new();
            for &pid in &participants {
                match sessions
                    .get_mut(&pid)
                    .unwrap()
                    .next(inputs.get(&pid).unwrap())
                    .unwrap()
                {
                    DkgOutput::Continue(messages) => {
                        outputs.insert(pid, messages);
                    }
                    DkgOutput::Complete { key_share, .. } => {
                        shares.insert(pid, key_share);
                    }
                }
            }
        }
        shares
    }

    fn helper_terms(
        shares: &BTreeMap<Identifier, KeyShareHandle>,
        helpers: &[Identifier],
        target: Identifier,
        sid: &[u8],
    ) -> Vec<Zeroizing<Vec<u8>>> {
        helpers
            .iter()
            .map(|helper| repair_helper_term(&shares[helper], helpers, target, sid).unwrap())
            .collect()
    }

    fn assemble(
        shares: &BTreeMap<Identifier, KeyShareHandle>,
        target: Identifier,
        terms: &[Zeroizing<Vec<u8>>],
        chain_code: &[u8],
        sid: &[u8],
    ) -> Result<KeyShareHandle, TssError> {
        let reference = shares.values().next().unwrap();
        let term_slices: Vec<&[u8]> = terms.iter().map(|term| term.as_slice()).collect();
        repair_assemble(
            Ciphersuite::Secp256k1ECDSA,
            reference.public_key_package(),
            chain_code,
            target,
            &term_slices,
            sid,
        )
    }

    #[test]
    fn lagrange_coefficient_matches_direct_interpolation() {
        let coefficients = [Scalar::from(7u64), Scalar::from(3u64), Scalar::from(11u64)];
        let evaluate = |x: Scalar| coefficients[0] + coefficients[1] * x + coefficients[2] * x * x;
        let xs: Vec<Scalar> = [1u64, 3, 4].into_iter().map(Scalar::from).collect();
        let target = Scalar::from(2u64);

        let mut interpolated = Scalar::ZERO;
        for (i, &x_i) in xs.iter().enumerate() {
            interpolated += evaluate(x_i) * lagrange_coefficient(&xs, i, target).unwrap();
        }

        assert_eq!(interpolated, evaluate(target));
    }

    #[test]
    fn lagrange_coefficient_rejects_duplicate_nodes_and_bad_position() {
        let xs = [Scalar::from(1u64), Scalar::from(1u64)];
        assert!(matches!(
            lagrange_coefficient(&xs, 0, Scalar::from(2u64)),
            Err(TssError::InvalidConfig(_))
        ));
        assert!(matches!(
            lagrange_coefficient(&xs, 2, Scalar::from(2u64)),
            Err(TssError::InvalidConfig(_))
        ));
    }

    #[test]
    fn helper_term_validation() {
        let shares = run_dkg(3, 5);
        let share = &shares[&id(1)];
        let sid = b"repair-sid";

        let cases: Vec<(&str, Vec<Identifier>, Identifier, &[u8])> = vec![
            ("too few helpers", vec![id(1), id(3)], id(2), sid),
            ("missing self", vec![id(3), id(4), id(5)], id(2), sid),
            ("contains target", vec![id(1), id(2), id(3)], id(2), sid),
            ("duplicate helper", vec![id(1), id(1), id(3)], id(2), sid),
            ("empty sid", vec![id(1), id(3), id(4)], id(2), b""),
        ];
        for (name, helpers, target, sid) in cases {
            assert!(
                matches!(
                    repair_helper_term(share, &helpers, target, sid),
                    Err(TssError::InvalidConfig(_))
                ),
                "{name}"
            );
        }

        assert_eq!(
            repair_helper_term(share, &[id(1), id(3), id(6)], id(2), sid),
            Err(TssError::InvalidIdentifier)
        );
        assert_eq!(
            repair_helper_term(share, &[id(1), id(3), id(4)], id(6), sid),
            Err(TssError::InvalidIdentifier)
        );
    }

    #[test]
    fn helper_term_rejects_non_dkls_share() {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Ed25519,
        };
        let (frost_shares, pubkey) = crate::frost::frost_generate_with_dealer(&config).unwrap();
        let share =
            keyshare::from_frost_dkg(frost_shares.into_iter().next().unwrap(), &pubkey).unwrap();

        assert_eq!(
            repair_helper_term(&share, &[id(1), id(2)], id(3), b"sid"),
            Err(TssError::ProtocolMismatch)
        );
    }

    #[test]
    fn terms_are_masked_and_sum_to_share() {
        let shares = run_dkg(3, 5);
        let helpers = [id(1), id(3), id(4)];
        let target = id(2);
        let sid = b"repair-sid";
        let terms = helper_terms(&shares, &helpers, target, sid);

        let xs: Vec<Scalar> = helpers
            .iter()
            .map(|helper| Scalar::from(u64::from(helper.as_u16())))
            .collect();
        let target_x = Scalar::from(u64::from(target.as_u16()));
        let mut sum = Scalar::ZERO;
        for (position, (helper, term)) in helpers.iter().zip(&terms).enumerate() {
            let scalar = scalar_from_message(term).unwrap();
            let party = keyshare::clone_dkls_party(&shares[helper]).unwrap();
            let unmasked =
                party.poly_point * lagrange_coefficient(&xs, position, target_x).unwrap();
            assert_ne!(scalar, unmasked, "term from {helper} is not masked");
            sum += scalar;
        }

        let lost = keyshare::clone_dkls_party(&shares[&target]).unwrap();
        assert_eq!(sum, lost.poly_point);
    }

    #[test]
    fn assemble_rebuilds_the_lost_share() {
        let shares = run_dkg(3, 5);
        let helpers = [id(1), id(3), id(4)];
        let target = id(2);
        let sid = b"repair-sid";
        let chain_code = shares[&id(1)].chain_code().unwrap();
        let terms = helper_terms(&shares, &helpers, target, sid);

        let repaired = assemble(&shares, target, &terms, &chain_code, sid).unwrap();

        assert_eq!(repaired.identifier(), target);
        assert_eq!(
            repaired.verifying_share(),
            shares[&target].verifying_share()
        );
        assert_eq!(
            repaired.group_verifying_key(),
            shares[&target].group_verifying_key()
        );
        assert_eq!(repaired.chain_code().unwrap(), chain_code);
        let party = keyshare::clone_dkls_party(&repaired).unwrap();
        assert!(party.mul_senders.is_empty());
        assert!(party.zero_share.seeds.is_empty());
        assert_eq!(party.session_id, sid.to_vec());
    }

    #[test]
    fn assemble_rejects_bad_inputs() {
        let shares = run_dkg(3, 5);
        let helpers = [id(1), id(3), id(4)];
        let target = id(2);
        let sid = b"repair-sid";
        let chain_code = shares[&id(1)].chain_code().unwrap();
        let terms = helper_terms(&shares, &helpers, target, sid);

        let mut tampered = terms.clone();
        tampered[0][31] ^= 1;
        assert_eq!(
            assemble(&shares, target, &tampered, &chain_code, sid).unwrap_err(),
            TssError::InvalidShare
        );

        assert!(matches!(
            assemble(&shares, target, &terms[..2], &chain_code, sid),
            Err(TssError::InvalidConfig(_))
        ));

        assert!(matches!(
            assemble(&shares, target, &terms, &chain_code[..31], sid),
            Err(TssError::InvalidConfig(_))
        ));

        assert!(matches!(
            assemble(&shares, target, &terms, &chain_code, b""),
            Err(TssError::InvalidConfig(_))
        ));

        let mut mixed = terms.clone();
        mixed[2] = repair_helper_term(&shares[&id(4)], &helpers, target, b"other-sid").unwrap();
        assert_eq!(
            assemble(&shares, target, &mixed, &chain_code, sid).unwrap_err(),
            TssError::InvalidShare
        );

        assert_eq!(
            assemble(&shares, id(3), &terms, &chain_code, sid).unwrap_err(),
            TssError::InvalidShare
        );

        let mut wrong_set = helper_terms(&shares, &[id(1), id(3), id(5)], target, sid);
        wrong_set[2] = terms[2].clone();
        assert_eq!(
            assemble(&shares, target, &wrong_set, &chain_code, sid).unwrap_err(),
            TssError::InvalidShare
        );
    }

    #[test]
    fn hollow_share_cannot_sign_or_help() {
        let shares = run_dkg(3, 5);
        let helpers = [id(1), id(3), id(4)];
        let target = id(2);
        let sid = b"repair-sid";
        let chain_code = shares[&id(1)].chain_code().unwrap();
        let terms = helper_terms(&shares, &helpers, target, sid);
        let hollow = assemble(&shares, target, &terms, &chain_code, sid).unwrap();

        assert_eq!(
            SignSession::new_dkls(&hollow, b"sign".to_vec(), &[id(1), id(3)], [9u8; 32])
                .map(|_| ())
                .unwrap_err(),
            TssError::InvalidShare
        );
        assert_eq!(
            repair_helper_term(&hollow, &[id(2), id(3), id(4)], id(1), sid)
                .map(|_| ())
                .unwrap_err(),
            TssError::InvalidShare
        );
    }

    #[test]
    fn hollow_share_survives_export_import() {
        let shares = run_dkg(2, 3);
        let helpers = [id(1), id(3)];
        let target = id(2);
        let sid = b"repair-sid";
        let chain_code = shares[&id(1)].chain_code().unwrap();
        let terms = helper_terms(&shares, &helpers, target, sid);
        let hollow = assemble(&shares, target, &terms, &chain_code, sid).unwrap();

        let exported = hollow.export().unwrap();
        let imported = keyshare::import_key_share(&exported, Ciphersuite::Secp256k1ECDSA).unwrap();

        assert_eq!(imported.identifier(), target);
        assert_eq!(imported.verifying_share(), hollow.verifying_share());
    }
}
