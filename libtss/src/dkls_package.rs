//! Conversion of a unified public key package into a DKLs23 one.

use dkls23_secp256k1::curve::DklsCurve;
use dkls23_secp256k1::protocols::{Parameters, PartyIndex, PublicKeyPackage};
use k256::elliptic_curve::ff::{Field, PrimeField};
use k256::elliptic_curve::group::CurveAffine;
use k256::elliptic_curve::group::{Group, GroupEncoding};
use sha2::{Digest, Sha256};

use crate::types::PublicKeyPackage as UnifiedPublicKeyPackage;
use crate::TssError;

fn point<C: DklsCurve>(bytes: &[u8]) -> Result<C::AffinePoint, TssError> {
    let invalid = || TssError::DeserializeFailed("invalid public key package point".into());
    let mut repr = <C::AffinePoint as GroupEncoding>::Repr::default();
    if bytes.len() != repr.as_ref().len() {
        return Err(invalid());
    }
    repr.as_mut().copy_from_slice(bytes);
    let point: C::AffinePoint =
        Option::from(C::AffinePoint::from_bytes(&repr)).ok_or_else(invalid)?;
    if bool::from(point.to_curve().is_identity()) {
        return Err(invalid());
    }
    Ok(point)
}

/// Whether the group key (at x = 0) and the verifying shares (at x = 1..=n)
/// lie on one polynomial of degree below `threshold`.
///
/// Points `P_i` at distinct `x_i` lie on such a polynomial if and only if
/// `sum_i c_i f(x_i) P_i = 0` for every polynomial `f` of degree below
/// `m - threshold`, where `m` is the number of points and
/// `c_i = prod_{j != i} (x_i - x_j)^-1`. The sum is linear in the
/// coefficients of `f`; for a wrong package at least one coefficient
/// multiplies a non-identity point, so one `f` with 128-bit coefficients
/// hashed from the package lets it pass with probability about `2^-128` per
/// check (per hash query when the hash is modeled as a random oracle).
fn on_one_polynomial<C: DklsCurve>(
    verifying_key: C::AffinePoint,
    verifying_shares: &[C::AffinePoint],
    threshold: usize,
) -> bool {
    let points: Vec<C::AffinePoint> = core::iter::once(verifying_key)
        .chain(verifying_shares.iter().copied())
        .collect();
    let m = points.len();
    if threshold == 0 || m <= threshold {
        return false;
    }
    let mut transcript = Sha256::new();
    transcript.update(b"libtss/package-consistency/v1");
    transcript.update((threshold as u64).to_le_bytes());
    for point in &points {
        transcript.update(point.to_bytes());
    }
    let transcript = transcript.finalize();
    let coefficients: Vec<C::Scalar> = (0..m - threshold)
        .map(|k| {
            let digest = Sha256::new()
                .chain_update(transcript)
                .chain_update((k as u64).to_le_bytes())
                .finalize();
            let mut low = [0u8; 16];
            low.copy_from_slice(&digest[..16]);
            C::Scalar::from_u128(u128::from_le_bytes(low))
        })
        .collect();
    let x = |i: usize| C::Scalar::from(i as u64);
    let mut sum = C::ProjectivePoint::identity();
    for (i, point) in points.iter().enumerate() {
        let mut denominator = C::Scalar::ONE;
        for j in (0..m).filter(|&j| j != i) {
            denominator *= x(i) - x(j);
        }
        let Some(c) = Option::<C::Scalar>::from(denominator.invert()) else {
            return false;
        };
        // f(x_i) by Horner's rule.
        let f = coefficients
            .iter()
            .rev()
            .fold(C::Scalar::ZERO, |acc, a| acc * x(i) + a);
        sum += point.to_curve() * (c * f);
    }
    bool::from(sum.is_identity())
}

/// The DKLs23 package for a unified package of a DKLs23 suite. The verifying
/// shares must be indexed `1..=n`, be valid non-identity points, and lie with
/// the group key on one polynomial of degree below `min_signers`.
pub(crate) fn to_dkls_package<C: DklsCurve>(
    package: &UnifiedPublicKeyPackage,
) -> Result<PublicKeyPackage<C>, TssError> {
    let threshold = u8::try_from(package.min_signers())
        .map_err(|_| TssError::InvalidConfig("threshold exceeds DKLs23 limits".into()))?;
    let share_count = u8::try_from(package.verifying_shares().len())
        .map_err(|_| TssError::InvalidConfig("share count exceeds DKLs23 limits".into()))?;
    let parameters = Parameters::new(threshold, share_count)
        .map_err(|_| TssError::InvalidConfig("invalid DKLs23 parameters".into()))?;
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
    let verifying_shares = package
        .verifying_shares()
        .iter()
        .map(|(id, share)| {
            let index = u8::try_from(id.as_u16())
                .ok()
                .and_then(|i| PartyIndex::new(i).ok())
                .ok_or(TssError::InvalidIdentifier)?;
            Ok((index, point::<C>(share)?))
        })
        .collect::<Result<Vec<_>, TssError>>()?;
    let verifying_key = point::<C>(package.verifying_key())?;
    let shares: Vec<C::AffinePoint> = verifying_shares.iter().map(|(_, share)| *share).collect();
    if !on_one_polynomial::<C>(verifying_key, &shares, usize::from(package.min_signers())) {
        return Err(TssError::InvalidShare);
    }
    Ok(PublicKeyPackage::new(
        verifying_key,
        verifying_shares.into_iter().collect(),
        parameters,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ciphersuite, ThresholdConfig};

    fn package() -> UnifiedPublicKeyPackage {
        let config = ThresholdConfig {
            min_signers: 2,
            max_signers: 3,
            suite: Ciphersuite::Secp256k1ECDSA,
        };
        crate::dkls_import::dkls_split_key(&config, &[0x42; 32], None)
            .unwrap()
            .1
    }

    fn with_min_signers(package: &UnifiedPublicKeyPackage, min: u16) -> UnifiedPublicKeyPackage {
        UnifiedPublicKeyPackage::new(
            package.suite(),
            package.verifying_key().to_vec(),
            package.verifying_shares().clone(),
            min,
        )
    }

    #[test]
    fn accepts_a_consistent_package() {
        assert!(to_dkls_package::<k256::Secp256k1>(&package()).is_ok());
    }

    #[test]
    fn rejects_bad_thresholds_as_config_errors() {
        let package = package();
        for min in [0, 1, 4, 300] {
            assert!(
                matches!(
                    to_dkls_package::<k256::Secp256k1>(&with_min_signers(&package, min)),
                    Err(TssError::InvalidConfig(_))
                ),
                "min_signers {min}"
            );
        }
    }

    #[test]
    fn rejects_a_package_off_the_polynomial() {
        let package = package();
        // Three points always lie on a polynomial of degree below 3.
        assert!(to_dkls_package::<k256::Secp256k1>(&with_min_signers(&package, 3)).is_ok());
        let mut shares = package.verifying_shares().clone();
        let first = shares.keys().next().copied().unwrap();
        let last = shares.keys().last().copied().unwrap();
        let swapped = shares[&last].clone();
        shares.insert(first, swapped);
        let broken = UnifiedPublicKeyPackage::new(
            package.suite(),
            package.verifying_key().to_vec(),
            shares,
            2,
        );
        assert_eq!(
            to_dkls_package::<k256::Secp256k1>(&broken).err(),
            Some(TssError::InvalidShare)
        );
    }
}
