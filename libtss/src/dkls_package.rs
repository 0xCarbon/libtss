//! Conversion of a unified public key package into a DKLs23 one.

use dkls23_secp256k1::curve::DklsCurve;
use dkls23_secp256k1::protocols::{Parameters, PartyIndex, PublicKeyPackage};
use k256::elliptic_curve::group::GroupEncoding;

use crate::types::PublicKeyPackage as UnifiedPublicKeyPackage;
use crate::TssError;

fn point<C: DklsCurve>(bytes: &[u8]) -> Result<C::AffinePoint, TssError> {
    let invalid = || TssError::DeserializeFailed("invalid public key package point".into());
    let mut repr = <C::AffinePoint as GroupEncoding>::Repr::default();
    if bytes.len() != repr.as_ref().len() {
        return Err(invalid());
    }
    repr.as_mut().copy_from_slice(bytes);
    Option::from(C::AffinePoint::from_bytes(&repr)).ok_or_else(invalid)
}

/// The DKLs23 package for a unified package of a DKLs23 suite. The verifying
/// shares must be indexed `1..=n`.
pub(crate) fn to_dkls_package<C: DklsCurve>(
    package: &UnifiedPublicKeyPackage,
) -> Result<PublicKeyPackage<C>, TssError> {
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
        .collect::<Result<_, TssError>>()?;
    let threshold = u8::try_from(package.min_signers())
        .map_err(|_| TssError::InvalidConfig("threshold exceeds DKLs23 limits".into()))?;
    let share_count = u8::try_from(package.verifying_shares().len())
        .map_err(|_| TssError::InvalidConfig("share count exceeds DKLs23 limits".into()))?;
    let parameters = Parameters::new(threshold, share_count)
        .map_err(|_| TssError::InvalidConfig("invalid DKLs23 parameters".into()))?;
    Ok(PublicKeyPackage::new(
        point::<C>(package.verifying_key())?,
        verifying_shares,
        parameters,
    ))
}
