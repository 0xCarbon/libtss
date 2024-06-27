use crate::dkls23::utilities::c_types::{
    CBTreeMap, CBroadcastDerivationPhase2to4, CBroadcastDerivationPhase3to4,
    CKeepInitMulPhase3to4, CKeepInitZeroSharePhase2to3,
    CKeepInitZeroSharePhase3to4, CPhase2Out, CPhase3Out, CProofCommitment,
    CScalar, CScalarVec, CSessionData, CTransmitInitMulPhase3to4Vec,
    CTransmitInitZeroSharePhase2to4Vec, CTransmitInitZeroSharePhase3to4Vec,
    CUniqueKeepDerivationPhase2to3,
};
use dkls23::protocols::dkg;

#[no_mangle]
pub extern "C" fn dkls_phase1(session: &CSessionData) -> CScalarVec {
    let session_data = CSessionData::to_session(session);
    let scalars: Vec<k256::Scalar> = dkg::phase1(&session_data);

    CScalarVec::from(&scalars)
}

#[no_mangle]
pub extern "C" fn dkls_phase2(
    session: &CSessionData,
    c_poly_fragments: &CScalarVec,
) -> CPhase2Out {
    let session_data = CSessionData::to_session(session);
    let poly_fragments = c_poly_fragments.to_vec();

    let (
        poly_point,
        proof_commitment,
        zero_keep,
        zero_transmit,
        bip_keep,
        bip_broadcast,
    ) = dkg::phase2(&session_data, poly_fragments.as_slice());

    let c_poly_point = CScalar::from(&poly_point);
    let c_proof_commitment = CProofCommitment::from(&proof_commitment);
    let c_zero_keep: CBTreeMap<CKeepInitZeroSharePhase2to3> =
        CBTreeMap::from(&zero_keep);
    let c_zero_transmit_vec =
        CTransmitInitZeroSharePhase2to4Vec::from(&zero_transmit);
    let c_bip_keep = CUniqueKeepDerivationPhase2to3::from(&bip_keep);
    let c_bip_broadcast = CBroadcastDerivationPhase2to4::from(&bip_broadcast);

    CPhase2Out {
        poly_point: c_poly_point,
        proof_commitment: c_proof_commitment,
        zero_keep: c_zero_keep,
        zero_transmit: c_zero_transmit_vec,
        bip_keep: c_bip_keep,
        bip_broadcast: c_bip_broadcast,
    }
}

#[no_mangle]
pub extern "C" fn dkls_phase3(
    c_session: &CSessionData,
    c_zero_kept: &CBTreeMap<CKeepInitZeroSharePhase2to3>,
    c_bip_kept: &CUniqueKeepDerivationPhase2to3,
) -> CPhase3Out {
    let session = c_session.to_session();
    let zero_kept = c_zero_kept.to_inner();
    let bip_kept = c_bip_kept.to_inner();

    let (zero_keep, zero_transmit, mul_keep, mul_transmit, bip_broadcast) =
        dkg::phase3(&session, &zero_kept, &bip_kept);
    let c_zero_keep: CBTreeMap<CKeepInitZeroSharePhase3to4> =
        CBTreeMap::from(&zero_keep);
    let c_zero_transmit =
        CTransmitInitZeroSharePhase3to4Vec::from(&zero_transmit);
    let c_mul_keep: CBTreeMap<CKeepInitMulPhase3to4> =
        CBTreeMap::from(&mul_keep);
    let c_mul_transmit = CTransmitInitMulPhase3to4Vec::from(&mul_transmit);
    let c_bip_broadcast = CBroadcastDerivationPhase3to4::from(&bip_broadcast);

    CPhase3Out {
        zero_keep: c_zero_keep,
        zero_transmit: c_zero_transmit,
        mul_keep: c_mul_keep,
        mul_transmit: c_mul_transmit,
        bip_broadcast: c_bip_broadcast,
    }
}
