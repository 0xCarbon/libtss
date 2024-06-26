use crate::dkls23::utilities::c_types::{
    CBroadcastDerivationPhase2to4, CPhase2Out, CProofCommitment, CScalar,
    CScalarVec, CSessionData, CTransmitInitZeroSharePhase2to4Vec,
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
    // let zero_keep = BTreeMap
    let c_zero_transmit_vec =
        CTransmitInitZeroSharePhase2to4Vec::from(&zero_transmit);
    let c_bip_keep = CUniqueKeepDerivationPhase2to3::from(&bip_keep);
    let c_bip_broadcast = CBroadcastDerivationPhase2to4::from(&bip_broadcast);

    CPhase2Out {
        poly_point: c_poly_point,
        proof_commitment: c_proof_commitment,
        zero_transmit: c_zero_transmit_vec,
        bip_keep: c_bip_keep,
        bip_broadcast: c_bip_broadcast,
    }
}
