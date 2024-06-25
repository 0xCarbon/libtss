use dkls23::protocols::dkg;
use crate::dkls23::utilities::c_types::{
    CSessionData, CScalarVec,
};

#[no_mangle]
pub extern "C" fn dkls_phase1(session: &CSessionData) -> CScalarVec {
    let session_data = CSessionData::to_session(session);
    let scalars: Vec<k256::Scalar> = dkg::phase1(&session_data);

    CScalarVec::from(&scalars)
}

#[no_mangle]
pub extern "C" fn dkls_phase2(
    session: &CSessionData,
    c_poly_fragments: &CScalarVec
) {
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
}
