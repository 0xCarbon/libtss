use dkls23::protocols::dkg;
use crate::dkls23::utilities::c_types::{
    CSessionData, CScalarVec,
    CProofCommitment,
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

    //println!("{:?}", poly_fragments[0]);
    //println!("{:?}", poly_fragments[1]);

    let (
        poly_point,
        proof_commitment,
        zero_keep,
        zero_transmit,
        bip_keep,
        bip_broadcast,
    ) = dkg::phase2(&session_data, poly_fragments.as_slice());

    //println!("{:?}", to_c_scalar(&poly_point));

    //let point = proof_commitment.proof.point;
    //println!("{:?}", point);

    //let c_point = to_c_affine_point(&point);
    //println!("{:?}", c_point);

    //let affine_point = from_c_affine_point(&c_point);
    //println!("{:?}", affine_point);

    let r = CProofCommitment::from(&proof_commitment);
    //let r = to_c_rand_commitments(proof_commitment.proof.rand_commitments);
    //println!("{:?}", r);

    // write tests for:
    // to_c_rand_commitments
    // to_c_interactive_proof
    // to_c_proofs_vec
    // to_c_dlog_proof
    // to_c_proof_commitment
}
