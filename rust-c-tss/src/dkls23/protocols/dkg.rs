use dkls23::protocols::dkg;
use crate::dkls23::utilities::{
    convertions::{
        from_c_session_data, to_c_scalar_vec, from_c_scalar_vec,
        to_c_scalar, to_c_affine_point, from_c_affine_point,
        to_c_rand_commitments,
    },
    c_types::{
        CSessionData, CScalarVec, CPhase2Out, CAffinePoint,
    },
};

#[no_mangle]
pub extern "C" fn dkls_phase1(session: &CSessionData) -> CScalarVec {
    let session_data = from_c_session_data(session);
    let scalars: Vec<k256::Scalar> = dkg::phase1(&session_data);

    to_c_scalar_vec(&scalars)
}

#[no_mangle]
pub extern "C" fn dkls_phase2(
    session: &CSessionData,
    c_poly_fragments: &CScalarVec
) {
    let session_data = from_c_session_data(session);
    let poly_fragments = from_c_scalar_vec(c_poly_fragments);

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

    let r = to_c_rand_commitments(proof_commitment.proof.rand_commitments);
    println!("{:?}", r);
}
