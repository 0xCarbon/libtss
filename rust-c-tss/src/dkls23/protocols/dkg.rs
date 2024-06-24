use dkls23::protocols::dkg;

use crate::dkls23::utilities::{
    convertions::{
        to_inner_session_data, scalar_vec_to_c_scalar_vec,
    },
    c_types::{
        CSessionData, CScalar, CPhase2Out
    },
    //logs::{
    //    print_session_data,
    //},
};

#[no_mangle]
pub extern "C" fn dkls_phase1(session: &CSessionData) -> *const CScalar {
    let session_data = to_inner_session_data(session);
    let scalars: Vec<k256::Scalar> = dkg::phase1(&session_data);

    //println!("session_id bytes: {:?}", session_data.session_id);
    //print_session_data(session);
    //println!("{:?}", scalars);

    scalar_vec_to_c_scalar_vec(&scalars)
}

#[no_mangle]
pub extern "C" fn dkls_phase2(
    session: &CSessionData,
    poly_fragments: *const CScalar
) -> *const CPhase2Out {
    let session_data = to_inner_session_data(session);
    //dkg::phase2(&session_data, poly_fragments);
}
