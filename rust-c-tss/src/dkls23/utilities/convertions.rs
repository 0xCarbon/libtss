use dkls23::protocols::{
    dkg::SessionData,
    Parameters,
};
use k256::Scalar;

use crate::dkls23::utilities::c_types::{
     CSessionData, CScalar,
};

pub fn to_inner_session_data(session: &CSessionData) -> SessionData {
    let session_id_slice = unsafe {
        std::slice::from_raw_parts(session.session_id, session.session_id_len)
    };

    SessionData {
        party_index: session.party_index,
        parameters: Parameters {
            threshold: session.parameters.threshold,
            share_count: session.parameters.share_count,
        },
        session_id: Vec::from(session_id_slice),
    }
}

pub fn scalar_vec_to_c_scalar_vec(scalars: &Vec<Scalar>) -> *const CScalar {
    let mut out: Vec<CScalar> = Vec::new();
    for scalar in scalars.iter() {
        out.push(scalar_to_c_scalar(&scalar));
    }
    Box::into_raw(out.into_boxed_slice()) as *const CScalar
}

pub fn c_scalar_vec_to_scalar_vec(scalars: *const CScalar) -> &[Scalar] {

}

fn scalar_to_c_scalar(scalar: &Scalar) -> CScalar {
    let mut c_scalar: CScalar = [0; 32];
    c_scalar.copy_from_slice(&scalar.to_bytes());
    c_scalar
}
