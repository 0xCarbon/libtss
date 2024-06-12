use std::collections::BTreeMap;

use dkls23::protocols::{
    dkg::{
        phase1, phase2, phase3, phase4, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4,
        KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4,
        ProofCommitment, SessionData, TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4,
        TransmitInitZeroSharePhase3to4, UniqueKeepDerivationPhase2to3,
    },
    Abort, Parameters, Party,
};
use k256::Scalar;
use std::ffi::CStr;
use std::os::raw::{c_char, c_uchar, c_void};

#[repr(C)]
pub struct CSessionData {
    parameters: CParameters,
    party_index: c_uchar,
    session_id: *const c_uchar,
    session_id_len: usize,
}

#[repr(C)]
pub struct CParameters {
    threshold: c_uchar,
    share_count: c_uchar,
}

#[no_mangle]
pub extern "C" fn dkls_dkg_phase_1(data: *const CSessionData) -> *mut Scalar {
    let data = unsafe { &*data };
    let session_data = SessionData {
        parameters: Parameters {
            threshold: data.parameters.threshold,
            share_count: data.parameters.share_count,
        },
        party_index: data.party_index,
        session_id: unsafe {
            std::slice::from_raw_parts(data.session_id, data.session_id_len).to_vec()
        },
    };
    let result = phase1(&session_data);
    let boxed_result = result.into_boxed_slice();
    Box::into_raw(boxed_result) as *mut Scalar
}
