use std::collections::BTreeMap;

use crate::SECURITY;
use dkls23::protocols::{
    dkg::{
        phase1, phase2, phase3, phase4, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4,
        KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4,
        ProofCommitment, SessionData, TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4,
        TransmitInitZeroSharePhase3to4, UniqueKeepDerivationPhase2to3,
    },
    Abort, Parameters, Party,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::Scalar;
use std::os::raw::c_uchar;

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

#[repr(C)]
pub struct CProofCommitment {
    index: c_uchar,
    proof: CDLogProof,
    commitment: [c_uchar; SECURITY as usize],
}

#[repr(C)]
pub struct CDLogProof {
    point: CAffinePoint,
    rand_commitments: *const CAffinePoint,
    rand_commitments_len: usize,
    proofs: *const CInteractiveDLogProof,
    proofs_len: usize,
}

#[repr(C)]
pub struct CAffinePoint {
    x: [u8; 32],
    y: [u8; 32],
    infinity: c_uchar,
}

#[repr(C)]
pub struct CInteractiveDLogProof {
    challenge: *const c_uchar,
    challenge_len: usize,
    challenge_response: Scalar,
}

#[repr(C)]
pub struct CKeepInitZeroSharePhase2to3 {
    seed: [c_uchar; SECURITY as usize],
    salt: *const c_uchar,
    salt_len: usize,
}

#[repr(C)]
pub struct CTransmitInitZeroSharePhase2to4 {
    parties: CPartiesMessage,
    commitment: [c_uchar; SECURITY as usize],
}

#[repr(C)]
pub struct CPartiesMessage {
    sender: c_uchar,
    receiver: c_uchar,
}

#[repr(C)]
pub struct CUniqueKeepDerivationPhase2to3 {
    aux_chain_code: [c_uchar; 32],
    cc_salt: *const c_uchar,
    cc_salt_len: usize,
}

#[repr(C)]
pub struct CBroadcastDerivationPhase2to4 {
    sender_index: c_uchar,
    cc_commitment: [c_uchar; SECURITY as usize],
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

#[no_mangle]
pub extern "C" fn dkls_dkg_phase_2(
    data: *const CSessionData,
    poly_fragments: *const Scalar,
    poly_fragments_len: usize,
    out_scalar: *mut Scalar,
    out_proof_commitment: *mut CProofCommitment,
    out_zero_shares: *mut *mut CKeepInitZeroSharePhase2to3,
    out_zero_shares_len: *mut usize,
    out_transmit_zero_shares: *mut *mut CTransmitInitZeroSharePhase2to4,
    out_transmit_zero_shares_len: *mut usize,
    out_unique_keep: *mut CUniqueKeepDerivationPhase2to3,
    out_broadcast: *mut CBroadcastDerivationPhase2to4,
) {
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

    let poly_fragments = unsafe { std::slice::from_raw_parts(poly_fragments, poly_fragments_len) };

    let (scalar, proof_commitment, zero_shares, transmit_zero_shares, unique_keep, broadcast) =
        phase2(&session_data, poly_fragments);

    unsafe {
        *out_scalar = scalar;

        let point = proof_commitment.proof.point.to_encoded_point(false);
        let x = point.x().unwrap().as_slice();
        let y = point.y().unwrap().as_slice();
        let infinity = if point.is_identity().into() { 1 } else { 0 };

        *out_proof_commitment = CProofCommitment {
            index: proof_commitment.index,
            proof: CDLogProof {
                point: CAffinePoint {
                    x: x.try_into().expect("slice with incorrect length"),
                    y: y.try_into().expect("slice with incorrect length"),
                    infinity,
                },
                rand_commitments: proof_commitment.proof.rand_commitments.as_ptr()
                    as *const CAffinePoint,
                rand_commitments_len: proof_commitment.proof.rand_commitments.len(),
                proofs: proof_commitment.proof.proofs.as_ptr() as *const CInteractiveDLogProof,
                proofs_len: proof_commitment.proof.proofs.len(),
            },
            commitment: proof_commitment.commitment,
        };

        let zero_shares_vec: Vec<CKeepInitZeroSharePhase2to3> = zero_shares
            .into_iter()
            .map(|(_, v)| CKeepInitZeroSharePhase2to3 {
                seed: v.seed,
                salt: v.salt.as_ptr(),
                salt_len: v.salt.len(),
            })
            .collect();
        *out_zero_shares_len = zero_shares_vec.len();
        *out_zero_shares = zero_shares_vec.into_boxed_slice().as_mut_ptr();

        let transmit_zero_shares_vec: Vec<CTransmitInitZeroSharePhase2to4> = transmit_zero_shares
            .into_iter()
            .map(|v| CTransmitInitZeroSharePhase2to4 {
                parties: CPartiesMessage {
                    sender: v.parties.sender,
                    receiver: v.parties.receiver,
                },
                commitment: v.commitment,
            })
            .collect();
        *out_transmit_zero_shares_len = transmit_zero_shares_vec.len();
        *out_transmit_zero_shares = transmit_zero_shares_vec.into_boxed_slice().as_mut_ptr();

        *out_unique_keep = CUniqueKeepDerivationPhase2to3 {
            aux_chain_code: unique_keep.aux_chain_code,
            cc_salt: unique_keep.cc_salt.as_ptr(),
            cc_salt_len: unique_keep.cc_salt.len(),
        };

        *out_broadcast = CBroadcastDerivationPhase2to4 {
            sender_index: broadcast.sender_index,
            cc_commitment: broadcast.cc_commitment,
        };
    }
}
