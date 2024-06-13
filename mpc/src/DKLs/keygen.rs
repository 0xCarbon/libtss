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
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::point::AffineCoordinates;
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

#[repr(C)]
pub struct CKeepInitZeroSharePhase3to4 {
    seed: [c_uchar; SECURITY as usize],
}

#[repr(C)]
pub struct CTransmitInitZeroSharePhase3to4 {
    parties: CPartiesMessage,
    seed: [c_uchar; SECURITY as usize],
    salt: *const c_uchar,
    salt_len: usize,
}

#[repr(C)]
pub struct CKeepInitMulPhase3to4 {
    ot_sender: COTSender,
    nonce: Scalar,
    ot_receiver: COTReceiver,
    correlation: *const c_uchar,
    correlation_len: usize,
    vec_r: *const Scalar,
    vec_r_len: usize,
}

#[repr(C)]
pub struct CBroadcastDerivationPhase3to4 {
    sender_index: c_uchar,
    aux_chain_code: [c_uchar; 32],
    cc_salt: *const c_uchar,
    cc_salt_len: usize,
}

#[repr(C)]
pub struct CEncProof {
    proof0: CCPProof,
    proof1: CCPProof,
    commitments0: CRandomCommitments,
    commitments1: CRandomCommitments,
    challenge0: Scalar,
    challenge1: Scalar,
}

#[repr(C)]
pub struct CCPProof {
    base_g: CAffinePoint,
    base_h: CAffinePoint,
    point_u: CAffinePoint,
    point_v: CAffinePoint,
    challenge_response: Scalar,
}

#[repr(C)]
pub struct CRandomCommitments {
    rc_g: CAffinePoint,
    rc_h: CAffinePoint,
}

#[repr(C)]
pub struct CTransmitInitMulPhase3to4 {
    parties: CPartiesMessage,
    dlog_proof: CDLogProof,
    nonce: Scalar,
    enc_proofs: *const CEncProof,
    enc_proofs_len: usize,
    seed: [c_uchar; SECURITY as usize],
}

#[repr(C)]
pub struct COTSender {
    s: Scalar,
    proof: CDLogProof,
}

#[repr(C)]
pub struct COTReceiver {
    seed: [c_uchar; SECURITY as usize],
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
    let boxed_slice = result.into_boxed_slice();
    let ptr = Box::into_raw(boxed_slice);
    ptr as *mut Scalar
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

#[no_mangle]
pub extern "C" fn dkls_dkg_phase_3(
    data: *const CSessionData,
    zero_kept: *const CKeepInitZeroSharePhase2to3,
    zero_kept_len: usize,
    bip_kept: *const CUniqueKeepDerivationPhase2to3,
    out_zero_shares: *mut *mut CKeepInitZeroSharePhase3to4,
    out_zero_shares_len: *mut usize,
    out_transmit_zero_shares: *mut *mut CTransmitInitZeroSharePhase3to4,
    out_transmit_zero_shares_len: *mut usize,
    out_keep_mul: *mut *mut CKeepInitMulPhase3to4,
    out_keep_mul_len: *mut usize,
    out_transmit_mul: *mut *mut CTransmitInitMulPhase3to4,
    out_transmit_mul_len: *mut usize,
    out_broadcast: *mut CBroadcastDerivationPhase3to4,
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

    let zero_kept = unsafe { std::slice::from_raw_parts(zero_kept, zero_kept_len) };
    let bip_kept = unsafe { &*bip_kept };

    let zero_kept_map: BTreeMap<u8, KeepInitZeroSharePhase2to3> = zero_kept
        .iter()
        .enumerate()
        .map(|(i, v)| {
            (
                i as u8,
                KeepInitZeroSharePhase2to3 {
                    seed: v.seed,
                    salt: unsafe { std::slice::from_raw_parts(v.salt, v.salt_len).to_vec() },
                },
            )
        })
        .collect();

    let bip_kept_rust = UniqueKeepDerivationPhase2to3 {
        aux_chain_code: bip_kept.aux_chain_code,
        cc_salt: unsafe {
            std::slice::from_raw_parts(bip_kept.cc_salt, bip_kept.cc_salt_len).to_vec()
        },
    };

    let (zero_shares, transmit_zero_shares, keep_mul, transmit_mul, broadcast) =
        phase3(&session_data, &zero_kept_map, &bip_kept_rust);

    unsafe {
        let zero_shares_vec: Vec<CKeepInitZeroSharePhase3to4> = zero_shares
            .into_iter()
            .map(|(_, v)| CKeepInitZeroSharePhase3to4 { seed: v.seed })
            .collect();
        *out_zero_shares_len = zero_shares_vec.len();
        *out_zero_shares = zero_shares_vec.into_boxed_slice().as_mut_ptr();

        let transmit_zero_shares_vec: Vec<CTransmitInitZeroSharePhase3to4> = transmit_zero_shares
            .into_iter()
            .map(|v| CTransmitInitZeroSharePhase3to4 {
                parties: CPartiesMessage {
                    sender: v.parties.sender,
                    receiver: v.parties.receiver,
                },
                seed: v.seed,
                salt: v.salt.as_ptr(),
                salt_len: v.salt.len(),
            })
            .collect();
        *out_transmit_zero_shares_len = transmit_zero_shares_vec.len();
        *out_transmit_zero_shares = transmit_zero_shares_vec.into_boxed_slice().as_mut_ptr();

        let keep_mul_vec: Vec<CKeepInitMulPhase3to4> = keep_mul
            .into_iter()
            .map(|(_, v)| CKeepInitMulPhase3to4 {
                ot_sender: COTSender {
                    s: v.ot_sender.s,
                    proof: CDLogProof {
                        point: {
                            let point = v.ot_sender.proof.point.to_encoded_point(false);
                            let x_slice = point.x().unwrap();
                            let y_slice = point.y().unwrap();
                            let mut x = [0u8; 32];
                            let mut y = [0u8; 32];
                            x.copy_from_slice(x_slice);
                            y.copy_from_slice(y_slice);
                            CAffinePoint {
                                x,
                                y,
                                infinity: if point.is_identity().into() { 1 } else { 0 },
                            }
                        },
                        rand_commitments: v.ot_sender.proof.rand_commitments.as_ptr()
                            as *const CAffinePoint,
                        rand_commitments_len: v.ot_sender.proof.rand_commitments.len(),
                        proofs: v.ot_sender.proof.proofs.as_ptr() as *const CInteractiveDLogProof,
                        proofs_len: v.ot_sender.proof.proofs.len(),
                    },
                },
                nonce: v.nonce,
                ot_receiver: COTReceiver {
                    seed: v.ot_receiver.seed,
                },
                correlation: v.correlation.as_ptr() as *const c_uchar,
                correlation_len: v.correlation.len(),
                vec_r: v.vec_r.as_ptr(),
                vec_r_len: v.vec_r.len(),
            })
            .collect();
        *out_keep_mul_len = keep_mul_vec.len();
        *out_keep_mul = keep_mul_vec.into_boxed_slice().as_mut_ptr();

        let transmit_mul_vec: Vec<CTransmitInitMulPhase3to4> = transmit_mul
            .into_iter()
            .map(|v| CTransmitInitMulPhase3to4 {
                parties: CPartiesMessage {
                    sender: v.parties.sender,
                    receiver: v.parties.receiver,
                },
                dlog_proof: CDLogProof {
                    point: {
                        let point = v.dlog_proof.point.to_encoded_point(false);
                        let x_slice = point.x().unwrap();
                        let y_slice = point.y().unwrap();
                        let mut x = [0u8; 32];
                        let mut y = [0u8; 32];
                        x.copy_from_slice(x_slice);
                        y.copy_from_slice(y_slice);
                        CAffinePoint {
                            x,
                            y,
                            infinity: if point.is_identity().into() { 1 } else { 0 },
                        }
                    },
                    rand_commitments: v.dlog_proof.rand_commitments.as_ptr() as *const CAffinePoint,
                    rand_commitments_len: v.dlog_proof.rand_commitments.len(),
                    proofs: v.dlog_proof.proofs.as_ptr() as *const CInteractiveDLogProof,
                    proofs_len: v.dlog_proof.proofs.len(),
                },
                nonce: v.nonce,
                enc_proofs: v.enc_proofs.as_ptr() as *const CEncProof,
                enc_proofs_len: v.enc_proofs.len(),
                seed: v.seed,
            })
            .collect();
        *out_transmit_mul_len = transmit_mul_vec.len();
        *out_transmit_mul = transmit_mul_vec.into_boxed_slice().as_mut_ptr();

        *out_broadcast = CBroadcastDerivationPhase3to4 {
            sender_index: broadcast.sender_index,
            aux_chain_code: broadcast.aux_chain_code,
            cc_salt: broadcast.cc_salt.as_ptr(),
            cc_salt_len: broadcast.cc_salt.len(),
        };
    }
}
