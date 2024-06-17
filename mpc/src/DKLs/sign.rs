use dkls23::{
    protocols::{
        signing::{
            KeepPhase1to2, KeepPhase2to3, SignData, TransmitPhase1to2, TransmitPhase2to3,
            UniqueKeep1to2, UniqueKeep2to3,
        },
        Abort, PartiesMessage, Party,
    },
    utilities::{
        multiplication::MulDataToKeepReceiver,
        ot::extension::{OTEDataToSender, EXTENDED_BATCH_SIZE},
    },
};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use std::{
    collections::BTreeMap,
    os::raw::{c_uchar, c_void},
};

use crate::SECURITY;

use super::keygen::{CAffinePoint, CPartiesMessage};

#[repr(C)]
pub struct CSignData {
    sign_id: *const c_uchar,
    sign_id_len: usize,
    counterparties: *const c_uchar,
    counterparties_len: usize,
    message_hash: [c_uchar; SECURITY as usize],
}

#[repr(C)]
pub struct CUniqueKeep1to2 {
    instance_key: Scalar,
    instance_point: CAffinePoint,
    inversion_mask: Scalar,
    zeta: Scalar,
}

#[repr(C)]
pub struct CKeepPhase1to2 {
    salt: *const c_uchar,
    salt_len: usize,
    chi: Scalar,
    mul_keep: CMulDataToKeepReceiver,
}

#[repr(C)]
pub struct CTransmitPhase1to2 {
    parties: CPartiesMessage,
    commitment: [c_uchar; SECURITY as usize],
    mul_transmit: COTEDataToSender,
}

#[repr(C)]
pub struct CMulDataToKeepReceiver {
    b: Scalar,
    choice_bits: *const c_uchar,
    choice_bits_len: usize,
    extended_seeds: *const CPRGOutput,
    extended_seeds_len: usize,
    chi_tilde: *const Scalar,
    chi_tilde_len: usize,
    chi_hat: *const Scalar,
    chi_hat_len: usize,
}

#[repr(C)]
pub struct CPRGOutput {
    data: [c_uchar; (EXTENDED_BATCH_SIZE / 8) as usize],
}

#[repr(C)]
pub struct COTEDataToSender {
    u: *const CPRGOutput,
    u_len: usize,
    verify_x: Scalar,
    verify_t: *const Scalar,
    verify_t_len: usize,
}

#[repr(C)]
pub struct CUniqueKeep2to3 {
    instance_key: Scalar,
    instance_point: CAffinePoint,
    inversion_mask: Scalar,
    key_share: Scalar,
    public_share: CAffinePoint,
}

#[repr(C)]
pub struct CKeepPhase2to3 {
    c_u: Scalar,
    c_v: Scalar,
    commitment: [c_uchar; SECURITY as usize],
    mul_keep: CMulDataToKeepReceiver,
    chi: Scalar,
}

#[repr(C)]
pub struct CTransmitPhase2to3 {
    parties: CPartiesMessage,
    gamma_u: CAffinePoint,
    gamma_v: CAffinePoint,
    psi: Scalar,
    public_share: CAffinePoint,
    instance_point: CAffinePoint,
    salt: *const c_uchar,
    salt_len: usize,
    mul_transmit: CMulDataToReceiver,
}

#[repr(C)]
pub struct CMulDataToReceiver {
    vector_of_tau: *const *const Scalar,
    vector_of_tau_len: usize,
    verify_r: [c_uchar; SECURITY as usize],
    verify_u: *const Scalar,
    verify_u_len: usize,
    gamma_sender: *const Scalar,
    gamma_sender_len: usize,
}

#[no_mangle]
pub extern "C" fn dkls_sign_phase_1(
    party: *const c_void,
    sign_data: *const CSignData,
    out_unique_keep: *mut CUniqueKeep1to2,
    out_keep_phase: *mut *mut CKeepPhase1to2,
    out_keep_phase_len: *mut usize,
    out_transmit_phase: *mut *mut CTransmitPhase1to2,
    out_transmit_phase_len: *mut usize,
) {
    let party = unsafe { &*(party as *const Party) };
    let sign_data = unsafe { &*sign_data };

    let sign_data_rust = SignData {
        sign_id: unsafe {
            std::slice::from_raw_parts(sign_data.sign_id, sign_data.sign_id_len).to_vec()
        },
        counterparties: unsafe {
            std::slice::from_raw_parts(sign_data.counterparties, sign_data.counterparties_len)
                .to_vec()
        },
        message_hash: sign_data.message_hash,
    };

    let (unique_keep, keep_phase, transmit_phase) = party.sign_phase1(&sign_data_rust);

    unsafe {
        let point = unique_keep.instance_point.to_encoded_point(false);
        let x = point.x().unwrap().as_slice();
        let y = point.y().unwrap().as_slice();
        let infinity = if point.is_identity().into() { 1 } else { 0 };

        *out_unique_keep = CUniqueKeep1to2 {
            instance_key: unique_keep.instance_key,
            instance_point: CAffinePoint {
                x: x.try_into().expect("slice with incorrect length"),
                y: y.try_into().expect("slice with incorrect length"),
                infinity,
            },
            inversion_mask: unique_keep.inversion_mask,
            zeta: unique_keep.zeta,
        };

        let keep_phase_vec: Vec<CKeepPhase1to2> = keep_phase
            .into_iter()
            .map(|(_, v)| CKeepPhase1to2 {
                salt: v.salt.as_ptr(),
                salt_len: v.salt.len(),
                chi: v.chi,
                mul_keep: CMulDataToKeepReceiver {
                    b: v.mul_keep.b,
                    choice_bits: v.mul_keep.choice_bits.as_ptr() as *const c_uchar,
                    choice_bits_len: v.mul_keep.choice_bits.len(),
                    extended_seeds: v.mul_keep.extended_seeds.as_ptr() as *const CPRGOutput,
                    extended_seeds_len: v.mul_keep.extended_seeds.len(),
                    chi_tilde: v.mul_keep.chi_tilde.as_ptr(),
                    chi_tilde_len: v.mul_keep.chi_tilde.len(),
                    chi_hat: v.mul_keep.chi_hat.as_ptr(),
                    chi_hat_len: v.mul_keep.chi_hat.len(),
                },
            })
            .collect();
        *out_keep_phase_len = keep_phase_vec.len();
        *out_keep_phase = keep_phase_vec.into_boxed_slice().as_mut_ptr();

        let transmit_phase_vec: Vec<CTransmitPhase1to2> = transmit_phase
            .into_iter()
            .map(|v| {
                let mut verify_x_bytes = [0u8; 32];
                verify_x_bytes[..26].copy_from_slice(&v.mul_transmit.verify_x);
                let verify_x = Scalar::from_repr(verify_x_bytes.into())
                    .expect("Failed to convert verify_x to Scalar");

                let verify_t: Vec<Scalar> = v
                    .mul_transmit
                    .verify_t
                    .iter()
                    .map(|&t| {
                        let mut t_bytes = [0u8; 32];
                        t_bytes[..26].copy_from_slice(&t);
                        Scalar::from_repr(t_bytes.into()).unwrap()
                    })
                    .collect();

                CTransmitPhase1to2 {
                    parties: CPartiesMessage {
                        sender: v.parties.sender,
                        receiver: v.parties.receiver,
                    },
                    commitment: v.commitment,
                    mul_transmit: COTEDataToSender {
                        u: v.mul_transmit.u.as_ptr() as *const CPRGOutput,
                        u_len: v.mul_transmit.u.len(),
                        verify_x,
                        verify_t: verify_t.as_ptr(),
                        verify_t_len: verify_t.len(),
                    },
                }
            })
            .collect();
        *out_transmit_phase_len = transmit_phase_vec.len();
        *out_transmit_phase = transmit_phase_vec.into_boxed_slice().as_mut_ptr();
    }
}

#[no_mangle]
pub extern "C" fn dkls_sign_phase_2(
    party: *const c_void,
    sign_data: *const CSignData,
    unique_kept: *const CUniqueKeep1to2,
    kept: *const CKeepPhase1to2,
    kept_len: usize,
    received: *const CTransmitPhase1to2,
    received_len: usize,
    out_unique_keep: *mut CUniqueKeep2to3,
    out_keep_phase: *mut *mut CKeepPhase2to3,
    out_keep_phase_len: *mut usize,
    out_transmit_phase: *mut *mut CTransmitPhase2to3,
    out_transmit_phase_len: *mut usize,
) -> c_uchar {
    let party = unsafe { &*(party as *const Party) };
    let sign_data = unsafe { &*sign_data };
    let unique_kept = unsafe { &*unique_kept };
    let kept = unsafe { std::slice::from_raw_parts(kept, kept_len) };
    let received = unsafe { std::slice::from_raw_parts(received, received_len) };

    // PART 1 - Convert C structs to Rust structs here
    let sign_data_rust = SignData {
        sign_id: unsafe {
            std::slice::from_raw_parts(sign_data.sign_id, sign_data.sign_id_len).to_vec()
        },
        counterparties: unsafe {
            std::slice::from_raw_parts(sign_data.counterparties, sign_data.counterparties_len)
                .to_vec()
        },
        message_hash: sign_data.message_hash,
    };

    let unique_kept_rust = UniqueKeep1to2 {
        instance_key: unique_kept.instance_key,
        instance_point: {
            let x = k256::FieldBytes::from_slice(&unique_kept.instance_point.x);
            let y = k256::FieldBytes::from_slice(&unique_kept.instance_point.y);
            k256::AffinePoint::from_encoded_point(&k256::EncodedPoint::from_affine_coordinates(
                x,
                y,
                unique_kept.instance_point.infinity != 0,
            ))
            .unwrap()
        },
        inversion_mask: unique_kept.inversion_mask,
        zeta: unique_kept.zeta,
    };

    let kept_map: BTreeMap<u8, KeepPhase1to2> = kept
        .iter()
        .enumerate()
        .map(|(i, v)| {
            (
                i as u8,
                KeepPhase1to2 {
                    salt: unsafe { std::slice::from_raw_parts(v.salt, v.salt_len).to_vec() },
                    chi: v.chi,
                    mul_keep: MulDataToKeepReceiver {
                        b: v.mul_keep.b,
                        choice_bits: unsafe {
                            std::slice::from_raw_parts(
                                v.mul_keep.choice_bits,
                                v.mul_keep.choice_bits_len,
                            )
                            .iter()
                            .map(|&byte| byte != 0)
                            .collect()
                        },
                        extended_seeds: unsafe {
                            std::slice::from_raw_parts(
                                v.mul_keep.extended_seeds,
                                v.mul_keep.extended_seeds_len,
                            )
                            .iter()
                            .map(|seed| seed.data)
                            .collect()
                        },
                        chi_tilde: unsafe {
                            std::slice::from_raw_parts(
                                v.mul_keep.chi_tilde,
                                v.mul_keep.chi_tilde_len,
                            )
                            .to_vec()
                        },
                        chi_hat: unsafe {
                            std::slice::from_raw_parts(v.mul_keep.chi_hat, v.mul_keep.chi_hat_len)
                                .to_vec()
                        },
                    },
                },
            )
        })
        .collect();

    let received_vec: Vec<TransmitPhase1to2> = received
        .iter()
        .map(|v| TransmitPhase1to2 {
            parties: PartiesMessage {
                sender: v.parties.sender,
                receiver: v.parties.receiver,
            },
            commitment: v.commitment,
            mul_transmit: OTEDataToSender {
                u: unsafe {
                    std::slice::from_raw_parts(v.mul_transmit.u, v.mul_transmit.u_len)
                        .iter()
                        .map(|output| output.data)
                        .collect()
                },
                verify_x: {
                    let mut verify_x_bytes = [0u8; 26];
                    let scalar_bytes = v.mul_transmit.verify_x.to_bytes();
                    verify_x_bytes.copy_from_slice(&scalar_bytes[..26]);
                    verify_x_bytes
                },
                verify_t: unsafe {
                    std::slice::from_raw_parts(v.mul_transmit.verify_t, v.mul_transmit.verify_t_len)
                        .iter()
                        .map(|&scalar| {
                            let mut scalar_bytes = [0u8; 26];
                            let bytes = scalar.to_bytes();
                            scalar_bytes.copy_from_slice(&bytes[..26]);
                            scalar_bytes
                        })
                        .collect()
                },
            },
        })
        .collect();

    match party.sign_phase2(&sign_data_rust, &unique_kept_rust, &kept_map, &received_vec) {
        Ok((unique_keep, keep_phase, transmit_phase)) => {
            unsafe {
                let point = unique_keep.instance_point.to_encoded_point(false);
                let x = point.x().unwrap().as_slice();
                let y = point.y().unwrap().as_slice();
                let infinity = if point.is_identity().into() { 1 } else { 0 };

                *out_unique_keep = CUniqueKeep2to3 {
                    instance_key: unique_keep.instance_key,
                    instance_point: CAffinePoint {
                        x: x.try_into().expect("slice with incorrect length"),
                        y: y.try_into().expect("slice with incorrect length"),
                        infinity,
                    },
                    inversion_mask: unique_keep.inversion_mask,
                    key_share: unique_keep.key_share,
                    public_share: {
                        let point = unique_keep.public_share.to_encoded_point(false);
                        let x = point.x().unwrap().as_slice();
                        let y = point.y().unwrap().as_slice();
                        let infinity = if point.is_identity().into() { 1 } else { 0 };
                        CAffinePoint {
                            x: x.try_into().expect("slice with incorrect length"),
                            y: y.try_into().expect("slice with incorrect length"),
                            infinity,
                        }
                    },
                };

                let keep_phase_vec: Vec<CKeepPhase2to3> = keep_phase
                    .into_iter()
                    .map(|(_, v)| CKeepPhase2to3 {
                        c_u: v.c_u,
                        c_v: v.c_v,
                        commitment: v.commitment,
                        mul_keep: CMulDataToKeepReceiver {
                            b: v.mul_keep.b,
                            choice_bits: v.mul_keep.choice_bits.as_ptr() as *const c_uchar,
                            choice_bits_len: v.mul_keep.choice_bits.len(),
                            extended_seeds: v.mul_keep.extended_seeds.as_ptr() as *const CPRGOutput,
                            extended_seeds_len: v.mul_keep.extended_seeds.len(),
                            chi_tilde: v.mul_keep.chi_tilde.as_ptr(),
                            chi_tilde_len: v.mul_keep.chi_tilde.len(),
                            chi_hat: v.mul_keep.chi_hat.as_ptr(),
                            chi_hat_len: v.mul_keep.chi_hat.len(),
                        },
                        chi: v.chi,
                    })
                    .collect();
                *out_keep_phase_len = keep_phase_vec.len();
                *out_keep_phase = keep_phase_vec.into_boxed_slice().as_mut_ptr();

                let transmit_phase_vec: Vec<CTransmitPhase2to3> = transmit_phase
                    .into_iter()
                    .map(|v| CTransmitPhase2to3 {
                        parties: CPartiesMessage {
                            sender: v.parties.sender,
                            receiver: v.parties.receiver,
                        },
                        gamma_u: {
                            let point = v.gamma_u.to_encoded_point(false);
                            let x = point.x().unwrap().as_slice();
                            let y = point.y().unwrap().as_slice();
                            let infinity = if point.is_identity().into() { 1 } else { 0 };
                            CAffinePoint {
                                x: x.try_into().expect("slice with incorrect length"),
                                y: y.try_into().expect("slice with incorrect length"),
                                infinity,
                            }
                        },
                        gamma_v: {
                            let point = v.gamma_v.to_encoded_point(false);
                            let x = point.x().unwrap().as_slice();
                            let y = point.y().unwrap().as_slice();
                            let infinity = if point.is_identity().into() { 1 } else { 0 };
                            CAffinePoint {
                                x: x.try_into().expect("slice with incorrect length"),
                                y: y.try_into().expect("slice with incorrect length"),
                                infinity,
                            }
                        },
                        psi: v.psi,
                        public_share: {
                            let point = v.public_share.to_encoded_point(false);
                            let x = point.x().unwrap().as_slice();
                            let y = point.y().unwrap().as_slice();
                            let infinity = if point.is_identity().into() { 1 } else { 0 };
                            CAffinePoint {
                                x: x.try_into().expect("slice with incorrect length"),
                                y: y.try_into().expect("slice with incorrect length"),
                                infinity,
                            }
                        },
                        instance_point: {
                            let point = v.instance_point.to_encoded_point(false);
                            let x = point.x().unwrap().as_slice();
                            let y = point.y().unwrap().as_slice();
                            let infinity = if point.is_identity().into() { 1 } else { 0 };
                            CAffinePoint {
                                x: x.try_into().expect("slice with incorrect length"),
                                y: y.try_into().expect("slice with incorrect length"),
                                infinity,
                            }
                        },
                        salt: v.salt.as_ptr(),
                        salt_len: v.salt.len(),
                        mul_transmit: CMulDataToReceiver {
                            vector_of_tau: v.mul_transmit.vector_of_tau.as_ptr()
                                as *const *const Scalar,
                            vector_of_tau_len: v.mul_transmit.vector_of_tau.len(),
                            gamma_sender: v.mul_transmit.gamma_sender.as_ptr(),
                            gamma_sender_len: v.mul_transmit.gamma_sender.len(),
                            verify_r: {
                                let mut verify_r_bytes = [0u8; 32];
                                verify_r_bytes[..26].copy_from_slice(&v.mul_transmit.verify_r);
                                verify_r_bytes
                            },
                            verify_u: v.mul_transmit.verify_u.as_ptr(),
                            verify_u_len: v.mul_transmit.verify_u.len(),
                        },
                    })
                    .collect();

                *out_transmit_phase_len = transmit_phase_vec.len();
                *out_transmit_phase = transmit_phase_vec.into_boxed_slice().as_mut_ptr();
            }
            0 // Return success
        }
        Err(_) => {
            1 // Return error
        }
    }
}
