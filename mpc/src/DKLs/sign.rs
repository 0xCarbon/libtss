use dkls23::{
    protocols::{signing::SignData, Party},
    utilities::ot::extension::EXTENDED_BATCH_SIZE,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use std::os::raw::{c_uchar, c_void};

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
