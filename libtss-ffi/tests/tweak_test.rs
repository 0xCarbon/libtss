//! FFI-level tests for scalar tweaks on DKLs23 key shares (tss_tweak_add, tss_tweak_mul).

mod common;

use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{ProjectivePoint, PublicKey, Scalar};
use libtss_ffi::tweak::{tss_tweak_add, tss_tweak_mul};
use libtss_ffi::types::*;
use sha2::{Digest, Sha256};

fn scalar_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn group_key(handle: TssHandle) -> Vec<u8> {
    let mut buf = TssBuffer::empty();
    assert_eq!(
        libtss_ffi::handles::tss_handle_group_key(handle, &mut buf as *mut TssBuffer),
        TSS_OK
    );
    common::take_buffer(&mut buf)
}

fn k1_point(compressed: &[u8]) -> ProjectivePoint {
    PublicKey::from_sec1_bytes(compressed)
        .unwrap()
        .to_projective()
}

fn compressed(point: ProjectivePoint) -> Vec<u8> {
    point.to_affine().to_sec1_point(true).as_bytes().to_vec()
}

fn tweak_add(handle: TssHandle, scalar: &[u8]) -> (TssStatus, TssHandle) {
    let mut out: TssHandle = 0;
    let status = tss_tweak_add(
        handle,
        scalar.as_ptr(),
        scalar.len(),
        &mut out as *mut TssHandle,
    );
    (status, out)
}

fn tweak_mul(handle: TssHandle, scalar: &[u8]) -> (TssStatus, TssHandle) {
    let mut out: TssHandle = 0;
    let status = tss_tweak_mul(
        handle,
        scalar.as_ptr(),
        scalar.len(),
        &mut out as *mut TssHandle,
    );
    (status, out)
}

fn ed25519_handles() -> Vec<TssHandle> {
    let mut handles = [0u64; 3];
    let mut count: usize = 0;
    let mut pkg = TssBuffer::empty();
    let status = libtss_ffi::frost_ops::tss_frost_generate_dealer(
        common::SUITE_ED25519,
        3,
        2,
        handles.as_mut_ptr(),
        &mut count as *mut usize,
        &mut pkg as *mut TssBuffer,
    );
    assert_eq!(status, TSS_OK);
    libtss_ffi::memory::tss_buffer_free(&mut pkg);
    handles[..count].to_vec()
}

#[test]
fn tweaked_shares_sign_and_verify_via_ffi() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 2, 2);
    let parent_key = group_key(keys[0]);

    let tweaked: Vec<TssHandle> = keys
        .iter()
        .map(|&key| {
            let (status, out) = tweak_add(key, &scalar_bytes(7));
            assert_eq!(status, TSS_OK);
            assert_ne!(out, 0);
            out
        })
        .collect();

    let tweaked_key = group_key(tweaked[0]);
    assert_eq!(tweaked_key, group_key(tweaked[1]));
    assert_eq!(
        tweaked_key,
        compressed(k1_point(&parent_key) + ProjectivePoint::GENERATOR * Scalar::from(7u64))
    );
    assert_eq!(group_key(keys[0]), parent_key, "parent must remain valid");

    let message = b"ffi scalar tweak";
    let msg_hash = Sha256::digest(message);
    let signature = common::run_dkls_sign(&tweaked, &msg_hash);
    assert!(libtss_ffi::tss_verify(
        common::SUITE_SECP256K1_ECDSA,
        common::slice(message),
        common::slice(&signature),
        common::slice(&tweaked_key),
    ));
    assert!(!libtss_ffi::tss_verify(
        common::SUITE_SECP256K1_ECDSA,
        common::slice(message),
        common::slice(&signature),
        common::slice(&parent_key),
    ));

    for handle in tweaked.into_iter().chain(keys) {
        libtss_ffi::memory::tss_handle_free(handle);
    }
}

#[test]
fn tweak_mul_by_one_keeps_group_key() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 2, 2);
    let (status, scaled) = tweak_mul(keys[0], &scalar_bytes(1));
    assert_eq!(status, TSS_OK);
    assert_eq!(group_key(scaled), group_key(keys[0]));

    let (status, scaled_by_three) = tweak_mul(keys[0], &scalar_bytes(3));
    assert_eq!(status, TSS_OK);
    assert_eq!(
        group_key(scaled_by_three),
        compressed(k1_point(&group_key(keys[0])) * Scalar::from(3u64))
    );

    for handle in [scaled, scaled_by_three].into_iter().chain(keys) {
        libtss_ffi::memory::tss_handle_free(handle);
    }
}

#[test]
fn tweak_rejects_bad_length() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 2, 2);

    let (status, out) = tweak_add(keys[0], &[1u8; 31]);
    assert_eq!(status, TSS_ERR_INVALID_CONFIG);
    assert_eq!(out, 0);

    let (status, out) = tweak_mul(keys[0], &[1u8; 33]);
    assert_eq!(status, TSS_ERR_INVALID_CONFIG);
    assert_eq!(out, 0);

    for handle in keys {
        libtss_ffi::memory::tss_handle_free(handle);
    }
}

#[test]
fn tweak_mul_zero_factor_rejected() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 2, 2);
    let (status, out) = tweak_mul(keys[0], &scalar_bytes(0));
    assert_eq!(status, TSS_ERR_TWEAK);
    assert_eq!(out, 0);
    for handle in keys {
        libtss_ffi::memory::tss_handle_free(handle);
    }
}

#[test]
fn tweak_unsupported_suite_rejected() {
    let handles = ed25519_handles();
    let (status, out) = tweak_add(handles[0], &scalar_bytes(7));
    assert_eq!(status, TSS_ERR_PROTO_MISMATCH);
    assert_eq!(out, 0);
    let (status, out) = tweak_mul(handles[0], &scalar_bytes(3));
    assert_eq!(status, TSS_ERR_PROTO_MISMATCH);
    assert_eq!(out, 0);
    for handle in handles {
        libtss_ffi::memory::tss_handle_free(handle);
    }
}

#[test]
fn tweak_null_pointers_rejected() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 2, 2);

    let mut out: TssHandle = 0;
    assert_eq!(
        tss_tweak_add(keys[0], std::ptr::null(), 32, &mut out as *mut TssHandle),
        TSS_ERR_INVALID_CONFIG
    );
    assert_eq!(out, 0);

    let scalar = scalar_bytes(7);
    assert_eq!(
        tss_tweak_mul(keys[0], scalar.as_ptr(), scalar.len(), std::ptr::null_mut()),
        TSS_ERR_INVALID_CONFIG
    );

    let (status, out) = tweak_add(u64::MAX, &scalar);
    assert_eq!(status, TSS_ERR_HANDLE_INVALID);
    assert_eq!(out, 0);

    for handle in keys {
        libtss_ffi::memory::tss_handle_free(handle);
    }
}
