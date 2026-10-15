//! FFI-level tests for BIP-32 key derivation (tss_derive_child, tss_derive_path)
//! and the chain code accessor (tss_handle_chain_code).

mod common;

use hmac::{Hmac, Mac};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar};
use libtss_ffi::types::*;
use sha2::{Digest, Sha256, Sha512};
use std::ffi::CString;

/// Helper: generate a FROST Taproot 2-of-3 dealer set and return the first handle.
fn taproot_handle() -> TssHandle {
    let mut handles = [0u64; 3];
    let mut count: usize = 0;
    let mut pkg = TssBuffer::empty();

    let status = libtss_ffi::frost_ops::tss_frost_generate_dealer(
        0x00, // Secp256k1Taproot
        3,
        2,
        handles.as_mut_ptr(),
        &mut count as *mut usize,
        &mut pkg as *mut TssBuffer,
    );
    assert_eq!(status, TSS_OK, "generate_dealer failed");
    assert_eq!(count, 3);
    libtss_ffi::memory::tss_buffer_free(&mut pkg);

    // Free handles [1] and [2]
    libtss_ffi::memory::tss_handle_free(handles[1]);
    libtss_ffi::memory::tss_handle_free(handles[2]);

    handles[0]
}

/// Helper: read group key bytes for a handle.
fn group_key(handle: TssHandle) -> Vec<u8> {
    let mut buf = TssBuffer::empty();
    let status = libtss_ffi::handles::tss_handle_group_key(handle, &mut buf as *mut TssBuffer);
    assert_eq!(status, TSS_OK);
    let bytes = unsafe { std::slice::from_raw_parts(buf.data, buf.len) }.to_vec();
    libtss_ffi::memory::tss_buffer_free(&mut buf);
    bytes
}

/// Helper: read the chain code for a handle.
fn chain_code(handle: TssHandle) -> Vec<u8> {
    let mut buf = TssBuffer::empty();
    let status = libtss_ffi::handles::tss_handle_chain_code(handle, &mut buf as *mut TssBuffer);
    assert_eq!(status, TSS_OK, "tss_handle_chain_code failed");
    common::take_buffer(&mut buf)
}

/// Helper: generate an Ed25519 2-of-3 dealer set (no BIP-32 support) and return all handles.
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

/// BIP-32 CKDpub computed independently of libtss: returns the child public
/// key (compressed SEC1) and the child chain code (`IR`).
fn bip32_ckd_pub(
    parent_key: &[u8],
    parent_chain_code: &[u8],
    child_number: u32,
) -> (Vec<u8>, Vec<u8>) {
    let mut mac = Hmac::<Sha512>::new_from_slice(parent_chain_code).unwrap();
    mac.update(parent_key);
    mac.update(&child_number.to_be_bytes());
    let output = mac.finalize().into_bytes();
    let (il, ir) = output.split_at(32);

    let il_bytes: &FieldBytes = il.try_into().unwrap();
    let tweak = <Scalar as Reduce<FieldBytes>>::reduce(il_bytes);
    let parent_point = PublicKey::from_sec1_bytes(parent_key)
        .unwrap()
        .to_projective();
    let child_point = (parent_point + ProjectivePoint::GENERATOR * tweak).to_affine();

    (
        child_point.to_sec1_point(true).as_bytes().to_vec(),
        ir.to_vec(),
    )
}

#[test]
fn derive_child_taproot_produces_new_key() {
    let parent = taproot_handle();
    let parent_key = group_key(parent);

    let mut child: TssHandle = 0;
    let status = libtss_ffi::derive::tss_derive_child(parent, 7, &mut child as *mut TssHandle);
    assert_eq!(status, TSS_OK, "derive_child failed");
    assert_ne!(child, 0);

    let child_key = group_key(child);
    assert_ne!(parent_key, child_key, "derived key must differ from parent");

    // Verify ciphersuite is preserved
    let suite = libtss_ffi::handles::tss_handle_ciphersuite(child);
    assert_eq!(suite, 0x00); // Secp256k1Taproot

    // Verify parent handle remains valid after derivation
    let parent_key_after = group_key(parent);
    assert_eq!(
        parent_key, parent_key_after,
        "parent must remain valid after derivation"
    );

    libtss_ffi::memory::tss_handle_free(child);
    libtss_ffi::memory::tss_handle_free(parent);
}

#[test]
fn derive_path_taproot_produces_new_key() {
    let parent = taproot_handle();
    let parent_key = group_key(parent);

    let path = CString::new("m/44/0/0").unwrap();
    let mut child: TssHandle = 0;
    let status =
        libtss_ffi::derive::tss_derive_path(parent, path.as_ptr(), &mut child as *mut TssHandle);
    assert_eq!(status, TSS_OK, "derive_path failed");
    assert_ne!(child, 0);

    let child_key = group_key(child);
    assert_ne!(parent_key, child_key, "derived key must differ from parent");

    // Verify parent handle remains valid after derivation
    let parent_key_after = group_key(parent);
    assert_eq!(
        parent_key, parent_key_after,
        "parent must remain valid after derivation"
    );

    libtss_ffi::memory::tss_handle_free(child);
    libtss_ffi::memory::tss_handle_free(parent);
}

#[test]
fn derive_child_hardened_rejected() {
    let parent = taproot_handle();

    let mut child: TssHandle = 0;
    let status =
        libtss_ffi::derive::tss_derive_child(parent, 1 << 31, &mut child as *mut TssHandle);
    assert_ne!(status, TSS_OK, "hardened index should be rejected");
    assert_eq!(child, 0);

    libtss_ffi::memory::tss_handle_free(parent);
}

#[test]
fn derive_path_hardened_rejected() {
    let parent = taproot_handle();

    let path = CString::new("m/44'/0").unwrap();
    let mut child: TssHandle = 0;
    let status =
        libtss_ffi::derive::tss_derive_path(parent, path.as_ptr(), &mut child as *mut TssHandle);
    assert_ne!(status, TSS_OK, "hardened path should be rejected");
    assert_eq!(child, 0);

    libtss_ffi::memory::tss_handle_free(parent);
}

#[test]
fn derive_child_unsupported_suite_rejected() {
    // Generate an Ed25519 handle (not BIP-32 compatible)
    let mut handles = [0u64; 3];
    let mut count: usize = 0;
    let mut pkg = TssBuffer::empty();

    let status = libtss_ffi::frost_ops::tss_frost_generate_dealer(
        0x02, // Ed25519
        3,
        2,
        handles.as_mut_ptr(),
        &mut count as *mut usize,
        &mut pkg as *mut TssBuffer,
    );
    assert_eq!(status, TSS_OK);
    libtss_ffi::memory::tss_buffer_free(&mut pkg);

    let mut child: TssHandle = 0;
    let st = libtss_ffi::derive::tss_derive_child(handles[0], 0, &mut child as *mut TssHandle);
    assert_ne!(st, TSS_OK, "Ed25519 derivation should fail");
    assert_eq!(child, 0);

    for h in &handles[..count] {
        libtss_ffi::memory::tss_handle_free(*h);
    }
}

#[test]
fn derive_null_pointer_rejected() {
    let parent = taproot_handle();

    // Null out_handle
    let status = libtss_ffi::derive::tss_derive_child(parent, 0, std::ptr::null_mut());
    assert_ne!(status, TSS_OK);

    // Null path
    let mut child: TssHandle = 0;
    let status =
        libtss_ffi::derive::tss_derive_path(parent, std::ptr::null(), &mut child as *mut TssHandle);
    assert_ne!(status, TSS_OK);

    libtss_ffi::memory::tss_handle_free(parent);
}

#[test]
fn handle_chain_code_taproot_is_sha256_of_group_key_and_changes_on_derive() {
    let parent = taproot_handle();
    let parent_chain_code = chain_code(parent);
    assert_eq!(parent_chain_code.len(), 32);
    assert_eq!(
        parent_chain_code,
        Sha256::digest(group_key(parent)).to_vec()
    );

    let mut child: TssHandle = 0;
    let status = libtss_ffi::derive::tss_derive_child(parent, 7, &mut child as *mut TssHandle);
    assert_eq!(status, TSS_OK);
    assert_ne!(chain_code(child), parent_chain_code);

    libtss_ffi::memory::tss_handle_free(child);
    libtss_ffi::memory::tss_handle_free(parent);
}

#[test]
fn handle_chain_code_unsupported_suite_rejected() {
    let handles = ed25519_handles();

    let mut buf = TssBuffer::empty();
    let status = libtss_ffi::handles::tss_handle_chain_code(handles[0], &mut buf as *mut TssBuffer);
    assert_eq!(status, TSS_ERR_PROTO_MISMATCH);
    assert!(buf.data.is_null(), "no buffer must be allocated on failure");

    for h in handles {
        libtss_ffi::memory::tss_handle_free(h);
    }
}

#[test]
fn handle_chain_code_null_out_rejected() {
    let parent = taproot_handle();
    let status = libtss_ffi::handles::tss_handle_chain_code(parent, std::ptr::null_mut());
    assert_eq!(status, TSS_ERR_INVALID_CONFIG);
    libtss_ffi::memory::tss_handle_free(parent);
}

#[test]
fn handle_chain_code_invalid_handle_rejected() {
    let mut buf = TssBuffer::empty();
    let status = libtss_ffi::handles::tss_handle_chain_code(u64::MAX, &mut buf as *mut TssBuffer);
    assert_eq!(status, TSS_ERR_HANDLE_INVALID);
}

#[test]
fn handle_chain_code_dkls_equal_across_parties_and_matches_bip32() {
    let keys = common::run_dkg(common::SUITE_SECP256K1_ECDSA, 2, 2);

    let parent_chain_code = chain_code(keys[0]);
    assert_eq!(parent_chain_code.len(), 32);
    assert_eq!(parent_chain_code, chain_code(keys[1]));

    let mut child: TssHandle = 0;
    let status = libtss_ffi::derive::tss_derive_child(keys[0], 3, &mut child as *mut TssHandle);
    assert_eq!(status, TSS_OK);

    let (expected_child_key, expected_child_chain_code) =
        bip32_ckd_pub(&group_key(keys[0]), &parent_chain_code, 3);
    assert_eq!(group_key(child), expected_child_key);
    assert_eq!(chain_code(child), expected_child_chain_code);

    libtss_ffi::memory::tss_handle_free(child);
    for key in keys {
        libtss_ffi::memory::tss_handle_free(key);
    }
}
