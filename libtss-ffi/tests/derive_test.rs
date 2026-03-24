//! FFI-level tests for BIP-32 key derivation (tss_derive_child, tss_derive_path).

use libtss_ffi::types::*;
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
