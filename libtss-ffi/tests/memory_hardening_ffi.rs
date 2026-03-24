//! FFI-level memory hardening verification tests (Issue #75).
//!
//! These tests validate:
//! - tss_buffer_free zeroes data before deallocation
//! - tss_handle_free on a freed handle is a safe no-op
//! - tss_init(TSS_INIT_MLOCK) succeeds or fails gracefully
//! - Double-free patterns across all handle types

use libtss_ffi::types::*;

// ---------------------------------------------------------------------------
// Buffer zeroing verification
// ---------------------------------------------------------------------------

#[test]
fn buffer_free_resets_struct_to_empty() {
    // Create a buffer with known non-zero contents
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let mut buf = TssBuffer::from_vec(data);

    // Capture pointer before free
    let ptr = buf.data;
    let len = buf.len;
    assert!(!ptr.is_null());
    assert_eq!(len, 8);

    // Read the raw bytes through the pointer to verify they're non-zero
    let pre_free: Vec<u8> = unsafe { std::slice::from_raw_parts(ptr, len).to_vec() };
    assert_eq!(
        pre_free,
        vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
    );

    // Free the buffer (implementation zeroes via zeroize() then deallocs — see
    // memory.rs:25. Observing the zeroed bytes is not possible without UB since
    // the allocation is freed. This test verifies the struct is reset to empty.)
    libtss_ffi::memory::tss_buffer_free(&mut buf);

    // After free, the TssBuffer struct itself should be reset to empty
    assert!(buf.data.is_null());
    assert_eq!(buf.len, 0);
}

#[test]
fn buffer_free_empty_is_noop() {
    let mut buf = TssBuffer::empty();
    libtss_ffi::memory::tss_buffer_free(&mut buf);
    assert!(buf.data.is_null());
    assert_eq!(buf.len, 0);
}

#[test]
fn buffer_free_double_free_is_safe() {
    let data = vec![1u8, 2, 3, 4, 5];
    let mut buf = TssBuffer::from_vec(data);
    libtss_ffi::memory::tss_buffer_free(&mut buf);
    // Second free should be a no-op (buf is already empty)
    libtss_ffi::memory::tss_buffer_free(&mut buf);
}

// ---------------------------------------------------------------------------
// Handle double-free safety
// ---------------------------------------------------------------------------

#[test]
fn handle_free_nonexistent_is_noop() {
    // Freeing a handle that was never inserted should not panic
    libtss_ffi::memory::tss_handle_free(0);
    libtss_ffi::memory::tss_handle_free(u64::MAX);
    libtss_ffi::memory::tss_handle_free(9999);
}

#[test]
fn handle_free_twice_is_safe() {
    // Insert a dummy value into the registry, free it twice
    let handle = libtss::REGISTRY.insert(libtss::CAT_FROST_KEY, 42u64);
    libtss_ffi::memory::tss_handle_free(handle);
    libtss_ffi::memory::tss_handle_free(handle);
}

#[test]
fn handle_operations_after_free_return_error() {
    // Insert, free, then try to query
    let handle = libtss::REGISTRY.insert(libtss::CAT_FROST_KEY, String::from("secret"));
    libtss_ffi::memory::tss_handle_free(handle);

    // tss_handle_ciphersuite returns 0xFF on invalid handle
    let suite = libtss_ffi::handles::tss_handle_ciphersuite(handle);
    assert_eq!(suite, u8::MAX);

    // tss_handle_identifier returns error status
    let mut id: u16 = 0;
    let status = libtss_ffi::handles::tss_handle_identifier(handle, &mut id as *mut u16);
    assert_ne!(status, TSS_OK);
}

// ---------------------------------------------------------------------------
// mlock initialization
// ---------------------------------------------------------------------------

#[test]
fn init_with_no_flags_succeeds() {
    let status = libtss_ffi::init::tss_init(0);
    assert_eq!(status, TSS_OK);
}

#[test]
fn init_with_mlock_succeeds_or_fails_gracefully() {
    // mlockall may fail without CAP_IPC_LOCK, but must not crash.
    let status = libtss_ffi::init::tss_init(libtss_ffi::init::TSS_INIT_MLOCK);
    if status != TSS_OK {
        // On failure, verify an error message was set and mentions mlockall
        // (to confirm this is the expected permission failure, not a random bug)
        let err_len = libtss_ffi::error::tss_last_error_len();
        assert!(
            err_len > 0,
            "tss_init failed with status {} but set no error message",
            status
        );
        let ptr = libtss_ffi::error::tss_last_error();
        let msg = unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()
            .unwrap_or("");
        assert!(
            msg.contains("mlockall"),
            "expected error about mlockall, got: {msg}",
        );
    }
}

#[test]
fn init_called_multiple_times_is_safe() {
    libtss_ffi::init::tss_init(0);
    libtss_ffi::init::tss_init(0);
    libtss_ffi::init::tss_init(0);
}

// ---------------------------------------------------------------------------
// Session free safety
// ---------------------------------------------------------------------------

#[test]
fn session_free_nonexistent_is_noop() {
    // Freeing a session handle that was never created should not panic
    libtss_ffi::session::tss_session_free(0);
    libtss_ffi::session::tss_session_free(u64::MAX);
}
