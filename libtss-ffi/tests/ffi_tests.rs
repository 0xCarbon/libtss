use libtss_ffi::error::*;
use libtss_ffi::types::*;

// -- Buffer helpers ------------------------------------------------------

#[test]
fn buffer_from_vec_and_free() {
    let data = vec![1u8, 2, 3, 4, 5];
    let mut buf = TssBuffer::from_vec(data);
    assert!(!buf.data.is_null());
    assert_eq!(buf.len, 5);

    // Read back
    let slice = unsafe { core::slice::from_raw_parts(buf.data, buf.len) };
    assert_eq!(slice, &[1, 2, 3, 4, 5]);

    libtss_ffi::memory::tss_buffer_free(&mut buf);
}

#[test]
fn buffer_free_null_is_safe() {
    libtss_ffi::memory::tss_buffer_free(&mut TssBuffer::empty());
}

// -- Message helpers -----------------------------------------------------

#[test]
fn message_build_and_count() {
    let payload = b"hello";
    let mut buf = TssBuffer::empty();

    let status =
        libtss_ffi::messages::tss_message_build(&mut buf, 1, 0, payload.as_ptr(), payload.len());
    assert_eq!(status, TSS_OK);
    assert!(!buf.data.is_null());

    let slice = TssSlice {
        data: buf.data as *const u8,
        len: buf.len,
    };
    let count = libtss_ffi::messages::tss_message_count(slice);
    assert_eq!(count, 1);

    libtss_ffi::memory::tss_buffer_free(&mut buf);
}

#[test]
fn message_build_multiple_and_extract() {
    let mut buf = TssBuffer::empty();

    // Build two messages
    let data1 = b"first";
    let data2 = b"second";
    let s1 = libtss_ffi::messages::tss_message_build(&mut buf, 1, 2, data1.as_ptr(), data1.len());
    assert_eq!(s1, TSS_OK);
    let s2 = libtss_ffi::messages::tss_message_build(&mut buf, 3, 0, data2.as_ptr(), data2.len());
    assert_eq!(s2, TSS_OK);

    let slice = TssSlice {
        data: buf.data as *const u8,
        len: buf.len,
    };
    assert_eq!(libtss_ffi::messages::tss_message_count(slice), 2);

    // Extract first message
    let mut from: u16 = 0;
    let mut to: u16 = 0;
    let mut out_data = TssSlice {
        data: core::ptr::null(),
        len: 0,
    };
    let status = libtss_ffi::messages::tss_message_at(slice, 0, &mut from, &mut to, &mut out_data);
    assert_eq!(status, TSS_OK);
    assert_eq!(from, 1);
    assert_eq!(to, 2);
    let msg_data = unsafe { core::slice::from_raw_parts(out_data.data, out_data.len) };
    assert_eq!(msg_data, b"first");

    // Extract second message
    let status = libtss_ffi::messages::tss_message_at(slice, 1, &mut from, &mut to, &mut out_data);
    assert_eq!(status, TSS_OK);
    assert_eq!(from, 3);
    assert_eq!(to, 0);

    libtss_ffi::memory::tss_buffer_free(&mut buf);
}

#[test]
fn message_count_empty() {
    let slice = TssSlice {
        data: core::ptr::null(),
        len: 0,
    };
    assert_eq!(libtss_ffi::messages::tss_message_count(slice), 0);
}

#[test]
fn message_at_out_of_range() {
    let mut buf = TssBuffer::empty();
    let data = b"x";
    libtss_ffi::messages::tss_message_build(&mut buf, 1, 0, data.as_ptr(), data.len());

    let slice = TssSlice {
        data: buf.data as *const u8,
        len: buf.len,
    };
    let mut from: u16 = 0;
    let mut to: u16 = 0;
    let mut out_data = TssSlice {
        data: core::ptr::null(),
        len: 0,
    };
    let status = libtss_ffi::messages::tss_message_at(slice, 99, &mut from, &mut to, &mut out_data);
    assert_ne!(status, TSS_OK);

    libtss_ffi::memory::tss_buffer_free(&mut buf);
}

// -- Error state ---------------------------------------------------------

#[test]
fn error_set_and_read() {
    set_last_error("test error");
    assert_eq!(tss_last_error_len(), 10);

    let ptr = tss_last_error();
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    assert_eq!(cstr.to_str().unwrap(), "test error");
}

#[test]
fn error_cleared_on_success() {
    set_last_error("old error");
    clear_last_error();
    assert_eq!(tss_last_error_len(), 0);
}

#[test]
fn abort_state_roundtrip() {
    let err = libtss::TssError::Abort {
        culprits: vec![
            libtss::Identifier::new(2).unwrap(),
            libtss::Identifier::new(5).unwrap(),
        ],
        message: "protocol violation".into(),
        ban: Some(libtss::Identifier::new(2).unwrap()),
    };
    set_last_error_from(&err);

    assert_eq!(tss_abort_culprit_count(), 2);
    assert_eq!(tss_abort_culprit(0), 2);
    assert_eq!(tss_abort_culprit(1), 5);
    assert_eq!(tss_abort_banned_party(), 2);
}

// -- Version -------------------------------------------------------------

#[test]
fn version_is_valid() {
    let ptr = libtss_ffi::tss_version();
    assert!(!ptr.is_null());
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    let version = cstr.to_str().unwrap();
    assert!(version.contains('.'));
}

// -- Panic safety --------------------------------------------------------

#[test]
fn ffi_entry_catches_panic() {
    let status = libtss_ffi::ffi_entry!({
        panic!("boom");
        #[allow(unreachable_code)]
        Ok(())
    });
    assert_eq!(status, TSS_ERR_INTERNAL_PANIC);
    assert!(tss_last_error_len() > 0);
}

// -- Handle queries ------------------------------------------------------

#[test]
fn handle_free_idempotent() {
    // Free a non-existent handle; should not panic
    libtss_ffi::memory::tss_handle_free(9999);
}

#[test]
fn test_ffi_verify() {
    let message = b"hello ffi verify";
    let message_slice = libtss_ffi::types::TssSlice {
        data: message.as_ptr(),
        len: message.len(),
    };

    // Test invalid signature should return false
    let public_key_slice = libtss_ffi::types::TssSlice {
        data: core::ptr::null(),
        len: 0,
    };
    let signature_slice = libtss_ffi::types::TssSlice {
        data: core::ptr::null(),
        len: 0,
    };

    // 6 is Secp256k1ECDSA
    let result = libtss_ffi::tss_verify(6, message_slice, signature_slice, public_key_slice);
    assert!(!result);
}
