use zeroize::Zeroize;

use crate::error::clear_last_error;
use crate::types::TssBuffer;

/// Free a buffer previously returned by a libtss FFI function.
///
/// The buffer data is zeroed before deallocation to prevent secret
/// material from persisting in freed heap memory. The caller's
/// `TssBuffer` is then set to empty, so a second call with the same
/// pointer is a safe no-op (prevents double-free).
#[no_mangle]
pub extern "C" fn tss_buffer_free(buf: *mut TssBuffer) {
    clear_last_error();
    let buf = match unsafe { buf.as_mut() } {
        Some(b) => b,
        None => return,
    };
    if buf.data.is_null() || buf.len == 0 {
        *buf = TssBuffer::empty();
        return;
    }
    unsafe {
        let raw = core::ptr::slice_from_raw_parts_mut(buf.data, buf.len);
        (*raw).zeroize();
        drop(Box::from_raw(raw));
    }
    *buf = TssBuffer::empty();
}

/// Free a key share handle. Session handles are freed automatically on
/// completion; use this only for `KeyShareHandle` returned by DKG/refresh.
#[no_mangle]
pub extern "C" fn tss_handle_free(handle: u64) {
    clear_last_error();
    libtss::REGISTRY.free(handle);
}
