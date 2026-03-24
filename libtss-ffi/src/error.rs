use std::cell::{Cell, RefCell};
use std::ffi::CString;

use libc::c_char;

use crate::types::{
    TssStatus, TSS_ERR_ABORT, TSS_ERR_ABORT_BAN, TSS_ERR_DESERIALIZE, TSS_ERR_HANDLE_INVALID,
    TSS_ERR_INVALID_COMMIT, TSS_ERR_INVALID_CONFIG, TSS_ERR_INVALID_ID, TSS_ERR_INVALID_SHARE,
    TSS_ERR_INVALID_SIG, TSS_ERR_NONCE_REUSE, TSS_ERR_PROTO_MISMATCH, TSS_ERR_SESSION_COMPLETE,
    TSS_ERR_TWEAK,
};

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
    static ABORT_CULPRITS: RefCell<Vec<u16>> = const { RefCell::new(Vec::new()) };
    static BANNED_PARTY: Cell<u16> = const { Cell::new(0) };
}

pub fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new("").unwrap();
    });
    ABORT_CULPRITS.with(|slot| slot.borrow_mut().clear());
    BANNED_PARTY.with(|slot| slot.set(0));
}

pub fn set_last_error(message: impl AsRef<str>) {
    LAST_ERROR.with(|slot| {
        let value = CString::new(message.as_ref())
            .unwrap_or_else(|_| CString::new("invalid error").unwrap());
        *slot.borrow_mut() = value;
    });
    ABORT_CULPRITS.with(|slot| slot.borrow_mut().clear());
    BANNED_PARTY.with(|slot| slot.set(0));
}

pub fn set_last_error_from(err: &libtss::TssError) {
    match err {
        libtss::TssError::Abort {
            culprits,
            message,
            ban,
        } => {
            LAST_ERROR.with(|slot| {
                *slot.borrow_mut() = CString::new(message.as_str())
                    .unwrap_or_else(|_| CString::new("invalid error").unwrap());
            });
            ABORT_CULPRITS.with(|slot| {
                *slot.borrow_mut() = culprits.iter().map(|c| c.as_u16()).collect();
            });
            BANNED_PARTY.with(|slot| {
                slot.set(ban.map(libtss::Identifier::as_u16).unwrap_or(0));
            });
        }
        _ => set_last_error(err.to_string()),
    }
}

pub fn error_to_status(err: &libtss::TssError) -> TssStatus {
    match err {
        libtss::TssError::InvalidConfig(_) => TSS_ERR_INVALID_CONFIG,
        libtss::TssError::InvalidIdentifier => TSS_ERR_INVALID_ID,
        libtss::TssError::InvalidShare => TSS_ERR_INVALID_SHARE,
        libtss::TssError::InvalidCommitment => TSS_ERR_INVALID_COMMIT,
        libtss::TssError::InvalidSignature => TSS_ERR_INVALID_SIG,
        libtss::TssError::NonceReuse => TSS_ERR_NONCE_REUSE,
        libtss::TssError::HandleInvalid => TSS_ERR_HANDLE_INVALID,
        libtss::TssError::ProtocolMismatch => TSS_ERR_PROTO_MISMATCH,
        libtss::TssError::DeserializeFailed(_) => TSS_ERR_DESERIALIZE,
        libtss::TssError::TweakError(_) => TSS_ERR_TWEAK,
        libtss::TssError::SessionComplete => TSS_ERR_SESSION_COMPLETE,
        libtss::TssError::Abort { ban: Some(_), .. } => TSS_ERR_ABORT_BAN,
        libtss::TssError::Abort { ban: None, .. } => TSS_ERR_ABORT,
    }
}

/// Return a pointer to the last error message (NUL-terminated).
///
/// **Lifetime:** The returned pointer is only valid until the next libtss FFI
/// call on the *same thread*. Every FFI entry clears the error state, which
/// invalidates the pointer. Callers must copy the string immediately.
///
/// For a safer alternative, use `tss_last_error_copy`.
#[no_mangle]
pub extern "C" fn tss_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

/// Return the byte length of the last error message (excluding NUL).
///
/// **Lifetime:** Must be called without any intervening libtss FFI calls
/// after the function that produced the error. See `tss_last_error`.
#[no_mangle]
pub extern "C" fn tss_last_error_len() -> usize {
    LAST_ERROR.with(|slot| slot.borrow().as_bytes().len())
}

/// Copy the last error message into a caller-provided buffer.
///
/// Returns the number of bytes needed (including NUL). If `buf` is null or
/// `buf_len` is 0, only the required size is returned. If the buffer is too
/// small, the message is truncated and NUL-terminated.
///
/// This is the recommended way to read errors — it atomically reads both
/// length and content in a single borrow, avoiding the TOCTOU window
/// between `tss_last_error_len` and `tss_last_error`.
#[no_mangle]
pub extern "C" fn tss_last_error_copy(buf: *mut u8, buf_len: usize) -> usize {
    LAST_ERROR.with(|slot| {
        let s = slot.borrow();
        let bytes = s.as_bytes_with_nul();
        let needed = bytes.len();

        if buf.is_null() || buf_len == 0 {
            return needed;
        }

        let copy_len = needed.min(buf_len);
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len) };

        // Ensure NUL termination even if truncated
        if copy_len < needed && buf_len > 0 {
            unsafe { *buf.add(buf_len - 1) = 0 };
        }

        needed
    })
}

#[no_mangle]
pub extern "C" fn tss_abort_culprit_count() -> usize {
    ABORT_CULPRITS.with(|slot| slot.borrow().len())
}

#[no_mangle]
pub extern "C" fn tss_abort_culprit(index: usize) -> u16 {
    ABORT_CULPRITS.with(|slot| slot.borrow().get(index).copied().unwrap_or(0))
}

#[no_mangle]
pub extern "C" fn tss_abort_banned_party() -> u16 {
    BANNED_PARTY.with(Cell::get)
}
