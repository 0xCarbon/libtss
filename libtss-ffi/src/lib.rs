#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::missing_safety_doc)]

pub mod derive;
pub mod error;
pub mod frost_ops;
pub mod handles;
pub mod init;
pub mod memory;
pub mod messages;
pub mod registry;
pub mod session;
pub mod types;

#[macro_export]
macro_rules! ffi_entry {
    ($body:block) => {{
        $crate::error::clear_last_error();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<(), libtss::TssError> { $body },
        )) {
            Ok(Ok(())) => $crate::types::TSS_OK,
            Ok(Err(err)) => {
                $crate::error::set_last_error_from(&err);
                $crate::error::error_to_status(&err)
            }
            Err(_) => {
                $crate::error::set_last_error("internal panic");
                $crate::types::TSS_ERR_INTERNAL_PANIC
            }
        }
    }};
}

#[no_mangle]
pub extern "C" fn tss_version() -> *const libc::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn tss_verify(
    suite: u8,
    message: types::TssSlice,
    signature: types::TssSlice,
    public_key: types::TssSlice,
) -> bool {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let suite = match suite.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };

        let message_slice = if message.data.is_null() || message.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(message.data, message.len) }
        };

        let signature_slice = if signature.data.is_null() || signature.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(signature.data, signature.len) }
        };

        let public_key_slice = if public_key.data.is_null() || public_key.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(public_key.data, public_key.len) }
        };

        libtss::verify(suite, message_slice, signature_slice, public_key_slice).unwrap_or(false)
    }));

    result.unwrap_or(false)
}
