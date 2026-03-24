use crate::ffi_entry;
use crate::session::borrow_key_share;
use crate::types::{TssHandle, TssStatus};

/// Derive a child key share using non-hardened BIP-32 derivation.
///
/// Supports Secp256k1ECDSA (DKLs23), Secp256r1ECDSA (DKLs23), and
/// Secp256k1Taproot (FROST). Returns `TSS_ERR_PROTO_MISMATCH` for
/// unsupported ciphersuites (e.g. Ed25519).
///
/// The original key share remains valid; the derived key is a new handle.
#[no_mangle]
pub extern "C" fn tss_derive_child(
    key_share: TssHandle,
    child_number: u32,
    out_handle: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_handle.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_handle is null".into()))?;
        *out = 0;

        let handle = borrow_key_share(key_share)?;
        let derived = libtss::derive_child(&handle, child_number)?;
        *out = derived.handle_id();
        std::mem::forget(derived);
        Ok(())
    })
}

/// Derive a key share along a BIP-32 path (e.g. "m/44/60/0/0").
///
/// Hardened segments (e.g. "m/44'/0'") are rejected with
/// `TSS_ERR_INVALID_CONFIG`. The `path` must be a valid UTF-8
/// NUL-terminated C string.
#[no_mangle]
pub extern "C" fn tss_derive_path(
    key_share: TssHandle,
    path: *const libc::c_char,
    out_handle: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_handle.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_handle is null".into()))?;
        *out = 0;

        if path.is_null() {
            return Err(libtss::TssError::InvalidConfig("path is null".into()));
        }
        let path_str = unsafe { std::ffi::CStr::from_ptr(path) }
            .to_str()
            .map_err(|_| libtss::TssError::InvalidConfig("path is not valid UTF-8".into()))?;

        let handle = borrow_key_share(key_share)?;
        let derived = libtss::derive_path(&handle, path_str)?;
        *out = derived.handle_id();
        std::mem::forget(derived);
        Ok(())
    })
}
