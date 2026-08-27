use crate::ffi_entry;
use crate::session::borrow_key_share;
use crate::types::{TssHandle, TssStatus};

/// Apply an additive scalar tweak to a key share: `k' = k + tweak mod n`.
///
/// `tweak` is a 32-byte big-endian scalar, reduced mod n (LND's per-commitment
/// "single tweak" convention). Supported for the DKLs23 ciphersuites
/// (Secp256k1ECDSA, Secp256r1ECDSA); other suites return
/// `TSS_ERR_PROTO_MISMATCH`. A wrong-length or null `tweak` returns
/// `TSS_ERR_INVALID_CONFIG`; a tweak producing the identity point returns
/// `TSS_ERR_TWEAK`. The original handle stays valid; `out_handle` receives a
/// new key share that must be freed with `tss_handle_free`.
#[no_mangle]
pub extern "C" fn tss_tweak_add(
    key_share: TssHandle,
    tweak: *const u8,
    tweak_len: usize,
    out_handle: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_handle.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_handle is null".into()))?;
        *out = 0;

        let bytes = scalar_bytes(tweak, tweak_len, "tweak")?;
        let handle = borrow_key_share(key_share)?;
        let tweaked = libtss::tweak_add(&handle, bytes)?;
        *out = tweaked.handle_id();
        std::mem::forget(tweaked);
        Ok(())
    })
}

/// Apply a multiplicative scalar tweak to a key share: `k' = k * factor mod n`.
///
/// `factor` is a 32-byte big-endian scalar, reduced mod n; it is the building
/// block of LND's revocation ("double") tweak. A factor that reduces to zero
/// returns `TSS_ERR_TWEAK`. Ciphersuite support and the remaining error
/// mapping match `tss_tweak_add`.
#[no_mangle]
pub extern "C" fn tss_tweak_mul(
    key_share: TssHandle,
    factor: *const u8,
    factor_len: usize,
    out_handle: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_handle.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_handle is null".into()))?;
        *out = 0;

        let bytes = scalar_bytes(factor, factor_len, "factor")?;
        let handle = borrow_key_share(key_share)?;
        let tweaked = libtss::tweak_mul(&handle, bytes)?;
        *out = tweaked.handle_id();
        std::mem::forget(tweaked);
        Ok(())
    })
}

fn scalar_bytes<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], libtss::TssError> {
    if ptr.is_null() {
        return Err(libtss::TssError::InvalidConfig(format!("{name} is null")));
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}
