//! DKLs23-specific C API.

use crate::ffi_entry;
use crate::messages::checked_slice;
use crate::types::{TssBuffer, TssHandle, TssSlice, TssStatus};

/// Import an existing ECDSA key as DKLs23 shares (trusted dealer).
///
/// `suite` is `Secp256k1ECDSA` (6) or `Secp256r1ECDSA` (7); `secret_key` is a
/// 32-byte big-endian scalar. `chain_code` is either empty (sample a new one)
/// or the key's existing 32-byte BIP-32 chain code. `out_handles` must have
/// room for `max_signers` handles. The group key is the key's own public key.
/// The caller holds every share: hand each one to its party, erase the key
/// and the shares, and have the parties run a complete refresh
/// (`tss_refresh_new_dkls`) before use.
#[no_mangle]
pub extern "C" fn tss_dkls_split_key(
    suite: u8,
    secret_key: TssSlice,
    chain_code: TssSlice,
    max_signers: u16,
    min_signers: u16,
    out_handles: *mut TssHandle,
    out_handle_count: *mut usize,
    out_pubkey_package: *mut TssBuffer,
) -> TssStatus {
    ffi_entry!({
        let out_count = unsafe { out_handle_count.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_handle_count is null".into()))?;
        let out_pkg = unsafe { out_pubkey_package.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_pubkey_package is null".into()))?;
        *out_count = 0;
        *out_pkg = TssBuffer::empty();

        if out_handles.is_null() {
            return Err(libtss::TssError::InvalidConfig(
                "out_handles is null".into(),
            ));
        }

        let suite = libtss::Ciphersuite::try_from(suite)?;
        let sk_bytes = checked_slice(secret_key)?;
        let chain_code = checked_slice(chain_code)?;
        let chain_code = (!chain_code.is_empty()).then_some(chain_code);
        let config = libtss::ThresholdConfig {
            min_signers,
            max_signers,
            suite,
        };
        let (handles, pubkey) = libtss::dkls_import::dkls_split_key(&config, sk_bytes, chain_code)?;

        let handle_slice = unsafe { core::slice::from_raw_parts_mut(out_handles, handles.len()) };
        for (i, h) in handles.into_iter().enumerate() {
            handle_slice[i] = h.handle_id();
            std::mem::forget(h);
        }
        *out_count = handle_slice.len();
        *out_pkg = TssBuffer::from_vec(pubkey.serialize()?);
        Ok(())
    })
}
