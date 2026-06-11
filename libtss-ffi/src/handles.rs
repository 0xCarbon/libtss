use std::mem::ManuallyDrop;

use crate::ffi_entry;
use crate::types::{TssBuffer, TssHandle, TssStatus};

/// Borrow a key share from the registry without taking ownership.
fn borrow_key_share(
    handle: TssHandle,
) -> Result<ManuallyDrop<libtss::KeyShareHandle>, libtss::TssError> {
    Ok(ManuallyDrop::new(libtss::KeyShareHandle::from_registry_id(
        handle,
    )?))
}

#[no_mangle]
pub extern "C" fn tss_handle_identifier(handle: TssHandle, out_id: *mut u16) -> TssStatus {
    ffi_entry!({
        let out_id = unsafe { out_id.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_id is null".into()))?;
        let ks = borrow_key_share(handle)?;
        *out_id = ks.identifier().as_u16();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_handle_verifying_share(handle: TssHandle, out: *mut TssBuffer) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out is null".into()))?;
        let ks = borrow_key_share(handle)?;
        *out = TssBuffer::from_vec(ks.verifying_share());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_handle_group_key(handle: TssHandle, out: *mut TssBuffer) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out is null".into()))?;
        let ks = borrow_key_share(handle)?;
        *out = TssBuffer::from_vec(ks.group_verifying_key());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_handle_chain_code(handle: TssHandle, out: *mut TssBuffer) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out is null".into()))?;
        let ks = borrow_key_share(handle)?;
        *out = TssBuffer::from_vec(ks.chain_code()?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_handle_pubkey_package(handle: TssHandle, out: *mut TssBuffer) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out is null".into()))?;
        let ks = borrow_key_share(handle)?;
        *out = TssBuffer::from_vec(ks.public_key_package().serialize()?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_handle_ciphersuite(handle: TssHandle) -> u8 {
    crate::error::clear_last_error();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ks = borrow_key_share(handle)?;
        Ok::<_, libtss::TssError>(ks.ciphersuite() as u8)
    }));
    match result {
        Ok(Ok(v)) => v,
        Ok(Err(err)) => {
            crate::error::set_last_error_from(&err);
            u8::MAX
        }
        Err(_) => {
            crate::error::set_last_error("internal panic");
            u8::MAX
        }
    }
}

/// Export a key share as a serialized byte blob.
///
/// **Security:** The output contains unencrypted secret key material.
/// The caller MUST encrypt the bytes before persisting to disk or
/// transmitting over a network.
#[no_mangle]
pub extern "C" fn tss_handle_export(handle: TssHandle, out: *mut TssBuffer) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out is null".into()))?;
        let ks = borrow_key_share(handle)?;
        *out = TssBuffer::from_vec(ks.export()?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_handle_import(
    data: *const u8,
    data_len: usize,
    suite: u8,
    out_handle: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out_handle = unsafe { out_handle.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_handle is null".into()))?;
        *out_handle = 0;

        let bytes = if data.is_null() {
            return Err(libtss::TssError::InvalidConfig("data is null".into()));
        } else {
            unsafe { core::slice::from_raw_parts(data, data_len) }
        };
        let suite = libtss::Ciphersuite::try_from(suite)?;
        let handle = libtss::import_key_share(bytes, suite)?;
        *out_handle = handle.handle_id();
        // Don't drop handle — the registry entry should persist for the C caller
        std::mem::forget(handle);
        Ok(())
    })
}
