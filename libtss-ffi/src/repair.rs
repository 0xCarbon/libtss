use crate::ffi_entry;
use crate::messages::checked_slice;
use crate::session::{borrow_key_share, checked_optional_slice};
use crate::types::{TssBuffer, TssHandle, TssSlice, TssStatus};

/// Compute this helper's masked DKLs23 repair term for `target`.
///
/// `helpers` lists every helper (this party included, the target excluded);
/// all helpers must pass the identical list and `session_id`. `out_term`
/// receives a 32-byte scalar to unicast to the target; free it with
/// `tss_buffer_free`. A share missing a zero-share pairing with any helper
/// (a hollow, not yet refreshed share) returns `TSS_ERR_INVALID_SHARE`
/// rather than an unmasked term.
#[no_mangle]
pub extern "C" fn tss_repair_helper_term(
    key_share: TssHandle,
    helpers: *const u16,
    helpers_len: usize,
    target: u16,
    session_id: *const u8,
    session_id_len: usize,
    out_term: *mut TssBuffer,
) -> TssStatus {
    ffi_entry!({
        let out_term = unsafe { out_term.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_term is null".into()))?;
        *out_term = TssBuffer::empty();

        let helper_ids: Vec<libtss::Identifier> = if helpers.is_null() || helpers_len == 0 {
            Vec::new()
        } else {
            let raw = unsafe { core::slice::from_raw_parts(helpers, helpers_len) };
            raw.iter()
                .map(|&id| libtss::Identifier::new(id))
                .collect::<Result<Vec<_>, _>>()?
        };
        let target = libtss::Identifier::new(target)?;
        let sid = checked_optional_slice(session_id, session_id_len)?.ok_or_else(|| {
            libtss::TssError::InvalidConfig("repair requires a session_id".into())
        })?;

        let handle = borrow_key_share(key_share)?;
        let term = libtss::repair_helper_term(&handle, &helper_ids, target, sid)?;
        *out_term = TssBuffer::from_vec(term.to_vec());
        Ok(())
    })
}

/// Assemble helpers' repair terms into a hollow DKLs23 key share for `target`.
///
/// `pubkey_package` is the serialized group package and `chain_code` its
/// 32-byte BIP-32 chain code, both as the helpers report them; `terms` holds
/// at least `min_signers` outputs of `tss_repair_helper_term`. The sum of the
/// terms is checked against the target's verifying share and a mismatch
/// returns `TSS_ERR_INVALID_SHARE` without creating a handle. The returned
/// share cannot sign until a `tss_refresh_new_dkls` refresh has run across the
/// whole group. Free it with `tss_handle_free`.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "C" fn tss_repair_assemble(
    suite: u8,
    pubkey_package: TssSlice,
    chain_code: TssSlice,
    target: u16,
    terms: *const TssSlice,
    terms_len: usize,
    session_id: *const u8,
    session_id_len: usize,
    out_key_share: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out_key_share = unsafe { out_key_share.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_key_share is null".into()))?;
        *out_key_share = 0;

        let suite = libtss::Ciphersuite::try_from(suite)?;
        let package = libtss::PublicKeyPackage::deserialize(checked_slice(pubkey_package)?)?;
        let chain_code = checked_slice(chain_code)?;
        let target = libtss::Identifier::new(target)?;
        let term_slices: Vec<&[u8]> = if terms.is_null() || terms_len == 0 {
            Vec::new()
        } else {
            let raw = unsafe { core::slice::from_raw_parts(terms, terms_len) };
            raw.iter()
                .map(|term| checked_slice(*term))
                .collect::<Result<Vec<_>, _>>()?
        };
        let sid = checked_optional_slice(session_id, session_id_len)?.ok_or_else(|| {
            libtss::TssError::InvalidConfig("repair requires a session_id".into())
        })?;

        let handle =
            libtss::repair_assemble(suite, &package, chain_code, target, &term_slices, sid)?;
        *out_key_share = handle.handle_id();
        std::mem::forget(handle);
        Ok(())
    })
}
