use std::mem::ManuallyDrop;

use crate::ffi_entry;
use crate::messages::{checked_slice, deserialize_messages, serialize_messages};
use crate::registry::{insert_session, remove_session, SessionEntry, SessionGuard};
use crate::types::{TssBuffer, TssHandle, TssSlice, TssStatus};

pub(crate) fn checked_optional_slice<'a>(
    data: *const u8,
    len: usize,
) -> Result<Option<&'a [u8]>, libtss::TssError> {
    if data.is_null() {
        if len == 0 {
            return Ok(None);
        }
        return Err(libtss::TssError::InvalidConfig(
            "null pointer with non-zero length".into(),
        ));
    }
    Ok(Some(unsafe { core::slice::from_raw_parts(data, len) }))
}

pub(crate) fn borrow_key_share(
    handle: TssHandle,
) -> Result<ManuallyDrop<libtss::KeyShareHandle>, libtss::TssError> {
    Ok(ManuallyDrop::new(libtss::KeyShareHandle::from_registry_id(
        handle,
    )?))
}

#[no_mangle]
pub extern "C" fn tss_dkg_new(
    suite: u8,
    self_id: u16,
    max_signers: u16,
    min_signers: u16,
    session_id: *const u8,
    session_id_len: usize,
    out_session: *mut TssHandle,
    out_messages: *mut TssBuffer,
) -> TssStatus {
    ffi_entry!({
        let out_session = unsafe { out_session.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_session is null".into()))?;
        let out_messages = unsafe { out_messages.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_messages is null".into()))?;
        *out_session = 0;
        *out_messages = TssBuffer::empty();

        let suite = libtss::Ciphersuite::try_from(suite)?;
        let self_id = libtss::Identifier::new(self_id)?;
        let config = libtss::ThresholdConfig {
            min_signers,
            max_signers,
            suite,
        };
        let sid = checked_optional_slice(session_id, session_id_len)?;
        let (session, messages) = libtss::DkgSession::new(&config, self_id, sid)?;

        *out_session = insert_session(SessionEntry::Dkg(session));
        *out_messages = TssBuffer::from_vec(serialize_messages(&messages));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_dkg_next(
    session: TssHandle,
    messages: TssSlice,
    out_key_share: *mut TssHandle,
    out_pubkey_package: *mut TssBuffer,
    out_messages: *mut TssBuffer,
    out_complete: *mut bool,
) -> TssStatus {
    ffi_entry!({
        let out_key_share = unsafe { out_key_share.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_key_share is null".into()))?;
        let out_pubkey_package = unsafe { out_pubkey_package.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_pubkey_package is null".into()))?;
        let out_messages = unsafe { out_messages.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_messages is null".into()))?;
        let out_complete = unsafe { out_complete.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_complete is null".into()))?;
        *out_key_share = 0;
        *out_pubkey_package = TssBuffer::empty();
        *out_messages = TssBuffer::empty();
        *out_complete = false;

        let received = deserialize_messages(checked_slice(messages)?)?;

        // Take session via RAII guard to avoid holding the session registry
        // lock while next() creates key shares (which insert into the key
        // share REGISTRY). The guard returns the session on drop — including
        // panic unwinds — preventing permanent session loss.
        let mut guard = SessionGuard::take(session)?;
        let SessionEntry::Dkg(ref mut dkg) = guard.entry_mut() else {
            return Err(libtss::TssError::HandleInvalid);
        };

        match dkg.next(&received) {
            Ok(libtss::DkgOutput::Continue(next)) => {
                *out_messages = TssBuffer::from_vec(serialize_messages(&next));
                // guard drops here, returning the session to the registry
            }
            Ok(libtss::DkgOutput::Complete {
                key_share,
                public_keys,
            }) => {
                *out_complete = true;
                *out_key_share = key_share.handle_id();
                *out_pubkey_package = TssBuffer::from_vec(public_keys.serialize()?);
                // Prevent Drop from freeing the registry entry — the C caller
                // now owns this handle and will free it via tss_handle_free.
                std::mem::forget(key_share);
                // Session is complete; consume the guard so it is not returned.
                guard.consume();
            }
            Err(err) => {
                // guard drops here, returning the session to the registry
                return Err(err);
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_sign_new(
    key_share: TssHandle,
    message: TssSlice,
    // DKLs-specific parameters (ignored for FROST, required for DKLs):
    counterparties: *const u16,
    counterparties_len: usize,
    sign_id: *const u8,
    sign_id_len: usize,
    out_session: *mut TssHandle,
    out_messages: *mut TssBuffer,
) -> TssStatus {
    ffi_entry!({
        let out_session = unsafe { out_session.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_session is null".into()))?;
        let out_messages = unsafe { out_messages.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_messages is null".into()))?;
        *out_session = 0;
        *out_messages = TssBuffer::empty();

        let msg_bytes = checked_slice(message)?;
        let handle = borrow_key_share(key_share)?;

        let (session, messages) = match handle.ciphersuite().protocol() {
            libtss::Protocol::Frost => libtss::SignSession::new_frost(&handle, msg_bytes)?,
            libtss::Protocol::DKLs23 => {
                let hash: [u8; 32] = msg_bytes.try_into().map_err(|_| {
                    libtss::TssError::InvalidConfig(
                        "DKLs23 signing requires a 32-byte message hash".into(),
                    )
                })?;

                let sid = checked_optional_slice(sign_id, sign_id_len)?
                    .ok_or_else(|| {
                        libtss::TssError::InvalidConfig("DKLs23 signing requires a sign_id".into())
                    })?
                    .to_vec();

                let cps = if counterparties.is_null() || counterparties_len == 0 {
                    return Err(libtss::TssError::InvalidConfig(
                        "DKLs23 signing requires at least one counterparty".into(),
                    ));
                } else {
                    let raw =
                        unsafe { core::slice::from_raw_parts(counterparties, counterparties_len) };
                    raw.iter()
                        .map(|&id| libtss::Identifier::new(id))
                        .collect::<Result<Vec<_>, _>>()?
                };

                libtss::SignSession::new_dkls(&handle, sid, &cps, hash)?
            }
        };

        *out_session = insert_session(SessionEntry::Sign(session));
        *out_messages = TssBuffer::from_vec(serialize_messages(&messages));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_sign_next(
    session: TssHandle,
    messages: TssSlice,
    out_signature: *mut TssBuffer,
    out_messages: *mut TssBuffer,
    out_complete: *mut bool,
) -> TssStatus {
    ffi_entry!({
        let out_signature = unsafe { out_signature.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_signature is null".into()))?;
        let out_messages = unsafe { out_messages.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_messages is null".into()))?;
        let out_complete = unsafe { out_complete.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_complete is null".into()))?;
        *out_signature = TssBuffer::empty();
        *out_messages = TssBuffer::empty();
        *out_complete = false;

        let received = deserialize_messages(checked_slice(messages)?)?;

        let mut guard = SessionGuard::take(session)?;
        let SessionEntry::Sign(ref mut sign) = guard.entry_mut() else {
            return Err(libtss::TssError::HandleInvalid);
        };

        match sign.next(&received) {
            Ok(libtss::SignOutput::Continue(next)) => {
                *out_messages = TssBuffer::from_vec(serialize_messages(&next));
            }
            Ok(libtss::SignOutput::Complete(signature)) => {
                *out_complete = true;
                *out_signature = TssBuffer::from_vec(signature.as_bytes().to_vec());
                guard.consume();
            }
            Err(err) => {
                return Err(err);
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_refresh_new(
    key_share: TssHandle,
    participants: *const u16,
    participants_len: usize,
    out_session: *mut TssHandle,
    out_messages: *mut TssBuffer,
) -> TssStatus {
    ffi_entry!({
        let out_session = unsafe { out_session.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_session is null".into()))?;
        let out_messages = unsafe { out_messages.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_messages is null".into()))?;
        *out_session = 0;
        *out_messages = TssBuffer::empty();

        let handle = borrow_key_share(key_share)?;

        let participant_ids: Vec<libtss::Identifier> =
            if participants.is_null() || participants_len == 0 {
                Vec::new()
            } else {
                let raw = unsafe { core::slice::from_raw_parts(participants, participants_len) };
                raw.iter()
                    .map(|&id| libtss::Identifier::new(id))
                    .collect::<Result<Vec<_>, _>>()?
            };

        let (session, messages) = match handle.ciphersuite().protocol() {
            libtss::Protocol::Frost => {
                libtss::RefreshSession::new_frost(&handle, &participant_ids)?
            }
            libtss::Protocol::DKLs23 => {
                return Err(libtss::TssError::ProtocolMismatch);
            }
        };

        *out_session = insert_session(SessionEntry::Refresh(session));
        *out_messages = TssBuffer::from_vec(serialize_messages(&messages));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_refresh_receiver(
    key_share: TssHandle,
    out_session: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out_session = unsafe { out_session.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_session is null".into()))?;
        *out_session = 0;

        let handle = borrow_key_share(key_share)?;
        let session = libtss::RefreshSession::new_frost_receiver(&handle)?;

        *out_session = insert_session(SessionEntry::Refresh(session));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_refresh_next(
    session: TssHandle,
    messages: TssSlice,
    out_key_share: *mut TssHandle,
    out_pubkey_package: *mut TssBuffer,
    out_messages: *mut TssBuffer,
    out_complete: *mut bool,
) -> TssStatus {
    ffi_entry!({
        let out_key_share = unsafe { out_key_share.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_key_share is null".into()))?;
        let out_pubkey_package = unsafe { out_pubkey_package.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_pubkey_package is null".into()))?;
        let out_messages = unsafe { out_messages.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_messages is null".into()))?;
        let out_complete = unsafe { out_complete.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_complete is null".into()))?;
        *out_key_share = 0;
        *out_pubkey_package = TssBuffer::empty();
        *out_messages = TssBuffer::empty();
        *out_complete = false;

        let received = deserialize_messages(checked_slice(messages)?)?;

        let mut guard = SessionGuard::take(session)?;
        let SessionEntry::Refresh(ref mut refresh) = guard.entry_mut() else {
            return Err(libtss::TssError::HandleInvalid);
        };

        match refresh.next(&received) {
            Ok(libtss::RefreshOutput::Continue(next)) => {
                *out_messages = TssBuffer::from_vec(serialize_messages(&next));
            }
            Ok(libtss::RefreshOutput::Complete {
                key_share,
                public_keys,
            }) => {
                *out_complete = true;
                *out_key_share = key_share.handle_id();
                *out_pubkey_package = TssBuffer::from_vec(public_keys.serialize()?);
                std::mem::forget(key_share);
                guard.consume();
            }
            Err(err) => {
                return Err(err);
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_session_free(session: TssHandle) {
    crate::error::clear_last_error();
    remove_session(session);
}
