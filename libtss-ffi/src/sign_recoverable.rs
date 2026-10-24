//! Signing step that also reports the ECDSA recovery identifier.

use crate::ffi_entry;
use crate::messages::{checked_slice, deserialize_messages, serialize_messages};
use crate::registry::{SessionEntry, SessionGuard};
use crate::types::{TssBuffer, TssHandle, TssSlice, TssStatus};

/// Value written to `out_recovery_id` when the signature has no recovery
/// identifier (FROST suites) or signing has not completed.
pub const TSS_NO_RECOVERY_ID: u8 = 255;

/// Same as `tss_sign_next`, and additionally writes the recovery identifier
/// of a completed DKLs23 ECDSA signature (0 or 1) to `out_recovery_id`.
/// FROST signatures and incomplete steps write `TSS_NO_RECOVERY_ID`.
#[no_mangle]
pub extern "C" fn tss_sign_next_recoverable(
    session: TssHandle,
    messages: TssSlice,
    out_signature: *mut TssBuffer,
    out_recovery_id: *mut u8,
    out_messages: *mut TssBuffer,
    out_complete: *mut bool,
) -> TssStatus {
    ffi_entry!({
        let out_signature = unsafe { out_signature.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_signature is null".into()))?;
        let out_recovery_id = unsafe { out_recovery_id.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_recovery_id is null".into()))?;
        let out_messages = unsafe { out_messages.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_messages is null".into()))?;
        let out_complete = unsafe { out_complete.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_complete is null".into()))?;
        *out_signature = TssBuffer::empty();
        *out_recovery_id = TSS_NO_RECOVERY_ID;
        *out_messages = TssBuffer::empty();
        *out_complete = false;

        let received = deserialize_messages(checked_slice(messages)?)?;

        let mut guard = SessionGuard::take(session)?;
        let SessionEntry::Sign(ref mut sign) = guard.entry_mut() else {
            return Err(libtss::TssError::HandleInvalid);
        };

        match sign.next(&received)? {
            libtss::SignOutput::Continue(next) => {
                *out_messages = TssBuffer::from_vec(serialize_messages(&next));
            }
            libtss::SignOutput::Complete(signature) => {
                *out_complete = true;
                *out_signature = TssBuffer::from_vec(signature.as_bytes().to_vec());
                *out_recovery_id = signature.recovery_id().unwrap_or(TSS_NO_RECOVERY_ID);
                guard.consume();
            }
        }
        Ok(())
    })
}
