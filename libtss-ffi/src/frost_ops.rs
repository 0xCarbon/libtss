use std::collections::BTreeMap;

use crate::ffi_entry;
use crate::messages::{checked_slice, deserialize_messages};
use crate::session::{borrow_key_share, checked_optional_slice};
use crate::types::{TssBuffer, TssHandle, TssSlice, TssStatus};

fn serialize_id_blobs(map: &BTreeMap<libtss::Identifier, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, data) in map {
        out.extend_from_slice(&id.as_u16().to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

#[no_mangle]
pub extern "C" fn tss_frost_aggregate(
    suite: u8,
    message: TssSlice,
    commitments: TssSlice,
    shares: TssSlice,
    pubkey_package: TssSlice,
    out_signature: *mut TssBuffer,
) -> TssStatus {
    ffi_entry!({
        let out_signature = unsafe { out_signature.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_signature is null".into()))?;
        *out_signature = TssBuffer::empty();

        let _ = libtss::Ciphersuite::try_from(suite)?;
        let msg = checked_slice(message)?;
        let commit_msgs = deserialize_messages(checked_slice(commitments)?)?;
        let share_msgs = deserialize_messages(checked_slice(shares)?)?;
        let pkg = libtss::PublicKeyPackage::deserialize(checked_slice(pubkey_package)?)?;

        let sig = libtss::frost::frost_aggregate(msg, &commit_msgs, &share_msgs, &pkg)?;
        *out_signature = TssBuffer::from_vec(sig.as_bytes().to_vec());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_frost_tweak_key_share(
    key_share: TssHandle,
    merkle_root: *const u8,
    merkle_root_len: usize,
    out_tweaked_share: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_tweaked_share.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_tweaked_share is null".into()))?;
        *out = 0;

        let handle = borrow_key_share(key_share)?;
        let frost_handle = libtss::keyshare::to_frost_handle(&handle)?;
        let pubkey = handle.public_key_package().clone();
        let merkle = checked_optional_slice(merkle_root, merkle_root_len)?;
        if let Some(m) = merkle {
            if m.len() != 32 {
                return Err(libtss::TssError::InvalidConfig(
                    "merkle_root must be exactly 32 bytes".into(),
                ));
            }
        }

        let (tweaked_frost, _parity) = libtss::frost::frost_tweak_key_share(&frost_handle, merkle)?;
        let (tweaked_pubkey, _) = libtss::frost::frost_tweak_pubkey_package(&pubkey, merkle)?;
        let new_handle = libtss::keyshare::from_frost_dkg(tweaked_frost, &tweaked_pubkey)?;
        *out = new_handle.handle_id();
        std::mem::forget(new_handle);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_frost_tweak_pubkey_package(
    pubkey_package: TssSlice,
    merkle_root: *const u8,
    merkle_root_len: usize,
    out_tweaked_package: *mut TssBuffer,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_tweaked_package.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_tweaked_package is null".into()))?;
        *out = TssBuffer::empty();

        let pkg = libtss::PublicKeyPackage::deserialize(checked_slice(pubkey_package)?)?;
        let merkle = checked_optional_slice(merkle_root, merkle_root_len)?;
        if let Some(m) = merkle {
            if m.len() != 32 {
                return Err(libtss::TssError::InvalidConfig(
                    "merkle_root must be exactly 32 bytes".into(),
                ));
            }
        }
        let (tweaked, _parity) = libtss::frost::frost_tweak_pubkey_package(&pkg, merkle)?;
        *out = TssBuffer::from_vec(tweaked.serialize()?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_frost_generate_dealer(
    suite: u8,
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
        let config = libtss::ThresholdConfig {
            min_signers,
            max_signers,
            suite,
        };
        let (frost_handles, pubkey) = libtss::frost::frost_generate_with_dealer(&config)?;

        // Collect all handles first; if any conversion fails, previously created
        // handles drop automatically (cleaning up the registry).
        let unified_handles: Vec<_> = frost_handles
            .into_iter()
            .map(|fh| libtss::keyshare::from_frost_dkg(fh, &pubkey))
            .collect::<Result<Vec<_>, _>>()?;

        let handle_slice =
            unsafe { core::slice::from_raw_parts_mut(out_handles, unified_handles.len()) };
        for (i, h) in unified_handles.into_iter().enumerate() {
            handle_slice[i] = h.handle_id();
            std::mem::forget(h);
        }
        *out_count = handle_slice.len();
        *out_pkg = TssBuffer::from_vec(pubkey.serialize()?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_frost_split_key(
    suite: u8,
    secret_key: TssSlice,
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
        let config = libtss::ThresholdConfig {
            min_signers,
            max_signers,
            suite,
        };
        let (frost_handles, pubkey) = libtss::frost::frost_split_key(&config, sk_bytes)?;

        // Collect all handles first; if any conversion fails, previously created
        // handles drop automatically (cleaning up the registry).
        let unified_handles: Vec<_> = frost_handles
            .into_iter()
            .map(|fh| libtss::keyshare::from_frost_dkg(fh, &pubkey))
            .collect::<Result<Vec<_>, _>>()?;

        let handle_slice =
            unsafe { core::slice::from_raw_parts_mut(out_handles, unified_handles.len()) };
        for (i, h) in unified_handles.into_iter().enumerate() {
            handle_slice[i] = h.handle_id();
            std::mem::forget(h);
        }
        *out_count = handle_slice.len();
        *out_pkg = TssBuffer::from_vec(pubkey.serialize()?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_frost_refresh_dealer(
    pubkey_package: TssSlice,
    participants: *const u16,
    participant_count: usize,
    out_refresh_shares: *mut TssBuffer,
    out_share_count: *mut usize,
    out_pubkey_package: *mut TssBuffer,
) -> TssStatus {
    ffi_entry!({
        let out_shares = unsafe { out_refresh_shares.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_refresh_shares is null".into()))?;
        let out_count = unsafe { out_share_count.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_share_count is null".into()))?;
        let out_pkg = unsafe { out_pubkey_package.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_pubkey_package is null".into()))?;
        *out_shares = TssBuffer::empty();
        *out_count = 0;
        *out_pkg = TssBuffer::empty();

        let pkg = libtss::PublicKeyPackage::deserialize(checked_slice(pubkey_package)?)?;

        if participants.is_null() && participant_count > 0 {
            return Err(libtss::TssError::InvalidConfig(
                "null pointer with non-zero participant count".into(),
            ));
        }
        let participant_ids: Vec<libtss::Identifier> = if participant_count == 0 {
            Vec::new()
        } else {
            let raw = unsafe { core::slice::from_raw_parts(participants, participant_count) };
            raw.iter()
                .map(|&id| libtss::Identifier::new(id))
                .collect::<Result<Vec<_>, _>>()?
        };

        let (share_map, new_pubkey) =
            libtss::frost::frost_refresh_with_dealer(&pkg, &participant_ids)?;

        *out_shares = TssBuffer::from_vec(serialize_id_blobs(&share_map));
        *out_count = share_map.len();
        *out_pkg = TssBuffer::from_vec(new_pubkey.serialize()?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_frost_apply_refresh(
    key_share: TssHandle,
    refresh_data: TssSlice,
    pubkey_package: TssSlice,
    out_key_share: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_key_share.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_key_share is null".into()))?;
        *out = 0;

        let handle = borrow_key_share(key_share)?;
        let frost_handle = libtss::keyshare::to_frost_handle(&handle)?;
        let rd = checked_slice(refresh_data)?;
        let pubkey = libtss::PublicKeyPackage::deserialize(checked_slice(pubkey_package)?)?;

        let refreshed = libtss::frost::frost_apply_refresh(&frost_handle, rd)?;
        let new_handle = libtss::keyshare::from_frost_dkg(refreshed, &pubkey)?;
        *out = new_handle.handle_id();
        std::mem::forget(new_handle);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_frost_repair_part1(
    key_share: TssHandle,
    helpers: *const u16,
    helper_count: usize,
    participant: u16,
    out_deltas: *mut TssBuffer,
    out_delta_count: *mut usize,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_deltas.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_deltas is null".into()))?;
        let out_count = unsafe { out_delta_count.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_delta_count is null".into()))?;
        *out = TssBuffer::empty();
        *out_count = 0;

        let handle = borrow_key_share(key_share)?;
        let frost_handle = libtss::keyshare::to_frost_handle(&handle)?;

        if helpers.is_null() && helper_count > 0 {
            return Err(libtss::TssError::InvalidConfig(
                "null pointer with non-zero helper count".into(),
            ));
        }
        let helper_ids: Vec<libtss::Identifier> = if helper_count == 0 {
            Vec::new()
        } else {
            let raw = unsafe { core::slice::from_raw_parts(helpers, helper_count) };
            raw.iter()
                .map(|&id| libtss::Identifier::new(id))
                .collect::<Result<Vec<_>, _>>()?
        };
        let participant_id = libtss::Identifier::new(participant)?;

        let delta_map =
            libtss::frost::frost_repair_part1(&frost_handle, &helper_ids, participant_id)?;
        *out = TssBuffer::from_vec(serialize_id_blobs(&delta_map));
        *out_count = delta_map.len();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_frost_repair_part2(
    suite: u8,
    deltas: *const TssSlice,
    delta_count: usize,
    out_sigma: *mut TssBuffer,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_sigma.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_sigma is null".into()))?;
        *out = TssBuffer::empty();

        let suite = libtss::Ciphersuite::try_from(suite)?;

        let delta_vec: Vec<Vec<u8>> = if deltas.is_null() || delta_count == 0 {
            Vec::new()
        } else {
            let raw = unsafe { core::slice::from_raw_parts(deltas, delta_count) };
            raw.iter()
                .map(|s| checked_slice(*s).map(|b| b.to_vec()))
                .collect::<Result<Vec<_>, _>>()?
        };

        let sigma = libtss::frost::frost_repair_part2(suite, &delta_vec)?;
        *out = TssBuffer::from_vec(sigma);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tss_frost_repair_part3(
    sigmas: *const TssSlice,
    sigma_count: usize,
    participant: u16,
    pubkey_package: TssSlice,
    out_key: *mut TssHandle,
) -> TssStatus {
    ffi_entry!({
        let out = unsafe { out_key.as_mut() }
            .ok_or_else(|| libtss::TssError::InvalidConfig("out_key is null".into()))?;
        *out = 0;

        let sigma_vec: Vec<Vec<u8>> = if sigmas.is_null() || sigma_count == 0 {
            Vec::new()
        } else {
            let raw = unsafe { core::slice::from_raw_parts(sigmas, sigma_count) };
            raw.iter()
                .map(|s| checked_slice(*s).map(|b| b.to_vec()))
                .collect::<Result<Vec<_>, _>>()?
        };

        let participant_id = libtss::Identifier::new(participant)?;
        let pubkey = libtss::PublicKeyPackage::deserialize(checked_slice(pubkey_package)?)?;
        let suite = pubkey.suite();

        let frost_handle =
            libtss::frost::frost_repair_part3(suite, &sigma_vec, participant_id, &pubkey)?;
        let new_handle = libtss::keyshare::from_frost_dkg(frost_handle, &pubkey)?;
        *out = new_handle.handle_id();
        std::mem::forget(new_handle);
        Ok(())
    })
}
