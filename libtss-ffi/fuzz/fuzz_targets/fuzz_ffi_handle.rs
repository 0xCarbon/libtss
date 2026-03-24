#![no_main]

use libfuzzer_sys::fuzz_target;
use libtss_ffi::handles::{tss_handle_ciphersuite, tss_handle_group_key, tss_handle_identifier};
use libtss_ffi::memory::tss_handle_free;
use libtss_ffi::types::{TssBuffer, TSS_OK};

fuzz_target!(|data: &[u8]| {
    let mut raw = [0u8; 8];
    let take = data.len().min(raw.len());
    raw[..take].copy_from_slice(&data[..take]);
    let handle = u64::from_le_bytes(raw);

    tss_handle_free(handle);

    let mut identifier = 0;
    let mut group_key = TssBuffer::empty();

    assert_ne!(
        tss_handle_identifier(handle, &mut identifier),
        TSS_OK
    );
    assert_ne!(
        tss_handle_group_key(handle, &mut group_key),
        TSS_OK
    );
    let _ = tss_handle_ciphersuite(handle);
});
