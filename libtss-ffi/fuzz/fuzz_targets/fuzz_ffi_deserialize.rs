#![no_main]

use libfuzzer_sys::fuzz_target;
use libtss_ffi::session::tss_dkg_next;
use libtss_ffi::types::{TssBuffer, TssSlice, TSS_OK};

fuzz_target!(|data: &[u8]| {
    let mut key_share = 0;
    let mut pubkey_package = TssBuffer::empty();
    let mut out_messages = TssBuffer::empty();
    let mut complete = false;
    let input = TssSlice {
        data: data.as_ptr(),
        len: data.len(),
    };
    let status = tss_dkg_next(
        0,
        input,
        &mut key_share,
        &mut pubkey_package,
        &mut out_messages,
        &mut complete,
    );
    assert_ne!(status, TSS_OK);
});
