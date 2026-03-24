#![no_main]

use libfuzzer_sys::fuzz_target;
use libtss_ffi::session::tss_sign_next;
use libtss_ffi::types::{TssBuffer, TssSlice, TSS_OK};

fuzz_target!(|data: &[u8]| {
    let mut signature = TssBuffer::empty();
    let mut out_messages = TssBuffer::empty();
    let mut complete = false;
    let input = TssSlice {
        data: data.as_ptr(),
        len: data.len(),
    };
    let status = tss_sign_next(
        0,
        input,
        &mut signature,
        &mut out_messages,
        &mut complete,
    );
    assert_ne!(status, TSS_OK);
});
