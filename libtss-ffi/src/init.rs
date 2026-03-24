use crate::types::{TssStatus, TSS_ERR_INTERNAL_PANIC, TSS_OK};

/// Flag for `tss_init`: lock all current and future pages into RAM.
///
/// Requires `CAP_IPC_LOCK` or `ulimit -l unlimited`.
pub const TSS_INIT_MLOCK: u32 = 1;

/// Perform optional one-time initialization.
///
/// # Flags
///
/// - `TSS_INIT_MLOCK` (1): Call `mlockall(MCL_CURRENT | MCL_FUTURE)` to prevent
///   all process pages from being swapped to disk. This protects both Rust-side
///   key material and any mmap'd buffers (e.g., Go memguard) from being written
///   to swap. Requires `CAP_IPC_LOCK` capability or sufficient `RLIMIT_MEMLOCK`.
///
/// Returns `TSS_OK` on success. On failure, sets the last error message.
#[no_mangle]
pub extern "C" fn tss_init(flags: u32) -> TssStatus {
    crate::error::clear_last_error();

    if flags & TSS_INIT_MLOCK != 0 {
        if let Err(msg) = do_mlock() {
            crate::error::set_last_error(&msg);
            return TSS_ERR_INTERNAL_PANIC;
        }
    }

    TSS_OK
}

#[cfg(unix)]
fn do_mlock() -> Result<(), String> {
    let ret = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        Err(format!("mlockall failed: {errno}"))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn do_mlock() -> Result<(), String> {
    Ok(()) // no-op on non-unix platforms
}
