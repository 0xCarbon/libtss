#[allow(non_camel_case_types)]
pub type TssStatus = i32;
pub type TssHandle = u64;

pub const TSS_OK: TssStatus = 0;
pub const TSS_ERR_INVALID_CONFIG: TssStatus = 1;
pub const TSS_ERR_INVALID_ID: TssStatus = 2;
pub const TSS_ERR_INVALID_SHARE: TssStatus = 3;
pub const TSS_ERR_INVALID_COMMIT: TssStatus = 4;
pub const TSS_ERR_INVALID_SIG: TssStatus = 5;
pub const TSS_ERR_NONCE_REUSE: TssStatus = 6;
pub const TSS_ERR_HANDLE_INVALID: TssStatus = 7;
pub const TSS_ERR_PROTO_MISMATCH: TssStatus = 8;
pub const TSS_ERR_DESERIALIZE: TssStatus = 9;
pub const TSS_ERR_ABORT: TssStatus = 10;
pub const TSS_ERR_ABORT_BAN: TssStatus = 0x0B;
pub const TSS_ERR_TWEAK: TssStatus = 0x0D;
pub const TSS_ERR_SESSION_COMPLETE: TssStatus = 0x0E;
pub const TSS_ERR_INTERNAL_PANIC: TssStatus = 0xFF;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TssBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl TssBuffer {
    pub fn empty() -> Self {
        Self {
            data: core::ptr::null_mut(),
            len: 0,
        }
    }

    pub fn from_vec(bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::empty();
        }
        let boxed = bytes.into_boxed_slice();
        let len = boxed.len();
        let data = Box::into_raw(boxed) as *mut u8;
        Self { data, len }
    }

    /// # Safety
    /// The buffer must have been created by `from_vec`. After calling, the
    /// buffer is reset to empty and the caller owns the returned `Vec`.
    pub unsafe fn take_vec(&mut self) -> Vec<u8> {
        let current = *self;
        *self = Self::empty();
        if current.data.is_null() || current.len == 0 {
            return Vec::new();
        }
        let raw = core::ptr::slice_from_raw_parts_mut(current.data, current.len);
        Box::from_raw(raw).into_vec()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TssSlice {
    pub data: *const u8,
    pub len: usize,
}

impl TssSlice {
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            data: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    /// # Safety
    /// The pointer must be valid for the given length.
    pub unsafe fn as_slice<'a>(&self) -> &'a [u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(self.data, self.len)
        }
    }
}
