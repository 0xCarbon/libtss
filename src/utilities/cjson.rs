use serde::{Deserialize, Serialize};
use serde_json;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub trait CJson: Serialize {
    fn to_json(&self) -> *const c_char {
        let json_str = serde_json::to_string(&self).unwrap();
        CString::new(json_str).unwrap().into_raw()
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn from_json<T>(data: *const c_char) -> T
    where
        T: Deserialize<'static>,
    {
        let json_str = unsafe { CStr::from_ptr(data) }.to_str().unwrap();

        serde_json::from_str::<T>(json_str).unwrap()
    }
}
