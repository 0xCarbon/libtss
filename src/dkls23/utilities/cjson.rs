use dkls23::protocols::dkg::SessionData;
use serde::{Deserialize, Serialize};
use serde_json;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::dkls23::protocols::dkg::{
    Phase1In, Phase1Out, Phase2In, Phase2Out, Phase3In, Phase3Out, Phase4In,
    Phase4Out,
};

pub trait CJson: Serialize {
    fn to_json(&self) -> *const c_char {
        let json_str = serde_json::to_string(&self).unwrap();
        CString::new(json_str).unwrap().into_raw()
    }

    fn from_json<T>(data: *const c_char) -> T
    where
        T: Deserialize<'static>,
    {
        let json_str = unsafe { CStr::from_ptr(data) }.to_str().unwrap();

        serde_json::from_str::<T>(json_str).unwrap()
    }
}

impl CJson for SessionData {}
impl CJson for Phase1In {}
impl CJson for Phase1Out {}
impl CJson for Phase2In {}
impl CJson for Phase2Out {}
impl CJson for Phase3In {}
impl CJson for Phase3Out {}
impl CJson for Phase4In {}
impl CJson for Phase4Out {}
