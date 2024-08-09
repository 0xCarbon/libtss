use crate::dkls23::utilities::cjson::CJson;
use dkls23::protocols::derivation::DerivData;
use serde::{Deserialize, Serialize};
use std::os::raw::c_char;

// Derivation structs
#[derive(Deserialize, Serialize)]
pub struct DeriveFromPathIn {
    pub data: DerivData,
    pub path: String,
}

#[derive(Deserialize, Serialize)]
pub struct DeriveFromPathOut {
    pub data: DerivData,
}

// Derivation structs
#[derive(Deserialize, Serialize)]
pub struct DeriveChildIn {
    pub data: DerivData,
    pub child_number: u32,
}

#[derive(Deserialize, Serialize)]
pub struct DeriveChildOut {
    pub data: DerivData,
}

impl CJson for DeriveFromPathIn {}
impl CJson for DeriveFromPathOut {}
impl CJson for DeriveChildIn {}
impl CJson for DeriveChildOut {}

#[no_mangle]
pub extern "C" fn dkls_derive_from_path(
    derive_json_in: *const c_char,
) -> *const c_char {
    let derive_from_path_in: DeriveFromPathIn =
        DeriveFromPathIn::from_json(derive_json_in);
    match derive_from_path_in
        .data
        .derive_from_path(derive_from_path_in.path.as_str())
    {
        Err(error) => {
            panic!("Derivation error: {:?}", error);
        }

        Ok(data) => DeriveFromPathOut { data }.to_json(),
    }
}

#[no_mangle]
pub extern "C" fn dkls_derive_child(
    derive_json_in: *const c_char,
) -> *const c_char {
    let derive_child_in: DeriveChildIn =
        DeriveChildIn::from_json(derive_json_in);
    match derive_child_in
        .data
        .derive_child(derive_child_in.child_number)
    {
        Err(error) => {
            panic!("Derivation error: {:?}", error);
        }

        Ok(data) => DeriveChildOut { data }.to_json(),
    }
}
