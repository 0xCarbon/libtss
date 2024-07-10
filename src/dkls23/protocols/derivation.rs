use crate::dkls23::utilities::cjson::CJson;
use dkls23::protocols::derivation::DerivData;
use serde::{Deserialize, Serialize};
use std::os::raw::c_char;

// Derivation structs
#[derive(Deserialize, Serialize)]
pub struct DerivationIn {
    pub data: DerivData,
    pub path: String,
}

#[derive(Deserialize, Serialize)]
pub struct DerivationOut {
    pub data: DerivData,
}

impl CJson for DerivationIn {}
impl CJson for DerivationOut {}

#[no_mangle]
pub extern "C" fn dkls_derivation(
    derivation_json_in: *const c_char,
) -> *const c_char {
    let derivation_in: DerivationIn =
        DerivationIn::from_json(derivation_json_in);
    match derivation_in
        .data
        .derive_from_path(derivation_in.path.as_str())
    {
        Err(error) => {
            panic!("Derivation error: {:?}", error);
        }

        Ok(data) => DerivationOut { data }.to_json(),
    }
}
