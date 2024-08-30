use crate::utilities::cjson::CJson;
use dkls23::protocols::derivation::ChainCode;
use dkls23::protocols::re_key::re_key;
use dkls23::protocols::{Parameters, Party};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use std::os::raw::c_char;

// Re key structs
#[derive(Deserialize, Serialize)]
pub struct RekeyIn {
    pub parameters: Parameters,
    pub session_id: Vec<u8>,
    pub secret_key: Scalar,
    pub option_chain_code: Option<ChainCode>,
}

#[derive(Deserialize, Serialize)]
pub struct RekeyOut {
    pub parties: Vec<Party>,
}

impl CJson for RekeyIn {}
impl CJson for RekeyOut {}

#[no_mangle]
pub extern "C" fn dkls_re_key(re_key_json_in: *const c_char) -> *const c_char {
    let re_key_in: RekeyIn = RekeyIn::from_json(re_key_json_in);
    let parties = re_key(
        &re_key_in.parameters,
        &re_key_in.session_id,
        &re_key_in.secret_key,
        re_key_in.option_chain_code,
    );
    RekeyOut { parties }.to_json()
}
