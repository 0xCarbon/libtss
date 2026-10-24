//! WASM tests for the session bindings.
//!
//! Run with:
//! ```sh
//! wasm-pack test --node -- --features testing --test session
//! ```

use js_sys::{Reflect, Uint8Array};
use libtss::frost::frost_generate_with_dealer;
use libtss::keyshare::from_frost_dkg;
use libtss::{serialize_messages, Ciphersuite, Identifier, RefreshSession, ThresholdConfig};
use libtss_wasm::session::WasmRefreshSession;
use libtss_wasm::WasmKeyShareHandle;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

const SUITE_ED25519: u8 = 2;

fn id(value: u16) -> Identifier {
    Identifier::new(value).unwrap()
}

fn js_error_code(err: &JsValue) -> String {
    Reflect::get(err, &JsValue::from_str("code"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

fn frost_shares() -> Vec<libtss::KeyShareHandle> {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    let (shares, pubkey) = frost_generate_with_dealer(&config).unwrap();
    shares
        .into_iter()
        .map(|share| from_frost_dkg(share, &pubkey).unwrap())
        .collect()
}

fn to_wasm(handle: &libtss::KeyShareHandle) -> WasmKeyShareHandle {
    let export = Uint8Array::from(handle.export().unwrap().as_slice());
    WasmKeyShareHandle::import_share(&export, SUITE_ED25519).unwrap()
}

#[wasm_bindgen_test]
fn frost_refresh_receiver_accepts_only_the_dealer() {
    let shares = frost_shares();
    let (_, messages) = RefreshSession::new_frost(&shares[0], &[id(1), id(2), id(3)]).unwrap();
    let bundle = Uint8Array::from(serialize_messages(&messages).unwrap().as_slice());
    let party = to_wasm(&shares[1]);

    let err = WasmRefreshSession::create_receiver(&party, 9)
        .err()
        .unwrap();
    assert_eq!(js_error_code(&err), "InvalidIdentifier");

    let mut wrong = WasmRefreshSession::create_receiver(&party, 3).unwrap();
    let err = wrong.next(&bundle).err().unwrap();
    assert_eq!(js_error_code(&err), "Abort");

    let mut receiver = WasmRefreshSession::create_receiver(&party, 1).unwrap();
    let result = receiver.next(&bundle).unwrap();
    assert!(result.complete);
    assert!(receiver.is_complete());
}
