//! WASM tests for the DKLs23 key import, BOLT 3 derivation, share repair and
//! complete refresh bindings.
//!
//! Run with:
//! ```sh
//! wasm-pack test --node -- --features testing --test dkls
//! ```

use js_sys::{Array, Uint8Array};
use libtss::dkls_import::dkls_split_key;
use libtss::{Ciphersuite, KeyShareHandle, ThresholdConfig};
use libtss_wasm::dkls::{
    bolt3_derive, bolt3_derive_public_keys, dkls_repair_assemble, dkls_repair_helper_term,
    dkls_split_key as wasm_split_key,
};
use libtss_wasm::session::WasmRefreshSession;
use libtss_wasm::WasmKeyShareHandle;
use wasm_bindgen_test::*;

const SUITE_K1: u8 = 6;

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn shares(secret: &[u8]) -> (Vec<KeyShareHandle>, Vec<u8>) {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Secp256k1ECDSA,
    };
    let (handles, package) = dkls_split_key(&config, secret, None).unwrap();
    (handles, package.serialize().unwrap())
}

fn to_wasm(handle: &KeyShareHandle) -> WasmKeyShareHandle {
    let export = Uint8Array::from(handle.export().unwrap().as_slice());
    WasmKeyShareHandle::import_share(&export, SUITE_K1).unwrap()
}

#[wasm_bindgen_test]
fn split_key_returns_shares_and_wipes_the_secret() {
    let secret = Uint8Array::from([0x42u8; 32].as_slice());
    let result = wasm_split_key(SUITE_K1, &secret, &Uint8Array::new_with_length(0), 3, 2).unwrap();
    assert_eq!(result.length(), 2);
    assert_eq!(Array::from(&result.get(0)).length(), 3);
    assert!(secret.to_vec().iter().all(|&b| b == 0));
}

#[wasm_bindgen_test]
fn bolt3_matches_the_bolt3_vector() {
    let (handles, package) =
        shares(&hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    let point = hex("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
    let expected = hex("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5");
    let derived = bolt3_derive(&to_wasm(&handles[0]), &point).unwrap();
    assert_eq!(derived.group_verifying_key().to_vec(), expected);
    let derived_package = bolt3_derive_public_keys(&package, &point).unwrap().to_vec();
    assert_eq!(
        libtss::PublicKeyPackage::deserialize(&derived_package)
            .unwrap()
            .verifying_key(),
        expected.as_slice()
    );
}

#[wasm_bindgen_test]
fn repair_rebuilds_a_lost_share() {
    let (handles, package) = shares(&[0x42u8; 32]);
    let helpers = [1u16, 3];
    let mut blob = Vec::new();
    for i in [0usize, 2] {
        let term = dkls_repair_helper_term(&to_wasm(&handles[i]), &helpers, 2, b"wasm-repair").unwrap();
        blob.extend(term.to_vec());
    }
    let repaired =
        dkls_repair_assemble(SUITE_K1, &package, 2, &Uint8Array::from(blob.as_slice())).unwrap();
    assert_eq!(repaired.verifying_share().to_vec(), handles[1].verifying_share());
    assert!(dkls_repair_assemble(SUITE_K1, &package, 2, &Uint8Array::from(&blob[..10])).is_err());
}

#[wasm_bindgen_test]
fn dkls_refresh_session_starts_and_rejects_an_empty_id() {
    let (handles, _) = shares(&[0x42u8; 32]);
    let started = WasmRefreshSession::create_dkls(&to_wasm(&handles[0]), b"wasm-refresh").unwrap();
    assert_eq!(started.length(), 2);
    assert!(WasmRefreshSession::create_dkls(&to_wasm(&handles[0]), b"").is_err());
}
