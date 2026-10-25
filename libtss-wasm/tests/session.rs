//! WASM tests for the session bindings.
//!
//! Run with:
//! ```sh
//! wasm-pack test --node -- --features testing --test session
//! ```

use js_sys::{Array, Reflect, Uint16Array, Uint8Array};
use libtss::frost::frost_generate_with_dealer;
use libtss::keyshare::from_frost_dkg;
use libtss::{serialize_messages, Ciphersuite, Identifier, RefreshSession, ThresholdConfig};
use libtss_wasm::dkls::{dkls_repair_helper_term, dkls_split_key};
use libtss_wasm::message::{message_at, message_build};
use libtss_wasm::session::{WasmDkgSession, WasmRefreshSession, WasmSignSession};
use libtss_wasm::WasmKeyShareHandle;
use libtss_wasm::{derive_child, verify};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::*;

const SUITE_ED25519: u8 = 2;

fn n(value: impl Into<f64>) -> JsValue {
    JsValue::from_f64(value.into())
}

fn is_range_error(err: &JsValue) -> bool {
    err.is_instance_of::<js_sys::RangeError>()
}

fn is_type_error(err: &JsValue) -> bool {
    err.is_instance_of::<js_sys::TypeError>()
}

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
    WasmKeyShareHandle::import_share(&export, n(SUITE_ED25519)).unwrap()
}

#[wasm_bindgen_test]
fn frost_refresh_receiver_accepts_only_the_dealer() {
    let shares = frost_shares();
    let (_, messages) = RefreshSession::new_frost(&shares[0], &[id(1), id(2), id(3)]).unwrap();
    let bundle = Uint8Array::from(serialize_messages(&messages).unwrap().as_slice());
    let party = to_wasm(&shares[1]);

    let err = WasmRefreshSession::create_receiver(&party, n(9))
        .err()
        .unwrap();
    assert_eq!(js_error_code(&err), "InvalidIdentifier");

    let mut wrong = WasmRefreshSession::create_receiver(&party, n(3)).unwrap();
    let err = wrong.next(&bundle).err().unwrap();
    assert_eq!(js_error_code(&err), "Abort");

    let mut receiver = WasmRefreshSession::create_receiver(&party, n(1)).unwrap();
    let result = receiver.next(&bundle).unwrap();
    assert!(result.complete);
    assert!(receiver.is_complete());
}

#[wasm_bindgen_test]
fn dkg_rejects_numbers_that_would_wrap_or_truncate() {
    let create = |suite: JsValue, self_id: JsValue, max: JsValue, min: JsValue| {
        WasmDkgSession::create(suite, self_id, max, min, None).err()
    };
    // 65538 would wrap to 2 and 2.9 would truncate to 2.
    for min in [n(65538), n(2.9), n(-1), n(f64::NAN), n(f64::INFINITY)] {
        let err = create(n(SUITE_ED25519), n(1), n(3), min).unwrap();
        assert!(is_range_error(&err));
    }
    for bad_id in [n(0), n(65536), n(1.5)] {
        assert!(is_range_error(
            &create(n(SUITE_ED25519), bad_id, n(3), n(2)).unwrap()
        ));
    }
    // 258 would wrap to suite 2.
    assert!(is_range_error(&create(n(258), n(1), n(3), n(2)).unwrap()));
    assert!(is_range_error(&create(n(2.5), n(1), n(3), n(2)).unwrap()));
    // Non-numbers are not coerced.
    let err = create(JsValue::from_str("2"), n(1), n(3), n(2)).unwrap();
    assert!(is_type_error(&err));
    let err = create(JsValue::TRUE, n(1), n(3), n(2)).unwrap();
    assert!(is_type_error(&err));
    // Valid numbers still work.
    assert!(create(n(SUITE_ED25519), n(1), n(3), n(2)).is_none());
}

#[wasm_bindgen_test]
fn identifier_arrays_are_checked_element_by_element() {
    let shares = frost_shares();
    let dealer = to_wasm(&shares[0]);
    // A plain array keeps the original value; 65537 would wrap to 1.
    let array = Array::of3(&n(1), &n(2), &n(65537));
    let err = WasmRefreshSession::create_dealer(&dealer, array.into())
        .err()
        .unwrap();
    assert!(is_range_error(&err));
    let array = Array::of3(&n(1), &n(2), &n(2.5));
    let err = WasmRefreshSession::create_dealer(&dealer, array.into())
        .err()
        .unwrap();
    assert!(is_range_error(&err));
    let err = WasmRefreshSession::create_dealer(&dealer, n(3))
        .err()
        .unwrap();
    assert!(is_type_error(&err));
    let ok = Array::of3(&n(1), &n(2), &n(3));
    assert!(WasmRefreshSession::create_dealer(&dealer, ok.into()).is_ok());
    let typed = Uint16Array::from([1u16, 2, 3].as_slice());
    assert!(WasmRefreshSession::create_dealer(&dealer, typed.into()).is_ok());

    let counterparties = Array::of1(&n(65538));
    let err = WasmSignSession::new_dkls(
        &dealer,
        &Uint8Array::from([1u8; 32].as_slice()),
        counterparties.into(),
        &Uint8Array::from([2u8; 32].as_slice()),
    )
    .err()
    .unwrap();
    assert!(is_range_error(&err));

    let helpers = Array::of2(&n(1), &n(65539));
    let err = dkls_repair_helper_term(&dealer, helpers.into(), n(2), b"repair")
        .err()
        .unwrap();
    assert!(is_range_error(&err));
}

#[wasm_bindgen_test]
fn other_entry_points_reject_out_of_range_numbers() {
    let secret = Uint8Array::from([0x42u8; 32].as_slice());
    let err = dkls_split_key(
        n(6),
        &secret,
        &Uint8Array::new_with_length(0),
        n(3),
        n(65538),
    )
    .err()
    .unwrap();
    assert!(is_range_error(&err));

    let shares = frost_shares();
    let share = to_wasm(&shares[0]);
    let err = derive_child(&share, n(2f64.powi(32))).err().unwrap();
    assert!(is_range_error(&err));
    let err = derive_child(&share, n(-1)).err().unwrap();
    assert!(is_range_error(&err));

    let export = Uint8Array::from(shares[0].export().unwrap().as_slice());
    let err = WasmKeyShareHandle::import_share(&export, n(258))
        .err()
        .unwrap();
    assert!(is_range_error(&err));

    let err = verify(
        n(258),
        &Uint8Array::new_with_length(0),
        &Uint8Array::new_with_length(64),
        &Uint8Array::new_with_length(32),
    )
    .err()
    .unwrap();
    assert!(is_range_error(&err));

    let err = message_build(n(65537), n(0), &Uint8Array::new_with_length(1))
        .err()
        .unwrap();
    assert!(is_range_error(&err));
    let err = message_build(n(1), n(65538), &Uint8Array::new_with_length(1))
        .err()
        .unwrap();
    assert!(is_range_error(&err));
    let bundle = message_build(n(1), n(0), &Uint8Array::new_with_length(1)).unwrap();
    assert!(message_at(&bundle, n(0)).is_ok());
    let err = message_at(&bundle, n(0.5)).err().unwrap();
    assert!(is_range_error(&err));
}
