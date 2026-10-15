//! WASM tests for the scalar tweak bindings (`tweakAdd` / `tweakMul`).
//!
//! Run with:
//! ```sh
//! wasm-pack test --node -- --features testing --test tweak
//! ```

use std::collections::BTreeMap;

use libtss::session::dkg::{DkgOutput, DkgSession};
use libtss::types::{Ciphersuite, Identifier, ThresholdConfig};
use libtss::Message;
use libtss_wasm::{tweak_add, tweak_mul, WasmKeyShareHandle};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

const PARTY_ONE: u16 = 1;
const PARTY_TWO: u16 = 2;

fn id(value: u16) -> Identifier {
    Identifier::new(value).unwrap()
}

fn route(
    outputs: &BTreeMap<Identifier, Vec<Message>>,
    recipients: &[Identifier],
) -> BTreeMap<Identifier, Vec<Message>> {
    let mut routed: BTreeMap<Identifier, Vec<Message>> =
        recipients.iter().map(|&r| (r, Vec::new())).collect();
    for (&sender, messages) in outputs {
        for msg in messages {
            match msg.to {
                Some(to) => routed.get_mut(&to).unwrap().push(msg.clone()),
                None => {
                    for &r in recipients {
                        if r != sender {
                            routed.get_mut(&r).unwrap().push(msg.clone());
                        }
                    }
                }
            }
        }
    }
    routed
}

fn run_two_of_two_dkls_dkg() -> (WasmKeyShareHandle, WasmKeyShareHandle) {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 2,
        suite: Ciphersuite::Secp256k1ECDSA,
    };
    let participants = [id(PARTY_ONE), id(PARTY_TWO)];
    let session_id = b"wasm-tweak-test-session";

    let mut sessions = BTreeMap::new();
    let mut phase1 = BTreeMap::new();
    for &pid in &participants {
        let (session, msgs) = DkgSession::new(&config, pid, Some(session_id)).unwrap();
        sessions.insert(pid, session);
        phase1.insert(pid, msgs);
    }

    let mut inbound = route(&phase1, &participants);
    for _ in 0..2 {
        let mut outbound = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(&inbound[&pid])
                .unwrap()
            {
                DkgOutput::Continue(msgs) => {
                    outbound.insert(pid, msgs);
                }
                DkgOutput::Complete { .. } => panic!("expected Continue"),
            }
        }
        inbound = route(&outbound, &participants);
    }

    let mut key_shares = BTreeMap::new();
    for &pid in &participants {
        match sessions
            .get_mut(&pid)
            .unwrap()
            .next(&inbound[&pid])
            .unwrap()
        {
            DkgOutput::Complete { key_share, .. } => {
                key_shares.insert(pid, WasmKeyShareHandle::from(key_share));
            }
            DkgOutput::Continue(_) => panic!("expected Complete"),
        }
    }
    (
        key_shares.remove(&id(PARTY_ONE)).unwrap(),
        key_shares.remove(&id(PARTY_TWO)).unwrap(),
    )
}

fn ed25519_handle() -> WasmKeyShareHandle {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    let (shares, pubkey) = libtss::frost::frost_generate_with_dealer(&config).unwrap();
    let share = shares.into_iter().next().unwrap();
    libtss::keyshare::from_frost_dkg(share, &pubkey)
        .unwrap()
        .into()
}

fn scalar_bytes(value: u64) -> js_sys::Uint8Array {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    js_sys::Uint8Array::from(&bytes[..])
}

fn error_code(result: Result<WasmKeyShareHandle, JsValue>) -> String {
    let err = result.err().expect("tweak must be rejected");
    js_sys::Reflect::get(&err, &JsValue::from_str("code"))
        .unwrap()
        .as_string()
        .unwrap()
}

#[wasm_bindgen_test]
fn tweak_add_moves_both_parties_to_the_same_new_group_key() {
    let (party_one, party_two) = run_two_of_two_dkls_dkg();
    let parent_group_key = party_one.group_verifying_key().to_vec();
    let tweak = scalar_bytes(7);

    let tweaked_one = tweak_add(&party_one, &tweak).unwrap();
    let tweaked_two = tweak_add(&party_two, &tweak).unwrap();

    assert_eq!(
        tweaked_one.group_verifying_key().to_vec(),
        tweaked_two.group_verifying_key().to_vec()
    );
    assert_ne!(tweaked_one.group_verifying_key().to_vec(), parent_group_key);
    assert_eq!(party_one.group_verifying_key().to_vec(), parent_group_key);
    assert_eq!(tweaked_one.identifier(), party_one.identifier());
    assert_eq!(tweaked_one.ciphersuite(), party_one.ciphersuite());
}

#[wasm_bindgen_test]
fn tweak_mul_by_one_keeps_group_key() {
    let (party_one, _) = run_two_of_two_dkls_dkg();

    let tweaked = tweak_mul(&party_one, &scalar_bytes(1)).unwrap();

    assert_eq!(
        tweaked.group_verifying_key().to_vec(),
        party_one.group_verifying_key().to_vec()
    );
    assert_eq!(
        tweaked.verifying_share().to_vec(),
        party_one.verifying_share().to_vec()
    );
}

#[wasm_bindgen_test]
fn tweak_mul_zero_factor_throws_tweak_error() {
    let (party_one, _) = run_two_of_two_dkls_dkg();

    assert_eq!(
        error_code(tweak_mul(&party_one, &scalar_bytes(0))),
        "TweakError"
    );
}

#[wasm_bindgen_test]
fn tweak_rejects_scalar_of_wrong_length() {
    let (party_one, _) = run_two_of_two_dkls_dkg();
    let short = js_sys::Uint8Array::from(&[1u8; 31][..]);

    assert_eq!(error_code(tweak_add(&party_one, &short)), "InvalidConfig");
    assert_eq!(error_code(tweak_mul(&party_one, &short)), "InvalidConfig");
}

#[wasm_bindgen_test]
fn tweak_rejects_frost_key_share() {
    let handle = ed25519_handle();

    assert_eq!(
        error_code(tweak_add(&handle, &scalar_bytes(7))),
        "ProtocolMismatch"
    );
    assert_eq!(
        error_code(tweak_mul(&handle, &scalar_bytes(3))),
        "ProtocolMismatch"
    );
}
