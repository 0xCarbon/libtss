//! WASM tests for `WasmKeyShareHandle`.
//!
//! Run with:
//! ```sh
//! wasm-pack test --node --test handle
//! ```
//!
//! These tests drive the protocols through the crate's own Rust API and only
//! cross the JS boundary at the `WasmKeyShareHandle` surface, so they need no
//! browser and run under Node.js.

use std::collections::BTreeMap;

use libtss::frost::frost_generate_with_dealer;
use libtss::keyshare::from_frost_dkg;
use libtss::{
    Ciphersuite, DkgOutput, DkgSession, Identifier, KeyShareHandle, Message, ThresholdConfig,
};
use libtss_wasm::WasmKeyShareHandle;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

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

fn run_dkls_dkg(min_signers: u16, max_signers: u16) -> BTreeMap<Identifier, KeyShareHandle> {
    let config = ThresholdConfig {
        min_signers,
        max_signers,
        suite: Ciphersuite::Secp256k1ECDSA,
    };
    let participants: Vec<Identifier> = (1..=max_signers).map(id).collect();
    let session_id = b"wasm-handle-chain-code";

    let mut sessions = BTreeMap::new();
    let mut phase1 = BTreeMap::new();
    for &pid in &participants {
        let (session, msgs) = DkgSession::new(&config, pid, Some(session_id)).unwrap();
        sessions.insert(pid, session);
        phase1.insert(pid, msgs);
    }

    // DKLs23 DKG: three Continue rounds followed by Complete.
    let mut prev = route(&phase1, &participants);
    for _ in 0..2 {
        let mut out = BTreeMap::new();
        for &pid in &participants {
            match sessions
                .get_mut(&pid)
                .unwrap()
                .next(prev.get(&pid).unwrap())
                .unwrap()
            {
                DkgOutput::Continue(msgs) => {
                    out.insert(pid, msgs);
                }
                DkgOutput::Complete { .. } => panic!("expected Continue"),
            }
        }
        prev = route(&out, &participants);
    }

    let mut results = BTreeMap::new();
    for &pid in &participants {
        match sessions
            .get_mut(&pid)
            .unwrap()
            .next(prev.get(&pid).unwrap())
            .unwrap()
        {
            DkgOutput::Complete { key_share, .. } => {
                results.insert(pid, key_share);
            }
            DkgOutput::Continue(_) => panic!("expected Complete"),
        }
    }
    results
}

fn js_error_code(err: &JsValue) -> String {
    js_sys::Reflect::get(err, &JsValue::from_str("code"))
        .expect("error object has a `code` property")
        .as_string()
        .expect("`code` is a string")
}

// ─── chainCode ──────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn chain_code_is_32_bytes_and_shared_across_dkls_parties() {
    let handles = run_dkls_dkg(2, 2);
    assert_eq!(handles.len(), 2);

    let chain_codes: Vec<Vec<u8>> = handles
        .into_values()
        .map(|handle| {
            WasmKeyShareHandle::from(handle)
                .chain_code()
                .expect("Secp256k1ECDSA exposes a chain code")
                .to_vec()
        })
        .collect();

    assert_eq!(chain_codes[0].len(), 32, "chain code must be 32 bytes");
    assert_eq!(
        chain_codes[0], chain_codes[1],
        "both DKG parties must agree on the chain code"
    );
    assert!(
        chain_codes[0].iter().any(|&b| b != 0),
        "chain code must not be all zeros"
    );
}

#[wasm_bindgen_test]
fn chain_code_rejects_ed25519_with_protocol_mismatch() {
    let config = ThresholdConfig {
        min_signers: 2,
        max_signers: 3,
        suite: Ciphersuite::Ed25519,
    };
    let (shares, pubkey) = frost_generate_with_dealer(&config).unwrap();
    let frost_handle = shares.into_iter().next().unwrap();
    let handle = WasmKeyShareHandle::from(from_frost_dkg(frost_handle, &pubkey).unwrap());

    let err = handle
        .chain_code()
        .expect_err("Ed25519 has no BIP-32 chain code");

    assert_eq!(js_error_code(&err), "ProtocolMismatch");
}
