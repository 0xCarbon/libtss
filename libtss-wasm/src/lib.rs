//! `libtss-wasm` — WebAssembly bindings for the libtss threshold signing library.
//!
//! Build with:
//! ```sh
//! wasm-pack build --target web
//! ```
//!
//! # Ciphersuite constants
//!
//! | Value | Name                | Protocol |
//! |-------|---------------------|----------|
//! |   0   | Secp256k1Taproot    | FROST    |
//! |   1   | Secp256k1           | FROST    |
//! |   2   | Ed25519             | FROST    |
//! |   3   | P256                | FROST    |
//! |   4   | Ristretto255        | FROST    |
//! |   5   | Ed448               | FROST    |
//! |   6   | Secp256k1ECDSA      | DKLs23   |
//! |   7   | Secp256r1ECDSA      | DKLs23   |

pub mod address;
pub mod derive;
pub mod error;
pub mod handle;
pub mod message;
pub mod secure;
pub mod session;

// Re-export all public wasm-bindgen items so wasm-pack finds them.
pub use address::{
    bitcoin_address, bitcoin_address_hrp, cosmos_address, cosmos_address_hrp, ethereum_address,
    neo3_address, sui_r1_address, tron_address,
};
pub use derive::{derive_child, derive_path};
pub use handle::WasmKeyShareHandle;
pub use message::{message_at, message_build, message_count, messages_concat, WasmMessage};
pub use secure::{wipe_bytes, SecureKeyShare};
pub use session::{
    WasmDkgResult, WasmDkgSession, WasmRefreshResult, WasmRefreshSession, WasmSignResult,
    WasmSignSession,
};

use js_sys::Uint8Array;
use libtss::Ciphersuite;
use wasm_bindgen::prelude::*;

use crate::error::map_err;

// ─── Ciphersuite constants ────────────────────────────────────────────────────

pub const SUITE_SECP256K1_TAPROOT: u8 = 0;
pub const SUITE_SECP256K1: u8 = 1;
pub const SUITE_ED25519: u8 = 2;
pub const SUITE_P256: u8 = 3;
pub const SUITE_RISTRETTO255: u8 = 4;
pub const SUITE_ED448: u8 = 5;
pub const SUITE_SECP256K1_ECDSA: u8 = 6;
pub const SUITE_SECP256R1_ECDSA: u8 = 7;

pub const PROTOCOL_FROST: u8 = 0;
pub const PROTOCOL_DKLS23: u8 = 1;

// Accessor functions for JS (wasm-bindgen cannot export const directly).
// wasm-bindgen auto-generates correct TypeScript declarations for these.

#[wasm_bindgen(js_name = "SUITE_SECP256K1_TAPROOT")]
pub fn suite_secp256k1_taproot() -> u8 { SUITE_SECP256K1_TAPROOT }
#[wasm_bindgen(js_name = "SUITE_SECP256K1")]
pub fn suite_secp256k1() -> u8 { SUITE_SECP256K1 }
#[wasm_bindgen(js_name = "SUITE_ED25519")]
pub fn suite_ed25519() -> u8 { SUITE_ED25519 }
#[wasm_bindgen(js_name = "SUITE_P256")]
pub fn suite_p256() -> u8 { SUITE_P256 }
#[wasm_bindgen(js_name = "SUITE_RISTRETTO255")]
pub fn suite_ristretto255() -> u8 { SUITE_RISTRETTO255 }
#[wasm_bindgen(js_name = "SUITE_ED448")]
pub fn suite_ed448() -> u8 { SUITE_ED448 }
#[wasm_bindgen(js_name = "SUITE_SECP256K1_ECDSA")]
pub fn suite_secp256k1_ecdsa() -> u8 { SUITE_SECP256K1_ECDSA }
#[wasm_bindgen(js_name = "SUITE_SECP256R1_ECDSA")]
pub fn suite_secp256r1_ecdsa() -> u8 { SUITE_SECP256R1_ECDSA }
#[wasm_bindgen(js_name = "PROTOCOL_FROST")]
pub fn protocol_frost() -> u8 { PROTOCOL_FROST }
#[wasm_bindgen(js_name = "PROTOCOL_DKLS23")]
pub fn protocol_dkls23() -> u8 { PROTOCOL_DKLS23 }

// ─── Utility functions ────────────────────────────────────────────────────────

/// Verify a signature against a message and compressed SEC1 public key.
///
/// - `suite`: ciphersuite discriminant (0-7)
/// - `message`: the message bytes (raw, not pre-hashed) for all FROST suites;
///   for `Secp256k1ECDSA` (6) this is also the raw message (SHA-256 hashed internally)
/// - `signature`: the signature bytes in the ciphersuite's canonical format
/// - `publicKey`: compressed SEC1-encoded public key bytes
///
/// Returns `true` if the signature is valid, `false` otherwise.
/// Throws a `TssError` if inputs are malformed.
#[wasm_bindgen]
pub fn verify(
    suite: u8,
    message: &Uint8Array,
    signature: &Uint8Array,
    public_key: &Uint8Array,
) -> Result<bool, JsValue> {
    let ciphersuite = map_err(Ciphersuite::try_from(suite))?;
    let msg = message.to_vec();
    let sig = signature.to_vec();
    let pk = public_key.to_vec();
    map_err(libtss::verify(ciphersuite, &msg, &sig, &pk))
}

/// Returns the version string of the libtss-wasm crate.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ─── WASM module initializer ──────────────────────────────────────────────────

/// Called automatically by the generated JS glue on module load.
/// Installs a panic hook that forwards Rust panics to `console.error`.
#[wasm_bindgen(start)]
pub fn start() {
    // Forward Rust panics to browser console for debugging.
    // In production builds this call is a no-op if the panic-hook feature is absent.
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
