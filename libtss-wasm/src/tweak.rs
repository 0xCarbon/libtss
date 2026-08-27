use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::error::map_err;
use crate::handle::WasmKeyShareHandle;

/// Return a key share whose secret is `secret + tweak (mod n)`.
///
/// `tweak` is a 32-byte big-endian scalar, reduced mod n — the convention of
/// btcec's `ModNScalar` and therefore of LND's per-commitment "single" tweak.
/// The public key, BIP-32 derivation data, address and every verifying share
/// of the public key package are moved by the same map, so a threshold set of
/// tweaked shares signs under the tweaked group key. Every party must apply
/// the same tweak before signing. A zero tweak is a no-op.
///
/// This is a plain scalar tweak on DKLs23 ECDSA shares; it is distinct from
/// BIP-341 Taproot tweaking of FROST shares, which is not exposed here.
///
/// Supported ciphersuites:
/// - 6 (`Secp256k1ECDSA`, DKLs23)
/// - 7 (`Secp256r1ECDSA`, DKLs23)
///
/// Throws a `TssError` whose `code` is:
/// - `InvalidConfig` when `tweak` is not exactly 32 bytes
/// - `TweakError` when the tweaked public key would be the identity point
/// - `ProtocolMismatch` for any other ciphersuite
///
/// Returns a new `WasmKeyShareHandle`. The parent handle is not consumed and
/// stays valid.
#[wasm_bindgen(js_name = "tweakAdd")]
pub fn tweak_add(
    key_share: &WasmKeyShareHandle,
    tweak: &Uint8Array,
) -> Result<WasmKeyShareHandle, JsValue> {
    let tweaked = map_err(libtss::tweak_add(&key_share.inner, &tweak.to_vec()))?;
    Ok(WasmKeyShareHandle { inner: tweaked })
}

/// Return a key share whose secret is `secret * factor (mod n)`.
///
/// `factor` is a 32-byte big-endian scalar, reduced mod n. It is the building
/// block of LND's revocation ("double") tweak. A factor of one is a no-op.
/// Ciphersuite support, the moved public data and the distinction from
/// BIP-341 Taproot tweaking match `tweakAdd`.
///
/// Throws a `TssError` whose `code` is:
/// - `InvalidConfig` when `factor` is not exactly 32 bytes
/// - `TweakError` when `factor` reduces to zero, which would destroy the key
/// - `ProtocolMismatch` for any other ciphersuite
///
/// Returns a new `WasmKeyShareHandle`. The parent handle is not consumed and
/// stays valid.
#[wasm_bindgen(js_name = "tweakMul")]
pub fn tweak_mul(
    key_share: &WasmKeyShareHandle,
    factor: &Uint8Array,
) -> Result<WasmKeyShareHandle, JsValue> {
    let tweaked = map_err(libtss::tweak_mul(&key_share.inner, &factor.to_vec()))?;
    Ok(WasmKeyShareHandle { inner: tweaked })
}
