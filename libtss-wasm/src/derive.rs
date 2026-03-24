use wasm_bindgen::prelude::*;

use crate::error::map_err;
use crate::handle::WasmKeyShareHandle;

/// Derive a child key share using non-hardened BIP-32 derivation.
///
/// Supported ciphersuites:
/// - 6 (`Secp256k1ECDSA`, DKLs23): delegates to the upstream DKLs23 derivation
/// - 7 (`Secp256r1ECDSA`, DKLs23): delegates to the upstream DKLs23-r1 derivation
/// - 0 (`Secp256k1Taproot`, FROST): HMAC-SHA512 tweak-based derivation
///
/// `childNumber` must be a non-hardened index (0 – 2^31 – 1).
/// Hardened indexes (≥ 2^31) will return an error.
///
/// Returns a new `WasmKeyShareHandle` for the child key. The parent handle is
/// not consumed — you may derive multiple children from the same parent.
#[wasm_bindgen(js_name = "deriveChild")]
pub fn derive_child(
    key_share: &WasmKeyShareHandle,
    child_number: u32,
) -> Result<WasmKeyShareHandle, JsValue> {
    let child = map_err(libtss::derive_child(&key_share.inner, child_number))?;
    Ok(WasmKeyShareHandle { inner: child })
}

/// Derive a key share along a BIP-32 path string.
///
/// Supported ciphersuites: same as `deriveChild` (6, 7, 0).
///
/// `path` must be a valid non-hardened BIP-32 path, e.g. `"m/44/60/0/0"`.
/// Hardened segments (e.g. `"m/44'/0'"`) are rejected with an error.
///
/// Returns a new `WasmKeyShareHandle` for the derived key.
#[wasm_bindgen(js_name = "derivePath")]
pub fn derive_path(key_share: &WasmKeyShareHandle, path: String) -> Result<WasmKeyShareHandle, JsValue> {
    let child = map_err(libtss::derive_path(&key_share.inner, &path))?;
    Ok(WasmKeyShareHandle { inner: child })
}
