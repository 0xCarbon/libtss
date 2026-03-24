use wasm_bindgen::prelude::*;

use crate::error::map_err;
use crate::handle::WasmKeyShareHandle;

/// Returns the Ethereum checksummed address derived from a DKLs23 secp256k1 key share.
///
/// Only valid for ciphersuite 6 (`Secp256k1ECDSA`). Throws for other suites.
/// Returns a `0x`-prefixed 42-character EIP-55 checksummed hex address.
#[wasm_bindgen(js_name = "ethereumAddress")]
pub fn ethereum_address(key_share: &WasmKeyShareHandle) -> Result<String, JsValue> {
    map_err(libtss::ethereum_address(&key_share.inner))
}

/// Returns the Bitcoin P2WPKH mainnet address derived from a DKLs23 secp256k1 key share.
///
/// Only valid for ciphersuite 6 (`Secp256k1ECDSA`). Throws for other suites.
/// Returns a `bc1q`-prefixed Bech32 segwit v0 address.
#[wasm_bindgen(js_name = "bitcoinAddress")]
pub fn bitcoin_address(key_share: &WasmKeyShareHandle) -> Result<String, JsValue> {
    map_err(libtss::bitcoin_address(&key_share.inner))
}

/// Returns the Bitcoin P2WPKH address with a custom HRP.
///
/// Only valid for ciphersuite 6 (`Secp256k1ECDSA`). Throws for other suites.
///
/// Common values for `hrp`:
/// - `"bc"` — Bitcoin mainnet
/// - `"tb"` — Bitcoin testnet / signet
/// - `"ltc"` — Litecoin mainnet
#[wasm_bindgen(js_name = "bitcoinAddressHrp")]
pub fn bitcoin_address_hrp(key_share: &WasmKeyShareHandle, hrp: String) -> Result<String, JsValue> {
    map_err(libtss::bitcoin_address_hrp(&key_share.inner, &hrp))
}

/// Returns the Cosmos address derived from a DKLs23 secp256k1 key share.
///
/// Only valid for ciphersuite 6 (`Secp256k1ECDSA`). Throws for other suites.
/// Returns a `cosmos1`-prefixed Bech32 address.
#[wasm_bindgen(js_name = "cosmosAddress")]
pub fn cosmos_address(key_share: &WasmKeyShareHandle) -> Result<String, JsValue> {
    map_err(libtss::cosmos_address(&key_share.inner))
}

/// Returns the Cosmos address with a custom Bech32 HRP.
///
/// Only valid for ciphersuite 6 (`Secp256k1ECDSA`). Throws for other suites.
///
/// Common values for `hrp`:
/// - `"cosmos"` — Cosmos Hub
/// - `"osmo"` — Osmosis
/// - `"juno"` — Juno
/// - `"inj"` — Injective
#[wasm_bindgen(js_name = "cosmosAddressHrp")]
pub fn cosmos_address_hrp(
    key_share: &WasmKeyShareHandle,
    hrp: String,
) -> Result<String, JsValue> {
    map_err(libtss::cosmos_address_hrp(&key_share.inner, &hrp))
}

/// Returns the TRON address derived from a DKLs23 secp256k1 key share.
///
/// Only valid for ciphersuite 6 (`Secp256k1ECDSA`). Throws for other suites.
/// Returns a Base58Check address starting with `'T'`.
#[wasm_bindgen(js_name = "tronAddress")]
pub fn tron_address(key_share: &WasmKeyShareHandle) -> Result<String, JsValue> {
    map_err(libtss::tron_address(&key_share.inner))
}

/// Returns the NEO N3 address derived from a DKLs23 secp256r1 key share.
///
/// Only valid for ciphersuite 7 (`Secp256r1ECDSA`). Throws for other suites.
/// Returns a Base58Check address starting with `'N'`.
#[wasm_bindgen(js_name = "neo3Address")]
pub fn neo3_address(key_share: &WasmKeyShareHandle) -> Result<String, JsValue> {
    map_err(libtss::neo3_address(&key_share.inner))
}

/// Returns the Sui secp256r1 address derived from a DKLs23 secp256r1 key share.
///
/// Only valid for ciphersuite 7 (`Secp256r1ECDSA`). Throws for other suites.
/// Returns a `0x`-prefixed 66-character hex address.
#[wasm_bindgen(js_name = "suiR1Address")]
pub fn sui_r1_address(key_share: &WasmKeyShareHandle) -> Result<String, JsValue> {
    map_err(libtss::sui_r1_address(&key_share.inner))
}
