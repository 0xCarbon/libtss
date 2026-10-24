//! DKLs23-specific operations: key import, BOLT 3 derivation and share repair.

use js_sys::{Array, Uint8Array};
use libtss::{Ciphersuite, Identifier, PublicKeyPackage, ThresholdConfig};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::map_err;
use crate::handle::WasmKeyShareHandle;
use crate::message::{decode_messages, encode_messages};

fn suite(value: u8) -> Result<Ciphersuite, JsValue> {
    map_err(Ciphersuite::try_from(value))
}

fn identifier(value: u16) -> Result<Identifier, JsValue> {
    map_err(Identifier::new(value))
}

/// Imports an existing ECDSA key as DKLs23 shares (trusted dealer).
///
/// `suite` is 6 (Secp256k1ECDSA) or 7 (Secp256r1ECDSA); `secretKey` is a
/// 32-byte big-endian scalar and is zeroed after the call; `chainCode` is the
/// key's existing 32-byte BIP-32 chain code or empty. The caller holds every
/// share: hand each one to its party, erase the key and the shares, and have
/// the parties run a complete refresh (`WasmRefreshSession.createDkls`).
///
/// Returns `[shares: WasmKeyShareHandle[], publicKeyPackage: Uint8Array]`.
#[wasm_bindgen(js_name = "dklsSplitKey")]
pub fn dkls_split_key(
    suite_id: u8,
    secret_key: &Uint8Array,
    chain_code: &Uint8Array,
    max_signers: u16,
    min_signers: u16,
) -> Result<Array, JsValue> {
    let secret = Zeroizing::new(secret_key.to_vec());
    secret_key.fill(0, 0, secret_key.length());
    let chain_code = chain_code.to_vec();
    let config = ThresholdConfig {
        min_signers,
        max_signers,
        suite: suite(suite_id)?,
    };
    let (handles, public_keys) = map_err(libtss::dkls_import::dkls_split_key(
        &config,
        &secret,
        (!chain_code.is_empty()).then_some(chain_code.as_slice()),
    ))?;
    let shares = Array::new();
    for inner in handles {
        shares.push(&JsValue::from(WasmKeyShareHandle { inner }));
    }
    let result = Array::new();
    result.push(&shares);
    result.push(&Uint8Array::from(map_err(public_keys.serialize())?.as_slice()));
    Ok(result)
}

/// BOLT 3 derivation of a DKLs23 secp256k1 share for a commitment
/// (`basepoint + SHA256(perCommitmentPoint || basepoint)·G`). Every party
/// derives with the same 33-byte compressed point. A derived share keeps the
/// base share's OT state, so a counterparty banned under a derived key is
/// banned for the base key too.
#[wasm_bindgen(js_name = "bolt3Derive")]
pub fn bolt3_derive(
    key_share: &WasmKeyShareHandle,
    per_commitment_point: &[u8],
) -> Result<WasmKeyShareHandle, JsValue> {
    let inner = map_err(libtss::bolt3::bolt3_derive(&key_share.inner, per_commitment_point))?;
    Ok(WasmKeyShareHandle { inner })
}

/// BOLT 3 revocation derivation for a commitment whose 32-byte
/// `perCommitmentSecret` was revealed; the secret must match the point and is
/// zeroed after the call.
#[wasm_bindgen(js_name = "bolt3DeriveRevocation")]
pub fn bolt3_derive_revocation(
    key_share: &WasmKeyShareHandle,
    per_commitment_point: &[u8],
    per_commitment_secret: &Uint8Array,
) -> Result<WasmKeyShareHandle, JsValue> {
    let secret = Zeroizing::new(per_commitment_secret.to_vec());
    per_commitment_secret.fill(0, 0, per_commitment_secret.length());
    let inner = map_err(libtss::bolt3::bolt3_derive_revocation(
        &key_share.inner,
        per_commitment_point,
        &secret,
    ))?;
    Ok(WasmKeyShareHandle { inner })
}

/// `bolt3Derive` on a serialized secp256k1 ECDSA public key package.
#[wasm_bindgen(js_name = "bolt3DerivePublicKeys")]
pub fn bolt3_derive_public_keys(
    public_keys: &[u8],
    per_commitment_point: &[u8],
) -> Result<Uint8Array, JsValue> {
    let package = map_err(PublicKeyPackage::deserialize(public_keys))?;
    let derived = map_err(libtss::bolt3::bolt3_derive_public_keys(
        &package,
        per_commitment_point,
    ))?;
    Ok(Uint8Array::from(map_err(derived.serialize())?.as_slice()))
}

/// `bolt3DeriveRevocation` on a public key package (no secret needed).
#[wasm_bindgen(js_name = "bolt3DeriveRevocationPublicKeys")]
pub fn bolt3_derive_revocation_public_keys(
    public_keys: &[u8],
    per_commitment_point: &[u8],
) -> Result<Uint8Array, JsValue> {
    let package = map_err(PublicKeyPackage::deserialize(public_keys))?;
    let derived = map_err(libtss::bolt3::bolt3_derive_revocation_public_keys(
        &package,
        per_commitment_point,
    ))?;
    Ok(Uint8Array::from(map_err(derived.serialize())?.as_slice()))
}

/// This helper's DKLs23 repair term for `target`, as an encoded message
/// blob to send to the target only, over a confidential, authenticated
/// channel. `helpers` lists the helper identifiers (no duplicates, at least
/// `minSigners`, including this party, not the target). The helpers must
/// authenticate the target: repair hands index `target`'s share to whoever
/// receives the terms.
#[wasm_bindgen(js_name = "dklsRepairHelperTerm")]
pub fn dkls_repair_helper_term(
    key_share: &WasmKeyShareHandle,
    helpers: &[u16],
    target: u16,
    repair_id: &[u8],
) -> Result<Uint8Array, JsValue> {
    let helpers = helpers
        .iter()
        .map(|&h| identifier(h))
        .collect::<Result<Vec<_>, _>>()?;
    let message = map_err(libtss::dkls_repair::repair_helper_term(
        &key_share.inner,
        &helpers,
        identifier(target)?,
        repair_id,
    ))?;
    encode_messages(&[message])
}

/// Assembles the helpers' repair messages (an encoded message blob) into the
/// target's repaired DKLs23 share. Each message's `from` must be its
/// authenticated sender. The share cannot sign until all parties run
/// `WasmRefreshSession.createDkls`.
#[wasm_bindgen(js_name = "dklsRepairAssemble")]
pub fn dkls_repair_assemble(
    suite_id: u8,
    public_keys: &[u8],
    target: u16,
    messages: &Uint8Array,
) -> Result<WasmKeyShareHandle, JsValue> {
    let package = map_err(PublicKeyPackage::deserialize(public_keys))?;
    let received = decode_messages(messages)?;
    let inner = map_err(libtss::dkls_repair::repair_assemble(
        suite(suite_id)?,
        &package,
        identifier(target)?,
        &received,
    ))?;
    Ok(WasmKeyShareHandle { inner })
}
