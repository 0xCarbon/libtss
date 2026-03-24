use js_sys::Uint8Array;
use libtss::{import_key_share, Ciphersuite, KeyShareHandle};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::map_err;
use crate::secure::SecureKeyShare;

/// A handle to a key share stored in the libtss registry.
///
/// **Security**: This object holds a reference to unencrypted secret key material
/// in the libtss in-memory registry. Do not serialize or expose the handle ID.
/// Call `free()` when done to securely drop the registry entry.
#[wasm_bindgen]
pub struct WasmKeyShareHandle {
    pub(crate) inner: KeyShareHandle,
}

#[wasm_bindgen]
impl WasmKeyShareHandle {
    /// Returns the participant identifier (1-based, non-zero u16).
    #[wasm_bindgen(js_name = "identifier")]
    pub fn identifier(&self) -> u16 {
        self.inner.identifier().as_u16()
    }

    /// Returns the ciphersuite discriminant (0-7).
    ///
    /// - 0: Secp256k1Taproot (FROST)
    /// - 1: Secp256k1 (FROST)
    /// - 2: Ed25519 (FROST)
    /// - 3: P256 (FROST)
    /// - 4: Ristretto255 (FROST)
    /// - 5: Ed448 (FROST)
    /// - 6: Secp256k1ECDSA (DKLs23)
    /// - 7: Secp256r1ECDSA (DKLs23)
    #[wasm_bindgen(js_name = "ciphersuite")]
    pub fn ciphersuite(&self) -> u8 {
        self.inner.ciphersuite() as u8
    }

    /// Returns the protocol discriminant.
    ///
    /// - 0: FROST
    /// - 1: DKLs23
    #[wasm_bindgen(js_name = "protocol")]
    pub fn protocol(&self) -> u8 {
        self.inner.ciphersuite().protocol() as u8
    }

    /// Returns the compressed SEC1-encoded verifying share for this participant.
    #[wasm_bindgen(js_name = "verifyingShare")]
    pub fn verifying_share(&self) -> Uint8Array {
        let bytes = self.inner.verifying_share();
        Uint8Array::from(bytes.as_slice())
    }

    /// Returns the compressed SEC1-encoded group verifying key (the shared public key).
    #[wasm_bindgen(js_name = "groupVerifyingKey")]
    pub fn group_verifying_key(&self) -> Uint8Array {
        let bytes = self.inner.group_verifying_key();
        Uint8Array::from(bytes.as_slice())
    }

    /// Returns the serialized `PublicKeyPackage` containing all verifying shares
    /// and the group key. Suitable for storage or transmission to other participants.
    #[wasm_bindgen(js_name = "publicKeyPackage")]
    pub fn public_key_package(&self) -> Result<Uint8Array, JsValue> {
        let bytes = map_err(self.inner.public_key_package().serialize())?;
        Ok(Uint8Array::from(bytes.as_slice()))
    }

    /// Export the key share as an encrypted-ready binary blob.
    ///
    /// **Security**: The returned `Uint8Array` contains **unencrypted** secret
    /// key material that crosses to the JavaScript heap.
    /// **Prefer `exportShareSecure()`** which keeps plaintext in WASM linear
    /// memory. If you must use this function, encrypt the output immediately
    /// and call `wipeBytes()` on the returned `Uint8Array` as a best-effort
    /// defense-in-depth measure.
    #[wasm_bindgen(js_name = "exportShare")]
    pub fn export_share(&self) -> Result<Uint8Array, JsValue> {
        let bytes = map_err(self.inner.export())?;
        Ok(Uint8Array::from(bytes.as_slice()))
    }

    /// Export the key share as a `SecureKeyShare` — plaintext stays in WASM
    /// linear memory and is zeroed on drop.
    ///
    /// This is the recommended export path for browser environments.
    /// Use `SecureKeyShare.encrypt()` to produce ciphertext safe for
    /// IndexedDB/localStorage persistence.
    #[wasm_bindgen(js_name = "exportShareSecure")]
    pub fn export_share_secure(&self) -> Result<SecureKeyShare, JsValue> {
        SecureKeyShare::from_handle(self)
    }

    /// Import a previously exported key share.
    ///
    /// `data` must be the output of `exportShare()`.
    /// `suite` is the ciphersuite discriminant (0-7) matching the exported share.
    ///
    /// **Security**: `data` must have been decrypted before calling this function.
    /// The input `Uint8Array` is read into WASM linear memory and the JS-side
    /// copy is **not** automatically wiped — call `wipeBytes(data)` after this
    /// function returns.
    #[wasm_bindgen(js_name = "importShare", static_method_of = WasmKeyShareHandle)]
    pub fn import_share(data: &Uint8Array, suite: u8) -> Result<WasmKeyShareHandle, JsValue> {
        let mut bytes = Zeroizing::new(data.to_vec());
        let ciphersuite = map_err(Ciphersuite::try_from(suite))?;
        let handle = map_err(import_key_share(&bytes, ciphersuite))?;
        // `bytes` is zeroed on drop via Zeroizing
        let _ = &mut bytes;
        Ok(WasmKeyShareHandle { inner: handle })
    }

    /// Import from a `SecureKeyShare` — plaintext stays in WASM linear memory.
    ///
    /// This is the recommended import path for browser environments.
    /// Use after `SecureKeyShare.decrypt()` to reconstitute a handle from
    /// encrypted storage.
    #[wasm_bindgen(js_name = "importShareSecure", static_method_of = WasmKeyShareHandle)]
    pub fn import_share_secure(
        secure: &SecureKeyShare,
        suite: u8,
    ) -> Result<WasmKeyShareHandle, JsValue> {
        secure.to_handle(suite)
    }
}

impl From<KeyShareHandle> for WasmKeyShareHandle {
    fn from(inner: KeyShareHandle) -> Self {
        Self { inner }
    }
}
