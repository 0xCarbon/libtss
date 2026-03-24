//! Secure key share handling — keeps plaintext in WASM linear memory.
//!
//! `SecureKeyShare` wraps exported key share bytes in `Zeroizing<Vec<u8>>` so
//! plaintext is kept in WASM linear memory rather than being exposed to
//! application-level JavaScript. Encryption and decryption use the Web Crypto
//! API (AES-256-GCM via `SubtleCrypto`) through `web_sys` bindings.
//!
//! # Security Model
//!
//! - **WASM linear memory** is zeroed on drop via `Zeroizing` (volatile write
//!   + compiler fence — honoured by wasm-opt).
//! - **Browser sandbox**: `mlock`/`mprotect` are not available. WASM linear
//!   memory reduces accidental plaintext exposure in cooperative application
//!   code but does **not** defend against arbitrary same-origin script execution.
//! - **Web Crypto `CryptoKey`** objects are non-extractable by default — the
//!   wrapping key cannot be read by JavaScript.
//! - **Ciphertext only** is returned to application JS: `encrypt()` returns a
//!   `Uint8Array` of `iv || ciphertext || tag` safe for IndexedDB/localStorage.
//!
//! # Residual Exposure
//!
//! - **Encrypt**: `wasm-bindgen` passes `&[u8]` as a typed-array *view* into
//!   WASM linear memory (no application-level JS copy), but the browser's
//!   WebCrypto implementation may internally buffer the plaintext.
//! - **Decrypt**: Web Crypto returns plaintext as a JS `ArrayBuffer`. This is
//!   immediately copied into `Zeroizing<Vec<u8>>` and the typed-array view is
//!   best-effort zeroed. The underlying `ArrayBuffer` may persist until GC'd.
//! - These transient browser-internal copies are unavoidable when using the
//!   Web Crypto API. The guarantees here are best-effort defense-in-depth.

use js_sys::Uint8Array;
use libtss::{import_key_share, Ciphersuite};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

use crate::error::map_err;
use crate::handle::WasmKeyShareHandle;

/// AES-GCM initialization vector length in bytes (96 bits, NIST recommendation).
const AES_GCM_IV_LEN: usize = 12;

/// An opaque wrapper around an exported key share whose plaintext is held
/// in WASM linear memory. The inner `Vec<u8>` is zeroed on drop.
///
/// Use `encrypt()` to produce ciphertext safe for JS-side persistence and
/// `decrypt()` to reconstitute from ciphertext. Application-level JavaScript
/// never handles the plaintext directly, though the browser's Web Crypto
/// implementation may internally buffer data during encrypt/decrypt operations
/// (see module-level documentation for details).
#[wasm_bindgen]
pub struct SecureKeyShare {
    data: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl SecureKeyShare {
    /// Create a `SecureKeyShare` from an existing `WasmKeyShareHandle`.
    ///
    /// The key share is exported (serialized) and stored in WASM linear memory
    /// wrapped in `Zeroizing<Vec<u8>>`. The handle remains valid after this call.
    #[wasm_bindgen(js_name = "fromHandle")]
    pub fn from_handle(handle: &WasmKeyShareHandle) -> Result<SecureKeyShare, JsValue> {
        let data = map_err(handle.inner.export())?;
        Ok(SecureKeyShare {
            data: Zeroizing::new(data),
        })
    }

    /// Encrypt the key share using AES-256-GCM via Web Crypto.
    ///
    /// Returns `iv || ciphertext || tag` as a `Uint8Array`. The plaintext
    /// is passed to Web Crypto as a view into WASM linear memory (no
    /// application-level JS copy), though the browser may internally buffer it.
    ///
    /// `key` must be an AES-GCM `CryptoKey` with the `encrypt` usage.
    #[wasm_bindgen]
    pub async fn encrypt(&self, key: &web_sys::CryptoKey) -> Result<Uint8Array, JsValue> {
        let subtle = get_subtle_crypto()?;

        // Generate a fresh 96-bit IV using Web Crypto.
        let iv = generate_iv()?;

        // Build the AES-GCM algorithm descriptor.
        let algorithm = build_aes_gcm_params(&iv)?;

        // Pass plaintext as a slice — wasm-bindgen creates a typed-array view
        // into WASM linear memory (no application-level JS copy).
        let promise =
            subtle.encrypt_with_object_and_u8_array(&algorithm, key, &self.data)?;
        let result = JsFuture::from(promise).await?;

        // result is an ArrayBuffer containing ciphertext || tag.
        let ct_buf = Uint8Array::new(&result);
        let ct_len = ct_buf.length() as usize;

        // Prepend the IV: output = iv (12 bytes) || ciphertext || tag.
        let mut output = vec![0u8; AES_GCM_IV_LEN + ct_len];
        output[..AES_GCM_IV_LEN].copy_from_slice(&iv);
        ct_buf.copy_to(&mut output[AES_GCM_IV_LEN..]);

        Ok(Uint8Array::from(output.as_slice()))
    }

    /// Decrypt ciphertext produced by `encrypt()` and return a new `SecureKeyShare`.
    ///
    /// `ciphertext` must be the `iv || ciphertext || tag` blob returned by `encrypt()`.
    /// The decrypted plaintext is copied from the Web Crypto result `ArrayBuffer`
    /// into `Zeroizing<Vec<u8>>` in WASM linear memory, then the JS-side view is
    /// best-effort zeroed. The underlying `ArrayBuffer` may persist until GC'd.
    ///
    /// `key` must be an AES-GCM `CryptoKey` with the `decrypt` usage.
    #[wasm_bindgen]
    pub async fn decrypt(
        ciphertext: &Uint8Array,
        key: &web_sys::CryptoKey,
    ) -> Result<SecureKeyShare, JsValue> {
        let ct_bytes = ciphertext.to_vec();
        if ct_bytes.len() < AES_GCM_IV_LEN + 1 {
            return Err(JsValue::from_str(
                "ciphertext too short (must be at least IV + 1 byte)",
            ));
        }

        let subtle = get_subtle_crypto()?;

        let iv = &ct_bytes[..AES_GCM_IV_LEN];
        let encrypted = &ct_bytes[AES_GCM_IV_LEN..];

        // Build the AES-GCM algorithm descriptor.
        let algorithm = build_aes_gcm_params(iv)?;

        let promise =
            subtle.decrypt_with_object_and_u8_array(&algorithm, key, encrypted)?;
        let result = JsFuture::from(promise).await?;

        // result is an ArrayBuffer containing the plaintext.
        let pt_buf = Uint8Array::new(&result);
        let mut plaintext = Zeroizing::new(vec![0u8; pt_buf.length() as usize]);
        pt_buf.copy_to(&mut plaintext);

        // Best-effort zeroing of the JS-side ArrayBuffer view. The underlying
        // ArrayBuffer may still hold data until GC'd, but this clears the
        // typed-array contents visible to JS.
        pt_buf.fill(0, 0, pt_buf.length());

        Ok(SecureKeyShare { data: plaintext })
    }

    /// Import the plaintext back into a session-ready `WasmKeyShareHandle`.
    ///
    /// `suite` is the ciphersuite discriminant (0-7) matching the original key share.
    #[wasm_bindgen(js_name = "toHandle")]
    pub fn to_handle(&self, suite: u8) -> Result<WasmKeyShareHandle, JsValue> {
        let ciphersuite = map_err(Ciphersuite::try_from(suite))?;
        let handle = map_err(import_key_share(&self.data, ciphersuite))?;
        Ok(WasmKeyShareHandle::from(handle))
    }

    /// Returns the byte length of the plaintext key share data.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.data.len()
    }

    /// Explicitly zero and drop the Rust-side plaintext key share buffer.
    ///
    /// After calling `destroy()`, the `SecureKeyShare` is consumed and the
    /// plaintext is zeroed in WASM linear memory. This happens automatically
    /// on garbage collection via `Drop`, but calling `destroy()` makes the
    /// zeroing deterministic for the Rust-owned buffer. Note: this does not
    /// clear any transient copies the browser's Web Crypto implementation may
    /// have created during prior `encrypt()`/`decrypt()` calls.
    #[wasm_bindgen]
    pub fn destroy(self) {
        drop(self); // Zeroizing<Vec<u8>> zeroes on Drop
    }
}

impl SecureKeyShare {
    /// Test-only constructor: create a `SecureKeyShare` from raw bytes.
    ///
    /// This is exposed only for WASM integration tests so that the real
    /// `encrypt()`/`decrypt()` code paths can be exercised without requiring
    /// a full DKG to produce a `WasmKeyShareHandle`.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_raw(data: Vec<u8>) -> Self {
        SecureKeyShare {
            data: Zeroizing::new(data),
        }
    }

    /// Test-only accessor: return a copy of the plaintext data.
    #[cfg(any(test, feature = "testing"))]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

// ─── JS-side helper functions ───────────────────────────────────────────────

/// Best-effort zeroing of a `Uint8Array` on the JavaScript side.
///
/// **Warning**: This cannot guarantee that the V8 GC has not already copied
/// the data elsewhere. Use `SecureKeyShare` to keep plaintext in WASM linear
/// memory whenever possible. This function is only useful for cleaning up
/// temporary JS-side buffers as a defense-in-depth measure.
#[wasm_bindgen(js_name = "wipeBytes")]
pub fn wipe_bytes(buf: &Uint8Array) {
    buf.fill(0, 0, buf.length());
}

// ─── Internal helpers ───────────────────────────────────────────────────────

/// Obtain the `SubtleCrypto` object from the global scope.
///
/// Works in both browser (`window.crypto.subtle`) and web-worker
/// (`self.crypto.subtle`) contexts via `js_sys::global()`.
fn get_subtle_crypto() -> Result<web_sys::SubtleCrypto, JsValue> {
    let global = js_sys::global();
    let crypto: web_sys::Crypto = js_sys::Reflect::get(&global, &"crypto".into())?
        .dyn_into()
        .map_err(|_| JsValue::from_str("crypto API not available in this environment"))?;
    Ok(crypto.subtle())
}

/// Build an AES-GCM algorithm params object for Web Crypto.
fn build_aes_gcm_params(iv: &[u8]) -> Result<js_sys::Object, JsValue> {
    let params = js_sys::Object::new();
    js_sys::Reflect::set(&params, &"name".into(), &"AES-GCM".into())?;
    js_sys::Reflect::set(&params, &"iv".into(), &Uint8Array::from(iv))?;
    Ok(params)
}

/// Generate a cryptographically random 96-bit IV using `crypto.getRandomValues`.
fn generate_iv() -> Result<Vec<u8>, JsValue> {
    let global = js_sys::global();
    let crypto: web_sys::Crypto = js_sys::Reflect::get(&global, &"crypto".into())?
        .dyn_into()
        .map_err(|_| JsValue::from_str("crypto API not available in this environment"))?;

    let mut buf = vec![0u8; AES_GCM_IV_LEN];
    crypto.get_random_values_with_u8_array(&mut buf)?;
    Ok(buf)
}
