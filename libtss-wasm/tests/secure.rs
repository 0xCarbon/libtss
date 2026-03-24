//! WASM tests for the `SecureKeyShare` memory hardening module.
//!
//! Run with:
//! ```sh
//! wasm-pack test --headless --chrome -- --features testing
//! ```
//!
//! Tests that require Web Crypto (encrypt/decrypt) need a browser environment.
//! The `SecureKeyShare` lifecycle tests (from_handle, to_handle, destroy) work
//! in Node.js as well.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// ─── wipeBytes ──────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn wipe_bytes_zeroes_buffer() {
    let buf = js_sys::Uint8Array::from(&[1u8, 2, 3, 4, 5][..]);
    libtss_wasm::wipe_bytes(&buf);

    let mut out = vec![0u8; 5];
    buf.copy_to(&mut out);
    assert!(out.iter().all(|&b| b == 0), "wipeBytes did not zero the buffer");
}

#[wasm_bindgen_test]
fn wipe_bytes_handles_empty() {
    let buf = js_sys::Uint8Array::new_with_length(0);
    // Should not panic
    libtss_wasm::wipe_bytes(&buf);
}

// ─── Helper: generate an AES-256-GCM CryptoKey ─────────────────────────────

async fn generate_test_key() -> web_sys::CryptoKey {
    let global = js_sys::global();
    let crypto: web_sys::Crypto = js_sys::Reflect::get(&global, &"crypto".into())
        .unwrap()
        .dyn_into()
        .unwrap();
    let subtle = crypto.subtle();

    let algorithm = js_sys::Object::new();
    js_sys::Reflect::set(&algorithm, &"name".into(), &"AES-GCM".into()).unwrap();
    js_sys::Reflect::set(&algorithm, &"length".into(), &256.into()).unwrap();

    let usages = js_sys::Array::new();
    usages.push(&"encrypt".into());
    usages.push(&"decrypt".into());

    let promise = subtle
        .generate_key_with_object(&algorithm, false, &usages)
        .unwrap();
    let key = wasm_bindgen_futures::JsFuture::from(promise).await.unwrap();
    key.dyn_into().unwrap()
}

// ─── SecureKeyShare encrypt/decrypt via real Rust methods ───────────────────

#[wasm_bindgen_test]
async fn secure_key_share_encrypt_decrypt_round_trip() {
    let key = generate_test_key().await;
    let test_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    // Create a SecureKeyShare from raw bytes (test-only constructor).
    let secure = libtss_wasm::SecureKeyShare::from_raw(test_data.clone());

    // Encrypt using the real Rust method.
    let ciphertext = secure.encrypt(&key).await.expect("encrypt should succeed");

    // Ciphertext: IV (12) + data (6) + AES-GCM tag (16) = 34 bytes.
    assert!(
        ciphertext.length() >= 12 + 6 + 16,
        "ciphertext too short: expected at least 34, got {}",
        ciphertext.length()
    );

    // Decrypt using the real Rust static method.
    let decrypted = libtss_wasm::SecureKeyShare::decrypt(&ciphertext, &key)
        .await
        .expect("decrypt should succeed");

    assert_eq!(
        decrypted.as_bytes(),
        &test_data,
        "decrypted data should match original"
    );
}

#[wasm_bindgen_test]
async fn secure_key_share_decrypt_wrong_key_fails() {
    let key1 = generate_test_key().await;
    let key2 = generate_test_key().await;

    let secure = libtss_wasm::SecureKeyShare::from_raw(vec![0x01, 0x02, 0x03]);
    let ciphertext = secure.encrypt(&key1).await.unwrap();

    let result = libtss_wasm::SecureKeyShare::decrypt(&ciphertext, &key2).await;
    assert!(result.is_err(), "decrypt with wrong key should fail");
}

#[wasm_bindgen_test]
async fn secure_key_share_decrypt_truncated_fails() {
    let key = generate_test_key().await;

    // Too short — less than IV (12 bytes) + 1.
    let short = js_sys::Uint8Array::from(&[0u8; 10][..]);
    let result = libtss_wasm::SecureKeyShare::decrypt(&short, &key).await;
    assert!(result.is_err(), "decrypt of truncated ciphertext should fail");
}

#[wasm_bindgen_test]
async fn secure_key_share_unique_iv_per_encryption() {
    let key = generate_test_key().await;

    let s1 = libtss_wasm::SecureKeyShare::from_raw(vec![0xAA, 0xBB, 0xCC]);
    let s2 = libtss_wasm::SecureKeyShare::from_raw(vec![0xAA, 0xBB, 0xCC]);

    let ct1 = s1.encrypt(&key).await.unwrap();
    let ct2 = s2.encrypt(&key).await.unwrap();

    // Extract the first 12 bytes (IV) from each.
    let mut iv1 = [0u8; 12];
    let mut iv2 = [0u8; 12];
    ct1.slice(0, 12).copy_to(&mut iv1);
    ct2.slice(0, 12).copy_to(&mut iv2);

    assert_ne!(iv1, iv2, "two encryptions must use different IVs");
}

#[wasm_bindgen_test]
fn secure_key_share_length() {
    let data = vec![1, 2, 3, 4, 5];
    let secure = libtss_wasm::SecureKeyShare::from_raw(data);
    assert_eq!(secure.length(), 5);
}

#[wasm_bindgen_test]
fn secure_key_share_destroy_does_not_panic() {
    let secure = libtss_wasm::SecureKeyShare::from_raw(vec![0xFF; 32]);
    secure.destroy(); // Should not panic
}

// ─── Baseline Web Crypto AES-GCM tests (via inline JS helpers) ─────────────
//
// These validate the underlying Web Crypto behavior independently of the
// SecureKeyShare Rust binding, serving as a baseline sanity check.

#[wasm_bindgen_test]
async fn baseline_aes_gcm_round_trip() {
    let key = generate_test_key().await;
    let test_data = js_sys::Uint8Array::from(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE][..]);

    let ciphertext = encrypt_test_data(&test_data, &key).await.expect("encrypt should succeed");
    assert!(ciphertext.length() > test_data.length());

    let decrypted = decrypt_test_data(&ciphertext, &key).await.expect("decrypt should succeed");
    let mut dec_bytes = vec![0u8; decrypted.length() as usize];
    decrypted.copy_to(&mut dec_bytes);

    assert_eq!(dec_bytes, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
}

#[wasm_bindgen_test]
async fn baseline_aes_gcm_wrong_key_fails() {
    let key1 = generate_test_key().await;
    let key2 = generate_test_key().await;

    let test_data = js_sys::Uint8Array::from(&[0x01, 0x02, 0x03][..]);
    let ciphertext = encrypt_test_data(&test_data, &key1).await.unwrap();

    let result = decrypt_test_data(&ciphertext, &key2).await;
    assert!(result.is_err(), "decrypt with wrong key should fail");
}

// ─── Inline JS helpers for baseline AES-GCM tests ──────────────────────────

#[wasm_bindgen(inline_js = r#"
export async function encrypt_test_data(data, key) {
    const subtle = crypto.subtle;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    const result = new Uint8Array(12 + ct.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ct), 12);
    return result;
}

export async function decrypt_test_data(ciphertext, key) {
    const subtle = crypto.subtle;
    const iv = ciphertext.slice(0, 12);
    const ct = ciphertext.slice(12);
    const pt = await subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new Uint8Array(pt);
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn encrypt_test_data(
        data: &js_sys::Uint8Array,
        key: &web_sys::CryptoKey,
    ) -> Result<js_sys::Uint8Array, JsValue>;

    #[wasm_bindgen(catch)]
    async fn decrypt_test_data(
        ciphertext: &js_sys::Uint8Array,
        key: &web_sys::CryptoKey,
    ) -> Result<js_sys::Uint8Array, JsValue>;
}
