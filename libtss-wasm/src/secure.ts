/**
 * @module secure
 *
 * TypeScript helpers for encrypted key share workflows in libtss-wasm.
 *
 * These functions orchestrate the `SecureKeyShare` Rust type so that
 * application-level JavaScript never handles plaintext key material directly:
 *
 * 1. `exportKeyShareEncrypted()` — export + encrypt in one call
 * 2. `importKeyShareEncrypted()` — decrypt + import in one call
 * 3. `deriveWrappingKey()` — PBKDF2-derived AES-256-GCM key from a password
 * 4. `generateWrappingKey()` — random AES-256-GCM key (for programmatic use)
 * 5. `wipeBytes()` — best-effort zeroing of a JS `Uint8Array`
 *
 * ## Security Model
 *
 * - Plaintext key shares are held in WASM linear memory (`Zeroizing<Vec<u8>>`),
 *   zeroed on drop via volatile writes + compiler fences.
 * - Only **ciphertext** (AES-256-GCM, 12-byte IV prepended) is returned to
 *   application JavaScript.
 * - `CryptoKey` objects are non-extractable by default — the wrapping key
 *   cannot be read by JavaScript.
 * - Browser site isolation provides the primary security boundary.
 * - WASM linear memory reduces accidental plaintext exposure in cooperative
 *   application code but does **not** defend against arbitrary same-origin
 *   script execution (XSS).
 * - **Residual exposure**: The browser's Web Crypto implementation may
 *   internally buffer plaintext during encrypt/decrypt. On decrypt, the
 *   JS-side `ArrayBuffer` is best-effort zeroed after copying to WASM memory.
 * - **Limitations**: `mlock`/`mprotect` are not available in browsers.
 *   For server-side WASM, use the Node.js binding (`libtss-node`) instead.
 */

// These imports reference the wasm-bindgen generated bindings.
// Adjust the import path if your bundler setup differs.
import type { WasmKeyShareHandle, SecureKeyShare } from "../pkg/libtss_wasm";

// wipeBytes is exported from the main wasm-bindgen module (pkg/libtss_wasm).
// Import it directly: import { wipeBytes } from "./pkg/libtss_wasm";

/**
 * Export a key share and encrypt it in one step.
 *
 * Plaintext stays in WASM linear memory — encryption uses Web Crypto
 * (AES-256-GCM). See module docs for residual exposure details.
 *
 * @param handle  - The key share handle to export
 * @param wrappingKey - An AES-GCM CryptoKey with `encrypt` usage
 * @returns Ciphertext (`iv || ciphertext || tag`) safe for IndexedDB/localStorage
 */
export async function exportKeyShareEncrypted(
  handle: WasmKeyShareHandle,
  wrappingKey: CryptoKey,
): Promise<Uint8Array> {
  // SecureKeyShare is imported at runtime from the wasm module
  const secure: SecureKeyShare = handle.exportShareSecure();
  try {
    return await secure.encrypt(wrappingKey);
  } finally {
    secure.destroy();
  }
}

/**
 * Decrypt ciphertext and import as a session-ready key share handle.
 *
 * Decrypted plaintext is held in WASM linear memory and imported directly.
 * See module docs for residual exposure details (Web Crypto intermediates).
 *
 * @param suite      - Ciphersuite discriminant (0-7)
 * @param ciphertext - Output of `exportKeyShareEncrypted()` or `SecureKeyShare.encrypt()`
 * @param wrappingKey - An AES-GCM CryptoKey with `decrypt` usage
 * @returns A `WasmKeyShareHandle` ready for signing/refresh/derivation
 */
export async function importKeyShareEncrypted(
  suite: number,
  ciphertext: Uint8Array,
  wrappingKey: CryptoKey,
): Promise<WasmKeyShareHandle> {
  // SecureKeyShare.decrypt is a static async method on the wasm class
  const { SecureKeyShare: SC } = await import("../pkg/libtss_wasm");
  const secure: SecureKeyShare = await SC.decrypt(ciphertext, wrappingKey);
  try {
    return secure.toHandle(suite);
  } finally {
    secure.destroy();
  }
}

/**
 * Derive an AES-256-GCM wrapping key from a password using PBKDF2.
 *
 * Uses 600,000 iterations of PBKDF2-HMAC-SHA-256 as recommended by OWASP.
 * The returned `CryptoKey` is **non-extractable** — JavaScript cannot read
 * the raw key bytes.
 *
 * @param password   - User-supplied passphrase
 * @param salt       - Random salt (at least 16 bytes; store alongside ciphertext)
 * @param iterations - PBKDF2 iteration count (default: 600,000; minimum: 100,000)
 * @returns A non-extractable AES-256-GCM CryptoKey
 * @throws If salt is shorter than 16 bytes or iterations is below 100,000
 */
export async function deriveWrappingKey(
  password: string,
  salt: Uint8Array,
  iterations = 600_000,
): Promise<CryptoKey> {
  if (salt.length < 16) {
    throw new Error("salt must be at least 16 bytes");
  }
  if (iterations < 100_000) {
    throw new Error("iterations must be at least 100,000");
  }

  const enc = new TextEncoder();
  const encoded = enc.encode(password);
  try {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoded,
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    // Best-effort zeroing of the encoded password bytes.
    encoded.fill(0);
  }
}

/**
 * Generate a random AES-256-GCM wrapping key.
 *
 * Useful for programmatic key management (e.g., wrapping with a master key
 * stored in a secure enclave). The returned `CryptoKey` is **non-extractable**.
 *
 * @returns A non-extractable AES-256-GCM CryptoKey
 */
export async function generateWrappingKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
