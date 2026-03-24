# libtss-wasm

WebAssembly bindings for the [libtss](../libtss) threshold signing library.
Exposes FROST (RFC 9591) and DKLs23 key generation, signing, and key refresh to
JavaScript/TypeScript via `wasm-bindgen`.

## Build

```sh
# Install wasm-pack once
cargo install wasm-pack

# Build for ES module consumption in browsers / bundlers
wasm-pack build --target web

# Build for Node.js
wasm-pack build --target nodejs

# Build for bundlers (webpack, rollup, vite)
wasm-pack build --target bundler
```

The output lands in `pkg/`. Import `libtss_wasm.js` (the glue) and
`libtss_wasm_bg.wasm` (the compiled module).

> **Note**: `libtss-wasm` is intentionally excluded from the workspace
> `Cargo.toml` because `wasm32-unknown-unknown` is incompatible with the
> native compilation targets used by the rest of the workspace. Always build
> it separately with `wasm-pack`.

---

## Usage Example

### DKLs23 DKG + Sign (3-of-3, secp256k1)

```js
import init, {
  WasmDkgSession,
  WasmSignSession,
  messagesConcat,
  ethereumAddress,
  SUITE_SECP256K1_ECDSA,
} from "./pkg/libtss_wasm.js";

await init();

// ── 1. DKG ──────────────────────────────────────────────────────────────────

const suite      = SUITE_SECP256K1_ECDSA;  // 6
const minSigners = 3;
const maxSigners = 3;
const sessionId  = crypto.getRandomValues(new Uint8Array(32));

// Each party creates its session and gets round-1 messages
const [session1, r1_1] = WasmDkgSession.create(suite, 1, maxSigners, minSigners, sessionId);
const [session2, r1_2] = WasmDkgSession.create(suite, 2, maxSigners, minSigners, sessionId);
const [session3, r1_3] = WasmDkgSession.create(suite, 3, maxSigners, minSigners, sessionId);

// Route round-1 messages to recipients (all-to-all except self)
// In production: send r1_X.messages over your transport layer.
// Here we simulate locally by concatenating all peers' messages.
function filterFor(msgBundle, recipientId) {
  // Parse TLV bundle and keep only messages for this recipient
  // (to === 0 = broadcast, to === recipientId = P2P)
  // Use messageCount() + messageAt() + messageBuild() if you need fine-grained control,
  // or just pass the full bundle — libtss sessions ignore messages not addressed to them.
  return msgBundle;
}

const r2_1 = session1.next(messagesConcat(r1_2.messages, r1_3.messages));
const r2_2 = session2.next(messagesConcat(r1_1.messages, r1_3.messages));
const r2_3 = session3.next(messagesConcat(r1_1.messages, r1_2.messages));

const r3_1 = session1.next(messagesConcat(r2_2.messages, r2_3.messages));
const r3_2 = session2.next(messagesConcat(r2_1.messages, r2_3.messages));
const r3_3 = session3.next(messagesConcat(r2_1.messages, r2_2.messages));

const dkg1 = session1.next(messagesConcat(r3_2.messages, r3_3.messages));
const dkg2 = session2.next(messagesConcat(r3_1.messages, r3_3.messages));
const dkg3 = session3.next(messagesConcat(r3_1.messages, r3_2.messages));

console.assert(dkg1.complete && dkg2.complete && dkg3.complete);

const ks1 = dkg1.takeKeyShare();  // WasmKeyShareHandle — call once!
const ks2 = dkg2.takeKeyShare();
const ks3 = dkg3.takeKeyShare();

console.log("Ethereum address:", ethereumAddress(ks1));

// ── 2. Sign ──────────────────────────────────────────────────────────────────

// Pre-hash the message (DKLs23 operates on a 32-byte hash)
const msgBytes   = new TextEncoder().encode("Hello, libtss!");
const hashBuffer = await crypto.subtle.digest("SHA-256", msgBytes);
const msgHash    = new Uint8Array(hashBuffer);

const signId = crypto.getRandomValues(new Uint8Array(32));

// All three parties sign
const [ss1, sr1] = WasmSignSession.newDkls(
  ks1, signId,
  new Uint16Array([2, 3]),  // counterparties
  msgHash
);
const [ss2, sr2] = WasmSignSession.newDkls(
  ks2, signId,
  new Uint16Array([1, 3]),
  msgHash
);
const [ss3, sr3] = WasmSignSession.newDkls(
  ks3, signId,
  new Uint16Array([1, 2]),
  msgHash
);

// Phase 2
const sp2_1 = ss1.next(messagesConcat(sr2.messages, sr3.messages));
const sp2_2 = ss2.next(messagesConcat(sr1.messages, sr3.messages));
const sp2_3 = ss3.next(messagesConcat(sr1.messages, sr2.messages));

// Phase 3
const sp3_1 = ss1.next(messagesConcat(sp2_2.messages, sp2_3.messages));
const sp3_2 = ss2.next(messagesConcat(sp2_1.messages, sp2_3.messages));
const sp3_3 = ss3.next(messagesConcat(sp2_1.messages, sp2_2.messages));

// Phase 4 → signature
const sig1 = ss1.next(messagesConcat(sp3_2.messages, sp3_3.messages));
console.assert(sig1.complete);

const signature  = sig1.signature;   // Uint8Array (64 bytes: r||s)
const recoveryId = sig1.recoveryId;  // 0 or 1

console.log("Signature (hex):", Buffer.from(signature).toString("hex"));
console.log("Recovery ID:", recoveryId);
```

---

## FROST DKG + Sign (2-of-3, Ed25519)

```js
import init, {
  WasmDkgSession,
  WasmSignSession,
  messagesConcat,
  SUITE_ED25519,
} from "./pkg/libtss_wasm.js";

await init();

const suite = SUITE_ED25519;  // 2

// DKG — 3 rounds for FROST
const [s1, r1_1] = WasmDkgSession.create(suite, 1, 3, 2, null);
const [s2, r1_2] = WasmDkgSession.create(suite, 2, 3, 2, null);
const [s3, r1_3] = WasmDkgSession.create(suite, 3, 3, 2, null);

const r2_1 = s1.next(messagesConcat(r1_2.messages, r1_3.messages));
const r2_2 = s2.next(messagesConcat(r1_1.messages, r1_3.messages));
const r2_3 = s3.next(messagesConcat(r1_1.messages, r1_2.messages));

const d1 = s1.next(messagesConcat(r2_2.messages, r2_3.messages));
const d2 = s2.next(messagesConcat(r2_1.messages, r2_3.messages));

const ks1 = d1.keyShare;
const ks2 = d2.keyShare;

// Sign with parties 1 and 2
const message = new TextEncoder().encode("Hello, FROST!");
const [ss1, sr1] = WasmSignSession.newFrost(ks1, message);
const [ss2, sr2] = WasmSignSession.newFrost(ks2, message);

// Round 2: share signing shares
const sp2_1 = ss1.next(sr2.messages);
const sp2_2 = ss2.next(sr1.messages);

// Round 3: aggregate
const sig1 = ss1.next(sp2_2.messages);
console.assert(sig1.complete);
console.log("Ed25519 signature (hex):", Buffer.from(sig1.signature).toString("hex"));
```

---

## API Reference

### Constants

| Constant                | Value | Description                    |
|-------------------------|-------|--------------------------------|
| `SUITE_SECP256K1_TAPROOT` | 0   | FROST secp256k1-taproot        |
| `SUITE_SECP256K1`       | 1     | FROST secp256k1                |
| `SUITE_ED25519`         | 2     | FROST Ed25519                  |
| `SUITE_P256`            | 3     | FROST P-256                    |
| `SUITE_RISTRETTO255`    | 4     | FROST Ristretto255             |
| `SUITE_ED448`           | 5     | FROST Ed448                    |
| `SUITE_SECP256K1_ECDSA` | 6     | DKLs23 secp256k1 ECDSA         |
| `SUITE_SECP256R1_ECDSA` | 7     | DKLs23 secp256r1 ECDSA         |
| `PROTOCOL_FROST`        | 0     | FROST protocol discriminant    |
| `PROTOCOL_DKLS23`       | 1     | DKLs23 protocol discriminant   |

### Functions

| Function                | Description                                              |
|-------------------------|----------------------------------------------------------|
| `verify(suite, msg, sig, pk)` | Verify a threshold signature                       |
| `version()`             | Returns the libtss-wasm crate version string             |
| `wipeBytes(buf)`        | Best-effort zeroing of a JS `Uint8Array`                 |
| `ethereumAddress(ks)`   | EIP-55 Ethereum address (suite 6 only)                   |
| `bitcoinAddress(ks)`    | Bitcoin P2WPKH mainnet address (suite 6 only)            |
| `bitcoinAddressHrp(ks, hrp)` | Bitcoin address with custom HRP (suite 6 only)      |
| `cosmosAddress(ks)`     | Cosmos address (suite 6 only)                            |
| `cosmosAddressHrp(ks, hrp)` | Cosmos address with custom HRP (suite 6 only)       |
| `tronAddress(ks)`       | TRON address (suite 6 only)                              |
| `neo3Address(ks)`       | NEO N3 address (suite 7 only)                            |
| `suiR1Address(ks)`      | Sui secp256r1 address (suite 7 only)                     |
| `deriveChild(ks, n)`    | BIP-32 non-hardened child derivation                     |
| `derivePath(ks, path)`  | BIP-32 path derivation (e.g. `"m/44/60/0/0"`)           |
| `messageCount(buf)`     | Count TLV-framed messages in a buffer                    |
| `messageAt(buf, i)`     | Decode message at index `i` from a buffer                |
| `messageBuild(from, to, data)` | Build a single TLV-framed message               |
| `messagesConcat(a, b)`  | Concatenate two TLV message buffers                      |

### Classes

- **`WasmKeyShareHandle`** — holds a participant's key share in the in-memory registry
- **`SecureKeyShare`** — opaque wrapper keeping key share plaintext in WASM linear memory (zeroed on drop)
- **`WasmDkgSession`** — drives DKG protocol rounds; use `WasmDkgSession.create()`
- **`WasmSignSession`** — drives signing protocol rounds; use `WasmSignSession.newFrost()` / `newDkls()` / `newDklsR1()`
- **`WasmRefreshSession`** — drives FROST key refresh; use `WasmRefreshSession.createDealer()` / `createReceiver()`

### TypeScript Helpers (`src/secure.ts`)

| Function                           | Description                                                |
|------------------------------------|------------------------------------------------------------|
| `exportKeyShareEncrypted(handle, key)` | Export + encrypt in one call (see Limitations) |
| `importKeyShareEncrypted(suite, ct, key)` | Decrypt + import in one call (see Limitations) |
| `deriveWrappingKey(password, salt)` | PBKDF2-derived AES-256-GCM key (600K iterations)         |
| `generateWrappingKey()`            | Random AES-256-GCM key (non-extractable)                  |

---

## Security: Memory Hardening

### Threat Model

The WASM binding operates in browser sandboxes where OS-level memory protection
(`mlock`, `mprotect`) is **not available**. The security model is defense-in-depth:

| Layer                  | Protection                                           |
|------------------------|------------------------------------------------------|
| WASM linear memory     | Application JS never handles plaintext directly      |
| `Zeroizing<Vec<u8>>`  | Volatile write + compiler fence zeroes on drop       |
| Web Crypto AES-256-GCM | Only ciphertext persisted to IndexedDB/localStorage |
| `CryptoKey` (non-extractable) | Wrapping key cannot be read by JavaScript     |
| Browser site isolation | Per-origin process isolation                         |

### Limitations

- **No swap prevention** — browsers do not expose `mlock`; WASM linear memory
  may be swapped to disk by the OS.
- **No core dump control** — handled by the browser process, not by application code.
- **V8 GC copies** — `wipeBytes()` zeroes the provided buffer but cannot guarantee
  that the GC has not already copied the data to a different heap page.
- **Web Crypto intermediates** — `encrypt()` passes plaintext as a WASM memory
  view (no app-level JS copy), but the browser may internally buffer it.
  `decrypt()` returns plaintext as a JS `ArrayBuffer` that is immediately
  copied to WASM and best-effort zeroed; the underlying buffer may persist
  until GC'd.
- **For server-side WASM** — use the Node.js binding (`libtss-node`) which supports
  `mlock` via a native addon.

### Recommended Workflow

```js
import init, {
  WasmDkgSession,
  SecureKeyShare,
  wipeBytes,
} from "./pkg/libtss_wasm.js";
import { deriveWrappingKey, exportKeyShareEncrypted, importKeyShareEncrypted } from "./src/secure.ts";

await init();

// After DKG completes...
const keyShare = dkgResult.takeKeyShare();

// Derive a wrapping key from a user password
const salt = crypto.getRandomValues(new Uint8Array(16));
const wrappingKey = await deriveWrappingKey("user-passphrase", salt);

// Export + encrypt — plaintext stays in WASM memory (see Limitations)
const ciphertext = await exportKeyShareEncrypted(keyShare, wrappingKey);

// Store ciphertext + salt in IndexedDB (safe — only ciphertext)
await db.put("keyShare", { ciphertext, salt });

// Later: restore from storage
const stored = await db.get("keyShare");
const restoreKey = await deriveWrappingKey("user-passphrase", stored.salt);
const restoredHandle = await importKeyShareEncrypted(suite, stored.ciphertext, restoreKey);
```
