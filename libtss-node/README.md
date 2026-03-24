# libtss-node

Node.js / Bun bindings for the [libtss](../libtss) threshold signing library.
Exposes FROST (RFC 9591) and DKLs23 key generation, signing, and key refresh to
TypeScript via [koffi](https://koffi.dev) FFI — loads the native shared library
directly, no WASM or native module compilation needed.

## Runtime Compatibility

| Runtime | Version | Status |
|---------|---------|--------|
| Node.js | ≥ 18 | Supported |
| Bun | ≥ 1.0 | Supported |

## Prerequisites

- `liblibtss_ffi` shared library (`.so` / `.dylib` / `.dll`)

## Build the native library

```sh
# From the repository root
cargo build --release -p libtss-ffi
```

The binding auto-discovers the library in `target/release/` or `target/debug/`
relative to `cwd`. You can also set an explicit path:

```sh
export LIBTSS_LIB=/path/to/liblibtss_ffi.so
```

## Install

```sh
cd libtss-node
npm install
```

## Usage Example

### DKLs23 DKG + Sign (3-of-3, secp256k1)

```ts
import {
  Ciphersuite,
  DkgSession,
  SignSession,
  version,
} from "@alore/libtss-node";
import { randomBytes } from "node:crypto";

console.log("libtss version:", version());

const suite = Ciphersuite.Secp256k1ECDSA;
const sessionId = randomBytes(32);

const config = { suite, maxSigners: 3, minSigners: 3 };

// Each party creates its DKG session — returns [session, round1Messages]
const [s1, r1_1] = DkgSession.create(config, 1, sessionId);
const [s2, r1_2] = DkgSession.create(config, 2, sessionId);
const [s3, r1_3] = DkgSession.create(config, 3, sessionId);

// Route messages between parties each round
const r2_1 = s1.next([...r1_2, ...r1_3]);
const r2_2 = s2.next([...r1_1, ...r1_3]);
const r2_3 = s3.next([...r1_1, ...r1_2]);
// ... continue until complete ...
```

### FROST DKG + Sign (2-of-3, Ed25519)

```ts
import { Ciphersuite, DkgSession, SignSession } from "@alore/libtss-node";

const config = { suite: Ciphersuite.Ed25519, maxSigners: 3, minSigners: 2 };

const [s1, r1_1] = DkgSession.create(config, 1);
const [s2, r1_2] = DkgSession.create(config, 2);
const [s3, r1_3] = DkgSession.create(config, 3);

// ... run DKG rounds, then sign with any 2-of-3 parties ...
```

## API

### Top-level Functions

| Function | Description |
|----------|-------------|
| `version()` | Returns the libtss version string |
| `init(options?)` | Initialize runtime (e.g. `{ mlock: true }` for swap prevention) |
| `verify(suite, msg, sig, pk)` | Verify a threshold signature |
| `importKeyShare(suite, data)` | Import a serialized key share |
| `importKeyShareSecure(suite, secure)` | Import a key share from a `SecureBuffer` |
| `frostAggregate(suite, msg, commits, shares, pkg)` | Coordinator-side FROST aggregation |
| `frostSplitKey(suite, secretKey, max, min)` | Split a secret key into FROST shares (wipes input) |
| `frostTweakKeyShare(ks, merkleRoot?)` | BIP-341 Taproot tweak on a key share |
| `frostTweakPubkeyPackage(pkg, merkleRoot?)` | BIP-341 Taproot tweak on a public key package |

### Ciphersuites

| Constant | Value | Protocol |
|----------|-------|----------|
| `Ciphersuite.Secp256k1Taproot` | 0 | FROST |
| `Ciphersuite.Secp256k1` | 1 | FROST |
| `Ciphersuite.Ed25519` | 2 | FROST |
| `Ciphersuite.P256` | 3 | FROST |
| `Ciphersuite.Ristretto255` | 4 | FROST |
| `Ciphersuite.Ed448` | 5 | FROST |
| `Ciphersuite.Secp256k1ECDSA` | 6 | DKLs23 |

### Classes

- **`KeyShareHandle`** — wraps an opaque handle to a participant's key share
  - `identifier()`, `ciphersuite()`, `protocol()`
  - `verifyingShare()`, `groupVerifyingKey()`, `publicKeyPackage()`
  - `export()`, `exportSecure()`, `free()`
- **`SecureBuffer`** — zeroing buffer allocated outside V8's pooled slab
  - `bytes()`, `destroy()`, `[Symbol.dispose]()`, `length`, `isDestroyed`
- **`DkgSession`** — drives DKG protocol rounds; `DkgSession.create(config, selfId, sessionId?)`
- **`SignSession`** — drives signing; `SignSession.create(keyShare, message, counterparties?, signId?)`
- **`RefreshSession`** — drives key refresh; `RefreshSession.create(keyShare, participants?)`

### Message Utilities

| Function | Description |
|----------|-------------|
| `encodeMessages(msgs)` | Encode `Message[]` to TLV wire format |
| `decodeMessages(buf)` | Decode TLV wire format to `Message[]` |
| `messageCount(buf)` | Count messages in a TLV buffer |

### Memory Hardening

| Function | Description |
|----------|-------------|
| `wipeBytes(buf)` | Best-effort zeroing of a `Uint8Array` via `fill(0)` |
| `SecureBuffer` | Buffer allocated via `Buffer.allocUnsafeSlow` (outside V8's pooled slab) |
| `init({ mlock: true })` | Instructs the Rust FFI to `mlock` all future allocations (swap prevention) |

V8's garbage collector moves objects across the heap and JavaScript has no
`mlock` or `explicit_bzero`. `SecureBuffer` mitigates this by using
`Buffer.allocUnsafeSlow()`, which allocates its own `BackingStore` that V8 does
not move during GC, and `fill(0)` for deterministic zeroing. This is a
best-effort strategy — true OS-level protection would require a native N-API
addon (out of scope).

```ts
import { SecureBuffer, init } from "@alore/libtss-node";

// Enable mlock for Rust-side allocations
init({ mlock: true });

// SecureBuffer with try/finally (works on all TS/Node versions)
const sb = new SecureBuffer(sensitiveData);
try {
  // use sb.bytes() ...
} finally {
  sb.destroy(); // zeroes the buffer
}

// For typed `using` support (TS 5.2+ / Node 20.4+), import the augmentation:
// import "@alore/libtss-node/disposable";
// using sb = new SecureBuffer(sensitiveData);

// frostSplitKey automatically wipes the input secret key
const { keyShares, publicKeys } = frostSplitKey(suite, secretKey, 3, 2);
// secretKey is now all zeros
```

## Architecture

libtss-node uses [koffi](https://koffi.dev) to load `liblibtss_ffi` via
`dlopen()` at runtime. This gives:

- **Cross-runtime** — works in Node.js and Bun without code changes
- **Native performance** — direct C ABI calls, no WASM overhead
- **Synchronous API** — all calls are synchronous (no async/await needed)
- **No build step for consumers** — koffi is a pre-built native addon
- **Automatic cleanup** — `FinalizationRegistry` frees handles on GC

### vs libtss-wasm

| | libtss-node (koffi) | libtss-wasm |
|--|---------------------|-------------|
| Runtime | Node.js, Bun | Browser, Node.js, Bun |
| Performance | Native speed | WASM overhead |
| Build | `cargo build` (native) | `wasm-pack build` |
| API style | Synchronous | Synchronous |
| Binary | Platform-specific `.so`/`.dylib` | Portable `.wasm` |

Use **libtss-node** for server-side / CLI applications where native performance
matters. Use **libtss-wasm** for browser or portable environments.

## Testing

```sh
# Unit tests (message codec, error types — no native library needed)
npm test

# Integration tests require the built native library
cargo build --release -p libtss-ffi
npm test
```
