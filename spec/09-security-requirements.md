# 09 - Security Requirements

## SR-1: Constant-Time Operations

**Requirement**: All operations on secret values MUST execute in constant time
(independent of the value being processed).

**Rationale**: Variable-time operations on secrets enable timing side-channel attacks.
CVE-2023-26556 and CVE-2023-26557 demonstrated practical key extraction from TSS
implementations using Go's non-constant-time `math/big` and secp256k1 scalar
multiplication.

**Implementation**:
- All scalar arithmetic uses the `k256` crate (secp256k1) or `curve25519-dalek`
  (Ed25519, Ristretto255), which provide constant-time implementations
- The `subtle` crate provides constant-time comparison (`ct_eq`) and conditional
  selection (`conditional_select`)
- Consumer language code NEVER performs arithmetic on secret values -- all such operations happen in Rust
- The `Field::Scalar` associated type in frost-core requires constant-time `PartialEq`

**Verification**: Audit checklist item. Static analysis cannot verify constant-time
properties; this requires manual review and/or tools like `dudect` or `ctgrind`.

## SR-2: Nonce Safety

**Requirement**: Signing nonces MUST be single-use and MUST include fresh randomness.

**Rationale**: Nonce reuse in Schnorr/ECDSA allows complete secret key recovery from
two signatures. In the threshold setting, this is even more critical because nonce
reuse by a single signer can expose their share, potentially enabling key reconstruction
if combined with other compromised shares.

RFC 9591 explicitly states: "The nonce values produced by this function MUST NOT be
used in more than one invocation of `sign`."

Deterministic nonce generation (RFC 6979 style) is UNSAFE in the multi-party setting
because a malicious coordinator can request signatures on chosen messages and extract
the key from the deterministic relationship between nonces.

**Implementation**:
1. Nonces are generated using FROST's hedged nonce derivation:
   `nonce = H3(random_bytes || secret_share)` -- combines fresh randomness with
   the secret share for protection against weak RNGs
2. Nonces are consumed internally by the `SignSession` during the round that
   computes the signature share — they are zeroed immediately after use
3. After the session returns `SignOutput::Complete`, subsequent calls return
   `TssError::SessionComplete`
4. If a `SignSession` is dropped without completing, the nonces are zeroed
   via Rust's `Drop` + `Zeroize`
5. DKLs23 instance keys are similarly single-use and zeroed after signing

**Verification**: The type system enforces single-use via handle consumption. Tests
verify that reuse attempts return errors.

## SR-3: Secret Memory Zeroing

**Requirement**: All secret values MUST be zeroed from memory when no longer needed.

**Rationale**: Secrets persisting in freed memory can be recovered via memory dumps,
swap files, core dumps, or cold boot attacks.

**Implementation**:
- All secret Rust types derive `Zeroize` and implement `ZeroizeOnDrop`:
  - `SigningShare<C>` (FROST key share)
  - `SigningKey<C>` (FROST full signing key)
  - `Nonce<C>`, `SigningNonces<C>` (FROST nonces)
  - `Party.poly_point` (DKLs23 key share scalar)
  - `SessionData.polynomial` (DKLs23 DKG polynomial coefficients)
  - Instance keys and inversion masks (DKLs23 signing)
- Intermediate session secrets are wrapped in `Zeroizing<Vec<u8>>`:
  - `FrostDkgState.round1_secret` and `round2_secret` (DKG round state)
  - `FrostSignPhase::AwaitCommitments.nonces` (signing nonces)
  - `frost_dkg_part1/part2` and `frost_commit` return `Zeroizing<Vec<u8>>`
  - When state transitions via `std::mem::replace`, old values are zeroed on drop
- The `zeroize` crate uses `core::ptr::write_volatile` + `compiler_fence(SeqCst)`
  to prevent the compiler from optimizing away the zeroing
- The handle registry's `free()` and `take()` methods trigger `Drop`, which triggers
  `Zeroize`
- Secrets are allocated by Rust's system allocator, NOT a GC-managed heap -- the
  consumer language's GC cannot copy or move them

**FFI buffer zeroing**:
- `tss_buffer_free()` zeroes buffer data before deallocation — any buffer containing
  exported key shares is wiped before the heap allocation is freed
- Callers no longer need to manually `memset` before calling `tss_buffer_free()`

**Swap prevention**:
- Optional `tss_init(TSS_INIT_MLOCK)` calls `mlockall(MCL_CURRENT | MCL_FUTURE)` to
  prevent all process pages from being swapped to disk
- Requires `CAP_IPC_LOCK` capability or `ulimit -l unlimited`
- Protects both Rust-side key material and any consumer-side locked buffers (e.g.,
  Go memguard `LockedBuffer`)

**Binding side**:
- GC-based languages (Go, Java, Python) make zeroing unreliable (copies may exist
  on different heap pages)
- Therefore, secrets NEVER exist as consumer language values
- Consumer languages work only with opaque `uint64` handle IDs
- For key share export/import, the Go binding provides `ExportKeyShareSecure()` and
  `ImportKeyShareSecure()` which use `SecureBytes` (backed by memguard's `LockedBuffer`)
  to keep key material in mmap'd, mlock'd memory outside the GC heap
- `WipeBytes()` provides best-effort zeroing for regular Go slices
- `FrostSplitKey()` automatically wipes the input `secretKey` slice after use
- `buildCSliceArray()` zeroes C-heap copies before calling `C.free()`
- `Init(OptMlock)` calls `tss_init(TSS_INIT_MLOCK)` and disables core dumps
- Example (C):
  ```c
  TssBuffer exported;
  tss_handle_export(handle, &exported);
  encrypt_and_store(exported.data, exported.len);
  tss_buffer_free(&exported);  // zeroes data automatically
  ```
- Example (Go):
  ```go
  tss.Init(tss.OptMlock)
  secure, _ := tss.ExportKeyShareSecure(keyShare)
  defer secure.Destroy()
  encrypted := encrypt(secure.Bytes())
  ```
- The .NET binding provides `SecureBytes` backed by `Marshal.AllocHGlobal` + `mlock`
  (Linux/macOS) / `VirtualLock` (Windows) to keep sensitive data outside the GC heap
- `ExportKeyShareSecure()` copies directly from native `TssBuffer` to unmanaged
  `SecureBytes` memory — no managed `byte[]` is ever created
- `ImportKeyShareSecure()` reads directly from the `SecureBytes` unmanaged pointer
- `Init(InitOptions.Mlock)` calls `tss_init` and best-effort `prctl(PR_SET_DUMPABLE, 0)`
  on Linux
- `SplitKey()` zeros input `secretKey` array after use via `CryptographicOperations.ZeroMemory`
- `RefreshDealer()` and `RepairPart1()` parse directly from native memory via
  `ReadOnlySpan<byte>` — the intermediate contiguous managed copy is eliminated,
  but the returned per-participant `Dictionary<ushort, byte[]>` values are still
  managed `byte[]` arrays (partial hardening only)
- `WipeBytes()` provides best-effort zeroing for regular `byte[]` arrays
- Example (.NET):
  ```csharp
  Tss.Init(InitOptions.Mlock);
  using var secure = keyShare.ExportKeyShareSecure();
  var encrypted = Encrypt(secure.Span);
  ```
- The React Native binding ensures raw key share bytes never reach the JavaScript
  context — only opaque string reference IDs cross the bridge
- `init({ mlock: true })` calls `tss_init(TSS_INIT_MLOCK)` via the native module
- iOS: `exportKeyShareSecure` uses zero-copy `NSData` wrapper (`dataWithBytesNoCopy`)
  around the `TssBuffer`, stores in Keychain via `SecItemAdd` with
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, then zeroes via `tss_buffer_free`.
  `importKeyShareSecure` retrieves from Keychain and force-wipes the
  `SecItemCopyMatching` result via `memset` before the `NSData` is released
- Android: `exportKeyShareSecure` exports via JNI (`nativeExportKeyShareRaw`),
  encrypts with AndroidKeyStore-backed AES-GCM, stores ciphertext in
  SharedPreferences, and zeroes the plaintext `byte[]` via `Arrays.fill`.
  JNI import uses `GetByteArrayRegion` into a controlled C++ `std::vector`
  (not `GetByteArrayElements` which may return a GC-managed pointer), then
  zeroes the vector via `std::fill` after `tss_handle_import`
- Both platforms: intermediate native buffers are zeroed after use
- Example (TypeScript):
  ```typescript
  import { init, exportKeyShareToKeychain, importKeyShareFromKeychain } from '@alore/libtss-rn';
  await init({ mlock: true });
  const keychainId = await exportKeyShareToKeychain(keyShare);
  const restored = await importKeyShareFromKeychain(Ciphersuite.Secp256k1, keychainId);
  ```
- The WASM binding (`libtss-wasm`) keeps key share plaintext in WASM linear memory
  via `SecureKeyShare` backed by `Zeroizing<Vec<u8>>` — application-level JavaScript
  never handles plaintext directly
- `SecureKeyShare.encrypt()` and `SecureKeyShare.decrypt()` use Web Crypto AES-256-GCM
  (`SubtleCrypto`) directly from WASM — only ciphertext is returned to application JS.
  Note: the browser's Web Crypto implementation may internally buffer plaintext during
  encrypt, and `decrypt()` returns plaintext as a JS `ArrayBuffer` that is immediately
  copied to WASM memory and best-effort zeroed (the underlying buffer may persist until GC'd)
- `exportShareSecure()` returns a `SecureKeyShare` (recommended over `exportShare()`
  which copies plaintext to a JS `Uint8Array`)
- `importShareSecure()` accepts a `SecureKeyShare` (recommended over `importShare()`
  which reads plaintext from a JS `Uint8Array`)
- `importShare()` wraps the input bytes in `Zeroizing<Vec<u8>>` for zeroing on the
  Rust side
- `wipeBytes()` provides best-effort zeroing for JS `Uint8Array` buffers (V8 GC may
  have copies)
- TypeScript helpers (`src/secure.ts`) provide `exportKeyShareEncrypted()`,
  `importKeyShareEncrypted()`, and `deriveWrappingKey()` for end-to-end encrypted
  key share persistence
- `CryptoKey` objects from Web Crypto are non-extractable by default — wrapping keys
  cannot be read by JavaScript
- **Limitations**: `mlock`/`mprotect`/swap prevention are not available in browser
  sandboxes; WASM linear memory may be swapped to disk by the OS. For server-side
  WASM, use the Node.js binding (`libtss-node`) which supports mlock via native addon
- Example (WASM/JS):
  ```js
  import { deriveWrappingKey, exportKeyShareEncrypted } from "./src/secure.ts";
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveWrappingKey("passphrase", salt);
  const ct = await exportKeyShareEncrypted(keyShare, key);
  // ct is ciphertext — safe for IndexedDB/localStorage
  ```
- The Python binding provides `SecureBytes` backed by `sodium_malloc` (libsodium,
  preferred) or `libc.malloc` + `mlock` (fallback) to keep sensitive data outside the
  CPython GC heap
- `SecureBytes.memoryview()` returns a zero-copy `memoryview` over the secure memory,
  avoiding leaking secrets to the GC heap via immutable `bytes` objects
- `SecureBytes.__del__` zeroes and frees the secure region (with class-level `ctypes`
  references to survive interpreter teardown)
- `export_secure()` copies from native `TssBuffer` to `SecureBytes` via a mutable
  `bytearray` intermediate that is wiped by the `SecureBytes` constructor
- `import_secure()` reads from `SecureBytes.memoryview()` directly; the intermediate
  ctypes array is wiped after import
- `TssSlice.__del__` automatically zeroes the backing `ctypes` array for all slices
  created via `make_slice()`, covering all intermediate copies across the codebase
  (sessions, messages, repair, refresh)
- `wipe_bytearray()` provides best-effort zeroing for mutable `bytearray` objects via
  `ctypes.memset`
- `frost.split_key()` wipes a mutable `bytearray` secret key after use
- `message.encode()` wipes intermediate ctypes arrays after each message build
- `init(mlock=True)` calls `tss_init(TSS_INIT_MLOCK)` and disables core dumps via
  `resource.setrlimit(RLIMIT_CORE, (0, 0))`
- Example (Python):
  ```python
  from libtss import init, SecureBytes, KeyShareHandle, Ciphersuite

  init(mlock=True)
  with key_share.export_secure() as secure:
      encrypted = encrypt(secure.memoryview())
  # secure is automatically zeroed and freed
  ```

**Deployment note**:
- To enable mlock, set `ulimit -l unlimited` or grant `CAP_IPC_LOCK`:
  ```bash
  # Option 1: ulimit (session-scoped)
  ulimit -l unlimited
  # Option 2: capability (binary-scoped)
  sudo setcap cap_ipc_lock=ep /path/to/binary
  ```

## SR-4: Input Validation

**Requirement**: All data received from network participants MUST be validated before
processing.

**Rationale**: Malformed inputs can cause panics, buffer overflows, or protocol
deviations. Every known TSS attack exploits insufficient input validation.

**Implementation** (two layers of validation):

**Layer 1: DKLs23 protocol crate (v0.4.1)** — validates at every phase entry point (also enforced by session state machines):

| Input | Validation |
|-------|-----------|
| Party index | In range `[1, share_count]` |
| Counterparty list | Unique, correct count (`threshold - 1`), no self-reference |
| Multiplication state | Required `mul_senders`/`mul_receivers` present for all counterparties |
| Message routing | Receiver matches self, sender in expected party set |
| Message completeness | All expected parties accounted for, no duplicates |
| Message count | Vector length matches expected number of counterparties |

All validation failures return `Abort` with `AbortKind::Recoverable` and a structured
`AbortReason` variant. No panic paths remain in protocol phases
(`#![forbid(unsafe_code)]`, no `unwrap()`/`expect()`). Phase ordering is additionally
enforced by `DkgSession` and `SignSession` state machines, which return
`AbortReason::PhaseCalledOutOfOrder` on misuse.

**Layer 2: libtss adapter** — validates at FFI deserialization:

| Input | Validation |
|-------|-----------|
| Scalars | Valid field element (< curve order), non-zero where required |
| Group elements | Valid curve point, not identity element, prime-order subgroup |
| Identifiers | Non-zero scalar, known participant |
| Commitment lists | Correct count (== expected signers), no duplicates |
| DKG packages | Correct count (== max_signers - 1), matching identifiers |
| Proof of knowledge | Valid Schnorr proof for the claimed public key |
| OT data | Correct dimensions (κ × batch_size), valid range |
| Signature shares | Valid scalar, verified against individual commitment |
| VSS commitments | Correct degree (== min_signers - 1), valid points |

**Binding-side validation** (before calling Rust):

| Input | Validation |
|-------|-----------|
| ThresholdConfig | `min_signers >= 2`, `min_signers <= max_signers` |
| Identifier | `index > 0`, within configured range |
| Ciphersuite | Known enum value |
| Handle | Non-zero, correct category |
| BIP-32 path | Valid format, all indices < 2^31, depth <= 255 |

## SR-5: No Panics Across FFI

**Requirement**: Rust panics MUST NOT propagate across the FFI boundary.

**Rationale**: Unwinding a Rust panic through the consumer's stack is undefined behavior
and typically causes a process crash with no error information.

**Implementation**:
- Every `extern "C"` function wraps the body in `std::panic::catch_unwind`
- Caught panics are converted to `TSS_ERR_INTERNAL_PANIC`
- The Rust crate is compiled with `panic = "unwind"` (not `abort`) to enable catching
- All public functions return `Result<T, TssError>` (no `unwrap()` in library code)
- DKLs23 v0.4.1 enforces `#![forbid(unsafe_code)]` crate-wide and has eliminated all
  panic paths from protocol phases — every phase returns `Result<T, Abort>`.
  Session state machines (`DkgSession<C>`, `SignSession<'a, C>`) add compile-time phase
  ordering enforcement via ownership (`phase4(self)` consumes the session).
- The FFI adapter layer converts `Result::Err` to `TssStatus` error codes, with
  `TssError::Abort { ban: None }` mapping to `TSS_ERR_ABORT` and
  `TssError::Abort { ban: Some(_) }` mapping to `TSS_ERR_ABORT_BAN`

**Testing**: Dedicated tests inject invalid inputs that would cause panics in an
unprotected implementation and verify that the caller receives proper `TssStatus` error codes.

## SR-6: Fiat-Shamir Session Binding

**Requirement**: All Fiat-Shamir challenge computations MUST include a unique session
identifier.

**Rationale**: Without session binding, an attacker can replay protocol messages from
one session into another, potentially extracting key material. CVE-2022-47930
demonstrated this attack on tss-lib.

**Implementation**:
- FROST: The `SigningPackage` includes the message, all commitments in sorted order,
  and the group verifying key in the binding factor computation:
  `ρ_i = H1(verifying_key || H4(msg) || H5(commitments) || identifier_i)`
- FROST DKG: Proof of knowledge includes the participant's identifier and the
  ciphersuite ID in the Fiat-Shamir hash
- DKLs23 (v0.4.1): All protocol oracles use explicit domain-separated tagged hashing
  via `tagged_hash(tag, components)` with versioned tags from `utilities::oracle_tags`.
  The multiplication protocol SID includes party indices, DKG session ID, signing
  session ID, and BIP-32 chain code. See [05-dkls23-integration.md](05-dkls23-integration.md#domain-separated-oracle-tags-tag-system)
  for the full tag registry.
- All hash-based commitments use the TAG system's length-delimited encoding

## SR-7: Serialization Safety

**Requirement**: Serialization MUST use length-prefixed encoding, never delimiter-based
concatenation.

**Rationale**: CVE-2022-47931 showed that dollar-separator concatenation in hash inputs
enables collision attacks that compromise the threshold signing protocol.

**Implementation**:
- FROST uses serde with built-in length-prefixed encoding for all hash inputs
- DKLs23 (v0.4.1) uses `tagged_hash()` with length-delimited encoding:
  `len(tag)||tag||len(c₀)||c₀||...` where all lengths are 8-byte big-endian `u64`.
  The legacy `hash(msg, salt)` API is deprecated and unused by internal protocol oracles.
- BTreeMap serialization produces sorted, deterministic output
- No string concatenation in any hash preimage computation

## SR-8: Commitment Verification Order

**Requirement**: Commitments MUST be verified BEFORE decommitments are processed.

**Rationale**: Processing decommitments before verifying commitments can lead to
information leakage that enables protocol attacks.

**Implementation**:
- FROST DKG Round 2: Verifies all Round 1 proofs of knowledge before generating shares
- FROST signing Round 2: Validates all commitments match before computing signature share
- DKLs23: Commitment verification happens at the start of each phase before processing
  the decommitted values

## SR-9: Cheater Identification

**Requirement**: Protocol failures MUST identify the misbehaving participant(s) when
possible.

**Rationale**: Without cheater identification, a single malicious party can repeatedly
cause aborts with no accountability. Identification enables exclusion and retry.

**Implementation**:
- FROST aggregation: On signature verification failure, each share is individually
  verified against its commitment. Shares that fail verification are reported via
  `TssError::Abort { culprits }`
- FROST DKG: Invalid proofs of knowledge report the culprit's `Identifier`
- FROST DKG: Invalid secret shares report the sender's `Identifier`
- DKLs23: `Abort` errors include the `index` of the reporting party and, for ban aborts,
  the specific counterparty to exclude via `AbortKind::BanCounterparty(party_index)`.
  Two severity levels are distinguished: `Recoverable` (safe to retry) and
  `BanCounterparty` (mandatory permanent exclusion to prevent key extraction via OT
  correlation leakage)

## SR-10: Cofactor Handling

**Requirement**: Signature verification MUST account for group cofactors.

**Rationale**: Some elliptic curve groups (e.g., Ed25519, Ed448) have a cofactor > 1.
Failing to multiply by the cofactor during verification can lead to accepting
signatures from small-subgroup points.

**Implementation**:
- FROST-core's `verify_signature` method multiplies by the group cofactor when present
- secp256k1 and P-256 have cofactor 1 (no special handling needed)
- Ed25519 (cofactor 8) and Ed448 (cofactor 4) verification includes cofactor multiplication
- Ristretto255 handles this internally via the ristretto encoding

## SR-11: Secure Randomness

**Requirement**: All random values MUST be generated from a cryptographically secure
random number generator.

**Rationale**: Predictable randomness in nonce generation, polynomial coefficients, or
OT setup enables key extraction.

**Implementation**:
- Rust uses `OsRng` (from the `rand` crate) which reads from `/dev/urandom` on Linux
- FROST nonce generation additionally hashes randomness with the secret share
  (hedged generation) for protection against weak RNGs
- DKLs23 uses `get_rng()` which wraps the system CSPRNG
- The `insecure-rng` feature (deterministic RNG for testing) is NEVER available in
  release builds. The FFI crate does NOT expose this feature.

## SR-12: Handle Safety

**Requirement**: The handle system MUST prevent use-after-free, type confusion, and
double-free.

**Rationale**: The FFI boundary uses `u64` handles to reference Rust-side state. Without
proper safeguards, consumer code could accidentally use an invalid handle, causing
undefined behavior.

**Implementation**:
- SlotMap with generation counters: each handle encodes a generation number that is
  incremented when a slot is reused. Stale handles fail lookup.
- Category bits: the top 4 bits of the handle encode the value's type category.
  Attempting to use a FROST key handle as a DKLs23 party handle returns an error.
- `take()` vs `get()` vs `get_mut()`: consuming operations use `take()` which
  atomically removes the value. Session `next()` uses `get_mut()` for in-place
  advancement. The same handle cannot be consumed twice.
- `free()` is idempotent: freeing an already-freed handle is a no-op.
- All registry access is behind a `Mutex`, preventing data races.

## Security Audit Checklist

For external auditors, the following areas are critical:

- [ ] Constant-time scalar multiplication in k256 and curve25519-dalek
- [ ] `Zeroize` implementation effectiveness (no compiler elision)
- [ ] `catch_unwind` coverage on all FFI entry points
- [ ] Nonce lifecycle enforcement (single-use guarantee)
- [ ] Fiat-Shamir hash inputs include all required binding data
- [ ] No secret values cross the FFI boundary as byte slices
- [ ] Input validation completeness (all deserialized network data)
- [ ] Handle registry prevents use-after-free
- [ ] Commitment verification order (before decommitment processing)
- [ ] BIP-32 derivation tweak validation (IL < curve order)
- [ ] OT base case security (DKLs23 endemic OT proofs)
- [ ] Multiplication consistency checks (DKLs23 signing Phase 2)
- [ ] Ban abort propagation: `TssError::Abort { ban: Some(_) }` correctly maps to `TSS_ERR_ABORT_BAN`
- [ ] No panic paths in DKLs23 protocol phases (all `Result<T, Abort>`)
- [ ] Session state machines (`DkgSession`, `SignSession`) enforce phase ordering and prevent reuse
- [ ] Tagged hash domain separation: all 17 oracle tags are unique and versioned
- [ ] Input validation completeness at protocol phase entry points (routing, counts, duplicates)
- [ ] `AbortReason::PhaseCalledOutOfOrder` is returned (not a panic) when sessions are misused
- [ ] Unified `SignSession` for FROST correctly zeroes nonces after round 2 share computation
- [ ] Unified `SignSession` returns `TssError::SessionComplete` after `Complete` output, preventing reuse
- [ ] Unified `Message` wire format correctly distinguishes broadcast (`to=0`) from P2P messages
- [ ] FROST `SignSession` round 3 (local aggregation) uses the same `frost_aggregate` path as standalone aggregation
- [ ] Intermediate DKG secrets (`round1_secret`, `round2_secret`) wrapped in `Zeroizing<Vec<u8>>`
- [ ] Signing nonces in `FrostSignPhase` wrapped in `Zeroizing<Vec<u8>>`
- [ ] `tss_buffer_free()` zeroes data before deallocation (no plaintext in freed heap)
- [ ] `tss_init(TSS_INIT_MLOCK)` correctly calls `mlockall` and handles permission errors
- [ ] Go `SecureBytes` via memguard uses mmap+mlock, bypassing GC entirely
- [ ] Go `FrostSplitKey` wipes input `secretKey` after use
- [ ] Go `buildCSliceArray` zeroes C-heap copies before `C.free()`
- [ ] .NET `SecureBytes` uses `Marshal.AllocHGlobal` + `mlock`/`VirtualLock`, bypassing GC
- [ ] .NET `SecureBytes.Dispose` zeroes via `NativeMemory.Clear` before freeing
- [ ] .NET `ExportKeyShareSecure` copies directly from native buffer to unmanaged memory (no managed `byte[]`)
- [ ] .NET `ImportKeyShareSecure` reads directly from `SecureBytes` unmanaged pointer
- [ ] .NET `SplitKey` zeros input `secretKey` via `CryptographicOperations.ZeroMemory`
- [ ] .NET `RefreshDealer`/`RepairPart1` parse from native memory via `ReadOnlySpan<byte>` (no intermediate copy)
- [ ] React Native: raw key share bytes never cross the JS bridge (only opaque string IDs)
- [ ] React Native iOS: `exportKeyShareSecure` uses `dataWithBytesNoCopy` (zero-copy) and `tss_buffer_free` zeroes after `SecItemAdd`
- [ ] React Native iOS: `importKeyShareSecure` force-wipes `SecItemCopyMatching` result via `memset`
- [ ] React Native Android: JNI `nativeImportKeyShareRaw` uses `GetByteArrayRegion` (not `GetByteArrayElements`) and zeroes the C++ vector
- [ ] React Native Android: `exportKeyShareSecure` zeroes plaintext `byte[]` via `Arrays.fill` after AES-GCM encryption
- [ ] React Native Android: AndroidKeyStore AES-GCM key is hardware-backed where available
- [ ] WASM `SecureKeyShare` stores plaintext in `Zeroizing<Vec<u8>>` (WASM linear memory, zeroed on drop)
- [ ] WASM `SecureKeyShare.encrypt()` passes plaintext as `&[u8]` slice (no JS heap copy) to SubtleCrypto
- [ ] WASM `SecureKeyShare.decrypt()` copies decrypted ArrayBuffer into `Zeroizing<Vec<u8>>` immediately
- [ ] WASM `importShare()` wraps input bytes in `Zeroizing<Vec<u8>>` for Rust-side zeroing
- [ ] WASM `encrypt()` generates a fresh 96-bit IV for every encryption (no IV reuse)
- [ ] WASM `wipeBytes()` calls `Uint8Array.fill(0)` as best-effort JS-side zeroing
- [ ] Python `SecureBytes` uses `sodium_malloc` (preferred) or `libc.malloc` + `mlock`, bypassing GC
- [ ] Python `SecureBytes.destroy` zeroes memory before freeing (via `sodium_free` or `memset`)
- [ ] Python `SecureBytes.memoryview()` provides zero-copy access (no GC-heap `bytes` copy)
- [ ] Python `SecureBytes.__del__` captures `ctypes.memset`/`ctypes.addressof` as class variables for GC teardown
- [ ] Python `TssSlice.__del__` zeroes backing arrays on garbage collection
- [ ] Python `export_secure` copies through mutable `bytearray` (wiped by SecureBytes constructor)
- [ ] Python `import_secure` reads via `memoryview`, wipes intermediate ctypes array
- [ ] Python `split_key` wipes mutable `bytearray` input after use
- [ ] Python `init(mlock=True)` calls `tss_init` and disables core dumps
