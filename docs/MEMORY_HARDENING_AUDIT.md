# Memory Hardening Audit Report

**Date**: 2026-03-22
**Scope**: Rust core (`libtss`, `libtss-ffi`), Go (`libtss-go`), .NET (`libtss-dotnet`), Node.js (`libtss-node`)
**Related PRs**: #76 (Rust + Go), #82 (.NET), #83 (Node.js), #84 (nil guard fix)

## Executive Summary

All four implemented language bindings (Go, .NET, Node.js, Rust FFI) provide memory hardening for threshold signing key material, with binding-specific differences documented below (see "Remaining Gaps"). The handle-based architecture ensures that during normal operation consumer languages never hold raw secret scalars; all key material lives in the Rust-side `HandleRegistry` behind opaque `u64` handles. The export APIs (`ExportKeyShareSecure()` / `SecureBytes` / `SecureBuffer`) intentionally materialize serialized secrets in consumer-managed protected memory (mlock'd or GC-isolated). Node.js lacks `mlock` on its `SecureBuffer`; WASM has no memory hardening (non-custodial only).

## Audit Findings by Layer

### 1. Rust Core (`libtss`)

| Property | Status | Evidence |
|----------|--------|----------|
| **FROST KeyPackage: ZeroizeOnDrop** | PASS | All 6 FROST ciphersuite KeyPackage types implement `ZeroizeOnDrop` (verified via compile-time trait assertion in `tests/memory_hardening.rs`) |
| **DKLs23 Party: Zeroize** | PASS | `Party<Secp256k1>` and `Party<NistP256>` implement `Zeroize`. The upstream `DKLs23` crate provides a manual `Drop` impl that zeroes the `poly_point` scalar. |
| **DKLs23 Party: not Copy** | PASS | Neither `Party<Secp256k1>` nor `Party<NistP256>` implements `Copy` (verified via `trybuild` compile-fail tests in `tests/compile_fail/`). This prevents accidental shallow copies of secret material. |
| **KeyShareInner Drop** | PASS | When `KeyShareInner` is dropped, Rust drops each field, triggering `ZeroizeOnDrop` (FROST) or manual `Drop+Zeroize` (DKLs23) on the secret-bearing inner types. |
| **KeyShareHandle Drop** | PASS | `KeyShareHandle::drop()` calls `REGISTRY.free(self.id)`, which removes the `KeyShareInner` from the registry and triggers its `Drop`. |
| **Export path uses Zeroizing** | PASS | `KeyShareHandle::export()` wraps the serialized payload in `Zeroizing<Vec<u8>>` (`keyshare.rs:120`). The `Zeroizing` wrapper implements `ZeroizeOnDrop`, so the serialized key material is zeroed when the temporary goes out of scope. |
| **HandleRegistry double-free** | PASS | `free()` is idempotent: if the key is already removed from the `SlotMap`, the call is a no-op. Tested in `tests/memory_hardening.rs::handle_free_is_idempotent`. |
| **HandleRegistry use-after-free** | PASS | `with()` / `with_mut()` / `take()` return `Err(HandleInvalid)` for freed handles. Tested in `tests/memory_hardening.rs::handle_free_returns_error_after_freed`. |

### 2. FFI Layer (`libtss-ffi`)

| Property | Status | Evidence |
|----------|--------|----------|
| **tss_buffer_free zeroes data** | PASS | `memory.rs:25` calls `(*raw).zeroize()` before `drop(Box::from_raw(raw))`. The `TssBuffer` is then set to `empty()`. Zeroing is verified by code review (reading freed memory would be UB). Struct reset tested in `tests/memory_hardening_ffi.rs::buffer_free_resets_struct_to_empty`. |
| **tss_buffer_free double-free** | PASS | After the first free, `buf` is set to `empty()` (null data, len 0). A second call short-circuits at the null check. Tested in `tests/memory_hardening_ffi.rs::buffer_free_double_free_is_safe`. |
| **tss_handle_free idempotent** | PASS | Delegates to `REGISTRY.free()` which is already idempotent. Tested in `tests/memory_hardening_ffi.rs::handle_free_twice_is_safe`. |
| **tss_init(MLOCK) graceful** | PASS | On systems without `CAP_IPC_LOCK`, returns an error status (not a crash). Tested in `tests/memory_hardening_ffi.rs::init_with_mlock_succeeds_or_fails_gracefully`. |
| **tss_session_free(0)** | PASS | Freeing a nonexistent session handle is a no-op. Tested in `tests/memory_hardening_ffi.rs::session_free_nonexistent_is_noop`. |

### 3. Go Binding (`libtss-go`)

| Property | Status | Evidence |
|----------|--------|----------|
| **SecureBytes uses memguard** | PASS | `NewSecureBytes()` calls `memguard.NewBufferFromBytes()` which `mmap`s + `mlock`s memory outside the GC heap, then wipes the source slice. |
| **SecureBytes.Destroy() idempotent** | PASS | Checks `s.buf == nil` before calling `buf.Destroy()`. Sets `buf = nil` after. Tested in `memory_hardening_test.go::TestSecureBytesDestroyIdempotent`. |
| **SecureBytes nil-safe** | PASS | All methods check for nil receiver. Tested in `memory_hardening_test.go::TestSecureBytesNilReceiver`. |
| **SecureBytes Seal/Open lifecycle** | PASS | `Seal()` encrypts in-place and returns an `Enclave`. `Open()` recovers the data. Tested in `memory_hardening_test.go::TestSecureBytesFullLifecycle`. |
| **ExportKeyShareSecure lifecycle** | PASS | `ExportKeyShareSecure()` calls `ExportKeyShare()` then wraps in `NewSecureBytes()`, which wipes the GC-heap copy. The secure export can be re-imported. Tested in `memory_hardening_test.go::TestExportKeyShareSecureLifecycle`. |
| **FrostSplitKey wipes secretKey** | PASS | `defer WipeBytes(secretKey)` at the top of `FrostSplitKey()`. Tested in `memory_hardening_test.go::TestFrostSplitKeyWipesSecretKey`. |
| **buildCSliceArray C-alloc zeroing** | PASS | The `cleanup` closure in `frost.go:264-271` calls `C.memset(p, 0, ...)` on each C-allocated copy before `C.free(p)`. All `buildCSliceArray` call sites (`FrostRepairPart2`, `FrostRepairPart3`) use `defer cleanup()`. |
| **bufferToBytes calls tss_buffer_free** | PASS | `errors.go:74-76`: after `C.GoBytes()` copies to Go heap, `C.tss_buffer_free(buf)` zeroes and frees the Rust-side buffer. |
| **KeyShareHandle GC finalizer** | PASS | `newKeyShareHandle()` registers a finalizer that calls `h.Free()`. `Free()` clears the finalizer and calls `native.free()`. Double-free is safe (mutex-protected, zero check). |
| **Init disables core dumps** | PASS | `Init()` calls `memcall.DisableCoreDumps()` after `tss_init()`. |
| **WipeBytes** | PASS | Delegates to `memguard.WipeBytes()`. Tested for various sizes in `memory_hardening_test.go::TestWipeBytesZeroesAllBytes`. |

**Known limitation (documented)**: `FrostSplitKey()` accepts `secretKey []byte` from the caller. The Go GC may have already copied this data before the library can wipe it. This is inherent to Go's memory model and is documented in `SECURITY.md`.

### 4. .NET Binding (`libtss-dotnet`)

| Property | Status | Evidence |
|----------|--------|----------|
| **SecureBytes uses unmanaged memory** | PASS | Constructor calls `Marshal.AllocHGlobal()` + `mlock()`, then wipes source via `CryptographicOperations.ZeroMemory()`. |
| **SecureBytes.Dispose() idempotent** | PASS | Uses `Interlocked.CompareExchange` for atomic dispose flag. Tested in `MemoryHardeningTests.cs::SecureBytes_DisposeIsIdempotent`. |
| **SecureBytes throws after dispose** | PASS | `ThrowIfDisposed()` checks the `_disposed` flag. Tested in `MemoryHardeningTests.cs::SecureBytes_ThrowsAfterDispose`. |
| **SecureBytes finalizer** | PASS | `~SecureBytes()` zeroes and frees memory if `Dispose()` was not called. Same `Interlocked` guard prevents double-cleanup. |
| **ExportKeyShareSecure no managed copy** | PASS | `KeyShareHandle.ExportKeyShareSecure()` (`KeyShareHandle.cs:154-181`) allocates `SecureBytes(len)` (unmanaged), then copies directly from the native `TssBuffer.Data` pointer via `Buffer.MemoryCopy()`. The `TssBuffer` is freed in the `finally` block. No intermediate `byte[]` is created. |
| **KeyShareHandle.Dispose() idempotent** | PASS | Uses `Interlocked.CompareExchange`. Tested in `MemoryHardeningTests.cs::KeyShareHandle_DisposeIsIdempotent`. |
| **KeyShareHandle finalizer** | PASS | `~KeyShareHandle()` calls `tss_handle_free()` if not already disposed. |
| **Init with prctl** | PASS | `Tss.Init(Mlock)` calls `prctl(PR_SET_DUMPABLE, 0)` on Linux (best-effort). |
| **WipeBytes** | PASS | `Tss.WipeBytes()` delegates to `CryptographicOperations.ZeroMemory()`. Tested for various sizes. |

### 5. Node.js Binding (`libtss-node`)

| Property | Status | Evidence |
|----------|--------|----------|
| **SecureBuffer uses allocUnsafeSlow** | PASS | Constructor calls `Buffer.allocUnsafeSlow(data.length)` which allocates outside V8's pooled slab, preventing GC from copying the data. Source is wiped via `wipeBytes()`. |
| **SecureBuffer.destroy() idempotent** | PASS | Checks `this._buf === null` before zeroing. Tested in `memory_hardening.test.ts`. |
| **SecureBuffer.bytes() throws after destroy** | PASS | Throws `Error("SecureBuffer has been destroyed")`. Tested. |
| **SecureBuffer.wrap()** | PASS | Takes ownership of a pre-allocated Buffer without copying. Destroy zeroes the original buffer. Tested. |
| **Symbol.dispose support** | PASS | `SecureBuffer.prototype[Symbol.dispose]` is aliased to `destroy()`. Works on Node >= 20.4. Tested. |
| **readBufferSecure** | PASS | `ffi.ts:196-208` allocates `Buffer.allocUnsafeSlow(len)`, copies from `koffi.view()` (a zero-copy typed array view into the native buffer), then calls `tss_buffer_free()`. The `koffi.view()` intermediate is a typed array *view* (not a copy) into the native allocation — when `tss_buffer_free` zeroes and frees the native memory, the view becomes invalid but no V8-heap copy was made. |
| **readBuffer (non-secure path)** | NOTE | `readBuffer()` calls `.slice()` on the `koffi.view()` which creates a V8-heap copy. This is the expected behavior for non-sensitive data (public keys, verifying shares, etc.). The secure path (`readBufferSecure`) avoids this. |
| **FinalizationRegistry for handles** | PASS | `handle.ts:11-13` registers each `KeyShareHandle` for cleanup via `FinalizationRegistry`. `free()` unregisters and calls `tss_handle_free()`. |
| **wipeBytes** | PASS | `buf.fill(0)`. Tested for various sizes. |

**Known limitation (documented)**: `Buffer.allocUnsafeSlow` is not `mlock`'d. Under extreme memory pressure, the OS may swap these pages. For server-side deployments, also enable mlock via `tss_init()`.

## Remaining Gaps

| Gap | Severity | Mitigation |
|-----|----------|------------|
| **Rust: no automatic `prctl`/`setrlimit`** | Low | Documented in SECURITY.md. Deployment configuration responsibility. Go and .NET bindings handle this automatically. |
| **Node.js: no `mlock`** | Medium | `Buffer.allocUnsafeSlow` is outside V8 slab but not locked. Calling `tss_init(MLOCK)` via FFI locks *all* pages including these. Documented. |
| **WASM: no hardening** | Medium | WASM linear memory is inherently visible to the host. libtss-wasm does not provide `SecureBytes`. Documented as non-custodial only. Tracked separately in #81. |
| **Python: not yet implemented** | N/A | Tracked in #77. |
| **React Native: not yet implemented** | N/A | Tracked in #80. |

## Verification Test Coverage

| Test file | Layer | Tests |
|-----------|-------|-------|
| `libtss/tests/memory_hardening.rs` | Rust core | Trait assertions (Zeroize, ZeroizeOnDrop), handle double-free, Zeroizing wrapper, not-Copy (via `trybuild` compile-fail in `tests/compile_fail/`) |
| `libtss-ffi/tests/memory_hardening_ffi.rs` | FFI | Buffer zeroing, buffer double-free, handle double-free, mlock init, session free safety |
| `libtss-go/tss/memory_hardening_test.go` | Go | SecureBytes lifecycle, WipeBytes, FrostSplitKey wipe, handle double-free, ExportKeyShareSecure, Init |
| `libtss-dotnet/tests/Libtss.Tests/MemoryHardeningTests.cs` | .NET | SecureBytes lifecycle, WipeBytes, KeyShareHandle lifecycle, ExportKeyShareSecure, Init |
| `libtss-node/src/__tests__/memory_hardening.test.ts` | Node.js | SecureBuffer lifecycle, wipeBytes, Symbol.dispose, Buffer.wrap, large buffers |
