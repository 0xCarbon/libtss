# Security Policy

## Introduction
Thank you for helping us keep our project secure. This document outlines our security policy and provides instructions for reporting vulnerabilities.

## Reporting a Vulnerability
If you discover a security vulnerability, please report it to us in a responsible manner. To report a vulnerability, please email us at [fabio@0xcarbon.org](mailto:fabio@0xcarbon.org). Include the following details in your report:
- A description of the vulnerability
- Steps to reproduce the vulnerability
- Any potential impact of the vulnerability

## Expected Response Time
We will acknowledge your report within 48 hours and provide a detailed response within 5 business days, including an evaluation of the vulnerability and an expected resolution date.

## Responsible Disclosure
We ask that you do not disclose the vulnerability publicly until we have had a chance to address it. We believe in responsible disclosure and will work with you to ensure that vulnerabilities are fixed promptly.

## Memory Hardening

libtss implements defense-in-depth memory hardening across its Rust core and all language bindings. This section describes what libtss provides, what it does not, and how to configure your environment for maximum protection.

### What libtss provides

| Protection | Mechanism | Layer |
|------------|-----------|-------|
| **Deterministic zeroing** | All secret key material is zeroed when handles are freed or sessions complete. | Rust: `zeroize` crate (`write_volatile` + `compiler_fence`); Go: `memguard.WipeBytes`; .NET: `CryptographicOperations.ZeroMemory` / `NativeMemory.Clear`; Node.js: `buf.fill(0)` |
| **Swap prevention** | `mlockall(MCL_CURRENT \| MCL_FUTURE)` pins all process pages in RAM. | `tss_init(TSS_INIT_MLOCK)` / `Init(OptMlock)` / `Tss.Init(InitOptions.Mlock)` |
| **GC isolation** | Key shares are stored outside the language runtime's GC heap, preventing the garbage collector from copying secret data to unpredictable memory locations. | Go: `memguard.LockedBuffer` (mmap+mlock); .NET: `Marshal.AllocHGlobal` + `mlock`; Node.js: `Buffer.allocUnsafeSlow` (outside V8 slab) |
| **Core dump prevention** | Prevents secret material from appearing in core dumps. | Go: `memcall.DisableCoreDumps()`; .NET: `prctl(PR_SET_DUMPABLE, 0)` on Linux; Rust: caller must set `RLIMIT_CORE=0` |
| **Handle-based API** | During normal operation, consumer languages never hold raw secret bytes — all key shares are stored in a Rust-side registry behind opaque `u64` handles. The export APIs (`ExportKeyShareSecure()` / `SecureBytes`) intentionally materialize serialized secrets in consumer-managed protected memory. | All bindings |
| **Double-free safety** | Freeing an already-freed handle is a safe no-op (not undefined behavior). | Rust `HandleRegistry` + binding wrappers |

### How to enable mlock

The `mlock` protection requires either:
- **Capability**: `CAP_IPC_LOCK` (set via `setcap cap_ipc_lock+ep /path/to/binary`)
- **Resource limit**: `ulimit -l unlimited` (or a sufficiently large value)

Without these, `tss_init(TSS_INIT_MLOCK)` will return an error. The library remains fully functional without mlock; it just means pages *may* be swapped to disk under memory pressure.

### What the consumer is responsible for

libtss hardens key material **within the process**. The following are outside the library's scope:

| Concern | Responsibility |
|---------|---------------|
| **Encrypting key shares at rest** | The consumer must encrypt the output of `ExportKeyShare()` / `ExportKeyShareSecure()` before persisting to disk or transmitting over a network. Use an authenticated encryption scheme (e.g., AES-256-GCM) with a key from a KMS or secure enclave. |
| **Caller-provided inputs** | When you pass a `secretKey []byte` to `FrostSplitKey()`, the library wipes it after use (`defer WipeBytes(secretKey)`). However, Go's GC may have already copied the data elsewhere on the heap. For maximum protection, use `SecureBytes` or keep secrets in `memguard.LockedBuffer` from the start. |
| **TEE / Confidential VM** | Hardware memory encryption (AMD SEV-SNP, Intel TDX, AWS Nitro) is an infrastructure-level decision. libtss benefits from CVM memory encryption transparently but does not require or configure it. |
| **Core dump prevention (Rust)** | The Rust layer does not call `prctl` or `setrlimit` automatically. Set `RLIMIT_CORE=0` in your deployment configuration if you need to prevent core dumps at the process level. |

### Known limitations

1. **GC copies of caller inputs**: When a Go/C#/Node.js caller passes a `byte[]` to the library, the runtime may have already created GC-managed copies. The library wipes the slice it receives, but earlier copies may persist until the GC reclaims their pages. Mitigation: use `SecureBytes` / `SecureBuffer` to keep secrets outside the GC heap from creation.

2. **WASM constraints**: WebAssembly linear memory cannot be `mlock`'d and is visible to the JavaScript host. The WASM binding (`libtss-wasm`) does not provide the same level of memory hardening as native bindings. WASM is suitable for non-custodial use cases only.

3. **Node.js `Buffer.allocUnsafeSlow`**: While this allocates outside V8's pooled slab allocator, the memory is not mlock'd. Under extreme memory pressure, the OS may swap these pages. For server-side Node.js deployments, also call `tss_init(TSS_INIT_MLOCK)` via the FFI.

## Acknowledgments
Thank you for helping us keep our project secure!
