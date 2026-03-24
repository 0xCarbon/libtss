# libtss Specification

A Rust threshold signing library providing a unified, safe interface over production-grade
implementations of FROST (RFC 9591) and DKLs23. Exposed via C ABI for consumption by
Go (Linux), Rust, and React Native.

## Documents

| # | Document | Description |
|---|----------|-------------|
| 01 | [Overview](01-overview.md) | Goals, architecture, and design philosophy |
| 02 | [Threat Model](02-threat-model.md) | Security model, adversary capabilities, trust assumptions |
| 03 | [API Design](03-api-design.md) | Rust public API + C ABI surface + language binding patterns |
| 04 | [FROST Integration](04-frost-integration.md) | FROST protocol wrapping: ciphersuites, DKG, signing, tweaking |
| 05 | [DKLs23 Integration](05-dkls23-integration.md) | DKLs23 protocol wrapping: DKG, signing, OT internals |
| 06 | [FFI Layer](06-ffi-layer.md) | C ABI design: functions, types, memory, build system |
| 07 | [Key Management](07-key-management.md) | BIP-32 derivation, share refresh, share repair |
| 08 | [Serialization](08-serialization.md) | Wire formats, encoding, versioning |
| 09 | [Security Requirements](09-security-requirements.md) | Constant-time ops, nonce safety, secret zeroing, input validation |
| 10 | [Testing Strategy](10-testing.md) | Test vectors, fuzzing, cross-implementation validation |
| 11 | [References](11-references.md) | Papers, audits, known vulnerabilities, implementations, authors |

## Design Principles

1. **Secrets stay in Rust** -- all secret key material lives in Rust-managed memory with `zeroize` on drop
2. **Consumers get opaque handles** -- every language binding works with `uint64` handle IDs, never raw key bytes
3. **Unified API** -- one consistent interface for both FROST (Schnorr) and DKLs23 (ECDSA)
4. **Transport-agnostic** -- no network, no async runtime, no threads. Pure computation: bytes in, bytes out
5. **C ABI for universality** -- standard `extern "C"` functions consumable by Go (cgo), Rust (direct), and React Native (native modules)
6. **Fail closed** -- errors are explicit, panics never cross FFI, invalid inputs are rejected early
