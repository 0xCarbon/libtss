# 10 - Testing Strategy

## Test Levels

### Level 1: Rust Unit Tests

The underlying Rust crates (frost-core, dkls23) have their own comprehensive test
suites. These are NOT part of libtss's test scope but MUST pass as a prerequisite.

Upstream tests are run against the git dependencies:
- [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost): `cargo test --workspace`
- [0xCarbon/DKLs23](https://github.com/0xCarbon/DKLs23): `cargo test`

### Level 2: FFI Adapter Tests

Tests for the libtss-ffi crate that verify the adapter layer correctly wraps the
protocol libraries.

```bash
cd rust/libtss-ffi && cargo test
```

**Test categories**:

| Category | Description |
|----------|-------------|
| Handle lifecycle | Create, get, take, free, double-free, use-after-free |
| Error conversion | All Rust errors map to correct error codes |
| Panic safety | Invalid inputs don't propagate panics |
| Serialization round-trip | Serialize→deserialize identity for all public types |

### Level 3: Integration Tests

End-to-end tests exercising the full stack through the C ABI. Written in Rust
(as `#[test]` functions calling the `extern "C"` entry points) and optionally
in each language binding's test suite.

```bash
cd libtss-ffi && cargo test --test integration
```

**Test categories**:

#### Protocol Correctness

| Test | Description |
|------|-------------|
| `TestFROSTDKG_2of3` | 2-of-3 FROST DKG produces valid key shares |
| `TestFROSTDKG_3of5` | 3-of-5 FROST DKG produces valid key shares |
| `TestFROSTSign_2of3` | 2 of 3 signers produce a valid Schnorr signature |
| `TestFROSTSign_3of5` | 3 of 5 signers produce a valid Schnorr signature |
| `TestFROSTSign_AllCiphersuites` | Signing works for each supported ciphersuite |
| `TestDKLsDKG_2of2` | 2-of-2 DKLs23 DKG (simplest case) |
| `TestDKLsDKG_2of3` | 2-of-3 DKLs23 DKG |
| `TestDKLsSign_2of2` | 2-of-2 DKLs23 signing produces valid ECDSA |
| `TestDKLsSign_2of3` | 2-of-3 DKLs23 signing |
| `TestDealerKeyGen` | Trusted dealer key generation + signing |
| `TestSplitKey` | Existing key split + threshold signing produces valid sig |

#### Verification

| Test | Description |
|------|-------------|
| `TestFROSTVerify_ExternalSig` | Verify known-good Schnorr signatures from other implementations |
| `TestFROSTVerify_BIP340Vectors` | Verify against official BIP-340 test vectors |
| `TestDKLsVerify_ExternalSig` | Verify known-good ECDSA signatures |
| `TestSignatureIndistinguishable` | Threshold sig verifies with standard single-signer verifier |

#### Key Management

| Test | Description |
|------|-------------|
| `TestDeriveChild` | BIP-32 child derivation produces correct public key |
| `TestDerivePath` | Multi-level path derivation matches reference |
| `TestDeriveChild_AllParties` | All parties derive same child public key independently |
| `TestRefresh_FROST` | Share refresh preserves signing ability |
| `TestRefresh_DKLs` | Complete and quick refresh preserve signing |
| `TestRefresh_OldSharesInvalid` | Old shares cannot produce valid signatures after refresh |
| `TestRepair_FROST` | Share repair reconstructs a working share |
| `TestExportImport` | Exported share imports correctly and can sign |

#### Error Handling

| Test | Description |
|------|-------------|
| `TestInvalidConfig` | Bad threshold configs return `ErrInvalidConfig` |
| `TestNonceReuse` | Reusing a signing session returns `ErrNonceReuse` |
| `TestFreedHandle` | Using a freed handle returns `ErrHandleFreed` |
| `TestInvalidShare` | Tampered share in aggregation identifies culprit |
| `TestInvalidCommitment` | Tampered commitment detected in round 2 |
| `TestInvalidDKGPackage` | Bad DKG package identified with culprit |
| `TestProtocolMismatch` | Using FROST handle with DKLs function returns error |
| `TestDKLsBanAbort` | Tampered OT data returns `TSS_ERR_ABORT_BAN` with correct banned party |
| `TestDKLsRecoverableAbort` | Invalid input (e.g. duplicate counterparty) returns `TSS_ERR_ABORT` (not BAN) |
| `TestDKLsBanPartyId` | `tss_abort_banned_party()` returns correct party index after ban abort |
| `TestDKLsInputValidation` | Wrong message count, misrouted messages, missing mul state all return recoverable abort |

#### Concurrency

| Test | Description |
|------|-------------|
| `test_concurrent_signing` | Multiple threads sign with different sessions |
| `test_concurrent_dkg` | Multiple DKG sessions run in parallel |
| `test_concurrent_handle_free` | Concurrent `tss_handle_free()` calls don't race |

### Level 4: Cross-Implementation Validation

Verify that signatures produced by libtss are accepted by independent implementations.

| libtss Output | Verified By |
|----------------|-------------|
| FROST secp256k1-TR signature | Bitcoin Core `OP_CHECKSIG` (BIP-340) |
| FROST Ed25519 signature | `ed25519-dalek` (Rust), `crypto/ed25519` (Go) |
| FROST P-256 signature | `p256` (Rust), `crypto/ecdsa` (Go) |
| DKLs23 ECDSA signature | `k256` (Rust), `crypto/ecdsa` (Go), `viem` (React Native/JS) |

### Level 5: Known Answer Tests (KAT)

Deterministic test vectors for regression testing. Generated with a fixed seed
(using the `insecure-rng` feature in a separate test binary, never in the production
library).

**FROST KAT**:
- frost-core includes test vectors in each ciphersuite crate's `tests/` directory
- These vectors include intermediate values (nonces, binding factors, etc.)
- libtss validates that the same inputs produce the same outputs

**DKLs23 KAT**:
- The existing prototype generates deterministic test data via
  `dkg_testdatagen.rs` and `sign_testdatagen.rs`
- libtss validates against SHA-256 hashes of expected outputs (same approach)

## Fuzzing

### C ABI Boundary Fuzzing

Fuzz the FFI boundary with arbitrary byte inputs to detect memory safety issues:

```rust
// In libtss-ffi/fuzz/
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz deserialization of protocol messages via unified session API
    let slice = libtss_ffi::TssSlice { data: data.as_ptr(), len: data.len() };
    let mut out_messages = libtss_ffi::TssBuffer::default();
    let mut complete = false;
    // Should return error status, never crash
    let _ = unsafe {
        libtss_ffi::tss_dkg_next(0, slice, &mut 0u64, &mut out_messages, &mut out_messages, &mut complete)
    };
});
```

### Protocol Input Fuzzing

Fuzz protocol functions with random/malformed messages:

```rust
fuzz_target!(|data: (&[u8], &[u8])| {
    let (messages, message) = data;
    // Should return error status, never crash
    let _ = unsafe {
        libtss_ffi::tss_sign_next(
            0, // invalid session handle
            TssSlice::from(messages),
            &mut TssBuffer::default(),
            &mut TssBuffer::default(),
            &mut false,
        )
    };
});
```

### Handle Fuzzing

Fuzz the handle system with random IDs:

```rust
fuzz_target!(|handle: u64| {
    // Should return errors, never crash
    let _ = unsafe { libtss_ffi::tss_handle_free(handle) };
    let mut out = TssBuffer::default();
    let _ = unsafe { libtss_ffi::tss_group_verifying_key(handle, &mut out) };
});
```

## Benchmarks

### Microbenchmarks

```rust
// In libtss-ffi/benches/
#[bench] fn bench_frost_dkg_2of3()        // Full DKG
#[bench] fn bench_frost_sign_2of3()       // Full signing (Round 1 + Round 2 + Aggregate)
#[bench] fn bench_frost_commit()          // Round 1 only
#[bench] fn bench_frost_sign_share()      // Round 2 only
#[bench] fn bench_frost_aggregate()       // Aggregation only
#[bench] fn bench_dkls_dkg_2of2()
#[bench] fn bench_dkls_sign_2of2()
#[bench] fn bench_derive_child()
#[bench] fn bench_ffi_call_overhead()     // Empty extern "C" round-trip
#[bench] fn bench_export_import()
```

### Expected Performance (rough targets, per operation)

| Operation | Target | Notes |
|-----------|--------|-------|
| FFI call overhead | < 10ns | Standard C ABI call ~1-5ns |
| FROST DKG (2-of-3) | < 50ms | 3 rounds, includes PoK |
| FROST Sign (2-of-3) | < 5ms | 2 rounds |
| FROST Aggregate | < 1ms | Single-party operation |
| DKLs23 DKG (2-of-2) | < 200ms | 4 phases, includes OT setup |
| DKLs23 Sign (2-of-2) | < 50ms | 4 phases, includes OT extension |
| BIP-32 Derive Child | < 1ms | Single HMAC + scalar add |
| Key Share Export | < 1ms | Serialization |

## CI/CD Integration

### Test Pipeline

```yaml
# .github/workflows/test.yml
steps:
  - name: Build libtss
    run: cargo build --release --workspace

  - name: Run Rust unit + integration tests
    run: cargo test --workspace

  - name: Run clippy
    run: cargo clippy --workspace -- -D warnings

  - name: Run benchmarks (smoke)
    run: cargo bench --workspace -- --test

  - name: Run fuzzing (short)
    run: cargo +nightly fuzz run fuzz_ffi -- -max_total_time=60

  - name: Build C header
    run: cbindgen --crate libtss-ffi --output libtss.h

  - name: Cross-compile targets
    run: |
      cargo build --release --target aarch64-unknown-linux-gnu
      cargo build --release --target aarch64-linux-android
      cargo build --release --target aarch64-apple-ios
```

### Test Environment

- OS: Linux (Ubuntu 22.04+), macOS, Windows (cross-compilation)
- Rust: 1.81+ (MSRV for frost-core)
- No network access required (all tests are local)
- No real cryptographic keys at risk (all tests use fresh or deterministic keys)

## Security Testing

### Deliberate Misbehavior Tests

Simulate malicious participants:

| Test | Misbehavior | Expected Result |
|------|-------------|-----------------|
| `TestCheaterDKG_BadPoK` | Send invalid proof of knowledge in DKG Round 1 | `TssError::Abort` with cheater's `Identifier` |
| `TestCheaterDKG_BadShare` | Send incorrect secret share in DKG Round 2 | `TssError::Abort` with cheater's `Identifier` |
| `TestCheaterSign_BadShare` | Submit incorrect signature share | `TssError::Abort` with cheater's `Identifier` |
| `TestCheaterSign_BadCommitment` | Modify commitment after broadcasting | Detected in Round 2 |
| `TestReplayMessage` | Replay Round 1 message in Round 2 | Deserialization error |
| `TestTruncatedMessage` | Send truncated protocol message | Deserialization error |
| `TestExtraParticipant` | Include unexpected participant in commitments | `ErrInvalidCommitment` |
| `TestMissingParticipant` | Omit a required participant's message | `ErrInvalidCommitment` |
| `TestDKLsCheaterSign_OTCorruption` | Corrupt OT extension data in signing Phase 2 | `TSS_ERR_ABORT_BAN` with culprit |
| `TestDKLsCheaterSign_MulCorruption` | Corrupt multiplication proof data in Phase 3 | `TSS_ERR_ABORT_BAN` with culprit |
| `TestDKLsCheaterSign_GammaU` | Tamper with γ_u consistency value | `TSS_ERR_ABORT_BAN` with culprit |
| `TestDKLsMisroutedMessage` | Send P2P message with wrong receiver field | `TSS_ERR_ABORT` (recoverable) |
| `TestDKLsDuplicateCounterparty` | Include same counterparty twice in signing set | `TSS_ERR_ABORT` (recoverable) |
