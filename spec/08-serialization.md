# 08 - Serialization

## Design Principles

1. **Protocol messages are opaque bytes** -- consumer languages do not parse protocol-internal
   serialization formats. Messages are byte blobs produced and consumed by Rust.
2. **Public types have defined formats** -- `PublicKeyPackage`, `Signature`, `Identifier`
   have documented serialization for storage and interoperability.
3. **Key share export is versioned** -- enables forward-compatible format evolution.
4. **No JSON at the FFI boundary** -- unlike the existing prototype, all FFI data passes
   as typed C structs (`TssBuffer`, `TssSlice`) via the standard C ABI.

## Unified Message Wire Format

All protocol messages are wrapped in the unified `Message` TLV format for transport
across the FFI boundary. Each message has a fixed 8-byte header:

```
┌──────────────┬───────────────┬──────────────┬──────────────────────┐
│ from (2B LE) │ to (2B LE)   │ len (4B LE)  │ data (len bytes)     │
│              │ 0 = broadcast │              │                      │
└──────────────┴───────────────┴──────────────┴──────────────────────┘
```

Multiple messages are concatenated in a single `TssBuffer`. Helper functions
`tss_message_count()`, `tss_message_at()`, and `tss_message_build()` parse and
construct these buffers. See [06-ffi-layer.md](06-ffi-layer.md) for details.

The `data` payload within each message is an opaque protocol-specific blob —
consumer languages route messages based on `from`/`to` without parsing `data`.

## Internal Protocol Message Encoding

### FROST Messages

FROST protocol messages use the frost-core serialization format internally
(inside the `data` field of a `Message`):

| Message | Content | Encoding |
|---------|---------|----------|
| DKG Round 1 Package | VSS commitment + PoK | `frost_core::keys::dkg::round1::Package::serialize()` |
| DKG Round 2 Package | Secret share for recipient | `frost_core::keys::dkg::round2::Package::serialize()` |
| Signing Commitment | Hiding + binding commitments | `frost_core::round1::SigningCommitments::serialize()` |
| Signature Share | Scalar share value | `frost_core::round2::SignatureShare::serialize()` |

Each serialized message includes:
- **Version byte** (currently 0)
- **Ciphersuite ID string** (for deserialization validation)
- **Payload** (type-specific)

Consumer languages treat these as opaque byte arrays -- they route them between
participants without parsing the contents. Deserialization and validation happen in Rust.

### DKLs23 Messages

DKLs23 messages use serde with bincode encoding:

| Message | Content | Size Estimate (2-of-3) |
|---------|---------|----------------------|
| DKG Phase 1 fragments | Scalar evaluations | ~32 bytes per fragment |
| DKG Phase 2 broadcast | Commitment + DLog proof | ~2 KB |
| DKG Phase 2 P2P | Zero-share init data | ~512 bytes per pair |
| DKG Phase 3 P2P | OT extension data | ~8 KB per pair |
| Sign Phase 1 broadcast | Instance point commitment | ~64 bytes |
| Sign Phase 1 P2P | OT data | ~4 KB per pair |
| Sign Phase 2 P2P | Correlation data | ~256 bytes per pair |
| Sign Phase 3 broadcast | `(u, w)` scalars | ~64 bytes |

## Public Type Serialization

### Identifier

```
┌──────────────────────────┐
│ Scalar bytes (32 bytes)  │  Big-endian encoding of the scalar value
└──────────────────────────┘
```

For the common case of small integer identifiers (1-65535), the scalar is the
field element corresponding to that integer.

### Signature

**FROST (Schnorr):**
```
┌──────────────────────────────────────────────────────┐
│ R (32-33 bytes)        │ z (32 bytes)                │
│ Group element          │ Scalar                      │
└──────────────────────────────────────────────────────┘
```

Size varies by ciphersuite:
- secp256k1 Taproot (BIP-340): 64 bytes (32-byte x-only R + 32-byte z)
- secp256k1: 65 bytes (33-byte compressed R + 32-byte z)
- Ed25519: 64 bytes (32-byte R + 32-byte z)
- P-256: 65 bytes (33-byte compressed R + 32-byte z)

**DKLs23 (ECDSA):**
```
┌──────────────────────────────────────────────────────┐
│ r (32 bytes)           │ s (32 bytes)                │
│ Scalar (big-endian)    │ Scalar (big-endian)         │
├──────────────────────────────────────────────────────┤
│ v (1 byte, optional)   │ Recovery ID (0 or 1)        │
└──────────────────────────────────────────────────────┘
```

Standard 64-byte ECDSA signature + optional 1-byte recovery ID.
DER encoding is available via a helper function.

### PublicKeyPackage

```
┌────────────────────────────────────────────────────┐
│ Header                                             │
│  version: u16                                     │
│  ciphersuite: u8                                  │
│  min_signers: u16                                 │
│  num_shares: u16                                  │
├────────────────────────────────────────────────────┤
│ Group Verifying Key                                │
│  length: u16                                      │
│  bytes: [u8; length]                              │
├────────────────────────────────────────────────────┤
│ Verifying Shares (repeated num_shares times)       │
│  identifier: [u8; scalar_size]                    │
│  share: [u8; element_size]                        │
└────────────────────────────────────────────────────┘
```

### Key Share Export (see also 07-key-management.md)

```
┌────────────────────────────────────────────┐
│ Magic bytes: "LTSS" (4 bytes)              │
│ Version: u16 (1)                           │
│ Protocol: u8                               │
│ Ciphersuite: u8                            │
├────────────────────────────────────────────┤
│ Payload length: u32 (big-endian)           │
│ Payload: [u8; length]                      │
│  (serde-bincode serialized key material)   │
├────────────────────────────────────────────┤
│ Public key package (serialized)            │
│  length: u32                               │
│  data: [u8; length]                        │
├────────────────────────────────────────────┤
│ Chain code (optional)                      │
│  present: u8 (0 or 1)                     │
│  chain_code: [u8; 32] (if present)        │
├────────────────────────────────────────────┤
│ SHA-256 checksum (32 bytes)                │
│  covers all preceding bytes                │
└────────────────────────────────────────────┘
```

## Wire Format Considerations

### Length-Prefixed vs Delimiter-Based

All variable-length fields use **length-prefixed** encoding. This prevents the
delimiter collision vulnerability found in multiple TSS implementations
(CVE-2022-47931: dollar-separator concatenation enabled hash collisions).

### Canonical Encoding

Protocol messages that participate in Fiat-Shamir hashing MUST be canonically encoded:
- Maps are serialized in sorted key order (BTreeMap in Rust)
- No duplicate keys
- No optional padding or alignment bytes
- Field order is fixed by the struct definition

This is enforced by Rust's serde + bincode, which produces deterministic output
for the same input.

### Endianness

All multi-byte integers use **big-endian** encoding, consistent with:
- BIP-340 signature format
- BIP-32 child index encoding
- secp256k1 scalar serialization
- Standard cryptographic conventions

## Interoperability

### FROST Signature Compatibility

Signatures produced by libtss are standard Schnorr/ECDSA signatures
indistinguishable from single-signer signatures:

| Ciphersuite | Compatible With |
|-------------|----------------|
| Secp256k1Taproot | BIP-340 verifiers, Bitcoin Core |
| Ed25519 | RFC 8032 verifiers, ed25519-dalek |
| Secp256k1ECDSA | Standard ECDSA verifiers, Ethereum |

### Cross-Implementation DKG

DKG messages are NOT expected to be interoperable across implementations.
Each implementation has its own internal serialization format. Interoperability
is at the signature level, not the protocol level.

### Key Share Migration

The key share export format is specific to libtss. Migrating key shares to/from
other implementations requires:
1. Export the secret scalar (if the other implementation supports it)
2. Re-share via trusted dealer (`SplitKey`)
3. Or run a new DKG

## Versioning Strategy

The serialization format includes version numbers at multiple levels:

| Level | Current Version | Location |
|-------|----------------|----------|
| Key share export | 1 | Export header |
| PublicKeyPackage | 1 | Serialization header |
| FROST protocol messages | 0 | frost-core `Header.version` |
| DKLs23 protocol messages | 4 | v0.4.1 adds curve-generic types (`Party<C>`, `PublicKeyPackage<C>`, etc.) and secp256r1 support. Tagged binary framing (`PhaseOutput`/`PhaseInput` with `MessageTag`), `EcdsaSignature`, and `PublicKeyPackage` since v0.3.0. Wire-incompatible with v0.1.x; uses tagged hashing since v0.2.0. |

Version bumps follow these rules:
- **Patch**: Bug fixes in serialization (must be backward-compatible)
- **Minor**: New optional fields (old versions can read, new fields are ignored)
- **Major**: Breaking changes (old versions cannot read)

Deserialization rejects unknown major versions and warns on unknown minor versions.
