# 04 - FROST Integration

## Protocol Reference

FROST (RFC 9591) implements two-round threshold Schnorr signatures. The ZCash Foundation
implementation (`frost-core` v3.0.0-rc.0) is the reference Rust crate.

## Ciphersuite Mapping

Each FROST ciphersuite is a separate Rust crate implementing the `Ciphersuite` trait:

| Ciphersuite Constant | Rust Crate | RFC 9591 ID | Curve | Hash |
|-------------|------------|-------------|-------|------|
| `Secp256k1Taproot` | `frost-secp256k1-tr` | `FROST-secp256k1-SHA256-TR-v1` | secp256k1 | SHA-256 |
| `Secp256k1` | `frost-secp256k1` | `FROST-secp256k1-SHA256-v1` | secp256k1 | SHA-256 |
| `Ed25519` | `frost-ed25519` | `FROST-ED25519-SHA512-v1` | Ed25519 | SHA-512 |
| `P256` | `frost-p256` | `FROST-P256-SHA256-v1` | NIST P-256 | SHA-256 |
| `Ristretto255` | `frost-ristretto255` | `FROST-RISTRETTO255-SHA512-v1` | ristretto255 | SHA-512 |
| `Ed448` | `frost-ed448` | `FROST-ED448-SHAKE256-v1` | Ed448 | SHAKE256 |

### Taproot-Specific Behavior

`frost-secp256k1-tr` overrides the `Ciphersuite` trait hooks to produce BIP-340-compatible
signatures:

- **x-only public keys**: 32 bytes (even Y coordinate enforced)
- **Nonce parity**: R is adjusted to have even Y; if odd, all nonces are negated
- **Challenge computation**: Uses BIP-340 tagged hash `BIP0340/challenge`
- **Tweaking support**: Plain tweaking (BIP-32) and x-only tweaking (BIP-341 Taproot)

The Rust crate implements `pre_sign()`, `pre_aggregate()`, `challenge()`, and
`compute_signature_share()` overrides to handle these transformations. The libtss
API is identical to other ciphersuites -- the differences are handled internally.

## Wrapped Types

### Internal Rust Types

The FFI crate defines internal wrapper types that flatten the generic FROST types
for each ciphersuite. These are used in the Rust implementation; the C ABI exposes
them as opaque byte buffers (`TssSlice`/`TssBuffer`):

```rust
// In libtss-ffi/src/frost.rs (internal, not exposed in C header)

pub(crate) struct FrostIdentifier {
    pub bytes: Vec<u8>,  // Serialized Identifier<C>
}

pub(crate) struct FrostDKGRound1Package {
    pub from: FrostIdentifier,
    pub data: Vec<u8>,  // Serialized keys::dkg::round1::Package<C>
}

pub(crate) struct FrostDKGRound2Package {
    pub from: FrostIdentifier,
    pub to: FrostIdentifier,
    pub data: Vec<u8>,  // Serialized keys::dkg::round2::Package<C>
}

pub(crate) struct FrostSigningCommitment {
    pub signer: FrostIdentifier,
    pub data: Vec<u8>,  // Serialized round1::SigningCommitments<C>
}

pub(crate) struct FrostSignatureShare {
    pub signer: FrostIdentifier,
    pub data: Vec<u8>,  // Serialized round2::SignatureShare<C>
}

pub(crate) struct FrostSignature {
    pub data: Vec<u8>,  // Serialized Signature<C>
}
```

### Secret State (Rust-side only)

These types are NEVER serialized across FFI. They live in a Rust-side handle registry:

| Rust Type | Lifetime | Content |
|-----------|----------|---------|
| `keys::dkg::round1::SecretPackage<C>` | DKG Round 1 → Round 2 | Polynomial coefficients, own commitment |
| `keys::dkg::round2::SecretPackage<C>` | DKG Round 2 → Round 3 | Round 1 data + received commitments |
| `KeyPackage<C>` | Permanent (key share) | Signing share, verifying share, group key |
| `round1::SigningNonces<C>` | Signing Round 1 → Round 2 | Hiding + binding nonces (MUST be single-use) |

Consumer languages receive opaque `uint64` handles that index into a Rust-side `SlotMap`.

## DKG Protocol Flow

```
                Party 1             Party 2             Party 3
                   │                   │                   │
  Round 1:         │                   │                   │
  part1()          ├──── Package1 ────►├──── Package1 ────►│
                   │◄─── Package2 ─────┤◄─── Package2 ─────┤
                   │◄─── Package3 ─────┤◄─── Package3 ─────│
                   │                   │                   │
  Round 2:         │                   │                   │
  part2()          │── Share(1→2) ────►│                   │
                   │── Share(1→3) ──────────────────────►  │
                   │◄─ Share(2→1) ─────┤── Share(2→3) ──►  │
                   │◄─ Share(3→1) ─────│◄─ Share(3→2) ─────┤
                   │                   │                   │
  Round 3:         │                   │                   │
  part3()          │  KeyPackage1      │  KeyPackage2      │  KeyPackage3
                   │  PublicKeyPkg     │  PublicKeyPkg     │  PublicKeyPkg
```

### C ABI (Unified Session API)

FROST DKG uses the unified session API (`tss_dkg_new` / `tss_dkg_next`):

```c
// Round 1: Create session, produce broadcast commitment.
TssStatus tss_dkg_new(suite, self_id, max_signers, min_signers,
                       NULL, 0,  // session_id: NULL for FROST
                       &session, &out_messages);

// Round 2: Process commitments, produce P2P secret shares.
TssStatus tss_dkg_next(session, received_messages,
                        &key_share, &pubkey_package, &out_messages, &complete);
// complete == false: out_messages contains P2P shares

// Round 3: Process shares, finalize key.
TssStatus tss_dkg_next(session, received_messages,
                        &key_share, &pubkey_package, &out_messages, &complete);
// complete == true: key_share and pubkey_package are valid
```

Internally, `tss_dkg_new` calls `frost::keys::dkg::part1()`, `tss_dkg_next` dispatches
to `part2()` then `part3()` based on the session's current round.

See [06-ffi-layer.md](06-ffi-layer.md) for the complete C header.

### Verification Steps (Rust-side)

Round 2 (`part2`) performs:
1. Check `round1_packages.len() == max_signers - 1`
2. Check no duplicate identifiers
3. Verify each participant's proof of knowledge (Schnorr PoK)
4. If DKG commitment hash is supported: verify `HDKG` binding

Round 3 (`part3`) performs:
1. Check `round2_packages.len() == max_signers - 1`
2. For each received share: verify against sender's VSS commitment
3. Sum all shares to produce final signing share
4. Verify final share against summed VSS commitments
5. Derive verifying shares for all participants

## Signing Protocol Flow

### Coordinator-Less Mode (Unified Session API)

In the unified API, each signer runs a 3-round session and aggregates locally:

```
                Signer A            Signer B
                   │                   │
  Round 1:         │                   │
  new()            ├── Commitment_A ──►│
                   │◄── Commitment_B ──┤
                   │                   │
  Round 2:         │                   │
  next()           │ (build package    │ (build package
                   │  internally)      │  internally)
                   ├── Share_A ───────►│
                   │◄── Share_B ───────┤
                   │                   │
  Round 3:         │                   │
  next()           │ aggregate()       │ aggregate()
                   │ → Signature       │ → Signature
```

Both signers produce the same final signature independently.

### Coordinator Mode (Traditional)

For deployments using a coordinator, signers use rounds 1-2 of the unified session,
and the coordinator calls `tss_frost_aggregate()` separately:

```
                Signer A            Signer B            Coordinator
                   │                   │                   │
  Round 1:         │                   │                   │
                   ├── Commitment_A ──────────────────────►│
                   │                   ├── Commitment_B ──►│
                   │                   │                   │
                   │◄─────────── All commitments ──────────┤
                   │                   │◄── All commits ───┤
                   │                   │                   │
  Round 2:         │                   │                   │
                   ├── Share_A ────────────────────────────►│
                   │                   ├── Share_B ────────►│
                   │                   │                   │
  Aggregate:       │                   │    aggregate()     │
                   │                   │    → Signature     │
```

### C ABI (Unified Session API)

FROST signing uses the unified session API (`tss_sign_new` / `tss_sign_next`).
The unified API operates in coordinator-less mode: each signer aggregates locally
in round 3 (instead of sending shares to a coordinator for aggregation).

```c
// Round 1: Create session, produce broadcast commitment.
// For FROST: counterparties and sign_id are NULL.
TssStatus tss_sign_new(key_share, message, NULL, 0, NULL, 0, &session, &out_messages);

// Round 2: Process all commitments, produce broadcast signature share.
TssStatus tss_sign_next(session, received_commitments,
                         &signature, &out_messages, &complete);
// complete == false: out_messages contains signature share broadcast

// Round 3: Process all shares, aggregate locally → final signature.
TssStatus tss_sign_next(session, received_shares,
                         &signature, &out_messages, &complete);
// complete == true: signature is valid
```

Internally, round 2 builds a `FrostSigningPackage` from received commitments + the
message stored at construction, calls `round2_sign()`, and stores the own share.
Round 3 calls `frost_aggregate()` with stored package + all received shares.

For coordinator-only deployments, use `tss_frost_aggregate()` directly:

```c
TssStatus tss_frost_aggregate(
    uint8_t suite, TssSlice message,
    TssSlice commitments, TssSlice shares,
    TssSlice pubkey_package, TssBuffer *out_signature
);
```

See [06-ffi-layer.md](06-ffi-layer.md) for the complete C header.

### Nonce Safety Enforcement

The signing nonce lifecycle is enforced at the Rust level:

1. `tss_sign_new` creates nonces internally and stores them in the `SignSession`
2. Round 2 (`tss_sign_next`) consumes the nonces — they are zeroed after computing
   the signature share
3. The `SignSession` tracks completion state: after returning `Complete`, subsequent
   calls to `next()` return `TSS_ERR_SESSION_COMPLETE`
4. If the session is dropped without completing, the nonces are zeroed via Rust's
   `Drop` + `Zeroize`

This ensures nonces can never be used for more than one signature, preventing the
catastrophic nonce reuse attack that allows full key recovery.

## Trusted Dealer Key Generation

For testing and migration:

```c
/* Generate shares via trusted dealer.
 * Returns handles to all KeyPackages via out_handles + serialized PublicKeyPackage. */
TssStatus tss_frost_generate_dealer(
    uint8_t suite,
    uint16_t max_signers,
    uint16_t min_signers,
    TssHandle *out_handles,
    size_t *out_handle_count,
    TssBuffer *out_pubkey_package
);

/* Split existing key into threshold shares. */
TssStatus tss_frost_split_key(
    uint8_t suite,
    TssSlice secret_key,
    uint16_t max_signers,
    uint16_t min_signers,
    TssHandle *out_handles,
    size_t *out_handle_count,
    TssBuffer *out_pubkey_package
);
```

## Taproot Tweaking (BIP-341)

The `frost-secp256k1-tr` crate provides a `Tweak` trait that applies BIP-341 tweaks
to key shares and public key packages. This enables both keypath and scriptpath spends.

### Tweak Computation

```rust
fn tweak(public_key: &Element, merkle_root: Option<&[u8]>) -> Scalar {
    let mut hasher = tagged_hash("TapTweak");
    hasher.update(public_key.to_affine().x());  // 32-byte x-only key
    if let Some(root) = merkle_root {
        hasher.update(root);
    }
    hasher_to_scalar(hasher)
}
```

### C ABI Functions

```c
/* Apply BIP-341 tweak to a key share.
 * merkle_root: zero-length for keypath-only, or 32-byte merkle root for scriptpath.
 * Returns a new key handle with the tweaked share.
 * The original handle remains valid (untweaked). */
TssStatus tss_frost_tweak_key_share(
    TssHandle key_handle,
    TssSlice merkle_root,
    TssHandle *out_handle
);

/* Apply BIP-341 tweak to a serialized PublicKeyPackage.
 * Returns the serialized tweaked PublicKeyPackage. */
TssStatus tss_frost_tweak_pubkey_pkg(
    uint8_t suite,
    TssSlice pubkey_pkg,
    TssSlice merkle_root,
    TssBuffer *out_pubkey_pkg
);
```

### Internal Steps (Rust Side)

1. Deserialize the `KeyPackage<Secp256K1Sha256TR>`
2. Normalize to even-Y via `into_even_y()` (BIP-340 requirement)
3. Compute tweak scalar `t = hash_TapTweak(pubkey_x [|| merkle_root])`
4. Apply: `new_signing_share = signing_share + t`
5. Apply: `new_verifying_key = verifying_key + t * G`
6. Apply: `new_verifying_share_i = verifying_share_i + t * G` for all participants
7. Return new `KeyPackage` wrapped in a handle

### Usage Pattern

All signers must apply the same tweak before signing:

```c
// Before signing, each signer tweaks their share:
TssHandle tweaked_share;
tss_frost_tweak_key_share(key_share, merkle_root, merkle_root_len, &tweaked_share);

// Now sign with the tweaked share using the unified session API:
TssHandle session;
TssBuffer out_messages;
tss_sign_new(tweaked_share, message, &session, &out_messages);
// ... normal new → next loop ...

tss_handle_free(tweaked_share);
```

### Keypath vs Scriptpath

| Spend Type | merkleRoot | On-chain Output Key |
|------------|------------|---------------------|
| Keypath only | empty (zero-length) | `P + hash_TapTweak(P) * G` |
| Scriptpath | 32-byte root | `P + hash_TapTweak(P \|\| root) * G` |

For keypath-only, the tweak prevents a malicious DKG participant from embedding
a hidden script path (a critical security requirement noted in BIP-FROST-Signing).

## Signature Verification

Single-signature verification uses the unified `tss_verify()` function:

```c
bool tss_verify(uint8_t suite, TssSlice message, TssSlice signature, TssSlice public_key);
```

The FROST signature `(R, z)` is verified as: `z * G == R + c * VerifyingKey`
where `c = H2(R || VerifyingKey || message)`.

For `Secp256k1Taproot`, this is BIP-340 Schnorr verification.

## Error Mapping

| Rust Error | TssStatus Code |
|------------|----------------|
| `Error::InvalidMinSigners` / `InvalidMaxSigners` | `TSS_ERR_INVALID_CONFIG` |
| `Error::MalformedIdentifier` | `TSS_ERR_INVALID_IDENTIFIER` |
| `Error::InvalidSecretShare { culprit }` | `TSS_ERR_ABORT` (culprit in `tss_last_error()`) |
| `Error::InvalidSignatureShare { culprits }` | `TSS_ERR_ABORT` (culprits in `tss_last_error()`) |
| `Error::InvalidProofOfKnowledge { culprit }` | `TSS_ERR_ABORT` (culprit in `tss_last_error()`) |
| `Error::DKGNotSupported` | `TSS_ERR_PROTOCOL_MISMATCH` |
| `Error::IncorrectCommitment` | `TSS_ERR_INVALID_COMMITMENT` |
| `Error::MalformedSignature` / `InvalidSignature` | `TSS_ERR_INVALID_SIGNATURE` |
| `Error::FieldError` / `GroupError` | `TSS_ERR_DESERIALIZE` |
