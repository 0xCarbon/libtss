# 03 - API Design

## Crate Structure

```
libtss/
├── Cargo.toml              # Workspace root
├── libtss/                  # Core Rust library (lib crate)
│   ├── src/
│   │   ├── lib.rs           # Public Rust API
│   │   ├── session.rs       # Unified DkgSession, SignSession, RefreshSession
│   │   ├── message.rs       # Unified Message type + wire format
│   │   ├── frost.rs         # FROST protocol wrappers (advanced API)
│   │   ├── dkls.rs          # DKLs23 protocol wrappers (advanced API)
│   │   ├── types.rs         # Shared types (Identifier, Signature, Config)
│   │   ├── derive.rs        # BIP-32 key derivation
│   │   ├── tweak.rs         # BIP-341 Taproot tweaking
│   │   ├── handle.rs        # Handle registry
│   │   └── error.rs         # Unified TssError
│   └── Cargo.toml
├── libtss-ffi/              # C ABI layer (cdylib + staticlib)
│   ├── src/
│   │   ├── lib.rs           # extern "C" functions
│   │   ├── types.rs         # C-compatible result/buffer types
│   │   └── error.rs         # Error code mapping
│   ├── cbindgen.toml        # Header generation config
│   └── Cargo.toml
├── libtss-go/               # Go binding (thin cgo wrapper)
│   ├── tss/                 # Go package
│   │   ├── session.go       # Unified DKG/Sign/Refresh sessions
│   │   ├── message.go       # Message parsing/building
│   │   ├── types.go
│   │   └── handle.go
│   └── go.mod
├── libtss-py/               # Python binding (PyO3 or cffi)
├── libtss-wasm/             # WASM binding (wasm-bindgen)
└── libtss-java/             # Java binding (JNI)
```

Two layers:
- **`libtss`**: Pure Rust library. Idiomatic Rust API with generics, `Result<T, E>`,
  and Rust ownership. Used directly by Rust applications.
- **`libtss-ffi`**: C ABI adapter. Flattens generics, converts `Result` to status codes,
  manages opaque handles. Consumed by every non-Rust language.

## Core Rust API (libtss crate)

### Protocol and Ciphersuite

```rust
/// Threshold signing protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// RFC 9591 threshold Schnorr signatures.
    Frost = 0,
    /// DKLs23 threshold ECDSA.
    DKLs23 = 1,
}

/// Ciphersuite identifier (curve + hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ciphersuite {
    /// FROST over secp256k1 with BIP-340 x-only keys (Taproot).
    Secp256k1Taproot = 0,
    /// FROST over secp256k1 with standard compressed keys.
    Secp256k1 = 1,
    /// FROST over Edwards25519 (Ed25519-compatible signatures).
    Ed25519 = 2,
    /// FROST over NIST P-256.
    P256 = 3,
    /// FROST over ristretto255.
    Ristretto255 = 4,
    /// FROST over Edwards448.
    Ed448 = 5,
    /// DKLs23 threshold ECDSA over secp256k1.
    Secp256k1ECDSA = 6,
    /// DKLs23 threshold ECDSA over secp256r1 (NIST P-256).
    Secp256r1ECDSA = 7,
}

impl Ciphersuite {
    pub fn protocol(&self) -> Protocol;
    pub fn scalar_size(&self) -> usize;
    pub fn element_size(&self) -> usize;
}
```

### Threshold Configuration

```rust
/// Threshold (t, n) parameters.
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    /// Minimum signers required (t). Must be >= 2.
    pub min_signers: u16,
    /// Total share holders (n). Must be >= min_signers.
    pub max_signers: u16,
    /// Ciphersuite determines protocol, curve, and hash.
    pub suite: Ciphersuite,
}

impl ThresholdConfig {
    pub fn validate(&self) -> Result<(), TssError>;
}
```

### Identifier

```rust
/// Participant identifier. Non-zero, 1-based index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Identifier(u16);

impl Identifier {
    /// Create from 1-based index. Returns error if index is 0.
    pub fn new(index: u16) -> Result<Self, TssError>;
    pub fn as_u16(&self) -> u16;
}
```

### Unified Message

```rust
/// Protocol message — opaque to the client.
///
/// Clients route messages based on the `to` field:
/// - `None` → broadcast to all other participants
/// - `Some(id)` → send to that specific participant (encrypted channel for DKLs23 P2P)
///
/// Message contents are produced and consumed by the library.
/// Clients MUST NOT parse or modify `data`.
#[derive(Debug, Clone)]
pub struct Message {
    pub from: Identifier,
    pub to: Option<Identifier>,
    pub data: Vec<u8>,
}
```

This single type replaces `FrostDKGRound1Package`, `FrostDKGRound2Package`,
`FrostSigningCommitment`, `FrostSignatureShare`, `FrostSigningPackage`,
`DKLsFragment`, `DKLsMessage`, and `DKLsMessageBundle` from the client's perspective.

The `to` field tells the client everything needed for routing and channel selection:
- `None` → broadcast (authenticated channel sufficient)
- `Some(id)` → point-to-point (authenticated + confidential channel required for
  DKLs23 P2P messages; FROST DKG Round 2 shares also require confidentiality)

### Unified Error

```rust
/// Library error type — replaces separate Error and AbortError.
#[derive(Debug)]
pub enum TssError {
    /// Invalid threshold configuration (t, n, suite).
    InvalidConfig(String),
    /// Identifier is zero or out of range.
    InvalidIdentifier,
    /// Key share validation failed.
    InvalidShare,
    /// Commitment verification failed.
    InvalidCommitment,
    /// Signature verification or format error.
    InvalidSignature,
    /// Attempted to reuse a consumed nonce or session.
    NonceReuse,
    /// Handle does not exist or has been freed.
    HandleInvalid,
    /// Wrong protocol for this operation (e.g., Taproot on DKLs23).
    ProtocolMismatch,
    /// Deserialization of protocol data failed.
    DeserializeFailed(String),
    /// BIP-341 tweaking error.
    TweakError(String),
    /// Session has already completed.
    SessionComplete,
    /// Protocol abort with culprit identification and severity.
    Abort {
        /// Participant(s) that caused the failure.
        culprits: Vec<Identifier>,
        /// Human-readable description (from DKLs23 AbortReason::Display or FROST error).
        message: String,
        /// If Some, this party MUST be permanently banned from all future sessions.
        /// Continuing to interact with a banned party enables gradual private key
        /// extraction via OT correlation leakage (DKLs23 only).
        ban: Option<Identifier>,
    },
}
```

One error type for the entire library. Protocol aborts (FROST verification failures,
DKLs23 `Abort` errors) are unified under `TssError::Abort`. For DKLs23, the `ban` field
maps directly from `AbortKind::BanCounterparty(PartyIndex)`. For FROST, `ban` is always
`None` (FROST does not reuse session state, so all failures are recoverable).

The `TssError::Abort.message` field is derived from DKLs23's structured `AbortReason` enum
(25+ variants) via its `Display` implementation. libtss can also inspect the upstream
`AbortReason` variant directly for programmatic handling (e.g., distinguishing
`OtConsistencyCheckFailed` from `MisroutedMessage`).

### Key Share Handle

```rust
/// Opaque handle to a key share stored in the handle registry.
/// Internally stores both the secret key material AND the associated
/// PublicKeyPackage, making the handle self-contained for signing.
/// Secret material is zeroed when the handle is dropped.
#[derive(Debug)]
pub struct KeyShareHandle {
    id: u64,
}

impl KeyShareHandle {
    /// Participant identifier for this share.
    pub fn identifier(&self) -> Identifier;

    /// Public verification key for this share.
    pub fn verifying_share(&self) -> Vec<u8>;

    /// Group public key (combined verification key).
    pub fn group_verifying_key(&self) -> Vec<u8>;

    /// Full public key package (group key + all verifying shares).
    pub fn public_key_package(&self) -> &PublicKeyPackage;

    /// Ciphersuite this share belongs to.
    pub fn ciphersuite(&self) -> Ciphersuite;

    /// Export for encrypted storage. Returns serialized secret material.
    /// Caller MUST encrypt before persisting.
    pub fn export(&self) -> Result<Vec<u8>, TssError>;
}

impl Drop for KeyShareHandle {
    fn drop(&mut self) {
        // Removes from registry, zeroes secret material.
        REGISTRY.free(self.id);
    }
}

/// Import a previously exported key share.
pub fn import_key_share(data: &[u8], suite: Ciphersuite) -> Result<KeyShareHandle, TssError>;
```

The handle stores both the secret key share and the `PublicKeyPackage` internally. This
makes `SignSession::new(key_share, message)` self-sufficient — the session accesses the
public key package through the handle without requiring an extra parameter.

### Public Key Package

```rust
/// Group public key and per-participant verification shares.
/// All public information — safe to share freely.
#[derive(Debug, Clone)]
pub struct PublicKeyPackage {
    suite: Ciphersuite,
    verifying_key: Vec<u8>,
    verifying_shares: BTreeMap<Identifier, Vec<u8>>,
    min_signers: u16,
}

impl PublicKeyPackage {
    pub fn verifying_key(&self) -> &[u8];
    pub fn verifying_share(&self, id: Identifier) -> Option<&[u8]>;
    pub fn min_signers(&self) -> u16;
    pub fn serialize(&self) -> Result<Vec<u8>, TssError>;
    pub fn deserialize(data: &[u8]) -> Result<Self, TssError>;
}
```

## Unified Session API

All interactive protocols (DKG, signing, refresh) follow the same pattern:

```
session, messages = new(params...)   // creates session + first-round messages
send(messages)

loop:
    received = receive()
    output = session.next(received)
    if output.complete:
        result = output.result
        break
    send(output.messages)
```

This pattern works identically for FROST (3-round DKG, 3-round signing) and DKLs23
(4-phase DKG, 4-phase signing). The client never needs to know which protocol is
running — the session handles the difference internally.

### DkgSession

```rust
/// Protocol-agnostic distributed key generation session.
///
/// Wraps either FROST DKG (3 rounds) or DKLs23 DKG (4 phases) internally.
/// The client uses the same `new()` → `next()` loop regardless of protocol.
pub struct DkgSession { /* ... */ }

/// DKG round output.
pub enum DkgOutput {
    /// More messages to exchange. Call `next()` again after receiving responses.
    Continue(Vec<Message>),
    /// DKG complete.
    Complete {
        key_share: KeyShareHandle,
        public_keys: PublicKeyPackage,
    },
}

impl DkgSession {
    /// Create a DKG session and produce first-round messages.
    ///
    /// For FROST: generates polynomial + commitment + proof of knowledge.
    /// For DKLs23: generates polynomial + evaluates fragments for each party.
    ///
    /// `session_id` is required for DKLs23 (domain separation). For FROST,
    /// pass `None` and the session will use the ciphersuite's built-in binding.
    pub fn new(
        config: &ThresholdConfig,
        self_id: Identifier,
        session_id: Option<&[u8]>,
    ) -> Result<(Self, Vec<Message>), TssError>;

    /// Process received messages and advance the protocol.
    ///
    /// Returns `Continue(messages)` with messages to send, or `Complete`
    /// with the final key share and public key package.
    ///
    /// FROST DKG: 2 calls to `next()` (round 2: P2P shares, round 3: finalize).
    /// DKLs23 DKG: 3 calls to `next()` (phases 2-4).
    pub fn next(&mut self, received: &[Message]) -> Result<DkgOutput, TssError>;

    /// Current round number (1-based). Round 1 was executed during `new()`.
    pub fn round(&self) -> u8;

    /// Total number of rounds for this protocol's DKG.
    /// FROST: 3. DKLs23: 4.
    pub fn num_rounds(&self) -> u8;

    /// Protocol being used.
    pub fn protocol(&self) -> Protocol;
}
```

#### Internal Dispatch

| Round | FROST | DKLs23 |
|-------|-------|--------|
| `new()` (round 1) | `frost::keys::dkg::part1()` → broadcast commitment | `DkgSession::phase1()` → P2P fragments |
| `next()` (round 2) | `part2(commitments)` → P2P secret shares | `phase2(fragments)` → broadcast + P2P |
| `next()` (round 3) | `part3(shares)` → `Complete(key, pubkeys)` | `phase3(messages)` → broadcast + P2P |
| `next()` (round 4) | — | `phase4(messages)` → `Complete(party, pubkeys)` |

### SignSession

```rust
/// Protocol-agnostic signing session.
///
/// Wraps either FROST signing (3 rounds: commit → share → aggregate) or
/// DKLs23 signing (4 phases) internally.
///
/// Both protocols produce a final `Signature` — FROST includes a local
/// aggregation step as round 3 so every participant gets the signature.
pub struct SignSession { /* ... */ }

/// Signing round output.
pub enum SignOutput {
    /// More messages to exchange.
    Continue(Vec<Message>),
    /// Signing complete.
    Complete(Signature),
}

impl SignSession {
    /// Create a signing session and produce first-round messages.
    ///
    /// The message to sign is provided at construction (DKLs23 needs it
    /// for phase 1; FROST stores it for use in round 2).
    ///
    /// For FROST: generates nonces and returns commitment broadcast.
    /// For DKLs23: runs phase 1 (instance key + OT start), returns
    ///   broadcast commitment + P2P OT data.
    pub fn new(
        key_share: &KeyShareHandle,
        message: &[u8],
    ) -> Result<(Self, Vec<Message>), TssError>;

    /// Process received messages and advance the protocol.
    ///
    /// FROST: 2 calls to `next()`:
    ///   1. Receive all commitments → compute + broadcast signature share
    ///   2. Receive all shares → aggregate locally → `Complete(Signature)`
    ///
    /// DKLs23: 3 calls to `next()`:
    ///   1. phase2(received) → P2P correlation data
    ///   2. phase3(received) → broadcast (u, w)
    ///   3. phase4(received) → `Complete(Signature)`
    pub fn next(&mut self, received: &[Message]) -> Result<SignOutput, TssError>;

    pub fn round(&self) -> u8;
    pub fn num_rounds(&self) -> u8;
    pub fn protocol(&self) -> Protocol;
}
```

#### FROST Signing: Coordinator-Less Mode

The unified `SignSession` operates FROST signing in coordinator-less mode by default,
adding a local aggregation step as round 3:

```
Round 1 (new):  Generate nonces → broadcast commitment
Round 2 (next): Receive all commitments → build SigningPackage internally
                → compute signature share → broadcast share
Round 3 (next): Receive all shares → aggregate locally → Signature
```

This means FROST signing uses 3 communication rounds in the unified API (vs 2 in
the traditional coordinator model). The extra round is "receive all shares and
aggregate locally" — participants broadcast shares to each other instead of sending
them to a coordinator.

For deployments using a coordinator topology:
- The coordinator relays commitments (round 1) and shares (round 2) between signers
- Each signer still runs the 3-round session
- The coordinator is just a message relay, not a cryptographic participant

For coordinator-only deployments (where the coordinator aggregates and signers do not),
use the standalone `frost_aggregate()` function directly.

#### Internal Dispatch

| Round | FROST | DKLs23 |
|-------|-------|--------|
| `new()` (round 1) | `round1_commit()` → broadcast commitment; store message | `SignSession::new(party, data)` → broadcast + P2P |
| `next()` (round 2) | Build `SigningPackage` from received commitments + stored message; `round2_sign()` → broadcast share | `phase2(received)` → P2P correlation data |
| `next()` (round 3) | `frost_aggregate(package, self_share + received_shares, pubkeys)` → `Complete(Signature)` | `phase3(received)` → broadcast (u, w) |
| `next()` (round 4) | — | `phase4(received)` → `Complete(Signature)` |

### RefreshSession

```rust
/// Protocol-agnostic share refresh session.
///
/// Wraps either FROST DKG-based refresh (3 rounds) or DKLs23 complete
/// refresh (4 phases). Produces new key shares of the same secret key.
pub struct RefreshSession { /* ... */ }

pub enum RefreshOutput {
    Continue(Vec<Message>),
    Complete {
        key_share: KeyShareHandle,
        public_keys: PublicKeyPackage,
    },
}

impl RefreshSession {
    /// Interactive share refresh (recommended mode).
    ///
    /// FROST: DKG-based refresh with zero-constant polynomial.
    /// DKLs23: Complete refresh (re-initializes OT/multiplication state).
    pub fn new(key_share: &KeyShareHandle) -> Result<(Self, Vec<Message>), TssError>;

    /// Create a FROST refresh receiver session (non-dealer participant).
    /// The receiver waits for messages from the dealer refresh and does
    /// not produce initial messages. Use with `frost_refresh_with_dealer`.
    /// Returns `TssError::ProtocolMismatch` for DKLs23 key shares.
    pub fn new_frost_receiver(key_share: &KeyShareHandle) -> Result<Self, TssError>;

    pub fn next(&mut self, received: &[Message]) -> Result<RefreshOutput, TssError>;
    pub fn round(&self) -> u8;
    pub fn num_rounds(&self) -> u8;
}
```

## Common Types

### Signature

```rust
/// Threshold signature (indistinguishable from single-signer).
#[derive(Debug, Clone)]
pub struct Signature {
    protocol: Protocol,
    data: Vec<u8>,
}

impl Signature {
    /// Raw signature bytes.
    /// FROST/BIP-340: 64 bytes (32-byte R + 32-byte z).
    /// ECDSA: 64 bytes (32-byte r + 32-byte s).
    pub fn as_bytes(&self) -> &[u8];

    /// ECDSA recovery ID (0 or 1). Returns None for FROST.
    pub fn recovery_id(&self) -> Option<u8>;

    /// Verify against group public key and message.
    pub fn verify(&self, public_key: &[u8], message: &[u8]) -> bool;

    pub fn protocol(&self) -> Protocol;
}
```

### BIP-32 Key Derivation

```rust
/// Derive a child key share (non-hardened BIP-32).
/// Returns a NEW handle; parent handle remains valid.
pub fn derive_child(
    key_share: &KeyShareHandle,
    child_number: u32, // Must be < 2^31
) -> Result<KeyShareHandle, TssError>;

/// Derive along a full BIP-32 path (e.g., "m/44/0/0/0").
pub fn derive_path(
    key_share: &KeyShareHandle,
    path: &str,
) -> Result<KeyShareHandle, TssError>;
```

## FROST-Specific Operations

These operations exist only for FROST and are not part of the unified session API.

### Coordinator Aggregation

For coordinator-only deployments where a non-signing coordinator aggregates
signature shares, use this standalone function instead of `SignSession`:

```rust
/// Aggregate FROST signature shares into a final Schnorr signature.
///
/// This is for coordinator-only deployments. When using `SignSession`,
/// aggregation happens automatically in round 3.
///
/// The `commitments` and `shares` are `Message` values received from
/// signers during rounds 1 and 2 respectively.
pub fn frost_aggregate(
    message: &[u8],
    commitments: &[Message],
    shares: &[Message],
    pubkeys: &PublicKeyPackage,
) -> Result<Signature, TssError>;
```

### Taproot Tweaking (BIP-341)

```rust
/// Apply a BIP-341 Taproot tweak to a key share.
/// merkle_root: None for keypath-only, Some(root) for scriptpath.
/// Returns a NEW key share handle; the original remains valid.
/// Only valid for Secp256k1Taproot ciphersuite.
pub fn frost_tweak_key_share(
    key_share: &KeyShareHandle,
    merkle_root: Option<&[u8]>,
) -> Result<KeyShareHandle, TssError>;

/// Apply a BIP-341 Taproot tweak to a public key package.
pub fn frost_tweak_pubkey_package(
    pubkeys: &PublicKeyPackage,
    merkle_root: Option<&[u8]>,
) -> Result<PublicKeyPackage, TssError>;
```

### Trusted Dealer

```rust
/// Generate key shares via trusted dealer (for testing/migration).
pub fn frost_generate_with_dealer(
    config: &ThresholdConfig,
) -> Result<(Vec<KeyShareHandle>, PublicKeyPackage), TssError>;

/// Split an existing secret key into threshold shares.
pub fn frost_split_key(
    config: &ThresholdConfig,
    secret_key: &[u8],
) -> Result<(Vec<KeyShareHandle>, PublicKeyPackage), TssError>;

/// Trusted dealer refresh: generate refreshing shares without interaction.
/// The group public key does NOT change.
pub fn frost_refresh_with_dealer(
    pubkeys: &PublicKeyPackage,
    participants: &[Identifier],
) -> Result<(BTreeMap<Identifier, Vec<u8>>, PublicKeyPackage), TssError>;

/// Apply a trusted-dealer refreshing share to an existing key share.
pub fn frost_apply_refresh(
    key_share: &KeyShareHandle,
    refresh_data: &[u8],
) -> Result<KeyShareHandle, TssError>;
```

### Share Repair (FROST Only)

```rust
/// Generate repair deltas (called by each helper).
pub fn frost_repair_part1(
    key_share: &KeyShareHandle,
    helpers: &[Identifier],
    participant: Identifier,
) -> Result<BTreeMap<Identifier, Vec<u8>>, TssError>;

/// Sum received deltas into sigma (called by each helper).
pub fn frost_repair_part2(deltas: &[Vec<u8>]) -> Result<Vec<u8>, TssError>;

/// Reconstruct key share from sigmas (called by the recovering participant).
pub fn frost_repair_part3(
    sigmas: &[Vec<u8>],
    participant: Identifier,
    pubkeys: &PublicKeyPackage,
) -> Result<KeyShareHandle, TssError>;
```

## Channel Security

The library is transport-agnostic but imposes requirements on channels.

### Routing by Message.to

The unified `Message` type tells the client exactly what channel properties each
message needs:

| `Message.to` | Channel Type | Authentication | Confidentiality |
|--------------|-------------|----------------|-----------------|
| `None` | Broadcast | Required | Not required |
| `Some(id)` (FROST DKG R2) | P2P | Required | **Required** |
| `Some(id)` (DKLs23 any) | P2P | Required | **Required** |
| `Some(id)` (FROST signing) | P2P | Required | Not required |

For simplicity, applications may treat all P2P messages (`to: Some`) as requiring
confidentiality. This is safe and avoids protocol-specific routing logic.

### DKLs23 P2P Encryption

**The DKLs23 protocol crate (0xCarbon) provides NO transport encryption.**
All P2P messages contain OT data that MUST be encrypted by the application.

Minimum requirements:
- AEAD cipher (ChaCha20-Poly1305 or AES-256-GCM)
- Ephemeral key agreement per session (X25519)
- Unique nonce per message **per direction** (TOB-SILA-6)
- Sender identity verification

## Advanced: Protocol-Specific APIs

For advanced use cases requiring fine-grained control over individual protocol rounds,
the protocol-specific session types remain available as a lower layer:

```rust
// Protocol-specific API (advanced — most clients should use the unified API)
pub mod frost {
    pub struct FrostDKGSession { /* ... */ }
    pub struct FrostSigningSession { /* ... */ }
    pub struct FrostRefreshSession { /* ... */ }
    // Protocol-specific message types (FrostDKGRound1Package, etc.)
}

pub mod dkls {
    pub struct DKLsDKGSession { /* ... */ }
    pub struct DKLsSigningSession { /* ... */ }
    pub struct DKLsRefreshSession { /* ... */ }
    // Protocol-specific message types (DKLsFragment, DKLsMessageBundle, etc.)
}
```

The unified `DkgSession`, `SignSession`, and `RefreshSession` are implemented as
dispatching wrappers over these protocol-specific types. The unified API is the
recommended interface for most clients.

## C ABI Surface

The C ABI in `libtss-ffi` is the stable interface consumed by all non-Rust bindings.
See [06-ffi-layer.md](06-ffi-layer.md) for the complete C function signatures
and memory conventions.

## Language Binding Examples

Each language binding wraps the C ABI with idiomatic types. Because the unified session
API uses a single pattern for all protocols, bindings are thin (~300-500 LoC).

### Go

```go
package tss

// #cgo LDFLAGS: -llibtss -ldl -lm
// #include "libtss.h"
import "C"

// DKG — same code works for FROST and DKLs23
func RunDKG(config ThresholdConfig, selfID Identifier, sessionID []byte, transport Transport) (*KeyShareHandle, *PublicKeyPackage, error) {
    session, msgs, err := NewDKGSession(config, selfID, sessionID)
    if err != nil {
        return nil, nil, err
    }
    defer session.Free()

    transport.Send(msgs)

    for {
        received := transport.Receive()
        output, err := session.Next(received)
        if err != nil {
            return nil, nil, err
        }
        if output.Complete() {
            return output.KeyShare(), output.PublicKeys(), nil
        }
        transport.Send(output.Messages())
    }
}

// Signing — identical pattern
func Sign(keyShare *KeyShareHandle, message []byte, transport Transport) (*Signature, error) {
    session, msgs, err := NewSignSession(keyShare, message)
    if err != nil {
        return nil, err
    }
    defer session.Free()

    transport.Send(msgs)

    for {
        received := transport.Receive()
        output, err := session.Next(received)
        if err != nil {
            return nil, err
        }
        if output.Complete() {
            return output.Signature(), nil
        }
        transport.Send(output.Messages())
    }
}
```

### Python

```python
import tss

# DKG
session, msgs = tss.new_dkg_session(config, my_id, session_id)
transport.send(msgs)

while True:
    received = transport.receive()
    output = session.next(received)
    if output.complete:
        key_share, pubkeys = output.key_share, output.public_keys
        break
    transport.send(output.messages)

# Signing — identical pattern
session, msgs = tss.new_sign_session(key_share, message)
transport.send(msgs)

while True:
    received = transport.receive()
    output = session.next(received)
    if output.complete:
        signature = output.signature
        break
    transport.send(output.messages)
```

### TypeScript (WASM)

```typescript
import { newDkgSession, newSignSession, type Message } from 'libtss-wasm';

// DKG
let [session, msgs] = newDkgSession(config, selfId, sessionId);
await transport.send(msgs);

while (true) {
  const received = await transport.receive();
  const output = session.next(received);
  if (output.complete) {
    const { keyShare, publicKeys } = output;
    break;
  }
  await transport.send(output.messages);
}
```

## Design Invariants

1. **Sessions complete via `next()`**: The final `next()` call returns `Complete` and
   marks the session as finished. Subsequent calls return `TssError::SessionComplete`.
2. **Nonces are single-use**: FROST signing nonces are generated in `new()` and consumed
   internally during `next()`. They cannot be reused.
3. **Secrets never leave Rust**: `KeyShareHandle.export()` is the only way to get
   secret bytes out, and it documents the encryption requirement.
4. **One error type**: All public functions return `Result<T, TssError>`. The FFI layer
   adds `catch_unwind` as defense-in-depth.
5. **No I/O, no runtime**: The library is `#[no_std]`-compatible in its core.
   All I/O and concurrency are the application's responsibility.
6. **Key shares are self-contained**: `KeyShareHandle` stores both the secret material
   and the `PublicKeyPackage`, making sessions self-sufficient.
7. **Protocol-agnostic client code**: A client using `DkgSession` + `SignSession` does
   not need any protocol-specific logic. The ciphersuite selection at `DkgSession::new()`
   is the only protocol-specific decision.
