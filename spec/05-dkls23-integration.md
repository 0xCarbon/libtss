# 05 - DKLs23 Integration

## Protocol Reference

DKLs23 implements threshold ECDSA based on oblivious transfer, as described in
[eprint 2023/765](https://eprint.iacr.org/2023/765). The 0xCarbon implementation
(v0.4.1) is the Rust workspace at [github.com/0xCarbon/DKLs23](https://github.com/0xCarbon/DKLs23),
structured as three crates: `dkls23-core` (v0.4.1, curve-generic), `dkls23-secp256k1`
(v0.4.2), and `dkls23-secp256r1` (v0.4.1).

### Implementation Landscape

Two major open-source Rust implementations exist:

| | [0xCarbon DKLs23](https://github.com/0xCarbon/DKLs23) | Silence Labs |
|---|---|---|
| **Version** | 0.4.1 (multi-crate workspace) | Production |
| **Curves** | secp256k1, secp256r1 (NIST P-256) | secp256k1 |
| **Audit** | Internal security review (Mar 2026) -- [PR #46](https://github.com/0xCarbon/DKLs23/pull/46); input validation hardening [PR #56](https://github.com/0xCarbon/DKLs23/pull/56) | Trail of Bits (Feb 2024) -- 15 findings, 14 resolved |
| **Features** | Curve-generic types (`Party<C: DklsCurve>`, `DkgSession<C>`, `SignSession<'a, C>`), DKG, signing, complete + fast refresh, BIP-32 derivation, re-key, `AddressScheme<C>` trait with blockchain-specific address functions, versioned domain-separated tagged hashing, structured `AbortReason` enum with ban/recoverable classification, comprehensive input validation, session state machines, typed `PartyIndex`, `PublicKeyPackage<C>`, `EcdsaSignature`, `PhaseOutput`/`PhaseInput` message containers, feature-gated serde | DKG, signing, refresh, dynamic quorum, key import/export, migration from GG/CMP |
| **OT foundation** | Endemic OT (base) + KOS-style extension | Similar (specific sub-protocol choices may differ) |
| **P2P encryption** | **None** -- app must provide AEAD channels | **Built-in**: X25519 key agreement + ChaCha20-Poly1305 + EdDSA sender auth |
| **Notable** | `#![forbid(unsafe_code)]`, all secrets `Zeroize`+`ZeroizeOnDrop`, no panic paths in protocol phases | Production-hardened, patched for TOB-SILA-6/12 |

The choice of which crate to wrap should consider audit status and channel security.
See [11-references.md](11-references.md) for the full Trail of Bits audit findings.

### Channel Security Implication

This is an **architectural decision** with significant consequences:

**Option A: Wrap 0xCarbon + provide application-side channel encryption**
- libtss must implement or integrate an AEAD layer (e.g., using Rust's
  `chacha20poly1305` crate or requiring the application to encrypt externally)
- Each DKLs23 P2P message is encrypted/decrypted by the application before/after crossing FFI
- Pros: simpler Rust crate, channel logic in application's language (visible, auditable)
- Cons: more application-side security surface, must correctly implement nonce management
  (TOB-SILA-6 showed this is error-prone)

**Option B: Wrap Silence Labs (includes built-in encryption)**
- P2P encryption happens inside the Rust crate -- consumer sees only encrypted blobs
- Pros: battle-tested, audit-patched channel encryption; less application-side security surface
- Cons: larger dependency, Silence Labs crate is more complex, different API shape

**Option C: Wrap 0xCarbon + document channel encryption as application responsibility**
- libtss provides no channel encryption -- purely the application's problem
- Pros: simplest library, clear separation of concerns
- Cons: easy for integrators to get wrong; shifts security burden to consumers

**Recommendation**: Option A or B. Option C is too risky -- the Trail of Bits audit
proved that even experienced cryptography teams get channel encryption wrong (TOB-SILA-6).
The spec currently assumes Option A (0xCarbon crate with application-side channel guidance), but
this decision should be revisited before implementation.

## Configuration

As of v0.4.0, DKLs23 supports two curves: **secp256k1** and **secp256r1** (NIST P-256).
All protocol types are generic over `C: DklsCurve`, with curve-specific crates providing
type aliases and blockchain address functions. The protocol parameters are:

| Parameter | Value | Description |
|-----------|-------|-------------|
| λ_c (computational security) | 256 bits | SHA-256 hash output |
| λ_s (statistical security) | 80 bits | OT extension parameter |
| κ (base OT instances) | 256 | One per bit of λ_c |
| Batch size | 128 | OT extension batch |
| Curves | secp256k1, secp256r1 | 256-bit curves |

## Domain-Separated Oracle Tags (TAG System)

As of v0.2.0+, all internal protocol oracles use explicit domain-separated tagged hashing.
This replaces the ad-hoc `hash(msg, salt)` pattern from v0.1.x and is a
**protocol-breaking change** (different hash inputs produce different outputs).

### Tagged Hash Construction

```
tagged_hash(tag, [c₀, c₁, ...]) = SHA-256(len(tag)||tag||len(c₀)||c₀||len(c₁)||c₁||...)
```

All lengths are 8-byte big-endian `u64` values. This length-delimited encoding prevents
the delimiter collision vulnerability (CVE-2022-47931) and ensures each sub-protocol
oracle is cryptographically isolated.

### Tag Registry (17 tags)

Tags follow the convention `dkls23/<component>/<function>/v1` and are defined in
`utilities::oracle_tags`. A compile-time uniqueness test (`test_oracle_tags_are_unique`)
ensures no collisions.

| Category | Tags |
|----------|------|
| **Commitment** | `TAG_COMMITMENT` |
| **DLog Proofs** | `TAG_DLOG_PROOF_FISCHLIN`, `TAG_DLOG_PROOF_COMMITMENT` |
| **Encryption Proofs** | `TAG_ENCPROOF_FS` |
| **Zero-Shares** | `TAG_ZERO_SHARE_FRAGMENT` |
| **Base OT** | `TAG_OT_BASE_H`, `TAG_OT_BASE_MSG` |
| **OT Extension** | `TAG_OTE_PRG`, `TAG_OTE_CHI`, `TAG_OTE_RANDOMIZE` |
| **Multiplication** | `TAG_MUL_GADGET`, `TAG_MUL_CHI_TILDE`, `TAG_MUL_CHI_HAT`, `TAG_MUL_VERIFY` |
| **Fast Refresh** | `TAG_REFRESH_FAST_R0`, `TAG_REFRESH_FAST_R1`, `TAG_REFRESH_FAST_B` |

### Implications for libtss

- Wire format is **incompatible** between v0.1.x and v0.2.0+ -- parties running different
  major versions cannot interoperate
- The key share export format (08-serialization.md) must include the DKLs23 protocol version
  to reject imports from incompatible versions
- The TAG system satisfies SR-6 (Fiat-Shamir session binding) and SR-7 (serialization safety)
  at the protocol crate level, not just the libtss wrapper

## Party State

Unlike FROST (which separates key shares from protocol state), DKLs23 maintains a
rich `Party` state that includes both the secret share and pre-computed OT/multiplication
correlations:

```rust
pub struct Party<C: DklsCurve> {
    pub parameters: Parameters,           // (t, n) config
    pub party_index: PartyIndex,          // 1-based participant index (validated newtype)
    pub session_id: Vec<u8>,              // Unique session identifier
    pub poly_point: C::Scalar,            // Secret key share (Shamir evaluation)
    pub pk: C::AffinePoint,              // Group public key
    pub zero_share: ZeroShare,            // Pre-computed zero-shares for consistency checks
    pub mul_senders: BTreeMap<PartyIndex, MulSender<C>>,    // OT multiplication state (sender role)
    pub mul_receivers: BTreeMap<PartyIndex, MulReceiver<C>>, // OT multiplication state (receiver role)
    pub derivation_data: DerivData<C>,    // BIP-32 chain code + derivation path
    pub address: String,                  // Derived blockchain address (via AddressScheme<C>)
}
```

As of v0.4.0, `Party` is generic over `C: DklsCurve` — a marker trait automatically
satisfied by any `CurveArithmetic + PrimeCurve` type (e.g., `k256::Secp256k1`,
`p256::NistP256`). The `eth_address` field was renamed to `address` since the address
format now depends on the curve and blockchain (Ethereum, Bitcoin, Cosmos, TRON for
secp256k1; NEO3, Sui for secp256r1).

`PartyIndex` is a validated 1-based newtype wrapper around `u8` — construction from `0`
is rejected at the type level. All maps previously keyed by raw `u8` now use `PartyIndex`.

`Party` implements manual `Zeroize` + `Drop`: `session_id`, `poly_point`, `zero_share`,
all multiplication state, `derivation_data`, and `address` are zeroed. Public values
(`parameters`, `party_index`, `pk`) are not zeroized.

This entire `Party` struct is the "key share" for DKLs23. It is stored in the Rust-side
handle registry, and consumer languages receive only an opaque `TssHandle`.

## DKG Protocol Flow (4 Phases)

DKLs23 DKG combines Shamir secret sharing with OT initialization in a single protocol:

```
              Party 0              Party 1              Party 2
                 │                    │                    │
  Phase 1:       │                    │                    │
  Polynomial     │                    │                    │
  generation     │ fragments[0→1]     │                    │
                 ├───────────────────►│                    │
                 │ fragments[0→2]     │                    │
                 ├────────────────────────────────────────►│
                 │                    │ fragments[1→0]     │
                 │◄───────────────────┤ fragments[1→2]     │
                 │                    ├───────────────────►│
                 │                    │                    │
  Phase 2:       │                    │                    │
  VSS commit +   │  broadcast + P2P  │                    │
  Zero-share     │◄──────────────────►│◄──────────────────►│
  init           │                    │                    │
                 │                    │                    │
  Phase 3:       │                    │                    │
  BIP-32 chain   │  broadcast + P2P  │                    │
  code + OT/Mul  │◄──────────────────►│◄──────────────────►│
  init           │                    │                    │
                 │                    │                    │
  Phase 4:       │                    │                    │
  Verification   │  broadcast + P2P  │                    │
  + finalize     │◄──────────────────►│◄──────────────────►│
                 │                    │                    │
                 │  Party(share,     │  Party(share,      │  Party(share,
                 │   OT state,       │   OT state,        │   OT state,
                 │   chain_code)     │   chain_code)      │   chain_code)
```

### Phase Details

**Phase 1** -- Polynomial generation:
- Each party samples a random degree `(t-1)` polynomial
- Evaluates the polynomial at all n points
- Sends fragment `f_i(j)` to party `j`
- No verification yet -- pure share distribution

**Phase 2** -- Commitment + zero-share initialization:
- Each party computes their `poly_point` (sum of received fragments)
- Generates proof commitment (Schnorr DLog proof + hash commitment)
- Initializes zero-share protocol (Functionality 3.4 from the paper)
- Produces broadcast data and per-party P2P messages
- 2 sub-rounds of communication

**Phase 3** -- Chain code + multiplication initialization:
- BIP-32 chain code derivation via committed random contributions
- Two-party multiplication (OT extension) initialization
- Produces broadcast data and per-party P2P messages
- 1 sub-round of communication

**Phase 4** -- Verification + finalization:
- Verify all commitments and proofs
- Verify zero-share consistency
- Finalize OT state
- Compute group public key and per-party verification data
- Return `(Party, PublicKeyPackage)` — the `PublicKeyPackage` bundles the group
  verifying key, per-party verification shares, and threshold parameters

### Session Abstraction (`DkgSession`)

The DKG phases are wrapped in a `DkgSession<C>` state machine that enforces
phase ordering and manages intermediate state internally:

```rust
pub struct DkgSession<C: DklsCurve> { /* private fields */ }

impl<C: DklsCurve> DkgSession<C> {
    pub fn new(parameters: Parameters, party_index: PartyIndex, session_id: Vec<u8>) -> Self;
    pub fn phase1(&self) -> Vec<C::Scalar>;
    pub fn phase2(&mut self, poly_fragments: &[C::Scalar]) -> Result<(...), Abort>;
    pub fn phase3(&mut self) -> Result<(...), Abort>;
    pub fn phase4(self, ..., address_fn: impl Fn(&C::AffinePoint) -> String)
        -> Result<(Party<C>, PublicKeyPackage<C>), Abort>;
}
```

Key properties:
- `phase4(self)` **consumes** the session — prevents reuse after finalization
- Calling phases out of order returns `AbortReason::PhaseCalledOutOfOrder`
- All `Keep*` types are `pub(crate)` — hidden from consumers
- Implements `Zeroize + Drop` for secret intermediate state
- The underlying `dkg::phase1..4` functions are now `pub(crate)`

### C ABI (Unified Session API)

DKLs23 DKG uses the unified session API (`tss_dkg_new` / `tss_dkg_next`):

```c
// Phase 1: Create session, produce P2P fragment messages.
TssStatus tss_dkg_new(SECP256K1_ECDSA, self_id, max_signers, min_signers,
                       session_id, session_id_len,
                       &session, &out_messages);

// Phases 2-3: Process received messages, produce outgoing messages.
TssStatus tss_dkg_next(session, received_messages,
                        &key_share, &pubkey_package, &out_messages, &complete);
// complete == false: out_messages contains broadcast + P2P messages

// Phase 4: Process final messages, finalize key.
TssStatus tss_dkg_next(session, received_messages,
                        &key_share, &pubkey_package, &out_messages, &complete);
// complete == true: key_share and pubkey_package are valid
```

Internally, `tss_dkg_new` calls `DkgSession::phase1()`, and each `tss_dkg_next` call
dispatches to the next phase. Broadcast and P2P messages are distinguished by the
`to` field in the unified `Message` wire format: `0` = broadcast, non-zero = P2P.

See [06-ffi-layer.md](06-ffi-layer.md) for the complete C header.

## Signing Protocol Flow (4 Phases / 3 Communication Rounds)

```
              Party 0              Party 1              Verifier
                 │                    │                    │
  Phase 1:       │  commitment +      │                    │
  Instance key   │  OT extension      │                    │
  + OT start     │◄──────────────────►│                    │
                 │                    │                    │
  ─── Communication Round 1 ──────────────────────────────
                 │                    │                    │
  Phase 2:       │  decommit +        │                    │
  Multiplication │  correlation data  │                    │
  + consistency  │◄──────────────────►│                    │
                 │                    │                    │
  ─── Communication Round 2 ──────────────────────────────
                 │                    │                    │
  Phase 3:       │  u (R.x) + w       │                    │
  Ephemeral R    │◄──────────────────►│                    │
                 │                    │                    │
  ─── Communication Round 3 ──────────────────────────────
                 │                    │                    │
  Phase 4:       │                    │                    │
  Final sig      │ (r, s, v)          │ (r, s, v)          │
                 │                    │                    │
                 │               verify(pk, msg, sig) ────►│
```

### Phase Details

**Phase 1** (Steps 4-6 of Protocol 3.6):
- Sample random instance key `d_i` and inversion mask `ρ_i`
- Compute instance point `D_i = d_i * G`
- Commit to instance point (hash commitment)
- Initialize multiplication as OT receiver
- Generate zero-shares for consistency checks

Output:
- Broadcast: commitment to instance point
- P2P: OT extension data to each counterparty
- Keep: instance key, inversion mask, OT state

**Phase 2** (Steps 7-10):
- Verify received commitments
- Decommit own instance point
- Run multiplication protocol (VOLE)
- Compute correlation values `(γ_u, γ_v, ψ)`
- Perform consistency checks via hash verification

Output:
- P2P: correlation points, public share, decommitted instance point, multiplication data

**Phase 3** (Steps 11-12):
- Reconstruct ephemeral point `R` from all instance points
- Compute `r = R.x mod order`
- Compute Fiat-Shamir challenge `w` for second message

Output:
- Broadcast: `(u = r, w)` to all parties

**Phase 4** (Steps 13-14):
- Receive `(u, w)` from all parties
- Verify consistency of `u` and `w` values
- Compute final signature component: `s_i`
- Combine partial signatures
- Verify final ECDSA signature `(r, s)` against group public key
- Include recovery ID `v` for Ethereum compatibility

### Session Abstraction (`SignSession`)

Signing is wrapped in a `SignSession<'a, C>` that borrows the `Party<C>`
(the key share is not consumed during signing):

```rust
pub struct SignSession<'a, C: DklsCurve> { /* borrows &'a Party<C> */ }

impl<'a, C: DklsCurve> SignSession<'a, C> {
    /// Phase 1 runs during construction.
    pub fn new(party: &'a Party<C>, data: SignData) -> Result<(Self, Vec<TransmitPhase1to2>), Abort>;
    pub fn phase2(&mut self, received: &[TransmitPhase1to2]) -> Result<Vec<TransmitPhase2to3<C>>, Abort>;
    pub fn phase3(&mut self, received: &[TransmitPhase2to3<C>]) -> Result<Broadcast3to4<C>, Abort>;
    pub fn phase4(mut self, received: &[Broadcast3to4<C>], normalize: bool) -> Result<EcdsaSignature, Abort>;
}
```

Key properties:
- `SignSession<'a, C>` **borrows** `&'a Party<C>` — the key share survives for reuse
- `phase4(mut self)` **consumes** the session — prevents reuse after signing
- Phase ordering enforced via `AbortReason::PhaseCalledOutOfOrder`
- Returns `EcdsaSignature` (typed struct) instead of hex strings

### `EcdsaSignature` Type

A typed signature struct (since v0.3.0):

```rust
pub struct EcdsaSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

impl EcdsaSignature {
    pub fn to_bytes(&self) -> [u8; 64];             // r || s
    pub fn to_bytes_with_recovery(&self) -> [u8; 65]; // r || s || v
}
```

This replaces the previous pattern of returning `(String, String, u8)` hex values.

### C ABI (Unified Session API)

DKLs23 signing uses the unified session API (`tss_sign_new` / `tss_sign_next`):

```c
// Phase 1: Create session (runs phase 1 internally), produce broadcast + P2P messages.
TssStatus tss_sign_new(key_share, message, &session, &out_messages);

// Phase 2: Process received messages, produce P2P correlation data.
TssStatus tss_sign_next(session, received_messages,
                         &signature, &out_messages, &complete);

// Phase 3: Process received messages, produce broadcast (u, w).
TssStatus tss_sign_next(session, received_messages,
                         &signature, &out_messages, &complete);

// Phase 4: Process broadcasts, finalize signature.
TssStatus tss_sign_next(session, received_messages,
                         &signature, &out_messages, &complete);
// complete == true: signature is 65 bytes = r (32) + s (32) + recovery_id (1)
// Maps from EcdsaSignature::to_bytes_with_recovery().
```

See [06-ffi-layer.md](06-ffi-layer.md) for the complete C header.

## Re-Keying (Trusted Dealer)

Splits an existing secret key into threshold shares without an interactive protocol.
Used for importing existing keys into the threshold scheme.

```rust
pub fn re_key<C: DklsCurve>(
    parameters: &Parameters,
    session_id: &[u8],
    secret_key: &C::Scalar,
    option_chain_code: Option<ChainCode>,
    address_fn: impl Fn(&C::AffinePoint) -> String,
) -> (Vec<Party<C>>, PublicKeyPackage<C>);
```

As of v0.4.0, `re_key` is generic over `C: DklsCurve` and takes an `address_fn`
parameter to compute blockchain-specific addresses from public keys (e.g.,
`compute_eth_address` for Ethereum, `compute_neo3_address` for NEO3).

All OT/multiplication state is initialized locally (no communication needed).
The function returns a vector of `Party<C>` structs (one per share) and a
`PublicKeyPackage<C>` containing the group verifying key and per-party verification shares.

## Signature Verification

Uses the unified `tss_verify()` function:

```c
bool tss_verify(SECP256K1_ECDSA, message, signature, public_key);
```

```rust
// Rust API
let valid = signature.verify(&public_key, &message);
```

Standard ECDSA verification over the signing curve (secp256k1 or secp256r1). The
signature produced by the threshold protocol is indistinguishable from a single-signer
ECDSA signature.

## Oblivious Transfer Internals

The OT subsystem is internal to the Rust crate and not exposed via FFI. It is
documented here for security audit reference.

### Base OT (Endemic OT, Zhou et al. 2022)

- Each pair of parties runs κ=256 base OT instances during DKG
- Sender generates random scalar `s` with DLog proof
- Receiver generates random scalar per OT instance
- Chaum-Pedersen encryption proofs ensure correctness
- Output: correlated random strings for sender and receiver

### OT Extension (Soft Spoken OT / KOS-style)

- Extends κ base OTs to arbitrary number of OTs
- Batch size: 128 bits per extension
- Forced-reuse optimization: concatenates payloads for multiple inputs
- Used in two-party multiplication (VOLE) for multiplicative-to-additive share conversion

### Two-Party Multiplication (Functionality 3.5)

- Implements random Vector OLE (rVOLE)
- Parameter `L=2`: two multiplications per protocol invocation
- Sender and receiver each hold multiplicative share
- Output: additive shares of the product
- Used in signing Phase 2 for computing `k * x` without revealing either value

## Error Handling

DKLs23 errors are reported via the `Abort` type with an `AbortKind` classification
and a structured `AbortReason` enum:

```rust
pub enum AbortKind {
    Recoverable,                    // Safe to retry
    BanCounterparty(PartyIndex),    // Must permanently exclude this party
}

/// Machine-readable reason for a protocol abort (25+ variants).
#[non_exhaustive]
pub enum AbortReason {
    // Input validation (all Recoverable)
    InvalidPartyIndex { index: PartyIndex },
    WrongCounterpartyCount { expected: usize, got: usize },
    DuplicateCounterparty { index: PartyIndex },
    SelfInCounterparties,
    MissingMulState { counterparty: PartyIndex },

    // Message routing (all Recoverable)
    MisroutedMessage { expected_receiver: PartyIndex, actual_receiver: PartyIndex },
    UnexpectedSender { sender: PartyIndex },
    DuplicateSender { sender: PartyIndex },
    WrongMessageCount { expected: usize, got: usize },
    MissingMessageFromParty { party: PartyIndex },

    // Cryptographic verification (severity varies)
    ProofVerificationFailed { counterparty: PartyIndex },
    CommitmentMismatch { counterparty: PartyIndex },
    PolynomialInconsistency,
    TrivialInstancePoint { counterparty: PartyIndex },
    TrivialPublicKey,
    TrivialKeyShare,
    MissingCommittedPoint { party: PartyIndex },

    // OT/Multiplication failures (typically BanCounterparty)
    OtConsistencyCheckFailed { counterparty: PartyIndex },
    MultiplicationVerificationFailed { counterparty: PartyIndex, detail: String },
    GammaUInconsistency { counterparty: PartyIndex },

    // Signature assembly
    SignatureVerificationFailed,
    ZeroDenominator,
    LagrangeCoefficientFailed,
    InvalidXCoordinateHex,

    // Zero-share initialization
    ZeroShareDecommitFailed { counterparty: PartyIndex },

    // Chain code / BIP derivation
    ChainCodeCommitmentFailed { party: PartyIndex },

    // Session state machine
    PhaseCalledOutOfOrder { phase: String },

    // Hex parsing
    InvalidHex { detail: String },
}

pub struct Abort {
    pub index: PartyIndex,      // Party that generated the abort
    pub kind: AbortKind,        // Severity classification
    pub reason: AbortReason,    // Machine-readable structured reason
}

impl Abort {
    pub fn recoverable(index: PartyIndex, reason: AbortReason) -> Abort;
    pub fn ban(index: PartyIndex, counterparty: PartyIndex, reason: AbortReason) -> Abort;
    pub fn description(&self) -> String;  // Human-readable via Display on AbortReason
}
```

The `AbortReason` enum replaces the previous free-form `description: String`. Each variant
carries contextual data (e.g., which counterparty, expected vs actual counts). The
`description()` method delegates to `AbortReason`'s `Display` implementation for
human-readable output.

**Critical**: When `kind` is `BanCounterparty(i)`, the application MUST permanently
exclude party `i` from all future signing and refresh sessions. The DKLs23 protocol
reuses OT correlations across sessions — a cheating counterparty leaks information
about this reused state, enabling gradual key extraction over multiple sessions.

### Abort Classification Table

| Failure Mode | AbortReason Variant | Phase | AbortKind |
|--------------|-------------------|-------|-----------|
| Party index out of range | `InvalidPartyIndex` | Any Phase 1 | Recoverable |
| Duplicate counterparty | `DuplicateCounterparty` | Sign Phase 1 | Recoverable |
| Self in counterparty list | `SelfInCounterparties` | Sign Phase 1 | Recoverable |
| Wrong counterparty count | `WrongCounterpartyCount` | Sign Phase 1 | Recoverable |
| Missing multiplication state | `MissingMulState` | Sign Phase 1 | Recoverable |
| Wrong message count | `WrongMessageCount` | Phase 2-4 | Recoverable |
| Misrouted message | `MisroutedMessage` | Any phase | Recoverable |
| Unexpected sender | `UnexpectedSender` | Any phase | Recoverable |
| Duplicate sender | `DuplicateSender` | Any phase | Recoverable |
| Missing message from party | `MissingMessageFromParty` | Any phase | Recoverable |
| Bad DLog proof | `ProofVerificationFailed` | DKG Phase 4 | Recoverable |
| Commitment mismatch | `CommitmentMismatch` | DKG Phase 4, Sign Phase 2 | Recoverable |
| Polynomial inconsistency | `PolynomialInconsistency` | DKG Phase 4 | Recoverable |
| Trivial instance point | `TrivialInstancePoint` | Sign Phase 2 | Recoverable |
| Trivial public key | `TrivialPublicKey` | DKG Phase 4 | Recoverable |
| Trivial key share | `TrivialKeyShare` | DKG Phase 4 | Recoverable |
| Missing committed point | `MissingCommittedPoint` | Sign Phase 3 | Recoverable |
| Seed decommitment failure | `ZeroShareDecommitFailed` | DKG Phase 4 | Recoverable |
| Chain code commitment | `ChainCodeCommitmentFailed` | DKG Phase 4 | Recoverable |
| Invalid partial signature | `SignatureVerificationFailed` | Sign Phase 4 | Recoverable |
| Zero denominator | `ZeroDenominator` | Sign Phase 4 | Recoverable |
| Lagrange coefficient failed | `LagrangeCoefficientFailed` | Sign Phase 4 | Recoverable |
| Phase called out of order | `PhaseCalledOutOfOrder` | Any (session) | Recoverable |
| COTe consistency check failure | `OtConsistencyCheckFailed` | Sign Phase 2-3 | **BanCounterparty** |
| Multiplication verification failure | `MultiplicationVerificationFailed` | Sign Phase 2-3 | **BanCounterparty** |
| γ_u inconsistency | `GammaUInconsistency` | Sign Phase 3 | **BanCounterparty** |

### Input Validation (v0.2.0+)

All protocol phases validate inputs at entry before processing:

| Validation | Where | Error |
|------------|-------|-------|
| Party index in `[1, share_count]` | All entry points | Recoverable abort |
| Counterparty list uniqueness | Sign Phase 1 | Recoverable abort |
| Counterparty count == `threshold - 1` | Sign Phase 1 | Recoverable abort |
| Required mul_senders/mul_receivers present | Sign Phase 1 | Recoverable abort |
| Message vector length matches expectations | Sign Phase 2-3, DKG Phase 3-4 | Recoverable abort |
| Message recipient == self | All P2P receive points | Recoverable abort |
| Message sender in expected party set | All receive points | Recoverable abort |
| No duplicate senders in message batch | All receive points | Recoverable abort |

These validations eliminate all panic paths from protocol phases. Every protocol function
returns `Result<T, Abort>` — no `unwrap()`, no `expect()`, no indexing panics.

### libtss Mapping

libtss maps DKLs23 `Abort` to the unified `TssError::Abort` variant:

1. **Recoverable aborts** → `TssError::Abort { ban: None, .. }` → `TSS_ERR_ABORT` status code
   + `AbortReason::description()` via `tss_last_error()`
2. **Ban aborts** → `TssError::Abort { ban: Some(party), .. }` → `TSS_ERR_ABORT_BAN` status code
   + banned party via `tss_abort_banned_party()` + `AbortReason::description()` via `tss_last_error()`

The structured `AbortReason` enum makes it possible for libtss to inspect the reason
programmatically (e.g., distinguishing `OtConsistencyCheckFailed` from `MisroutedMessage`)
rather than parsing a free-form string.

The application MUST maintain a persistent ban list. After receiving `TSS_ERR_ABORT_BAN`,
the banned party must be excluded from all future signing, refresh, and DKG sessions
involving the same key group.

See the [DKLs23 security documentation](https://github.com/0xCarbon/DKLs23/blob/main/docs/security.md) for the formal
security argument.

## Unified Message Types (`PhaseOutput`/`PhaseInput`)

Behind the `serde` feature (since v0.3.0), DKLs23 provides unified message containers
with tagged binary framing:

```rust
// Available with #[cfg(feature = "serde")]
pub struct PhaseOutput {
    pub broadcasts: Vec<Vec<u8>>,
    pub p2p: BTreeMap<u8, Vec<u8>>,
}

pub struct PhaseInput {
    pub broadcasts: BTreeMap<u8, Vec<u8>>,
    pub p2p: BTreeMap<u8, Vec<u8>>,
}
```

Each message is framed as `[tag: u8][length: u32 BE][payload: bincode]`. Multiple
message types can be concatenated in a single byte stream and extracted by tag via
the `MessageTag` trait. This replaces the need for libtss to manually serialize/deserialize
~20 individual `Transmit*`/`Broadcast*` types.

The `MessageTag` trait is implemented on all `Transmit*` and `Broadcast*` types when
the `serde` feature is enabled.

## `PublicKeyPackage`

Bundles the group public key with per-party verification shares (since v0.3.0, generic
over `C: DklsCurve` since v0.4.0):

```rust
pub struct PublicKeyPackage<C: DklsCurve> {
    verifying_key: C::AffinePoint,
    verifying_shares: BTreeMap<PartyIndex, C::AffinePoint>,
    parameters: Parameters,
}

impl<C: DklsCurve> PublicKeyPackage<C> {
    pub fn verifying_key(&self) -> &C::AffinePoint;
    pub fn verifying_share(&self, party: PartyIndex) -> Option<&C::AffinePoint>;
    pub fn threshold(&self) -> u8;
    pub fn share_count(&self) -> u8;
    pub fn verify_share(&self, party: PartyIndex, verification_share: &C::AffinePoint) -> bool;
}
```

Note: The `ethereum_address()` method was removed in v0.4.0. Address computation is now
handled by the `AddressScheme<C>` trait and curve-specific address functions (see below).

Returned by both `DkgSession::phase4()` and `re_key()`. This mirrors FROST's
`PublicKeyPackage` and simplifies the libtss adapter — a single type for both protocols'
public key bundles.

## Address Computation

As of v0.4.0, address computation is decoupled from the protocol core via the
`AddressScheme<C>` trait and curve-specific address functions:

```rust
// Trait for address derivation (dkls23-core)
pub trait AddressScheme<C: DklsCurve> {
    fn compute_address(pk: &C::AffinePoint) -> String;
}

// secp256k1 address functions (dkls23-secp256k1)
pub fn compute_eth_address(pk: &k256::AffinePoint) -> String;      // Ethereum (EVM)
pub fn compute_btc_address(pk: &k256::AffinePoint) -> String;      // Bitcoin P2WPKH
pub fn compute_cosmos_address(pk: &k256::AffinePoint) -> String;   // Cosmos Hub
pub fn compute_tron_address(pk: &k256::AffinePoint) -> String;     // TRON

// secp256r1 address functions (dkls23-secp256r1)
pub fn compute_neo3_address(pk: &p256::AffinePoint) -> String;     // NEO3
pub fn compute_sui_address(pk: &p256::AffinePoint) -> String;      // Sui
```

These functions are passed as the `address_fn` parameter to `DkgSession::phase4()` and
`re_key()`. libtss selects the appropriate function based on the ciphersuite.

## Feature-Gated Serde

All `Serialize`/`Deserialize` derives are gated behind `#[cfg_attr(feature = "serde", ...)]`:

```toml
[features]
default = ["serde"]
serde = ["dep:serde", "dep:serde_bytes", "dep:bincode", "k256/serde"]
```

libtss depends on DKLs23 with `features = ["serde"]` (the default). The `messages` module
(`PhaseOutput`/`PhaseInput`) is only available with the `serde` feature.

## Differences from Existing libtss Prototype

The new libtss improves on the existing prototype:

| Aspect | Old prototype | New (libtss) |
|--------|-------------------|-----------------|
| FFI method | JSON strings over `extern "C"` | Typed C ABI with `TssBuffer`/`TssSlice` |
| Error handling | `unwrap()` → panic across FFI | `catch_unwind` → `TssStatus` codes + `tss_last_error()` |
| State management | Caller serializes full state as JSON each phase | Opaque handles, Rust manages state |
| Memory safety | `CString::into_raw()` leak + manual free | `TssBuffer` with explicit `tss_buffer_free()` |
| Performance | JSON serialize/deserialize every phase | Direct pointer+length, no serialization overhead |
| Type safety | `*const c_char` everywhere | Typed `TssSlice`/`TssBuffer` with cbindgen header |
| Secret zeroing | No explicit zeroing | `Zeroize` on Drop for all secrets |
