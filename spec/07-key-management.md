# 07 - Key Management

## Key Lifecycle

```
                    ┌──────────────┐
                    │   Generate   │
                    │  (DKG or     │
                    │   Dealer)    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
              ┌────►│   Active     │◄────┐
              │     │  Key Share   │     │
              │     └──┬───┬───┬──┘     │
              │        │   │   │        │
         Refresh       │   │   │     Import
              │   Sign │   │   │ Derive │
              │        │   │   │        │
              │        ▼   │   ▼        │
              │     ┌──────┘ ┌──────┐   │
              │     │        │Child │   │
              │     │        │Share │   │
              │     │        └──────┘   │
              │     │                   │
              │     ▼                   │
              │  ┌──────────────┐       │
              └──┤  Refreshed   ├───────┘
                 │  Key Share   │
                 └──────┬───────┘
                        │
                   Free │
                        ▼
                 ┌──────────────┐
                 │   Zeroed     │
                 │  (dropped)   │
                 └──────────────┘
```

## BIP-32 Key Derivation

### Non-Hardened Derivation

Both FROST and DKLs23 support non-hardened BIP-32 derivation. Each participant derives
their child key share locally without any communication:

```
child_share_i = parent_share_i + delta
child_pubkey  = parent_pubkey + delta * G

where:
  (IL, IR) = HMAC-SHA512(chain_code, parent_pubkey || child_index)
  delta    = IL (interpreted as scalar mod curve_order)
  new_chain_code = IR
```

This works because Shamir secret sharing is additively homomorphic:
if `parent_key = sum(lambda_i * parent_share_i)`, then
`parent_key + delta = sum(lambda_i * (parent_share_i + delta))`.

### Rust API

```rust
/// Derive a child key share using non-hardened BIP-32 derivation.
/// Returns a NEW handle; the parent handle remains valid.
/// child_number must be < 2^31 (non-hardened only).
pub fn derive_child(
    key_share: &KeyShareHandle,
    child_number: u32,
) -> Result<KeyShareHandle, TssError>;

/// Derive along a full BIP-32 path (e.g., "m/44/0/0/0").
/// All indices must be < 2^31. Max depth: 255.
pub fn derive_path(
    key_share: &KeyShareHandle,
    path: &str,
) -> Result<KeyShareHandle, TssError>;
```

### C ABI

```c
TssStatus tss_derive_child(TssHandle key_share, uint32_t child_number, TssHandle *out);
TssStatus tss_derive_path(TssHandle key_share, const char *path, TssHandle *out);
```

### FROST Derivation

For FROST, derivation modifies the `KeyPackage`:

```rust
fn frost_derive_child(key_handle: u64, child_number: u32) -> HandleResult {
    let key_package: &KeyPackage<C> = registry.get(key_handle)?;

    // Compute BIP-32 tweak
    let parent_pubkey = key_package.verifying_key().serialize();
    let chain_code = key_handle.chain_code()?;
    let (il, ir) = hmac_sha512(&chain_code, &[&parent_pubkey, &child_number.to_be_bytes()]);
    let delta = Scalar::deserialize(&il)?;

    // New signing share = old share + delta
    let new_share = key_package.signing_share().to_scalar() + delta;
    // New verifying key = old key + delta * G
    let new_vk = key_package.verifying_key().to_element() + Element::generator() * delta;

    // Construct new KeyPackage
    let child_package = KeyPackage::new(
        key_package.identifier().clone(),
        SigningShare::new(new_share),
        VerifyingShare::new(key_package.verifying_share().to_element() + Element::generator() * delta),
        VerifyingKey::new(new_vk),
        key_package.min_signers(),
    );

    Ok(registry.insert(Category::FrostKey, (child_package, ir)))
}
```

### DKLs23 Derivation

DKLs23 has built-in BIP-32 support via the `DerivData` struct:

```rust
fn dkls_derive_child(party_handle: u64, child_number: u32) -> HandleResult {
    let party: &Party = registry.get(party_handle)?;
    let child_party = party.derive_child(child_number)?;
    Ok(registry.insert(Category::DKLsParty, child_party))
}

fn dkls_derive_path(party_handle: u64, path: String) -> HandleResult {
    let party: &Party = registry.get(party_handle)?;
    let child_party = party.derive_from_path(&path)?;
    Ok(registry.insert(Category::DKLsParty, child_party))
}
```

The `Party::derive_child` method:
1. Computes `HMAC-SHA512(chain_code, pubkey || child_number)`
2. Updates `poly_point` (secret share) by adding the tweak
3. Updates `pk` (public key) by adding `tweak * G`
4. Updates `chain_code`, `depth`, `parent_fingerprint`, `child_number`
5. Returns a new `Party` with updated derivation data

### Derivation Constraints

| Constraint | Value | Rationale |
|------------|-------|-----------|
| Max depth | 255 | BIP-32 spec limit |
| Max child number | 2^31 - 1 | Non-hardened only (bit 31 = 0) |
| Hardened derivation | Not supported | Requires MPC hash (future work) |
| Path format | `m/N/N/N/...` | Standard BIP-32 path notation |

### Exposing the Chain Code (xpub Construction)

`KeyShareHandle::chain_code()` (C ABI `tss_handle_chain_code`) returns the 32-byte
chain code paired with `group_verifying_key()`. Wrapping the two into a BIP-32
extended public key lets a host derive child public keys off-MPC that match the
child shares every party derives with `derive_child` / `derive_path`.

| Ciphersuite | Chain code | Agreement with an external CKDpub |
|-------------|------------|-----------------------------------|
| Secp256k1ECDSA / Secp256r1ECDSA (DKLs23) | Established at DKG; children carry the BIP-32 `IR` | Any depth |
| Secp256k1Taproot (FROST) | `SHA-256(group verifying key)`, re-derived from each child's key | Depth 1 only — FROST derivation never carries `IR` (follow-up) |
| All others | Not available | `ProtocolMismatch` — these suites have no BIP-32 derivation |

The chain code is public material; exposing it reveals nothing about the shares.

### Security Note: Derivation + Refresh

Deriving a child key and then refreshing its shares is safe but has a subtlety:
after refresh, the parent key's shares and the child key's shares are no longer
related by the same additive tweak. This is expected and does not affect security.

Recommendation: derive keys as needed, refresh the master (root) shares periodically.

## Scalar Tweaks (Lightning)

Lightning derives per-commitment keys from caller-supplied scalars rather than
BIP-32 indices: LND's single tweak is `k' = k + t (mod n)` and its revocation
("double") tweak composes `k' = k * a (mod n)` with an additive step. libtss
exposes both on DKLs23 shares:

```rust
pub fn tweak_add(key_share: &KeyShareHandle, tweak: &[u8]) -> Result<KeyShareHandle, TssError>;
pub fn tweak_mul(key_share: &KeyShareHandle, factor: &[u8]) -> Result<KeyShareHandle, TssError>;
```

```c
TssStatus tss_tweak_add(TssHandle key_share, const uint8_t *tweak, size_t tweak_len, TssHandle *out_handle);
TssStatus tss_tweak_mul(TssHandle key_share, const uint8_t *factor, size_t factor_len, TssHandle *out_handle);
```

Every party applies the same tweak to its share and the public key package is
moved by the same map (group key and every verifying share). Because Lagrange
coefficients sum to one, `Σ lᵢ·(xᵢ + t) = sk + t` and `Σ lᵢ·(a·xᵢ) = a·sk`, so
the tweaked shares sign under the tweaked group key. The DKLs23 base-OT
correlations, zero-share seeds and multiplication state never depend on the
share value — the same property BIP-32 derivation relies on — and are reused
unchanged. The map itself is DKLs23's (`Party::tweak_add` / `tweak_mul` and the
matching `PublicKeyPackage` methods); libtss parses the scalar, picks the
address function and wraps the result in a new handle.

| Field | After `tweak_add(t)` | After `tweak_mul(a)` |
|-------|----------------------|----------------------|
| `poly_point`, `derivation_data.poly_point` | `x + t` | `a·x` |
| `pk`, `derivation_data.pk`, group key, verifying shares | `P + t·G` | `a·P` |
| `address` | recomputed | recomputed |
| `chain_code`, `depth`, `child_number`, `parent_fingerprint`, `session_id`, OT state | unchanged | unchanged |

Rules: scalars are 32-byte big-endian and reduced mod n (btcec `ModNScalar`
semantics, so LND tweaks round-trip); a factor that reduces to zero or a result
equal to the identity point is rejected with `TweakError`; wrong-length input is
`InvalidConfig`; non-DKLs23 suites return `ProtocolMismatch`. All signers must
apply the same public tweak before a signing session — a mismatch aborts
recoverably in signing phase 3. A tweak is not a BIP-32 edge: the derivation
metadata still describes the un-tweaked ancestor, and `derive_child` on a
tweaked share is a further additive shift under the unchanged chain code.

## Share Refresh

Share refresh replaces all participants' shares with new shares of the same secret key.
After refresh, old shares are useless (proactive security).

### Unified Refresh Session

Interactive refresh uses the unified `RefreshSession` API (same `new()` → `next()` loop
pattern as DKG and signing):

```rust
/// Protocol-agnostic share refresh session.
pub struct RefreshSession { /* ... */ }

impl RefreshSession {
    /// Interactive refresh (recommended mode).
    /// FROST: DKG-based refresh with zero-constant polynomial (3 rounds).
    /// DKLs23: Complete refresh with OT re-initialization (4 phases).
    pub fn new(key_share: &KeyShareHandle) -> Result<(Self, Vec<Message>), TssError>;

    /// FROST refresh receiver (non-dealer participant).
    /// Waits for messages from the dealer refresh. Does not produce
    /// initial messages. Use with `frost_refresh_with_dealer`.
    pub fn new_frost_receiver(key_share: &KeyShareHandle) -> Result<Self, TssError>;

    pub fn next(&mut self, received: &[Message]) -> Result<RefreshOutput, TssError>;
}
```

This is a DKG where the polynomial constant term is zero. The new share
is: `new_share = old_share + sum(refreshing_shares_from_peers)`.

See [03-api-design.md](03-api-design.md) for the full `RefreshSession` and `RefreshOutput` API.

### FROST Trusted Dealer Refresh

For non-interactive refresh with a trusted party (not a session):

```rust
pub fn frost_refresh_with_dealer(
    pubkeys: &PublicKeyPackage,
    participants: &[Identifier],
) -> Result<(BTreeMap<Identifier, Vec<u8>>, PublicKeyPackage), TssError>;

pub fn frost_apply_refresh(
    key_share: &KeyShareHandle,
    refresh_data: &[u8],
) -> Result<KeyShareHandle, TssError>;
```

### DKLs23 Complete Refresh

DKLs23 refresh uses `RefreshSession::new_dkls(key_share, session_id)` (C ABI:
`tss_refresh_new_dkls`), which re-runs DKG with a zero-constant polynomial and
re-initializes the OT and zero-share state from scratch. Three message rounds
follow the same shape as DKG phases 2–4, minus the BIP-32 derivation
broadcasts; the chain code is carried over unchanged. dkls23's
`refresh_complete_phase4` returns only the refreshed `Party`, so libtss rebuilds
the public key package itself: every verifying share moves by its party's
correction point (`share'(j) = share(j) + G·correction_j`, read from the
broadcast proof commitments) while the group key stays put, and the result is
self-checked against the new share before a handle is created.

Two properties bind callers:

- **All `n` parties must refresh together under one fresh `session_id`.** The
  refreshed party records it as its session id, and signing salts the
  two-party multiplication transcript with it, so pre- and post-refresh shares
  never co-sign. A partial refresh leaves the group unsignable until the
  stragglers are repaired from the majority generation and refreshed again.
- **Only secp256k1 shares are supported.** FROST and secp256r1 shares return
  `ProtocolMismatch`; a hollow share from [`repair_assemble`](#dkls23-share-repair)
  is accepted — turning it back into a signing share is the point.

This is also the recommended mode when OT state may have been partially
compromised.

### FROST Dealer/Receiver Refresh

Two alternatives for FROST refresh with a trusted dealer:

**One-shot (no session):** Dealer calls `frost_refresh_with_dealer` to
generate per-participant refresh data, distributes it, and each receiver
applies it directly via `frost_apply_refresh`.

**Session-based:** Each non-dealer participant creates a receiver session
via `RefreshSession::new_frost_receiver` (C ABI: `tss_refresh_receiver`)
and processes the dealer's refresh data through the `next()` loop.
This is useful when bindings want a uniform session-based API for all
refresh paths.

### Refresh Properties

| Property | Guaranteed |
|----------|-----------|
| Public key unchanged | Yes (zero-constant polynomial) |
| Old shares invalidated | Yes (new shares are independent) |
| Forward secrecy | Yes (compromising new shares reveals nothing about old shares) |
| Participant set change | Yes (for FROST dealer refresh; for DKG refresh, all participants must be present) |
| OT state refreshed | DKLs23 complete refresh: yes |

## Share Repair

Share repair allows `t` helpers to reconstruct a lost share for a designated participant
without revealing the group secret key to anyone.

### FROST Share Repair

Based on the Repairable Threshold Scheme (RTS) from [eprint 2017/1155](https://eprint.iacr.org/2017/1155).

```rust
/// Part 1: called by each helper to generate repair deltas.
pub fn frost_repair_part1(
    key_share: &KeyShareHandle,
    helpers: &[Identifier],
    participant: Identifier,
) -> Result<BTreeMap<Identifier, Vec<u8>>, TssError>;

/// Part 2: called by each helper to sum received deltas into sigma.
pub fn frost_repair_part2(deltas: &[Vec<u8>]) -> Result<Vec<u8>, TssError>;

/// Part 3: called by recovering participant to reconstruct key share.
pub fn frost_repair_part3(
    sigmas: &[Vec<u8>],
    participant: Identifier,
    pubkeys: &PublicKeyPackage,
) -> Result<KeyShareHandle, TssError>;
```

#### Repair Protocol Flow

```
              Helper A            Helper B            Participant (lost share)
                 │                   │                        │
  Part 1:        │                   │                        │
  Generate       │ delta(A→B) ──────►│                        │
  deltas         │◄──── delta(B→A) ──┤                        │
                 │                   │                        │
  Part 2:        │                   │                        │
  Sum deltas     │ sigma_A ──────────────────────────────────►│
                 │                   │ sigma_B ──────────────►│
                 │                   │                        │
  Part 3:        │                   │                        │
  Reconstruct    │                   │           new_share =  │
                 │                   │           sum(sigmas)  │
```

### DKLs23 Share Repair

dkls23 has no built-in repair; libtss implements one for secp256k1 as a
two-step recovery (`repair_helper_term` / `repair_assemble`, C ABI
`tss_repair_helper_term` / `tss_repair_assemble`) followed by a complete
refresh. The OT correlations in a `Party` cannot be reconstructed by helpers,
so repair rebuilds only the *secret share* and leaves the refresh to rebuild
the rest.

**Step 1 — helpers (one round, unicast to the target).** A set of at least
`t` surviving parties agree on the helper set and a fresh `repair_sid`. Each
helper `i` sends the target

```text
term_i = poly_point_i · λ_i(target) + ZeroShare::compute(helpers \ {i}, "libtss/dkls23-repair/v1" || repair_sid)
```

`λ_i(target)` is the Lagrange coefficient over the helper indices, so the
unmasked terms sum to `f(target)`. The masks are the same pairwise zero-share
seeds signing uses, keyed by a domain-separated session id, and sum to zero
over the helper set — no new key material and no mask exchange. Any proper
subset of the terms is uniformly random, so no helper learns the share.
`repair_helper_term` fails closed with `InvalidShare` if the caller lacks a
seed pair with any helper counterparty (`ZeroShare::compute` would otherwise
skip it silently and leave `poly_point · λ` unmasked).

**Step 2 — target.** `repair_assemble` sums the terms, checks
`G · Σ terms == verifying_share(target)` from the helpers' public key package
(`InvalidShare` otherwise — no handle is created) and builds a *hollow*
`Party`: correct `poly_point`, `pk`, address and root-level derivation data
(`depth 0`, the group chain code), but an empty `ZeroShare` and empty
multiplication maps. The handle passes import validation, exports, derives
addresses and refreshes; `SignSession::new_dkls` refuses it with
`InvalidShare` and it cannot act as a repair helper.

**Step 3 — complete refresh across all `n`.** `RefreshSession::new_dkls`
rebuilds the OT and zero-share state for every party and re-randomises every
share under the unchanged group key. Only after this can the repaired party
sign.

Only master (depth-0) shares are repaired; derived shares are re-derived from
the refreshed master, per dkls23's own guidance on refreshing derivations.

## Key Share Persistence

### Export Format

Key shares are exported as versioned binary blobs. The caller is responsible for
encrypting the blob before storage.

```
┌────────────────────────────────────────────┐
│ Header (8 bytes)                           │
│  version: u16 (currently 1)               │
│  protocol: u8 (0=FROST, 1=DKLs23)        │
│  ciphersuite: u8                          │
│  reserved: u32                            │
├────────────────────────────────────────────┤
│ Payload (variable)                         │
│  FROST: serde-serialized KeyPackage<C>    │
│  DKLs23: serde-serialized Party           │
│  + PublicKeyPackage                        │
│  + chain_code (if present)                │
├────────────────────────────────────────────┤
│ Checksum (32 bytes)                        │
│  SHA-256 of header + payload              │
└────────────────────────────────────────────┘
```

### Security Requirements for Persistence

1. The exported blob contains SECRET material -- it MUST be encrypted at rest
2. Recommended: AES-256-GCM with a key derived from a user password (Argon2id)
3. The library does NOT handle encryption -- this is the application's responsibility
4. The library documents this requirement clearly in the `export_key_share` rustdoc

### Import Validation

On import, the library:
1. Verifies the checksum
2. Validates the version and ciphersuite
3. Deserializes and validates the key share
4. Verifies the signing share against the verifying share: `share * G == verifying_share`
5. Returns a new handle

## Compact Export with Seed-Based Reconstruction (Future)

> **Status**: Design idea — not yet implemented. See [DKLs23#43](https://github.com/0xCarbon/DKLs23/issues/43) for background.

The full `Party` serde blob is large (~tens of KB for 2-of-3) because it includes OT
correlations and multiplication state. However, all of this state is derivable from
a small set of core values plus a deterministic seed.

### Minimal Key Share (Compact Export)

```
┌────────────────────────────────────────────┐
│ parameters: (u8, u8)        // (t, n)      │  2 bytes
│ party_index: u8                            │  1 byte
│ session_id: [u8; 32]                       │ 32 bytes
│ poly_point: Scalar                         │ 32 bytes
│ pk: AffinePoint (compressed)               │ 33 bytes
│ chain_code: [u8; 32]                       │ 32 bytes
│ zk_seed: [u8; 32]                          │ 32 bytes
└────────────────────────────────────────────┘
                                          ~164 bytes total
```

### Reconstruction via `re_key` with Seeded CSPRNG

On import, libtss can reconstruct the full `Party<C>` by calling the upstream
`re_key(parameters, session_id, poly_point, chain_code, address_fn)` function (which
returns `(Vec<Party<C>>, PublicKeyPackage<C>)`) with a CSPRNG seeded from `zk_seed`. This
derives all OT correlations, zero-share seeds, and multiplication gadgets
deterministically — producing identical state to the original DKG output.

**Implementation approach**:
- libtss wraps the DKLs23 `re_key` call with a seeded `StdRng::from_seed(zk_seed)`
  injected via the existing `rng` module abstraction
- The DKLs23 protocol crate is NOT modified — it continues using `Scalar::random(rng)`
- The wrapper controls determinism, not the protocol library

**Why this belongs in libtss, not DKLs23**:
- State persistence is an application-layer concern
- The same approach works for both DKLs23 and FROST (unified backup/recovery)
- Avoids threading `random_seed` parameters through protocol APIs (which increases
  nonce reuse risk — the #1 cause of ECDSA key compromise)
- Keeps the protocol crate focused on cryptographic correctness

### Security Considerations

- The `zk_seed` is SECRET material — same encryption requirements as the full export
- The seed MUST be generated from a CSPRNG at DKG time and stored alongside the key share
- Compact export saves storage/bandwidth but NOT security surface — the seed is
  equivalent in sensitivity to the full OT state
- The seed MUST NOT be reused across different key shares or sessions

## Blockchain Address Derivation

As of DKLs23 v0.4.0, address computation is decoupled from the protocol core via the
`AddressScheme<C>` trait and blockchain-specific address functions in the curve crates:

| Ciphersuite | Address Functions | Blockchains |
|-------------|-------------------|-------------|
| `Secp256k1ECDSA` | `compute_eth_address`, `compute_btc_address`, `compute_cosmos_address`, `compute_tron_address` | Ethereum, Bitcoin, Cosmos, TRON |
| `Secp256r1ECDSA` | `compute_neo3_address`, `compute_sui_address` | NEO3, Sui |

Since a single ciphersuite may support multiple blockchains, libtss exposes an
explicit `AddressScheme` enum so the caller specifies which address format to derive:

```rust
/// Supported blockchain address formats.
pub enum AddressScheme {
    Ethereum,   // secp256k1 — keccak256 of uncompressed public key
    Bitcoin,    // secp256k1 — P2WPKH (bech32)
    Cosmos,     // secp256k1 — bech32 with "cosmos" HRP
    Tron,       // secp256k1 — base58check of keccak256
    Neo3,       // secp256r1 — Neo3 address encoding
    Sui,        // secp256r1 — Blake2b of flag || pubkey
}

/// Compute the blockchain address for the given key share and address scheme.
/// Returns an error if the scheme is incompatible with the key share's ciphersuite
/// (e.g., requesting Ethereum for a secp256r1 key).
pub fn compute_address(
    key_share: &KeyShareHandle,
    scheme: AddressScheme,
) -> Result<String, TssError>;
```

Internally, `compute_address` extracts the group public key from the key share and
dispatches to the appropriate DKLs23 function (e.g., `compute_eth_address` for
`AddressScheme::Ethereum`). This works for both FROST and DKLs23 key shares since
it only requires the public key and curve type.

### C ABI

```c
/// AddressScheme constants (matches Rust enum discriminants).
#define TSS_ADDRESS_ETHEREUM  0
#define TSS_ADDRESS_BITCOIN   1
#define TSS_ADDRESS_COSMOS    2
#define TSS_ADDRESS_TRON      3
#define TSS_ADDRESS_NEO3      4
#define TSS_ADDRESS_SUI       5

TssStatus tss_compute_address(TssHandle key_share, uint8_t scheme, TssBuffer *out);
```
