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
    let chain_code = get_chain_code(key_handle)?;
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

### Security Note: Derivation + Refresh

Deriving a child key and then refreshing its shares is safe but has a subtlety:
after refresh, the parent key's shares and the child key's shares are no longer
related by the same additive tweak. This is expected and does not affect security.

Recommendation: derive keys as needed, refresh the master (root) shares periodically.

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

DKLs23 refresh uses `RefreshSession::new`, which re-runs the full DKG
(including OT re-initialization). This is the recommended mode when OT
state may have been partially compromised.

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

DKLs23 does not have a built-in repair mechanism equivalent to FROST's RTS. For DKLs23,
share recovery requires:

1. Re-running the complete DKG with the recovering party
2. Or using the re-key function with the reconstructed secret (requires trusted entity)

This is a limitation of the OT-based approach where the Party state includes OT
correlations that cannot be independently reconstructed.

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
