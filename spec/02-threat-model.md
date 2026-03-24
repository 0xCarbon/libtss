# 02 - Threat Model

## Adversary Model

### Threshold Assumption

Both FROST and DKLs23 provide security under the **dishonest majority** model:

- Up to `t - 1` of `n` participants may be **fully corrupted** (controlled by adversary)
- The adversary is **malicious** (not just semi-honest): corrupted parties may deviate
  arbitrarily from the protocol
- The adversary is **adaptive** for DKLs23 (can corrupt parties during protocol execution)
  and **static** for FROST (corruptions happen before protocol start)

### Coordinator Trust (FROST)

The FROST Coordinator:
- Learns which participants are signing (metadata leakage)
- Does **not** hold any secret material
- Cannot forge signatures without `t` secret shares
- Can cause **denial of service** (abort) but cannot cause incorrect signatures
- All Coordinator↔signer communication can occur over authenticated public channels

### Communication Model

| Requirement | FROST | DKLs23 |
|-------------|-------|--------|
| Authenticated broadcast | Required (DKG Round 1, signing commitments) | Required (commitment phases) |
| Authenticated P2P | Required (DKG Round 2 secret shares) | Required (OT messages, signing phases) |
| Confidential P2P | Required (DKG Round 2) | Required (all inter-party messages) |
| Message ordering | Rounds are sequential | Phases are sequential |

The library is **transport-agnostic**: it produces and consumes byte messages. The
application layer must provide authenticated and (where noted) confidential channels.

### CRITICAL: P2P Channel Security Requirement

**The DKLs23 protocol crate (0xCarbon) provides NO transport-layer encryption.**
All inter-party messages are plain serialized structs. The application MUST provide
its own authenticated encryption for P2P channels.

Without authenticated encryption on P2P channels:
- An eavesdropper can learn OT extension data, potentially compromising the protocol
- A MitM can alter messages, causing key destruction (TOB-SILA-6 class)
- Replay attacks become possible despite session IDs in the protocol

**Minimum requirement**: Each P2P channel must use an authenticated encryption scheme
(e.g., X25519 key agreement + ChaCha20-Poly1305 AEAD, or TLS 1.3) with:
- Forward secrecy (ephemeral key exchange per session)
- Unique nonce per message per direction (never reuse across directions -- TOB-SILA-6)
- Sender authentication (each party must verify the identity of its counterpart)

**Note**: The Silence Labs DKLs23 crate (the audited alternative) includes built-in
X25519 + ChaCha20-Poly1305 + EdDSA sender authentication. The [0xCarbon crate](https://github.com/0xCarbon/DKLs23) does not. See [05-dkls23-integration.md](05-dkls23-integration.md)
for implications.

For FROST, the DKG Round 2 secret shares also require confidential channels. Signing
commitments and signature shares only require authenticated (not confidential) channels.

## Cryptographic Assumptions

### FROST
- **Discrete Logarithm Problem (DLP)** over the chosen group (e.g., secp256k1)
- **Random Oracle Model** for hash functions (H1-H5 in RFC 9591)
- Security level: 128-bit (secp256k1, Ed25519, P-256, Ristretto255) or 224-bit (Ed448)

### DKLs23
- **Oblivious Transfer (OT)** security, which can be instantiated from DLP on the signing curve
- **Random Oracle Model** for hash-based commitments and Fiat-Shamir transforms
- No additional assumptions (unlike GG18/CGGMP21 which require Strong RSA for Paillier)
- Security parameters: λ_c = 256 (computational), λ_s = 80 (statistical)

## Threat Categories

### T1: Key Extraction via Protocol Attacks

**Applicable to**: Both protocols

Known attack classes on threshold signing (all mitigated by protocol choice):

| Attack | Affected Protocols | libtss Mitigation |
|--------|--------------------|----------------------|
| TSSHOCK alpha-shuffle | GG18/GG20/CGGMP21 (tss-lib, THORChain, Multichain, Taurus multi-party-sig) | Not applicable -- uses FROST/DKLs23, no Paillier dlnproofs |
| TSSHOCK c-split | GG20 (Axelar tofn, ING Bank, ZenGo multi-party-ecdsa) | Not applicable -- no composite-order group ZK proofs |
| TSSHOCK c-guess | GG18/GG20 (Multichain fastMPC) | Not applicable -- no iterated dlnproofs |
| BitForge (CVE-2023-33241) | GG18/GG20 (16 sigs for key extraction via malicious Paillier modulus with small factors) | Not applicable -- no Paillier encryption in FROST/DKLs23 |
| TOB-SILA-6 (nonce reuse in P2P channels) | DKLs23 implementations with shared encryption keys for bidirectional channels | Not applicable: 0xCarbon crate is transport-agnostic (no built-in encryption); channel encryption is the application's responsibility with explicit directional nonce requirements documented |
| TOB-SILA-12 (selective abort mishandling) | DKLs23 implementations that panic instead of identifying culprit | Mitigated in 0xCarbon v0.2.0+: all protocol phases return `Result<T, Abort>` with structured `AbortReason` enum and `AbortKind::BanCounterparty(PartyIndex)` for OT-related failures; no panic paths remain; session state machines with phase ordering enforcement since v0.3.0; v0.4.1 adds curve-generic types and secp256r1 support; `catch_unwind` as defense-in-depth |
| Rogue-key attacks | Naive Schnorr multisig | FROST DKG includes proof-of-knowledge |
| Nonce reuse → key recovery | All threshold schemes | Hedged nonce generation with fresh randomness (SR-2) |
| Fiat-Shamir replay (CVE-2022-47930) | Implementations without session binding (tss-lib) | Session IDs in all challenge computations (SR-6) |
| Hash collision via delimiter (CVE-2022-47931) | Implementations using '$' separator in hash inputs (tss-lib) | Length-prefixed encoding only (SR-7) |
| Non-constant-time math/big (CVE-2023-26556, CVE-2023-26557) | Go TSS implementations using `math/big` for secrets | Consumer languages never touch secret scalars; all arithmetic in Rust (SR-1) |

### T2: Side-Channel Attacks

**Applicable to**: FFI boundary and implementation

| Channel | Risk | Mitigation |
|---------|------|------------|
| Timing | Variable-time scalar operations leak key bits | All secret operations in Rust using `k256`/`curve25519-dalek` (constant-time). Consumer languages never touch secret scalars. |
| Memory | Secrets persist in freed memory, swap, core dumps | Rust `zeroize` on Drop for all secret types. Secrets allocated by Rust system allocator, never by consumer language's GC heap. |
| GC observation | GC languages (Go, Java, Python) can copy/move data, leaving secret copies | Secrets never exist as consumer-language values. Opaque `uint64` handles only. |
| Microarchitecture | Cache timing, speculative execution (GoFetch) | Constant-time Rust implementations. Application-level: process isolation. |

### T3: FFI Boundary Attacks

**Applicable to**: C ABI boundary (all consumer languages)

| Attack | Risk | Mitigation |
|--------|------|------------|
| Panic across FFI | Rust panic unwinding into consumer is UB | `catch_unwind` at every `extern "C"` entry point, convert to status code |
| Use-after-free | Consumer language frees/GCs memory still referenced by Rust | Secrets allocated by Rust. Consumer handles are `uint64` indices, not pointers. |
| Double-free | Both consumer and Rust attempt to free same allocation | Clear ownership: Rust allocates/frees secrets via handles, consumer frees `TssBuffer`s via `tss_buffer_free()` |
| Buffer overflow | Incorrect length parameters at FFI boundary | `TssSlice` carries explicit length; all functions validate buffer sizes |
| Type confusion | Wrong type passed through opaque handle | Typed handle registry with category bits + generation counters |

### T4: Protocol-Level Denial of Service

**Applicable to**: Both protocols (neither is robust)

| Attack | Impact | Mitigation |
|--------|--------|------------|
| Abort during signing | Signing session fails | **Identifiable abort**: misbehaving signer is identified via `culprits()`. Application can exclude and retry. ROAST wrapper for robustness (future work). |
| Invalid DKG shares | Key generation fails | Feldman VSS verification (FROST). Commitment verification (DKLs23). Bad actors identified. |
| Message withholding | Protocol stalls | Application-layer timeout. Not a library concern. |

### T5: Key Share Compromise (Proactive Security)

**Applicable to**: Operational security over time

| Scenario | Mitigation |
|----------|------------|
| Single share compromised | Attacker needs `t` shares; single share is useless alone |
| Share compromised over time (mobile adversary) | **Share refresh**: rotate shares without changing public key. Old shares become useless. |
| Share lost (device failure) | **Share repair**: `t` helpers can reconstruct a lost share for a designated participant |
| All shares of one party compromised | Refresh immediately. If < `t` total compromised, security is maintained. |

### T6: Additive Key Derivation + Presignatures

**Applicable to**: DKLs23 with BIP-32

When combining threshold ECDSA with non-hardened BIP-32 derivation and presignatures,
security degrades from 128 bits to ~85 bits (see [Aragon Research](https://research.aragon.org/ecdsa-akd.html)).

**Mitigation**: DKLs23 in libtss does NOT use presignatures. Each signing session
generates fresh nonces. This attack does not apply.

## Trust Boundaries

```
┌────────────────────────────────────────────────┐
│ UNTRUSTED: Network, other parties' messages     │
│                                                │
│  ┌──────────────────────────────────────────┐  │
│  │ VERIFIED: Deserialized + validated input  │  │
│  │                                          │  │
│  │  ┌────────────────────────────────────┐  │  │
│  │  │ TRUSTED: Rust cryptographic core    │  │  │
│  │  │                                    │  │  │
│  │  │  Secret key shares                 │  │  │
│  │  │  Nonces                            │  │  │
│  │  │  Intermediate protocol state       │  │  │
│  │  │  Scalar/point arithmetic           │  │  │
│  │  └────────────────────────────────────┘  │  │
│  │                                          │  │
│  │  Consumer language orchestration layer    │  │
│  │  (handles, public values, messages)      │  │
│  └──────────────────────────────────────────┘  │
│                                                │
│  Application code (transport, storage, UI)      │
└────────────────────────────────────────────────┘
```

All input validation happens at the boundary between UNTRUSTED and VERIFIED. The Rust core
never processes unvalidated input.

## Security Properties Guaranteed

| Property | FROST | DKLs23 |
|----------|-------|--------|
| **EUF-CMA** (existential unforgeability under chosen message attacks) | Yes | Yes |
| **Identifiable abort** | Yes (cheater detection in aggregation) | Yes (abort with party index) |
| **Key secrecy** | No single party learns the full signing key | No single party learns the full signing key |
| **Signature unforgeability** | `t` shares required; `t-1` shares reveal nothing | `t` shares required; `t-1` shares reveal nothing |
| **Proactive security** | Via share refresh | Via share refresh (complete + quick) |
| **Forward secrecy after refresh** | Old shares unusable after refresh | Old shares unusable after refresh |

## Security Properties NOT Guaranteed

- **Robustness**: A single misbehaving party can cause abort (both protocols)
- **Anonymity**: The Coordinator (FROST) or all parties (DKLs23) learn who participates
- **Post-quantum security**: Neither protocol is quantum-resistant
- **Hardened BIP-32 derivation**: Requires MPC hash computation (out of scope)
- **Protection against compromised OS/hardware**: If the machine running a signer is
  fully compromised, the share on that machine is compromised
