# 11 - References

## Protocol Specifications

| Ref | Title | Authors | Link |
|-----|-------|---------|------|
| RFC 9591 | Two-Round Threshold Schnorr Signatures with FROST | Komlo, Goldberg | [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9591.html) |
| DKLs23 | Threshold ECDSA in Three Rounds | Doerner, Kondi, Lee, shelat | [eprint 2023/765](https://eprint.iacr.org/2023/765) |
| DKLs19 | Threshold ECDSA from ECDSA Assumptions (t-of-n) | Doerner, Kondi, Lee, shelat | [eprint 2019/523](https://eprint.iacr.org/2019/523) |
| DKLs18 | Threshold ECDSA from ECDSA Assumptions (2-of-n) | Doerner, Kondi, Lee, shelat | [eprint 2018/499](https://eprint.iacr.org/2018/499) |
| BIP-340 | Schnorr Signatures for secp256k1 | Wuille, Nick, Towns | [bips.dev/340](https://bips.dev/340/) |
| BIP-341 | Taproot: SegWit version 1 spending rules | Wuille, Nick, Towns | [bips.dev/341](https://bips.dev/341/) |
| BIP-32 | Hierarchical Deterministic Wallets | Wuille | [bips.dev/32](https://bips.dev/32/) |

## Supporting Cryptographic Papers

| Ref | Title | Authors | Relevance | Link |
|-----|-------|---------|-----------|------|
| OT→OLE | From OT to OLE with Subquadratic Communication | Doerner, Haitner, Ishai, Makriyannis | 5x comm improvement for distributed ECDSA | [eprint 2025/1722](https://eprint.iacr.org/2025/1722) |
| Proactive Refresh | Refresh When You Wake Up: Proactive Threshold Wallets with Offline Devices | Kondi, Magri, Orlandi, Shlomovits | Offline-compatible share refresh for DKLs-family protocols | [eprint 2019/1328](https://eprint.iacr.org/2019/1328) |
| KOS OT Extension | Actively Secure OT Extension with Optimal Overhead | Keller, Orsini, Scholl | Foundation for OT extension in DKLs23 | [eprint 2015/546](https://eprint.iacr.org/2015/546) |
| SoftSpokenOT | Quieter OT Extension From Small-Field Silent VOLE | Roy | Improved OT extension, ~5x speedup over IKNP | [eprint 2022/192](https://eprint.iacr.org/2022/192) |
| Threshold BBS+ | Threshold BBS+ for Distributed Anonymous Credential Issuance | Doerner, Kondi, Lee, shelat, Tyner | DKLs-based threshold signing for anonymous credentials | [eprint 2023/602](https://eprint.iacr.org/2023/602) |
| BitForge | Practical Key-Extraction Attacks in Leading MPC Wallets | Makriyannis et al. (Fireblocks) | Paillier key vulnerability in GG18/GG20 | [eprint 2023/1234](https://eprint.iacr.org/2023/1234.pdf) |

## Security Audits

| Audit | Target | Auditor | Date | Findings | Link |
|-------|--------|---------|------|----------|------|
| Silent Shard DKLs23 | Silence Labs dkls23 crate | Trail of Bits | Feb 2024 | 15 issues (2 high: TOB-SILA-6 nonce reuse, TOB-SILA-12 selective abort); 14 resolved | [Audit Report PDF](https://github.com/silence-laboratories/dkls23/blob/main/docs/ToB-SilenceLaboratories_2024.04.10.pdf) |
| Silent Shard DKLs23 (blog) | Silence Labs dkls23 crate | Trail of Bits | Jun 2025 (blog) | Summary and lessons learned | [Blog Post](https://blog.trailofbits.com/2025/06/10/what-we-learned-reviewing-one-of-the-first-dkls23-libraries-from-silence-laboratories/) |
| FROST | ZCash Foundation frost crate v0.6.0 | NCC Group | 2023 | Included in frost repo | [frost repo](https://github.com/ZcashFoundation/frost) |

## Known Vulnerabilities in Other Implementations

### TSSHOCK (Verichains, BlackHat USA 2023)

Three key extraction attacks against GG18/GG20/CGGMP21 requiring only 1-2 signatures
with no abort (undetectable). None apply to FROST or DKLs23.

| Attack | Mechanism | Affected | Status |
|--------|-----------|----------|--------|
| alpha-shuffle | Ambiguous encoding in dlnproof Fiat-Shamir -- `$` delimiter enables hash collision. Attacker rearranges α values post-hashing. | tss-lib (Binance), THORChain, Multichain, Swingby, Threshold Network, Taurus multi-party-sig | Fixed in most |
| c-split | Exploits composite group order in optimized dlnproofs. When `e∤c`, computes `ρ + c·log mod N` via lattice attacks. Success probability 1/e. | Axelar tofn, ING Bank threshold-signatures, ZenGo multi-party-ecdsa | Axelar/ING unfixed; ZenGo won't fix |
| c-guess | Brute-forces reduced dlnproof iterations (128→1). Success probability 1/2^iterations. | Multichain fastMPC | Fixed |

Source: [verichains.io/tsshock](https://verichains.io/tsshock/)

### BitForge (Fireblocks, Aug 2023)

Key extraction via malicious Paillier modulus with small factors (CVE-2023-33241).

- **Mechanism**: Attacker constructs Paillier key N with small 16-bit prime factors.
  Sets k_A = N/p_i in MtA sub-protocol. Forges range proof since `e mod p_i = 0`.
  After 16 signatures, Chinese Remainder Theorem reconstructs victim's key share.
- **Root cause**: No zero-knowledge proof that N is a biprime of two large primes.
- **Fix**: Add Blum Modulus proof + No Small Prime Factors proof.
- **Affected**: All GG18/GG20 implementations lacking these proofs.
- **Not applicable to libtss**: FROST and DKLs23 do not use Paillier encryption.

Sources:
- [Fireblocks Technical Report](https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report)
- [Safeheron Analysis](https://safeheron.com/blog/bitforge-vulnerability/)

### io.finnet CVEs (2022-2023)

| CVE | Issue | Impact |
|-----|-------|--------|
| CVE-2022-47930 | Missing session ID in Fiat-Shamir challenges | MitM replay, unauthorized signing |
| CVE-2022-47931 | Hash collision via `$` delimiter concatenation | Secret compromise |
| CVE-2023-26556 | Non-constant-time `math/big` operations | Timing-based key extraction |
| CVE-2023-26557 | Non-constant-time secp256k1 scalar multiplication | Timing-based key extraction |

### Trail of Bits DKLs23 Audit Findings (Silence Labs)

| Finding | Severity | Issue | Resolution |
|---------|----------|-------|------------|
| TOB-SILA-6 | High | Communication channels reuse nonces -- enables message alteration between parties, key destruction | Fixed: unique encryption keys per direction |
| TOB-SILA-12 | High | Selective abort causes panic instead of identifying malicious party -- prevents banning bad actors | Fixed: explicit error handling with party identification |
| (timing) | Low | `eval_pprf` function has potential timing side-channel on secret values | Fixed: constant-time implementation |
| (13 others) | Info-Med | Documentation, testing, edge cases | 12 of 13 resolved |

**Key audit insight**: "OT-based systems proved less error-prone than Paillier approaches,
needing simpler validations for security." The DKLs23 protocol specification "gives
implementers significant freedom to choose sub-protocols (base OT, OT extension,
pairwise multiplication), requiring careful study."

## Implementations (DKLs Family)

### Open Source

| Implementation | Protocol | Language | License | Notes |
|---------------|----------|----------|---------|-------|
| [Silence Labs dkls23](https://github.com/silence-laboratories/dkls23) | DKLs23 | Rust | Apache-2.0 | Audited by Trail of Bits. Dynamic quorum, key import/export, migration from GG/CMP. Production SDK. |
| [0xCarbon DKLs23](https://github.com/0xCarbon/DKLs23) | DKLs23 | Rust | Apache-2.0/MIT | Used by libtss as a git dependency. v0.4.1: Multi-crate workspace (`dkls23-core` v0.4.1 + `dkls23-secp256k1` v0.4.2 + `dkls23-secp256r1` v0.4.1). Curve-generic types (`Party<C: DklsCurve>`, `DkgSession<C>`, `SignSession<'a, C>`, `PublicKeyPackage<C>`), `AddressScheme<C>` trait with blockchain-specific address functions (Ethereum, Bitcoin, Cosmos, TRON, NEO3, Sui). DKG, signing, complete + fast refresh, BIP-32 derivation, re-key, versioned tagged hashing (domain separation), structured `AbortReason` enum (25+ variants) with ban/recoverable classification, comprehensive input validation, session state machines, typed `PartyIndex`, `EcdsaSignature`, `PhaseOutput`/`PhaseInput` message containers, feature-gated serde, `#![forbid(unsafe_code)]`. |
| [Taurus multi-party-sig](https://github.com/taurusgroup/multi-party-sig/tree/main/protocols/doerner) | DKLs | Go | Apache-2.0 | Go implementation. Known vulnerability [GHSA-7f6p-phw2-8253](https://www.miggo.io/vulnerability-database/cve/GHSA-7f6p-phw2-8253) (OT reuse). Unaudited. |
| [Coinbase kryptology](https://github.com/coinbase/kryptology/tree/master/pkg/tecdsa/dkls/v1) | DKLs18 (2-of-2 only) | Go | Apache-2.0 | **Archived** (Sep 2022). 2-of-2 only, not t-of-n. |
| [Dock Network](https://github.com/docknetwork/crypto/tree/main/bbs_plus/src/threshold) | DKLs (BBS+) | Rust | Apache-2.0 | Threshold BBS+ signatures, not ECDSA. |
| [DKLs reference](https://jackdoerner.net/) | DKLs19/18 | Rust | BSD | Authors' proof-of-concept. |

### Proprietary

| Company | Protocol | Notes |
|---------|----------|-------|
| [BlockDaemon](https://www.blockdaemon.com/) | DKLs19/23 | Builder Vault. Supports BIP-32 hardened derivation for limited thresholds. |
| [Utila](https://utila.io/) | DKLs | MPC ECDSA with DKLs. |
| [Vultisig](https://vultisig.com/) | DKLs | Consumer vault application. |
| [Copper](https://copper.co/) | DKLs | Institutional custody. |
| [Lit Protocol](https://www.litprotocol.com/) | DKLs | Decentralized key management. |
| [Sodot](https://www.sodot.dev/) | DKLs | MPC infrastructure. |
| [Web3Auth](https://web3auth.io/) | DKLs | Web-based MPC. |
| [Visa](https://usa.visa.com) | DKLs | Payment systems research. |

## DKLs Protocol Authors

- [Jack Doerner](https://jackdoerner.net) (University of Virginia)
- [Yashvanth Kondi](https://www.ykondi.net/) (Silence Laboratories)
- [Eysa Lee](https://www.eysalee.com/) (Brown University)
- [abhi shelat](https://shelat.khoury.northeastern.edu/) (Northeastern University)
- [LaKyah Tyner](https://www.khoury.northeastern.edu/home/lakyahtyner/index.html) (Northeastern, BBS+ work)

## Talks

| Title | Event | Link |
|-------|-------|------|
| DKLs23 presentation | Real World Crypto 2023 | [YouTube (starts at 36:00)](https://youtu.be/-d0Ny7NAG-w?t=2160) |

## Tools Used in DKLs23 Auditing

| Tool | Purpose |
|------|---------|
| [cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit) | Dependency vulnerability scanning |
| [Clippy](https://doc.rust-lang.org/clippy/) | Rust linting |
| [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) | Test coverage analysis |
| [Dylint](https://github.com/trailofbits/dylint) | Custom Rust lint rules (Trail of Bits) |
| [subtle](https://crates.io/crates/subtle) | Constant-time comparison primitives |

## Portal

- [dkls.info](https://dkls.info/) -- Official DKLs protocol information hub (papers, implementations, deployments)
