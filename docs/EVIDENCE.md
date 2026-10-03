# Evidence and verification boundaries

Source observation date: 2026-10-03. Moving branch names are discovery aids; the commits below identify the inspected source. Repository state is not evidence of a running network's activation state.

## Source inventory

| Source | Immutable revision | Observed role |
| --- | --- | --- |
| `go-zenon` PTLC proposal | `8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18` | Open Draft PR #13; embedded contract and its tests |
| `go-zenon` master | `667a69d9e9a418edf7580b08492ba5dcb9efd63a` | HTLC baseline; implemented spork list has no PTLC |
| `go-zenon` dev | `44c0baf1106a76407ac4becf204306f499ae28f9` | Composed feature activation; no PTLC contract registration |
| Experimental PTLC demo | `bdc02c11e78fcf9e7af2dafa3a39d7a771935ce3` | Historical single-process Ed25519 swap illustration |
| Bitcoin BIPs | `927b6de9915c9262615a6399de51b200f81e5aa4` | BIP340, BIP341, BIP327, and locktime requirements |

The PR's recorded base SHA is not necessarily the current target-branch tip. An unassigned or old PR does not establish that work has no owner. The open-PR title check found #13 and #101 (community spork address renewal); it is a preliminary overlap check, not a complete ownership audit or maintainer agreement.

## Core contract facts

At the pinned [PTLC implementation](https://github.com/zenon-network/go-zenon/blob/8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18/vm/embedded/implementation/ptlc.go), `PointLock` is the public key used to verify an ordinary signature. The unlock message binds the contract ID and destination. The contract neither verifies an adaptor pre-signature nor establishes the relationship between two chain spends.

Creation checks the supported point type and byte length; BIP340 public-key parsing occurs during unlock. The accepted encoding policy and unexpected stored-type behavior remain integration decisions. These observations do not establish an externally reachable theft path in the contract.

Existing [contract tests](https://github.com/zenon-network/go-zenon/blob/8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18/vm/embedded/tests/ptlc_test.go) already cover exact expiry boundaries and attempts to reuse a spent entry. Preserve and extend them rather than describing them as absent. No embedded-contract tests have run here. The [Go compatibility harness](../qualification-go/README.md) executes the same signature-verifier dependency version in isolation.

Current registration and baseline references:

- [Master HTLC implementation](https://github.com/zenon-network/go-zenon/blob/667a69d9e9a418edf7580b08492ba5dcb9efd63a/vm/embedded/implementation/htlc.go)
- [Master implemented sporks](https://github.com/zenon-network/go-zenon/blob/667a69d9e9a418edf7580b08492ba5dcb9efd63a/common/types/spork.go)
- [Dev contract registration](https://github.com/zenon-network/go-zenon/blob/44c0baf1106a76407ac4becf204306f499ae28f9/vm/embedded/embedded.go)

## Historical scalar-disclosure finding

The pinned demo's [client](https://github.com/KingGorrin/znn_ptlc_use_cases_go/blob/bdc02c11e78fcf9e7af2dafa3a39d7a771935ce3/app/main.go#L124-L136) transmits `c1*a1` and `c2*a2`. The recipient [computes the same public challenges](https://github.com/KingGorrin/znn_ptlc_use_cases_go/blob/bdc02c11e78fcf9e7af2dafa3a39d7a771935ce3/app/main.go#L301-L316). The [arithmetic helper](https://github.com/KingGorrin/znn_ptlc_use_cases_go/blob/bdc02c11e78fcf9e7af2dafa3a39d7a771935ce3/crypto/ed25519/ed25519.go#L110-L187) uses ordinary scalar multiplication modulo the Ed25519 subgroup order.

For nonzero public `c`, the recipient can recover `a = (c*a) * inverse(c) mod l`. Knowing its own scalar `b`, it can then sign under the aggregate public key `(a+b)G` without the intended adaptor secret. This concerns the ephemeral PTLC signing scalar; it does not imply recovery of a wallet seed or long-term wallet key.

The local tests reproduce that algebra and obtain independent verification of a synthetic aggregate-key signature. They do not execute the original demo, invoke the Zenon VM, or demonstrate on-chain theft. Synthetic fixture values are public and must never be used for funds.

The demo also leaves counter-lock verification incomplete and relays the final signature through an in-process channel. Its cryptographic implementation is not an adopted dependency.

### Inspected file digests

SHA-256 is computed over the exact raw file bytes at the pinned commits. Source files are linked, not vendored.

| Source file | SHA-256 |
| --- | --- |
| Demo `app/main.go` | `9b033a05a13c8225cf66e08ed55f4b8aa00e053d4894fde4f864500e7e4fb885` |
| Demo `crypto/ed25519/ed25519.go` | `43ed182609ca1e27362cf4ef3a0e4e8f24e130dd2a0fc8c4d9bc1e88bee2a1d7` |
| PR #13 `vm/embedded/implementation/ptlc.go` | `d85891a4ed8ee2c824cc519ab5e4049de4bcf9b43cd5ec30d7baf7711ecf0028` |
| PR #13 `vm/embedded/tests/ptlc_test.go` | `d11de77fb4491586105ac431b60ccfb8abf89594c42eccfd6105147958b2eb58` |

## Standards

- [BIP340](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0340.mediawiki): Schnorr signature verification and adaptor-signature applications. It is not a complete swap protocol.
- [BIP341](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0341.mediawiki): Taproot spending and signature commitments.
- [BIP327](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0327.mediawiki): MuSig2, if selected; not a general adaptor-swap specification.
- [BIP65](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0065.mediawiki), [BIP68](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0068.mediawiki), and [BIP113](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0113.mediawiki): absolute/relative locktime and median-time semantics.
- [RFC8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1): independent Ed25519 public test-vector reference for the offline regression.

## Limits and outstanding evidence

- [Stage 1](STAGE1_VALIDATION.md) records primitive, compatibility and finite-model results. [Stage 2](STAGE2_VALIDATION.md) records historical public-session and journal results. [Stage 3](STAGE3_VALIDATION.md) records nonce rounds and an ephemeral test owner. [Stage 4](STAGE4_VALIDATION.md) records the managed Bob public-artifact flow, journal v3 and actual public-verifier integration. [Stage 5](STAGE5_VALIDATION.md) records Alice synthetic completion, actual Bob public recovery, journal v4 and separate-journal integration. Local test success establishes only the covered inputs and abstraction, not safety of a complete protocol.
- No selected production adaptor implementation or complete transaction graph is approved by this package.
- No core port, node execution, regtest/devnet swap, wallet operation, or activation was performed.
- The hosted CI definition is prepared locally; hosted execution is not established by local tests.
- Before core changes, refresh source refs, inspect target-file overlap, and coordinate contract semantics and activation with maintainers.

## Reused public vector provenance

The BIP340 fixture retains only public verification fields from the official corpus at the BIPs revision above. Its source URL and raw CSV SHA-256 are embedded in the JSON. The specification offers its test vectors under BSD-2-Clause, MIT or CC0-1.0; this derived fixture uses the CC0-1.0 option. Secret-key and auxiliary-randomness columns were omitted. The fixture is not newly authored signature data.

The RFC8032 public key/message/signature example is identified in the historical regression fixture. No upstream Ed25519 implementation was copied into the local algebra regression. Library dependencies and their licenses are documented in each qualification module; their source is acquired into an ignored cache rather than vendored into this repository.
