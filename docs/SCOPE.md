# Scope and delivery boundaries

Status: **Stage 8 - durable Bob recovery allowance. CANDIDATE-01 has primitive, transaction, session and schedule evidence, with no executable swap client or production signing backend.**

The intended later deliverable is a reference application for one bilateral Bitcoin regtest <-> Zenon devnet swap. Current work establishes an inspectable specification, source inventory, synthetic primitive tests and bounded schedule evidence before connecting nodes. It is not a production wallet, a deployed contract, or an activation proposal.

## Stage 0 deliverables

- Record the exact upstream contract behavior and distinguish existing tests from missing evidence.
- Compare a compatible HTLC baseline with a prospective BIP340/secp256k1 adaptor design. Document what additional benefit justifies the cryptographic and integration work.
- Specify the safety properties, unresolved protocol choices, failure model, and later validation requirements.
- Keep any offline algebra or regression demonstrations separate from cryptographic implementations intended to hold funds. A passing demonstration does not establish protocol security.

Stages 0 through 8 exclude node integration, wallet access, live RPC interaction, real funds, production key material, upstream node changes, and feature activation. Source inspection and local fixture checks cannot establish successful cross-chain settlement.

## Stage 1 deliverables

- Fix one candidate graph and roles in [TRANSACTION_GRAPH.md](TRANSACTION_GRAPH.md), including independently executable refunds and artifact exchange order.
- Qualify two pinned adaptor primitive implementations and untweaked two-party linkage using synthetic inputs. Cross-check completed signatures through separate arithmetic implementations and the pinned Go contract verifier dependency.
- Qualify a real synthetic Taproot key-path claim and independent CLTV refund, including exact serialization, tweak, sighash, and separate Go script execution.
- Enumerate finite schedules under explicit bounds and produce counterexamples when safety guards are removed.
- Record all executed checks, intermediate failures and unimplemented boundaries in [STAGE1_VALIDATION.md](STAGE1_VALIDATION.md). This is no substitute for transaction construction, durable signing or real-node integration.

## Ownership boundaries

Stage 2 adds bounded versioned transcript commitments, session-wide funding/entry bindings, exclusive public-state ownership and a one-use synthetic producer journal. Its [design](SESSION_JOURNAL.md) and [validation](STAGE2_VALIDATION.md) explicitly separate public metadata from real cryptographic nonce handling. A separately stored checkpoint detects one-sided restore; restoring both matching copies remains undetectable.

Stage 3 adds [public nonce-round commitments](NONCE_ROUNDS.md), journal v2 round pins and local duplicate-public-nonce history, plus a separate ephemeral Rust test owner. Shared public fixtures connect the Python hashes, actual pinned MuSig2 signing, legacy Go BIP340 verification, and Bitcoin script execution. The Python callback only replays checked-in public bytes; no signing backend is attached. [Stage 3 validation](STAGE3_VALIDATION.md) records the evidence boundary.

Stage 4 implements the [managed Bob artifact flow](ARTIFACT_EXCHANGE.md) in journal v3. It verifies public partials/bundles, retains the complete Zenon extraction context, commits release intent, and returns exact replayable bytes. The Rust subprocess is a public verifier, not a signing worker. Its integration and process-death checks are recorded in [Stage 4 validation](STAGE4_VALIDATION.md). Peer authentication, actual chain/timing policy and secret signing remain absent.

Stage 5 adds [Alice completion and Bob public recovery](COMPLETION_LIFECYCLE.md) in journal v4. Alice validates the complete inbound bundle, consumes her synthetic producer before invocation, and persists exact completion output. Bob retains the observed public signature before actual verification, witness extraction and Bitcoin adaptation. Alice still returns a fixture signature; no private signing backend is attached. [Stage 5 validation](STAGE5_VALIDATION.md) records public cryptographic integration, process-death tests and the remaining paired-restore and observation-selection limits.

Stage 6 adds [explicit completion observation reconciliation](OBSERVATION_RECONCILIATION.md) in journal v5. A different candidate requires an exact retained-input guard and positive public cryptographic recovery before the completed replacement and original archive are persisted. This local recovery path does not authenticate observations or change Alice ownership. [Stage 6 validation](STAGE6_VALIDATION.md) records the evidence.

Stage 7 replaces temporary-file stdout spooling with [bounded public worker transport](PUBLIC_WORKERS.md), shared by the artifact and completion adapters. It adds concurrent pipe transfer, immediate overflow rejection, a transfer/exit deadline and bounded cleanup attempts without changing storage or cryptographic inputs. [Stage 7 validation](STAGE7_VALIDATION.md) separates synthetic process tests from actual Rust integration. Peer admission and aggregate resource policy remain unresolved.

Stage 8 adds a [durable Bob recovery allowance](RECOVERY_ADMISSION.md) in journal v6, shared by ordinary completion and explicit reconciliation. The caller chooses a finite immutable limit; each eligible attempt is charged before the worker, with no crash/failure refund. This changes reconciliation's storage behavior on failure, while preserving its candidate and archive rules. [Stage 8 validation](STAGE8_VALIDATION.md) records the evidence. Alice and initial artifact verification are outside this allowance; it is not authenticated admission or funded-swap availability policy.

| Component | Responsibility | Boundary for this repository |
| --- | --- | --- |
| Reference application | Session transcript, counterparty validation, chain observations, signing orchestration, durable recovery, and user-visible outcomes | Specify these now; implement only after the construction and transaction graph are selected. |
| `go-zenon` core / PTLC PR #13 | Consensus-visible contract admission, signature verification, expiry, transfers, RPC representation, and activation | Treat pinned source as evidence. Do not silently patch or redefine its rules from the client. A contribution requires fresh upstream state and overlap/ownership coordination. |
| Zenon SDK | Encoding calls, decoding responses, transaction construction and signing interfaces | Specify the required interface. Do not treat experimental fork support as integration into a maintained shared SDK. |
| Cryptographic library | Correct key handling, adaptor construction, verification, extraction, randomness, and nonce rules | Select and evaluate separately in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md). Do not import a demonstration because it completes a happy path. |
| Bitcoin node and transaction policy | Consensus and script validation; mempool admission and relay policy | A later regtest harness must distinguish these from client assumptions. Regtest cannot establish production fee-market behavior. |

## Initial product boundary

The design target is two participants, one agreed asset pair, one swap at a time per session, and one explicitly selected Bitcoin spend/refund graph. CANDIDATE-01 uses BIP340 over secp256k1 with two-party aggregate adaptor signing, a Taproot key-path claim and a unilateral CLTV refund leaf. This is an offline design choice, not approval of a particular backend or complete protocol.

The baseline asset is BTC against ZNN. Supporting QSR or other Zenon token standards, both trade directions, concurrent sessions, or additional spend structures requires explicit coverage; a generic token field is not that evidence. Concurrency safety remains mandatory even if the interface exposes only one session: a second process or restored copy must not reuse signing state.

Order books, routing, Lightning integration, lending, wrapped-BTC issuance, Portal accounting, and general cross-chain state verification are outside this reference application's initial boundary. A bilateral swap does not create a redeemable BTC-backed asset on Zenon.

## HTLC comparison before committing to PTLC

The current upstream master includes an HTLC contract. The existence of atomic swaps is therefore not a unique justification for adding PTLC. The baseline comparison must examine compatible hash/preimage rules, expiry and refund behavior, supported assets, privacy leakage, client complexity, and recovery costs. It must not assume that source availability demonstrates a working BTC <-> ZNN HTLC product.

A PTLC candidate must identify a concrete benefit, such as removing a shared on-chain hash linkage under a specified observer model or enabling a required signature protocol. Amounts, timing, endpoints, and the explicit Zenon contract remain observable. General claims of anonymity or lower cost require additional evidence.

## Source baseline

The following references were checked on **2026-10-03**. Branch state must be refreshed before implementation or coordination; these identifiers are evidence pins, not promises about current upstream state.

| Source | Pinned reference | Established fact |
| --- | --- | --- |
| [PTLC PR #13](https://github.com/zenon-network/go-zenon/pull/13) | `8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18` | Open draft at inspection; contract and tests exist. The two PR commits are dated 2023-05-22. |
| [Current master spork list](https://github.com/zenon-network/go-zenon/blob/667a69d9e9a418edf7580b08492ba5dcb9efd63a/common/types/spork.go) | `667a69d9e9a418edf7580b08492ba5dcb9efd63a` | HTLC is listed; PTLC is not. This is a source-level observation, not a live-chain activation query. |
| [Current dev contract registration](https://github.com/zenon-network/go-zenon/blob/44c0baf1106a76407ac4becf204306f499ae28f9/vm/embedded/embedded.go) | `44c0baf1106a76407ac4becf204306f499ae28f9` | Composed feature variants include HTLC and Dynamic Plasma; PTLC is absent. |

The PR's stored base SHA is not necessarily the current target-branch tip. See [EVIDENCE.md](EVIDENCE.md) for the evidence inventory and limitations.

## Exit criteria and next work

Stage 0 is reviewable when the source facts, cryptographic candidates, threat model, and unresolved decisions are documented and internally consistent. It does not have to resolve the construction to truthfully complete the research package.

Starting a runnable swap requires a separate decision resolving the cryptographic construction and the full transaction/message graph, with an independent assessment of the safety argument. The acceptance checklist in [PROTOCOL.md](PROTOCOL.md) must then become specific to that graph. A local proof of concept may expose additional blockers.

A later core port must preserve pre-activation historical behavior and compose PTLC with other activated features. Existing expiry and replay tests must be retained and extended; their presence must not be reported as absent. Any core contribution needs coordination with current maintainers and overlapping work before changes are proposed.

No result from this repository authorizes production activation. A later activation decision requires its own reviewed core commit, protocol implementation, operational assumptions, and network evidence.
