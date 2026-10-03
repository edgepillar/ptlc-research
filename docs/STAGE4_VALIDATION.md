# Stage 4 validation: managed public artifact exchange

Historical milestone: [Stage 5 validation](STAGE5_VALIDATION.md) records the later completion flow, v2 release packets and journal v4. [Stage 6](STAGE6_VALIDATION.md) records current reconciliation and v5. Counts, storage version and remaining-work items below describe Stage 4.

Date: 2026-10-03. This milestone uses only public synthetic fixtures, local temporary state and cached dependencies. No wallet, participant identity, peer transport, live RPC, node, broadcast, real funds, commit or publication was used. The new exchange has no application signing backend; its executable performs public verification only. Existing Rust signing tests ran separately with deliberately public synthetic inputs.

## Executed checks

| Check | Result | Scope |
| --- | --- | --- |
| Required-mode Python suite | 145 passed, 0 failed, 0 skipped | Python 3.9.6 on local macOS; required OpenSSL verification included |
| Rust locked offline suite | 30 passed, 0 failed, 0 ignored | 24 existing tests and 6 new verifier tests; Rust/Cargo 1.90.0 |
| Rust public verifier example | Built successfully | Existing pinned dependencies; no new dependency or signing capability |
| Real Python-to-Rust integration | 2 passed | Actual cryptographic acceptance/rejection, durable retention and exact public replay |
| Legacy core-verifier Go module | Passed all 4 top-level tests | Go 1.23.12; readonly modules and offline cache |
| Bitcoin Go module | Passed all 8 top-level tests | Existing independent transaction/script checks |
| Rust formatting and workflow YAML syntax | Passed | Hosted workflow execution not established |
| Artifact hygiene | Passed | ASCII/disclosure scan of candidate contents; no anonymity proof |

The Python total is the previous 108 tests plus 17 pure exchange/adapter tests, 17 managed-journal tests and 3 new process/recovery tests. Its fake verifier is intentionally not cryptographic evidence. The separate two-test integration executes the built Rust verifier; it is not included in the 145 count. The CI workflow now builds that executable and runs the integration after locked offline Rust tests. No hosted CI run or additional operating-system run occurred here.

## State and verification evidence

The pure tests exercise the six-stage order, wrong predecessors, exact output derivation, static/wrong-role/wrong-binding contexts, Alice-partial substitution, cross-leg public nonce reuse, defensive copies, state bounds, missing predecessor artifacts and altered stored release/receipt state. Wrong-stage actions invoke no verifier. False, wrong-digest, unknown-field, truthy-integer, malformed, mutating and exceptional verifier responses cannot advance accepted state.

The subprocess tests mock process responses to qualify nonzero status, timeout, malformed/noncanonical JSON, duplicate keys, oversized output and deeply nested output handling. They do not establish the safety of arbitrary executables. The explicitly selected verifier remains trusted local code; the wrapper is not a process resource sandbox.

The managed journal tests cover complete persistence/reopening, predecessor and public nonce pins, generic-path exclusion, reentrant mutations, foreign-thread ownership, verifier interruption, exact replay, stored-state semantic tampering, retained/release hook failures and v2 quarantine without modification. Existing generic shared-owner tests exercise actual fork-child refusal; existing v1 quarantine tests also pass. No automatic migration is implemented.

The six new Rust tests verify both legs and both artifact kinds against the unchanged public fixture. They reject message, key/order/tweak, adaptor-point, nonce, partial and pre-signature mutations, malformed curve/scalar encodings, schema/type/width changes, unknown and duplicate fields, noncanonical input and size violations. The final example build and formatting check pass without changing the manifest or lockfile.

The actual integration follows Bob's full managed sequence using the Rust subprocess. A Bitcoin partial substituted for Alice's Zenon partial is rejected without state change; a Bitcoin pre-signature substituted into the Zenon bundle is also rejected. Release is denied before the complete Zenon bundle exists. The journal is reopened before release, and again before exact replay. No external cryptographic verifier runs during release/replay; local structural/hash validation still runs. A separate mutation matrix directly exercises the real executable for both legs.

Rust receives an opaque application context digest and supplied Bitcoin message/root. Python derives those fields from the reconstructed context. This test does not independently rebuild Bitcoin transaction/script data or validate funding, identity, timing or chain history. Existing separate transaction fixtures remain bounded supporting evidence.

## Real process-death matrices

The process tests use an explicitly fake verification callback with valid public fixture bytes, then terminate real child processes at journal boundaries using `SIGKILL`. These qualify persistence order separately from the actual-verifier integration.

| Retention checkpoint | Result after reopen |
| --- | --- |
| Before complete Zenon-bundle database commit | Alice partial remains retained; no complete bundle; release/replay refused |
| After database commit, before checkpoint update | Quarantined; no automatic repair |
| After checkpoint synchronization | Complete Zenon bundle/context retained; release may proceed |
| After the retained-artifact hook | Same complete retention evidence |

| Release checkpoint | Result after reopen |
| --- | --- |
| Before release database commit | Complete extraction material remains; no release record; only a fresh public-byte release transition is available |
| After database commit, before checkpoint update | Quarantined; no automatic repair |
| After checkpoint replacement | Recorded release and possible-release marker retained; exact replay only |
| After checkpoint synchronization | Same recorded release and exact replay |
| After the release-commit hook, before return | Same recorded release and exact replay |

All nine subcases pass. Recovered release packets contain the exact retained Zenon context and pre-signature. The generic witness-exposure flag remains distinct and false in this Bob-only flow. A separate restart test refuses release/replay from an incomplete Alice-partial stage.

No child transmits to a peer. An output record marks possible escape conservatively, not delivery. A process kill after atomic replacement is not a power-cut simulation. Full matching snapshot rollback, privileged mutation and cloned secret state remain outside the guarantee.

## Intermediate failures and repairs

The first two process tests reported two errors: their expectations used `Conflict` for replay without a stored release, while the journal intentionally returned `OutcomeUnknown`. The assertions were corrected to the existing replay contract. The retention matrix was then added, and all three process tests passed in the final combined run.

Adversarial review found that a small but deeply nested JSON verifier reply could raise an uncaught `RecursionError` when calling `SubprocessVerifier` directly. The reducer already sanitized verifier exceptions, but the adapter's direct failure contract was incomplete. Adding the 3,001-byte response regression caused one targeted test error. The adapter now catches `RecursionError`; the targeted 17-test suite and the final 145-test suite passed afterward.

The 17 managed-journal tests and 36 legacy journal tests passed on their initial Stage 4 runs. Rust compiled and passed all 30 tests on its first Stage 4 run. The actual-verifier integration passed both tests on its first run. No failing test remains unresolved.

Parallel review inspected the protocol order, context derivation, Rust validation, journal ownership/reload/replay paths and CI integration. It reported no remaining actionable code finding within this offline scope after the adapter fix. This is not an independent human cryptographic audit or a security proof.

## Remaining work

- Alice's inbound verification, witness-bearing completion and Bob's final-signature extraction/completion lifecycle.
- Authenticated participants, durable network exchange, delivery reconciliation and routing all outbound artifacts through the managed owner.
- Actual funding observations, safe release deadlines, fee policy, chain rollback handling and finality assumptions.
- Production entropy, secret memory/storage, actual signer-worker ownership and its process-death boundary.
- Restored-copy/clone protection, independent review, current-node coordination and later regtest/devnet work.

The [managed exchange design](ARTIFACT_EXCHANGE.md) defines the precise implemented boundary. The Rust verifier is now connected to public artifact retention; the ephemeral Rust signing owner is still separate from the journal.
