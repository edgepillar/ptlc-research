# Stage 6 validation: explicit Bob observation reconciliation

Historical milestone: [Stage 8](STAGE8_VALIDATION.md) adds journal v6 and a durable admission commit before Bob recovery. Failed reconciliation now consumes allowance while preserving the original protocol state. Storage-unchanged and single-commit claims below describe Stage 6 before that change.

Date: 2026-10-03. Scope: a local public-input replacement path for a retained Bob completion candidate, with positive cryptographic acceptance, exact original-packet retention and unchanged Alice ownership. No signing keys, secret nonce ownership, peer authentication, chain observation or live settlement were added.

## Executed checks

| Check | Result | Evidence boundary |
| --- | --- | --- |
| Required-mode full Python suite | 210 passed, 0 failed, 0 skipped | Previous 182 plus 18 pure, 9 journal and 1 process-matrix test |
| New pure reconciliation tests | 18 passed | Fake cryptographic callbacks; strict types, binding, snapshots and state boundaries |
| New journal reconciliation tests | 9 passed | Ownership, unchanged storage on failed recovery, single completed transition and version quarantine |
| New process-death matrix | 1 test, 7 subcases passed | Actual child `SIGKILL`; public fake recovery callback |
| Actual Rust completion integration | 5 passed | Existing 3 tests plus valid reconciliation and invalid replacement rejection |
| Existing actual Rust exchange integration | 2 passed | Retention/release regression on current storage schema |
| Artifact, links, whitespace and workflow syntax | Passed | Candidate hygiene, not anonymity or comprehensive secret detection |

The full local suite uses Python 3.9.6 on macOS with required OpenSSL verification. The seven real Rust subprocess integration tests are separate from Python discovery. This change does not modify Rust or Go source, manifests, lockfiles or cryptographic fixtures; their suites were not independently rerun as part of the local Python change. The already built pinned Rust executables were used for integration. Current hosted results must be read from the corresponding commit/PR checks rather than inferred from local success.

The initial published baseline `ac5f41e6dc56453df0c653d3972bfa6331d9c4b2` passed all seven hosted jobs in [run 37140504593](https://github.com/edgepillar/ptlc-research/actions/runs/37140504593), including Python 3.11/3.13 on Ubuntu/macOS, 37 Rust tests and both Go modules. That baseline result is historical evidence, not a test result for this change.

## State and cryptographic evidence

The pure tests require the exact domain-separated observation digest before invoking a callback. They reject stale, malformed, uppercase and wrong-type digests; absent candidates; wrong stages; identical replacements; noncanonical/duplicate/deep/oversized packets; changed role/session/round/context; and bool-for-integer context substitutions. False, malformed, stale, mutating or exceptional callback results cannot change the original state. Caller mutation during recovery cannot change the validated snapshot used for the output.

Successful reconciliation preserves the exact previous candidate, release, bundles and artifact receipts, changes only the completed observation/output fields, and seals further completion. Reload validates the historical packet's type, encoding, canonical context, inequality with the current packet, stage constraints and total-state bounds. A fake callback can accept invalid cryptography; a specific test prevents confusing callback sequencing with signature verification.

Journal tests compare the actual database and checkpoint bytes before and after failed recovery, and during the callback. No replacement is persisted before positive verification. Success advances the journal sequence once and stores the full completed transition. Generic and Alice sessions cannot use this path; reentrant mutation/close, foreign-thread use and competing owners are rejected. In-process checkpoint failures and a resealed v4 snapshot are tested separately; old storage is quarantined without migration or modification.

The actual Rust integration first retains an invalid original packet. Ordinary implicit replacement remains forbidden. The new explicit operation accepts a correct replacement only after the existing worker verifies the final Zenon signature, extraction point and completed Bitcoin signature. The output matches the unchanged independently checked fixture. Reopening preserves both the original archive and exact output/release replay, and prohibits another reconciliation. A second test supplies a different invalid replacement and verifies that the real worker's rejection leaves both storage copies unchanged.

The worker treats application context digests as opaque and supplied Bitcoin messages/roots as commitments. These results establish no funding, chain identity, safe reveal deadline, delivery or inclusion. An archived original is historical local evidence, not a cryptographic verdict that it was invalid.

## Process-death evidence

The child records a public invocation marker, reaches the selected checkpoint and is killed before returning any output. All seven subcases exercise one public recovery invocation:

| Checkpoint | Reopened result |
| --- | --- |
| Inside the recovery callback | Original session unchanged; replacement must be resupplied |
| After positive recovery | Same original state |
| Before database commit | Same original state |
| After database commit before checkpoint update | Quarantined |
| After checkpoint replacement | Completed replacement plus original archive; exact replay |
| After checkpoint synchronization | Same completed state and replay |
| After final commit hook before return | Same completed state and replay |

Tests verify the original release, replacement, superseded packet and expected Bitcoin signature exactly. Possible exposure remains true throughout. Pre-commit retries explicitly resupply the replacement and repeat only public computation. There is no persistent pending replacement to retrieve. Process kills do not simulate power loss or prove every filesystem's durability.

## Intermediate results and remaining gates

The initial 17-test pure suite, 9-test journal suite, 7-case process matrix and 5-test actual completion integration passed on their first runs. Later review found a strict local-API input issue: replacement equality ran before exact `bytes` type validation. A new eighteenth regression reproduced an unsanitized `RuntimeError` from a custom object's equality method. The helper now validates the packet before comparison; all 18 focused tests pass. This was a hostile local object case, not a JSON input or cryptographic bypass. An initial full run passed 209 tests before that final regression was included. The final full run passed all 210 tests with it included; all 5 actual completion integration tests also passed again after the fix. No failing test remains unresolved. Parallel review is an implementation check, not an independent human cryptographic audit.

The workflow runs on pushes to `main` and on pull requests, avoiding duplicate branch-push and pull-request runs for the same development change. The existing job matrix and checks are unchanged.

An initial pre-commit report check incorrectly treated the explanatory phrase "pending replacement" as an unfinished test result. The guard was narrowed to actual placeholder cells. That failed check created no commit or publication and required no implementation change.

The [reconciliation design](OBSERVATION_RECONCILIATION.md) specifies the implemented acceptance and crash boundaries. Remaining work includes authenticated transport and observation selection, funding/time/resource policy, complete transaction construction, actual private-worker integration, restored-copy protection and independent construction review. Production use and core activation remain outside this milestone.
