# Stage 8 validation: durable Bob recovery allowance

Historical milestone report. [Stage 9](STAGE9_VALIDATION.md) adds a separate completion-envelope qualifier; the journal allowance and its unenforced authentication boundary remain unchanged.

Scope: a caller-selected local allowance shared by ordinary Bob public recovery and explicit reconciliation. Admission is persisted before the worker and never refunded. No peer authentication, Alice producer policy, cryptographic construction, chain observation or live execution was added.

## Executed checks

| Check | Result | Evidence boundary |
| --- | --- | --- |
| Required-mode full Python suite | 241 passed, 0 failed, 0 skipped | Previous 225 plus 15 allowance tests and one process-death matrix |
| New allowance boundary tests | 15 passed | Fake callbacks, real journal/checkpoint persistence and strict accounting |
| New admission process-death matrix | 1 test, 6 subcases passed | Actual child `SIGKILL` on both Bob paths before worker invocation |
| Pure reconciliation regressions | 18 passed | Shared preflight and strict local packet-type checks |
| Affected existing journal and crash regressions | Passed | Admission accounting plus the separate reconciliation output-commit boundary |
| Actual Rust artifact integration | 2 passed | Existing retention/release path with explicit allowance configuration |
| Actual Rust completion integration | 6 passed | Existing five cases plus real rejection/exhaustion across reopen |
| Artifact hygiene, local links, workflow syntax and whitespace | Passed | Limited source checks, not anonymity or comprehensive secret detection |

Local execution uses Python 3.9.6 on macOS, with required independent OpenSSL verification for the full suite. The eight actual Rust subprocess integration tests run separately from Python discovery. Rust and Go sources, manifests, dependencies and cryptographic fixtures are unchanged; their suites were not independently rerun locally for this journal-only change. The already built pinned Rust executables were used for integration. Hosted results must be read from the corresponding commit/PR checks rather than inferred from these local results.

## Admission and persistence evidence

Tests require an explicit exact-integer limit from 1 through 64, reject missing/unlimited/boolean/floating-point choices, and show the allowance is not spent by initial artifact verification or Alice's synthetic completion. Ordinary recovery and reconciliation share the same count after reopen. Invalid stages, packet types, encodings and reconciliation guards reject without a debit. An exhausted eligible call invokes no worker and preserves storage.

Callbacks observe the admitted count in both current memory and the matched database/checkpoint before they run. A failed, false, malformed, stale or interrupted recovery keeps the admission consumed. Reconciliation failures change only allowance metadata; the original candidate, release and archive/output fields remain intact. Exact recorded output and release replay cost nothing, including at the limit.

Ownership tests reject reentrant mutation, close, competing owners and foreign-thread use while preserving the allowance. Continuity checks reject limit changes, decrements, increments greater than one, budget removal and session removal. Reload rejects invalid shapes/types, impossible candidate/count relationships and a superseded-observation archive with fewer than two admissions. Resealed v5 storage quarantines without modification or migration. A separate test demonstrates that restoring both matching earlier files can replenish the allowance; this is a known limitation, not a protection supplied by the change.

## Crash and actual cryptographic evidence

The new six-case matrix covers ordinary recovery and reconciliation at three admission boundaries. Before database commit, reopening retains the prior count and another attempt can run. After database commit but before its matching checkpoint, reopening quarantines. After matched admission persistence but before the worker, the final slot remains spent and both recovery paths cannot use it again. The public invocation marker remains absent in all six cases.

The existing seven-case reconciliation process matrix explicitly targets the later output commit after recovery returns. It now checks that admission stays consumed when the original candidate remains, while still distinguishing output-commit quarantine from completed replacement/archive replay. Existing ordinary completion crash tests also verify the admission count. Process termination is not a power-loss test.

Actual Rust integration checks that two cryptographically rejected observations consume the shared allowance. After reopen, even a valid replacement cannot invoke the worker once it is exhausted; the original candidate and release remain available. Other integration cases continue to verify successful completion, exact fixture output, positive replacement/archive retention and Alice's one-use synthetic producer. This establishes the intended local stopping behavior, not a safe policy for funded recovery.

## Intermediate results and compatibility

The initial 15-test allowance suite passed. Review strengthened causal validation for candidate/count equivalence, maximum one-step increments, and archive/count consistency; targeted regressions passed after those additions. The full required-mode suite passed all 241 tests in 325.396 seconds on its first run. All focused and integration runs passed without skips. Parallel implementation review is not an independent human cryptographic audit.

The ordinary completion preflight now checks the packet's exact type before comparing it with retained bytes, matching reconciliation's existing defensive order. The strict-type regression also covers both request-preparation helpers. This concerns hostile local API objects, not sender authentication.

The Python CI job timeout increases from ten to fifteen minutes to accommodate the expanded durable-state and process-death suite. The job matrix and required OpenSSL mode are unchanged. This does not alter a worker's runtime deadline.

Journal v6 adds a nullable session-level `recovery_budget` and changes `start_exchange` to require `recovery_limit`. Older v1-v5 storage is not migrated. Public packet/result schemas and cryptographic inputs remain unchanged. Historical Stage 6 storage-unchanged-on-failure claims now refer only to that earlier implementation; current reconciliation first commits its admission and later commits a positively verified result.

## Evidence and limits

The [admission design](RECOVERY_ADMISSION.md) describes configuration, continuity, crash gaps, exhaustion and availability limits. Fake callbacks establish sequencing only. Separate integration uses the actual pinned Rust executables and unchanged public fixtures. Process-death tests use real child termination, not a power-loss simulator.

The allowance applies to two Bob journal APIs only. Initial artifact verification, Alice completion, pure helpers, direct worker calls, other sessions and independent journals remain outside it. Jointly restored matching files can replenish the allowance. A callback failure does not prove cryptographic invalidity, and exhaustion can prevent a later valid recovery. Peer authentication and a production recovery policy remain unresolved.
