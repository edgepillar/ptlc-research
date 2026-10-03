# Stage 7 validation: bounded public worker transport

Historical milestone: [Stage 8](STAGE8_VALIDATION.md) adds Bob's durable recovery allowance and journal v6. Counts and storage-version references below describe Stage 7.

Scope: replace temporary-file stdout spooling in the public artifact and completion adapters with bounded concurrent pipe transfer. This changes local process handling, not the cryptographic construction, journal format, observation policy or signing ownership.

## Executed checks

| Check | Result | Evidence boundary |
| --- | --- | --- |
| Required-mode full Python suite | 225 passed, 0 failed, 0 skipped | Previous 210 plus 15 new process-boundary tests |
| Focused worker and adapter tests | 22 passed, 0 failed, 0 skipped | 15 real-worker/mixed fault-injection tests and 7 existing adapter tests |
| Actual Rust artifact integration | 2 passed | Public retention/release through the new transport |
| Actual Rust completion integration | 5 passed | Public completion, recovery and reconciliation through the new transport |
| Artifact hygiene, Markdown links and whitespace | Passed | Limited source checks, not an anonymity or comprehensive secret scan |

Local execution uses Python 3.9.6 on macOS, with required independent OpenSSL verification for the full suite. The seven Rust subprocess integration tests are separate from Python discovery. Rust and Go sources, manifests, dependencies and cryptographic fixtures are unchanged. Their suites were not independently rerun locally for this transport-only change; integration uses the existing pinned Rust binaries. Hosted checks for this change must be read from its corresponding commit/PR, not inferred from local results.

## Process and response evidence

The new synthetic actors exercise concurrent 65,536-byte stdin and 4,096-byte stdout, output floods before consuming stdin, exact output-limit acceptance and one-byte overflow, a smaller configured output allowance, discarded stderr floods, nonzero exit with plausible output, and early stdin closure. Error checks exclude the synthetic stderr marker, response contents and executable path. Actor lifetimes have a separate alarm so a faulty runner cannot leave a persistent test worker.

Deadline cases include a worker that never reads the request, a worker that closes stdout but continues running, and a worker that exits while a same-group child retains stdout. Tests check direct-child reaping; the inherited-pipe case also checks that the child's synthetic heartbeat stops. That finite observation does not prove arbitrary descendant containment.

Fault injection after spawn checks selector I/O errors and `KeyboardInterrupt`: pipes close and the direct child is reaped; I/O errors are sanitized and the interrupt propagates. A separate regression verifies that completed success and nonzero exit do not trigger a signal to an already reaped worker's old process group. Invalid deadlines, bounds and oversized/wrong-type requests reject before process creation. Existing adapter regressions still reject malformed, noncanonical, duplicate, deep and incorrectly bound responses.

Actual Rust integration preserves the complete artifact-retention, Alice completion and Bob recovery/reconciliation results against unchanged fixtures. Worker failure remains a transport failure, not proof that a candidate is cryptographically invalid. No stored state, exposure marker or one-use signing rule is reset by the new runner.

## Intermediate results

The first focused run passed 19 tests. Review added three process-boundary tests; the expanded run passed all 22. The flood test was then adjusted to use a more generous configured deadline while still requiring an explicit output-overflow error before that deadline; its final targeted run passed. Both actual Rust integration scripts passed on their first runs. The full required-mode suite passed all 225 tests in 272.831 seconds on its first run. There were no failed or skipped test runs in this milestone. Parallel implementation review is not an independent human security audit.

A local publication guard initially rejected Git's `Z` spelling of a UTC timestamp because it expected the equivalent `+00:00` suffix. The commit already used the explicit project identity and UTC dates; publication had not occurred. The guard was corrected to compare the parsed UTC offset, and this documentation note was added before publication. No implementation or test change was required.

## Evidence boundary

Synthetic subprocess tests isolate transport, overflow, deadlines and cleanup. The separate integration scripts exercise the already built pinned Rust artifact verifier and completion/recovery executable against public fixtures. Neither kind of test establishes peer authentication, chain identity, funding, timing authorization, settlement or private signing safety.

The [worker design](PUBLIC_WORKERS.md) separates pipe bounds from executable containment. Per-invocation limits do not provide aggregate rate control. Cleanup is best effort for the owned POSIX process group; it is not arbitrary descendant containment or a universal wall-clock return guarantee. Independent protocol review, restored-copy protection and actual private-worker integration remain unresolved.
