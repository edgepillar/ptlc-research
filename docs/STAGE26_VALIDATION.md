# Stage 26 validation: controlled resource-store storage failures

Scope: test-only v4 before/after storage faults, secondary rollback/cleanup
failures, poisoned-owner behavior and a native file-size refusal in a disposable
writer. Application sources, journal, mathematical records, cryptography,
store/pool/resource formats and dependencies are unchanged.

Source parent: [`1e0ae6f73df0dccbb309034a0451f5ea811095c8`](https://github.com/edgepillar/ptlc-research/tree/1e0ae6f73df0dccbb309034a0451f5ea811095c8).
The parent had [seven successful exact-head hosted jobs](https://github.com/edgepillar/ptlc-research/actions/runs/37195130029):
600 Python tests in each Linux/macOS 3.11/3.13 job, required OpenSSL, 55 Rust
checks, 13 Go top-level tests and 61 selected-worker qualifier cases. This parent
evidence does not execute or independently assess the new fault delta.

## Local checks

| Check | Result | Boundary |
| --- | --- | --- |
| First new fault suite | 9 passed in 52.017 seconds, no skips | Real SQLite/files/locks; synthetic verdicts and API failures; macOS v4 host selection is simulated |
| Combined fault, v3/v4 crash and continuity suites | 48 passed in 109.220 seconds, no skips | Includes prior real process-death and hot-journal cases |
| Full required offline suite | 609 passed in 672.218 seconds, no skips | OpenSSL required; macOS resource enforcement cases assert refusal |
| Existing actual v3 store qualifier | 6 passed in 16.027 seconds, no skips | Real selected Rust public verdicts and shared-actor regression |
| Artifact, local links and whitespace | 378 index/worktree versions, 189 tracked files, 535 valid local Markdown links; whitespace clean | English/ASCII and disclosure checks; four changed Python files parse; frozen subject unchanged |

No failed regression run occurred during this stage's local validation. Native
file-size cases require exact readback and actual one-byte `EFBIG` in the tracked
writer process; both local macOS cases passed. This native writer behavior is
separate from the simulated v4 host selector, synthetic normal verdicts and
synthetic `EIO`/`ENOSPC`/SQLite errors. It establishes no Linux worker-cap behavior.

## Qualified failure partitions

Nine discovery methods include 16 admission points, 16 result points, 16 recovery
points and 18 initial-creation points. Additional cases cover secondary rollback
and temporary-file cleanup failures, cancellation, recheck with prior normal
evidence and native writer file-size refusal. An after-operation fault requires
the real operation to have returned first.

Admission failure launches no selected or fallback worker. Result failure never
returns the normal statement. The live handle refuses reads and retries, while
a competing process remains busy before SQLite access until owner close; caller
capacity is released. Consistent reopen retains charge and earlier normal
evidence, resolves pending as unknown without replay and performs no extra work
or write on another reopen. Divergent/incomplete pairs and orphan checkpoints
remain quarantined without reset or repair. A real committed transaction followed
by synthetic reported failure is distinguished from successful rollback.

## Actual Linux and hosted gate

The expanded [actual v4 qualifier](../scripts/qualify_observation_resource_store.py)
contains 13 top-level cases. Three new methods cover seven result-fault
partitions after an actual positive, four recovery faults after an actual
interrupted recheck and two native writer file-limit cases. An actual positive
must be parsed from the original limited adapter; an unknown does not satisfy
this gate. The native result-side case requires the actual `verified` marker
before file-size refusal. Source journal state, sequence and both files remain
unchanged throughout each case.

This Linux-only qualifier and native CPU/address-space enforcement are not run
locally. The Rust CI job selects all nine actual-worker groups, with 64 total
cases expected. Only completed exact-head logs establish execution; all seven
jobs and the native Linux paths remain required. Rust/Go primitives and locked
dependencies are unchanged and are not rerun locally for this test delta.
Completed hosted results must be recorded separately from this source report.

The [first hosted attempt](https://github.com/edgepillar/ptlc-research/actions/runs/37197914016)
at [`c9d7826cbf8d3b9a66bdb1452bd0c1f8b585cd86`](https://github.com/edgepillar/ptlc-research/tree/c9d7826cbf8d3b9a66bdb1452bd0c1f8b585cd86)
completed six jobs successfully. All three completed Python jobs ran 609 tests
without skips and checked 378 artifact versions. Rust ran 55 tests and 64 actual
qualifier cases, including all 13 v4 cases; both Go jobs passed. Linux Python 3.13
was cancelled at the configured 20-minute job limit, with 562 test-method log
lines and no completed suite summary. GitHub's annotation explicitly identifies
the job time limit; this attempt is incomplete evidence, not seven-job success.
The follow-up raises only the Python CI job allowance to 30 minutes. It removes
no test and changes no per-worker deadline, CPU/address-space cap or native
assertion. A new exact-head seven-job run remains required.

## Progression decision

The [fault design](RESOURCE_STORE_FAULTS.md) separates desired failure behavior,
unchanged construction and executed evidence. Controlled API exceptions do not
qualify native disk exhaustion, `EIO`, physical synchronization failure or power
loss. Native file-size refusal qualifies only that writer boundary. Prepare a
separate exact assessment subject for the later observation/ownership/resource
deltas and their evidence, retaining unresolved native storage, restore, source,
aggregate-budget and availability obligations. The frozen Stage 12 subject and
119-file inventory are unchanged; independent assessment remains pending. No
production signer, chain source, funded recovery policy or core activation is
authorized by this stage.
