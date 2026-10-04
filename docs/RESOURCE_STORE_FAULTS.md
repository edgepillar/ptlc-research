# Explicit resource-store storage failures

Status: **Stage 26 offline v4 fault qualification. Application behavior, formats,
cryptography and recovery admission are unchanged. Independent assessment,
native I/O-error qualification and power-loss durability remain open.**

Source parent: [`1e0ae6f73df0dccbb309034a0451f5ea811095c8`](https://github.com/edgepillar/ptlc-research/tree/1e0ae6f73df0dccbb309034a0451f5ea811095c8).
The [v4 selection design](DURABLE_RESOURCE_POLICY.md) defines the entry and
[Stage 25 cut matrix](RESOURCE_STORE_CRASH_CUTS.md) defines process-death evidence.
This delta adds controlled API failures and a separate native writer file limit;
none changes the [owned store](../offline_session/observation_store.py).

## Requirements and unchanged construction

| Requirement | Selected construction | Qualified boundary |
| --- | --- | --- |
| Start no work after failed admission | Pending SQLite/checkpoint persistence precedes selected dispatch | Every injected admission failure launches no selected or ordinary worker |
| Return no uncommitted normal result | Exact result persistence precedes return | A storage failure raises a sanitized quarantine error, even after an actual positive verdict |
| Refuse uncertain live ownership | Persistence failure poisons the handle; both store locks remain held until close | Reads and retries refuse; a competing process remains busy before SQLite access |
| Release caller capacity on storage failure | The observation method closes its slot reference in its final cleanup | A fresh slot can be acquired while the failed store handle still owns its two locks |
| Preserve charge and earlier normal evidence | Recovery finishes pending work as unknown, without replay or refund | Consistent reopen preserves consumed attempts and an earlier exact normal claim |
| Refuse divergent or incomplete pairs | Full canonical pair validation under lifetime ownership | Reopen quarantines without resetting, adopting an orphan or repairing files |

Persistence uses a real SQLite transaction and DELETE/FULL settings, followed by
a flushed and fsynced temporary checkpoint, replacement and directory fsync.
Failures attempt rollback and then poison the handle. A rollback cannot undo an
already committed transaction. A separately opened, consistent pair can recover;
that does not make the failed live handle usable again.

## Controlled before/after failures

[The test helper](../tests/observation_store_fault_support.py) calls the exact
application persistence method. It tags the existing phase and wraps real
connection, file and operating-system operations. A one-shot failure occurs
either before the operation or after it has actually returned. After-operation
cases require a recorded real return, so an after-commit case cannot silently
become a pre-commit exception.

The error values are explicitly synthetic: SQLite `OperationalError`, `ENOSPC`
at checkpoint writes and `EIO` at other file operations. They qualify the
application response to reported failure. They do not demonstrate a real full
disk, native `EIO`, failed physical synchronization or partial-sector writes.
The helper is trusted test instrumentation, not a supported application API.

| Phase | Fault points | Expected reopen partition |
| --- | --- | --- |
| Admission, result, recovery | Before/after SQLite begin, row write and commit; checkpoint write, flush, fsync and replacement; directory fsync: 16 points per phase | Before committed database change: prior pair; committed database with old checkpoint: quarantine; completed replacement: consistent pair |
| Initial creation | The same 16 points plus before/after schema creation: 18 | Consistent completed empty pair may reopen; every incomplete pair refuses reinitialization |
| Secondary failures | Row write followed by failed rollback; checkpoint write followed by failed temporary-file unlink | Poisoned ownership persists; close forwards real connection close; an orphan is neither adopted nor deleted by reopen |
| Cancellation | Result faults after an interrupted selected call | Charge remains; consistent pending recovery is unknown; divergent pair quarantines |
| Recheck | Result faults after an earlier retained normal | Earlier exact normal and consumed allowance remain when the pair is consistent |

Nine [discovery test methods](../tests/test_observation_resource_store_faults.py)
cover these partitions. Their normal verdicts are synthetic. On macOS, only the
v4 supported-host selector is simulated; SQLite, processes, file operations and
locks are real. The real-return fault instrumentation is still synthetic on
Linux. Neither host supplies physical storage-failure evidence through it.

A result transaction that actually commits before a synthetic exception leaves
a divergent pair until checkpoint publication; reopening must quarantine. If
replacement already succeeded, the pair may be consistent, retaining the exact
normal result. Failure before directory fsync still poisons the original handle.
Consistent reopen in a running host proves no survival across power loss.

## Separate native file-size refusal

The disposable [owner actor](../tests/observation_store_actor.py) can install
`RLIMIT_FSIZE = (0, 0)` only in its own writer process, ignore `SIGXFSZ`, and require
exact limit readback. A one-byte write to a synthetic probe must fail with actual
kernel `EFBIG` before the actor proceeds. The parent controller and application
resource policy are unchanged. This is not a new production file-size policy.

Two discovery scenarios install this limit before admission or after a synthetic
selected result has returned. The first starts no work and consumes no attempt;
the second recovers one charged unknown without replay. A Linux-only qualifier
repeats both boundaries using the actual selected Rust worker and demands its
`verified` marker before the result-side limit. Only the disposable owner is
limited, after the worker has returned; no cap is installed on a signer or chain
process. Temporary probes use public synthetic bytes and have no secret content.

The official [Linux getrlimit manual](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
(man-pages 6.19, inspected 2026-10-04) describes file-size-limit refusal and
`SIGXFSZ`/`EFBIG` behavior. That Linux description is not macOS evidence; local
macOS cases independently demand the actual one-byte `EFBIG` failure. Native
file-size refusal supplies no evidence for native `EIO`, disk exhaustion,
physical fsync failure, controller faults or power cuts. No external code is
copied and no dependency is added.

## Actual verdict and review gates

The [Linux qualifier](../scripts/qualify_observation_resource_store.py) keeps its
ten prior cases and adds three methods: seven result-fault partitions after an
actual positive, four recovery faults after an actual interrupted recheck, and
the two native file-size refusals. Actual-positive instrumentation requires one
parsed `verified` result from the original limited adapter. Ordinary-worker
fallback is forbidden. Every case separately preserves the source journal's
state, sequence, database and checkpoint bytes.

**Go:** prepare a separately pinned assessment subject for the observation,
ownership, pool, resource and storage deltas, with exact executed evidence and
remaining native storage/restore/source obligations. Keep the original frozen
119-file subject unchanged. Execute the affected native Linux and actual-worker
checks; configured CI alone is not evidence.

**No-go:** infer native I/O-error or power-loss safety, rotate policy, enroll
trusted pools, connect retained claims to funded recovery, add private signing,
port this client owner into core or activate PTLC from these results. Matching
old pairs, coherent rewrites, new histories and separate physical pools retain
their quota and capacity bypasses. Aggregate budgets, fairness, source authority,
arbitrary worker containment and independent assessment remain unresolved.
See [Stage 26 validation](STAGE26_VALIDATION.md) for executed versus pending work.
