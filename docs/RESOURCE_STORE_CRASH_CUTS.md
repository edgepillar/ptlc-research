# Explicit resource-store process-death cuts

Status: **Stage 25 offline v4 storage/recovery qualification. No runtime,
cryptographic, journal, policy-rotation or core behavior changes are introduced.**

Source parent: [`8817589397c6697ac4aed003af19aff760cdf598`](https://github.com/edgepillar/ptlc-research/tree/8817589397c6697ac4aed003af19aff760cdf598).
[Stage 24](DURABLE_RESOURCE_POLICY.md) binds an explicit requested Linux resource
profile before SQLite access. Its synthetic exceptions and inherited v3 crash
matrix do not establish process-death behavior through every v4 write boundary.
This delta adds that separate qualification and real hot-journal refusal cases.

## Requirement and evidence separation

| Requirement | Selected check | Execution boundary |
| --- | --- | --- |
| Distinguish rollback, consistent publication and divergent pairs | Kill a tracked owner at each named SQLite/checkpoint hook, then reopen | Real POSIX SIGKILL and local SQLite, not power loss or storage failure |
| Reject another resource choice before SQLite rollback | Separate wrong-CPU, wrong-address-space and ordinary-v3 actors with a visible forbidden-connect marker | Real SQLite-produced hot journal and byte comparisons, not checkpoint authentication |
| Preserve an admitted charge through interrupted recovery | Kill recovery before/after database commit and checkpoint replacement/directory sync | No worker replay, refund, extra attempt or automatic repair |
| Preserve earlier normal evidence after a killed recheck | Reopen an interrupted second attempt and assert the exact prior normal bytes | Synthetic verdicts in Python discovery; actual Rust verdicts in a separate Linux qualifier |
| Establish actual result loss separately | Require a `verified` marker from the selected limited Rust adapter before killing its publisher | Actual selected public verification on unprivileged Linux, not independent protocol assessment |

The [controlled actor](../tests/observation_store_actor.py) supports ordinary v3
and explicit v4 entries with matching budgets and physical-pool configuration.
Recovery/initialization hooks are armed before opening; ordinary work hooks are
armed after opening. Signals target only the controller's tracked unreaped child.
Marker PIDs are never used for signaling. A connect attempt emits a separate
marker before raising, so sanitized exceptions cannot make a forbidden SQLite
access appear to pass.

## All nineteen named write/publication cuts

The [v4 crash suite](../tests/test_observation_resource_store_crash.py) covers
four initial-pair cuts, eleven admission/worker/result cuts and four recovery
cuts. Both worker entry methods and subprocess launch are forbidden during
matched parent-side reopen checks. Every successful recovered pair is reopened
again without another write, charge or worker. Mode/resource profile is retained.

| Cut | Expected subsequent matched reopen | Synthetic calls before the cut |
| --- | --- | --- |
| `initialize.before_db_commit` | Incomplete pair quarantines unchanged | 0 |
| `initialize.after_db_commit` | Missing checkpoint quarantines unchanged | 0 |
| `initialize.after_checkpoint_replace` | Consistent empty v4 pair | 0 |
| `initialize.after_checkpoint_commit` | Consistent empty v4 pair | 0 |
| `admission.before_db_commit` | SQLite rollback to prior empty history, no charge | 0 |
| `admission.after_db_commit` | Divergent pair quarantines unchanged | 0 |
| `admission.after_checkpoint_replace` | One charged unknown | 0 |
| `admission.after_checkpoint_commit` | One charged unknown | 0 |
| `admission.committed` | One charged unknown | 0 |
| `worker.returned` | One charged unknown; returned normal was not committed | 1 |
| `result.before_db_commit` | One charged unknown after SQLite rollback | 1 |
| `result.after_db_commit` | Divergent pair quarantines unchanged | 1 |
| `result.after_checkpoint_replace` | Exact normal retained | 1 |
| `result.after_checkpoint_commit` | Exact normal retained | 1 |
| `result.committed` | Exact normal retained | 1 |
| `recovery.before_db_commit` | Pending rollback then one charged unknown | 0 |
| `recovery.after_db_commit` | Divergent pair quarantines unchanged | 0 |
| `recovery.after_checkpoint_replace` | Recovered charged unknown retained | 0 |
| `recovery.after_checkpoint_commit` | Recovered charged unknown retained | 0 |

Recovery cases start from a consistent charged pending record. Three consecutive
deaths before its recovery commit preserve that charge; a later successful
recovery has revision two, no pending record and no worker replay. Killed recheck
cases separately preserve an old normal claim, consume the second allowance and
refuse an exhausted third attempt. Live writing/recovering owners block another
open before SQLite access; persistent lock-file inodes survive owner death.

## Real hot rollback journals

Merely creating a small rollback sidecar does not prove a hot journal. The
controlled `--spill-cache` mode lowers the real SQLite cache and, at a selected
pre-commit hook, adds an uncommitted synthetic table containing 128 KiB of zero
bytes. This test-only pressure forces real dirty-page spill; it never edits or
fabricates journal bytes and is absent from application code. Only a pre-commit
crash cut accepts this mode. The controller then kills the owner without commit.

The tests require a journal larger than 512 bytes with SQLite's valid header
magic and an actual database byte change. Only that tracked owner held the
transaction, and it has been killed and reaped. Wrong CPU, address-space and v3
probes retain exact database, checkpoint and journal bytes, and print no forbidden
connect marker. Matching selection permits SQLite rollback, then ordinary pair
validation and pending recovery. The uncommitted admission case restores the
exact previous database/checkpoint bytes. Result/recovery cases preserve the
charge as unknown and remove the rollback sidecar.

[SQLite's cache-spill documentation](https://www.sqlite.org/pragma.html#pragma_cache_spill)
describes dirty pages reaching the database during an unfinished transaction.
Its [rollback documentation](https://www.sqlite.org/lockingv3.html#the_rollback_journal)
and [journal format](https://www.sqlite.org/fileformat2.html#the_rollback_journal)
describe hot-journal recovery and the header checked by the fixture. These
official pages were inspected 2026-10-04; no external code was copied. The
recorded fixture readback/bytes and reopen outcome are implementation evidence;
the documentation alone is not execution evidence.

## Host and mathematical boundaries

Python discovery uses synthetic normal statements around real processes,
SQLite, advisory locks and files on Linux/macOS. On macOS only the v4 supported-host
selector is explicitly simulated in the parent and synthetic actor. This neither
launches a limited worker nor establishes Linux CPU/address-space enforcement.
The existing native resource cases still assert macOS refusal before creation.
Hosted unprivileged Linux executes the same cut matrix without host simulation.

The [actual v4 qualifier](../scripts/qualify_observation_resource_store.py) never
simulates its host. Two added test methods cover six actual result-publication
cuts and four recovery cuts after an actual interrupted recheck. A verified
adapter marker is mandatory before each work-related SIGKILL. Actual normal
retention, charged unknown, torn-pair quarantine, real hot-result-journal refusal
and no replay are checked separately. Every case preserves source journal state,
sequence, database and checkpoint bytes. See [validation](STAGE25_VALIDATION.md)
for local versus hosted execution; subcases are not separate top-level test counts.

## Decision and next gate

**Go:** review the exact v4 cut evidence, then qualify controlled write, sync and
replacement failures with precise poisoned-handle, quarantine, charge and slot
release expectations. Include uncertain outcomes; do not add implicit retry,
repair, migration or quota reset. Keep native execution and synthetic faults
separate from effective-resource or cryptographic claims.

**No-go:** policy rotation, a production swap client, live sources, private
signing, core activation, power-loss guarantees, clone/restore defense, aggregate
budgets, capability isolation, fairness or funded availability based on these
cuts. Acceptance after checkpoint replacement before directory sync proves only
the tested process-death behavior. The frozen 119-file review subject is unchanged
and independent assessment remains pending. No dependency or public upstream
communication is added.
