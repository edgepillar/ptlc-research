# Separately owned offline observation records

Status: **Stage 21 local SQLite/checkpoint ownership with worker-held leases, separate
from recovery admission. No chain source, private signer or funded policy is
connected. Arbitrary process containment and paired-restore protection remain open.**

Original Stage 20 source parent: [`eda29365089ebf99008e779afaffbcbc3299015c`](https://github.com/edgepillar/ptlc-research/tree/eda29365089ebf99008e779afaffbcbc3299015c).
The [Stage 21 lease design](OBSERVATION_LEASES.md) identifies the current source
parent and supervision boundary.
The [pure record contract](OBSERVATION_RECORDS.md) and
[selected mathematical profile/predicate](OBSERVATION_VERIFIER.md) remain unchanged. The separate
[module](../offline_session/observation_store.py) supplies local record ownership
and ordering around those two surfaces. It imports no signing implementation and
accepts no incoming statement or arbitrary verification callback.

## Requirements, construction and observed evidence

| Requirement | Selected local construction | Evidence and remaining boundary |
| --- | --- | --- |
| Prevent cooperating stale writers | Two lifetime advisory locks, before SQLite/checkpoint load, owned by the opening PID and thread object | Native concurrent-owner, foreign-thread, fork and owner-death tests; trusted local filesystem and cooperating writers only |
| Charge before work | Commit pending records using SQLite DELETE/FULL, then file fsync, checkpoint replacement and directory fsync before calling the selected adapter | Real SIGKILL boundary matrix; failed or uncertain admission invokes no worker |
| Commit before returning a result | Append exact normal/unknown finish and checkpoint before return | Synthetic boundaries plus actual Rust result-loss and restart tests; power loss is not exercised |
| Recover unfinished publication | A separately successful locked reopen commits pending work as unknown, retaining its charge and earlier normal claims | No replayed worker; cooperative live holders exclude reopen even after guard death |
| Detect inconsistent storage | Expected public store ID, profile/limits, bounded canonical history, and exact database/checkpoint pair | Wrong config, corruption, missing half and one-sided restore quarantine; matching old pairs and coherent rewrites remain indistinguishable |
| Keep recovery authority separate | No session-journal reference, output signer, reconciliation call or source input | Actual positive leaves an exhausted reopened journal's exact state and bytes unchanged |

The current owner conditionally meets the
[Stage 19 worker-lifetime requirement](OBSERVATION_RECORDS.md#required-owned-backend-ordering)
for a selected cooperative nonforking worker. An internal guard watches owner
death; the guard and worker retain both lock references. A killed guard can leave
computing work alive, but those references block a new owner until exit. Workers
receive public request bytes and lock capabilities, never a database/checkpoint
handle; only the synchronous owner commits a result. Malicious/escaped workers,
uninterruptible tasks and aggregate resource admission remain outside this
construction. A dead/inherited caller cannot publish through the managed API.

## Local ownership and configuration

`ObservationStore.open` requires a private directory, a checkpoint path outside
that directory, a caller-assigned `store_id_hex`, one exact
`SubprocessObservation` instance, and plain integer attempt/target limits of
1 through 64. The public 32-byte store ID is a namespace expectation, never a
secret, MAC, trusted monotonic counter or anti-clone anchor. Reopen requires the
same expected ID, profile and limits. No import, reset, eviction, pruning,
profile rotation or pair-repair API exists.

The selected adapter's constructor already requires an explicitly provisioned
entry-file hash. Its profile excludes a runtime deadline: different deadlines
for the same selected predicate/entry can reopen the same history. This is not
source/build attestation or an aggregate-time budget. Runtime entry measurement
and launch have the unchanged trusted-host gap described in Stage 18.

`observations.lock` and the separate checkpoint's `.lock` file are opened as
private regular files without following their final symlinks, then locked
exclusively and nonblocking. Managed code never unlinks/replaces these lock
files. Both locks are held throughout the handle lifetime, including known-claim
lookup, work, commits and return. Another checkpoint cannot bypass the database
lock; another database cannot bypass the checkpoint lock. A failed second lock
releases the first without reading or creating the database.

The opening PID and `threading.current_thread()` object must remain identical.
Foreign threads and forked handles cannot inspect, mutate or close the store.
Their cleanup cannot unlock the original owner's shared file description.
Public reads, mutations and close reject reentrancy while an observation is
active. Independent handles must acquire the same locks. Inherited descriptors
can delay ownership release; locks establish exclusion, not a liveness promise.

The implementation supports local Linux/macOS POSIX hosts. It does not establish
network-filesystem lock behavior, hostile directory integrity, equal-privilege
attacker resistance or Windows support. Trusted callers must not unlink locks,
rewrite live files, tamper with the Python objects, independently reap worker
children, or give a worker storage credentials/capabilities outside this API.
Diagnostic hooks are trusted local test instrumentation, never peer-controlled.

## Storage pair and validation

The private directory contains `observations.sqlite3`. One `checkpoint` row has
exactly the selected version 2, slot one, expected store ID, record revision,
bounded canonical record bytes and checkpoint digest. Before fetching a record
BLOB, load checks its SQLite length against the existing 1 MiB record limit and
reads at most two metadata rows. Database and rollback-journal files have an
8 MiB local size cap; checkpoints have a 1024-byte cap. Unsupported WAL/SHM
sidecars, symlinks, nonregular or nonprivate files are rejected. SQLite opens
only an existing `mode=rw` path, after ownership, with DELETE journal mode,
FULL synchronous mode and a checked quick-check result.

The separate checkpoint is exact compact ASCII JSON with no trailing LF:
`version`, `store_id_hex`, `revision`, `records_digest_hex`, `digest_hex`.
The records digest is SHA256 of the exact canonical record bytes. The outer
digest is SHA256 of the first four canonical fields under
`PTLC/observation-store-checkpoint/v2` followed by a NUL byte. These hashes are
consistency commitments, not authenticators. Record limits, profile, complete
transition replay and at most one pending attempt are validated before a claim
is exposed or pending publication recovered. This synchronous backend does not
produce parallel pending attempts.

A missing pair half is never reinitialized. A divergent pair is quarantined
without selecting whichever copy appears newer or replaying work. The separate
checkpoint is a logically distinct local file; physical storage independence or
an external trusted anchor is not established. A consistent v1 pair, including
pending work, is quarantined unchanged; no automatic migration or old-work
recovery is performed. Existing unleased work cannot be retroactively excluded.

## Admission, result and interrupted publication

`observe(state, signature, recheck=False)` takes a private copy of the local
public snapshot. Exhausted attempt quota rejects before target preparation.
The unchanged pure begin validates the target/recheck choice and produces a
charged pending revision. That revision is committed to SQLite first, then to
the separately fsynced/replaced checkpoint, with a directory fsync before work.
The selected adapter's explicit owned method is called only after those
operations return successfully. It passes exactly the two held lock descriptors
through the guard to the cooperative worker, with no invalid-lease fallback to
legacy transport. The owner releases only its references by closing them; an
explicit shared LOCK_UN would release a still-live worker's exclusion.

The returned statement must finish that exact target and profile. A malformed
or cross-target return becomes an explicitly charged unknown, never a normal
negative. Unexpected ordinary worker exceptions also become unknown without
retaining their diagnostics. BaseException cancellation is committed unknown
before propagation if persistence succeeds. A result persistence failure
instead raises a sanitized quarantine error and exposes no claim.

Only a successful result commit allows a statement to return. A contradictory
normal result is committed, retaining both attempts, before `RecordConflict`
is raised. No normal statement is selected for a conflicting target and no
further attempt for that key is admitted. Unknown/pending rechecks preserve an
earlier unchanged normal. Explicit retries consume new quota; there is no retry
loop, refund or worker invocation during lookup/reopen.

Any interrupted/uncertain storage operation poisons the handle. It can be
closed by its owner but cannot inspect, retry or expose a retained claim. A
separately successful locked reopen first validates both files. Matching pending
records become unknown under ownership and are committed before open returns.
The guarded worker's live references block that ownership acquisition before
SQLite access, including after its guard dies. Owner-death monitoring and
descriptor cooperation are specified in the [lease design](OBSERVATION_LEASES.md).
If that recovery commit leaves a database/checkpoint gap, reopen quarantines too.

## Tested crash boundaries and restore limits

| Owner killed at | Reopen result | Worker calls in synthetic matrix |
| --- | --- | --- |
| Before admission database commit | Rolled-back prior state; no charged work | 0 |
| After admission database commit, before checkpoint replacement | Quarantined pair | 0 |
| After admission checkpoint replacement/commit or pending commit | One charged unknown | 0 |
| After worker return or before result database commit | One charged unknown | 1 |
| After result database commit, before checkpoint replacement | Quarantined pair | 1 |
| After result checkpoint replacement/commit or final commit | Retained exact normal | 1 |

The matrix kills real owner processes with SIGKILL and uses clearly labeled
synthetic normal claims. A separate actual qualifier kills an owner after its
selected Rust worker returns, before result persistence, and verifies charged
unknown recovery without replay. Its marker requires the actual adapter's
`verified` outcome before the kill. SIGKILL preserves the host/storage process;
it is not a power cut. Acceptance after checkpoint replacement before directory
sync in that matrix establishes only this tested process-death boundary.

One-sided old restores fail closed in either direction. Restoring both matching
old files demonstrably replenishes quota and permits another worker call.
Coherently rewriting both files under the same public ID/profile is likewise
outside the trust boundary. New directories, IDs, profiles and histories can
bypass per-history limits. No global CPU, memory, process, session or
verification-resource defense is supplied by these quotas.

**Go:** assess this exact storage/producer delta and specify aggregate admission,
arbitrary worker containment, source authority and external restore handling separately.
**No-go:** connect these retained claims as a funded recovery guarantee, bypass
journal exhaustion, infer a chain fact from a mathematical verdict, introduce
private signing, port the client store into core or activate PTLC. The frozen
Stage 12 review subject and pending independent assessment remain unchanged.
See [Stage 20 historical validation](STAGE20_VALIDATION.md) and
[Stage 21 current validation](STAGE21_VALIDATION.md).
