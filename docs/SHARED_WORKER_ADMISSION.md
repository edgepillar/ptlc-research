# Shared admission for owned observation workers

Status: **Stage 22 offline qualification of a finite shared lease pool. It
limits simultaneous admitted invocations among cooperating stores selecting
the same physical pool files. CPU/memory accounting, rate control, fairness,
host-wide enforcement and funded availability remain unresolved.**

Source parent: [`7e267e9bc71c3a6c7c72577bb9177b07f43ed9af`](https://github.com/edgepillar/ptlc-research/tree/7e267e9bc71c3a6c7c72577bb9177b07f43ed9af).
The [pool module](../offline_session/worker_pool.py) is separate from the
mathematical verifier, pure records, session journal and recovery admission.
The [owned store](OBSERVATION_STORE.md) now requires an explicit pool and uses
store version 3. The earlier [owner guard and leases](OBSERVATION_LEASES.md)
remain the lifetime mechanism; admitted work adds one slot reference.

## Requirements and construction

Per-history attempt quotas do not limit many independent histories executing
at once. An owner guard alone does not establish a shared work allowance. The
selected construction is a caller-provisioned pool of 1 through 16 private
slot files, each with one nonblocking exclusive advisory lock. Every managed
admitted invocation must hold one slot before pending persistence or launch.

| Requirement | Selected construction | Remaining boundary |
| --- | --- | --- |
| Finite simultaneous admission across different stores | All participating owners select the same physical slot files | Profile equality alone does not authenticate the directory or prevent another pool |
| Reject excess work before charging | Pure begin validates a prospective target; slot acquisition precedes the pending commit | Preflight/lookup/storage work is outside the slot bound; no CPU accounting |
| Retain capacity across owner/guard death | Owner, guard and cooperative worker share the admitted slot description | A live holder can occupy capacity indefinitely; explicit unlock or escape violates cooperation |
| Prevent managed reconfiguration | Fixed expected ID/count, canonical configuration and serialized open | Hostile rewrites, coherent clones and external administration remain outside trust |
| Bind store reopening to the selected policy | Store v3 checkpoints include the expected pool profile | Matching profile clones still pass; hashes provide consistency, not enrollment authority |
| Keep worker failure distinct from saturation | Busy before admission makes no attempt; unavailable admitted work remains charged unknown | Neither condition establishes a mathematical negative or funded availability |

This supplies no default production limit or enrollment service. A configured
pool is an explicit local choice. Legacy direct helpers and two-lease guarded
calls remain outside admission. Arbitrary callbacks cannot be substituted for
the store's selected adapter or exact pool type through the managed API.

## Pool configuration and ownership

`PublicWorkerPool.open(directory, pool_id_hex=..., slot_limit=...)` requires a
private local directory, a public 32-byte lowercase hex ID and a plain integer
count from 1 through 16. A nonblocking configuration lock serializes open and
first initialization. The dedicated directory contains only `pool.lock`,
`pool.json` and the configured `slot-N.lock` files. Configuration bytes are
exact compact canonical JSON with `version: 1`, `pool_id_hex` and `slot_limit`,
bounded at 512 bytes. The profile is SHA256 of domain
`PTLC/public-worker-pool/v1`, a NUL byte and those exact bytes.

First initialization creates and fsyncs the empty slot files, then writes and
fsyncs configuration and syncs the directory. Existing partial/missing state
quarantines; it is not automatically completed, reset or repaired. A missing
configuration lock in a nonempty pool is not recreated. Slots/configuration
must be private regular files owned by the effective user, with distinct file
identities; slots are empty. Unknown contents, final symlinks, malformed or
oversized configuration and wrong expected ID/count reject without migration.
This is process/filesystem qualification, not tested power-loss durability.

Open remembers configuration and slot identities. Admission checks current
inventory and exact bounded configuration, then validates a slot's identity
before attempting its lock. It neither creates a missing slot nor replaces a
changed one. The opening PID/thread binds the pool handle and each returned
lease. Foreign-thread or forked handles cannot acquire, obtain or close the
original owner's lease. A worker receives descriptor capabilities, never a
Python pool object, configuration path, database or checkpoint connection.

## Admission and durable ordering

`ObservationStore.open` requires `worker_pool` to be one exact selected pool.
Pool storage must be separate from the store directory and checkpoint, with
neither directory nested inside the other. Reopen checks the immutable expected
pool profile alongside existing ID, verifier profile, limits and record history.
The stored profile has a checked SQLite length of 64 before fetch, then must
equal the selected canonical hex digest. Checkpoints
include `worker_pool_profile_digest_hex` and use domain
`PTLC/observation-store-checkpoint/v3` followed by a NUL byte. Consistent v1/v2
pairs quarantine unchanged before old pending recovery; no migration is supplied.

After existing exhaustion/target/recheck checks, admission scans at most the
configured slots without waiting. No free slot raises `StoreBusy`, leaving the
pair, revision, allowance and history unchanged and invoking no worker. There
is no queue, automatic retry, token refund or fairness promise. Configuration
failure quarantines the handle before a pending charge. Retry is a new explicit
caller action when capacity becomes available.

The acquired slot is retained during pending commit, selected adapter work and
result commit. The store invokes only `observe_admitted`, which requires one
distinct private admission descriptor in addition to both ownership descriptors.
Missing/invalid admission never falls back to unadmitted guarded or legacy work.
The guard passes all three references to the selected cooperative nonforking
worker, with other inherited handles closed. Guarded input/output/deadline,
entry measurement, parent monitoring and exclusive child reaping keep their
earlier boundaries; the mathematical profile and schemas remain unchanged.

Normal completion or safe cancellation closes the owner's slot reference after
the result boundary. It never explicitly unlocks a shared description. Owner
death is monitored by the guard. Guard death can leave computation alive, yet
the cooperative worker retains both store ownership and shared capacity until
exit. Failed cleanup or an uninterruptible worker can keep that slot busy
indefinitely. Admission failure before pending commit launches no worker and
retains no charge; admitted unknown/cancellation keeps its charge.

Lookup and pending recovery require no new slot because they invoke no selected
worker. Store locks still exclude its prior cooperative worker before reopen.
Per-history attempt/target limits, conflict retention, one-sided restore checks
and matching-pair rollback limitations are unchanged.

## Evidence and negative boundary

Native tests hold two workers in different store processes under one two-slot
pool, reject a third before any pending charge, then require explicit retry
after one worker exits. Separate owner SIGKILL, guard SIGKILL and cancellation
tests check the slot's lifetime. A killed guard and closed owner do not allow
another store to reclaim the live worker's capacity. Synthetic actors establish
no signature validity; an actual Rust qualifier separately checks saturation
before work and a positive after explicit retry.

Two intentionally separate physical pools with the same public ID/count have
the same profile and independent capacity. A store accepts a matching profile
clone. These tested counterexamples mean configuration/profile binding is not
physical enrollment, anti-clone protection or a host-wide limit. All cooperating
callers must be externally configured to select the same actual files. A finite
live slot count also bounds neither cumulative verification nor each worker's
CPU, memory, filesystem/network behavior, preflight work or parent processes.

The lock/reference premise is attributed to [Linux flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html)
(man-pages 6.19, inspected 2026-10-04) and descriptor handoff to
[pinned CPython documentation](https://github.com/python/cpython/blob/de54cf5be371a6f5e2e9f208c38def5f81d3ef02/Doc/library/subprocess.rst).
Shared references release on last close; explicit unlock would affect the shared
lock. These are documentation premises, not portability or containment proof.
Native Linux/macOS execution must be reported separately. No external source
code was copied. See [Stage 22 validation](STAGE22_VALIDATION.md).

**Go:** assess this exact pool/guard/storage delta, then define CPU/memory,
cumulative rate/fairness and trusted shared enrollment independently. **No-go:**
treat it as funded recovery availability, authenticate a source/profile clone,
connect private signing or chain submission, port client admission into core or
activate PTLC. The 119-file frozen subject and pending independent review remain
unchanged; later deltas need their own exact assessment.

[Stage 23](WORKER_RESOURCE_LIMITS.md) separately qualifies explicit Linux CPU and
virtual-address-space caps before worker exec. The v3 owned store does not select
that experimental path or persist its profile. The pool's physical concurrency
scope and clone counterexamples remain unchanged; per-process maxima supply no
RSS accounting, cumulative rate, fairness, enrollment or funded availability.
