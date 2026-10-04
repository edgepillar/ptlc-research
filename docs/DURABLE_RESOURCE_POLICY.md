# Durable explicit worker resource selection

Status: **Stage 24 offline Linux v4 policy continuity. No signer, chain source,
recovery-admission rule or funded availability policy is connected.**

Source parent: [`c0fcec8828c8506e61b3d5da0c412a18f43d1845`](https://github.com/edgepillar/ptlc-research/tree/c0fcec8828c8506e61b3d5da0c412a18f43d1845).
The [Stage 23 construction](WORKER_RESOURCE_LIMITS.md) supplies the explicit
per-process Linux installer. This stage selects it through a separate owned
[store entry](../offline_session/observation_store.py), preserving the
[pure record contract](OBSERVATION_RECORDS.md), mathematical profile and pool.

## Requirements and selected construction

| Requirement | Construction | Remaining boundary |
| --- | --- | --- |
| Require an explicit runtime choice | `ObservationStore.open_limited` requires `resource_limits` and unprivileged supported Linux | No production defaults, trusted enrollment or privilege isolation |
| Retain the same requested CPU/address-space policy | Store v4 binds the resource profile in SQLite and the separate checkpoint | Profile commits to requested maxima, not actual usage or effective inherited values |
| Reject a changed choice before recovery | Bounded checkpoint mode/profile selection is checked before SQLite connect, then the complete pair before record recovery | Checkpoint consistency authenticates no host or storage |
| Preserve ordinary work | `ObservationStore.open` remains v3; neither entry upgrades or downgrades an existing pair | Migration, rotation and quota resets remain absent |
| Charge before limited work | Shared slot and durable v4 pending precede `observe_limited` | Caller/guard/bootstrap resources remain outside selected caps |
| Preserve unknown/error partition | Resource failure after admission is charged unknown, never an ordinary-work fallback | A mathematical negative still requires the unchanged exact normal result |
| Preserve cooperative lifetime exclusion | Both ownership references and the acquired slot survive selected exec | Trusted nonforking worker, local filesystem and exclusive child reaping remain premises |

## Explicit selection and storage identity

Callers must supply the same exact `WorkerResourceLimits` construction used in
Stage 23: a plain integer CPU maximum from 1 through 30 seconds and virtual
address space from 64 MiB through 1 GiB. Its canonical profile also fixes the
Linux installer implementation and disabled core dumps. Missing policy, an
unsupported host, root or invalid construction refuses before store filesystem
creation or worker launch. A nonzero UID still does not prove absence of
hard-limit-raising capabilities; the selected worker and runtime remain trusted.

The ordinary v3 API remains available on Linux/macOS and selects admitted work.
The separate v4 API is Linux-only and always selects limited work. An existing
v3 pair cannot acquire v4 semantics implicitly, and a v4 pair cannot reopen
through the v3 API. A different requested CPU or address-space maximum requires
separate design and review; there is no profile-change or migration API.

| Surface | Ordinary v3 | Explicit limited v4 |
| --- | --- | --- |
| SQLite version | `3` | `4` |
| Pool profile | Existing `worker_pool_profile` | Identical existing pool profile |
| Resource profile | No column | Required `worker_resource_profile`, length 64 before fetch |
| Checkpoint resource field | Absent | `worker_resource_profile_digest_hex` |
| Checkpoint hash domain | `PTLC/observation-store-checkpoint/v3` + NUL | `PTLC/observation-store-checkpoint/v4` + NUL |
| Worker method | `observe_admitted` | `observe_limited` with the explicitly supplied policy |

The v4 checkpoint includes its version, store ID, revision, records digest, pool
profile and resource profile in the canonical domain-separated digest. The
existing 1024-byte checkpoint and 8 MiB database caps are unchanged. Pure record
bytes and mathematical statements contain no new field. The selected predicate,
entry-file measurement, request/result schemas and cryptographic sources are
unchanged. A runtime deadline remains outside both mathematical identity and
the CPU/address-space profile; this stage adds no hard wall-clock guarantee.

## Opening, work and interrupted publication

1. Validate the explicit policy and existing store/pool configuration.
2. Acquire both lifetime locks before loading the pair.
3. For an existing pair, read the bounded checkpoint mode/resource choice before
   SQLite can recover a rollback journal. This preflight selects no trusted state.
4. Check the complete canonical database/checkpoint pair, expected profiles,
   record history and limits before exposing claims or interrupting pending work.
5. Recover matched pending publication as charged unknown without a worker.

Every public read/work call checks the live policy against the captured resource
profile. Before work, the unchanged pure begin prepares a prospective pending
revision; shared saturation writes nothing, charges nothing and launches nothing.
Once a slot is acquired, pending is committed to both v4 files before limited
dispatch. The policy is checked again immediately before that dispatch. A policy
change at the post-admission boundary causes charged unknown with no worker or
fallback, retaining the originally selected checkpoint profile.

The selected child uses the Stage 23 installer/readback/exec path. Parent, guard
and interpreter/module bootstrap are outside those installed limits. The guard
and worker retain both lock descriptions and the shared slot. A killed guard
can leave computation alive, retaining exclusion until worker exit. Only the
owned synchronous publisher receives and commits a result.

Normal verified/rejected results use the same mathematical statement and pure
records. Worker errors, malformed returns and unavailable admitted work are
unknown; cancellation commits unknown before propagation if storage succeeds.
Conflicts remain retained without selecting a normal claim. Interrupted storage
poisons the handle; torn pairs quarantine without repair, quota refund or replay.
Policy mismatch is rejected before pending recovery, including when a private
rollback sidecar is present.

[SQLite's rollback documentation](https://www.sqlite.org/lockingv3.html)
(inspected 2026-10-04) describes hot-journal recovery before a database read.
That premise motivates selection before SQLite access; it does not establish
host/storage authenticity. No external source code is copied.

## Evidence and next gates

[Synthetic continuity tests](../tests/test_observation_resource_store.py) use
simulated supported-host selection and mocked mathematical outcomes around real
SQLite and locks. They cover unchanged reopen, cross-mode/policy refusal, bounded
metadata, pre-SQLite selection, admission ordering, conflicts, charged unknown
and uncertain persistence. They establish no signature truth or Linux cap.

[Native lifecycle cases](../tests/test_observation_resource_store_native.py)
separately require Linux mapping/CPU behavior, three inherited references,
owner-death pending recovery, guard-loss exclusion and cancellation cleanup.
Other hosts assert refusal before creation, never a skipped enforcement success.
The [actual Rust qualifier](../scripts/qualify_observation_resource_store.py)
checks normal results, cached reopen, mismatch/downgrade/unsupported refusal,
saturation and actual returned-result loss while preserving journal bytes.
See [Stage 24 validation](STAGE24_VALIDATION.md) for executed versus pending gates.

**Go:** assess this exact v4 selection delta, then qualify real process-death cuts
through every v4 database/checkpoint write and recovery boundary. The inherited
v3 SIGKILL matrix and v4 synthetic hooks do not establish that full v4 matrix.
**No-go:** claim RSS or aggregate budgets, process-tree/capability containment,
fairness, trusted enrollment, paired-restore/clone defense, power-loss safety,
funded recovery availability, private signing or core activation.

Matching old pairs, coherent rewrites, new histories and matching-profile pool
clones retain their existing bypasses. Resource profile equality supplies no
source authority, monotonic anchor or runtime attestation. The frozen 119-file
review subject remains unchanged; this later delta requires separate independent
assessment, which remains pending. No external source code or dependency is added.
