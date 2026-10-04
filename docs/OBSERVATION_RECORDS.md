# Bounded observation attempt and claim records

Status: **Stage 19 pure record contract and transitions. No owned disk backend,
durable evidence cache, observation source or recovery admission is connected.**

Source parent: [`5c47ac8e715a4902f337d3837512f6ad9dc9c4ff`](https://github.com/edgepillar/ptlc-research/tree/5c47ac8e715a4902f337d3837512f6ad9dc9c4ff).
[Stage 18](OBSERVATION_VERIFIER.md) supplies explicit local normal verdicts under
its trusted-host and caller-provisioned entry-file assumptions. A future store
needs a concrete distinction between attempted work, normal mathematical claims
and incomplete work before it can safely retain or reuse such results.

## Requirement, selected construction and evidence

| Requirement | Selected pure construction | Still required |
| --- | --- | --- |
| Charge work before invocation | `begin` returns a pending revision with consumed quota and monotonic attempt ID | Owned durable commit before any worker starts |
| Preserve exact normal results | Target/profile-bound claims retained in complete attempt history | Independently trusted producer and durable result-before-return ordering |
| Keep uncertainty separate | Pending attempt, explicit `unknown` finish, and earlier normal claims are distinct | Crash/ownership detection and exact recovery ordering |
| Retain contradictions | Both conflicting normal claims remain; lookup and further begin fail for that target | Investigation, profile/delta review and separately specified remediation |
| Bound one record history | Frozen managed limits of 1..64 attempts and 1..64 targets | Global admission, validation/measurement cost, concurrency and restored-copy policy |
| Validate serialized history | Canonical ASCII, exact fields and replayed begin/finish ordering | Authentic storage identity, anti-rollback and single-owner persistence |

The [module](../offline_session/observation_records.py) performs no file access,
worker invocation, arithmetic, source authentication or journal mutation. All
values are immutable canonical byte strings; every successful transition
returns another validated value. A returned pending value has no durability
until a future backend commits it under ownership. A byte roundtrip is not a
restart, power-loss or filesystem test.

## Record schema

`ptlc-observation-records-v1` is compact canonical ASCII JSON, without a trailing
LF, at most 1 MiB. The exact top-level fields are:

| Field | Meaning |
| --- | --- |
| `schema` | Fixed record schema |
| `verifier_profile_digest_hex` | One explicit local profile for this history |
| `attempt_limit` | Plain integer from 1 through 64 |
| `target_limit` | Plain integer from 1 through 64 |
| `revision` | Number of begin and finish transitions |
| `targets` | Map from exact evidence key to fixed statement fields |
| `attempts` | Ordered list of never-removed attempts |

Limits and profile stay unchanged through every managed transition. Pending,
unknown, positive, negative and conflicting attempts all consume the same finite
attempt quota; nothing refunds it. Targets remain present after completion and
unknown work, with no eviction, reset, pruning or replacement method. Creating
another history or coherently restoring an older value is outside that scope.
The public profile argument must match the recorded profile; a response or
serialized value cannot select the caller's expectation.

Each target contains the six fixed [Stage 17 statement fields](OBSERVATION_EVIDENCE_CONTRACT.md)
other than `outcome`: schema, predicate, binding digest, evidence key, verifier
profile and request digest. Digests are plain lowercase 32-byte hex. The key
is recomputed from binding digest, predicate and local profile under the existing
evidence-key domain. Target fields commit to the complete Stage 17 target; raw
candidate/request bytes and their source evidence are not stored in this format.
Fresh local target reconstruction remains required on begin, finish and lookup.

Each attempt has exactly `id`, `evidence_key_hex`, `recheck`, `started_revision`,
`finished_revision` and `outcome`. IDs are plain integers starting at one, with
no gaps or reuse. `recheck` is a plain Boolean. A pending attempt has null finish
revision and outcome; a finished attempt has a later finish revision and exactly
one of `verified`, `rejected` or `unknown`. There is no error, stderr, source,
authority, timestamp, hostname or private environment field.

Every revision from one through the declared current revision must occur exactly
once as a begin or finish event. Starts increase with IDs; finishes can occur in
another order for distinct targets. Loading replays all events and rejects
overlapping pending work for one key, finish-before-begin, missing/duplicate
revisions, a recheck without a prior normal claim, an implicit retry of a normal
claim, any begin after conflicting normal claims, or an unreferenced target.
Plausible final counters alone are insufficient to accept an unreachable history.

## Managed operations and claim selection

| Operation | Result |
| --- | --- |
| `create` | Empty bounded canonical value; no persistent ownership epoch |
| `inspect` | Immutable counts/revision summary of structurally accepted claims |
| `begin` | New charged pending value and attempt ID; no worker starts |
| `finish` | Exact bound locally supplied statement finishes that pending attempt |
| `interrupt` | Owning caller explicitly finishes pending work as unknown |
| `known_statement` | Exact sole normal claim, None for no normal claim, or conflict error |

`begin` checks exhausted attempt quota before reconstructing a target. A new key
also needs an available target slot. A key with pending work raises `RecordBusy`.
A key with one normal claim raises `RecordKnown` unless the caller explicitly
selects `recheck=True`; that choice is only supported for a prior normal claim.
This caller option is not source authorization or recovery admission.

`finish` validates the existing statement against fresh local state/signature and
the expected local profile, then checks its exact target against the pending
attempt. A malformed or cross-target result raises `RecordError` and leaves the
original pending value charged. Its owning caller must later commit an explicit
unknown transition if no reliable result is available. A late or repeated finish
or interruption of a closed attempt raises `RecordClosed`.

An unknown retry is a new charged attempt. A pending/unknown recheck cannot erase
an earlier unchanged normal claim. A repeated equal normal decision retains both
charged attempts and yields one normal claim. Contradictory positive/negative
claims retain both records and yield `RecordConflict`, with no selected normal
statement or further attempt for that key. Other keys retain their own history.
There is no remediation or conflict-reset method.

The predicate is fixed mathematical input validity, not a changing chain fact.
Its evidence key excludes source labels and observation history deliberately;
retained-candidate comparison and per-candidate authority still belong to a
future owned application and the unchanged recovery journal. A normal lookup
does not produce a Bitcoin signature, archive/replace an observation or spend or
replenish Bob's recovery allowance. Lookup remains possible after this record's
attempt quota is exhausted, subject to exact local binding and conflict checks.

## Trust, rollback and resource boundaries

The module authenticates neither statements nor stored bytes. A peer can forge
a perfectly matching claim, including `verified` for invalid fixture bytes.
Tests intentionally show that this becomes a structurally accepted claim. The
future owner must obtain a result from its independently trusted selected local
producer; it must not import peer claims as cached truth. `inspect` counts claims
without reconstructing target artifacts or establishing their mathematical truth.

Canonical bytes, hashes, event replay and a locally supplied profile establish
structure and identity only. Restoring an earlier valid byte value demonstrably
replenishes pure quota and permits another ID-one attempt. These transitions
cannot detect a stale writer, concurrent owner, coherent rewrite or restored
copy. Serializing state to a file, even with atomic rename, cannot supply those
properties by itself. No rollback, filesystem or process ownership protection
is claimed at this stage.

The quotas count only admitted attempts/targets within one retained history.
Target validation, record parsing, lookup, file measurement, new histories,
different profiles, outside helpers, CPU/memory use and worker containment are
separate resource obligations. Repeated unknown work still drains finite quota;
many different valid-shaped targets can drain target slots. Retaining a normal
negative may avoid repeating that exact work in a future cache, but is not a
funded-availability or global denial-of-service guarantee.

## Required owned-backend ordering

These are requirements for the next implementation, not observed behavior here:

1. Acquire exclusive cooperating-process and thread ownership before loading
   state and independent checkpoint, retaining it through commit, worker lifetime,
   result commit and return. Atomic rename alone cannot prevent stale-writer loss.
2. Freeze expected profile, limits and storage identity. Validate the complete
   canonical record history and checkpoint before exposing any retained claim.
3. Durably commit charged pending bytes before invocation. Failed or ambiguous
   admission persistence permits no worker and no quota reset or replacement.
4. Commit a normal/unknown result before exposing it. Interruption after admission
   retains the charge; missing result is not a mathematical negative. A crash
   after worker success but before durable result commit remains unknown.
5. Reopen only after excluding prior live/stale owners and workers. Recover pending
   attempts as explicit unknown without deleting earlier normal claims. Database
   and independent checkpoint divergence must fail closed; partial writes are
   not permission to replay a callback.
6. Exercise death before/after both persistence boundaries, worker cancellation,
   concurrent owners, stale writers, one-sided restore and paired restore. State
   the paired-restore limitation honestly and define any external trust anchor
   separately. Do not silently convert local consistency into anti-clone evidence.

Existing recovery-journal schema, allowances and callbacks remain unchanged. The
new record contract is a separate client surface, outside the frozen Stage 12
review subject. It needs its own producer, record-policy and backend delta
assessment before any funded recovery policy is connected.

**Go:** implement and qualify a separately owned offline backend against these
exact transition and failure rules, then review aggregate resources and source
authority independently. **No-go:** call these bytes durable evidence, promote a
received claim to trust, infer rejection from unknown work, bypass journal
exhaustion or claim live-swap/core readiness. See [validation](STAGE19_VALIDATION.md).

[Stage 20](OBSERVATION_STORE.md) now implements a separate owned offline disk
backend around these unchanged pure transitions. It qualifies managed record
publication and commit ordering, not containment of a worker orphaned by owner
death. That stronger lifetime/resource requirement, paired-restore protection,
source authority and any funded admission policy remain explicit open gates.
