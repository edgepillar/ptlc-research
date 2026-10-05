# Local source read snapshot and use ordering

Status: **Offline local qualification only. No authenticated source, signed live
response, application admission, external lineage service or physical-use fence.**

This Stage 45 delta follows `b4dbd200e185093b5cb0e521f27c749387d5f11d` and qualifies
one owned SQLite read snapshot using the unchanged
[Stage 41 synthetic store](OFFLINE_POLICY_EFFECT_STORE.md) and
[Stage 44 unsigned response construction](SOURCE_RESPONSE_SIGNATURE_QUALIFICATION.md).
The new [experiment](../qualification/source_read_ordering.py) is imported only
by its qualification tests and synthetic native actor. It does not connect a
historical signature check to a source service or existing application runner.

## Requirements, selected construction and observed behavior

Protocol requirements remain independently authenticated source/root/role
provisioning, a complete current policy decision at a selected cutoff, original
operation identity, retained charge lineage, compromise recovery and an explicit
protected-use definition. A successful local read does not supply these facts.

The selected local construction is `BEGIN IMMEDIATE` over the existing owned
SQLite database. One transaction validates the complete stored history, selects
the complete current policy and matches the independently prepared checkpoint
query. It creates an unsigned diagnostic response and reads the original
operation record while that transaction excludes other managed writers. The
read linearization point is completion of that snapshot under the transaction
lock; a successful return follows `COMMIT`. A policy mutation may commit after
that lock is released and before the caller receives the old active response.

Observed behavior is limited to [27 directed tests](../tests/test_source_read_ordering.py),
including four groups using real processes, SQLite contention and process death.
The [validation record](STAGE45_VALIDATION.md) separates local runs from hosted
Linux/macOS Python execution and unchanged cryptographic qualification. Neither
these tests nor the earlier finite schedule model prove a replacement protocol.

## Complete checkpoint and query binding

The local checkpoint digest covers a distinct domain,
`PTLC/offline-local-policy-read-state/v1` with a NUL suffix, and the complete
selected root declaration, local revision, complete canonical fourteen-field
profile, active status and source mode. The root includes the complete source
context, source incarnation/profile pin, resource/authority namespace, five role
encodings and selected declaration revision. The digest is a fingerprint of
these local bytes, not authentication or a nonrollbackable head certificate.

`local_checkpoint` is an operator diagnostic for preparing a synthetic test
query. Its transaction is separate from `sample_original`. An intervening
policy or mode change makes an old query refuse even if its challenge is new.
A source-mode change changes the digest even without changing the policy revision.
Charges and synthetic effects do not change the policy-head digest. They change
the original-record/event diagnostics that accompany a later sample.

The retained query validates the complete governor packet, decoded scope and
resource, source context, selected checkpoint and challenge. Its profile must
exactly match the selected root and complete local profile. No cap attenuation
or administrator authority is inferred from a root's cap ceiling. The inherited
profile grammar is not curve checking, signature verification or operational
provisioning.

A live local policy produces an unsigned `active` or `revoked` claim.
`unavailable` produces no asserted assignment/checkpoint in the claim. Ambiguity
and detected compromise refuse. Detection of compromise is an operator premise.
There is always one retained policy row in this construction; an `absent` read
is not implemented. The separate historical worker retains all four observation
forms and its original tests. No successful unavailable read authorizes work.

## Original request association and no-refund accounting

A sample associates the complete original operation id, revision, profile bytes
and proposal digest with the complete response and any matching original charge
or effect record. Colliding original ids with changed complete requests refuse.
An uncharged request must match the current complete local snapshot. An already
charged original can be inspected after revocation without being rebound to the
new revision and without refund. The read itself creates no operation, charge,
effect, event, durable read receipt or deduplication record.

The local sample digest uses `PTLC/offline-local-original-read-sample/v1` with a
NUL suffix and binds the complete selected root, original request, response,
event sequence and original charge/effect sequence. It is unsigned. In
particular, the existing historical response schema does **not** sign this
original operation/proposal association. Two original requests can have the same
historical response bytes and different local sample digests. They are not
cryptographic original-operation receipts. A future authenticated original-read
contract needs an independently selected schema, namespace and assessment.

A lost sample return is an unknown read. Repeating the same original request
against an unchanged source can reproduce the diagnostic; it is not proof of
what the earlier attempt observed. A policy change can instead make that same
old query refuse. Reconcile the retained original operation, prepare a separately
selected new checkpoint query where allowed, and retain its original charge.
There is no automatic replacement id, refund or inferred absence after loss.
An unavailable sample can still show a locally retained original record as a
diagnostic. This is not an authoritative source lookup or reconciliation of an
unknown remote outcome; the existing allocation/effect paths still require live
local mode. No application may use this diagnostic as an availability fallback.

## Read, synthetic commit and physical use remain separate

| Boundary | Executed local rule | Evidence limit |
| --- | --- | --- |
| Read sample | Complete snapshot under `BEGIN IMMEDIATE`; return after commit | Local byte/history consistency only; response can age before return |
| New synthetic allocation | Existing atomic current revision/profile check and original charge record | Owned local database; no authenticated allocation service |
| Synthetic effect commit | Existing current revision/profile check, original record and effect row in one commit | A row is the entire protected effect in this experiment |
| Physical entry | No implementation | A committed effect row cannot fence later external actuation |

Revocation after a read but before allocation prevents a new local charge.
Revocation after a charge but before the synthetic effect prevents that effect
and retains the charge. A previously committed effect can still be reconciled
after revocation. A deliberately blind ideal actuator can act on that historical
record after revocation; this unsafe control is a list event, not a real worker.
The read cannot extend the database transaction lock across physical use.

The separate [Stage 40 model](POLICY_SOURCE_USE_MODEL.md) retains conditional
commit-versus-entry cutoff comparisons. This local experiment selects neither
for production and implements no dispatcher, worker fence or exactly-once
physical actuation. The tests use a no-op store crash hook, never an application
callback or signing hook.

## Explicit unsafe and recovery controls

- A freshly challenged stale active claim can still be constructed outside this
  reader. The unchanged historical worker separately verifies the corresponding
  synthetic signed vectors; historical math is not a current read.
- An exact local reader refuses an old checkpoint after managed revocation. A
  coherent old database restore, however, restores the accepted checkpoint and
  can repeat the same read, original charge and synthetic effect.
- Coherent database copies have independent local caps under identical labels.
  Client-only restore does not rewind an independently retained source history.
- The four stored source labels are matched, but the root key and opaque source
  profile pin are independently selected operator premises. An all-ff root
  encoding and arbitrary profile pin can produce an unsigned local active claim.
  This explicit control prevents a claim of authenticated SQLite or curve checks.
- Five distinct role encodings do not prove independent key custody. The earlier
  malicious selected-verifier control remains in the unchanged signature suites;
  the new reader invokes no verifier callback and cannot repair that trust gap.

An ideal external audit list exposes repeated original operations across a
coherent source restore. This list is intentionally not rewound in the test and
is **not** an implemented durable lineage mechanism. A real design would have
to preserve, outside a restorable/clonable source and under independently
assessed authority, at least the retained resource/authority namespace, source
incarnation and authorized transitions, complete original request identity,
charge consumption and committed protected-effect/entry history. Its retention,
atomic updates, conflict handling and disaster recovery cannot be derived from
this local database or its hash. Trusted current authentication alone is also
insufficient for that nonrollback requirement.

## SQLite connection lifecycle follow-up

Stage 44's Python 3.13 logs reported unclosed-connection warnings at garbage
collection sites. Those sites were not allocation evidence. A separate local
trace, using the real driver's connection subclass and explicit close tracking,
ran 147 inherited tests and observed 300 allocations. Ten test methods accounted
for 22 allocations left unclosed at eleven test-only `with sqlite3.connect(...)`
sites. The traced journal, observation store and policy-effect store connections
closed; production/reference store logic is unchanged.

The five affected test modules now retain the connection's transaction context
inside `contextlib.closing`, so successful writes still commit and failed writes
still roll back before the connection closes. The same 147-test trace then
observed all 300 allocations closed. No warning filter or suppression was added.
This local trace used Python 3.9.6; it is not a Python 3.13 warning reproduction.
Hosted Python 3.13 full-log inspection is required separately.

Python documents that the connection context handles transactions and leaves
connection closure to the caller, and that Python 3.13 reports a connection
that is deleted without `close`. The documentation reference is pinned to
[CPython v3.13.0 commit `60403a5409ff2c3f3b07dd2ca91a7a3e096839c7`](https://github.com/python/cpython/blob/60403a5409ff2c3f3b07dd2ca91a7a3e096839c7/Doc/library/sqlite3.rst).
No third-party implementation, passage or test vector is copied. New experiment
code is original project MIT material; dependencies remain unchanged.

## Remaining gates

An actual authenticated current-source service, operational root/response key
custody, atomic original administrator-command commit/deduplication, external
nonrollback lineage, compromise/revocation recovery and protected physical-entry
fencing remain separate unimplemented gates. Both fixed review inventories and
unfilled reports are unchanged; the later delta requires independent assessment.

Offline qualification is **GO**. Source integration, application signing, core
port, activation, deployment, wallet access, broadcasts and real funds remain
**NO-GO**.
