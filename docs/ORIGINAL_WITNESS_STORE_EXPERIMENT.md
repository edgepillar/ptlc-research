# Test-only owned original witness transaction

## Requirements and selected experiment

Retaining a completed original requires comparing an incoming complete history
with the persisted consumer witness before replacing it. A separately acquired
read and later atomic rename can allow a stale writer to erase intervening
knowledge. The Stage 54 model assumed an atomic comparison/retention event;
this experiment tests one bounded realization of that assumption.

This is **test-only SQLite storage** in
[the isolated helper](../tests/original_witness_store.py), outside application
modules and both fixed review subjects. It does not select an application
backend, a source of canonical heads, a production durability construction or
an authenticated recovery protocol. All records, signatures and effects come
from existing public synthetic fixtures; no signing operation or key material
is added.

## Owned transaction and complete binding

The caller independently selects one exact Root/original query before peer
bytes. The file binds the complete canonical Root and complete original tuple.
Each supplied query is reconstructed against those independently retained
objects and checked against its complete canonical wire. Root, profile,
incarnation, revision and proposal migration are outside this API.

The helper owns one SQLite connection on one process and thread. Closed,
foreign-PID, foreign-thread and reentrant handles refuse. The selected directory,
pathname, SQLite/VFS and runtime are external ownership premises. Rejecting a
direct symlink does not defend against an adversary replacing ancestors, file
aliases or the opened file. This is not a sandbox.

Each retention executes these steps without releasing the SQLite writer lock:

1. Acquire `BEGIN IMMEDIATE` with a zero busy timeout.
2. Validate the exact schema, complete binding, native settings and bounded row
   shape; load the latest persisted witness rather than a cached scalar.
3. Reconstruct the stored query and complete opening. Compare stored and
   incoming histories with the unchanged signed-prefix composition. Both
   complete packets are framed before either selected public check.
4. Replace the sole witness row, validate the structural state and commit.
5. Return an unsigned frozen scalar description only after commit.

An empty store compares the incoming witness with itself; it has no prior
knowledge to reject a valid historical first choice. Opening a nonempty file
validates structural bindings and its complete opening, but does not verify
stored signatures until inspection or retention. Neither opening nor the
scalar result authenticates the store or discovers a current source head.

The unchanged opening/prefix helpers preserve all earlier charges, exact
original tuples and completed effects. A pending original may gain its effect
after the retained head. Incomparable futures and delayed older histories
refuse. No Root migration, witness eviction or automatic retry is provided.

## Bounds and failure semantics

There is one binding row and at most one complete witness row. Query and public
response wires are at most 16384 bytes each; an opening is at most 262144 bytes.
Existing opening bounds remain 32 revisions, 256 events and 64 originals.
Lengths and SQLite storage types are checked before fetching witness blobs.
At most 64 successful retention calls are allowed, including identical
redelivery or a fresh challenge over the same history. Reaching the update cap
refuses instead of deleting retained knowledge.

These are logical input/history bounds, not a physical file/page, CPU, wall
clock or disk reservation guarantee. Arbitrary callbacks have no deadline.
The actual-worker qualifier uses the existing measured executable adapter and
its bounded subprocess timeout. That adapter does not establish executable
provenance, an atomic measurement-to-launch boundary or sandboxing.

The selected native settings are rollback journal `DELETE`, synchronous
`EXTRA` (3) and `trusted_schema=OFF`. A schema/settings/comparison refusal before
commit rolls back and returns no positive result. SQLite/I/O or unexpected
exceptions that are not sanitized as comparison refusals, a failed rollback
and any exception after commit return
`WitnessOutcomeUnknown` and dispose the handle. A post-commit lost reply can
leave the completed witness persisted without a conclusive command return.
Interruption performs cleanup and propagates the interruption. There is no
automatic retry, repair, deletion or authoritative source reconciliation.
The existing worker adapter sanitizes a timeout, changed executable or invalid
worker result as a comparison refusal. This also returns no positive retention;
it is not a finding about the original source's unknown external outcome.

Creation has a separate binding/schema transaction. The creation lifecycle is
not comprehensively crash-qualified here; a failed creation can leave a file
that refuses reopening. Owned-directory setup, backups, migration, power-loss
qualification, path replacement, hostile storage and application integration
remain unresolved.

## Observed behavior and mathematical boundary

[The normal regressions](../tests/test_original_witness_store.py) deliberately
use forged callback flags to isolate framing and native transaction behavior.
[The actual-worker qualifier](../scripts/qualify_original_witness_store.py)
replays the same cases with the unchanged public signature executable and adds
actual zero-signature, stored-signature, measurement and historical-permission
controls. The explicit malicious callback control remains malicious even when
included in that qualifier. Signature validity does not authenticate current
source ownership or canonicality.

The cases cover absent/pending/completed retention, all nine live first choices,
complete Root/original binding, unsigned results, unavailable null facts,
false signed states, malformed/oversized packets, altered stored witnesses,
the update cap, ownership and reentrancy, real writer contention, already-open
stale writers, SQL write refusal and lost replies. A separate child writer is
killed at five cuts before commit and one after commit with cache spilling
enabled. These test process-death recovery under the selected native runtime;
they are not filesystem, drive, power-loss or every-platform durability proof.

## Copied-state and unknown-outcome limits

Independent consumer files can retain opposite signed futures from the same
pending witness. Writer serialization chooses an order only inside one owned
file. It does not select a shared canonical history across consumer/source
copies.

Restoring a coherent old consumer copy erases knowledge of completion and its
local version. The restored store accepts another future that extends its old
pending witness. The version counter, complete signatures and fresh challenge
are all replayable; none is an independent nonrollback anchor.

A directed source-and-consumer restore case applies the same external
synthetic effect twice at sequence `[2, 2]`, while the restored source contains
only one charge and one local effect. A still-retained completed consumer can
detect an older history, but cannot prevent or reconcile the source's external
effect. Copying/restoring both domains removes even that local knowledge.

Inspection and retention never allocate, refund, retry, apply a protected
effect, change source policy or resolve an original outcome. A mathematically
valid historical completion can be retained while the current source is
revoked and refuses its pending effect. No Boolean permission or authority
flag is returned.

## Pins, review and decision

Parent: `22d02ec4731d34c406a77cc601bb9b8132cef281`,
[PR 49](https://github.com/edgepillar/ptlc-research/pull/49).
The existing complete-opening helper, retained-prefix helper, signed-prefix
composition, owned source store, public worker, grammars and fixtures remain
byte-preserved. Measurements and execution scope are recorded separately in
[Stage 55 validation](STAGE55_VALIDATION.md).

**GO** for this bounded offline transaction experiment and review.
**NO-GO** for application witness integration or core/product use. Required
gates still include independently authenticated Root/issuance/head provenance,
current/canonical selection, source and consumer nonrollback ownership outside
copied domains, minimal disclosure, signer custody, authoritative unknown
reconciliation, protected-use ordering and an independent security/privacy
assessment. SQLite serialization does not close those gates.

## Later lifecycle qualification

[Stage 56](ORIGINAL_WITNESS_LIFECYCLE_EXPERIMENT.md) adds nine selected creation
cuts, a bounded native child actor, real inherited-owner refusal and selected
opening/inspection/retention cancellation controls. It narrowly changes the
test helper's constructor, preserving all subsequent transaction methods.
The earlier creation limitation above describes Stage 55's execution scope;
the later [validation](STAGE56_VALIDATION.md) records the expanded bounded
scope. Power-loss qualification, hostile-path defense, application integration
and independent nonrollback/source authority remain unresolved.
