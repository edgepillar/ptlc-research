# NoM reference anchor lifecycle and lost acknowledgments

This additive finite model retains an exact pending anchor transition and compares
it with a separately selected complete reference history. Every diagnostic remains
**HOLD**, publication outcome **UNKNOWN**, recovery **NONE**, application/core
**NO-GO**. It implements no external store, service dispatch, authenticated
acknowledgment, shared atomic compare-and-swap, or original work entry.

Baseline:
[`6e7e629a199b8e2cba79fbba3aeb288fb3ea5c3c`](https://github.com/edgepillar/ptlc-research/tree/6e7e629a199b8e2cba79fbba3aeb288fb3ea5c3c).
All 218 earlier measured inputs remain unchanged. This construction extends the
[complete reference read order](NOM_CHECKPOINT_READ_ORDERING.md). Earlier
source/custody/response signatures authenticate none of its new lifecycle roles.

## Required operational lifecycle

An operational anchor needs independently provisioned identity, role, epoch and
initial state; unique creation must not infer absence from a missing local file,
unavailable service or restored database. A new epoch or location must not erase
an old active record, pending request or retirement tombstone. These are external
requirements, not consequences of choosing different identifiers or encodings.

Before returning an operational acknowledgment, the selected service must commit
the exact preceding state, complete request and original evidence through a shared
atomic transition in an independently retained nonrollback domain. The consumer
must retain the exact possible publication before losing the result. Lost replies
must preserve both committed and uncommitted possibilities. A lookup of the same
request must not repeat an original operation or replenish UNKNOWN work. Current
read authentication, durable acknowledgment and original-operation entry remain
separate obligations.

Retirement must preserve complete history and charged work, prevent reactivation,
and survive restore, copy, relocation and epoch change. Outage is not absence.
Migration, capacity exhaustion, tombstone retention and recovery after lost
consumer state require independent provisioning and acceptance. This profile
chooses no storage product, operational authority, signature construction,
deployment or physical persistence guarantee.

## Selected finite construction

`bootstrap_reference_anchor` explicitly selects an actual complete ordered trace,
anchor identifier and positive epoch. It creates an ACTIVE reference at revision
zero. This research bootstrap proves no safe absence, uniqueness, provisioning,
unused budget or absence of an earlier tombstone.

`prepare_anchor_advance` retains the actual complete before-state and exactly one
next ordered event. Initial opening, service selection, scope and complete event
prefix remain exact. A trace cannot skip an event, regress, replace a sibling or
silently change service/source history. Its request binds the whole preceding
anchor digest, exact proposed trace and a nonce unused in that retained history.
Checkpoint sequence, ordered-event position and anchor revision are distinct.

`commit_reference_anchor` performs a pure functional expected-state transition.
It retains the complete request commitment and actual trace at each position.
Replaying the same request after the reference has advanced refuses; a different
nonce is another request, not an idempotent retry. No network dispatch or shared
server transaction occurs. SHA-256 domains for state, transition and held
acknowledgment are distinct commitments, not authentication.

`prepare_anchor_retirement` selects a terminal reference tombstone. Its commit
preserves the current trace and every earlier transition. A retired reference
accepts no new advance or retirement. Historical lookup remains possible without
reactivating it. Explicitly selecting another initial reference can still hide an
old tombstone; no cross-enrollment protection is implemented.

The anchor admits at most sixteen transitions and 32 KiB of canonical ASCII JSON
under the existing twelve-level decoder. Requests and held acknowledgments admit
8 KiB each. Event and byte limits both apply; exhaustion refuses without dropping
history. The earlier checkpoint and ordered-trace limits remain unchanged.

## Lost acknowledgment and exact lookup

`retain_unknown_anchor_acknowledgment` retains the actual complete transition
before comparison. It represents a caller-declared possible publication; it
performs no dispatch. Public descriptors or digests cannot reconstruct absent
before-states, requests, original contexts or ordered traces.

| Separately selected reference | Diagnostic and retained obligation |
| --- | --- |
| Unchanged complete before-state | Request not found in that reference; proposed UNKNOWN work stays charged; no absence or retry permission |
| Exact next retained request | Reference request matches; operational publication outcome stays UNKNOWN |
| Later history retaining that exact request | Preserve its position and larger UNKNOWN list |
| Retirement after the request | Keep the matching request and terminal tombstone; no reactivation |
| Regressed history, changed identity/epoch or another next request | Refuse the comparison |
| Unavailable independent anchor | No current anchor, cached positive record or absence claim; retain proposed and larger local UNKNOWN work |

All successful diagnostics forbid new work, automatic retry, same-request
republication, replacement originals, replenishment, automatic bootstrap and
automatic reenrollment. A reference lookup does not authenticate a current
service or establish currentness at delivery.

Each public call starts fresh actual-input validation, deduplicated only inside
that pure operation. Frozen objects and defensive exports detect accidental
aliasing. This is no hostile-runtime or concurrent-service boundary.

## Unsafe controls and remaining gates

Coherent old anchor/hold selection still matches. Two independent copies of the
same expected state accept different functional transitions. Explicit research
reenrollment after retirement starts another ACTIVE lifecycle. Restoring a
pre-retirement reference permits another reference transition while hiding the
later tombstone. These controls expose missing independent nonrollback authority;
they do not certify real restore, power loss, service behavior or work permission.

Actual independent provisioning, authenticated current lookup, external
nonrollback retention, shared atomic transitions, original-operation entry,
independent assessment and physical power-loss qualification remain unfilled.
No wallet, application signing, transaction construction/broadcast, deployment,
activation or funds are connected. See the [qualification boundary](NOM_ANCHOR_LIFECYCLE_VALIDATION.md).
