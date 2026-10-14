# Selected NoM external checkpoint reference protocol

This additive offline protocol compares complete retained NoM originals and
UNKNOWN work against a separately selected reference. It implements no external
service, provisioned authority, signed response, nonrollback store or work entry.
Every result remains **HOLD**, recovery action **NONE**, and application/core
**NO-GO**. The earlier [historical role signatures](NOM_SOURCE_CHECKPOINT.md) and
all 190 measured inputs remain unchanged.

## Requirements before choosing a construction

An operational design must select the service and its authority independently
of a peer response and independently of restorable consumer state. It must retain
every charged ordinal and possible disclosure, compare complete journal lineage,
and distinguish the service counter from the journal and observer counters.
Source outage, key rotation, a new challenge and a later public completion cannot
erase UNKNOWN work or create another allowance.

A service transition must compare the expected current head before accepting an
extension. Cold start must not turn a local old copy into evidence that no earlier
service or charge existed. Changing an identity, key, epoch or policy must not
implicitly reset retention. Exhaustion must preserve the last accepted reference
and refuse further extension. Atomic persistence, interruption reconciliation,
nonrollback authority and protected work entry need independent designs.

## Selected independent service expectation

`select_service` takes a complete existing `NoMSourceCheckpointSelection`, an
explicit synthetic service identifier and epoch, a fourth public key encoding,
and a finite reference-history limit. Three source-role encodings cannot serve
as that fourth encoding. Distinct encodings prove neither distinct operators nor
independent custody domains. The parser checks key shape, not curve membership,
signatures or provisioning.

The chosen realm contains nine independently selected fields: core commit,
chain identifier, genesis, binary and spork digests, and canonicality, finality,
freshness and restore policy digests. Source authority identifier, profile,
incarnation and provisioning-root commitment are separate source selections.
Changing source roles does not create another reference scope. Changing a realm
field refuses under the old service expectation; this profile supplies no service
migration or policy-authority protocol.

The public fixture reuses an existing disclosed enrollment-owner public encoding.
It reuses no enrollment role, permission, signature, authority or message domain.
No signing algorithm for service responses is selected by this unsigned profile.
Actual service authentication must be assessed separately before adoption.

## Complete retained reference and transitions

`bootstrap_reference` explicitly creates an in-memory reference from the actual
complete selected capsule/read context. Both original envelopes must already be
present. A recovered signature, signed hash or reference reply cannot fill a
missing long original. The reference retains that context and its complete prior
reference chain; an incoming digest is never used to construct expected custody.

Each checkpoint commits to the service-selection digest, stable work scope,
capsule and journal digests, exact journal head and sequence, every charged UNKNOWN
entry, possible disclosure, a separate reference sequence and its parent digest.
Its counter is not a journal position, observer counter or execution receipt.
The finite selected limit is at most sixteen checkpoints. No history eviction,
automatic bootstrap, work release or replenishment exists.

`advance_reference` is a functional compare-and-advance against the supplied
current object. A stale expected digest refuses. The candidate must preserve the
full exact journal prefix, original bytes and prior charges. An extension advances
the reference sequence even when it adds no charge. Exact replay or a different
view of the same journal returns the same object; source rotation, epoch changes
and new challenges do not mint another sequence or work allowance.

The transition is not a shared-server CAS, lock, durable transaction or admission
receipt. Selecting the old current object twice can create two different heads
with the same counter. This successful unsafe control is retained, not described
as atomic serialization. Caller and runtime cooperation remain explicit premises.

## Exact expected reply and restore comparison

`checkpoint_query` binds an exact independently selected reference head and
sequence, service selection, work scope and challenge. It is not a request from a
minimum checkpoint that discovers a newer authenticated head. The current complete
expectation must already come from the separately selected reference domain.
`reference_reply` emits an unsigned frame against that exact expectation. A peer
can reproduce the frame from public fields; matching it establishes no authority.

The comparison accepts only the exact canonical reply and exact independent
query. It never chooses its expected current head, counter, service or custody
from that reply. A changed challenge refuses the old frame without changing the
checkpoint. Objects use strict ASCII canonical JSON, an 8 KiB wire limit and the
existing twelve-level depth bound. Alternate numeric/boolean encodings, duplicate
fields, noncanonical whitespace and extra privilege flags refuse.

| Complete local journal relative to the selected reference | Result |
| --- | --- |
| Same journal | `MATCHING_JOURNAL`; retain all charges and HOLD |
| Strict extension | `LOCAL_AHEAD_REFERENCE`; retain the larger local charge list, leave the reference unchanged and HOLD |
| Strict prefix | `LOCAL_BEHIND_REFERENCE`; retain the larger reference charge list and HOLD |
| Divergent or another work scope | Refuse without changing the reference |

These results compare independently supplied inputs. They do not update a local
journal, substitute originals, invoke a worker or authorize recovery. Effective
charged work remains UNKNOWN even when the historical source claim is supported
or unavailable.

## Unsafe controls and next independent gates

A local restore loses the later charge when considered alone; retaining the newer
reference detects that prefix and preserves the larger list. However, restoring
local context, current reference and reply together still matches. A fresh explicit
bootstrap from the old local state also produces an old reference. Neither action
proves that an earlier external service or charge was absent. The reference
construction does not satisfy nonrollback requirements.

The next design must independently provision service identity and authority,
authenticate an exact challenge-bound response and its complete evidence opening,
specify minimum-to-new-head discovery and outage handling, and qualify a storage
domain outside coherent consumer restore. It must then qualify shared atomic
service transitions, interruptions, physical durability and a separate atomic
work-entry protocol. Source truth, canonicality, finality and currentness remain
independent obligations. No wallet, node activation, deployment, application signer,
transaction construction, broadcast or real funds enter this workspace.

See the [qualification boundary](NOM_CHECKPOINT_PROTOCOL_VALIDATION.md).
