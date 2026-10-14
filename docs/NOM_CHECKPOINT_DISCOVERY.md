# Minimum-bound NoM checkpoint candidate discovery

This separate offline protocol discovers a candidate at or above a complete
independently retained minimum. It supplies no authenticated current service,
nonrollback storage, signer, signature verifier or application work entry.
Every result remains **HOLD**, recovery action **NONE**, application/core **NO-GO**.
All 196 earlier measured inputs, including the [exact reference comparison](NOM_CHECKPOINT_PROTOCOL.md),
remain unchanged at baseline
[`8f9f4afde9a6949b6f7377f7f03549c41a49e2f7`](https://github.com/edgepillar/ptlc-research/tree/8f9f4afde9a6949b6f7377f7f03549c41a49e2f7).

## Requirements before choosing current-read authentication

An operational current read must begin with independently provisioned service
identity, key authority and a complete known retention history. A peer cannot
select its own service, root, epoch, work scope or minimum. The service must retain
every UNKNOWN charge, possible disclosure and original operation across restart,
outage, key transition and lost replies. A fresh challenge creates no new work
allowance and proves no currentness by itself.

Authentication must cover the exact complete query, response and evidence opening.
It must be separate from the old source/custody signature domains and from mere
key-encoding equality. Valid mathematics under a self-selected key cannot assign
checkpoint authority. The service must also establish the position at which its
response was evaluated against current serialized retention state. A signed old
checkpoint, newly challenged old response or counter above a minimum can still
hide a later checkpoint. That ordering requirement is separate from signature math.

Complete custody cannot be reconstructed from checkpoint hashes, header arrays,
recovered long bytes or later public completion. Operational migration must retain
the same old work lineage and known history. Changing identity, epoch, key or policy
cannot silently bootstrap a fresh service or release an exhausted budget.

## Selected known minimum and complete openings

`checkpoint_read` retains an actual complete `ReferenceCheckpoint` as its known
minimum. Its nine-field query binds a complete independently selected service
policy, that policy's digest, stable work scope, minimum checkpoint digest and
counter, the complete minimum opening digest and a challenge. The candidate current
head is deliberately absent: the client has not independently established it.

`checkpoint_opening` retains an actual complete candidate reference and every
original context in its bounded immutable history. Public descriptors contain
each full snapshot, its checkpoint digest and a new domain-separated source-context
digest. The latter commits to the complete historical declaration/statements and
their actual read/original bindings. It distinguishes source views that share the
same checkpoint header. A hash or public descriptor dict cannot construct this
opening; both actual originals and complete journal contexts must already exist.

The candidate must have the same service policy and preserve the entire known
descriptor prefix, including its source views. The existing reference construction
checks exact journal continuity and separate checkpoint counters. A skipped record,
changed parent, divergent branch after the minimum or retroactively replaced source
view refuses. This profile implements no migration of known history. Source
rotation, epoch and challenge changes do not replenish work or mutate the minimum.

History is finite at sixteen reference checkpoints. Query/reply bytes are bounded
at 32 KiB using the existing twelve-level strict ASCII JSON decoder. Both limits
apply; a valid history that exceeds the wire bound still refuses. There is no
history truncation, counter-only shortcut, eviction or automatic bootstrap.

## Candidate, outage and local comparison

`discovery_reply` frames an unsigned `CHECKPOINT_CANDIDATE` containing the complete
descriptor lineage, head and opening digest, bound to the exact query digest.
The complete actual opening is a separate required input to `inspect_discovery`;
reply descriptors cannot supply missing custody. The opening is untrusted as a
producer or latest-head assertion even when its complete lineage matches.

| Selected inputs | Diagnostic result |
| --- | --- |
| Candidate is the exact minimum | `MINIMUM_CANDIDATE`; preserve complete UNKNOWN work and HOLD |
| Candidate extends all known history | `NEWER_CANDIDATE`; report the discovered head/counter and HOLD |
| Local journal is ahead of candidate | Preserve the larger local UNKNOWN list; do not advance or mutate service state |
| Local journal is behind candidate | Preserve the larger candidate UNKNOWN list and possible disclosure |
| Candidate is below the minimum or forks after it | Refuse |
| Local and candidate journals diverge | Refuse |
| Service is unavailable | Preserve the known minimum and larger local work; report no candidate head and HOLD |

`UNAVAILABLE` is an unsigned outage shape with no head, opening digest or lineage.
It proves no absence and accepts no cached positive opening as fallback. Missing
or malformed replies refuse. Neither outage nor a successful candidate comparison
updates the minimum, opens a store, invokes a worker or authorizes recovery.

## Exact response preimage and unfilled authority

`response_message_digest` selects a new public SHA-256 domain over the complete
canonical query and exact validated reply. It commits to service policy, minimum,
challenge, all candidate descriptors and their complete opening commitments.
Changed challenges or substituted openings produce a different statement or
refuse. The preimage is available for later independent authority design; no
signature algorithm, signer, verifier or delegated service role is selected here.
The disclosed fourth public encoding reuses no old enrollment or source permission.

The following acceptance gates remain independent:

| Gate | Missing mechanism or evidence |
| --- | --- |
| Independent authority | Provision the exact service/root/key role and work scope outside peer replies and restorable consumer state |
| Response authentication | Select and assess the actual algorithm/delegation construction; authenticate complete message and actual evidence openings under the provisioned role |
| Current-read semantics | Define the serialized read instant and qualify stale replicas, rollback, conflicting heads, compromise and outage |
| Nonrollback retention | Select a storage domain outside coherent consumer/source restore and preserve original UNKNOWN charge history |
| Service transitions | Qualify shared atomic compare-and-advance, interruption reconciliation and explicit epoch/key/policy migration |
| Actual work entry | Bind durable original operation and charge to the protected entry instant without duplicate dispatch or automatic retry |
| Independent assessment | Review the exact source, runtime, authority and storage delta separately from these reference tests |
| Physical durability | Qualify real power-loss/storage behavior separately from controlled process exits and logical snapshots |

## Successful unsafe controls

A service can answer a new challenge with the old minimum while withholding a
later candidate; this still matches and remains HOLD. Restoring the local context,
known minimum and old opening together also matches. Two siblings above the same
old minimum can both match at the same counter. Finally, anybody can reproduce
the unsigned frame from public fields, provided the required complete opening is
already retained. None of these controls establishes a unique latest head or
creates another work allowance. They expose the missing authentication, currentness,
nonrollback and shared-service ordering requirements.

No application cryptography, live service, node activation, wallet, transaction
construction, broadcast or real funds are connected. See the
[qualification boundary](NOM_CHECKPOINT_DISCOVERY_VALIDATION.md).
