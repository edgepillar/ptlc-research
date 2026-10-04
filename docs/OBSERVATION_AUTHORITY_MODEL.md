# Observation freshness and dispatch authority model

Status: **Stage 29 finite offline design comparison. No external authority,
dispatcher, restore defense or application integration is implemented.**
The model's strongest policy assumes trusted external state and dispatch. A
complete bounded search under those premises does not establish a backend,
distributed protocol, cryptographic construction or funded availability.

Source parent: [`b94f04d4e03ff747a72c0b6b5f3ab691cf6853f1`](https://github.com/edgepillar/ptlc-research/tree/b94f04d4e03ff747a72c0b6b5f3ab691cf6853f1).
Its [completed seven-job run](https://github.com/edgepillar/ptlc-research/actions/runs/37206694311)
qualifies the existing implementation and [v4 restore experiments](RESOURCE_STORE_RESTORES.md).
Those experiments expose coherent history rewind and independent copied quotas.
This separate model asks which additional premises could bound participating
worker entries in one canonical scope. It imports no application module and
changes no runtime, storage format, mathematical record, journal or dependency.

## Requirements versus modeled choices

| Desired requirement | Modeled choice | Evidence and unresolved construction |
| --- | --- | --- |
| Old local history cannot replenish one enrolled scope's allowance | One external, non-rollbackable head and charged count | Coherent local rewind leaves this ideal state unchanged; its actual trust root, durability and recovery remain unselected |
| Two copies cannot both spend a stale read | Atomic expected-head reservation consumes shared allowance and records pending before returning a receipt | Read-check comparison exposes a time-of-check gap; no real transaction or authenticated service is supplied |
| A charged receipt cannot launch multiple participating workers | An ideal external dispatcher spends the receipt at the worker-entry event | Charge-only comparison exposes copied-receipt replay; a public acknowledgment followed by local spawn is not this premise |
| Lost replies and recovery do not refund | Pending resolves to charged unknown; authority count never decreases | Receipt loss can exhaust allowance before any worker entry; no funded recovery or retry policy is selected |
| A late result cannot overwrite newer authoritative history | Current head and pending ticket fence result publication | Recovery can refuse the old result while its worker was still running; history fencing is not process containment |
| Backup cannot rewind the protection itself | External state and spent-dispatch history survive local restoration | Rollbackable-dispatch comparison replenishes quota and reuses receipt identity; another co-restorable database is insufficient |
| New caller labels cannot create a fresh allowance for the same protected scope | One exact pre-enrolled scope and immutable profile are fixed inputs | Wrong scope/profile requests are refused in the model; canonical enrollment, principal authorization and duplicate detection are assumed, not implemented |

The scope is an abstract enrollment identity, not the existing public store ID,
session label or pool/profile digest. Its mapping to protected session, retained
context, verifier, physical enrollment and requested resources must be specified
and reviewed. The model fixes that mapping instead of claiming that public
labels authenticate it. A second independently instantiated authority has its
own allowance; nothing here proves a host-wide or ecosystem-wide quota.

## Five comparisons

The [pure model](../scripts/model_observation_authority.py) uses two copies,
one fixed scope/profile and explicit finite bounds. Local revision values and
ticket integers are abstract labels; they implement no commitment, wire format,
capability or authenticated response. Closed idle snapshots can copy a pending
receipt or restore the initial local history. They never copy a running worker.

1. `local`: each history charges its own requests. Restoring its empty snapshot
   permits another entry after its one-attempt history was already exhausted.
2. `read-check`: a copy reads the current external head before local admission.
   Two reads can precede the first result; the second cached read can authorize
   work after that head has changed. Reading freshness does not atomically spend
   shared allowance or guarantee freshness at entry.
3. `authority-charge`: expected-head reservation atomically consumes the
   external allowance. Its returned receipt is copyable and starts local work.
   Two copies can start with one charged receipt. Recovery also cannot revoke
   that local starting capability. Result publication still checks the current
   external pending ticket and head.
4. `ideal-dispatch`: reservation and result fencing are unchanged; an additional
   ideal external enforcer spends a receipt once at entry. Its authoritative
   dispatch history and charged count cannot be restored. All modeled worker
   entries go through this enforcer. Direct calls, hostile executors, copied
   executor state and crash-safe actuation are outside this premise.
5. `rollbackable-dispatch`: entry uses that same ideal enforcer, but an explicit
   event rewinds its authority and spent history. Restored local state can then
   obtain reused receipt identity and another entry. Current-head checks still
   reject an immediately stale receipt; that retained check does not prevent
   quota replenishment after both sides rewind.

Normal and unknown finishes are environmental events. A modeled normal is not
an executed Rust verdict, an authenticated chain observation or mathematical
evidence. Authority loss may prevent retaining it, leaving the reservation
pending until recovery records unknown. This supplies no normal negative.

## Ordering, availability and ownership

Reservation consumes allowance before receipt delivery. Lost receipt, client
restoration, canceled publication and recovered pending leave it consumed.
There is no refund, automatic new enrollment or uncharged retry. Authority loss
refuses external reservations and ideal dispatch without local fallback. The
model can resume service, but it assumes no eventual return, time bound,
fairness, response authentication or available recovery path.

The ideal dispatcher makes worker entry indivisible only as an abstract trust
premise. It does not implement an atomic durable-write/process-spawn operation.
A backend must address acknowledgment loss, duplicate callers, copy/restart,
crash between charge and spawn, and stale execution authority. Preventing replay
may sacrifice progress after uncertain dispatch. No exactly-once completion or
physical worker termination follows from this finite model.

Authority recovery resolves pending history and advances its head. It does not
kill a previously entered worker. With a two-attempt allowance, recovery can
permit another current worker while the prior one still runs; its late result
is fenced out. The existing [physical pool](SHARED_WORKER_ADMISSION.md), inherited
leases, resource limits and source-journal boundaries remain separate. No pool,
CPU/memory, cancellation, orphan cleanup or nonce-owner protection is replaced.

## Reproduction and interpretation

Run from the repository root, with no network or backend:

```sh
python3 -B scripts/model_observation_authority.py --policy local
python3 -B scripts/model_observation_authority.py --policy read-check
python3 -B scripts/model_observation_authority.py --policy authority-charge
python3 -B scripts/model_observation_authority.py --policy ideal-dispatch
python3 -B scripts/model_observation_authority.py --policy rollbackable-dispatch
python3 -B scripts/model_observation_authority.py --policy ideal-dispatch --max-states 1
python3 -B -m unittest discover -s tests -p test_observation_authority_model.py -v
```

The default domain is two copies, allowance one and at most two total worker
entries. All reachable states in that finite domain are enumerated. Trace
findings can replay to their exact final states. `bounded-complete` with exit
zero reports completed enumeration, including discovered counterexamples; it
does not mean the policy is secure. An exploration cap reports `incomplete` and
exit two, even if no violation was found. Larger allowances/entry domains need
their own completed searches; no unbounded safety or liveness proof is claimed.
See [Stage 29 validation](STAGE29_VALIDATION.md) for the executed domain, counts,
initial failed expectation and remaining hosted gates.

## Acceptance gates before an implementation

| Gate | Required specification and evidence |
| --- | --- |
| Canonical enrollment | Identify the scope owner, protected context, duplicate enrollment rule, initial trust pins, rotation and exceptional reset authority; define how new public IDs cannot evade the selected budget |
| External head and count | Select an authenticated, independently anchored authority; state host/storage assumptions and test stale reads, concurrent reservations, reply loss, backup/restore, native storage faults and power failure |
| Dispatch ownership | Select the trusted enforcer and its entry capability; qualify copied receipts, cloned enforcers, reserve/dispatch acknowledgment loss, uncertain spawn and result fencing without claiming crash-safe exactly-once execution |
| Availability policy | Review exhaustion, authority outage, legitimate late witness, recovery authorization, deadlines, fairness and uncertain dispatch; safety without a remaining recovery path is insufficient for funds |
| Narrow integration | Preserve source-journal authority, ordinary/v4 separation, profile selection, normal/unknown partition and physical leases/resources; prohibit silent migration, fresh quota or ordinary-work fallback |
| Independent assessment | Assess this exact model delta separately from both fixed subjects, then assess any selected backend, its protocol and implementation; no template is filled by this model |

**Go:** use explicit counterexamples and conditional finite results to specify
and assess the enrollment, authority and dispatch contract. **No-go:** select a
production backend, claim implemented anti-rollback/clone defense, connect secret
signing or funded recovery, port core rules, activate a node or broadcast funds
from these results. Both fixed review subjects and their unfilled reports remain
unchanged; this later model needs its own explicit assessment.

The later [Stage 30 candidate contract](OBSERVATION_AUTHORITY_CONTRACT.md) supplies
a separate pure scope/request/reply encoding for reviewing those bindings. It
does not implement this model's ideal state, enrollment or dispatcher. Matching
reply claims remain forgeable/replayable, and existing entry points are unchanged.
Its assessment and any selected backend remain separate gates.
