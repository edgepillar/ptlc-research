# Candidate A: a separately administered NoM anchor ledger

Baseline:
[`06066b08991da4764e3c00cb28bc5e1fba9f1004`](https://github.com/edgepillar/ptlc-research/tree/06066b08991da4764e3c00cb28bc5e1fba9f1004).
This is one proposal for an offline experiment following the
[service acceptance obligations](NOM_ANCHOR_SERVICE_ACCEPTANCE.md). It selects a
trust model and a proposed local transaction boundary for assessment. It selects
no operational service, runtime build, transport, root key, signature role,
message encoding, deployment or original-operation adapter. Every AS-1 through
AS-7 gate remains **UNFILLED**. Application/core remain **NO-GO**, publication
outcomes **UNKNOWN**, and recovery action **NONE**.

## Authority and fault model

The candidate has one administered service and one authoritative ledger in a
failure domain outside consumer and source restore. Every cooperating consumer
must use that same independently provisioned authority for the selected scope.
A directory, database filename, process, host name, key encoding or newly
challenged reply cannot establish this independence.

Before a request, an independent provisioning record must bind the authority,
realm, service, epoch, policy, work scope and original enrollment obligation. Its
retention must survive coherent consumer restore. Revocation and transitions must
preserve the same obligation and terminal history. Packet-supplied roots, a
restored consumer configuration and the existing public signature fixtures supply
no such provisioning. The actual authority and its authentication construction
remain unselected.

The hypothesis trusts the service administrator to preserve one complete
authoritative history and prevent rollback or competing writable copies. It
also trusts the selected service host, database engine, filesystem, synchronization
implementation and storage hardware within a declared fault model. These are
assumptions to assess, not guarantees obtained by moving a file to another host.
Compromised administration, coherent service restore and split service copies
are not tolerated by this candidate. A threat model requiring those properties
needs a different, independently assessed retention mechanism.

The proposed first experiment uses synthetic public objects, one service process
and a local SQLite database. It has no replication, automatic failover, backup
promotion or migration protocol. A service outage preserves the original
obligation. Another endpoint cannot replace it through discovery or local setup.

## Proposed retained state

One logical scope retains its complete enrollment, ordered transitions, exact
requests, current head, charged UNKNOWN work and terminal retirement history.
Request identity must bind the complete expected before-state and proposed
transition. Uniqueness and exact equality are separate checks: an equal request
identifier with different contents must refuse.

The database must retain complete public objects and evidence openings needed
to review those relationships. Digests, counters and row identifiers cannot
reconstruct missing originals. Required actual custody remains separately
available under the existing reference rules. No private key, application signer
or wallet material enters this experiment. A storage schema, canonical encoding,
finite capacity and schema-version transition must be reviewed before a prototype
writes any record; none is defined by this document.

Provisioning an enrollment is an explicitly authorized administrative transition.
Opening an existing service never creates a missing ledger or infers safe
absence. Retirement appends terminal history; it does not delete the enrollment.
New epochs, aliases, directories and keys cannot reset charged work or remove a
tombstone. Unknown schema, missing state or lost provenance must refuse service.

## Proposed transaction and evaluation boundary

The initial storage hypothesis is SQLite rollback-journal mode `DELETE` with
`synchronous=EXTRA`, checked on the selected connection. SQLite documents one
simultaneous write transaction; `BEGIN IMMEDIATE` starts a write transaction and
may return `SQLITE_BUSY`. Its synchronization documentation describes an added
directory sync for `EXTRA` in this journal mode. These documented mechanisms
motivate an experiment; they are not measurements of this repository, a selected
runtime or physical durability. See the official [transaction semantics](https://www.sqlite.org/lang_transaction.html)
and [synchronization settings](https://www.sqlite.org/pragma.html#pragma_synchronous).

A proposed submission would perform the following within one explicit database
transaction, without a signer, callback, network dispatch or original operation:

1. Verify the independently selected scope and complete enrollment/retirement
   binding, then compare the exact retained expected state.
2. Check the complete request identity, unused nonce, retained obligations,
   capacity and allowed one-event reference extension.
3. Retain the exact request, complete resulting state and every earlier charge
   and terminal record, then update the current head in the same transaction.
4. Attempt the one selected database commit. An operational acknowledgment is
   unavailable until the complete service construction and durability meaning
   have been independently qualified.

An exact request already retained is an existing observation, not another
transition or permission to resubmit. A conflicting request, stale expected head
or terminal enrollment refuses without changing the ledger. No application-level
write or commit retry is selected, including after `SQLITE_BUSY`. SQLite error
handling can leave different transaction states; a failed commit must not be
treated as a clean rollback or as permission for another attempt. Original
errors and uncertain commit evidence must be retained separately. The engine's
documented transaction behavior does not settle service publication or an
original operation's outcome. Engine recovery after restart must be separately
characterized against the saved original image; it supplies no earlier service
acknowledgment or independent authority.

A proposed lookup evaluates the exact query, request and retained minimum within
one read transaction and retains the complete selected evaluation opening. The
query challenge, scope and evaluated position must be bound by a separately
assessed authentication construction. Existing source, custody and response
signature roles do not acquire that permission. A read snapshot names one
evaluation instant; a later committed transition can make it old at delivery.
Missing requests and outages establish neither global absence nor fresh work.

## Failure disposition

| Selected event | Required candidate behavior and remaining limitation |
| --- | --- |
| Writer contention or refused expected state | Preserve the request and all existing charges; return no positive service or operation result. No automatic retry is selected. |
| Process death, I/O error, capacity failure or lost reply around commit | Preserve the exact pending request and both possible publication outcomes. Reopen and later lookup cannot manufacture an earlier acknowledgment or settle the original operation. |
| Read sees an older complete snapshot | Bind the exact evaluated position and complete opening. Do not label the reply current at delivery or replace larger local UNKNOWN work. |
| Missing ledger, schema mismatch or missing actual custody | Refuse without creation, repair, trimming, replacement, fallback authority or reenrollment. Preserve the original enrollment obligation. |
| Database copied into two writable service domains | Both copies may advance independently. Local SQL serialization does not discharge shared independent authority or nonrollback retention. |
| Complete service history restored before a later transition or retirement | A coherent older ledger may appear internally valid. The trusted-administration hypothesis fails; SQLite supplies no external monotonic witness. |
| Capacity reached or an epoch/key transition requested | Preserve complete history and terminal records. No compaction, allowance reset, migration or continuity protocol is selected. |

The four existing successful unsafe controls in the
[acceptance inputs](NOM_ANCHOR_SERVICE_ACCEPTANCE.md#counterexamples-retained-as-acceptance-inputs)
remain required. A same-database contention experiment cannot turn independent
copies, old-image restore, reenrollment or hidden retirement into safe recovery.

## Assessment map and next bounded experiment

| Gate | Candidate mechanism or explicit assumption | Disposition |
| --- | --- | --- |
| AS-1 | Independently retained provisioning record and assessed authentication roles; no actual provider or root selected. | **UNFILLED** |
| AS-2 | One administrative enrollment with retained terminal history and explicit continuity obligations. | **UNFILLED** |
| AS-3 | Proposed single-database expected-state transaction retaining the complete request and resulting obligations. No implementation or operational acknowledgment. | **UNFILLED** |
| AS-4 | Proposed exact read snapshot plus separately assessed query/result authentication. No message, transport or verifier selected. | **UNFILLED** |
| AS-5 | Trusted service history outside consumer/source restore. Administrator rollback, service copies and external nonrollback enforcement remain unresolved. | **UNFILLED** |
| AS-6 | No original-operation adapter or atomic work-entry boundary selected. Database commit cannot authorize application signing or dispatch. | **UNFILLED** |
| AS-7 | No independent-machine, system-fault, physical power-loss or independent construction assessment performed. | **UNFILLED** |

The next permissible prototype is a finite offline comparison of the proposed
single-database boundary with the unchanged functional reference. It must first
pin the exact engine source/build and configuration, define bounded storage
encoding, and preserve complete original command and failure evidence. Required
controls include two contenders for one expected head, conflicting equal request
identifiers, read positions before and after commit, selected death/error cuts,
lost replies, terminal history and capacity refusal. Independent copies and
coherent restore remain explicit successful unsafe controls. No live service,
application cryptography or original operation belongs in that experiment.

This document runs no SQLite experiment, adds no directed runtime control and
reclassifies no earlier evidence. The linked SQLite documentation was reviewed
on 2026-10-16; it is a mutable upstream reference, not an immutable engine pin or
a qualification result. Release/security review and actual platform behavior
remain required before any engine selection. Deployment, node activation,
wallet access, transaction broadcast and real funds remain outside scope.
