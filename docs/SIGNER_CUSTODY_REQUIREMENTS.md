# Signer custody requirements and candidate acceptance

Status: **AUTHOR REQUIREMENTS / NO REAL CONSTRUCTION SELECTED**. This document
defines evidence needed before selecting a private signer, fresh entropy, durable
nonce custody or independent nonrollback authority. All four remain **UNSELECTED**;
independent assessment is **NOT ASSESSED**. Application/core progression is **NO-GO**.
This is a decision framework, without a private signing API or deployed remedy.

## Examined source and evidence boundary

The examined preceding source is
[`2f8757def8618578e857c214bb457a2dc8a74eed`](https://github.com/edgepillar/ptlc-research/tree/2f8757def8618578e857c214bb457a2dc8a74eed),
tree `e4503a4de52e304e20b2aefe2e348bf80504fbfb`, with 511 tracked files. This
requirements document is later packaging outside that tree. The unchanged
[native author packet](NATIVE_SIGNER_REVIEW_HANDOFF.md) selects the separate
508-file source `bc9e972dbf30bdd6be1d0264a6a518b23ebc1434`; its manifest digest is
`0c217d04cc936c2e9b6c55efdeb83964c8337e4052b3748979870f9a7c27e545`.
Neither subject may be silently extended by this requirements document.

Evidence codes below refer to these immutable preceding documents and their
pinned source/test references. Their observations are author qualification with
public synthetic values; their models state ideal premises separately from
implemented behavior. A required future check is not a check performed here.

| Code | Pinned author evidence | Limit relevant to candidate selection |
| --- | --- | --- |
| E1 | [Pre-consumption model](https://github.com/edgepillar/ptlc-research/blob/2f8757def8618578e857c214bb457a2dc8a74eed/docs/NONCE_INVOCATION_MODEL.md) | Local journals, split checks and result fencing do not supply the model's unimplemented atomic, durable admission outside all usable copies |
| E2 | [Granted-work copy model](https://github.com/edgepillar/ptlc-research/blob/2f8757def8618578e857c214bb457a2dc8a74eed/docs/NONCE_GRANT_COPY_MODEL.md) | Unique issuance alone does not prevent copied ready, checked or permitted workers from repeating work; effect-coupled authority is an ideal unimplemented premise |
| E3 | [Public intent and conformance](https://github.com/edgepillar/ptlc-research/blob/2f8757def8618578e857c214bb457a2dc8a74eed/docs/PUBLIC_NONCE_INTENT.md) | Exact public bytes and four fixed projected contexts do not authenticate private inputs, participant approval or actual nonce use |
| E4 | [Native partial/journal handoff](https://github.com/edgepillar/ptlc-research/blob/2f8757def8618578e857c214bb457a2dc8a74eed/docs/NATIVE_PARTIAL_JOURNAL_HANDOFF.md) | Actual pinned partial math uses public deterministic owners; copied/restored matching histories repeat nonce and partial despite each original owner's local refusal |
| E5 | [Native owner process death](https://github.com/edgepillar/ptlc-research/blob/2f8757def8618578e857c214bb457a2dc8a74eed/docs/NATIVE_OWNER_PROCESS_DEATH.md) | Twenty selected owner deaths retain a surviving journal coordinator; coordinator/parent death, primitive interruption and power loss remain outside the measured scope |
| E6 | [Acknowledged nonce boundaries](https://github.com/edgepillar/ptlc-research/blob/2f8757def8618578e857c214bb457a2dc8a74eed/docs/NATIVE_NONCE_BOUNDARY_CUTS.md) | Eight killed pauses are outside the primitive; the removed nonce remains on the live stack, and an empty Option supplies no erasure or exclusive custody |
| E7 | [Authority evidence](https://github.com/edgepillar/ptlc-research/blob/2f8757def8618578e857c214bb457a2dc8a74eed/docs/CURRENT_AUTHORITY_EVIDENCE.md) | Pins, public events and prefix scans authenticate no producer, loaded runtime, actual private consumption or independent current authority |
| E8 | [Independent review obligations](https://github.com/edgepillar/ptlc-research/blob/2f8757def8618578e857c214bb457a2dc8a74eed/docs/INDEPENDENT_REVIEW.md) and [transaction graph](https://github.com/edgepillar/ptlc-research/blob/2f8757def8618578e857c214bb457a2dc8a74eed/docs/TRANSACTION_GRAPH.md) | Ordinary verification and finite vectors do not assess the exact adaptor extension, disclosure, refund races, fees, reorgs or observation |

## Requirements and refusal predicates

Each SC identifier is a requirement for a later candidate, not a claim about
current implementation. Every row is **OPEN**. A design assumption must identify
its controlling party, excluded threats and failure consequences; a local test
cannot be substituted for independent assessment of that assumption.

| ID | Required predicate | Evidence to supply for a candidate | Refusal gate; existing evidence |
| --- | --- | --- | --- |
| SC01 | The exact two-party adaptor construction, both legs, participant/key order, aggregation, tweak/parity, signing/completion/extraction rules and dependency revisions have an assessed specification | Immutable specification and implementation subjects; dependency/notice inventory; adversarial vectors and independent findings with scope/conditions | Refuse selection based only on BIP340 verification, a PointLock or finite partial vectors; E8 |
| SC02 | Every usable key, nonce and work-permission copy has a named custody boundary throughout generation, admission, computation, retention and retirement | The inventory below, actual ownership/permission transitions and a threat model covering forks, backups, snapshots, queues, temporaries and suspended work; explain any excluded copying adversary | Refuse an unexplained copy, an out-of-band nonce holder or a claim that local Option removal proves exclusive custody; E1, E2, E4, E6 |
| SC03 | Real nonce generation uses an explicitly selected, assessed entropy/derivation and provisioning construction, with domain/context binding and failure behavior | Exact entropy source and backend revision; draw/provisioning policy, failure controls and evidence for freshness under the selected restore/clone threats | Refuse fixed synthetic seeds, deterministic reconstruction of consumed nonce state, failed entropy treated as success or an unassessed fresh-generation claim; E4, E6 |
| SC04 | Actual consumed backend inputs equal the independently approved complete context, including operation, session, leg, role, key order, tweak, message, round, public nonces and adaptor | Mapping from validated public declarations to real key/nonce handles and actual backend arguments; authenticated participant approval; malformed/substituted/changed-context refusal checks | Refuse a peer-selected expectation, descriptive operation string, matching public projection or receipt as proof of actual private consumption; E3, E7 |
| SC05 | Durable consumption precedes nonce work, and nonrollback admission covers the actual effect of every usable copy without an exportable replayable permission | Exact placement and failure semantics of the authority/secret boundary; source-pinned implementation and copy-after-grant/backend-entry challenges; assessed atomicity and compromise assumptions | Refuse preflight-only checks, a durable Boolean, unique issuance, mutex, accepted-result filtering or an exported permit as the complete remedy; E1, E2, E4 |
| SC06 | Independent current authority remains continuous across permitted restores and refuses stale, conflicting or unverifiable authority before new nonce work | Authority owner, trust roots, epoch/continuity evidence, durable ordering, failover/quorum and outage/compromise/split-brain policies; coherent owner/journal/authority restore challenges | Refuse rollback of the authority with the caller, cached successful reads after lost continuity, or authority unavailability enabling work; E1, E2, E7 |
| SC07 | Any uncertain consumed operation remains spent; recovery releases only an already retained exact original output without nonce-dependent reentry | State/transition record below, crash-consistent retention ordering, integrity/context checks, replay authorization and loss/ambiguity controls | Refuse resigning, resetting, seed reconstruction, replacement computation or fresh-nonce retry as recovery for that uncertain operation; E4, E5, E6 |
| SC08 | Required counterpart material and the exact original output are retained and validated before exposure under the assessed protocol | Separate signing, completion/extraction and participant retention obligations; authenticated original artifacts and ordering; lost/altered material and early-disclosure checks | Refuse a partial-signature receipt as proof that all later completion/refund material or participant obligations are satisfied; E8 |
| SC09 | Failure qualification exercises the later selected owner, custody and journal together at their actual boundaries | Source/input pins and the distinct failure scopes below; measured work, delivery, retention, reopen and replay outcomes; retained negative controls | Refuse extrapolating fixture callbacks, surviving-coordinator SIGKILL or acknowledged outer pauses to unexecuted private/platform/backend failure scopes; E4, E5, E6 |
| SC10 | Producer, examined source, distribution, loaded runtime and actual private-input origin are authenticated within an explicit trust model | Independently selected complete subjects, reproducible correspondence evidence where claimed, authenticated releases/runtime and protected consumed-input evidence without publishing secrets | Refuse source hashes, build logs, public events, equation checks or self-selected manifests as complete provenance; E7 |
| SC11 | Disclosure, memory, diagnostic, backup and public-artifact policies are independently assessed against the selected privacy/custody threats | Secret-free public evidence; bounded access/retention; private handling of keys/nonces/handles; evaluated leakage and erasure limitations | Refuse private material in the public intent grammar, public fixtures/logs or claims of anonymity/erasure from a path scan, process exit or Option state; E3, E6, E7 |
| SC12 | Cross-chain safety and proposed core scope have separate acceptance evidence | Assessed spend graph, material release, clocks, fees/replacement, refunds/claims, observation and reorg assumptions; later regtest/devnet qualification and upstream coordination | Refuse interpreting signer qualification or this matrix as swap security, deployment/activation or core consensus permission; E8 |

SC05 does not require successful output on every consumed operation: burning a
nonce and then failing safely may be necessary. Its safety requirement is that
no copied permission or surviving secret holder can perform a second prohibited
nonce use. The construction must explain how authority encloses or controls the
real computation, rather than merely saying that an authority database is atomic.
SC06 names trust and continuity assumptions explicitly; it does not promise
safety after an unrestricted compromise of every trusted custody/authority party.

## Mandatory copy and permission inventory

A candidate must enumerate concrete instances of each applicable class, its
owner, creation/export points, permitted readers, persistence/restore scope,
maximum lifetime, retirement/erasure limitations and admission enforcement at
actual use. Mark an absent class with an implementation-backed reason. Unknown
instances keep SC02 and SC05 open. Secret bytes and real identifiers stay private.

| Class | Required question before selection |
| --- | --- |
| Key and nonce provisioning | Can an importer, seed, backup, entropy snapshot or recovery process recreate a consumed nonce? Who can invoke it? |
| Owner memory and call frames | Which heap/stack/register/temporary copies remain after local consumption, across fork, checkpoint or suspended calls? |
| Backend and dependency state | Can backend handles, reusable contexts, serialization, caches or foreign-language copies invoke signing independently of the owner? |
| Pending work and transports | Can queues, RPC retries, duplicated requests, serialized grants or acknowledged workers repeat work after admission? |
| Checks and permissions | Can cached successful checks, issued grants, returned permits or a resumed preflight bypass the final authority/effect boundary? |
| Durable owner, journal and authority | Which backup pairs or replicas can restore a matching history; which external state cannot roll back under the selected threat model? |
| Output and counterpart artifacts | Which exact original bytes are durably retained before release; which lost acknowledgement can create uncertainty without allowing computation again? |
| Diagnostics and retirement | Can crash dumps, logs, debugging, device recovery or administrative access expose usable secret/permission copies after retirement? |

Single-process ownership is a proposed local control only until the candidate
states how its allowed copy/restore adversaries are excluded or contained.
An external ledger cannot control an unrestricted nonce holder merely by refusing
to record its second result. A hardware or remote boundary also needs the exact
construction, administration, backup, reset and granted-work analysis; its name
alone closes no row.

## Consumption, uncertainty and exact-output recovery

The states below are abstract requirements for a later implementation. They do
not rename the existing public journal's states or provide a private recovery API.
Backend entry, completed computation, delivery and durable retention are distinct
facts; lost observability must be classified conservatively.

| State | Minimum established fact | Permitted next action |
| --- | --- | --- |
| Reserved, not consumed | No admission or usable exported work permission exists, under the candidate's assessed boundary | Admit once under SC04-SC06, or retire without performing work; never infer this state from a missing receipt alone |
| Consumed, proven no computation | Durable burn exists and the assessed boundary establishes zero nonce work on all usable copies | Retire spent; no reset or reconstruction. A separate protocol action, if ever allowed, needs its own approval and cannot be called recovery of this operation |
| Consumed, outcome unknown | Work or output may exist, but exact original bytes are not durably authenticated and retained | Quarantine the operation as spent; seek evidence of already retained original output without invoking signing/completion again |
| Computed, original output unretained | Computation is known but exact durable retention is absent or unverifiable | Remain spent/unknown for recovery; delivery success or caller memory does not authorize reconstruction |
| Original output retained | Exact original bytes and their complete context are durably authenticated; no second computation is needed | Authorized delivery/replay of those bytes under assessed participant and current-authority rules; no backend reentry |
| Retired | The operation is permanently unavailable for new nonce work under the selected boundary | Preserve refusal and required evidence under restore; retirement alone supplies no physical erasure proof |

An authority outage does not make an unknown operation unconsumed. If exact-output
replay is permitted during an outage, the candidate must separately assess that
release policy and counterpart consequences; silence or a cached check grants
no exception. Resetting the whole session, changing a message or allocating a new
nonce must not conceal uncertain prior work or material already disclosed.

## Candidate decision record and comparison

No vendor, device, service, library or custody design is selected here. A later
proposal must have an immutable, nonidentifying decision record with: candidate
identifier and revisions; SC01 construction; controlling parties and threat
model; complete copy inventory; entropy/provisioning; actual input/admission/effect
boundary; authority/restore/outage/compromise policy; uncertain-output recovery;
dependency/license subjects; planned versus executed checks; independent findings;
omissions and per-SC refusal predicates. Use distinct statuses **PROPOSED**,
**SELECTED FOR OFFLINE QUALIFICATION**, **IMPLEMENTED**, **AUTHOR QUALIFIED** and
**INDEPENDENTLY ASSESSED**, each with scope/revision and unmet conditions. They
are evidence labels, not an automatic promotion chain or application permission.

| Candidate class, hypothetical only | Decisive evidence missing | Current decision |
| --- | --- | --- |
| Local process with journal-only consumption | Enforceable custody/restore threat model for every copy; a boundary beyond local restored state and result filtering | UNSELECTED; current journal/owner counterexamples remain unresolved |
| Local secret owner with external authority | How final nonrollback admission controls actual computation and all copied grants/secret holders; continuity during failures | UNSELECTED; adding a ledger or preflight check alone is insufficient |
| Remote custody/signing service | Exact adaptor/backend support, authenticated context, server replica/grant/custody copies, administration and nonrollback recovery semantics | UNSELECTED; remote placement is not assessed custody |
| Device-contained custody/signing | Exact construction support, secret/permit export limits, entropy, device backup/reset/rollback policy and actual failure behavior | UNSELECTED; a device label is not independent qualification |

Reject a proposal that cannot satisfy a required predicate within its stated
threat model. A proposal with missing evidence remains open; do not convert an
unknown into a pass. Offline selection of a fully specified candidate still
requires a reviewed scope and independent construction assessment before any
application decision. Public synthetic tests may support that assessment but
must never serve as the private custody construction.

## Later integration acceptance and review order

The selected implementation must retain all current nonce/partial repetition,
copied-grant and coherent-restore counterexamples as negative controls. State
which later remedy addresses each adversary; do not remove a failing threat by
changing the fixture or silently narrowing the model. Execute separately:

| Failure scope | Required observations and current qualification gap |
| --- | --- |
| Owner-only death with journal surviving | Work/admission/retention/reopen separation; E5 and E6 cover selected public-synthetic cases only |
| Journal/coordinator death with owner surviving | Contain a surviving owner and any released grant; show no orphan can perform a prohibited second use; unqualified for a real construction |
| Parent and supervisor death | Specify descendant/queue containment and restart authority; test the selected topology rather than assume owner death; unqualified |
| Storage faults and coherent restore | Corrupt/missing/torn records, persistence ordering, full owner/journal replicas and external-authority continuity; current deterministic counterexamples must remain visible |
| Interruption inside the real backend | Selected primitive/library interruption and usable secret/permission copies; outer acknowledgements cannot qualify this scope |
| Machine or device power loss | Actual selected platform durability, reset/backup and uncertain-output behavior; process SIGKILL cannot establish this scope |
| Authority outage, failover or compromise | Prevent stale/cached/exported permission reuse and document trust failures; no independent authority is currently selected |

Start with SC01 construction and SC02-SC07 custody/authority specification, then
assess the proposed boundary before implementing its private API. Qualify the
later real owner/journal integration under SC08-SC09, independently authenticate
provenance/privacy under SC10-SC11 and separately assess SC12 cross-chain/core
scope. Missing evidence blocks the dependent decision; additional toy schedules
alone cannot close the real custody gate.

All four fixed independent inventories, both historical author packets and their
handoff documents, and the three UNFILLED reports remain exact. No reviewer is
contacted or independent review requested. Source-to-worker/reproducibility remain
**NOT VERIFIED**; private consumed inputs, producer origin and loaded runtime
remain **NOT AUTHENTICATED**; privacy remains **NOT ASSESSED**. No wallet, funds,
broadcast, live chain, release, merge, deployment, activation or core action is
qualified. See [local validation](STAGE94_VALIDATION.md).
