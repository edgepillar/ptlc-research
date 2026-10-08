# CUSTODY-01: a party-owned custody domain proposal

Status: **PROPOSED / UNSELECTED / NOT IMPLEMENTED**. This is one author decision
record against the [twelve OPEN requirements](SIGNER_CUSTODY_REQUIREMENTS.md).
It is not a real signer selection, protected device/service, private API or
independent assessment. Application/core progression remains **NO-GO**.

The [static decision record](../design/custody-candidate-01.json) fixes the proposed
topology, input mapping, failure policy, trust premises and rejection conditions.
It is descriptive author metadata, not a signing wire format, capability,
admission grant or trusted executable checker. Its examined preceding source is
[`7cba45449515f5fb8deae939323a2378c7e87f07`](https://github.com/edgepillar/ptlc-research/tree/7cba45449515f5fb8deae939323a2378c7e87f07),
tree `3a56df715b36140f6d913cf13ba782652a48f960` (513 files). The new proposal and
record are outside that immutable tree. The native author packet still selects
its separate 508-file main source; neither historical subject is extended here.

Decision-record SHA256:
`8225498b35e4873c3a433b7126c4cbb144036d4ed4e70764782225c98bb2d2d2`.
Independently select the expected revision/digest before any later assessment;
the received record cannot select its own expected truth.

## Concrete proposal and controlling parties

Alice and Bob would each control a separate custody domain containing only that
party's per-leg signing keys, nonce generation, consumption ledger, policy state,
backend invocation and retained original partial outputs. No domain would possess
both parties' aggregate-key shares. An untrusted session coordinator could submit
public requests and restore its own journal, but receive no signing scalar,
secret nonce, entropy seed or reusable work permission.

An independently authenticated nonrewinding continuity anchor would lie outside
ordinary owner/coordinator backup state. The actual custody platform, anchor,
entropy source, provisioning, administrator controls and private implementation
are all **UNSELECTED**. This topology requires an assessed mechanism to prevent
usable secret/work-state copies inside the custody domain, including during the
interval between burn and backend entry. Calling a process, service or device a
custody domain supplies no such mechanism.

Authority policy updates and the final permission predicate would serialize with
actual backend entry inside that domain: **entry-cutoff** semantics. A revocation
after burn but before entry would refuse work while retaining the spent burn.
A cached external read or exported permit would not satisfy this requirement.
Completed work cannot be retroactively uncomputed; subsequent output delivery
has its own current-policy check. The proposed default refuses both new work and
retained-output delivery if current authority/continuity cannot be established.
Availability and cross-chain consequences of that default remain unassessed.

## Exact backend reference and existing observations

The proposal references the existing qualification backend, not an approved
production dependency: `conduition/musig2` at
[`5a09b1197b1b5c621a5a9abc60fa95fa84a1da30`](https://github.com/conduition/musig2/tree/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30).
Its manifest is `0.4.1`, licensed Unlicense. Both existing test crates declare
`default-features = false`, `features = ["secp256k1"]`; complete current manifests,
locks and [third-party notices](../THIRD_PARTY_NOTICES.md) remain unchanged.
The single-signer `schnorr_fun` comparator is not substituted for the two-party
adaptor construction. No new arithmetic, dependency or external implementation
is copied.

Nine named upstream files in the record were compared with their exact Git
blob/mode/length/SHA256 bytes, including the manifest and license. That is a
limited source inspection, not a complete upstream inventory, full upstream
test-suite execution, binary/source correspondence or independent cryptographic
assessment. The local Cargo source cache also contained its untracked completion
marker; that marker is not upstream source or producer authentication.

| Pinned source observation | Consequence for this proposal |
| --- | --- |
| [`adaptor` aliases](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/lib.rs#L27) select `sign_partial_adaptor` and `verify_partial_adaptor` | Use the exact adaptor path; an ordinary signing API is not an interchangeable operation |
| [`sign_partial_adaptor`](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/signing.rs#L54) takes the aggregation context, secret key, SecNonce, aggregate nonce, adaptor point and message; checks key membership/nonce key binding and verifies the partial | Mathematical input checks do not approve a participant, authenticate an actual private input or enforce durable one-use custody |
| [`SecNonce`](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/nonces.rs#L470) derives Clone; its [encoding](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/nonces.rs#L720) serializes/parses two nonce scalars and the public key in 97 bytes | Consuming the argument by value is not a noncopyability boundary. The proposal must prevent every usable copy/encoding escaping its assessed custody boundary |
| [`SecNonce::generate`](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/nonces.rs#L528) accepts a supplied seed, key, aggregate public key, message and extra input | A real fresh seed and context policy are still needed; accepting seed bytes is not evidence of fresh entropy or safe restored generation |
| The [existing synthetic owner](https://github.com/edgepillar/ptlc-research/blob/7cba45449515f5fb8deae939323a2378c7e87f07/qualification-native-partial/tests/native_partial_journal.rs) removes its local Option before checks/work and uses fixed public keys/seeds | Its lack of exposed Clone/serialization, PID/thread check and local refusal do not implement this proposal or contain backend temporaries, snapshots or deterministic reconstruction |

These are API constraints and author source observations, not a new library
vulnerability or an executed changed-message key-extraction claim. All existing
nonce/partial repetition and copied/restored-history controls remain unchanged.

## Four partial operations and complete input mapping

The proposed domain handles nonce-dependent partial signing only. The selected
offline [CANDIDATE-01 graph](TRANSACTION_GRAPH.md) retains separate Alice/Bob
keys and nonces on both legs and a common adaptor point. Ordinary Zenon account
authentication, funding/refund keys, Alice's private witness custody, completion,
extraction, Bitcoin construction and chain observation are not selected by this
partial-signer proposal.

| Operation scope | Proposed actual backend inputs |
| --- | --- |
| Alice, Bitcoin claim | Alice index zero; ordered Alice/Bob Bitcoin key aggregation, exact refund-leaf Taproot tweak, agreed claim sighash, complete aggregate nonce and common adaptor point |
| Bob, Bitcoin claim | Bob index one; the same exact Bitcoin aggregation/tweak/message/round, with Bob's separately generated nonce and key |
| Alice, Zenon claim | Alice index zero; ordered distinct Zenon keys without the Bitcoin tweak, exact validated entry/destination claim message, distinct Zenon round and the common adaptor point |
| Bob, Zenon claim | Bob index one; the same exact Zenon aggregation/message/round, with Bob's separately generated nonce and key |

The proposal must map an independently approved complete context to actual key
handles, ordered validated public points/nonces, constructed KeyAggContext and
tweak, AggNonce, message and adaptor. It must check declared aggregate/output
keys against the constructed context. Private seeds/nonces remain internal;
the existing [public intent](PUBLIC_NONCE_INTENT.md) is not a private grammar or
authentication credential. Exact extra-input encoding, key provisioning, entropy
and participant approval are unselected. Neither a caller's self-consistent
context nor a library-valid partial closes SC04 or the cross-chain input gate.

## Burn, entry, retention and recovery sequence

The steps below are proposed obligations, not executed candidate behavior.

1. Provision only the party's separately bound keys through an assessed private
   path. Authenticate complete participant approval and current source/policy;
   validate funding/message/round obligations before any permitted work.
2. Generate a nonce with assessed fresh entropy inside the domain; bind its
   stable internal identity to the complete context. No caller-selected label,
   namespace, role or session reset may turn that nonce into a new reservation.
3. Seal and verify the complete public round and actual backend context. Requests
   cannot import a secret nonce, seed or reusable backend/work permission.
4. Durably burn the internal nonce reservation under nonrollback continuity
   before work. On ambiguous persistence, refuse work and quarantine the operation
   as spent; missing acknowledgement is no absent burn.
5. Recheck current eligibility indivisibly with actual entry into the same-domain
   backend. No queue, returned grant, cached check or suspended work state may
   escape the assessed effect boundary. If eligibility is lost, retain the burn
   and refuse without treating the nonce as reusable.
6. Invoke the exact adaptor partial path at most once under that boundary,
   verify the result against the exact public inputs, and durably retain the
   original bytes/context before exposure and an authorized delivery.
7. After uncertainty, reconcile only already retained original output. Missing,
   altered or unauthenticated retention leaves the operation spent/unknown.
   Never reconstruct a consumed nonce, resign, allocate a fresh retry nonce,
   restore permission, repair the epoch or reset the session as its recovery.

Nonce burn, current-policy eligibility, actual computation and output release
are distinct facts. The sequence is conditional on the missing noncopyable
effect and nonrollback premises; it is not made atomic by naming the sequence.
An opaque handle, Rust move, ledger transaction or internal callback alone
cannot prove those premises. If the backend or post-burn work state can be
cloned/resumed into a second use, reject this candidate even if only one result
is accepted or both outputs are identical.

## Threat model, controls and rejection decisions

| Adversary or failure | Required handling; current evidence status |
| --- | --- |
| Malicious counterparty/coordinator; duplicate, changed or reordered public requests | Exact approved-input checks, per-party ownership and one-use admission; authentication/private consumption remain unimplemented |
| Copied/restored coordinator journals, request queues or returned artifacts | They cannot recreate permission or trigger another nonce computation; current deterministic counterexamples remain negative controls |
| Copied backend/nonce state or a snapshot after burn/final check | In scope: prevent usable copies at the real custody/effect boundary or reject the proposal. Do not exclude this threat merely to obtain a positive result |
| Owner, coordinator, parent or backend interruption; lost output/acknowledgement | Retain nonrollback burn and spent uncertainty; qualify each actual component separately. Existing synthetic owner SIGKILL is narrower evidence |
| Authority outage, stale state, failover, split brain or coherent full restore | Refuse new work and delivery until assessed continuity/current authority is established; a local restore or admin reset is not continuity |
| Entropy failure, seed restore, debug/crash dump or key/nonce export | Fail closed and contain/retire usable copies; selected entropy, memory/privacy and provisioning evidence are absent |
| Compromise of the entire trusted custody/authority platform or its controlling trust roots | Outside a conditional trusted-platform guarantee; no safety after unrestricted trusted-boundary compromise is claimed. Actual boundaries/compromise policy still need selection and assessment |
| Cross-chain reorg, censorship, clock/fee/resource failure or refund/claim race | Outside this partial-signer proposal; retain SC08/SC12 obligations and NO-GO for the swap/application |

Reject selection if the chosen platform cannot execute the exact assessed
adaptor path, preserve nonrollback burn/continuity, contain all usable copies and
bind actual approved private inputs. Reject a plan that relies on exported
permission, current-result filtering, restoring consumed nonce objects, shared
custody of both participants' keys, or a missing independent construction scope.
No device or remote-service capability, audit, erasure, availability or security
certificate is inferred. Selecting a physical mechanism and proving its premise
remain separate work.

The record leaves every SC01-SC12 gate OPEN. SC01 construction, SC02/SC05 physical
custody/effect control, SC03 entropy, SC04 approval/input mapping and SC06 anchor
continuity are prerequisite decisions; SC07 recovery, SC08 retention, SC09 actual
failure integration, SC10 provenance, SC11 privacy and SC12 cross-chain/core
evidence remain unmet. The old four fixed inventories, both historical author
packets and three UNFILLED reports stay exact. No reviewer is contacted.
Source-to-worker/reproducibility remain NOT VERIFIED; private inputs, producer
and runtime remain NOT AUTHENTICATED; privacy remains NOT ASSESSED. See
[local validation](STAGE95_VALIDATION.md).
