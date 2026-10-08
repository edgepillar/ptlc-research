# Custody authority ordering and revocation semantics

Status: **AUTHOR INTERFACE PROPOSAL. NOT IMPLEMENTED.** No physical authority,
custody platform or nonrewinding anchor is selected. All SC01-SC12 requirements
remain **OPEN**; independent assessment is **NOT ASSESSED** and application/core
remain **NO-GO**. The [descriptive record](../design/custody-authority-interface.json)
is design metadata, not a wire format, credential, work permit or private API.

This proposal refines the unimplemented effect premise in the
[finite composition](CUSTODY_ENTRY_MODEL.md). That model treats work as one
indivisible event; an actual computation takes time. This document specifies
which ordering a future construction must enforce throughout that interval.
It does not change the model, implement these semantics or qualify a platform.
The [candidate](CUSTODY_CANDIDATE_01.md) and
[mechanism comparison](CUSTODY_MECHANISM_FEASIBILITY.md) stay exact.

## One authority order, with separate party owners

For each party's domain, one authoritative order must cover policy revision,
revocation acceptance, nonce burn, actual effect admission, completion or
certified fencing, exact-original retention and each output release. Every
usable key, nonce and already admitted work copy must remain subject to that
order. An ordinary coordinator database or copied local ledger cannot be its
independent nonrewinding anchor. What makes this order authoritative, durable,
authenticated and nonrewinding remains an unselected construction obligation.

The policy issuer must delegate or participate in this same effective-policy
order. This is a proposed trust arrangement, not an existing provisioning fact.
If an independent policy service commits a revocation first while a signer can
still execute against a previous read, that design does not meet this proposal.
Calling the signer's later read its own "current policy" cannot hide the gap.
No read result, signed checkpoint, challenge, image admission or key-delivery
receipt is a transferable permission for subsequent local computation.

Alice and Bob retain separate domains, keys, anchors and administrative trust.
The same obligations apply independently to each domain. There is no single
domain with both parties' key shares and no global cross-chain commit order.
The exact four partial operations and excluded operations in the
[candidate record](../design/custody-candidate-01.json) are preserved.

## Revocation has three distinct positions

1. **Proposal submitted:** a caller asks for a change. Arrival at a remote queue,
   transport acknowledgment or a timeout says nothing about owner acceptance or
   current policy. A computation can precede acceptance even if the proposal
   was submitted first. No instantaneous submission-time guarantee is claimed.
2. **Proposal accepted and fenced:** the owner authenticates the complete
   issuer/scope/expected predecessor and records an admission fence in its
   nonrewinding order. New affected effect admissions and output releases stop.
   Existing admitted computations must finish or be certified unable to resume.
   This is a pending state, not a successful committed-revocation receipt.
3. **Revocation committed:** the owner advances the effective policy revision
   only after the affected earlier effect/release intervals have ended or all
   usable continuations are certified fenced. A successful receipt refers to
   this committed position and complete scope. A lost receipt leaves the caller
   uncertain; it does not undo the commit or authorize a retry of signing.

Acceptance itself needs current authenticated administrative authority and
verified continuity. A rejected or unobserved proposal is not a durable fence.
Policy updates and rotations use the same ordering obligations. Neither a new
revision nor a new owner incarnation can clear burns or revive old work copies.
Future receipt encoding, issuer authentication, transport, fencing mechanism
and proof of the selected latest history remain unresolved.

An effect admitted before the fence may finish under its original policy while
the revocation is pending. The owner must hold effective-policy exclusion from
the final current-policy decision through the last nonce-dependent instruction,
or certify that no usable continuation can execute. The commit cannot pass that
interval. An admission record by itself, a lease deadline, process timeout,
local mutex, kill request or encrypted backup is not such a certificate.
If a suspended worker or copy might resume, report pending/unavailable, retain
the spent outcome and do not issue a success receipt. Liveness can stop; no
bounded completion or recovery guarantee is established here.

## Abstract operations and their response boundaries

These are obligations for a future owned domain, not callable interfaces in
this repository. Private keys, nonces and admission grants never leave it.

| Abstract operation | Required owner action | Response meaning |
| --- | --- | --- |
| Submit revocation | Authenticate complete scope and predecessor; fence admissions, then serialize the policy commit after earlier intervals | Pending and committed are distinct. A historical receipt is not permission or proof of the latest head. |
| Attempt one partial | Validate the complete selected operation and actual backend inputs; durably burn its internal nonce; admit at current policy with verified continuity and shared consumption | No reusable work permission. A success label alone does not release bytes; delivery has its own current admission. |
| Retain original internally | Bind exact original bytes to the one actual effect and complete operation, without invoking the backend again | May preserve an earlier admitted result while revocation is pending or committed; retention does not authorize outward delivery. |
| Query original status | Read the authenticated retained history under applicable read policy | Missing, timeout, absent output or historical success cannot establish an unspent nonce or permission to recompute. |
| Release original | Revalidate current policy, continuity, pending fences and exact original identity at the actual controlled outward release | Every first delivery and replay is a separate admission; replay invokes no nonce-dependent work. |
| Restore continuity | Independently establish the current complete nonrewinding history and fence every obsolete usable incarnation | Restores access to that history only; it never refunds, clears uncertainty, replaces the original or creates a new signing attempt. |

Every partial attempt binds the party, leg, distinct per-leg key handle, signer
index, ordered aggregate keys and nonces, stable internal nonce identity, exact
adaptor point, exact message and leg-specific tweak. It also binds the approved
operation identity, policy namespace/revision, anchor lineage/incarnation and
actual backend arguments. These facts must come from authenticated independent
approval and protected inputs; caller-supplied identifiers, matching opaque
hashes or JSON fields cannot establish them. A nonce cannot be renamed to make
a spent private value appear fresh. The backend argument mappings remain those
in the unchanged candidate; this document supplies no input authenticator.

## Nonrewinding facts and crash outcomes

The authority history must distinguish at least these facts. They are
requirements for persistent semantics, not a selected storage schema:

- Complete effective policy and accepted pending fences, with authenticated
  authority and anchor lineage; a cached checkpoint is not the latest head.
- Stable operation and internally owned nonce identity, complete approved
  selection, durable burn and at most one actual effect admission across all
  usable copies. Renaming a request or incarnation cannot create a second use.
- Active effect/release intervals and their completion or certified fencing;
  a durable admission record does not prove that a worker cannot resume.
- Spent uncertainty after interrupted work, missing output or unverified
  continuity; uncertainty may only be resolved from authenticated original
  history, never by speculative absence or a new effect.
- Exact original output with its complete operation and actual invocation
  lineage, plus independently ordered release admissions. A digest comparison
  alone does not authenticate private original bytes or their producer.

A burn survives refusal caused by later revocation. A crash after burn but
before trustworthy original retention is spent/unknown, even when a local log
suggests no computation occurred. Neither recovery with a new nonce nor a
replacement operation/session is permitted as repair of that attempt. A
surviving original can be reconciled without work if its exact identity and
history are independently established. A lost reply after retention is another
case of original reconciliation, not another signing request.

Reanchoring must establish the complete current history, including pending
fences, burns, admitted intervals, consumption, spent uncertainty and originals,
and exclude all obsolete usable worker/authority branches. A signed historical
prefix, larger counter, matching image or coherent restored backup is
insufficient. Conflicting histories or unverifiable continuity refuse both new
work and original delivery. There is no reset/restore-permission/unspend command.
Exact proof and failover mechanisms remain unselected; no administrator can
declare continuity merely by choosing a preferred branch.

Release ordering covers the point where bytes cross the controlled owner
boundary. If a release interval precedes the fence, it must end or be certified
fenced before revocation commit; an already completed release cannot be recalled.
Receipt arrival at the recipient may be delayed by transport and is not that
owner release event. After the fence, no new affected release may be admitted.
An interval already admitted before the fence may end before the commit under
its original admission; a delayed worker response or replay has no release
permission of its own. Retained private bytes remain available for permitted
internal reconciliation, not as a bypass of the delivery fence. No network-wide
erasure guarantee is claimed.

## Acceptance obligations, all unexecuted

The following schedules are future construction acceptance cases. They are
distinct from the executed symbolic regressions and the four still unexecuted
physical obligations in the mechanism comparison. **None is executed here.**

| Case | Required result |
| --- | --- |
| A01: remote proposal precedes work, owner acceptance follows it | Describe the pre-acceptance interval honestly; submission is not committed revocation. |
| A02: accepted fence arrives after burn but before effect admission | Refuse effect, preserve the burn, never return an exported permission. |
| A03: fence arrives during an earlier admitted computation | Block new affected admissions/releases; complete or certify fencing of the earlier interval before commit; retain original internally without automatic delivery. |
| A04: worker suspends, a deadline expires, old copy later resumes | No success receipt based on timeout; require evidence that all usable continuations are fenced, or stay pending/unavailable and spent. |
| A05: independent policy source commits while local cached work remains usable | Reject that construction as a split authority order; a later read cannot repair the intervening effect. |
| A06: two equal approved images restore a ready local history | Both copies face the same current authority and stable nonce consumption; at most one actual effect. Image equality is not copy containment. |
| A07: loss after burn, before authenticated original retention | Stay spent/unknown; no reconstruction, resigning, new nonce, replacement request or administrative reset. |
| A08: exact original retained, delivery reply lost | Reconcile and, if current policy/continuity allow a new release, replay the same original without another effect. |
| A09: retained original, then pending/committed revocation or lost continuity | Internal retention grants no outward permission; refuse delivery and replay. |
| A10: conflicting failover branches or restored historical prefix | Refuse work and release until complete continuity and obsolete-copy fencing are independently established; preserve every spent fact. |
| A11: completed release precedes fence, recipient receives later | Report the real owner release order; do not claim recall or retroactive revocation of already released bytes. |
| A12: one party's authority recovers or revokes independently | Preserve separate domains and four partial mappings; do not infer cross-chain atomicity, refund safety or a global policy commit. |

## Verified scope and remaining decisions

This slice adds author prose and descriptive metadata only. Existing contracts,
current-policy read framing, models, native workers, journals, cryptographic
primitives, test assertions and CI workflows are unchanged. In particular,
[checkpoint read framing](../offline_session/current_authority_contract.py)
remains replayable public framing and does not implement this interface.
The [local validation](STAGE98_VALIDATION.md) records preservation and regression
results; those results execute existing behavior, not this proposed authority.

Platform/copy containment, authority delegation, authenticated policy history,
continuity proof, interval exclusion/fencing, private input approval, entropy,
key provisioning, receipt encoding, retention authentication, privacy, erasure,
availability and independent review remain unresolved. Source-to-worker and
reproducibility remain NOT VERIFIED; private inputs, producer and runtime remain
NOT AUTHENTICATED; privacy remains NOT ASSESSED. No cloud/device access, real
signer, wallet, funds, transaction broadcast, core change or activation occurs.
