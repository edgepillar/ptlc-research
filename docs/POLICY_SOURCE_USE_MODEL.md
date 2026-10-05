# Policy source, durable operations and protected-use cutoffs

Status: **Offline conditional comparison only. No policy source, authenticator,
operation service, dispatcher or worker-entry gate is implemented.**

This Stage 40 delta follows the [read requirements](CURRENT_AUTHORITY_EVIDENCE.md)
at source commit `6761b682929330c226b8d50e7cfb74dccf3ab813`. The earlier pure read
contract binds a selected checkpoint; it neither establishes current authority
nor serializes a subsequent use. This [standalone model](../scripts/model_policy_source_use.py)
compares where a trusted current-policy decision would have to meet a durable
operation record. Existing parsers, signatures, workers and journals are unchanged.

## Requirements, candidate policies and executed behavior

The requirements are independently provisioned source identity and roles,
complete decoded scope, current policy at the selected cutoff, preserved charge
lineage, scoped operation idempotency and an explicit revocation rule. They do
not follow from a valid credential or matching read claim.

The selected construction is an ideal finite state model. Policy transitions,
commit-and-charge and recorded entry are indivisible abstract events. Durable
records and trusted current evidence are assumptions, except in the explicit
unsafe controls. A candidate cutoff is a comparison hypothesis, not a final
runtime policy or a proof of a source implementation.

Executed behavior is limited to [34 directed/model tests](../tests/test_policy_source_use_model.py)
and selected schedule comparisons. The [validation record](STAGE40_VALIDATION.md)
separates these from the required full suite, source inventories and hosted CI.
No existing admission path imports or acts on this model.

## Ideal trust and finite domain

There are two callers and two operation slots in one fixed, canonical, already
enrolled resource and authority namespace. A slot stands for a scoped operation
identity, not a real collision-resistant identifier. Resource equivalence,
enrollment, source provisioning, credential signature facts and all other role
and scope fields are fixed trusted premises. There is no actual wire decoding,
signature verification, credential issuance or source authentication here.

Four symbols stand for complete independently selected profiles. Owner, source
incarnation and cap are descriptive projections, not enough to reconstruct or
authenticate the fourteen-field assignment.

| Trusted world phase | Complete profile | Owner | Source/root era | Resource cap |
| --- | --- | --- | --- | --- |
| 0 | 0 | 0 | 0 | 2 |
| 1: complete policy update | 1 | 0 | 0 | 1 |
| 2: owner rotation | 2 | 1 | 0 | 1 |
| 3: revocation | None | No active assignment | 0 | No new charge |
| 4: independently authorized root/incarnation rotation | 4 | 1 | 1 | 1 |

The world advances in this order and never rewinds. Phase 4 assumes an externally
authorized trust transition; it does not derive recovery authority from a
compromised root's own statement. Repeated rotations, multiple resources,
administrative consensus and additional actors are outside this domain.

Source modes are live, unavailable, ambiguous and compromise-detected. The last
mode assumes a trusted compromise signal. Undetected compromise and a malicious
source that fabricates authenticated current evidence are not solved or tested
as safely rejected implementations.

## Read, commit, lookup and entry are separate events

1. A caller independently selects a complete profile and original operation slot.
   A read stores a claim only. Separate stale and forged reads can supply a
   positive claim without current truth.
2. A new commit checks the current complete profile and available trusted source,
   then charges the retained resource and writes the operation record atomically.
   These are model assumptions. A cap reduction keeps prior charges; it supplies
   no refund or fresh namespace. Old charges count against later profiles.
3. Repeating the same scoped operation and complete profile returns the original
   record without another charge. The same slot with another profile refuses
   rebinding. An original record can be reconciled after revocation; this is not
   a new policy decision or another resource allocation.
4. A lost commit reply produces an unknown caller outcome, including when the
   request charged nothing. Unavailable lookup leaves it unknown. A live lookup
   reconciles the original slot; there is no automatic replacement operation,
   inferred absence, quota refund or granted capability.
5. Entry requires the caller's matching known record and an unentered durable
   record. The selected cutoff determines whether current policy is checked
   again. Entry and its record mutation are one abstract audited event.

No actual work, process launch, dispatch acknowledgement, entry nonce or worker
fence occurs. A durable charge is not proof of physical entry or completion.
Recording an entry atomically in this model does not establish that an external
process can enter exactly once across a crash between its record and actuation.

## Compared policies and revocation semantics

| Policy | New commit | Abstract entry | Selected-schedule result |
| --- | --- | --- | --- |
| `cached-read` | Cached positive; ignores source failure | Original unentered record; ignores source failure | Counterexamples to current-policy charging and selected-cutoff entry |
| `commit-cutoff` | Live current complete policy plus atomic durable charge/record | Live source serializes one entry; previously committed decision survives later policy changes | No violation in the selected schedules, conditional on ideal premises |
| `entry-cutoff` | Same current commit and durable charge/record | Live source and current complete policy checked again at entry | No violation in the selected schedules, conditional on ideal premises |
| `rollbackable-ledger` | Same current check | Same entry cutoff, but source records may be restored once | No violation in selected schedules; directed source restore repeats charge and entry |

Under `commit-cutoff`, revocation after a committed decision does not cancel its
single pending entry. The later entry still needs the source to serialize its
record. Under `entry-cutoff`, a cap/profile change, owner rotation, revocation or
root/incarnation transition before entry can refuse that old entry. Refusal
retains the original charge. Both choices audit completed entries at their
chosen instant; a later revocation does not retroactively invalidate old work.

This is a material operational choice. A real design must define whether
"commit" means an allocation, a durable dispatch commitment or another protected
effect, and whether "entry" means dispatch, receipt, process start or a gated
instruction. Names alone do not establish a linearization point or worker fence.
Neither candidate cutoff has been selected for production.

## Preserved failure and restore boundaries

The conditional policies refuse new commits while the source is unavailable,
ambiguous or known compromised. Stale or forged cached reads do not replace the
current check. Existing-record lookup supplies no new charge. Pending abstract
entry also waits for live source availability in both conditional policies.
These rules express an ideal failure policy, not an implemented network outage
or compromise detector.

A coherent local caller restore resets receipt knowledge but preserves its
original proposal and slot. The independently trusted source and its operation
history do not rewind; duplicate commit and entry remain bounded by that history.
This is not rollback protection for an actual local database or backup.

The unsafe source-ledger restore erases operation records while keeping the
trusted policy world and external audit history. A caller can then charge and
enter the same operation again while profile 0 remains genuinely current. Thus
current authentication alone cannot supply non-rollbackable operation lineage.
The external audit used to expose this witness is itself an ideal model premise.

Different operation identities may charge the same proposal twice under cap 2.
Scoped idempotency does not provide business-intent uniqueness. A real service
must select its identity derivation, complete-request collision checks and
retention rules independently; no enrollment or uniqueness mechanism is added.

## Selected schedule enumeration and directed tests

The comparison preserves each caller's `read -> commit -> enter` order and
interleaves it with one, two, three or four ordered policy advances. There are
140, 560, 1,680 and 4,200 shuffles, respectively: **6,580 schedules and 62,580
transitions per policy/operation variant**. Same-slot and distinct-slot variants
across four policies produce eight comparisons, totaling 52,640 schedules and
500,640 transitions. These are all shuffles of these selected streams, not the
full action graph or an exhaustive protocol/security proof.

Outages, ambiguity, detected compromise, forged/stale reads, lost replies,
original-operation lookup, cap preservation, client restore and source-ledger
restore are separate directed tests. They are not included in those enumeration
counts. In particular, the source-restoration counterexample is required even
though `rollbackable-ledger` has no selected-schedule violation. Recorded
witnesses are replayed, and later policy changes do not alter earlier cutoffs.

Run the affected suite and all eight CLI comparisons:

```sh
python3 -B -m unittest discover -s tests -p test_policy_source_use_model.py -v
for policy in cached-read commit-cutoff entry-cutoff rollbackable-ledger; do
  python3 -B scripts/model_policy_source_use.py --policy "$policy"
  python3 -B scripts/model_policy_source_use.py --policy "$policy" --distinct-operations
done
```

The CLI names the policy, cutoff and operation variant and reports
`full_action_graph: false`. A schedule cap gives `incomplete`, reason
`schedule-cap` and exit 2. A completed selected comparison is exit 0 even when
it exposes an unsafe policy witness; completion is not a safety verdict.

## Gates before a real source adapter

The next implementation decision must identify an actual independently
administered source candidate, its immutable construction, provisioning roles
and authenticated current-read/update contract. Specify its operation namespace,
atomic policy/charge/idempotency record and non-rollbackable lineage separately
from its authentication. An authenticated old snapshot is still an old snapshot.

Select one protected-use definition and revocation rule, then assess dispatch,
worker fencing and crash/unknown-outcome reconciliation at that exact boundary.
Native persistence and process tests must verify the chosen mechanism; this
finite model does not substitute for them. Root rotation, trusted compromise
recovery, source unavailability, retention and business-intent uniqueness also
need explicit treatment. Do not attach a parsed positive read to the existing
runner or journal as a permission shortcut.

Both [fixed review subjects](OBSERVATION_REVIEW.md), manifests and unfilled
reports remain unchanged. This later delta needs its own independent assessment.
Offline comparison is **GO**. Current-authority integration, core port,
activation, deployment, private signing and funded recovery remain **NO-GO**.
