# Original-operation checkpoint read contract

Status: **Unsigned offline framing only. No authenticated source, original-operation
receipt, historical signature worker, application recovery or protected-use gate.**

Stage 46 follows `88527956a163a184dccca28590f6c7491fbb2576`. The
[separate contract](../qualification/original_read_contract.py) closes a framing
gap identified by [Stage 45](LOCAL_SOURCE_READ_ORDERING.md): its local sample
associated the original operation with a response, while the retained Stage 44
signature schema did not cover that association. Neither earlier schema changes
meaning. This new contract is not yet used by a source or signed-response worker.

## Requirements, selected construction and observed behavior

An authoritative lookup would require independently authenticated current source
and root/response roles, an exact retained original, complete policy and record
history at an independently selected cutoff, conflict-safe source deduplication,
nonrollbackable lineage, explicit retention and recovery rules, and a separately
chosen protected-use boundary. None follows from matching public bytes.

The selected construction is a bounded canonical ASCII JSON grammar with exact
objects, types, schemas and two distinct digest domains. The root, original
operation, policy checkpoint, record checkpoint and challenge are prepared before
peer bytes. There is no clock, network, store access, verifier callback, signing,
allocation, recovery adapter or worker entry in this module. Any party can forge
a structurally matching claim, including mutually inconsistent claims under the
same query.

Observed behavior is [36 directed tests](../tests/test_original_read_contract.py)
and an [unsigned synthetic framing fixture](../qualification/fixtures/original_read_contract.json).
Thirty-two methods exercise the contract and four use the unchanged owned local
store as explicit unsafe controls. These four tests are synchronous SQLite tests,
not new native death/writer groups. The full inherited process/death suites remain
required. See the [validation record](STAGE46_VALIDATION.md) for execution facts.

## Independent original, policy and record selections

| Selection | Complete binding | Limit |
| --- | --- | --- |
| Root | Complete retained declaration digest and source context | Provisioning and key custody remain external premises |
| Original | Operation id, expected revision, complete fourteen-field governor profile and proposal digest | No registration, owner authentication or original policy history is proved |
| Policy position | Selected revision and policy-state digest | No latest-head or elapsed-time claim |
| Record position | Retention rule, event sequence and record-lineage digest | A hash/sequence does not prove complete, durable or nonrollbackable history |
| Read | Challenge and the complete preceding selections | A new challenge does not refresh policy or record history |

The original schema is `ptlc-observation-original-operation-v1`; the query is
`ptlc-observation-original-read-query-v1`; the claim is
`ptlc-observation-original-read-claim-v1`. Query and claim domains are respectively
`PTLC/observation-original-read-query/v1` and
`PTLC/observation-original-read-claim/v1`, each with a NUL suffix. Query/claim wire
is at most 16,384 bytes. Exact integer positions are bounded by `2^53-1`; booleans,
floats, strings and numeric aliases are refused where an integer is required.

The selected read rule is `same-incarnation-original-lookup-v1`. Its namespace is
the complete selected source context, including source id, incarnation, opaque
profile pin, provisioning root, authority, resource and role. The original
profile must retain that authority/resource/role. The selected original revision
cannot exceed the selected policy revision; at equal revisions the complete
profile must match the selected root profile. At an earlier revision the original
profile is kept intact even when the selected current root has different caps,
epoch, owner or other policy pins. The grammar does not authenticate that claimed
historical policy. There is no implicit cap attenuation or new assignment.

This rule selects lookup in **one source incarnation**. It does not discover an
original's namespace from an operation id, migrate records, authorize root/source
rotation or recover an old original across incarnations. Deliberately selecting
a new incarnation creates different query bytes and still supplies no authorized
transition history. Those recovery and retention decisions remain unresolved.

The separately selected record position declares
`retained-all-originals-in-incarnation-v1`. It describes the claim's completeness
premise, not a verified retention implementation. A source that cannot establish
complete retained coverage at that selected position must not claim absence.
Pruning, retention duration, namespace retirement, disaster recovery, external
head selection and storage of nonrollbackable operation/charge/effect history
remain unimplemented. The existing Stage 45 policy digest intentionally does not
advance on charges/effects; it is not reused as a record-lineage certificate.

## Observation meanings and no-refund boundary

Every claim binds the complete selected query, root/source digests and challenge.
Non-unavailable claims must match both selected checkpoints exactly and include
the complete selected head profile and an exact Boolean active flag. The active
flag is only a claim and never permission. Original record status is separate
from the current head policy's active/revoked status.

| Observation | Required record shape | Meaning within this grammar |
| --- | --- | --- |
| `absent` | No original record; both checkpoints and head policy present | Claimed absence within the selected complete retention position only |
| `pending` | Complete original, positive charge sequence, no effect sequence | Claimed retained charge without a committed synthetic effect |
| `completed` | Complete original, positive charge and strictly later effect sequences | Claimed synthetic effect at or before the selected record position |
| `unavailable` | Both checkpoints, head policy and record are null | No asserted record or policy state; original query remains bound |

Charge/effect sequences cannot exceed the selected record position. These ordering
checks do not count all consumed charges, implement a cap, authenticate an event
log or prove an effect. Completion means the retained synthetic row vocabulary,
not a transaction receipt, chain finality, payment, physical entry or delivery.
No charge is refunded and no replacement operation is selected by this module.

Loss of a return is an unknown observation. Repeating a query can match identical
bytes without proving what the lost attempt observed. `unavailable` does not mean
`absent`; absence at an old position does not prove that no operation ever
happened, or that one cannot happen later. No observation automatically resolves
an unknown remote outcome, authorizes a retry, changes an id or allows work. A
caller must retain the complete original and rely on a separately assessed
authoritative reconciliation mechanism. That mechanism is not connected here.

Knowing an operation id or proposal digest does not authorize a caller to read
records. Lookup authorization, confidentiality, correlation limits and disclosure
of retained policy/usage metadata remain unresolved service-design gates. The
fixture uses synthetic values only; this grammar supplies no lookup endpoint.

## Required unsafe controls and evidence limits

- Same id with a changed proposal, revision or complete profile changes the
  query; an old claim cannot match it. Separately forged claims under both
  self-selected alternatives can still match. Actual collision refusal and
  atomic deduplication require retained source state.
- Different ids with the same proposal remain distinct. Proposal equality
  does not merge operations, refund charges or establish idempotency.
- A fresh challenge can be paired with the same old policy and original-record
  state. That fresh unsigned claim matches the new query. No signature math is
  executed in this stage; future historical signatures still cannot prove that
  the sampled state was current or retained.
- An all-ff root encoding and arbitrary source-profile/record-lineage pins can
  match. There is no curve check or source authentication here. Five distinct
  role encodings also do not prove separate controllers or operational custody.
- Coherent source restore and clones repeat an original charge and synthetic
  effect while the same selected historical framing still matches. The tests'
  arbitrary lineage digest is deliberately not an external trusted witness.
- A fabricated completed claim does not reenable a revoked pending effect or
  refund its retained local charge. There is no connection from a parsed claim
  to store admission or reconciliation.
- A response can age after selection and before delivery. A deliberately blind
  ideal list actuator can still use a historical record after revocation; that
  list is not an implemented physical-entry fence.
- Legacy assignment queries, claims, signed responses and signature packets are
  refused as original-read objects. Their historical signature successes supply
  no signature over this new original association.

The parser returns an immutable, defensively decoded **unsigned statement**.
It provides no authenticated/current/receipt/permit/refund flag. No selected
verifier callback exists in this stage. A later signature worker must have its
own exact schema/domains, independently selected trust boundary, cross-language
qualification and malicious-verifier controls; it must not reinterpret a legacy
response or turn a mathematical result into source truth.

## Reuse record and remaining gates

The grammar, fixture and tests are original project MIT material, reusing project
framing and profile/root decoders at `88527956a163a184dccca28590f6c7491fbb2576`.
No third-party source, passage or vector is copied and no dependency is added.
Existing signature workers, fixtures, locked dependencies and CI workflow remain
unchanged. The unsigned fixture SHA-256 is
`a0df63db7a366425bf789ac1c1c61c7fb1e9d9eec9d0ecb43b21331f356fb1cb`.

Next is isolated historical root/response signature qualification for this
explicit original-read schema. Signing domain/response envelope and role powers
are not selected by the present grammar. Actual authenticated current source,
operational response/root custody, complete external nonrollback policy/original/
charge/effect lineage, atomic original administrator-command commit/deduplication,
compromise/revocation recovery, lookup privacy and physical-entry fencing remain
separate unimplemented gates. Both fixed independent inventories and unfilled
reports stay unchanged; this later delta needs independent assessment.

Offline framing qualification is **GO**. Source integration, application signing,
core port, activation, deployment, wallet access, broadcasts and funds remain
**NO-GO**.
