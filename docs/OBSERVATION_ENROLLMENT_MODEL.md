# Canonical observation enrollment and quota ownership comparison

Status: **Stage 31 pure finite offline model. No enrollment owner, authenticated
source, authorization service, registry backend or dispatcher is implemented.**
Protected-resource identity and owner authorization are environmental facts.
An ideal finite result does not authenticate them or select a funded policy.

Source parent: [`3ecc884f1b5179f7adb977f6559f16fcf4e6c453`](https://github.com/edgepillar/ptlc-research/tree/3ecc884f1b5179f7adb977f6559f16fcf4e6c453).
Its [completed seven-job run](https://github.com/edgepillar/ptlc-research/actions/runs/37214410686)
qualifies the prior source, including the [candidate message contract](OBSERVATION_AUTHORITY_CONTRACT.md).
That contract binds selected public fields but owns no enrollment, target set or
shared quota. Different selected IDs, epochs or profiles can construct different
scope digests. This separate model asks which additional enrollment premises are
needed before using any digest as a quota key.

## Requirement, selected comparison and implementation boundary

| Requirement | Modeled choice | Evidence and missing mechanism |
| --- | --- | --- |
| Alternate labels cannot mint another allowance for one protected resource | Canonical lookup independent of caller label, epoch and profile | Scope-keyed and claimed-resource comparisons expose quota splitting; the actual resource equivalence relation and its provenance remain unselected |
| Knowing the resource does not grant owner permission | Independently supplied owner authorization for enrollment and every charge | Canonical-source comparison permits unauthorized events; the stronger policies assume authorization rather than verifying credentials |
| Two copies cannot both register the same missing canonical resource | One atomic uniqueness operation | Cached absence checks produce two records, even with identical labels and valid owner facts; no database transaction is implemented |
| Duplicate lookup cannot refresh a spent allowance | Exact duplicate binds the existing record; another label cannot replace it | Atomic-owner retains the charge across copies and lost bindings; no actual identity discovery, idempotency table or recovery protocol exists |
| Restoring the authority itself cannot refill allowance | Non-rollbackable registry and charge lineage | Rollbackable-owner reuses registration identity and replenishes quota; another coherently restorable database is insufficient |
| Separate protected resources keep separate allowances | Two independent canonical budget classes | Two charges to distinct resources are allowed; this is not a global host quota, aggregate resource guarantee or funding policy |

The [model](../scripts/model_observation_enrollment.py) imports no application
module, cryptographic library, worker, journal or storage code. Existing codec,
entry points, models, records/formats, qualifiers, workflows and dependencies
are unchanged. The model's `step` function must not become application admission.
A Boolean owner fact in a model is not an authentication certificate.

## Resource identity is an input

The default domain contains two synthetic protected budget classes, two caller
copies, five proposals per class and two independent owner-authorization facts.
Each proposal has an environmental `resource`, a caller `claimed_resource`,
opaque `label`, requested `epoch` and requested `profile`.

The five proposals for each class are its baseline and one change at a time:
another label, epoch, profile or claimed resource. Combined field changes and
additional classes are outside this selected domain. The environment's actual
class is used by the auditor to count protected-resource charges. It is not a
peer-selected truth field, an implementation of context verification or a wire
field added to the existing contract.

The equivalence relation is deliberately fixed, not inferred from a session ID,
funding ID, store path or profile digest. These two classes are not the two swap
legs. A future construction must specify which protected unit is budgeted and
why changed sessions, retained contexts, funding references, operators, profiles
or public labels refer to the same or a different unit. The model chooses none
of those mappings and supplies no chain observations.

Likewise, `owner_authorized` is an independent environmental premise for each
event. It is never derived from resource equality, a matching hash or a peer's
Boolean. The model does not select an owner key, pin establishment, delegation,
revocation, role-authentication protocol or public-witness recovery authority.
An honest funded recovery may require a different policy; no such policy is
qualified here.

## Six policies

1. `scope-keyed` indexes allowance by the full modeled selection, including the
   resource and caller variants. Even correct resource knowledge does not stop a
   new label/profile/epoch from opening another record. Owner permission is not
   checked, so unauthorized enrollment and charges are separate findings.
2. `claimed-resource` collapses labels to the caller's asserted resource bucket.
   An alias can open another bucket for the same protected class or charge a
   record originally bound to another class. Owner and profile/epoch checks are
   still absent. A stable caller assertion is not canonical source knowledge.
3. `canonical-source` uses the environmental canonical class and freezes epoch
   one/profile zero. Another label cannot replace the existing enrollment, and
   exact duplicate lookup shares its allowance. Without independent owner
   authorization, unauthorized registration and charges remain possible.
4. `checked-owner` additionally requires the independent owner fact at check,
   registration and charge. Each copy caches a missing-registration check, then
   allocates without revalidating absence. Two cached misses can create two
   canonical records, including for exactly the same label, and spend both quotas.
5. `atomic-owner` checks source/profile/epoch and independent owner permission,
   then uses one atomic canonical lookup/create. Exact duplicates share the same
   consumed record; a different label is refused. All selected reservations
   charge that record and check owner permission again. The registry cannot rewind.
6. `rollbackable-owner` has those same rules but permits one explicit coherent
   registry rewind. The auditor remembers previous registrations and charges;
   the restored registry does not. Fresh enrollment can obtain the same ticket
   and allowance again. Authorization and atomicity do not prevent that restore.

Registry `generation` labels the external auditor's trace. It is **not an
authenticated epoch, monotonic anchor or restore detector** supplied to clients.
An old binding cannot charge an empty registry or a differently labeled current
record, but reestablishing the same selected registration after rewind still
replenishes its budget. Refusing a mismatched binding is not anti-rollback defense.

## Ordering, losses and explicit limits

Enrollment and charge are separate abstract events. A charge consumes one unit
and is never refunded by binding loss, exact lookup or service return. A caller
may lose its retained lookup/binding once; the selected record and audit remain.
Outage refuses registration and charging with no local fallback. Return of the
service is another environmental event, not eventual availability or fairness.

The model defaults to allowance one per record, at most two total registration
events, two total charges, one binding loss and at most one registry rewind.
Reattached records create no new registration event. The audit survives rewind
only to report what protection was lost; it is not a backend capability.
Actor bindings, record consumption, registration identities and charge references
are checked for exact types and consistent finite partitions before transitions.

These charges are **not worker entries**. There are no processes, verdicts,
statements, target sets, request IDs, transport, secret nonces or result commits.
The [earlier dispatch model](OBSERVATION_AUTHORITY_MODEL.md) separately demonstrates
that even an externally charged receipt can start multiple abstract workers.
Canonical enrollment and shared charging cannot substitute for unique entry,
physical leases, resource limits, source trust or a remaining funded recovery path.

## Reproduction and results

Run from the repository root with no backend or network:

```sh
python3 -B scripts/model_observation_enrollment.py --policy scope-keyed
python3 -B scripts/model_observation_enrollment.py --policy claimed-resource
python3 -B scripts/model_observation_enrollment.py --policy canonical-source
python3 -B scripts/model_observation_enrollment.py --policy checked-owner
python3 -B scripts/model_observation_enrollment.py --policy atomic-owner
python3 -B scripts/model_observation_enrollment.py --policy rollbackable-owner
python3 -B scripts/model_observation_enrollment.py --max-states 1
python3 -B -m unittest discover -s tests -p test_observation_enrollment_model.py -v
```

The default search cap is one million states. Complete enumeration reports
`bounded-complete` and exit zero even when counterexamples are found. A cap
reports `incomplete` and exit two, never a security result. An initial 20,000-state
probe was incomplete for both naive policies; complete searches and regression
counts are recorded in [Stage 31 validation](STAGE31_VALIDATION.md). A separate
allowance-two trace exposes quota splitting but is not a complete larger-domain
search. Nothing here proves unbounded safety, liveness or a native transaction.

## Gates before an enrollment implementation

1. Define the protected resource and canonical equivalence relation, authenticated
   source evidence, owner authority and independently established pins. Dispose
   of changed-context/label/profile duplicates and first-registration capture.
2. Select atomic uniqueness and exact duplicate lookup semantics. Define an
   existing enrollment's immutable identity, requested limits and explicit
   rotation/reset authority without opening a second live allowance.
3. Anchor enrollment and charge lineage outside coherent restores. Qualify
   concurrent copies, native persistence faults, backup/restore, reply loss and
   power failure. A restorable row with matching hashes is insufficient.
4. Specify scoped request idempotency and uncertain reply reconciliation, then
   select and assess the trusted single-use dispatcher. Preserve source-journal
   authority, existing physical/resource limits and funded recovery exclusions.
5. Independently assess this exact model delta and every later construction.
   The fixed [119-file](INDEPENDENT_REVIEW.md) and [189-file](OBSERVATION_REVIEW.md)
   subjects and their unfilled reports remain unchanged; this work is outside both.

**Go:** use these counterexamples to specify and assess canonical enrollment,
owner authority, atomic uniqueness and non-rollbackable lineage. **No-go:** use
model inputs as authentication, claim implemented restore/clone or worker-entry
defense, select a production backend, connect private signing, port core rules,
activate a node or authorize real funds.

The later [Stage 32 content-key and unsigned owner contract](RETAINED_RESOURCE_INTENT.md)
selects a narrower equality class for seven public source commitments and a
separate owner-bound proposal. It does not implement this model's canonical
source/owner facts, atomic registry or non-rollbackable lineage. Changed source
and namespace remain explicit policy gates, and matching unsigned intent
replays. This model and both fixed subjects remain unchanged; see
[Stage 32 validation](STAGE32_VALIDATION.md) for the separate contract delta.
