# Test-only complete retained snapshot opening

This isolated delta targets `136eb9120455125899d900a68187cee757e2c663`.
It derives an unsigned historical original-read claim from complete public
synthetic retained rows. No incoming claim supplies its own expectation.
The helper lives under [tests](../tests/original_snapshot_opening.py); no
application import, public worker, source exporter, lookup service or signer is
connected. The [tests](../tests/test_original_snapshot_opening.py) use owned
synthetic stores and unchanged public fixtures.

## Requirements, selected experiment and verified behavior

| Layer | Statement |
| --- | --- |
| Protocol requirement | Independently select a complete root, original tuple, both heads and challenge; establish the authority of observations and the current-use boundary separately from signature mathematics. |
| Selected experiment | A bounded canonical input contains complete synthetic policy/original/effect/event history. The test-only parser checks internal event semantics and opens the two existing diagnostic commitments before deriving an unsigned claim. |
| Verified behavior | Nine live scenarios reproduce the existing complete claims. The tenth unavailable scenario refuses a full-row opening. Three signed false-state claims disagree with derived state, two complete-original collisions refuse, and freshly challenged old absence remains historical. |
| External premise | The complete query and its diagnostic heads are selected independently of incoming material. Their authentication, latest position and nonrollback retention are not implemented. |
| Privacy boundary | Complete retained rows are public synthetic test values. This is not a selected minimal-disclosure proof, authorized private lookup or application privacy construction. |
| Open requirement | Source identity, authenticated current heads, historical issuance, full original provenance, private lookup authority, signer custody, nonrollback retention, administrative deduplication/incarnation changes, authoritative unknown-outcome recovery, protected-use ordering and independent assessment. |

The [preceding model](ORIGINAL_READ_PROVENANCE_MODEL.md) used an owned claim as a
qualification oracle. This experiment instead derives that claim from material
which must open independently selected heads. It addresses internal consistency;
an unauthenticated or coherently restored selection can still describe the past.
The parser does not contact a source or discover an authoritative head.

## Selected test input and finite bounds

The input is a canonical ASCII JSON object with exactly `schema`, `purpose` and
`record_material`. Its test-only schema is
`ptlc-test-only-original-snapshot-opening-v1`; its purpose is
`synthetic-complete-retained-opening-only`. This wrapper does not replace any
existing response/worker schema. The input bound is 262144 bytes and decoded
container depth is at most 16. Duplicate keys, whitespace/trailing bytes,
numeric aliases, floats, oversized integers and noncanonical hex refuse.
Existing response/query byte bounds remain unchanged.

`record_material` reproduces the seven existing commitment fields:

| Field | Complete retained content |
| --- | --- |
| `root_declaration` | Exact complete independently selected declaration, including role keys, current profile, source context and declaration revision. Canonical byte equality prevents Boolean/integer aliases. |
| `retention_rule` | The existing `retained-all-originals-in-incarnation-v1` label; matching it is not evidence of real retention. |
| `source` | Revision, canonical profile hex, Boolean active flag and selected mode. |
| `policies` | Sequential revisions from zero, canonical historical profile hex, Boolean active flag and exact policy-event position. |
| `operations` | Strictly id-ordered unique complete original tuples, charge position and optional effect position. |
| `effects` | Strictly id-ordered unique synthetic effect rows with matching event position and fixed synthetic payload. |
| `events` | Sequential event position, kind, policy revision, optional original id and detail. |

The source has at most 32 revisions, 33 retained policy rows, 64 originals,
64 effects and 256 events. Profiles retain the existing 4096-byte grammar bound.
Owned-store tests reach revision 32 and separately reach 64 originals, 64 effects
and 256 events; their complete opening fits the separate input byte bound.
These finite tests do not establish performance for an unbounded deployment.

## Event semantics and commitment comparison

The parser replays rows in memory, independently of SQLite's validator:

1. Require the initial policy to be active at event zero and every retained
   profile to match the complete source authority/resource/role namespace.
2. Require source revision/profile/active to match the final retained policy and
   the profile in the independently selected root.
3. Bind every original to its complete id/revision/historical profile/proposal.
   A queried historical profile must match its retained row even for absence.
4. Replay sequential policy and mode events. Charge/effect events require the
   live active policy and the exact original revision/profile at that event.
5. Enforce the retained-charge cap at each charge event, without deleting charges
   on completion. An effect has one unique earlier charge and a matching row.
6. Require complete event/operation/effect correspondence and final mode/revision
   agreement. Missing, duplicate, reordered and orphaned history refuse.
7. Reproduce both diagnostic commitments and compare them to the complete query.
   Then derive absence, pending or completion and the actual head active flag.

Cap reduction is temporal: two old charges under an earlier larger cap remain
valid history when a later policy reduces its cap to one. A later third charge
under the reduced cap refuses. An opened pending claim grants no new admission.
Old originals retain their old complete profile and owner after current profile
replacement; they do not inherit the new owner's authority.

The unchanged [policy commitment](../qualification/source_read_ordering.py) is
SHA256 over `PTLC/offline-local-policy-read-state/v1\0` and canonical complete
root/revision/profile/active/mode. The unchanged
[record commitment](../qualification/original_read_snapshot.py) is SHA256 over
`PTLC/offline-local-original-record-lineage/v1\0` and canonical seven-field
material. Both domains include the terminal NUL byte. Tests pin these domains
to the existing implementation. A mode round trip can reproduce the policy
digest while changing the complete record commitment.

No commitment is an authenticated latest-head certificate. Correctly rehashing
altered material cannot make it match an independently retained different head.
Self-selecting a different head can make coherent truncated history open as
absence; a directed control demonstrates this while the actual owned source
still retains a pending charge. External head/retention provenance remains a gate.

## Claim, signatures, outage and restored history

The return is the existing frozen unsigned `OriginalReadClaim`. It contains no
signature-verification fact, permission, registry mutation, source capability,
allocation, refund, retry instruction or recovery decision. Caller dictionary
mutation does not change its retained bytes.

The three unchanged signed false-state packets still carry public mathematical
signatures, but their absence/completion/active assertions disagree with the
derived claim. Existing response framing refuses them against the derived
expectation before mathematical work. Same-id proposal and historical-profile
collisions refuse even when both diagnostic heads open. The six signature
fixtures and the separate [actual worker qualifier](../scripts/qualify_original_read_snapshot_response.py)
remain unchanged; this parser performs no signature or curve mathematics.

Fresh challenge over an old empty snapshot still derives historical absence
under the old selected heads. After the actual source charges, the old opening
refuses against new heads but still opens against its retained old selection.
Revocation after sampling similarly leaves old active history replayable.
A coherent restore reproduces diagnostic heads and can repeat the separately
executed synthetic effect. The opening supplies no rollback prevention.

The unavailable fixture retains null state facts in the existing claim grammar.
This full-row experiment refuses every non-live source mode. Unavailable does
not mean absence and gives no entitlement to disclose complete retained rows.
Ambiguous or known-compromised modes similarly supply no derived claim here.
No lookup result clears an unknown original outcome or authorizes physical entry.

## Acceptance and open gates

See [local validation](STAGE51_VALIDATION.md). All prior application modules,
samplers, workers, schemas, fixtures, stores, journals, dependencies, workflows,
toolchain/action pins and fixed review subjects remain byte-preserved. Existing
full-suite discovery runs the new tests without adding CI steps or changing pins.
Both fixed independent reports remain unfilled. This delta is outside their
fixed inventories and needs separate independent consistency/privacy assessment.

Offline qualification is GO within this boundary. Source or recovery integration,
private/application signing, core port, node activation, deployment, wallet access,
broadcast, funded execution and protected physical use remain NO-GO.
