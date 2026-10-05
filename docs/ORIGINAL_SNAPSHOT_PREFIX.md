# Test-only retained-prefix comparison

This isolated delta targets `8222457af79573aaa8acc277fc626b84fd7a5cd8`.
It compares two complete public synthetic retained openings relative to a
retained earlier witness. Both openings first pass the unchanged
[Stage 51 construction](ORIGINAL_SNAPSHOT_OPENING.md). The new
[helper](../tests/original_snapshot_prefix.py) and
[controls](../tests/test_original_snapshot_prefix.py) live under tests;
no application parser, witness store, source provider or lookup adapter is added.

## Requirements, selected experiment and verified behavior

| Layer | Statement |
| --- | --- |
| Protocol requirement | Establish complete original provenance, authenticated head authority, retained history, latest selection and current-use ordering as distinct requirements. |
| Selected experiment | Compare two complete bounded synthetic openings with independently selected queries. Require one exact complete root/source/incarnation and original tuple, then retain complete event/policy prefixes, original bindings, charges and completed effects. |
| Verified behavior | Actual absent/pending/completed and policy/mode extensions compare; coherent truncation, rewritten prior rows and divergent earlier history refuse relative to the retained earlier witness. |
| External premise | The caller independently selects and retains both complete queries and opening bytes. No authenticated selection, latest-head provider or nonrollback consumer retention is implemented. |
| Privacy boundary | Both inputs disclose complete public synthetic retained rows. This is not an authorized private lookup or selected minimal-disclosure application construction. |
| Open requirement | Source authentication, historical issuance, original provenance, lookup authority/privacy, signer custody, nonrollback source/consumer witnesses, administrative command deduplication/incarnation transitions, authoritative unknown-outcome reconciliation, protected-use ordering and independent assessment. |

Internal opening consistency alone permits a coherent truncated history to open
under newly self-selected diagnostic heads. Retaining a different earlier
witness supplies a comparison point which that truncated history cannot extend.
The origin, currentness and durable retention of the witness remain separate
requirements. The helper does not obtain an authoritative head or keep a witness.

## Complete selections and unchanged opening bounds

The caller passes two exact `OriginalReadQuery` objects and two exact immutable
opening byte strings. Query subclasses and byte subclasses refuse before
opening. Each query revalidates its complete factory-selected objects; both
openings must match their own selected policy and record commitments.
No incoming claim or signature-result flag supplies the comparison expectation.

Complete root declarations must be byte-identical, including declaration
revision, all role keys, source labels/incarnation, current profile and scope
pins. Complete original tuples must match, including id, revision, historical
profile and proposal digest. The challenge can differ; a new challenge does not
make retained old history current.

Policy revision, active flag and mode history can advance under the same complete
root and current profile. Revocation or a policy round trip therefore compares
when the entire retained history is consistent. Current-profile replacement,
cap changes requiring a different root, role reprovisioning and authorized
source-incarnation changes refuse. They need a separately specified authority
and transition construction; matching key labels do not establish continuity.

The helper uses the unchanged Stage 51 wrapper, grammar and finite bounds:
262144 bytes per opening, depth 16, 32 revisions, 33 policy rows, 64 originals,
64 effects and 256 events. Its validator still derives unsigned claims by
replaying complete event/row semantics and opening both diagnostic commitments.
Both non-live openings refuse; unavailable retains null facts in the separate
existing claim grammar and is never converted to absence or disclosure authority.

There is no new incoming wire protocol, response schema, commitment domain,
public fixture or signature worker. The output is a frozen unsigned scalar
`PrefixDescription` with a defensive dictionary. It records `same-history` or
`retained-extension`, both query digests, revisions/event positions, observations
and retained/appended original/effect counts. Constructing this description
directly proves nothing. It contains no permission, currentness, signature fact,
source capability, refund, recovery decision or use instruction.

## Retained-prefix rules

After both complete openings pass the unchanged validator:

1. Require the complete earlier event list to be an exact prefix of the later
   event list. Reversing an extension or changing a prior event refuses.
2. Require the complete earlier policy list to be an exact prefix of the later
   policy list. Event positions alone do not preserve historical profile bytes.
3. Retain every earlier complete original tuple and its exact charge position.
   The original list is id-ordered, so a new original may sort before an old row;
   retained rows are matched by id and complete tuple rather than list prefix.
4. Preserve every previously completed original row and synthetic effect exactly.
   An earlier pending original may stay pending or gain a unique effect only
   after the earlier event head. Complete opening validation binds that effect
   to the unique earlier charge and the live active policy at the effect event.
5. New originals and new effects must have positions after the earlier event
   head. Retained charges are never removed or refunded by completion.

Each opening independently checks complete event/row correspondence, historical
profile equality, temporal charge caps, final source state, canonical encoding
and finite bounds. The comparison does not loosen those checks. An extension
from actual empty history to 64 originals, 64 effects and 256 events fits the
unchanged byte bound; another actual control retains all policy rows through
revision 32. These finite tests do not establish unbounded performance.

## Forks, stale history and restored consumers

The [directed controls](../tests/test_original_snapshot_prefix.py) distinguish
the following limitations from the retained-prefix result:

| Control | Result and boundary |
| --- | --- |
| Truncated pending history or lost completed effect | Each coherent snapshot can open under its own selected heads, but it cannot extend the independently retained later witness. |
| Rewritten nonqueried original proposal or old policy profile | Event bytes may still form the same prefix and the queried original can be unchanged. Complete retained-row comparison refuses the rewrite. |
| Two different futures from one prefix | Actual cloned sources can complete one original on one branch and revoke it on another. Both individually extend the earlier pending witness; the two branches cannot extend each other. Two proposals for a newly appended other original can likewise share event bytes and both extend the prior prefix. No canonical future is selected. |
| Fresh challenge or later revocation | Identical old history remains replayable, and a correctly compared pending-to-completed extension remains openable after the actual source later revokes. Prefix consistency supplies no latest-head or current-use fact. |
| Coherent source and consumer restore | Retaining the completed witness detects restoration to pending history. Restoring the consumer's witness to the same old pending selection loses that detection. The actual synthetic effect can repeat at positions `[2, 2]`; even the two completed histories then compare as identical. No cross-consumer deduplication or rollback protection is implemented. |

The restored-effect test is a counterexample control, not an authorized recovery
algorithm. No unknown outcome is reconciled, retry selected, physical entry
performed or protected-use adapter connected. Consumer knowledge must survive
the source's copied-state domain for a retained witness to detect an older source.
Two coherent copies can still produce competing futures; authentication and
nonrollback provenance need separate evidence and independent assessment.

## Existing signature evidence and acceptance

All ten existing snapshot scenarios and six signed counterclaims remain intact.
Nine live identical comparisons reproduce the observations; the unavailable
case refuses full-row comparison. The three signed false-state claims disagree
with derived facts, the two complete-original collisions refuse, and freshly
challenged old absence remains historical. The comparison performs no signature
or curve mathematics; existing public mathematical verification stays in the
unchanged [actual-worker qualifier](../scripts/qualify_original_read_snapshot_response.py).

See [local validation](STAGE52_VALIDATION.md). All preceding helpers, application
modules, stores, samplers, journals, schemas, workers, fixtures, dependencies,
workflows, action/toolchain pins and fixed review inventories/reports remain
byte-preserved. Four existing documents gain only scope/evidence links.
Both independent reports remain unfilled; this delta is outside their fixed
subjects and requires separate consistency, retention and privacy assessment.

Offline qualification is GO within this stated boundary. Authenticated source
or recovery integration, private/application signing, core port, node activation,
deployment, wallet access, transaction broadcast, funded execution and protected
physical use remain NO-GO.
