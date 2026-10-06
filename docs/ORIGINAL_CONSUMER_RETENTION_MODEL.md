# Bounded original-read consumer retention

Stage 54 separates preserving one consumer's knowledge from selecting a
canonical history shared by consumers. It is an offline, test-only schedule
experiment. No application witness storage or current-head protocol is selected.
The [model](../scripts/model_original_consumer_retention.py) and
[regressions](../tests/test_original_consumer_retention_model.py) extend the
[historical delivery model](ORIGINAL_READ_PROVENANCE_MODEL.md) and
[signed-prefix experiment](ORIGINAL_SNAPSHOT_PREFIX_RESPONSE.md).

## Requirements and selected experiment

A consumer that has retained a complete historical witness should refuse an
older or incompatible history relative to that witness. Comparison must bind the
independently selected complete Root, source context, original tuple, both heads
and claim before interpreting signature validity. A valid response must not
select its own expected query or erase known completed effects.

These requirements do not define authenticated head selection, issuance,
canonicality, private lookup, a retention backend or an application capability.
An authenticated nonrollback anchor, its custody, availability and recovery
rules remain unresolved. Independent consumers do not acquire agreement merely
by each preserving a prefix. Root/profile/incarnation migration remains separate.

The selected experiment reuses the unchanged ten snapshot scenarios and six
counterclaims. Opaque event symbols describe nine complete live histories.
Tests compare all 81 live pairs against the unchanged complete-opening and
retained-prefix helpers. The existing statement model supplies complete query
and claim symbols; no revision-only ordering or hash arithmetic is substituted.
The unavailable sample has four null state facts and cannot retain a live opening.

Every comparison policy first requires independent snapshot binding and a
complete live opening. The three policies differ only in retained knowledge:

| Policy | Comparison witness | Restore behavior |
| --- | --- | --- |
| `replace-witness` | No previous-prefix check | Unsafe control replaces known history with any independently bound live sample. |
| `retained-prefix` | This consumer's copied local witness | Refuses older and incompatible histories until coherent consumer restore loses that witness. |
| `ideal-nonrollback-prefix` | An ideal witness outside both copied-state domains | Retains prior knowledge through consumer restore, conditional on the external premise. |

The ideal witness is not an implemented store, certificate, quorum, canonical
oracle or storage guarantee. Comparison and retention are one serialized abstract
event per consumer; real concurrent writers and durable atomic ownership are not
qualified. An observer's trace audit survives restores only to expose lost
knowledge. Neither of the first two policies consults that audit as authority.

## Executed finite domain

Two consumers each retain their own witness and designated saved copy. The source
copy can complete, revoke, lose availability, return live or coherently restore.
An external synthetic-effect count stays outside source restore. Cached delivery
values are selected immutable historical fixtures, independently of the source
copy's event order; this is not a causal network-emission protocol. An apparent
mismatch with the modeled source view is a boundary observation, not authenticated
evidence of a latest canonical state.

Each schedule has at most eight events and four deliveries. Source restore occurs
at most once, consumer restore at most once per consumer, and at most two external
synthetic effects are recorded. Within each selected stream, event order is fixed;
only shuffles between streams are enumerated.

| Selected stream set | Schedules | Transitions |
| --- | ---: | ---: |
| Opposite orders of completion and revocation futures | 30 | 150 |
| Completion followed by delayed fresh-challenge old absence | 30 | 150 |
| Source and consumer restore with repeated synthetic effect | 560 | 4480 |
| Unavailable delivery and a distinct live mode-round-trip future | 90 | 540 |
| Total per policy | 710 | 5320 |

Across the three policies this is 2130 selected schedules and 15960 transitions.
Directed regressions separately cover all ten samples, six counterclaims, cold
bootstrap, Root boundaries, callback forgery, null facts and strict finite budgets.
They are not extra branches in the enumerated domain. A schedule cap reports
incomplete and returns exit 2, including cap zero; a complete result covers only
the listed stream sets, not a full action graph or an unbounded theorem.

Run the complete comparisons from the repository root:

```sh
python3 -B -m scripts.model_original_consumer_retention --policy replace-witness
python3 -B -m scripts.model_original_consumer_retention --policy retained-prefix
python3 -B -m scripts.model_original_consumer_retention --policy ideal-nonrollback-prefix
```

## Observed behavior and limits

In the selected schedules, the replacement control accepts both older and
incompatible histories after previous knowledge. Prefix retention refuses those
deliveries while the witness remains available. Coherent consumer restore permits
an old pending history after prior completion; the ideal external witness refuses
that regression within this domain. Neither prefix policy prevents two consumers
from retaining different valid futures that extend the same pending prefix.

Real owned-store regressions reproduce completion/revocation forks, delayed old
absence, null unavailable facts and source restore with synthetic effects `[2,2]`.
A consumer can detect a restored old head while the restored source still repeats
its synthetic effect. Detection is not source deduplication or reconciliation.
A cold consumer with no earlier witness cannot distinguish a valid old first
choice from a current one through prefix comparison alone. Outcomes remain unknown;
no policy authorizes retry, refund, protected entry or recovery.

This model performs **no signature mathematics**. Signature-validity symbols are
premises associated with named public fixtures. A separate callback-flags control
can accept zero signatures and is explicitly unsafe. The retained actual-worker
groups, including the Stage 53 signed-fork/restore group, execute public historical
signature checks separately. Their success does not establish source ownership,
historical issuance, canonicality or current authority.

All complete-row values are public synthetic test material. Disclosure minimization
for a real source remains unresolved. Existing fixtures, workers, store, samplers,
application logic, fixed inventories and unfilled independent reports remain
unchanged. One focused CI comparison step is added to the existing Python jobs.

**GO:** bounded offline qualification and independent review of this separate
delta. **NO-GO:** application witness integration, authoritative head selection,
source signing/custody, private lookup, recovery, protected use, core port,
activation, broadcast or funded use. See [validation](STAGE54_VALIDATION.md) and
[current-authority evidence](CURRENT_AUTHORITY_EVIDENCE.md).
