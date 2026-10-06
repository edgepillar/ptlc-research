# Test-only public-signature composition of retained histories

This isolated delta targets `c4182664222b89f464cc2453b88898bdd42df09a`.
It composes the unchanged [complete opening](ORIGINAL_SNAPSHOT_OPENING.md)
and [retained-prefix comparison](ORIGINAL_SNAPSHOT_PREFIX.md) with the unchanged
historical public original-response checker. It derives both expected claims
from public synthetic rows before checking the incoming responses. No source,
private lookup, witness storage, signer, recovery or protected-use adapter is added.

## Requirements, selected experiment and observed behavior

| Layer | Statement |
| --- | --- |
| Protocol requirement | Establish authenticated head authority, original provenance, retained consistency, latest selection, signer custody and current-use ordering separately. |
| Selected experiment | Under the same complete root/source/incarnation and original tuple, open both independently selected histories, compare their retained prefixes and bind both existing public response packets to the derived claims. |
| Observed behavior | Existing actual signed histories compare. Two actual source forks can each extend one pending witness and pass public signature mathematics while refusing extension of each other. Neither future becomes canonical or latest. |
| External premise | Independent queries and opening bytes, selected checker/runtime trust and consumer witness retention are supplied externally. No authenticated selection or nonrollback witness store is implemented. |
| Privacy boundary | Complete retained-row disclosure uses public synthetic values only. This is not an authorized private lookup or selected minimal-disclosure construction. |
| Open gates | Authenticated source/latest heads, historical issuance/full original provenance, lookup authority/privacy, signer custody, nonrollback source and consumer witnesses, administrative command deduplication/incarnation transitions, authoritative unknown reconciliation, actual protected use and independent assessment. |

## Two expectations before either check

The [test-only helper](../tests/original_snapshot_prefix_response.py) accepts two
exact `OriginalReadQuery` objects, two exact immutable opening byte strings,
two exact existing response-envelope byte strings and a selected callback.
It requires callable checking and exact input types before opening any data.

The unchanged prefix helper opens both complete histories and requires the
earlier event/policy lists, complete original bindings, charges and completed
effects to remain retained. Both queries select their own diagnostic policy and
record heads. Complete root declarations and original tuples must match.
Root/profile replacement and authorized incarnation changes remain out of scope.

The composition derives both unsigned original-read claims with the unchanged
opening validator, then constructs both complete expected responses with the
existing grammar. Both incoming packets must match those expectations before
either callback runs. A malformed or differently bound second packet therefore
does not cause even the first checker invocation. Incoming claims and result
flags never supply the independent expectation.

Each existing response check then binds its result to that complete request.
If either check refuses, the composition returns no partial description.
Success returns the unchanged frozen unsigned `PrefixDescription`, with a
defensive dictionary and no signature fact, currentness, authority, permission,
refund, recovery decision, retry selection or protected-use instruction.

The opening bounds stay unchanged: 262144 bytes, depth 16, 32 policy revisions,
64 originals, 64 effects and 256 events per history. Existing envelope and
request bounds stay 16384 bytes. Non-live complete openings refuse. Unavailable
still has four null facts in the separate historical statement grammar and
never becomes absence or lookup authority.

## Framing controls and actual public mathematics

The [18 ordinary regressions](../tests/test_original_snapshot_prefix_response.py)
use explicitly dishonest callback controls which manufacture the existing
result flags. They test expectation derivation, ordering, complete request
binding, both-packet preflight, type/wire limits and sanitized refusal. They do
not perform signature mathematics or qualify an arbitrary callback as secure.

The separate [12-case actual-worker qualifier](../scripts/qualify_original_snapshot_prefix_response.py)
executes the unchanged bounded `PublicOriginalResponseCheck` with the existing
compiled public worker. It reuses the ten snapshot scenarios and six signed
counterclaims without generating any signature, key material, schema, domain,
fixture or worker. Its selected entry digest measures that executable; repeated
measurement is not atomic launch, a sandbox, release provenance or custody.
The construction needs independent assessment of those runtime premises.

| Actual public-worker control | Observation and limit |
| --- | --- |
| Nine live identical histories | Both complete expectations reproduce the existing responses and both checks pass without mutating the owned synthetic store. |
| Absent to pending to completed | Existing public responses bind all three histories; forward retained extensions compare and reverse directions refuse before checker work. Completion does not refund the charge. |
| Completed versus revoked pending fork | An actual cloned pending source produces two distinct futures. Both retain the earlier charge and have valid existing signatures; neither future extends the other. Revocation prevents the pending synthetic effect on that branch. |
| Three false-state statements | Their signatures pass under deliberately unsafe packet-selected expectations, but the statements disagree with independently opened rows and the composition refuses before checker work. |
| Two same-id tuple collisions | Independent synthetic queries differ in proposal or historical profile; complete retained originals refuse to open despite valid packet-selected signature mathematics. |
| Fresh challenge over old absence | A differently challenged signed old absence still compares after the actual source charges. A retained pending witness detects the older history; the fresh challenge supplies no latest-head fact. |
| Signed unavailable statement | Its standalone historical signatures pass with four null facts. Complete live-history composition refuses on either side. |
| Delivery after source revocation | A previously captured valid pending extension still compares after a separate writer revokes before delivery. Current resampling and synthetic effect refuse; comparison gives no use permission. |
| Source and consumer restore | Keeping a completed witness detects a restored pending source. Restoring that consumer witness too permits the old signed pending history to compare again, and synthetic effect positions repeat as `[2, 2]`. Each repeated completed extension has the same valid historical signatures. |
| Callback forgery | Two zero signatures can pass framing under a dishonest callback, but actual worker mathematics refuses zero signatures on either side. |
| Mode round trip and cached result | Policy heads can repeat while record history extends. Both actual signatures pass; a cached result for the other complete request refuses. |
| Changed selected executable | A changed entry measurement refuses before it can qualify the composed response. |

These are directed consistency and limitation controls. They do not implement
source authenticity, canonical fork choice, a latest-head protocol, durable
consumer knowledge, unknown-outcome reconciliation or authorized retry.
No physical entry or protected effect is connected; only synthetic SQLite rows
are used for the restore counterexample.

## Scope, fixed subjects and acceptance

All preceding application modules, helpers, stores, samplers, journals, schemas,
workers, fixtures and dependencies remain byte-preserved. Four existing documents
gain only scope/evidence links. The existing adaptor CI job gains one focused
post-build invocation; all earlier seventeen script steps, action/toolchain pins,
seven jobs, matrix and timeouts stay unchanged. No dependency or external code
is copied. Existing project attribution remains unchanged.

Both fixed independent inventories and their unfilled reports stay unchanged;
this delta is outside both subjects. Independently assess expectation provenance,
complete-row disclosure, callback/worker trust, fork/currentness limits and
nonrollback consumer retention. See [local validation](STAGE53_VALIDATION.md).

Offline qualification is GO within this stated boundary. Authenticated source
and recovery integration, private/application signing, core port, node activation,
deployment, wallet access, transaction broadcast, physical entry and funded use
remain NO-GO.
