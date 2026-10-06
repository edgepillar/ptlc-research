# Current-authority evidence and use ordering

Status: **Offline read-framing qualification only. No current-authority source,
source authenticator, backend or use-time authorization is implemented.**

The [Stage 38 public checks](GOVERNOR_SIGNATURE_QUALIFICATION.md) verify two
mathematical statements under independently selected keys. Neither statement
provisions the issuer, authenticates a policy service, proves its latest head or
allows an existing worker to start. Stage 39 specifies these missing requirements
and adds a pure checkpoint-bound read query and forgeable response-claim parser.
The [validation record](STAGE39_VALIDATION.md) separates executed checks from
the unresolved mechanisms and independent assessments.

The unchanged signature framing, source/profile definitions and finite governor
comparison are pinned to parent commit
[`295dd90234c2aac246f753a05698351aee809bdf`](https://github.com/edgepillar/ptlc-research/tree/295dd90234c2aac246f753a05698351aee809bdf).
This stage adds separate requirements and read bytes; it makes no new claim about
an external authority implementation.

## Requirements before selecting a source

The following are requirements, not claims about a running implementation.
The abstract reference trust model is an independently provisioned policy service
whose policy changes and protected-use decisions have one serialization order.
Its source identity, provisioning root and incarnation cannot be replaced or
rewound by a proposal, restored local journal or copied credential. This is a
candidate model for assessment; a database, consensus system, endpoint, transport,
authentication construction and operational owner have not been selected.

| Requirement | Required evidence and boundary |
| --- | --- |
| Independent provisioning | A trusted process authorizes an exact root and policy source for a resource, namespace and governor role. A valid assignment signature under a self-selected issuer supplies none of this. |
| Issuer delegation | The provisioned source establishes the issuer's role and delegation scope. Assignment-key validity is separate from the provisioning root and source-response authentication key. |
| Source provenance | Authenticate the exact source configuration, incarnation and response, including the complete query. A source label or configuration hash alone is no provenance. |
| Policy interpretation | Publish an unambiguous mapping from authoritative source state to the complete governor assignment: issuer, owner, role, resource, all six namespace/epoch/profile pins and both caps. An opaque state hash or scope hash cannot provide that mapping. |
| Current-state read | Establish that the authenticated response was evaluated at a current position in the trusted serialization order. A matching checkpoint, timestamp, challenge or valid retained signature is insufficient by itself. |
| Revision and incarnation | Define non-rollbackable source history. Revision reset requires independently authorized new incarnation and root-transition evidence; restoring the previous incarnation cannot restore permission. |
| Update and revocation | Order cap/policy changes, issuer and owner rotation, root/source rotation, suspension and revocation relative to protected use. History must distinguish valid past statements from current authority. |
| Availability | An unavailable, unauthenticated, ambiguous, stale or inconsistent source cannot create a new protected use. Do not fall back to a cached active claim or another peer-selected source. |
| Use ordering | Recheck all applicable policy at the defined authorization instant, atomically with the protected-use decision. A successful read followed by separate use leaves a revocation race. |
| Separate state ownership | Canonical resource enrollment, scoped idempotency, non-rollbackable charge lineage and unique worker entry require their own reviewed mechanisms. Policy evidence cannot replenish quota or repair journals. |

An issuer credential and an authenticated source response are separate statements.
The root may delegate distinct keys for each. Which keys, delegation path,
compromise policy and rotation protocol are used remains unresolved. An initial
key pin must not silently become an authority for arbitrary namespaces or roles.
Root compromise requires independently trusted recovery; a compromised root
cannot prove its own replacement safe.

## Selected offline read construction

[The pure module](../offline_session/current_authority_contract.py) selects one
comparison unit: **an exact assignment read at an independently selected policy
checkpoint**. It does not ask or prove that this checkpoint is latest. All inputs
must be selected independently of an incoming query or reply. Selecting them
from that same untrusted reply is circular even when every byte matches.

The eight-field source context contains `schema`, `source_id_hex`,
`source_profile_digest_hex`, `source_incarnation_hex`, `provisioning_root_key_hex`,
`resource_digest_hex`, `authority_id_hex` and the fixed governor `role`. Its digest
uses `PTLC/observation-policy-source-context/v1` followed by a zero byte and its
canonical JSON. The root-key encoding is a separate pin from the issuer key in
the signed assignment. No curve check, delegation proof or authentication runs.
Equal root/issuer bytes are representable; they establish no role separation.

A policy checkpoint contains only `revision` and `policy_state_digest_hex`.
Revision is an exact integer from zero through `9007199254740991`; no ordering,
clock, increment, rollover or freshness is inferred. The state digest is an opaque
independent pin, not decoded policy evidence. This is distinct from the quota
[authority contract's](OBSERVATION_AUTHORITY_CONTRACT.md) consumed/pending head.

The eight-field query contains:

1. The fixed `schema` and `operation = read-assignment-at-checkpoint`.
2. The complete source context and exact expected policy checkpoint.
3. An independently selected `challenge_hex`.
4. The complete Stage 38 five-field governor signature request, including both
   public signatures, the complete assignment and the v2 owner intent.
5. The decoded requested scope and retained-resource object from the independently
   prepared bound intent. Preparation revalidates all six profile pins, both
   requested limits, retained-source commitments and assignment/intent binding.

The query digest uses `PTLC/observation-policy-read-query/v1` followed by a zero
byte and the entire canonical query. This is a new read digest, not the issuer
message, owner message or Stage 38 verifier-result digest. Public signatures are
framed, not verified here. The decoded objects expose the selected requested
limits; their matching hashes do not authenticate the underlying chain or
establish economic equivalence. These research objects are not a public network
request design or a decision to disclose a live session's metadata.

The seven-field response claim contains `schema`, `query_digest_hex`,
`source_context_digest_hex`, `challenge_hex`, `observation`, `claimed_checkpoint`
and `assignment_digest_hex`. The selected observations have these shapes:

| Claimed observation | Checkpoint | Assignment digest | Effect of parsing |
| --- | --- | --- | --- |
| `active` | Exact selected checkpoint | Exact complete selected assignment | Matched public label only |
| `revoked` | Exact selected checkpoint | Exact complete selected assignment | Matched public label only |
| `absent` | Exact selected checkpoint | Null | Matched public label only |
| `unavailable` | Null | Null | Matched public label only; no fallback or refund |

All messages use compact sorted ASCII JSON with exact fields, lowercase 32-byte
hex pins and a 16384-byte bound. Both parsers refuse extra fields, duplicate or
escaped key aliases, alternate numeric encodings, whitespace, trailing newline,
deep or oversized wire, cross-selection replacements and changed bindings. This
format has no source signature, membership proof or assertion of latest state.
No authenticated-evidence adapter is supplied. Anybody can construct an exact
`active` claim, including for a query carrying all-zero public signatures.

The [synthetic public vector](../qualification/fixtures/current_authority_contract.json)
fixes one independently prepared query and all four claim shapes. Its governor
packet preserves the old public vector bytes. The [32 directed tests](../tests/test_current_authority_contract.py)
check exact framing and boundary counterexamples; they are not an independently
implemented source verifier or security assessment. Original project framing is
MIT material; no new dependency or third-party dataset is introduced.

## Required use order and missing implementation

The next construction must name a precise authorization instant. The existing
[finite governor comparison](GOVERNOR_AUTHORITY_MODEL.md) uses indivisible abstract
`use`. It assumes an independently trusted non-rewindable world at that instant;
it is not an implementation of the following sequence.

1. Independently provision the source, resource, namespace, role and delegation
   rules. Obtain policy state through the selected authenticated current-read
   mechanism. Do not bootstrap these expectations from the proposal.
2. Independently prepare the complete decoded request and assignment and qualify
   both issuer and owner signatures over their separate exact domains. Bind all
   retained commitments, pins and requested limits. Signature math cannot recover
   missing policy provenance.
3. Establish canonical resource identity and the existing enrollment/charge
   lineage under separately reviewed ownership and idempotency rules. A read
   challenge, owner request ID or local OS lock supplies none of these.
4. At the defined protected-use instant, validate current source incarnation,
   issuer delegation, complete assignment, owner, pins, caps and revocation in the
   same serialization order as the irrevocable decision. Repeated requests must
   consult the same durable scoped operation record without another charge or
   independent dispatch. The actual atomic storage/actuation mechanism is missing.
5. Record the decision and outcome without treating a timeout or lost reply as
   absence. Reconcile the original operation; do not issue a fresh duplicate.
   Root rotation, restart, journal restore and source outage must retain the same
   trusted history and committed-use meaning.

Whether protected use means durable allocation, committed dispatch or actual
worker entry must be resolved with the source and dispatcher design. These are
different instants. A source transaction that checks policy and writes a permit
does not alone fence later process entry. A proposed permit lifetime, fencing
rule or revocation cutoff requires an explicit safety argument and independent
assessment. Revocation after an already committed use is not retroactively a
failure of that earlier decision; it must prevent later uses according to the
selected cutoff. No cutoff or permit mechanism is selected by this stage.

## Mandatory stale, replay, restore and outage counterexamples

| Sequence | Executed or required conclusion |
| --- | --- |
| Read active; update caps or rotate owner; use retained read | Stage 36's cached-current policy can admit old authority. Stage 39 still parses the retained claim; it supplies no use gate. |
| Read active; revoke; separate use | Only an independently current check ordered atomically with the selected use decision closes this model race. There is no runtime implementation. |
| Select newer checkpoint; replay old reply | Stage 39 refuses the old binding. Keeping the old selection instead still matches; exact equality is not freshness. |
| Authorize new source incarnation with revision zero | New independently selected source context has another digest and refuses the old claim despite the same revision. This does not implement trusted rotation or non-rollbackability. |
| Restore old source pins, query, checkpoint, challenge and reply together | The coherent copy matches again. Current trusted source history must remain outside that rollback domain. |
| Reuse the same query/challenge | Both query and claim replay. There is no consumed challenge set, registration or unique dispatch. |
| Choose a new challenge and forge a matching active reply | The parser still matches. A challenge needs authenticated live evaluation and durable use ordering, not just a different label. |
| Source unavailable after an old active read | The unavailable shape has no head or assignment; the old active claim remains parseable. An actual source gate must fail closed for new use, without cached fallback or refund. |
| Parse any observation after an exhausted journal reopens | Real journal state/sequence/database/anchor bytes and consumed recovery allowance remain unchanged; recovery still refuses before its callback. |

## Acceptance gate before an adapter or runtime connection

Select and document the actual source, trust distribution, delegation and rotation
mechanism; authenticate the complete query/result and decode authoritative policy.
Demonstrate current-read semantics and failure behavior against stale replicas,
rollback, cloned clients, partition/outage, conflicting heads and source compromise.
Define the protected-use instant and prove its policy/lineage/dispatch ordering.
Then obtain separate independent assessment of these mechanisms and later deltas.
Both existing fixed subjects and unfilled reports remain unchanged.

The current stage is **GO for offline qualification only**. A source adapter that
claims current authority, application admission, production signer, node core
port, activation, deployment and funded recovery remain **NO-GO**. The existing
workers, journal entry points, crypto constructions, dependencies and CI workflow
are unchanged.

The later [Stage 40 source/use model](POLICY_SOURCE_USE_MODEL.md) compares
conditional commit and entry cutoffs with ideal durable scoped operation records.
It makes lost replies, source-ledger restore and actual-entry limits explicit,
without authenticating this read contract or connecting it to runtime admission.
Its selected schedules and directed faults remain separate evidence; see
[validation](STAGE40_VALIDATION.md).

The later [Stage 44 public response qualification](SOURCE_RESPONSE_SIGNATURE_QUALIFICATION.md)
checks four historical signatures over this complete read framing in an isolated
worker. This pure read contract remains unsigned. A newly challenged old active
response can still verify; no serialized current read or operational source is
connected. See [validation and explicit unsafe controls](STAGE44_VALIDATION.md).

The later [Stage 45 local read experiment](LOCAL_SOURCE_READ_ORDERING.md) samples
this complete query and an unsigned response under one owned SQLite transaction.
It refuses a stale selected local checkpoint after managed policy changes, while
coherent source restore and clones still replay. Original-operation association
is unsigned, operational source authentication is absent, and a read can age
before return. No application admission or physical-use fence is connected. See
[validation](STAGE45_VALIDATION.md).

The later [Stage 46 original-read grammar](ORIGINAL_OPERATION_READ_CONTRACT.md)
separately binds complete original-operation identity, policy and retained-record
positions without changing any earlier signature schema. Old originals retain
their complete historical profile under a fixed same-incarnation lookup rule.
The four record observations are unsigned and forgeable; matching bytes prove
neither absence, completion, current truth nor nonrollbackable retention. No
source adapter or unknown-outcome recovery is connected. See
[validation](STAGE46_VALIDATION.md).

The later [Stage 47 original-response signature qualification](ORIGINAL_READ_RESPONSE_SIGNATURE_QUALIFICATION.md)
checks selected historical root and response bytes under separate framing. The
complete old original profile and both policy/record positions are bound, while
current-read authentication, independent source heads, old-profile provenance,
lookup privacy and nonrollback retention remain external gates. Freshly challenged
old active statements still verify; no live source, application recovery or
physical-entry ordering is implemented. See [validation](STAGE47_VALIDATION.md).

The later [Stage 48 original snapshot experiment](ORIGINAL_READ_SNAPSHOT_QUALIFICATION.md)
reads actual retained originals and both local checkpoints in one owned SQLite
transaction. Historical profile equality is checked against retained local policy
history; complete record material is hashed deterministically. These checks supply
local consistency, not authenticated historical issuance or nonrollback lineage.
Native read/writer/death controls expose delayed delivery, while coherent original
replacement and source restore/copy still succeed under replaced local selections.
No signer, authenticated source, recovery or physical-entry adapter is connected.
See [validation](STAGE48_VALIDATION.md); both independent assessments remain unfilled.

The later [Stage 49 sample-to-signature qualification](ORIGINAL_READ_SNAPSHOT_SIGNATURE_BINDING.md)
recreates actual local snapshots as exact public synthetic signed messages under
the unchanged historical worker. Six validly signed false/conflicting/stale
counterclaims still pass mathematics when selected from the packet itself;
actual independent expectations refuse them before work. Restored/cloned state
and delayed delivery still preserve valid historical math without current truth.
No application signer, source service, lookup authority or recovery is added.
See [validation](STAGE49_VALIDATION.md); both independent reports remain unfilled.

The later [Stage 50 provenance/delivery model](ORIGINAL_READ_PROVENANCE_MODEL.md)
compares expectation binding against the unchanged ten actual public samples and
six signed counterclaims. Separate delivery and ideal entry events expose old
valid reads, coherent source restore and repeated original entry. Its external
current facts and nonrollback audit are assumptions; no source authentication,
application permission or unknown-outcome recovery is implemented. Selected
schedules are not a full action graph. See [validation](STAGE50_VALIDATION.md);
both fixed independent reports remain unfilled.

The later [Stage 51 complete-opening experiment](ORIGINAL_SNAPSHOT_OPENING.md)
derives unsigned claims from public synthetic retained rows which must open both
independently selected diagnostic heads. Three signed false-state claims disagree
with derived facts; two original-tuple collisions refuse; old freshly challenged
absence can still open as history. Complete-row disclosure is test-only, and
source authentication, current heads, nonrollback retention and authorized private
lookup remain unresolved. See [validation](STAGE51_VALIDATION.md); both fixed
reports remain unfilled.

The later [Stage 52 retained-prefix experiment](ORIGINAL_SNAPSHOT_PREFIX.md)
compares two complete synthetic openings relative to a retained earlier witness.
Coherent truncation and rewritten prior rows refuse; two different futures can
each extend one prefix, and old or coherently restored witnesses still compare.
Source authentication, current heads and nonrollback consumer knowledge remain
external premises. Complete-row disclosure is test-only; no application witness
store, source service, signer, private lookup, recovery or use adapter is added.
See [validation](STAGE52_VALIDATION.md); both fixed reports remain unfilled.

The later [Stage 53 signed-prefix composition](ORIGINAL_SNAPSHOT_PREFIX_RESPONSE.md)
independently derives both complete claims before checking the existing public
historical responses. Actual signed completion and revocation futures each
extend a pending prefix but cannot extend each other; neither selects canonical
or latest authority. Fresh challenges, stale delivery and restored consumer
knowledge retain their separate limits. No source authentication, witness store,
signer, private lookup, recovery or protected-use adapter is added. See
[validation](STAGE53_VALIDATION.md); both fixed reports remain unfilled.

The later [Stage 54 consumer-retention model](ORIGINAL_CONSUMER_RETENTION_MODEL.md)
enumerates bounded delivery shuffles for two separate consumers. Prefix retention
does not produce agreement on competing valid futures; coherent consumer restore
can lose completion knowledge. An ideal witness outside copied state illustrates
an external nonrollback premise, without selecting a storage or authority
construction. Signature symbols remain separate from actual-worker evidence.
See [validation](STAGE54_VALIDATION.md); both fixed reports remain unfilled.
