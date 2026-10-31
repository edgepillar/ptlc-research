# NoM reference client protocol candidate

Status: **M1 design candidate; NOT independently assessed.** This document
specifies a narrow CANDIDATE-02 NoM-to-NoM reference client. It selects no
application signer, operational observer, finality depth or safe funded timeout.
The initial `reference_client` slice is deterministic public-input tooling only.
Application/core acceptance remains **NO-GO** and recovery authority **NONE**.
No statement here authorizes a node, spork, wallet, signature, broadcast or funds.

## Source and implementation subjects

| Subject | Selection and evidence boundary |
| --- | --- |
| Contract/account behavior used by this design | [go-zenon `77ba9c7ee8c881e90911946756cdb67d8b586043`](https://github.com/zenon-network/go-zenon/tree/77ba9c7ee8c881e90911946756cdb67d8b586043), tree `57da4b9588e053facfdb8299181fe15a8ad2a223` |
| Separately tracked upstream head | [`821bdd25eabacbf8a07b6310986f38713f27b4e3`](NOM_DEV_821BDD2.md); complete source inventory, shared-path impact and a separately [accepted finite Linux comparison](NOM_DEV_821BDD2_NATIVE.md); no behavior/journal pin upgrade or complete admission proof |
| Historical codec profile | `zenon-ptlc-unlock:v1`; its historical PR #138 source selection and existing manifests remain unchanged |
| New implementation target | `reference_client`: Python public terms/ABI/hash and presignature-request tools; `public_crypto`: a separate public relation checker using the already pinned backend; synthetic signing remains confined to qualification tests |
| Existing executable evidence | Component-specific source, runtime, run and platform selections in the existing qualification documents; no old result is relabeled as a result for this design |

The [77ba9c7 source comparison](NOM_DEV_77BA9C7.md) identifies unchanged PTLC
files and changed shared VM paths. The [821bdd2 tracking corpus](NOM_DEV_821BDD2.md)
adds a complete inventory and a proportionate finite native selection. Its
recorded Linux comparison does not establish complete current-source admission. The
[historical fixed-recipient subject](NOM_FIXED_RECOVERY.md), its
journals, original bytes and independent-review records remain separate. A new
client must not silently migrate their source pins, formats or guarantees.
The linked upstream implementation remains GPL-covered; this document copies no
node implementation. Selecting JSON-RPC does not itself establish distribution
license compatibility.

## Scope, actors and commitments

The candidate has two parties and two independent account owners. Alice funds
the long-expiry leg with Bob as its fixed recipient. Bob funds the short-expiry
leg with Alice as its fixed recipient. Each leg uses a distinct single-signer
BIP340 lock key and `PointTypeBIP340` (`1`). Both adaptor pre-signatures bind the
same full compressed secp256k1 point `T = tG`; Alice alone initially knows `t`.
Wildcard destinations, scalar-lock entries, aggregate NoM keys, arbitrary ZTS
support, discovery, routing and production wallet integration are outside this
candidate. Native token identifiers and integer amounts are explicit terms;
synthetic allocations must never be described as real asset custody.

The account key that signs a send is separate from its leg's BIP340 lock key.
Direct `Unlock` uses the send account as the destination, so Alice sends the
short Unlock and Bob sends the long Unlock. Reclaim is sent by that entry's
creator. A different fee payer requires the separately scoped `ProxyUnlock`
path; it cannot silently replace a direct Unlock original.

Before either party funds, both retain the same public agreement: protocol
version, session identifier, node source selection, chain identifier, genesis,
PTLC contract, party addresses/roles, leg lock public keys, `T`, exact token
identifiers/amounts, expiries, declared timing and observation policies, and any
fee-candidate policy. `0 < E_short < E_long` is necessary, not a safety proof.
The candidate's initial offline terms inspector accepts chain identifier `69`
only. That number alone identifies neither a particular genesis nor an active
devnet, and a supplied genesis value is an unverified claim.

Entry identifiers are **not known before funding**: each is its actual Create
send hash. Bind the long entry after successful long Create execution and
before Alice releases its pre-signature. Bind the short entry after successful
short Create execution and before Bob releases its pre-signature. These are
append-only extensions of the same economic agreement. A changed Create hash
requires a newly checked funding binding; it must not be accepted by relabeling
an old witness or a claimed entry identifier.

The initial `inspect-terms` input is a complete, declared public projection with
both entry identifiers supplied. It is suitable for post-funding inspection and
offline fixtures. It implements neither the staged agreement nor proof that
either Create occurred. Its digest commits to those supplied claims; it does not
authenticate counterparty agreement, key ownership, curve validity, funding,
currentness, spork activation, economic margins or permission to act.

The implemented projection schema is `ptlc-nom-client-terms-v1` in
[`reference_client/plan.py`](../reference_client/plan.py). It has exactly
`schema`, `source_commit`, `session_id_hex`, `chain_id`, `genesis_hash_hex`,
`alice_address_hex`, `bob_address_hex`, `adaptor_point_sec1_hex`,
`minimum_expiry_gap_seconds`, `long` and `short`. Each leg has exactly
`entry_id_hex`, `funder`, `recipient`, `funder_key_xonly_hex`,
`token_standard_hex`, `amount` and `expires_at`. Fixed-width hex is lowercase:
32-byte session/genesis/entry/key, 20-byte addresses, 33-byte `T` and 10-byte
token identifier. Amounts are positive canonical decimal strings below `2^256`;
expiries and the declared minimum gap are positive decimal strings below `2^63`.
Roles, distinct payable party addresses, distinct leg keys/entry identifiers,
the compressed point prefix and the declared expiry-gap relation are checked.
Curve membership and safe timing are not checked. The terms digest is SHA-256
of the schema name, a zero byte and the complete canonical supplied projection;
it includes both claimed entry identifiers. A pre-funding economic commitment
and explicit operational timing/observation policies are later separate work.

The inner Unlock message is SHA3-256, not legacy Keccak, of the exact 101-byte
preimage: ASCII `zenon-ptlc-unlock:v1`, big-endian uint64 chain identifier,
20-byte PTLC contract, one-byte point type, 32-byte entry identifier, and
20-byte destination. Amounts, expiries, `T` and both parties' full agreement are
not all explicit fields of that preimage. The client must independently match
them to the observed entry and retained transcript. See the pinned
[message definition](https://github.com/zenon-network/go-zenon/blob/77ba9c7ee8c881e90911946756cdb67d8b586043/vm/embedded/definition/ptlc.go)
and the existing [public codec](../offline_session/pr138.py).

## Staged public agreement and funding projections

The additive `inspect-agreement` command accepts schema
`ptlc-nom-client-agreement-v1`. Its top-level fields match the initial terms
projection, but each leg omits `entry_id_hex`. No entry identifier or Unlock
message is invented before funding. The output derives the two Create calls and
an economic agreement digest using the agreement schema, a zero byte and the
canonical public projection. This is a commitment to supplied terms, not proof
of counterparty consent or a complete operational timing/observation agreement.

`bind-funding` accepts exactly `schema`, `agreement`, `bindings` and `funding`,
with schema `ptlc-nom-client-bind-funding-v1`. `bindings` is a prefix of at most
two declared records in long-then-short order. Each funding record has exactly
`schema`, `agreement_digest_hex`, `leg`, `account_block` and `entry_projection`,
with schema `ptlc-nom-client-declared-funding-v1`. `account_block` uses the
existing public hash-input codec; it is neither RPC JSON nor signed wire.
The selected projection requires a version-1 chain-69 user send, the agreed
creator, PTLC contract, amount/token and exact canonical Create data, with no
receive reference or descendant claims. Height/predecessor shape and a positive
acknowledged momentum height are checked; ledger ancestry is not authenticated.

The entry projection has exactly `entry_id_hex`, `creator_hex`, `point_type`,
`point_lock_hex`, `destination_hex`, `token_standard_hex`, `amount` and
`expires_at`. All must match the agreement and the entry identifier must equal
the locally computed Create send hash. A second binding produces the existing
post-funding inspection plan from these hashes. These are declared matching
projections, not successful Create executions, live entries or a permission to
fund or disclose. Funding binding itself performs no pre-signature check. The
separate public checker below covers mathematical validity only.

An exact canonical public record may be replayed without changing the prefix.
A conflicting candidate cannot replace either retained binding, including when
only Plasma changes. The economic digest stays constant while a separate
binding digest commits to the accumulated records. Neither digest authenticates
a peer, detects coherent rollback or retains original signed bytes. There is no
persistent journal, automatic retry, new account signature or fee-refresh policy.

The public examples use preserved synthetic bilateral hash inputs. Their
historical byte/hash/message oracles remain distinct from current-source
admission, current fees and real chain execution. The source label selects the
candidate behavior; changing it does not qualify a fixture on another revision.

## Selected public presignature preparation and checking

This M2b implementation slice has no signing owner, observer, durable state or
funding permission. Its own exact-source qualification is separate from protocol
assessment and application/core acceptance.

`prepare-presignature-check` accepts exactly `schema`, `agreement`, `bindings`,
`leg` and `presignature`, with schema `ptlc-nom-client-prepare-presignature-v1`.
It rechecks the complete ordered funding prefix before selecting an already
bound leg. A long-leg check requires no short entry identifier. A short-leg check
requires the ordered long and short bindings. All existing agreement, Create
hash-input and entry-projection checks apply.

The command derives the selected key, full compressed adaptor point and exact
Unlock message locally. It accepts no peer-supplied message, context digest,
backend or executable path. The presignature has exactly `r_x_hex`, `s_hat_hex`
and boolean `needs_negation`. The compact ASCII output is a request for the
selected `schnorr_fun-encrypted-v1` backend at revision
`74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce`. This representation is neither a
musig2 adaptor encoding nor the earlier 65-byte test comparison value.

The Rust checker parses the x-only key and adapted nonce as nonzero curve points,
the full compressed adaptor point as a nonzero curve point, and the scalar
without reducing out-of-range input. It checks the selected library's encrypted
signature relation against the locally derived 32-byte message. It generates no
operational presignature, adapts no signature, extracts no witness, selects no
file, reads no key and contacts no node. Test scalars are public synthetic inputs.

Preparation commits to the entire economic agreement and the selected leg's
exact declared Create binding. Appending the other leg leaves the first leg's
request unchanged. This is a local association of supplied public records.
The context digest is not part of the contract's inner message; the checker only
echoes it. Mathematical validity does not authenticate economics, session/genesis,
peers, key ownership, signing/nonce safety, funding, currentness or timing.

The backend library accepts canonical compact ASCII JSON up to 8 KiB. Exact
canonical roundtrip refuses alternate encodings and duplicate fields. The CLI
also admits one trailing framing LF; the request digest hashes JSON without it.
Refusals echo no input. Success reports `PUBLIC_MATHEMATICS_ONLY`, action
permission `NONE`, unauthenticated context and application/core NO-GO. A claimed
backend label or caller-supplied result authenticates neither code nor source.

Public presignature validity remains insufficient permission to fund, disclose
or recover. Both current entry checks, authenticated agreement, a selected
timing/observation policy, exact original custody and a separately assessed
signing owner remain open. Independent assessment remains unfilled.

## Required party sequence

The following is a target state machine, **not implemented network behavior**.
Every observation below means the exact event admitted under the selected own
node policy, not a peer's assertion or a parsed offline file.

| Step | Actor and required prior state | Required retained result |
| --- | --- | --- |
| 1 | Both agree on economics, roles, keys, `T` and conditional timing policies | Immutable pre-funding agreement; no entry identifiers invented |
| 2 | Alice prepares and funds the long Create | Exact signed send and result uncertainty; successful Create and its exact live entry matched to all long-leg terms |
| 3 | Alice derives the long message from that actual entry; Bob checks her adaptor pre-signature | Exact entry binding and pre-signature, including key/message/`T` relation; Bob must not fund on a failed or unavailable check |
| 4 | Bob funds the short Create only after step 3 and a current long-entry check | Exact short signed send, result uncertainty, successful Create and complete live short-entry binding; Alice checks both current entries |
| 5 | Bob derives and releases the short pre-signature; Alice verifies it | Both retained pre-signatures and staged commitments; failure permits only waiting for the applicable authorized refund |
| 6 | Alice checks the complete disclosure predicate, adapts the short pre-signature and prepares its direct Unlock | Exact completion and signed account candidate retained; durable possible-disclosure and UNKNOWN outcome before any witness-bearing bytes leave the owner |
| 7 | Alice sends the retained short candidate; Bob observes its exact witness and successful short contract execution under the observation policy | Separate send, execution and payout records; retained pre-signature/completion pair; extraction checked with `tG = T`; no replacement of missing bytes |
| 8 | Bob adapts the retained long pre-signature, verifies it and prepares/sends the long Unlock before its send-confirmation deadline | Exact long completion/candidate and UNKNOWN before handoff, then separate send/execution/payout records |
| 9 | Each fixed recipient receives its exact payout on its own account | Confirmed recipient receive, expected token/amount credit, and duplicate-receive refusal; only then the corresponding received-balance outcome |
| 10 | If a leg remains unconsumed at its refund boundary, its creator may follow the explicit reclaim path | Exact Reclaim send, successful execution, refund payout and creator receive; no assumption that entry absence proves refund or claim |

Ordinary BIP340 validity alone does not establish extraction from the selected
pre-signature. The completed signature, retained pre-signature and full `T`
must satisfy the selected adaptor relation. The public presignature checker
does not implement completion, extraction or an application secret owner.
If Bob learns a valid completion before the client's success threshold,
possible witness knowledge must still be retained; the observation rule cannot
make that knowledge disappear.

## Observation, timing and outcomes

The future observer must expose distinct, linked facts: funding send;
successful Create/live entry; Unlock send; send-confirming momentum;
successful contract receive; its exact payout; and recipient account receive.
The supplied node/genesis/spork profile and canonical momentum lineage must
match the retained session. A send acknowledgment is neither successful contract
execution nor recipient credit. A missing entry may mean claim, reclaim,
rollback or incomplete observation. An outage never establishes absence.
The existing [observation requirements](NOM_OBSERVATION_REQUIREMENTS.md)
provide a reading map; the selected own node may supply trusted facts without
implementing the historical checkpoint service architecture.

At the source pin, Unlock requires a send-confirming momentum timestamp
strictly before expiry; Reclaim is due at or after expiry. The contract receive
uses that original confirming context and may occur later. Wall time, the
latest queried momentum and the later receive-inclusion timestamp must not
replace it. The [delayed-receive regression](https://github.com/zenon-network/go-zenon/blob/77ba9c7ee8c881e90911946756cdb67d8b586043/zenon/mock/ptlc_delayed_receive_test.go)
illustrates this distinction. A timely send acknowledgment does not prove a
timely send confirmation, and generating a receive is not committing it.

Before disclosure, the selected policy must provide a justified bound for the
remaining short confirmation/execution/observation path and Bob's long-account
preparation, inclusion and confirmation path. `E_long - E_short`, an online Bob
and a recent fee quote are insufficient by themselves. For example, a short
send confirmed before `E_short` may have a successful contract receive observed
only after `E_long`. No numeric safe margin or finality depth is selected here.
These bounds and availability assumptions require protocol review and later
controlled measurements; synthetic timestamps do not establish them.

Each leg needs independent states for exact candidate custody, possible
disclosure, UNKNOWN handoff, send confirmation, contract outcome, payout and
recipient credit. A reorg may invalidate funding or confirmation evidence and
return an outcome to UNKNOWN. It must retain the displaced lineage, all original
candidates and possible disclosure. Even a deep reorg cannot retract a witness
already learned by a counterparty. Loss of live-entry evidence blocks further
disclosure; historical journal replay is not a fresh entry check.

## Local persistence and fee candidates

Each party must have an independently owned store. A future SQLite store must
serialize cooperating owners and commit the exact relevant public inputs,
candidate bytes, intent and UNKNOWN state before their network handoff. It must
retain failed and interrupted states, distinguish exact output replay from new
work, and refuse unsupported, torn or inconsistent histories without repair.
This does not connect the historical synthetic journals to application signing.

SQLite transactions, fsync, hash chains and a separate checkpoint do not make
history irreversible. Restoring a complete matching old copy can lose disclosure
knowledge; independent copies can diverge. The [existing counterexample](SESSION_JOURNAL.md#rollback-detection-has-a-precise-limit)
must remain visible. Deterministic signatures on identical inputs do not recover
lost observations or prove unique ownership. Restored or cloned operational
stores must remain blocked from new signing/disclosure until a separately
selected reconciliation policy resolves their retained obligations. No safe
restore mechanism, physical power-loss claim or all-copy fence is implemented.

An outer account block commits to `FusedPlasma`, `Difficulty` and PoW `Nonce`
as well as its account predecessor and acknowledged momentum. Altering these
fields changes its hash and requires a new outer authorization, even when the
inner witness and economic call are unchanged. The initial tools may hash an
explicit supplied public candidate; they must never modify a retained original,
obtain a quote, sign, broadcast, or authorize a replacement.

D3 remains a redesign obligation. Before implementing fee refresh, specify a
candidate family that retains every exact signed original/hash and UNKNOWN
outcome, fixes the permissible semantic fields, serializes the signing account,
and reconciles every candidate against actual chain execution. A missing or
timed-out original cannot be treated as rejected. A stale account predecessor
cannot be repaired by changing only Plasma. Refund/expiry competition, delayed
confirmation and reorg must be covered. A fresh quote does not undo disclosure
or guarantee timely inclusion. `requiredFusedPlasma` is a fused-only **total**
target, not a shortfall to add to a PoW recommendation.

## D1-D8 decision records

These records state design direction and open acceptance conditions. They are
not completed independent reviews or permission records.

| Decision | Candidate direction | Required disposition and boundary |
| --- | --- | --- |
| D1: chain observation | Trust an explicitly selected, synchronized own node and a declared depth policy for a later controlled local demo | Node/genesis/spork identity, endpoint ownership, consistent reads, lag/outage behavior, depth `N` and deeper reorg assumptions remain to be selected and tested. Retire unnecessary service mechanisms explicitly; retain required event distinctions. |
| D2: signing/nonces | Distinct single-signer BIP340 lock keys per leg; investigate reviewed deterministic adaptor signing bound to key, message and full `T` | The additive `nom_deterministic_adaptor` Rust test target exercises the already pinned `schnorr_fun` candidate with public constants. Application selection, domain separation, entropy, key custody, retry/restore/copy behavior and independent review remain OPEN. Test source or a passing synthetic run does not supply an application signer. |
| D3: fee refresh | Consider a family of economically equivalent outer account candidates while preserving the inner witness | Policy and implementation UNSELECTED. Preserve exact bytes and UNKNOWN for every candidate. No automatic re-signing, account rebasing or original-only journal migration. |
| D4: operating scope | Offline public tools first; later separately scoped local devnet with synthetic allocations and explicitly owned test accounts | This document does not expand Stage 0 authority. Testnet, mainnet, user wallets, real funds and activation remain outside the current slice. Any later execution must meet the then-current explicit authorization and storage lifecycle. |
| D5: language/license | Python for public deterministic tooling; a separate Rust public checker using the already pinned backend; a signing owner remains separately unselected | No Go node import or new cryptographic primitive is introduced. The small package uses existing pinned dependencies. A process boundary is not a license conclusion; actual dependency and distribution obligations remain separately scoped. |
| D6: upstream tracking | Compare immutable inventories of PTLC and relevant shared paths; qualify affected behavior rather than every unrelated commit | Include ABI, verifier, VM accounting/pricing, receive sequencing, account/momentum insertion and rollback, pool behavior, token/spork/genesis configuration and dependencies. Unchanged PTLC filenames alone are insufficient. Keep tracked `821bdd2` distinct from behavior/journal pin `77ba9c7`; its accepted finite Linux comparison retains the declared shared-state, admission and compiler-authentication exclusions. |
| D7: Bitcoin extension | Preserve the historical CANDIDATE-01 subject; investigate a separate tapscript 2-of-2/NUMS design later | Bitcoin is outside this NoM implementation. Key-path exclusion, sighash/output binding, refund, MTP/momentum margin, fee policy/CPFP and delta review remain OPEN. No existing Bitcoin review or test is inherited. |
| D8: work and acceptance | Add work only against a named protocol, implementation or evidence gate; stop at its explicit exit condition | Preserve old evidence and unrelated work. Parallel early crypto review preparation and bounded synthetic development are appropriate. No reviewer outreach, cleanup, branch deletion, CI erasure or publication follows from this record. |

## CLI mapping and acceptance

The first six commands below are present in the Python source at
[`reference_client/__main__.py`](../reference_client/__main__.py). Invoke them
with `python3 -B -m reference_client COMMAND`, supplying one bounded public JSON
object on standard input. This is implementation presence, not an execution or
test result; actual evidence must be reported for its exact revision.

The Python input API reads at most 32 KiB plus one refusal byte through declared
EOF before parsing. Short reads are accumulated; a later value, read fault or
invalid read result cannot be hidden behind a valid JSON prefix. The boundary
does not authenticate the producer, impose an IO timeout or grant action.

| Command | Initial slice | Guarantee excluded |
| --- | --- | --- |
| `inspect-terms` | Strictly inspect a new declared public terms profile, derive both Create calls and Unlock preimages/messages, and report a terms digest and required actor/event sequence | No entry proof, curve/pre-signature check, agreement authentication, time safety or execution permission |
| `inspect-agreement` | Inspect economic terms without entry IDs; derive Create calls and a separate agreement digest | No counterparty consent, curve check, funding, operational policy or action permission |
| `bind-funding` | Match supplied Create hash inputs and entry projections in long-then-short order, preserving exact declared replay | No signature verification, chain execution, persistent custody, pre-signature admission or fee replacement |
| `prepare-presignature-check` | Recheck the funding prefix and derive one bound leg's message/key/point/context request | No curve check, agreement authentication, chain truth, action or signer permission |
| `encode-call` | Reuse the existing bounded public ABI codec for explicit supplied calls | No transaction admission, signing or network action; codec support for ProxyUnlock is not client proxy support |
| `hash-account-block` | Reuse the existing public account hash-input codec for an explicit supplied public block | No account authorization, canonical signed wire, valid account predecessor, Plasma sufficiency, inclusion or replacement permission |
| `public_crypto` executable | Separately verify the selected public adaptor relation from bounded canonical JSON | No authenticated context, signing, adaptation, extraction, operational recovery or action permission |
| `init`, `fund`, `presign`, `verify`, `claim`, `watch`, `reclaim`, `receive` | Planned stateful client responsibilities mapped to the sequence above; not implemented by the initial slice | No secret, node, transport or persistent application state interface yet |

Initial offline-slice acceptance requires strict bounded input handling, exact
field/type/encoding checks, deterministic output, source/profile separation,
separate declared-terms versus inner-message commitments, and explicit unverified-claim
labels. Reject malformed, duplicate, oversized or conflicting input without
echoing private input. Valid public output must grant no action. Tests may use
only synthetic public values and unchanged selected codecs; no node or signer
is a test prerequisite.

The later minimum local demonstration requires two actual successful Create
executions, both verified adaptor pre-signatures, two timely Unlock sends,
successful contract receives and exact payouts, both explicit recipient receives
and expected balance deltas. Retain each node/source/spork selection, exact
candidate, relevant momentum and result. A clean reproduction must report its
own evidence. Controlled scenarios must distinguish process death, lost replies,
fee rejection, expiry boundaries, restore/copy limits and reorg evidence. A mock
fallback is labeled component evidence, not a completed devnet scenario.

Independent protocol/cryptography and client/recovery assessment must identify
the exact code, dependencies, assumptions, exclusions, findings and disposition.
Begin review preparation alongside synthetic development; its status remains
NOT ASSESSED until a separately attributable written assessment exists. A
reviewer contribution to the construction must be disclosed when describing
independence. No passing offline suite, happy path, closed issue or repeated
author/model review fills this gate. All unresolved signing, timing, observation,
fee-candidate and restore assumptions remain visible at each later milestone.
