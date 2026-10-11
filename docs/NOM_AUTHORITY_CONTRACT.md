# NoM source, freshness and restore admission requirements

Application/core remain **NO-GO**. This increment frames public synthetic read
claims and compares finite abstract use ordering. It implements no observation
authority, proof verifier, profile provisioning, clock, source signature,
nonrollback witness, atomic entry service or recovery admission. No RPC,
transaction construction, signer, broadcast, wallet or funded use is enabled.

## Requirements before composition

The unchanged [momentum corpus](NOM_MOMENTUM_CONFORMANCE.md) establishes selected
structural bindings. The unchanged [retention backend](NOM_EVIDENCE_RETENTION.md)
preserves selected public bytes through controlled process restart. Neither
establishes the current canonical chain or survives coherent old restore safely.
The [existing current-authority requirements](CURRENT_AUTHORITY_EVIDENCE.md) and
[consumer-prefix model](ORIGINAL_CONSUMER_RETENTION_MODEL.md) already distinguish
exact framing, retained knowledge, authenticated source truth and use-time order.
This separate NoM contract applies those distinctions to the following evidence.

| Required claim | Independent mechanism still required |
| --- | --- |
| Network profile | Provision exact node/binary, chain id, genesis, active sporks, authority identity/incarnation and root through an independently reviewed path. Pin canonicality, finality, freshness and restore policies separately. |
| Funding send | Retain actual signed original wire, recompute source hash, qualify outer account authorization, Create ABI/destination, token and amount for each leg. |
| Live funding entry | Authenticate current successful Create state, exact send-derived entry id, funder, point/key, expiry, fixed recipient, token and amount for each leg. Recheck even when funding is in a common momentum prefix. |
| Original authorization | Bind exact retained originals, complete terms, inner witness and outer account authority. An inner signature or a source label cannot replace account authorization. |
| Unlock send | Authenticate exact original witness/entry, caller or proxy semantics and send confirmation context. |
| Contract receive | Verify exact send linkage, canonical execution context and successful transition, distinguishing failed execution and reclaim. |
| Contract payout | Recompute child hash and verify parent/child/account linkage, contract sender, fixed recipient, token, amount and acknowledgement context. |
| Recipient receipt | Authenticate recipient receive referencing that payout; apply the independently selected spendability/finality rule. |
| Momentum lineage | Authenticate producers/election, execution/changes, anchor and current canonical lineage. A hash match or higher height supplies none of these. |
| Consumer restore fence | Establish a current nonrollback checkpoint outside coherent consumer copies, bind the exact originals, retention/disclosure knowledge and consumer incarnation, and define authorized reanchoring without resetting charged work. |
| Current source position | Establish authenticated evaluation at the required current position and recheck at the defined irreversible decision. An exact challenged old read can still be stale. |

Each evidence obligation covers all applicable legs and links, not a single
unqualified boolean. The selected digest fields below have no proof openings.
Their presence does not implement the mechanism in this table. Funding margins,
root rotation, finality rules, source compromise recovery, availability and
freshness bounds remain unselected production decisions.

## Selected offline framing construction

[The pure module](../offline_session/nom_authority_contract.py) selects a complete
comparison unit independently of an incoming reply:

- Full existing fixed-recipient terms and the exact two public synthetic original
  envelopes, including their signatures. These are not signed Zenon account
  blocks; even a shaped zero signature remains a framing-only unsafe control.
- A complete network selection containing PR #138 commit
  `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`, chain/genesis matched to the terms,
  binary/spork commitments, authority id/profile/incarnation, provisioning-root
  commitment and four separate policy commitments. No pin authenticates itself.
- An exact authority revision, final momentum hash/height/timestamp and opaque
  state-root commitment. Revision is a bounded integer, not a freshness order.
- Consumer incarnation, opaque external checkpoint, retention selection/head/
  sequence and possible disclosure. These are caller assertions; this module
  reads no retention file and validates no external fence.
- Selected anchor and exact required header inclusions, the digest of exact raw
  candidate bytes, a challenge and the eleven fixed evidence obligations.

Query preparation reuses the unchanged bounded momentum inspection and requires
`MATCH` and exact equality between the final candidate context and selected
checkpoint momentum. This is structural consistency, not source authentication.
The six old opaque account headers retain their existing limitations: their old
acknowledgement contexts are not composed with these synthetic momenta. No new
account execution proof or actual-created funding witness is implied.
Adaptor-pair validity and the public worker's verification context remain
separate existing requirements; an authority claim replaces neither check.

The raw candidate commitment is SHA256 over
`ptlc-nom-authority-candidate-v1`, a zero byte and the exact bytes. Whitespace
changes this commitment even when the momentum digest is unchanged. The query
commitment similarly uses `ptlc-nom-authority-query-v1`, a zero byte and the full
canonical query. Neither is an account or momentum hash. The complete copied
selection is immutable; incoming bytes must exactly match the selected query.

A reply binds the exact query digest/challenge and has `available` or
`unavailable` status. Every obligation is present exactly once. Its label is
`supported`, `contradicted` or `unknown`; the first two have an opaque 32-byte
evidence commitment and unknown has null evidence. Available replies must assert
the exact selected checkpoint. Unavailable replies have null checkpoint and
eleven unknown facts. Mixed supported/unknown/contradicted claims are retained
distinctly; contradiction dominates only the coverage summary.

The parser returns `MATCHED_UNAUTHENTICATED_CLAIM` and a claim coverage summary.
Even `COMPLETE_CLAIM` is forgeable, including all-zero evidence digests, entirely
self-selected roots or a freshly challenged old checkpoint. It returns action
`NONE`, no replacement, no work replenishment and explicit unfilled authority/
freshness/restore gates. It requests retention of prior evidence/originals/
disclosure and fresh funding/live-entry checks; it does not perform that I/O.
Exact replay matches without proving freshness, spending an allowance, changing
storage or dispatching a worker. A caller must never treat this result as a
capability or plug it into the recovery journal's trusted verifier boundary.

Canonical compact sorted ASCII JSON is bounded to 32 KiB and depth 12 before
decoding. Exact fields, lowercase encodings and exact integer/boolean types
refuse duplicate/escaped aliases, alternate numeric forms, extra labels and
cross-query replacements. Candidate parsing retains its own existing 512 KiB/
depth-16 bound. Reused codecs and public fixtures are repository MIT material;
no new dependency, third-party code or network dataset is copied.

## Selected finite source/restore/use comparison

[The separate test-only model](../scripts/model_nom_authority.py) enumerates only
72 selected schedules per policy: 48 order-preserving read/check/entry shuffles
with eleven fact invalidations or a benign extension, twenty two-consumer copy
shuffles, and four directed source-restore, consumer-restore and lost-result
schedules. Each policy executes 334 transitions; all four cover 288 schedules
and 1,336 transitions. This is not a full action graph or an unbounded proof.

| Selected policy | Source and entry rule | Exposed boundary |
| --- | --- | --- |
| `cached-claim` | Use a supported historical claim with a local operation ledger. | Stale source and consumer restore permit unsafe entry; independent copies repeat an effect. |
| `check-before-entry` | Check ideal current facts first, then separately use the cached decision. | Change/restore between check and entry remains unsafe; copy ledgers still diverge. |
| `rollbackable-atomic-entry` | Check and charge atomically against copied source/consumer state. | Source restore supplies old supported facts; consumer restore/copies lose unique entry. |
| `ideal-atomic-entry` | Check current facts/fence and charge in one abstract event using a ledger outside copied state. | No counterexample in this finite selection, conditional on those ideal premises. No authority mechanism is implemented. |

The complete fixed-terms/original resource is one candidate-independent scope.
Challenges, new queries and local copy names never create another operation key.
Entry records `COMPLETE` or `UNKNOWN` before the abstract effect. Exact replay
returns the retained outcome without another effect, including through an ideal
consumer restore. It does not resolve unknown completion, authorize a retry or
prove actual source delivery. The model performs no cryptographic mathematics,
reads no chain, stores no durable state and starts no recovery worker.

```sh
python3 -B -m scripts.model_nom_authority --policy cached-claim
python3 -B -m scripts.model_nom_authority --policy check-before-entry
python3 -B -m scripts.model_nom_authority --policy rollbackable-atomic-entry
python3 -B -m scripts.model_nom_authority --policy ideal-atomic-entry
```

A partial schedule cap reports incomplete and exits 2. Green model output cannot
establish canonicality, source provisioning or an available nonrollback service.
The separate [public-opening comparison](NOM_EVIDENCE_OPENINGS.md) now opens three
selected typed payloads without selecting source authority or proof verification;
eight obligation profiles remain unselected. Next, independently select and
assess the authority/proof and restore protocol and its exact use boundary.
Keep application recovery, actual signed-original custody, operational network
composition and any core contribution behind their independent requirements.
See [validation and evidence limits](NOM_AUTHORITY_VALIDATION.md).
