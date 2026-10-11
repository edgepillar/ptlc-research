# Selected public NoM evidence openings

Application/core remain **NO-GO**. This separate bounded offline comparison opens
three public payload types under the [authority read contract](NOM_AUTHORITY_CONTRACT.md).
It verifies exact commitment bindings and selected structural relationships,
not source truth, account authorization, execution, canonicality or freshness.
No source service, proof system, wallet, signer, transaction serializer, network
operation, persistent store or recovery admission is implemented or connected.

## Requirements and selected scope

All eleven [evidence obligations](NOM_AUTHORITY_CONTRACT.md#requirements-before-composition)
remain independent requirements. This profile selects payload grammars for only
`funding_send`, `original_authorization` and `momentum_lineage`. The other eight
have no opening profile here: network provisioning, live funding entry, unlock
send, contract receive, payout, recipient receipt, consumer restore fence and
current source position. An all-supported source reply cannot fill these gaps.
Missing proof syntax is never replaced with arbitrary blobs or trusted booleans.

| Selected payload | Local comparison | Independent evidence still absent |
| --- | --- | --- |
| Funding send | Open complete advertised hash and hash-input fields for both legs; recompute source SHA3 hash, compare Create fields to each selected leg and the hash to its entry id; look for exact recomputed headers in the opened candidate. | Actual signed account wire, outer authorization, account/acknowledged-momentum admission, Plasma rules, successful Create execution and current live entry. |
| Original authorization | Open both exact retained public synthetic envelopes; enforce existing term/leg grammar and compare exact bytes. Changed shaped signatures remain explicit byte conflicts. | Inner signature verification, adaptor-pair qualification, actual signed account wire and outer account authorization. Synthetic envelope identity is not an account-block hash. |
| Momentum lineage | Open exact raw candidate bytes; compare their selected raw commitment and final checkpoint, then reuse unchanged momentum structural inspection. | Producer signature/election, changes execution, source provisioning, current canonicality and finality. |

The implementation is [a pure separate module](../offline_session/nom_evidence_openings.py).
It uses repository MIT helpers and existing public synthetic fixtures only. No
dependency, external code, signing implementation or network dataset is copied.
The pinned source remains PR #138 commit
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`; source compatibility is not activation.
Existing single-leg observation claims and their acknowledgement contexts are
not silently composed into this profile. Funding header lookup adds no account
admission or validation of the block's acknowledged momentum.

## Exact binding construction

The independent `NoMReadQuery` already commits to complete terms, both originals,
network/checkpoint/consumer selection, anchor, required inclusions, exact raw
candidate and challenge. The unchanged authority parser first frames the source
reply against that selection. The opening bundle has exact fields `schema`,
`query_digest_hex`, `claim_wire_digest_hex` and `openings`. All three selected
opening keys occur exactly once, with a payload or null. Unsupported extra proof
profiles refuse. The claim-wire commitment uses SHA256 over
`ptlc-nom-opened-claim-v1`, a zero byte and the exact canonical claim bytes.
It binds even changed labels in obligations whose opening profiles are unselected.

Each present payload opens its fact's evidence digest. SHA256 commits to
`ptlc-nom-evidence-payload-v1`, a zero byte and compact sorted ASCII JSON containing
`schema=ptlc-nom-public-evidence-payload-v1`, the complete `query_digest_hex`,
`obligation`, claimed `status` and typed `payload`. It therefore binds the
challenge, checkpoint, consumer disclosure selection, both originals and all
other query selections transitively. Cross-query substitution, changed status
or changed payload requires a different commitment. Preparing such a digest
checks only the encoding; it cannot make a supported or contradicted fact true.

Payloads are exact objects:

- `funding_send`: `records` with exactly `long` and `short`; each record has
  `hash_hex` and the existing complete account hash-input `block` fields.
- `original_authorization`: `originals_hex` with both complete synthetic envelopes.
- `momentum_lineage`: `candidate_wire_hex` with the exact raw public branch bytes.

An opened momentum must match the independent raw candidate commitment,
structural inspection and final selected context. Equal momentum hashes with
changed public keys, signatures or JSON whitespace cannot replace the selected
raw bytes. An original must be a complete shaped envelope for its selected leg;
changed shaped bytes are retained as a separate comparison. Swapped legs or
malformed envelopes refuse without normalization or replacement.

Funding record encoding is checked before comparison. A well-shaped wrong
advertised hash, wrong Create field or different entry id is retained as a
comparison rather than converted into a parser error or a trusted negative.
The exact Create comparison covers version/chain/send type, funder, contract,
token, integer amount, empty descendant list, zero from-send hash, expiry,
point type 1, selected inner funding key and fixed recipient. Difficulty,
nonce, Plasma, previous account chain and acknowledged momentum are not admitted
by this comparison. A matching Create comparison can therefore coexist with
invalid account admission. Header membership uses the recomputed hash and full
address/height header, never the possibly false advertised hash. Membership
returns only `INCLUDED_CLAIM`, `NOT_INCLUDED_CLAIM`, or
`NOT_CHECKED_MISSING_CANDIDATE`, with supplied confirmation contexts separately.

The frozen reference terms contain synthetic entry ids, not the recomputed Create
send hashes. Opening otherwise matching Create hash inputs exposes that mismatch
on both legs. A test-only selection of computed ids and matching headers still
has zero-shaped inner signatures, no signed account wire and no independent
authority. It is an explicit unsafe control, not a created-funding witness or
application signature construction. Source execution and public worker checks
retain their own frozen contexts and are not inferred from this comparison.

## Outcomes and retention boundary

`BOUND_UNAUTHENTICATED_PAYLOAD` means only that the typed payload opened its exact
selected commitment. Local comparisons and the untrusted supported/contradicted
label remain separate, including when they disagree. Unknown facts require null
evidence and null openings; present known facts may have a missing opening.
Unavailable replies remain eleven unknown facts with null openings. Missing,
conflicting, unknown and unselected evidence never authorize a fallback or a
terminal unlock/reclaim outcome. The returned decoded claim and opening bundle
preserve those distinctions but perform no durable retention.

Even all selected payloads and comparisons matching leaves proof verification,
source authentication, currentness, provisioning, restore fencing and atomic
entry unfilled. The result permits action `NONE`, no work replenishment and no
replacement original. It requests retention of prior evidence, exact originals
and possible disclosure and fresh funding/live-entry revalidation even for a
common funding prefix. The caller must preserve malformed raw input too; refusal
does not prove absence or invalid remote state. No storage or recovery callback
is invoked, and the result must not be wired into a trusted recovery boundary.
Exact replay and a freshly challenged old selection remain historical claims.

The canonical outer wire is bounded to 2 MiB and depth 12 before JSON decoding.
Originals retain the existing 8 KiB each bound, raw candidate 512 KiB, and the
complete two-leg funding payload 32 KiB. Hex length/type/case is checked before
decoded allocation. Existing account widths and 4 KiB data/64 descendant bounds
remain unchanged. Duplicate/escaped keys, nonfinite/non-ASCII wire, alternate
numeric encodings, extra fields, excessive depth and input-type aliases refuse.
These finite bounds do not establish an aggregate work budget or service policy.

Next select and independently assess source/proof and nonrollback mechanisms,
then implement their missing payload grammars and verifiers against exact source
and restore requirements. Actual-created funding, signed-wire custody, use-time
admission and controlled network composition remain separate gates.
See [validation](NOM_EVIDENCE_OPENINGS_VALIDATION.md).
