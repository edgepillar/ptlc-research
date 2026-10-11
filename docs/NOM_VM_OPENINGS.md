# Query-bound public VM evidence openings

Research baseline: `d4576f58b17d71a07062015e3feed9cfeaf64f58`.
Profile: `zenon-pr138-vm-public-openings-v1`. Application/core remain **NO-GO**.

## Requirements and selected comparison

The unchanged [authority contract](NOM_AUTHORITY_CONTRACT.md) requires eleven
independent forms of evidence before composition. The frozen [base opening
profile](NOM_EVIDENCE_OPENINGS.md) selects only funding hash inputs, retained
synthetic originals and raw momentum bytes. This additive pure module selects
four further public grammars. Selecting a grammar fills no authority requirement.
Network provisioning, live entry, consumer restore fencing and current source
position still have no grammar. All eleven requirements remain independently
unfilled even when every local field comparison matches.

| Added role | Selected local comparison | Required independent evidence |
| --- | --- | --- |
| Unlock send | Complete account hash inputs, advertised hash, exact retained inner witness, computed funding id, direct caller or fixed ProxyUnlock destination. | Actual signed account wire, signature/Plasma/account admission, inclusion and time authority. |
| Contract receive | Funding receive and selected claim receive, recomputed from-send linkage, successful status bytes, zero transfer fields and acknowledgement order. | Authenticated execution, live state and expiry context. A status marker is only a claim. |
| Contract payout | Contract sender, fixed asset/amount/recipient, recomputed child membership, previous account hash, heights and exact parent acknowledgement. | Admitted parent/child/account context and an authenticated execution/state proof. |
| Recipient receipt | Recipient, recomputed payout from-hash, empty receive fields, acknowledgement order and selected adjacent account ancestry when Unlock used that recipient account. | Recipient frontier authority, received marker, duplicate admission, spendability and finality. |

The four new payloads are exact `records` objects with `long` and `short` keys.
Unlock, payout and receipt each contain one record. Contract receive contains
`funding_receive` and `receive` records per leg. Each record has exactly
`hash_hex`, `changes_hash_hex` and all seventeen existing account hash-input fields
under `block`. `ChangesHash` remains an opaque separate claim: the source account
hash does not include it. No signature, arbitrary proof blob, trusted boolean,
received-marker patch or source log is substituted for missing proof syntax.

## Exact bindings and outcomes

The unchanged authority parser frames the complete query and source claim first.
The unchanged base parser opens its three commitments separately. The new bundle
has `schema`, `query_digest_hex`, `claim_wire_digest_hex`,
`base_opening_wire_digest_hex` and exactly four `openings` keys, each typed or null.
The base wire digest is SHA256 of `ptlc-nom-vm-base-openings-v1`, a zero byte and
the exact base-opening bytes. The claim commitment is the frozen exact-byte
construction. Neither commitment authenticates a source.

Each role's evidence digest is SHA256 of `ptlc-nom-vm-evidence-payload-v1`, a zero
byte and canonical sorted compact ASCII JSON containing
`schema=ptlc-nom-vm-evidence-payload-v1`, complete `query_digest_hex`, `obligation`,
untrusted claimed `status` and typed `payload`. This binds both originals, terms,
challenge, consumer selection, network, checkpoint and candidate transitively.
The outer bundle separately binds the complete claim and exact base bundle,
avoiding a circular claim/base commitment. Cross-query, role, status, claim or
uncommitted payload substitutions refuse.

Well-shaped hash, linkage, field, ancestry and acknowledgement conflicts survive
as explicit comparisons. Supported/contradicted source labels stay separate from
these results. Links and candidate headers use recomputed hashes, never a false
advertised hash. Candidate membership is only `INCLUDED_CLAIM`,
`NOT_INCLUDED_CLAIM` or `NOT_CHECKED_MISSING_CANDIDATE`. Equal acknowledgement
heights require equal supplied hashes; a supplied higher height authenticates
nothing. No momentum timestamp establishes expiry without authority.

Missing/unknown openings remain missing/unknown claims. Missing funding cannot be
invented from the query; a missing original opening cannot verify the selected
inner witness. The selected original is a retained synthetic envelope, whose
identity is not an account-block hash. Direct receipt adjacency is a deliberately
narrow comparison: a gap can be explained only with independently selected and
authenticated intervening account evidence. A proxy caller on another account
leaves `PRIOR_RECIPIENT_FRONTIER_UNSELECTED`; its frontier is not reused for the
recipient. No missing role, failed execution, reclaim or entry absence establishes
a terminal outcome or authorizes replacement signing.

All results retain prior-evidence/original/disclosure and funding/live-entry
revalidation requirements, allow action `NONE`, and deny work replenishment and
replacement originals. Returned decoded copies perform no durable retention.
Malformed raw bytes must also be retained by a separately qualified caller.
Source authentication/currentness, proof verification, canonicality, finality,
restore fencing, account admission and atomic journal entry remain unfilled.
There is no I/O, wallet, signer, node, observer, admission callback or journal
connection. Finite per-wire bounds are not an aggregate service work budget.

## Fresh source evidence and exposed limits

The [public corpus](../compatibility/fixtures/nom_vm_openings_v1.json) projects ten
cases from the unchanged [VM source driver](NOM_VM_PATH.md): direct success,
funder proxy, third-party proxy, expiry followed by reclaim, and intentional raw
receive replay, each for both independent legs. It retains complete synthetic
block records but omits private command streams, actual patch dumps and logs.
The new qualifier executes the frozen 33 VM and 25 verifier tests afresh, requires
all 32 records, and compares the complete projection to the corpus before
inspecting query-bound roles. A parser-only test cannot provide that positive
source evidence. Compiler, cache, runtime and host remain trusted.

Actual direct VM records expose an account continuity mismatch: the Unlock send
uses a selected recipient-account height of 21, while `applyReceive` starts from
an independently selected empty recipient frontier at height 1. Their valid local
hashes do not establish one admitted account path. The numbered VM acknowledgement
stubs also differ from the preserved momentum candidate at the same heights, and
their headers are not in that candidate. Neither difference is normalized away
or presented as an upstream consensus defect. The old VM test remains a selected
accounting/lifecycle test, not full account admission.

Both proxy success projections preserve the recipient while leaving its prior
frontier unselected. Actual expiry reclaim pays the funder and fails the selected
Unlock-witness/recipient comparisons; successful status bytes cannot relabel it
as unlock success. The intentionally duplicated raw receive still references the
correct payout. This demonstrates why from-hash linkage alone is no received-state
proof or duplicate admission. Even a forged adjacent receipt or all-supported
reply permits no recovery action.

Source execution remains pinned to PR #138 commit
[`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`](https://github.com/zenon-network/go-zenon/tree/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced),
tree `b8bb3720dd36e6f9ba0537864c18bbb4a001b910`. The separately obtained source
is GPL-3.0. The overlays, consumer and synthetic projections are independently
written MIT research inputs; no upstream implementation is copied. The new
[manifest](../compatibility/nom_vm_openings_manifest.json) pins source/license,
consumer/fixture/parser and preserved dependencies. It changes no core behavior
and makes no merge, release or activation claim. Original local streams and
handoffs are retained privately; hosted private custody may be ephemeral and is
not proved by the console ZIP. Overlay vet remains unperformed.

## Next gates

Select and independently assess source/proof provisioning, recipient account
frontier evidence, full signature/Plasma/admission context, expiry authority,
canonicality/finality and nonrollback restore/currentness mechanisms. Obtain
scoped construction and observation assessments. Only after those independent
requirements pass should retained original evidence enter recovery atomically
with its journal. Keep observation, recovery and Bitcoin construction in this
client/research workspace; coordinate narrow consensus work upstream. This
profile supplies comparison coverage, not a safe live swap construction.
