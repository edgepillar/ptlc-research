# Price movement, account order and recovery obligations

Status: offline author component study. Application/core remain **NO-GO**. Independent assessment, combined
admission and all seven service gates remain **UNFILLED**. This document is
not permission to sign, release an original, retry or broadcast.

## Exact scope

The selected upstream source is
[go-zenon 85c3979](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe),
tree `cdeb5b6276c13447197c829c5855faa72afd86b9`, with 444 files.
The existing two public synthetic signed Unlock originals are unchanged. Each
has account version 1, height 2, canonical base 73500, fused plasma 73500 and
zero work difficulty. Dynamic Plasma momentum version 2 is a separate field.

A new independently written local probe calls the public content selector and
public `MomentumVerifier.Momentum` with the real `vm.CanonicalBasePlasma`.
Its state provider is a declared test double. It does not execute account VM
application or pool admission, and does not call `MomentumTransaction`, verify
an elected producer, obtain an authenticated frontier or commit any state.
The selected next-price functions prepare the candidate momentum fields; this
is not an independent oracle for those price-update functions.

The actual author run passed 21 Go test/subtest outcomes, including its parent,
and produced 20 selected records. All 444 upstream files and the one installed
project probe remained unchanged. Normal default vet was enabled. Original
stdout, stderr, actual exit and completeness are retained separately. These
are local results, not hosted or independent-machine evidence.

## Observed component differences

Each case below ran once for each leg. The table concerns the supplied declared
component context and does not say that a transaction is valid or included.

| Case | Content selector | Momentum state component |
| --- | --- | --- |
| Minimum fusion/work prices 1000/1000 | Selects the candidate original | Passes the declared component |
| Work price 1103, fusion price still 1000 | Selects the candidate original | Passes; the original pays with fusion only |
| Fusion/work prices 1051/1103 | Omits the original | Refuses the canonical price |
| Missing account frontier at minimum prices | Selects the candidate original | Refuses account order |
| Changed account frontier at minimum prices | Selects the candidate original | Refuses account order |
| Diagnostic zero advertised base at raised fusion price | Selects the metadata copy | Refuses using the canonical base |
| Diagnostic maximum advertised base at minimum prices | Omits the metadata copy under its supplied budget | Passes using the canonical base |
| Underpriced original plus premium unsigned child and unrelated premium diagnostic | Omits the original and child; selects only the unrelated diagnostic | Refuses the original's canonical price |
| Child listed before original at minimum prices | Sorts original before child | Refuses the supplied reverse order |
| Original then child at minimum prices | Selects original then child | Passes the declared order component |

Eight records pass the declared momentum component, six refuse price and six
refuse account order. The input objects are byte-identical before and after
each component call. The separately held exact original wire bytes and node
hashes remain unchanged. No passing record authorizes an action.

The producer labels exact originals as `exact-original`. Changed advertised
base fields are `diagnostic-metadata-copy`; they are not retained original
wire bytes. Unsigned child and unrelated premium candidates are diagnostics,
not valid replacements or new signed transactions. The earlier private
producer used an ambiguous role label. Its successful execution remains
separate; the exact changed producer was executed again before selecting
these explicit labels. Neither execution supplies independent review.

The selector and momentum checks have different responsibilities. The selector
uses the supplied base field; the momentum state check replaces it only in a
local priced copy using the canonical resolver. This study does not establish
an upstream bypass: actual account application and the caller's earlier
invariants have not been composed in this probe.

## Recovery implication

The preserved price study already refuses these originals with fusion price
1001. Each original has no fusion-price headroom at its current canonical cost.
A work-price increase alone does not change that fusion-only comparison.
Neither a component pass at time A nor a selected candidate implies continued
includability at time B. Account-frontier movement is another independent
reason that a retained original can fail the declared state check.

In a fixed-recipient swap, disclosure cannot be undone by later assigning HOLD
to an underpriced or unordered recovery original. A safe disclosure decision
therefore needs a protocol argument covering the complete remaining path and
failure assumptions. No callback, recent price sample or finite test table
provides a bound on future inclusion time. No wait duration is selected here.

Changing fused plasma, account predecessor, work or another signed field may
require a new signature and a different custody/protocol design. Reconstructing
or replacing an UNKNOWN original is not a repair. Missing bytes, an unavailable
custodian or an absent node-hash binding must stay missing. No component result
fills any of those inputs from a fixture.

| Remaining obligation | Required disposition |
| --- | --- |
| Exact byte custody | Independently accepted original retention and recovery, including unavailable custody and coherent restore; never substitute decoded or regenerated bytes |
| Complete admission | Compose authenticated source selection, account authorization/application, frontier order, pool behavior, canonical pricing and momentum requirements on one declared state path |
| Disclosure and timeout | Assess both legs, actual send-confirming expiry rules, price movement, ordering, latency, refund races and the point of irreversible disclosure |
| Reorg and finality | Assess which observations survive replacement or rollback and how uncertainty preserves the same original and charged UNKNOWN work |
| Availability | Explicitly assess missing party, observer, custodian and service responses; no timeout may silently refill allowance or produce a replacement |
| Independent assurance | Obtain written protocol and custody/runtime assessment against a frozen source and actual retained evidence; this author study does not supply it |

## Bounded corpus and reproduction

The [producer](../compatibility/nom_price_account_order_test.go.txt),
[finite reference](../compatibility/fixtures/nom_price_account_order_v1.json)
and [selection](../compatibility/nom_price_account_order_manifest.json) define
this additive subject. Historical sources, results and journals remain pinned
to their original subjects. Source acquisition, GPL-3.0 checking and measured
Go 1.23.12 selection are separate from the MIT project probe.

Install the producer in a fresh owned source view at
`dp/zz_research_nom_price_order_test.go`. Set
`PTLC_NOM_PRICE_ORDER_ORIGINALS` to the public synthetic signed-original fixture.
Use separately selected read-only offline modules, a new owned compiler/temp
workspace, read-only modules and normal default vet. Retain actual command exits
and both original streams:

```text
GO_EXECUTABLE test -json -mod=readonly -count=1 -run '^TestResearchNoMPriceOrder$' ./dp
```

The [bounded reader](../qualification/nom_price_account_order.py) starts no
compiler, network request, signer or journal. It requires all 21 named outcomes
and all 20 exact records. Duplicate JSON keys, nonfinite values, changed types,
wrong record/test bindings, missing rows and reclassified price/order refusals
are refused. Its independent source-content check requires exactly 444 upstream
files and this one project producer. Physical paths, regular single-link files,
16 MiB stdout, 2 MiB stderr and a 40 MiB total source bound are required.

```text
python3 -B -m qualification.nom_price_account_order \
  --source OWNED_PINNED_SOURCE \
  --stream OWNED_GO_STDOUT --stderr OWNED_GO_STDERR
```

A manufactured transcript can match the finite values and pass labels. The
reader therefore leaves execution origin and actual command exits unestablished.
Stderr is retained diagnostic data, not an exit code. A matching source view
does not authenticate a producer or prove that it produced an acquired stream.
Reference fixtures and Python unit streams are explicitly synthetic; they must
not fill missing acquired records. Every result has no actions or replacements
and leaves the operational and independent requirements unfilled.

## Remaining development order

Qualify this additive subject with actual retained native originals, its reader
controls, complete offline regression and separate exact-head hosted PR/main
acceptance. A preparation snapshot or focused pass is not that complete gate.

Then assess disclosure and timeout counterexamples together with unavailable
custody and reorg/availability obligations in a finite offline model. Every
result must preserve HOLD, absent originals and UNKNOWN-work charges. Do not
attach this study to a current-source journal adapter or mark a service gate
fulfilled. Obtain external assessment when a reviewer is available.
