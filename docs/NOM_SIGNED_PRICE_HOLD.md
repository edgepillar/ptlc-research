# Signed original price comparison and development checkpoint

Status: **author source review and finite offline comparison; application/core
NO-GO**. Independent assessment and all seven service gates remain **UNFILLED**.
This adds no journal adapter, trusted chain, signer, transport or recovery action.

## Source selection and actual local executions

The separate subject selects go-zenon
[`85c39796fa5ab6fb5ca16e61af34b6616f0ceafe`](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe),
Git tree `cdeb5b6276c13447197c829c5855faa72afd86b9`. Its source archive has
SHA-256 `54336f7c1f75f84d0f513d3b22da135bebf62d8da84b776e961b0c3f52f8e1c9`
and 1,705,302 bytes. All 444 file contents, Git blob identifiers, modes and the
reconstructed Git tree were checked before execution. The complete source index
has SHA-256 `6168b36ee6487272bf128862f141093db4d47c411a5d551fb132de5d9ab8890a`.
The source was separately obtained under its
[GPL version 3 license](https://github.com/zenon-network/go-zenon/blob/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe/LICENSE),
whose checked SHA-256 is
`3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`.
The original project probe, reader and locally generated public records do not
vendor or relicense the node implementation.

Relative to the separate `b5f93c2` RPC subject, 437 files are byte-identical,
six change and one principal test file is added. The principal changes select
the genesis spork address instead of a compiled governance address and judge the
community window at the send's confirming momentum. A matching genesis/community
address does not bypass that window. This source review establishes no authority
on any live network.

Two distinct local command groups completed with actual exit zero, complete
original streams, Go 1.23.12, default vet, read-only modules and a selected offline
dependency proxy. Source contents were checked again after each command.

| Actual local group | Selected scope | Go test/subtest outcomes |
| --- | --- | ---: |
| Existing public signed-original probe | The preserved 24 transaction-only records | 25 |
| Existing generic RPC probe | 13 synthetic-store calls and a typed zero serialization | 15 |
| Existing PTLC RPC probe | Two existing public Unlock inputs in eight contexts each | 17 |
| Selected upstream RPC tests | Existing public price/serialization assertions | 14 |
| Upstream principal tests | Four in-process mock-chain tests, including confirmation-window edges | 4 |
| New source-price probe | Two originals in eight price/metadata contexts each | 17 |

The first five groups account for 75 outcomes. The last group is a separate
17-outcome command and produces the [16 retained price records](../compatibility/fixtures/nom_signed_price_hold_v1.json).
These are local component executions, not complete source-suite, account-pool,
momentum-admission, operational-node or independent-machine qualification.
The upstream principal tests use their in-process mock and public synthetic
genesis; they do not start a peer-to-peer node or an operational RPC service.
Original private command streams remain retained separately; this document and
public record values do not supply those original streams or authenticate their
producer. Hosted acceptance must be recorded separately for each published head.

## Why a fresh quote cannot upgrade an original

The [new probe](../compatibility/nom_signed_price_hold_test.go.txt) reads the
existing public signed long and short Unlock originals. Each commits 73500 fused
Plasma and zero PoW difficulty. It obtains the canonical Unlock base cost, 73500,
through the selected source's `vm.CanonicalBasePlasma` against an explicitly
synthetic acknowledged-cache view. It then calls `dp.NewDynamicPlasma` and
`ValidPrice`. No account frontier, balance, pool, authenticated momentum, finality
or observation proof is supplied by that view.

| Selected context | Result for each unchanged original |
| --- | --- |
| Version 2, fusion/work prices 1000/1000 | Price component passes |
| Version 2, fusion/work prices 1000/1103 | Price component passes; these inputs pay with fusion only |
| Version 2, fusion/work prices 1001/1000 | Price component refuses |
| Version 2, fusion/work prices 1051/1103 | Price component refuses |
| Version 2, fusion price 1051 and maximum uint64 work price | Price component refuses without narrow-integer overflow |
| Version 1 constructor with advertised prices 1051/1103 | Constructor selects minimum prices; price component passes |

The other two contexts per leg use **diagnostic copies**, with an advertised
`BasePlasma` of zero or maximum uint64. Trusting that field can change the price
answer in either direction. Recomputing the canonical base restores the selected
answer. The diagnostic encodings never replace a retained original. The probe
checks that comparison preserves its selected bytes and that these metadata
changes leave the computed node identifier unchanged. It does not claim that
such a copy passes complete admission.

For these zero-difficulty, fused-only inputs the finite Python model compares
`73500 * work_price * 21000` with
`floor(21000 * fusion_price / 1000) * work_price * canonical_base`.
Version 1 selects minimum prices first. This deliberately covers only the
declared inputs; it is not a general PoW, fusion-capacity or admission calculator.
Cross-language agreement remains author qualification, not independent review.

The selected source calls `ValidPrice` during
[content selection](https://github.com/zenon-network/go-zenon/blob/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe/pillar/content_selector.go)
and uses a recomputed canonical base during
[momentum verification](https://github.com/zenon-network/go-zenon/blob/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe/verifier/momentum.go).
Those complete paths are source-review observations here; the new native probe
does not execute them. A transaction-only signature result and a fresh unsigned
RPC quote cannot establish inclusion. Changing hash-committed fusion, difficulty
or acknowledged momentum would require a different transaction authorization.
This subject supplies no replacement original, signing or automatic fee update.

For a recovery design, retain the exact original, UNKNOWN work and original
allowance when this price component refuses. A later favorable price is not a
retry or recovery authorization. Neither an unavailable quote nor a passing
price component resolves the original outcome or proves a safe time to act.
The selected comparison introduces no new handoff or state transition.

## Reproduction and reader boundary

The [selection manifest](../compatibility/nom_signed_price_hold_manifest.json)
pins the project inputs, source identity, archive and public records. The
[finite reader](../qualification/nom_signed_price_hold.py) checks complete selected
Go-shaped outcomes, record framing, exact original bindings, types and integer
results. It explicitly reports `NOT_ESTABLISHED_BY_THIS_READER` for execution
origin. A manufactured passing transcript can satisfy a value comparator; it
cannot serve as source-execution evidence.

For native reproduction, independently acquire and verify the exact source above
into newly owned qualification scratch. Add the pinned project probe as
`dp/zz_research_nom_price_hold_test.go`; do not adopt a dirty checkout. Select the
preserved public signed-original fixture through `PTLC_NOM_RPC_PTLC_FIXTURE`.
Use an explicitly measured Go 1.23.12, read-only offline module proxy and fresh
owned compiler/module/temp directories. Capture the complete actual exit and
original stdout/stderr from this command in the selected source:

```text
GO_EXECUTABLE test -json -mod=readonly -count=1 -run '^TestResearchNoMSignedPriceHold$' ./dp
```

There must be 444 unchanged upstream files plus the one selected probe, checked
before and after execution. A skipped test, truncated stream or missing native
run is not a successful execution. Compare the bounded stdout from the project:

```text
python3 -B -m qualification.nom_signed_price_hold --stream OWNED_GO_JSON
```

The regular Python suite exercises the reader with synthetic frames and retained
values. It does **not** run this new upstream native probe. Existing hosted RPC
jobs retain their `b5f93c2` selection. Their passing status must not be presented
as a hosted `85c3979` native result. No old source manifest, historical journal
context or independent review subject is repinned by this addition.

## Next development and independent acceptance

The [author review](NOM_AUTHOR_REVIEW.md) permitted bounded offline work despite
the missing reviewer. Its observation snapshot entry and separate exact signed
byte custody candidate now exist, followed by
[actual signed-journal interruption comparisons](NOM_SIGNED_RECOVERY.md).
They preserve absent originals, public completions and charged UNKNOWN work as
different states. These implementations do not close the external review gate.

Continue in this order:

1. Keep this price/inclusion obligation in the offline fixed-recipient recovery
   model. Qualify a bounded refusal/hold interface before considering a new
   current-source journal adapter. A component pass must never become permission
   to sign, retry, replenish work or release an original.
2. Replay the separately selected account/VM, pool and momentum subjects on an
   explicitly pinned source before making a combined admission claim. Review
   the actual dependency and source delta; do not repin old journals or relabel
   their historical executions as current.
3. Assess price movement together with account ordering, unavailable custody,
   disclosure timing, timeout margins, reorg/finality and availability. Local
   hold behavior cannot guarantee that a preauthorized original will become
   includable before a timeout. A redesign requiring a new signature has a
   separate signer/custody and protocol assessment obligation.
4. Obtain a written external review against a fixed source/tree and raw evidence
   when a reviewer is available. Protocol/cryptography and custody/runtime may
   be reviewed separately. The same author, a repeated model run and additional
   local or hosted tests do not supply that independence.
5. Keep the independently provisioned source/observer, signer, nonrollback and
   operational requirements and [AS-1 through AS-7](NOM_ANCHOR_SERVICE_ACCEPTANCE.md)
   unfilled until their actual evidence is accepted. Deployment, node activation,
   wallet access, application signing, broadcast and real funds remain outside
   this offline workspace.
