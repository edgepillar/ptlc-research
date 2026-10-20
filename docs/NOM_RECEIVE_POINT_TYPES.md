# Finite NoM receive credits across three point types

This additive profile preserves the earlier
[ED25519 credit subject](NOM_RECEIVE_CREDIT.md) and selects the same immutable
[`go-zenon` commit `85c3979`](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe),
tree `cdeb5b6276c13447197c829c5855faa72afd86b9`. It makes no current-branch,
activated-network or deployed-node claim.

## Selected finite cases

The six fresh in-process public-genesis mock cases combine the earlier Unlock
before expiry and Reclaim at or after expiry scenarios with each point type:

| Point type | Selected witness | Operation-message binding |
| --- | --- | --- |
| ED25519, type 0 | Public-genesis fixture signature | Selected Unlock message |
| BIP340, type 1 | Signature using public synthetic scalar 3 | Selected Unlock message |
| Compressed secp256k1 point, type 2 | Public synthetic scalar 3 | No operation-message binding |

The raw scalar mode is a distinct construction. The selected core requires a
nonzero fixed destination for it. Its witness does not become a signature over
the operation, and these cases do not establish adaptor-signature completion or
interchangeability with the fixed-recipient BIP340 swap construction.

Each case retains the earlier send order, expiry and two contract receive
comparisons. Exactly one generated payout is committed; the later receive
commits a method error without another payout. Both user balances stay unchanged
until the selected user explicitly receives the exact committed payout. That
user gains exactly 1,000,000,000 units, the other user's balance stays unchanged,
and a duplicate receive refuses without another credit or frontier change.
User confirmation must follow all earlier selected confirmations in strict order.

The Reclaim-first cases do not establish successful verification of a later
Unlock witness: the entry has already been removed. Six finite mock cases are
not exhaustive witness rejection, pool scheduling, liveness, canonicality,
finality, reorg handling, bilateral atomicity or safe disclosure margins.

## Source and original-output reproduction

The [selection manifest](../compatibility/nom_receive_point_types_manifest.json)
pins the earlier reader dependency, 444-file upstream inventory, added probe,
notice and synthetic controls. The new source comparator requires exactly those
445 source file contents. Keep compiler caches outside the selected source.
Place the [probe](../compatibility/nom_receive_point_types_test.go.txt) at
`zenon/mock/zz_research_nom_receive_point_types_test.go` and use one compiler
context:

```sh
GOMAXPROCS=1 go test -p=1 -json -mod=readonly -count=1 -timeout=8m \
  -run '^TestResearchNoMReceivePointTypes$' ./zenon/mock
```

Retain original stdout, stderr, actual exit, capture completeness and exact
source/toolchain selections. Compare their bounded contents with:

```sh
python3 -B -m qualification.nom_receive_point_types \
  --source selected-core --stdout original.stdout --stderr original.stderr
```

The reader requires all six bound records, seven Go test outcomes and one
package success. It preserves the earlier balance, duplicate-credit, order and
expiry comparisons, with bounded same-test line reassembly. Its value checks
do not authenticate a producer, prove an actual command exit or establish source
execution. Manufactured transcripts can satisfy a value comparator. New reader
qualification and reconciliation of retained original execution evidence are
separate from a fresh native execution and exact-head hosted acceptance.

The harness uses public fixture signing helpers only in the in-process mock.
No node server, chain contact, user wallet, application signing or broadcast is
connected. No journal write, replacement original, automatic retry or recovery
permission follows. Independent assessment and AS1-AS7 remain **UNFILLED**;
application and core remain **NO-GO**, with recovery action **NONE**.

The adapted Go probe retains
[GPL-3.0-only attribution](NOM_RECEIVE_POINT_TYPES_NOTICE.md). Original Python
code, controls and documents retain the project MIT license.
