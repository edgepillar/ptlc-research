# New bilateral account graph and separately bound public witnesses

This additive offline subject uses two user accounts and **one shared contract
account** for both legs. New Create hashes, entry ids and fixed destinations
require new inner witnesses. Application and core remain **NO-GO**. There is no
application signer, journal composition, recovery permission or node start.

## Selected subject and observed behavior

Outer Ed25519 accounts derive from the deliberately public repeated-byte seeds
`0x41` and `0x42`. Their public keys select different addresses from the old
synthetic terms. Inner secp256k1 keys, adaptor scalar and nonce auxiliary inputs
are separate deliberately public toy constants in Rust tests. No private input
is accepted, and no scalar is returned by the public verification worker.
These tests are not an application cryptographic construction or signer API.

Both funding sends start at account height one with zero predecessors. Alice
funds the long entry to Bob; Bob funds the short entry to Alice. Each Create ABI
contains its new fixed recipient. Python and the pinned source independently
compute the new funding hash. The new Rust witnesses bind that hash, chain,
contract, point type and destination. Old witnesses and cross-leg witnesses
refuse; an unrelated valid short Schnorr signature cannot recover this selected
adaptor pair. Separate Rust comparison recovers exactly the new long completion
from the new short completion. It does not compose a journal or authorize use.

| Account | Complete-case order | Actual memory effect |
| --- | --- | --- |
| Alice | long funding 1, short Unlock send 2, short payout receipt 3 | Debit long token, disclose selected short witness, credit short token and mark its payout received. |
| Bob | short funding 1, long Unlock send 2, long payout receipt 3 | Debit short token, use separately selected long completion, credit long token and mark its payout received. |
| Shared PTLC contract | long Create 1, short Create 2, short payout child 3 and parent 4, long payout child 5 and parent 6 | Store both new entries, delete each on valid Unlock, debit each fixed payout and consume the actual mailbox sequence. |

The four fresh source cases execute 46 graph steps and 24 selected refusal
controls. Three cases execute a refused short claim before the valid claim:
an old inner witness, the other leg's new witness, or the wrong caller. Refused
claims emit no payout, preserve both entries and their balances, and advance
distinct signed user originals and contract parents. The later valid claim
continues those actual frontiers; it is not a replacement of the failed original.
Both tokens are conserved independently after completed receipts.

Wrong-account predecessors refuse both public verifier entry points. A signed
receipt under the wrong fixed destination passes transaction-only authorization
but refuses structure at the selected enforcement height. Exact receipt replay
refuses the cemented ancestor context; a newly signed successor for the same
payout instead reaches the actual received marker and refuses. No refused
control is executed as a receive or replaced with a guessed original.

## What the execution establishes

The independently written MIT overlay executes source `applySend`,
`generateEmbeddedReceive` and `applyReceive` against actual memory balances,
entries, frontiers, mailbox sequence and markers. Exact source protobuf bytes,
all seventeen account-hash fields, child hashes and ancestry, before/after
patches, balances and verifier outcomes are retained. Python checks the complete
graph, cross-step state continuity, new ABI/witness selection and accounting.
Native serialization and deserialization must round trip exactly; there is no
claim of an independent Python protobuf decoder. Independent OpenSSL verifies
51 outer public signatures and rejects changed messages.

The source `Snapshot()` layers over a live base. The overlay therefore clones
the exact actual pre-execution memory patch into a fresh real account store
before VM writes. Public structural and transaction checks run independently
against that unchanged pre-execution selection. Source changes, unsupported
results, partial output or a mismatch fail qualification; no fixture fallback
exists. The qualifier first reruns all 270 preserved account-context source
tests, including the authorization and VM parents; its five new native tests
bring the selected total to 275. Earlier corpora and observations stay frozen.

## Separate unfilled gates

Synthetic account budgets are written by test setup. Their height-one funding
is not a real genesis, funded account ingress or authenticated chain history.
Momentum hashes, timestamps, confirmations and adopted frontiers are explicit
test selections. The earlier placeholder genesis field is not an authenticated
network identity. User blocks have zero difficulty/fused Plasma and no selected
user VM changes-hash packing. Raw VM calls deliberately bypass `enoughPlasma`
and supervisor packing; two public checks passing does not establish complete
admission. Contract execution uses actual source finalization and changes hashes.

Memory patches are cumulative dumps of the selected synthetic account state,
not authenticated per-transaction deltas or state proofs. Contract finalization
computes its changes hash from that chosen context.

No supervisor, Plasma, account pool, momentum acceptance, source authority,
currentness, canonicality, finality, restore fence, wallet or network operation
is implemented. Public toy recovery does not prove swap protocol security,
cross-party custody, nonce ownership or safe concurrent recovery. Compiler,
dependency cache, loader, runtime and host remain trusted reproduction inputs.
Independent source, runtime and construction assessment remains unfilled.

Next qualify supervisor/Plasma generation and complete admission against this
separate subject, with reviewed original-byte custody and explicit budget,
context and chain gates. Keep exact originals and failed evidence. Only after
those independent requirements may a separately reviewed adapter compose real
originals with recovery journals; the existing synthetic journals remain unchanged.

## Reproduction and attribution

The [manifest](../compatibility/nom_bilateral_graph_manifest.json) pins the
separately obtained GPL-3.0 source at
[commit `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`](https://github.com/zenon-network/go-zenon/tree/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced),
tree `b8bb3720dd36e6f9ba0537864c18bbb4a001b910`, source/license files, new
inputs and all preserved profile inputs. No source implementation is copied.
MIT overlays and toy tests are independently written. Dependencies are acquired
separately, then execution is offline:

```sh
cargo test --locked --offline --manifest-path qualification/Cargo.toml --test nom_bilateral_graph
python3 -B scripts/qualify_nom_bilateral_graph.py --checkout CORE_SOURCE --go GO_EXECUTABLE
```

The bounded native runner retains exclusive private command streams and exact
handoffs; failed attempts are preserved. Hosted private custody may be ephemeral;
original console ZIPs do not replace it. Synthetic Go overlay vet is not
performed under the selected Go 1.23 limitation; standalone Go retains normal vet.
