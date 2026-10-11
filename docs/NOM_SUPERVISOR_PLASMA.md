# Selected Supervisor originals and transaction deltas

This additive offline subject selects new Plasma-committed public originals and
inner witnesses. Two user accounts continue through one shared PTLC contract.
Application and core remain **NO-GO**. Complete admission, custody and recovery
permission remain unfilled. There is no application signer or node start.

## Observed source execution

The independently written MIT overlay calls public source `NewSupervisor`,
`GenerateFromTemplate`, `GenerateAutoReceive` and `ApplyBlock`. Each generated
original is independently reapplied from the same unchanged memory base before
one explicit adoption of its exact transaction patch. Both calls must return
identical source protobuf bytes and per-transaction patch bytes. Reapplication
does not call the public-constant test signature callback. Generation, failed
attempts and unapplied successful controls must leave the base unchanged.

The two cases contain 22 complete graph steps and 24 selected controls. One
case completes directly. The other consumes a separately signed short Unlock
with an old inner witness, records its contract refusal without payout or entry
deletion, and continues with a distinct valid original from the actual new
frontier. That refused user send consumes its own Plasma once. Both fixed
payouts are received and each token is independently conserved.

The legacy cache view explicitly selects a public synthetic fusion amount of
20,000,000,000, committed Plasma zero, PTLC selection true and Dynamic Plasma
selection false. The source computes capacity 420,000, canonical Create cost
52,500, Unlock cost 73,500 and user receipt cost 21,000. Unconfirmed chain Plasma
is held in the real account store and deducted from availability at each step.
The extra refused short original leaves Alice with 199,500 available after her
receipt; the directly completed case leaves each user with 273,000. These
synthetic selections are not real fusion ingress or spork activation evidence.
Dynamic Plasma and proof of work are separately unselected.

The old raw public funding original retains its exact id, acknowledgement,
signature and wire bytes. Source `ApplyBlock` refuses it with
`ErrNotEnoughTotalPlasma`. It is never upgraded. A new generated funding original
refuses under a separately depleted fusion view with `ErrNotEnoughPlasma`, then
reproduces under the original selected budget using exactly the same bytes and
signature. Missing/changed outer signatures and an insufficient token budget
return no transaction and leave all actual adopted memory unchanged, including
VM writes attempted before late signature verification.

## Separate patch and admission boundaries

Each chain account lookup returns a new source snapshot over a base that stays
unchanged during generation and application. This uses the source's live-base
snapshot semantics explicitly. Returned patches are actual transaction deltas,
not cumulative account-state dumps. Python independently decodes the selected
bounded headerless LevelDB batch format, replays each delta over the actual
prior logical state, and compares actual committed state. Frontier adoption
must add exactly its three source-selected writes, including the protobuf
`HashHeight` identifier. Balances, chain Plasma, receipt markers, account and
batch ancestry, mailbox order, exact wire/delta hashes and all refusals are
checked. This is a selected format comparison, not an authenticated state proof
or independent general account-block protobuf implementation.

Two deliberately unadopted controls retain a scoped source observation: changing
only a user's advertised `ChangesHash` leaves its account hash and signature
unchanged; selected `ApplyBlock` returns a transaction with a different actual
patch hash. Changing a contract parent's advertised changes hash instead
refuses source VM reproduction. Generated blocks do commit the correct source
patch. These observations are not a full-chain vulnerability classification.
Account pool and momentum validation must be independently examined before any
admission claim; two public account checks are insufficient for that claim.

Strict synthetic chain/cache views provide only the selected methods. Other
inherited interface methods fail if reached. A placeholder pillar reader is
selected for embedded construction; no pillar election or momentum consensus
method is exercised. Synthetic confirmations, heights and frontiers are test
selections. No account pool, momentum insertion, network identity, currentness,
canonicality, finality, restore fence, wallet, signing service or journal adapter
is implemented. Exact bytes here do not establish application original custody.

The new inner witnesses use separately disclosed toy secp256k1 constants and
new auxiliary nonce inputs. The outer Ed25519 test constants are separate keys.
Rust tests reproduce selected recovery, refuse old/cross-leg witnesses and
require the selected adaptor relation. Independent OpenSSL verifies 31 valid
outer signatures and refuses both explicitly changed signatures and changed
messages. Test arithmetic and source/regression success do not establish swap
construction security, cross-party custody, nonce ownership or safe recovery.

## Pins, reproduction and next gates

The [manifest](../compatibility/nom_supervisor_plasma_manifest.json) retains all
earlier profile inputs, the separately obtained GPL-3.0 source at
[commit `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`](https://github.com/zenon-network/go-zenon/tree/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced)
and additional Supervisor, Plasma, consensus-interface and patch-format inputs.
The checked [upstream PR #138 head `4cf0e443e777c5e386204ab9996a5a91ff982613`](https://github.com/zenon-network/go-zenon/commit/4cf0e443e777c5e386204ab9996a5a91ff982613)
is one commit ahead and changes only the variant-table comment from four sporks
to five. The exact file-byte replacement was compared. Native execution remains
bound to the qualified earlier commit; exact-head execution of that newer commit
is not claimed.

The separately obtained BSD-2-Clause
[LevelDB batch format source](https://github.com/syndtr/goleveldb/blob/2ae1ddf74ef7020251ff1ff0fe8daac21a157761/leveldb/batch.go)
and license are hashed and compared in the selected module cache. No upstream
implementation is copied. Overlays and the narrow Python format reader are
independently written. Dependencies are acquired separately before offline use:

```sh
cargo test --locked --offline --manifest-path qualification/Cargo.toml --test nom_supervisor_graph
python3 -B scripts/qualify_nom_supervisor_plasma.py --checkout CORE_SOURCE --go GO_EXECUTABLE
```

The qualifier first reruns all 275 preserved source tests and then three new
native tests, totaling 278. Original private command streams and handoffs are
retained; failures have no fixture fallback. Hosted console ZIPs do not replace
private stream custody. Overlay vet remains unperformed under the selected Go
1.23 limitation; standalone Go retains normal vet. Compiler, dependency cache,
loader, runtime and host are trusted reproduction inputs.

Next qualify pool and momentum admission, including the observed user changes
boundary and rollback behavior. Separately review original custody, authenticated
source/context, restore fencing and construction security before any recovery
journal composition. Existing synthetic journals and workers remain unchanged.
