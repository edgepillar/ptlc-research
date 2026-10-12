# Actual local momentum execution controls

Profile `zenon-pr138-momentum-admission-v1` preserves every prior source profile,
swap original, funding identifier and inner witness. It is additive offline
research. Application/core remain **NO-GO**; recovery action is **NONE**.

The unchanged, separately obtained GPL source is pinned to
[`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`](https://github.com/zenon-network/go-zenon/tree/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced).
The MIT overlay and Python projection are independently written. The manifest
retains all prior source/license pins and selected inputs. No core implementation
is copied, changed, deployed or activated.

## Selected construction

Three new zero-amount UserSend/UserReceive candidates use the zero token standard.
The first two sends have the same sender and fixed recipient. The recipient
receives the first send after its two sends enter a local memory momentum.
There is no PTLC method, application secret, Bitcoin transaction or old witness
replacement. Public test seeds are 32 repetitions of `0x61` for the sender,
`0x62` for the recipient and `0x64` for the selected producer. These synthetic
keys have no wallet or funds. The actual empty spork store selects legacy rules;
the test cache supplies a fixed fusion amount and zero committed Plasma.

The base momentum is deliberately synthetic: chain identifier 69, height
10109300, timestamp 100 and an explicit label digest. Its advertised hash does
not authenticate genesis, a producer or a chain. The Genesis adapter supplies
only the selected chain identifier; unsupported methods have no fallback.

## Observed source paths

The actual Supervisor generates each plain candidate once and applies its exact
wire without signing. Normal pending-pool admission retains the original patch
plus the actual memory manager's ordered frontier writes. Each momentum includes
the exact headers in advertised account order and the matching prefetched blocks.

GenerateMomentum and ApplyMomentum run the actual raw momentum verifier,
MomentumVM and `momentumStore.AddAccountBlockTransaction`. Every exact previous
momentum query returns a fresh snapshot from the actual memory manager. The
stable base remains byte-identical during generation, exact application and all
refused applications. The VM delta is reproduced independently from the plain
account deltas and source-selected store layouts; it is not fixture replay.

After successful local execution, normal memory-manager Add steals the actual
transaction changes and appends exact momentum frontier records. The actual
store then resolves every included header and confirmation. Actual
PrefetchMomentum returns original account wires in advertised order. An actual
pool InsertMomentum callback runs after each local memory insertion. This
controls memory execution and selected callback sequencing; it does not run the
node momentum pool, persistent manager, producer process or network admission.

The independent Python model checks complete logical DB views, including both
account histories, zero ZNN balance indexes, global serialized header mappings,
confirmation heights and both mailboxes. Receiving the first send deletes only
its recipient pending marker, retains its unreceived history and records the
exact receive header in the sender mailbox. The second send remains pending.

## Refusal boundaries

Thirteen controls select reversed account content, duplicate content, duplicate
prefetch, nil prefetch, wrong header address, missing prefetch, wrong chain,
non-increasing timestamp, wrong changes hash, wrong outer hash, wrong signature,
false producer response and producer error. Exact candidate and prefetched wires,
returned errors, snapshot counts, producer counts and complete unchanged stable
views are retained. Every refusal returns no transaction and signs zero times.

Static changes/hash/signature errors stop before producer verification. A valid
self-signature still reaches a separate consensus producer query. Explicit
`accept`, `reject` and `error` responses exercise that boundary; the adapter does
not determine the elected producer. Source self-signature verification is
performed; independent Python cryptographic verification is not supplied by the
projection. Fixture/source hashes bind the selected evidence, not its authority.

## Remaining gates

This profile does not fill authenticated genesis/spork/producer selection,
canonicality, finality, currentness, host/source authentication, persistent
caller ordering, concurrency, batched child content, actual rollback caller
events or complete network admission. Old historical/pending views remain
insufficient for recovery. Custody, restored-copy fencing, application signer
composition and independent construction assessment remain separate gates.

The next bounded source selection should combine actual content construction,
prefetch and rollback caller events for batched descendants, preserving every
original wire. It must establish the selected event array before classifying
dependency behavior. Application recovery must remain gated by authenticated
currentness and original operation identity; it must not generate replacements.

Run `scripts/qualify_nom_momentum_admission.py --checkout <pinned-checkout>
--go <selected-go>` with separately obtained source and offline module contents.
Missing, failed or changed evidence fails closed without fixture fallback.
See [validation](NOM_MOMENTUM_ADMISSION_VALIDATION.md) for evidence limits.
