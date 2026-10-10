# NoM momentum claims and conservative reorg plans

Status: additive **offline research**, not a chain observer or journal admission
path. Application/core remain **NO-GO**. Source authentication, producer election,
network/genesis/spork authority, canonicality, finality, signing custody, durable
evidence retention and restore protection are independently unqualified.

## Pinned source and selected layout

This subject extends `e86354ef795add0b0bd7f769f3c01472bd3571ed` and references
PR #138 at `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`, tree
`b8bb3720dd36e6f9ba0537864c18bbb4a001b910`. The manifest measures 16 selected
source/license/module files and 16 preserved recovery/wire/observation inputs.
The GPL node is separately obtained and not copied; new research material is MIT.

The independently written layout follows the pinned
[momentum hashing](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/chain/nom/momentum.go),
[content bytes](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/chain/nom/momentum_content.go)
and [account header bytes](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/common/types/account_header.go):

- A header is raw 20-byte address, big-endian uint64 height and 32-byte hash.
  Content commits to the supplied header order. Inspection never sorts it.
- The 160-byte momentum preimage commits to version, chain identifier, previous
  hash, height, timestamp, SHA3-256 data/content digests and changes hash.
- Version >= 2 appends big-endian uint64 fusion/work prices, making 176 bytes.
  Raw hashing also accepts versions the node's separate version check refuses.
- Version 1 ignores both prices in its digest. The separate source price checks
  still require zero. The source version check selects exactly 1 or 2 according
  to its supplied Dynamic Plasma state; a version field proves no activation.
- Public key/signature are excluded from the digest. A matching hash never
  replaces signature verification or chain-dependent producer election.

The selected inspection supports versions 1 and 2, empty data, zero legacy
prices and dynamic prices >= the pinned source floor of 1000. It does not verify
dynamic price computation, active sporks, changes execution, account histories,
balances, Plasma pricing, full momentum admission or protobuf wire. Raw hash
vectors deliberately include zero/three versions, nonempty data and uint64
boundaries to keep hashing separate from admission.

## Bounded structural comparison

`offline_session.nom_momentum` performs no I/O. `inspect_branch` compares at most
64 momenta, 64 headers per momentum and 64 required inclusions to an explicitly
supplied chain identifier and common anchor claim. It recomputes every momentum
hash, checks contiguous previous hash/height, increasing timestamps and exact
header membership at each supplied confirming hash/height/timestamp. Timestamp
inspection selects positive signed-int64 values; raw hashing retains uint64.
Duplicate content identifiers and repeated exact headers in the selected branch
are refused. These are bounded research selections, not universal admission.

The public fixture copies six existing unsigned observation headers as opaque
header claims. Their old account payload acknowledgements are **not composed**
with these new momenta. This corpus demonstrates header membership only; it
does not authenticate, re-execute or rehash their account payloads. The preserved
observation corpus separately recomputes account hashes. Neither comparison
proves a funded flow or validates the old witness for a Create-derived id.

Missing history or header coverage stays `INCOMPLETE`, not an unlock, reclaim,
refund or receipt outcome. Contradictory known confirmation contexts are refused.
Self-selected forks and matching forged producer fields deliberately `MATCH`.
All results retain separate unfilled authority/canonicality/finality gates,
`recovery_action: NONE`, and application/core **NO-GO**.

ASCII JSON is bounded to 512 KiB and 16 nesting levels before parsing; duplicate
keys, nonfinite values and malformed/non-ASCII wire are refused. Raw hash data
is bounded to 4096 bytes. These limits qualify local parsing, not a network
denial-of-service assessment.

## Reorg evidence policy is a plan, not durable storage

`compare_candidates` structurally checks both supplied branches under the same
caller anchor. It classifies an identical branch, extension, shorter prefix,
divergent fork or unknown input. The previous branch must cover every retained
inclusion. Displaced confirming contexts and affected inclusion ids are returned
for later **trusted reconciliation**. The same header appearing on another fork
does not bypass rechecking its changed confirmation context.

Every plan retains both evidence sets, exact originals and possible disclosure;
it forbids restoring an older journal, replenishing charged work or selecting a
replacement original. A shorter/empty provider reply cannot erase positive
evidence. Even a valid extension selects no canonical branch and establishes no
finality. No RPC source, network/genesis pin, consensus authority or number of
confirmations is selected as trustworthy.

This is a pure retention/recheck plan. It writes no record, restores no journal,
persists no original bytes and provides no power-loss, rewind or clone protection.
The result explicitly says `durable_retention: NOT_IMPLEMENTED` and
`accepted_branch: NONE`. Connecting it to recovery requires a separately assessed
authority, durable evidence/original custody and protected reconciliation order.
Trusted reconciliation must revalidate funding and the live entry even when
their earlier headers lie in the common prefix. The returned displaced-inclusion
list is not the complete funding/recovery authorization checklist.

## Actual unchanged-core comparison

One independent MIT Go overlay executes 24 hash/content/header vectors and 26
source controls in `verifier`. It checks raw layouts, excluded producer fields,
version/price/data rules, previous-context linkage and legacy content lookup/order
with explicit ledger stubs. Static controls reject missing/invalid signatures
and a changed payload. No private key or signing backend is used.

Content lookup controls use explicitly claimed block hashes and a disposable
empty account frontier. They qualify the selected helper, not account payload
admission or authenticated inclusion. Dynamic Plasma's full content pricing,
momentum timestamp wall-clock checks, changes patches and producer election are
unperformed. The driver requires all 50 subtests, the parent and package pass;
missing/duplicate/foreign/failing/skipped output is incomplete evidence.

Source/input/tool hashes are checked before and after. Native streams remain
private and bounded; durable hosted stream custody remains unqualified. The
compiler/cache/environment/host are trusted, and overlay vet is explicitly
unperformed because Go 1.23 cannot resolve the synthetic overlay path. See
[validation evidence](NOM_MOMENTUM_VALIDATION.md) for separate local/hosted gates.

Next: independently select and assess observation authority and exact network
profile, then qualify durable preservation of originals, positive/displaced
evidence and disclosure across restart/reorg/restore before any journal admission.
Stage 0 authorizes no activation, wallet operation, broadcast or funds.
