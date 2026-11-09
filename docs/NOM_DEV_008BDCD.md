# NoM dev source tracking at 008bdcd

The complete source inventory was checked against the original upstream ZIP
and Git tree. The offline reader reconstructs all 562 file records from the
previously verified `18c048a` inventory and a 126-entry delta. The delta adds
37 paths and replaces 89 records. The other 436 file records retain their
exact bytes and modes. The reader checks the complete index digest and Git
tree again. [Pinned upstream comparison](https://github.com/zenon-network/go-zenon/compare/18c048abb3f825274fa7b6900b65bd691ced15ef...008bdcd60f65923952f27a9d9a8c39fba7254a21)

| Input | Value |
|---|---|
| Tracked commit | `008bdcd60f65923952f27a9d9a8c39fba7254a21` |
| Git tree | `75972edb844964cab52639209c3610aa9dc1cc81` |
| Complete source | 562 files and 8,971,060 bytes |
| Complete index SHA-256 | `c4a98ce0abbfb61702d1981a47bd64a09e20a6aa3fb2acdf8ee00a4ed23bbf76` |
| Delta SHA-256 | `4a6e0cf58bbade03d094da17979b361c373a6c8c2d0948042fad347bd06e5e67` |
| Original ZIP SHA-256 | `bb6db6683795515669b88cb8e293c32e00494514d388324ebe5af55b4d63849a` |

The source retains the same 18 PTLC paths, GPLv3 license and Go dependency
files as the previous tracked revision. The selected behavior and journal
remain pinned to `77ba9c7`.
[Previous source record](NOM_DEV_18C048A.md)

## Finite native comparison

The Linux workflow selects 39 top-level tests in 13 packages and checks every
observed subtest. It uses the unchanged project PR #138 corpus and the
upstream unlock and reclaim message vectors. It also selects synthetic ABI,
account-block decoding, VM rollback, store failure, verifier, and observation
controls. The workflow runs the entire selection in one `go test` command.

Dependency acquisition uses an alternate module lock pair and a fresh module
cache. The runner verifies the downloaded modules, then reuses the same cache
with module and checksum network access disabled. The native command reads
the unchanged upstream lock files. The source view is checked before and
after the command. The runner retains only explicitly selected safe original
streams and a bounded receipt. The receipt records failed or incomplete
execution separately from passing test values.

The workflow definition is a reproducible test plan. Native compatibility
and producer authentication require separately bound execution evidence.
The selection does not cover live observation, full account admission or
source selection for the recovery journal.

## Source boundaries

1. Reuse the independent PR #138 message and hash vectors. Add fixed-width ABI
   and nested account-block decoding refusals around the same inputs.
   [ABI checks](https://github.com/zenon-network/go-zenon/blob/008bdcd60f65923952f27a9d9a8c39fba7254a21/vm/abi/error.go)
   [Account-block decoding](https://github.com/zenon-network/go-zenon/blob/008bdcd60f65923952f27a9d9a8c39fba7254a21/chain/nom/account_block.go)
2. Exercise rollback before the VM saves a snapshot, inverse-read failure
   before a store write, and auto-receive generation failure. A local
   generation error leaves the foreign verdict unresolved.
   [VM lifecycle](https://github.com/zenon-network/go-zenon/blob/008bdcd60f65923952f27a9d9a8c39fba7254a21/vm/vm_context/lifecycle.go)
   [Versioned store](https://github.com/zenon-network/go-zenon/blob/008bdcd60f65923952f27a9d9a8c39fba7254a21/common/db/versioned_db.go)
   [VM execution](https://github.com/zenon-network/go-zenon/blob/008bdcd60f65923952f27a9d9a8c39fba7254a21/vm/vm.go)
3. Compare bounded mailbox scans and subsecond time lookup. Retain an unknown
   observation when the selected page or chain evidence is incomplete.
   [Ledger queries](https://github.com/zenon-network/go-zenon/blob/008bdcd60f65923952f27a9d9a8c39fba7254a21/rpc/api/ledger.go)
   [Momentum time lookup](https://github.com/zenon-network/go-zenon/blob/008bdcd60f65923952f27a9d9a8c39fba7254a21/chain/momentum/range.go)

The observed open proposals for enforced-spork acknowledgement, genesis
spork authority binding and detailed-momentum response limits require separate
comparisons if adopted. An acknowledgement that becomes stale does not grant
retry or signing authority. [PR #280](https://github.com/zenon-network/go-zenon/pull/280)
[PR #286](https://github.com/zenon-network/go-zenon/pull/286)
[PR #281](https://github.com/zenon-network/go-zenon/pull/281)

Application and core remain **NO-GO**. Independent assessment remains
**UNFILLED**.
