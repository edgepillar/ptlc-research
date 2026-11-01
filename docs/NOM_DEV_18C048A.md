# Tracked go-zenon dev source at 18c048a

This M1 D6 item binds the complete source and the shared storage/lifecycle delta.
It selects no new native engine, client behavior, journal source or operational
recovery. Application/core remain **NO-GO**, recovery authority **NONE**, and
independent assessment **UNFILLED**.

## Immutable source and acquisition

| Subject | Selection |
| --- | --- |
| Tracked source | [`18c048abb3f825274fa7b6900b65bd691ced15ef`](https://github.com/zenon-network/go-zenon/tree/18c048abb3f825274fa7b6900b65bd691ced15ef), tree `460c182324f021e0e54b23fcf6df6d19a98f5e3b` |
| Previous tracked source | [`821bdd25eabacbf8a07b6310986f38713f27b4e3`](https://github.com/zenon-network/go-zenon/tree/821bdd25eabacbf8a07b6310986f38713f27b4e3); its [source corpus](NOM_DEV_821BDD2.md) and [finite Linux comparison](NOM_DEV_821BDD2_NATIVE.md) retain their own subjects |
| Selected behavior and journal | `77ba9c7ee8c881e90911946756cdb67d8b586043`; unchanged by this tracking item |

The [525-file inventory](../compatibility/nom_dev_18c048a_source_v1.json) is
107,908 bytes, SHA-256
`59300ed77726277034f9bccdab63c78b2e38a0ac01bb13a8d6b838a95ac99f7a`.
The retained source ZIP is 2,076,928 bytes, SHA-256
`98b7c5ec34484b26159d9dbad4cbcd34426f8969caf607652036e406ed95a55c`.
Regular source members total 8,552,692 bytes.

The acquisition checked every source member's bytes, Git blob, SHA-256 and
logical mode, then recomputed the complete Git tree. Opening and terminal dev
observations both selected this commit on 2026-11-01. No source extraction,
materialized compiler tree or native process was needed. HTTPS and Git content
IDs do not establish independent producer, compiler or release authentication.

The source ZIP reader is unchanged from its existing two positive and 16
negative controls. The strict UTF-8 metadata decoder retains duplicate-key and
nonfinite refusals; its seven JSON refusals and the 16 source-specific metadata
substitutions are author-run reader controls. They are not native results or
independent review. Original successful transports and historical failures stay
preserved; this item needs no repeated old archive transport or native test.

Upstream [GPL version 3 source](https://github.com/zenon-network/go-zenon/blob/18c048abb3f825274fa7b6900b65bd691ced15ef/LICENSE)
was obtained separately and is not vendored or relicensed. `LICENSE`, `go.mod`
and `go.sum` retain their previous complete bytes. The inventory records source
metadata; it contains no copied Go implementation.

## Complete delta and PTLC relevance

The source is six commits ahead of 821bdd2: two files added, six modified, none
removed, and 517 byte-identical files. Against the selected 77ba9c7 behavior
source, four files are added, eleven modified and 510 byte-identical. All 18
PTLC-named paths remain byte-identical. These complete inventories also cover
verifier/VM, sequencing/pool, insertion/rollback, momentum/time, ABI/RPC,
Plasma/spork, serialization and dependency inputs.

| Changed surface | Source finding and remaining boundary |
| --- | --- |
| `common/db/enable_delete.go` | [PR #246](https://github.com/zenon-network/go-zenon/pull/246) adds `Next`, `Prev` and `Last` wrappers that skip raw empty deletion markers. `Put` retains its existence-byte encoding and `Get`/`Has` are unchanged. This changes shared iteration after deletion/rollback; direct PTLC-file equality does not qualify the storage composition. |
| `definition/sentinel.go`, `definition/accelerator.go` | [PR #243](https://github.com/zenon-network/go-zenon/pull/243) guards empty values in `GetAllSentinelInfo`, `IterateSentinelEntries` and `GetProjectList` before parsing. These collection readers belong to other embedded contracts, rather than a new PTLC method or witness rule. |
| `protocol/handler.go`, `protocol/sync.go` | [PR #238](https://github.com/zenon-network/go-zenon/pull/238) includes `txsyncLoop` in the protocol manager's wait group and replaces the unowned ticker with a stopped `NewTicker`. This is lifecycle work relevant to later shutdown tests, not evidence of a node run or recovered swap. |
| Added DB/definition tests and modified protocol test | The DB file declares six parents, including actual LevelDB `Pop` and reopen cases; the definition file declares three. The protocol file adds a Start/Stop parent beside the retained Stop-twice parent. Presence is not execution. Its goroutine-growth branch logs a message rather than failing, so it is not a proof of general leak freedom. |

The inspected [PTLC RPC API](https://github.com/zenon-network/go-zenon/blob/18c048abb3f825274fa7b6900b65bd691ced15ef/rpc/api/embedded/ptlc.go#L43)
has by-id entry and reclaim-lock reads. They call definition getters using
`DB.Get`; it exposes no PTLC collection-list method. The iterator delta must not
be described as a changed PTLC list RPC. The unchanged PTLC definitions,
implementation and dependency inputs introduce no direct ABI, witness, message
hash or fee-rule edit in this delta. That is a bounded source finding, not a
general equivalence or consensus-neutrality claim.

The historical-view [manager path](https://github.com/zenon-network/go-zenon/blob/18c048abb3f825274fa7b6900b65bd691ced15ef/common/db/versioned_db.go#L603)
merges raw rollback/frontier layers before the outer enable-delete wrapper.
Duplicate-key suppression and deletion masking therefore belong to the composed
iterator, not only the new loop. The unchanged merged iterator rejects reverse
iteration with an error. Single-memory-backend `Prev`/`Last` tests do not qualify
reverse iteration on historical merged views. Empty application values and
raw deletion markers also need separate expectations; filtering an empty raw
marker is not a universal empty-value policy.

## Executable inventory boundary

The [index reader](../qualification/nom_dev_18c048a_source.py) reuses the existing
strict schema/tree checks. It binds the new inventory, the prior tracked 821bdd2
inventory and the 77ba9c7 comparison input to their own complete bytes. It opens
no source ZIP, compiler or node. The [three test selectors](../tests/test_nom_dev_18c048a_source.py)
cover complete delta/non-authority output, seven missing/substituted inventory
cases, and explicit archive/process nonexecution. Their source-bound execution
and applicable hosted acceptance must be recorded separately from acquisition.

For an owned qualification environment:

```sh
python3 -B -W error::ResourceWarning -m unittest discover -s tests -p 'test_nom_dev_18c048a_source.py' -v
```

This work item ends with complete source/delta binding and its relevant checks.
It does not promote a new behavior source. The earlier 821bdd2 native results
cannot be relabeled as 18c048a compatibility.

## Next native gate before a behavior upgrade

1. Select this complete source in a separate finite native plan and run the
   applicable preserved contract/account/fee profiles against it. Keep exact
   originals and source identity; unchanged direct PTLC files are insufficient.
2. Add explicit storage expectations for live/deleted rows, complete prefixes,
   deletion masking across snapshots, `Pop`, reopen and lookup/iteration
   distinctions. Preserve unsupported merged reverse iteration and iterator
   errors; name malformed-row and empty-value exclusions rather than inferring
   them from ordinary tests.
3. Treat sentinel/project collection guards and protocol shutdown as separate
   scopes. No mock Start/Stop result qualifies real networking, chain truth,
   signer restore, bilateral funding or operational recovery.
4. Reuse verified compiler/module inputs in one newly admitted owned workspace;
   do not adopt closed caches, repeat completed native runs for bookkeeping or
   change production resource limits to admit work. Separate local comparison,
   hosted PR, normal main integration and own-main original acceptance.

Compiler authentication, independent assessment and the application/core gates
remain unfilled. No signing, wallet access, activation, broadcast or funds follow
from this corpus.
