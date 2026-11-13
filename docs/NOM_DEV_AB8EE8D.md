# NoM dev source tracking at ab8ee8d

The complete upstream ZIP was checked against its Git tree and all 574 file
records. The offline reader reconstructs that inventory from the preserved
`008bdcd` index and this 39-entry delta: 12 added paths, 27 changed records,
535 unchanged records and no removals.
[Pinned upstream comparison](https://github.com/zenon-network/go-zenon/compare/008bdcd60f65923952f27a9d9a8c39fba7254a21...ab8ee8da3a50231b0910c536632e9b05fff42795)

| Input | Value |
|---|---|
| Tracked commit | `ab8ee8da3a50231b0910c536632e9b05fff42795` |
| Git tree | `9576b71caf1dcf0e6931e2c39af53522b63102c6` |
| Complete source | 574 files and 9,161,440 bytes |
| Complete index SHA-256 | `951dbafdc8d86a87de720f6c6cd8df08fcb083d9da9751728810445497992818` |
| Delta SHA-256 | `31c197201b5196794d0b02caabdc4b58c01e36e538ee41896b3233a5622d7c45` |
| Original ZIP SHA-256 | `4f1e9dd18c875dbc76f2f0e3e58345cc90e64f7f202c2443c0b0ee31abd1584b` |

All 18 direct PTLC files, the GPLv3 license and `go.sum` retain their previous
bytes and modes. `go.mod` changes: the existing `golang.org/x/net v0.25.0`
requirement moves from indirect to direct. The archive comparison checked that
this was the complete module-file change. The index reader checks exact
records and hashes; it neither opens the archive nor executes Go.

The selected behavior and recovery journal remain pinned to `77ba9c7`.
The [previous source record](NOM_DEV_008BDCD.md) has a separately accepted finite
Linux comparison of 39 top-level tests in 13 packages. Those originals do not
qualify this revision. The [new finite plan](NOM_DEV_AB8EE8D_NATIVE.md) preserves
all 39 selected tests and adds 89, selecting 128 top-level tests in 19 packages.
Declaring that selection supplies no Go execution result. Native compatibility
for `ab8ee8d` remains **UNFILLED**.

## Changes relevant to the reference client

The pinned comparison includes the merged downloader, HTTP admission,
embedded-refund and acknowledgement-recency changes. Their shared paths affect
a PTLC client even though the direct PTLC file records are unchanged.

| Source change | Client consequence and bounded next check |
|---|---|
| [Acknowledgement recency](https://github.com/zenon-network/go-zenon/blob/ab8ee8da3a50231b0910c536632e9b05fff42795/chain/acknowledgement_recency.go) and its account-pool, producer and verifier callers; [PR #280](https://github.com/zenon-network/go-zenon/pull/280) | Under DynamicPlasmaSpork enforcement at the selected parent, a user block's canonical acknowledgement must cover the sporks active at that parent. Check activation boundaries, delayed activation receive, canonicality, read errors, admission after a frontier change, pool suffix eviction, producer selection and momentum verification separately. |
| [Embedded refund recovery](https://github.com/zenon-network/go-zenon/blob/ab8ee8da3a50231b0910c536632e9b05fff42795/verifier/embedded_refund.go) and [VM refund flow](https://github.com/zenon-network/go-zenon/blob/ab8ee8da3a50231b0910c536632e9b05fff42795/vm/vm.go); [PR #277](https://github.com/zenon-network/go-zenon/pull/277) | Recovery-height lookup targets the positive embedded Burn-to-Token refund case. It does not relax an ordinary user's PTLC Unlock acknowledgement. Check pre/post-spork behavior, delayed activation, actual refund value and the user-receive exclusion. |
| [HTTP admission](https://github.com/zenon-network/go-zenon/blob/ab8ee8da3a50231b0910c536632e9b05fff42795/rpc/server/admission.go) and [request lifecycle](https://github.com/zenon-network/go-zenon/blob/ab8ee8da3a50231b0910c536632e9b05fff42795/rpc/server/http.go); [PR #276](https://github.com/zenon-network/go-zenon/pull/276) | Busy admission can return HTTP 503 with JSON-RPC code -32005 before reading the body. Check request and connection limits, body/drain lifetime, response completion and shutdown. A transport refusal cannot establish chain state or replace a retained transaction original. |
| [Downloader no-progress handling](https://github.com/zenon-network/go-zenon/blob/ab8ee8da3a50231b0910c536632e9b05fff42795/protocol/downloader/downloader.go); [PR #272](https://github.com/zenon-network/go-zenon/pull/272) | Busy imports, in-flight work and a full cache have distinct liveness conditions. Check the declared no-progress controls; a synchronized observer remains a separately selected requirement. |

The acknowledgement requirement is bound to one parent and is not a concurrent
service. Its callers recheck at their own admission or selection boundary. An
RPC verification followed by a frontier change can therefore still be refused
by account-pool admission. Stale account blocks and their later suffix may be
evicted. A client must retain exact originals, account dependencies and UNKNOWN
for ambiguous transport or possible disclosure. Recency refusal supplies no
automatic re-signing, rebasing, fee replacement or recovery authority.

The refund change is gated separately from acknowledgement recency. Its source
presence establishes neither spork activation nor an operational recovery path.
The existing journal format, source selection and original-only recovery rules
are unchanged by this inventory.

## Next acceptance gates

1. Check the declared 128-test selection against this exact source. Preserve
   the independent PR #138 message/hash corpus and prior selected ABI,
   verifier, VM rollback, store-failure and observation controls. Require the
   selected recency, refund, admission and downloader roots to remain present.
2. Execute and retain complete source/build/dependency and original-stream
   evidence for that new plan. Account for the changed module declaration;
   unchanged checksum bytes alone do not qualify dependency acquisition.
   Account for every observed subtest. Hosted PR execution and the exact pushed
   main need separate acceptance.
3. Assess the client consequences against an explicitly selected observation
   and signing policy before changing behavior or journal pins. Independent
   protocol, cryptography and recovery assessment remains **UNFILLED**.

This record supplies source inventory and impact analysis only. Native execution,
complete account admission, live observation, wallet custody, signing, broadcast,
activation and funds are outside its evidence. Application and core remain
**NO-GO**.
