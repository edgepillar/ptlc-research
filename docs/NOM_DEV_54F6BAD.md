# NoM dev source tracking at 54f6bad

The tracked dev commit is `54f6badac5064d7ca82c3dd86f0e539d9077e25b`.
The original source ZIP was checked in memory against every blob in the pinned
Git tree. The index uses the file modes from that tree. The delta covers 109
commits after `ab8ee8d`. It records
52 additions, 60 modifications and five removals. The other 509 records include
all 18 direct PTLC files and the upstream GPLv3 license. Both `go.mod` and
`go.sum` changed.
[Pinned upstream comparison](https://github.com/zenon-network/go-zenon/compare/ab8ee8da3a50231b0910c536632e9b05fff42795...54f6badac5064d7ca82c3dd86f0e539d9077e25b)

| Evidence | Value |
| --- | --- |
| Base inventory | [`ab8ee8d`](NOM_DEV_AB8EE8D.md), 574 file records |
| Upstream Git tree | `93152e797c18aef0ce49c96ee63450faa1e11b3c` |
| Complete source | 621 files, 9,776,906 bytes |
| Complete index SHA-256 | `5f7c22b96384ce270e9773febb4f0136b1a64d832a91e1a21fbc8912e00d2be9` |
| [Delta](../compatibility/nom_dev_54f6bad_source_delta_v1.json) | 23,166 bytes, SHA-256 `039187252c6d6dfa383863cdccbb3f75b773a0f88a84b57467ecc366136ecf2d` |
| Original upstream ZIP | 2,442,216 bytes, SHA-256 `0e70b556e7c7c01d7a7399637a3e1ea1930ceac67ac7a2c05c75e6c47ca791d6` |

The [offline reader](../qualification/nom_dev_54f6bad_source.py) reconstructs
the complete index from the previous index and the tracked delta. It checks
disjoint path sets and the complete index digest and Git tree. The tracked
artifact contains file records only. The tests read those records without
opening an archive or starting a process. They exercise the actual removals
and refuse missing, duplicate, unknown and overlapping removals, overlapping
additions, no-op modifications, unexpected fields and changed digests.

```sh
python3 -B -W error::ResourceWarning -m unittest discover -s tests -p test_nom_dev_54f6bad_source.py
```

## Shared paths relevant to PTLC

| Source change | Scope for later native qualification |
| --- | --- |
| [`chain` binds its database to the genesis spork address](https://github.com/zenon-network/go-zenon/blob/54f6badac5064d7ca82c3dd86f0e539d9077e25b/chain/chain.go), [upstream PR #286](https://github.com/zenon-network/go-zenon/pull/286) | Bind the observation subject to the selected genesis and spork authority. Check startup and restore with the expected configuration and refusal of mismatched chain metadata. |
| [Detailed momentum RPC has an encoded-byte limit](https://github.com/zenon-network/go-zenon/blob/54f6badac5064d7ca82c3dd86f0e539d9077e25b/rpc/api/ledger_types.go), [upstream PR #281](https://github.com/zenon-network/go-zenon/pull/281) | Treat a `more` result as a partial range. Compare contiguous continuation, an oversized first item and interrupted pages before relying on a complete observation. |
| [Embedded dispatch and ABI validation share the spork variant selector](https://github.com/zenon-network/go-zenon/blob/54f6badac5064d7ca82c3dd86f0e539d9077e25b/vm/embedded/embedded.go), [upstream PR #300](https://github.com/zenon-network/go-zenon/pull/300) | Compare the released ladder across acknowledgement heights. Check the separate PTLC and Dynamic Plasma gates and agreement between method dispatch and trailing-byte validation. |
| [RPC IPC endpoint removal](https://github.com/zenon-network/go-zenon/pull/282) | Check both module locks and compile the selected RPC path without the removed IPC files. Preserve explicit request and response boundaries in any later observer. |
| [Shared account pool, verifier and VM changes](https://github.com/zenon-network/go-zenon/compare/ab8ee8da3a50231b0910c536632e9b05fff42795...54f6badac5064d7ca82c3dd86f0e539d9077e25b) | Keep pool observation, account admission, embedded execution and journal recovery as separate evidence. Select the affected behavior using the complete delta before qualifying a new native source. |

The behavior and journal pin is `77ba9c7`. The finite native results for
earlier revisions retain their own source and limits. The `54f6bad` inventory
establishes source correspondence. Its native compatibility and independent
assessment are **UNFILLED**. Application and core are **NO-GO**. Action
permission is **NONE**.
