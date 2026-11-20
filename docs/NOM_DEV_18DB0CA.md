# NoM dev source tracking at 18db0ca

The tracked upstream dev commit is `18db0ca1777df64ce87940f3534b78db4abcd7d1`.
Only `.github/workflows/test.yml` and `.github/workflows/znn_builder.yml`
changed from [`54f6bad`](NOM_DEV_54F6BAD.md). The complete index retains 619
file records from that inventory. Those records include all 18 direct PTLC
files, the Go dependency locks and the upstream GPLv3 license.
[Pinned upstream comparison](https://github.com/zenon-network/go-zenon/compare/54f6badac5064d7ca82c3dd86f0e539d9077e25b...18db0ca1777df64ce87940f3534b78db4abcd7d1)

| Evidence | Value |
| --- | --- |
| Upstream Git tree | `77eb6fec9371109a01f0898e8fd1cf773183e05e` |
| Complete source inventory | 621 files, 9,777,883 bytes |
| Complete index SHA-256 | `36da59a1dc56550e6fc44e2653d05e0bb7c11065f05814fa1065e7025363ceb5` |
| [Workflow delta](../compatibility/nom_dev_18db0ca_source_delta_v1.json) | 458 bytes, SHA-256 `96024906955d66fd2c47a20962f20395b07fed72be577667bb7e4090727f066c` |
| Original changed blobs | 12,305 bytes across two files |

The two original workflow blobs were checked against their Git blob IDs and
SHA-256 digests. The [offline reader](../qualification/nom_dev_18db0ca_source.py)
reconstructs the pinned inventory and tree from the retained base records and
the two-file delta. The repository stores the records and their digests.

[Upstream PR #315](https://github.com/zenon-network/go-zenon/pull/315) adds
push-triggered test runs for `dev`, `testnet` and `master` to the test workflow.
The release workflow retains tag and manual triggers and drops its `dev` and
`testnet` branch-push triggers. The separate automatic test run on the exact
`dev` commit passed. Release builds and the vulnerability scan belong to the
release workflow.
[Exact upstream dev push run](https://github.com/zenon-network/go-zenon/actions/runs/44715732937/attempts/1)

The qualified behavior and journal pin remains `77ba9c7`. The shared behavior
changes before `54f6bad` remain in the [earlier impact record](NOM_DEV_54F6BAD.md).
Native compatibility for `18db0ca` and independent assessment remain **UNFILLED**.
Application and core remain **NO-GO**. Action permission remains **NONE**.
