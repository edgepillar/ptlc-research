# NoM receive commit source and license notice

Modification date: 2026-10-19.

`compatibility/nom_receive_commit_test.go.txt` extends the GPL-3.0-only
[receive sequencing probe](https://github.com/edgepillar/ptlc-research/blob/a03178187c5dff16dcd0c3abe3de7b389d16a7e2/compatibility/nom_receive_sequencing_test.go.txt).
That probe adapts the public-genesis PTLC setup, held-receive mechanism and mock
supervisor patterns from
[`zenon/mock/ptlc_delayed_receive_test.go`](https://github.com/zenon-network/go-zenon/blob/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe/zenon/mock/ptlc_delayed_receive_test.go)
and the surrounding go-zenon mock harness at commit
`85c39796fa5ab6fb5ca16e61af34b6616f0ceafe`. Attribution remains with the
go-zenon authors and contributors. Their endorsement or independent review is
not asserted.

The new probe preserves the original attribution header and adds head receive
insertion, confirming momentums, a later method-error receive, exact committed
block comparisons and bounded observations for both finite cases. This notice
extends the [preceding attribution](NOM_RECEIVE_SEQUENCING_NOTICE.md) to the new
file. The retained header and executable probe bytes identify the same source
subject used by its original Go execution.

The adapted Go file is distributed under **GPL-3.0-only**, separately from the
project MIT license. The complete selected upstream license is retained at
[`licenses/GPL-3.0-go-zenon.txt`](../licenses/GPL-3.0-go-zenon.txt), SHA-256
`3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`.
The probe SPDX header and selection manifest preserve this exception.

The original Python reader, synthetic controls and explanatory documents retain
the project MIT license. Existing dependency notices remain unchanged. No
upstream node implementation, dependency archive or executable is bundled.
