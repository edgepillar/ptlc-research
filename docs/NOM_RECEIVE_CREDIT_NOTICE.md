# NoM explicit receive credit source and license notice

Modification date: 2026-10-19.

`compatibility/nom_receive_credit_test.go.txt` extends the GPL-3.0-only
[receive commit probe](https://github.com/edgepillar/ptlc-research/blob/5ed6b08e278a33805dde12f8f1813fc935cb375b/compatibility/nom_receive_commit_test.go.txt).
That probe adapts public-genesis PTLC setup and mock supervisor patterns from
[`go-zenon` commit `85c3979`](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe).
Attribution remains with the go-zenon authors and contributors. Their endorsement
or independent review is not asserted. The preceding
[receive commit notice](NOM_RECEIVE_COMMIT_NOTICE.md) remains unchanged.

The new probe adds explicit user receive insertion and confirmation, exact
synthetic balance comparisons, an unchanged other-user balance and refusal of
a duplicate receive. It preserves the original attribution and retains
**GPL-3.0-only** terms separately from the project MIT license. The full upstream
license remains at [licenses/GPL-3.0-go-zenon.txt](../licenses/GPL-3.0-go-zenon.txt),
SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`.

The original Python reader, synthetic controls and explanatory documents retain
the project MIT license. No upstream implementation or executable is bundled.
