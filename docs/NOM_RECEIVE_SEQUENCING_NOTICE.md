# NoM receive sequencing source and license notice

Modification date: 2026-10-19.

`compatibility/nom_receive_sequencing_test.go.txt` adapts the public-genesis
PTLC setup, held-receive mechanism and mock supervisor patterns from
[`zenon/mock/ptlc_delayed_receive_test.go`](https://github.com/zenon-network/go-zenon/blob/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe/zenon/mock/ptlc_delayed_receive_test.go)
and the surrounding go-zenon mock harness at commit
`85c39796fa5ab6fb5ca16e61af34b6616f0ceafe`. Attribution remains with the
go-zenon authors and contributors. This notice does not assert their
endorsement or independent review of this research.

The selected upstream [LICENSE](https://github.com/zenon-network/go-zenon/blob/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe/LICENSE)
contains the GNU General Public License version 3. The adapted probe is
distributed under **GPL-3.0-only**, separately from the project MIT license.
The complete selected license text is retained verbatim at
[`licenses/GPL-3.0-go-zenon.txt`](../licenses/GPL-3.0-go-zenon.txt),
SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`.
The probe's SPDX header and manifest preserve this exception.

Project modifications add the paired Unlock-first and Reclaim-first cases,
out-of-order receive refusal checks, precise confirmation/expiry observations,
non-commit checks and bounded public JSON records. These are test-only source
changes; no upstream node implementation or dependency archive is bundled.
The original Python reader, its synthetic controls and accompanying explanation
retain the project MIT license. Existing dependency notices are unchanged.
