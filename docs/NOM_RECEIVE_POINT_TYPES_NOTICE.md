# NoM receive point-type source and license notice

Modification date: 2026-10-20.

`compatibility/nom_receive_point_types_test.go.txt` extends the GPL-3.0-only
[explicit receive credit probe](https://github.com/edgepillar/ptlc-research/blob/20a9c0740547a8df12d0b66a93301e46b01366fd/compatibility/nom_receive_credit_test.go.txt).
It adds finite ED25519, BIP340 and compressed secp256k1 point cases using public
synthetic fixture values. Its original header and reference to the preceding
[credit notice](NOM_RECEIVE_CREDIT_NOTICE.md) remain unchanged. The added probe
retains GPL-3.0-only terms separately from the project MIT license.

The harness patterns originate in
[`go-zenon` commit `85c3979`](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe).
Attribution remains with the go-zenon authors and contributors; endorsement or
independent review is not asserted. The complete license remains at
[licenses/GPL-3.0-go-zenon.txt](../licenses/GPL-3.0-go-zenon.txt), SHA-256
`3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`.

The original Python reader, synthetic controls and explanatory documents retain
the project MIT license. No upstream implementation or executable is bundled.
