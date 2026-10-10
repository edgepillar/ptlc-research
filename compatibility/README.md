# PR #138 compatibility profile

This additive, synthetic offline subject pins
[`go-zenon` PR #138](https://github.com/zenon-network/go-zenon/pull/138) at
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`, base
`c64ed6279ff1d07335dab0ac36156dec8b5b71e9`.
The older PR #13 corpus, message rule and locked qualification graphs are retained.
They are separate profiles and are not migrated or relabeled.

The new preimage is 101 bytes:
`ASCII("zenon-ptlc-unlock:v1") || uint64be(chain) || contract20 || type1 || id32 || destination20`.
The message is SHA3-256. It is neither Keccak-256 nor the old 52-byte rule.
The codec rejects unknown versions, extra fields, integer aliases and width errors.
Encoding a zero or reserved destination does not establish that it is payable.

The standalone Go test module pins PR #138's relevant verifier resolution:
btcec 2.2.0, secp256k1 4.2.0, edwards25519 1.1.0 and x/crypto 0.31.0.
It is independent of the legacy Go modules. Rust uses the existing locked graph.
The Rust SHA3 helper is test-only reference arithmetic and is not an application
hash implementation. Python uses its standard SHA3 implementation.

Fixtures are independently generated synthetic inputs under this repository's
MIT license. No GPL node implementation or unlicensed console code is copied.
Public source attribution is recorded in `manifest.json`. Ordinary BIP340
acceptance is not adaptor-protocol safety, node activation or a successful swap.
ED25519 results describe the pinned Go decoder/cofactor and Go signature verifier;
they do not assert strict canonical prime-subgroup admission.

Witness vectors are primitive-verifier inputs over supplied messages, distinct
from the independently checked domain-encoding vectors. The NoM completion
fixture separately verifies the complete, type-1 core message binding. This
corpus does not substitute primitive checks for VM/stateful contract tests.

Run `python3 -m unittest discover -s tests -p 'test_pr138_compatibility.py'`,
`go test -mod=readonly ./...` in `pr138-go`, and the locked Rust qualification
tests. `PTLC_REGENERATE_PUBLIC_PR138_V1=1` regenerates synthetic witness fixtures
inside the Go tests; it is never a signing interface for application inputs.

Core VM storage, activation combinations, refund rollback and confirming-momentum
semantics remain upstream test obligations. A private pinned-node differential
run supplements this corpus; it is not silently counted as a hosted core test.

`scripts/qualify_pr138_core.py` uses an independently written test overlay against
the exact clean node pin, with offline dependency resolution. Go 1.23's vet cannot
open the synthetic overlay path, so vet is explicitly disabled for this narrow
differential run. Normal corpus-module tests retain their default vet behavior.
The first overlay attempt failed before test execution and its original private
log is retained separately from the corrected run.
