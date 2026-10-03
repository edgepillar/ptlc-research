# Independent synthetic Bitcoin transaction verification

This offline test module independently checks the Rust-generated public [Bitcoin transaction fixture](../qualification/fixtures/bitcoin_transactions.json). It deserializes real transaction bytes, reconstructs the Taproot commitment, recomputes the Bitcoin sighashes, and executes both spend paths through btcd's script engine. It has no signer, wallet, RPC client, node process, or broadcast operation.

The synthetic funding outpoint is not asserted to exist on any blockchain. The funding amount is 200,000 satoshis; each candidate spend has one output of 199,000 satoshis. These are public test values, not live funds or fee recommendations.

## Pinned implementation

The script engine and finality helper come from `github.com/btcsuite/btcd v0.25.0`, whose annotated release tag resolves to source commit [`e764c170e6a9ec55bc5882b2d2a3302276988a77`](https://github.com/btcsuite/btcd/tree/e764c170e6a9ec55bc5882b2d2a3302276988a77). Its [ISC license](https://github.com/btcsuite/btcd/blob/e764c170e6a9ec55bc5882b2d2a3302276988a77/LICENSE) was inspected. Dependencies are referenced, not vendored. This is a qualification pin, not a recommendation to deploy this release.

The release requires Go 1.23.2; local validation uses the existing isolated Go 1.23.12 toolchain. The newer release inspected during selection requires Go 1.25 and was not silently substituted or used to install another toolchain. `go.mod` and `go.sum` fix module resolution and checksums. Direct supporting modules are `btcec/v2 v2.3.5`, `btcutil v1.1.5`, and `chaincfg/chainhash v1.1.0`. Historical module metadata in `go.sum` does not mean every listed version is compiled.

This dependency graph is separate from `qualification-go/`, which retains the older verifier version used by the Zenon PTLC proposal. Neither module changes the node's dependencies.

## What is checked

- Strict fixture schema and lowercase hexadecimal widths; canonical transaction byte round trips without trailing data; exact transaction ID and witness transaction ID.
- Exactly one input and one output, the stated funding outpoint, empty input script, selected sequence, locktime, destination script, output amount and fee.
- Reconstruction of the single Alice-only refund leaf from the declared refund key and timestamp: `<L_B> CHECKLOCKTIMEVERIFY DROP <A_R> CHECKSIG`.
- Independent leaf hash, single-leaf Merkle root, aggregate-internal-key Taproot tweak, funding output key/script, and exact 33-byte control-block commitment including output parity.
- Independent key-path claim and script-path refund `SIGHASH_DEFAULT` calculations matching the exported Rust digests.
- Actual `txscript.NewEngine` execution with the pinned release's `StandardVerifyFlags`, including witness and Taproot verification. Claim witness is exactly one 64-byte signature; refund witness is signature, leaf script and control block. Neither selected spend includes an annex.
- Rejection of changed claim outputs, previous-output amount or key, an added annex, and a 65-byte signature with an explicit zero default-sighash byte.
- Rejection of modified refund script/control block and of unsatisfied CLTV conditions. Below-threshold locktime, wrong height/time domain and final input sequence must return `ErrUnsatisfiedLockTime`; a generic signature failure is not accepted as evidence for those checks.
- Rejection of truncated or trailing transaction bytes.

Each mutation gets a fresh previous-output fetcher and signature-hash cache. A cache from the unmodified transaction cannot conceal a changed signed input.

## Script checks are not chain finality

The refund script compares its embedded bound with the transaction's own locktime and requires a nonfinal sequence. The script engine takes no chain height or median-time-past input. Its acceptance therefore does not establish that the refund is currently mineable.

A separate test invokes btcd's pure `blockchain.IsFinalizedTransaction` helper with supplied synthetic timestamp context. The same script-valid refund is not final when that timestamp is before or exactly equal to its locktime, and is final when it is greater. Supplying synthetic context does not obtain or validate a real chain's median time; the test is limited to the helper's transaction-level rule. See the pinned [finality helper](https://github.com/btcsuite/btcd/blob/e764c170e6a9ec55bc5882b2d2a3302276988a77/blockchain/validate.go) and [script engine](https://github.com/btcsuite/btcd/blob/e764c170e6a9ec55bc5882b2d2a3302276988a77/txscript/engine.go).

This module does not run full transaction/block validation, prove UTXO existence, establish mempool/package acceptance, simulate a claim/refund race, or demonstrate inclusion, confirmations or finality. Script flags include policy checks but do not amount to the full mempool policy. It also does not independently reconstruct the two participants' aggregate internal key: that key is a public fixture input produced by the Rust aggregate-signing exercise. The Go engine independently validates the resulting spend signatures and Taproot commitment, not the adaptor exchange's security.

## Reproduction

Use Go 1.23.12 with the full repository checkout available. From this module's directory, populate an approved dependency cache once:

```sh
GOTOOLCHAIN=local go mod download all
```

Then test without dependency network access or module-file changes:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -mod=readonly -count=1 -v ./...
```

`GOMODCACHE`, `GOPATH` and `GOCACHE` can select isolated directories. The tests read the shared fixture but never rewrite it.

## Validation history

The initial offline compile-only check succeeded before fixture delivery and executed zero tests. The first fixture-dependent offline run then passed all **7 top-level tests and 15 named subtests**, with no failures or skips. Both actual script-engine spends, both independently recomputed sighashes, all mutation controls, and the separate synthetic finality boundary passed. There were no intermediate compile or test failures in this module.

The fixture's output-key parity is odd, so its valid single-leaf control block starts with `0xc1`; flipping that parity is rejected. This is one fixed tree/transaction example, not exhaustive Taproot parity, script or sighash coverage. No node execution or live-chain acceptance is implied by these results.

Stage 3 adds a new claim signature from the public nonce-round fixture. The test installs that signature as the sole claim witness, confirms unchanged txid and changed wtxid, independently recomputes the claim digest, and executes the script engine. Mutated signature and output value reject. The first Stage 3 offline run passed all **8 top-level tests**, with no compile or assertion failures. See [STAGE3_VALIDATION.md](../docs/STAGE3_VALIDATION.md).
