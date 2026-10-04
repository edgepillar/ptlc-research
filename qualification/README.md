# Offline adaptor primitive qualification

This crate is a synthetic test harness, with no production signing API. It contains no wallet, RPC client, chain submission, or node dependency. Fixed scalar and nonce inputs in the tests are deliberately public examples and must never be used with funds.

The harness evaluates existing implementations. It does not implement curve arithmetic, a new adaptor construction, or an aggregation formula. `publish = false` prevents publishing this crate through Cargo's normal package publishing command.

## Pinned implementations

| Package | Immutable source | Enabled direct features | License |
| --- | --- | --- | --- |
| `musig2` 0.4.1 | [`5a09b1197b1b5c621a5a9abc60fa95fa84a1da30`](https://github.com/conduition/musig2/tree/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30) | Defaults disabled; `secp256k1` | [Unlicense](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/LICENSE) |
| `schnorr_fun` 0.13.0 | [`74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce`](https://github.com/LLFourn/secp256kfun/tree/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce) | Defaults disabled; `std` | [0BSD](https://github.com/LLFourn/secp256kfun/blob/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/schnorr_fun/LICENSE); separately licensed vendored code |
| `bitcoin` 0.32.7 | Exact registry release; upstream release tag resolves to [`8aec2406262924220321751deb926b53cc9128d5`](https://github.com/rust-bitcoin/rust-bitcoin/tree/8aec2406262924220321751deb926b53cc9128d5) | Defaults disabled; `std` | [CC0-1.0](https://github.com/rust-bitcoin/rust-bitcoin/blob/8aec2406262924220321751deb926b53cc9128d5/LICENSE) |

`Cargo.lock` records exact transitive resolution and registry checksums. Test utilities additionally use `sha2` and `serde_json`. The active C verification path resolves `secp256k1` 0.31.1 and `secp256k1-sys` 0.11.0. A lockfile may contain optional or alternate-target packages that are not compiled for this feature/target selection; it is not evidence that every listed package executes.

The transaction tests additionally activate rust-bitcoin's `secp256k1` 0.29.1 / `secp256k1-sys` 0.10.1 path (both CC0-1.0). The exact `bitcoin` registry checksum is `0fda569d741b895131a88ee5589a467e73e9c4718e958ac9308e4f7dc44b6945`; the upstream tag link is source context, not a claimed byte-for-byte equivalence audit of the published crate. Newly resolved support packages are `base58ck` 0.1.101, `bitcoin-internals` 0.3.0, and `bitcoin-units` 0.1.101 (CC0-1.0), `bech32` 0.11.1 (MIT), and `hex_lit` 0.1.1 (MITNFA). Versions and license identifiers were checked in the downloaded package manifests. No dependency is adopted as a production signer.

Final signatures are checked through three entry points: direct `libsecp256k1` Schnorr verification, `musig2` verification, and `schnorr_fun` verification. The first two share the C curve backend; `schnorr_fun` provides the separate Rust arithmetic path. This is not a claim of three independently developed cryptographic backends.

## What the tests establish

- All 19 public [official BIP340 vectors](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0340/test-vectors.csv) produce the expected accept/reject result through all three verification entry points. The shared fixture omits secret-key and auxiliary-randomness columns. It includes message lengths 0, 1, 17, 32, and 100 bytes.
- Each candidate completes 32 single-signer adaptor cases. Assertions require all four combinations of original signer-key parity and adapted-nonce parity/negation to execute. Each completed signature passes all three verifiers and returns the expected witness through the candidate's extraction API.
- Negative cases cover wrong pre-signature message, signer key, adaptor point, wrong completion witness, unrelated final signature, an altered final signature, and malformed signature lengths or out-of-range values. `schnorr_fun` also rejects the flipped parity flag in the tested pre-signature.
- A pre-signature does not pass ordinary final-signature verification in the tested encodings. Adaptation success alone is not treated as final-signature validity.
- A two-party MuSig2 case uses two distinct aggregate keys, two distinct messages, and one shared witness. Every partial signature is checked, and both complete pre-signatures are verified before the first completed signature is produced. Extraction from that completed signature permits completion of the second. Incorrect partial-signature/message checks reject in the same exercise.
- The public completed-signature fixture is regenerated through the pinned candidate APIs and compared exactly during every normal run. Tests do not rewrite it.

The original aggregate case in `adaptor_qualification.rs` checks cryptographic linkage only. Its Bitcoin-leg message is a synthetic 32-byte value, **not a Bitcoin transaction sighash**. Its Zenon-leg message is a concrete `SHA3-256(id32 || destination20)` digest matching the proposed contract's message rule. For public synthetic bytes `id32 = 00..1f` and `destination20 = 00..13`, that digest is `e357d6597d0149f0adb2ab0f0d7dff932412e2f55fd9b94bb9301c8ccf9df974`. This is SHA3-256, not Keccak-256. Sources: [contract](https://github.com/zenon-network/go-zenon/blob/8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18/vm/embedded/implementation/ptlc.go), [hash implementation](https://github.com/zenon-network/go-zenon/blob/8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18/common/crypto/hash.go). Full Zenon account-block serialization remains outside these tests. The separate Bitcoin transaction tests below do not change the original four-vector fixture.

## Actual Bitcoin transaction qualification

`tests/bitcoin_transaction.rs` uses rust-bitcoin to construct and serialize two alternative transactions spending one fictional Taproot output. Both have version 2, one input with sequence `0xfffffffd`, and one output. The synthetic previous output is 200,000 satoshis; each alternative pays 199,000 satoshis. This arithmetic does not establish fee adequacy.

The key-path claim pays Bob with locktime zero. Its MuSig2 internal key commits to the actual single refund leaf through `KeyAggContext::with_taproot_tweak`; the result must match `TaprootBuilder` in both x-coordinate and full output parity. The claim's exact BIP341 `SIGHASH_DEFAULT` is passed to both partial-signature operations. Every partial signature and the aggregate pre-signature is checked before completion. The completed signature is verified under the output key using rust-bitcoin's libsecp256k1 binding; extraction must reproduce the witness and its committed point.

The script-path refund pays Alice and signs `<500000100> OP_CHECKLOCKTIMEVERIFY OP_DROP <AliceRefundXOnlyKey> OP_CHECKSIG`. Alice's separate leaf key signs the exact script-path digest without Bob's key or the adaptor witness. Its locktime is the time-based value 500000100; the sequence is non-final. The witness is exactly `[signature64, leaf_script, control_block]`. The claim witness is `[signature64]`. Both use DEFAULT with no appended sighash byte, no annex, and no code separator. rust-bitcoin produces the consensus encoding, tagged hashes, tree, and control block; the harness implements none of those algorithms.

Four tests cover the fixture, transaction commitment mutations, leaf/control-block/tweak mutations, and a 32-case internal/output parity exercise. The parity test requires all four even/odd combinations and runs aggregate partial verification, pre-signature verification, adaptation, final verification, and extraction for each case. Negative controls alter output value/destination, prevout value/script, the tweak root, refund leaf, control parity, refund locktime, and sequence. Rust locktime/sequence negatives demonstrate changed signature commitments; they do not execute CLTV.

[`fixtures/bitcoin_transactions.json`](fixtures/bitcoin_transactions.json) uses schema `ptlc-bitcoin-transactions-v1`. It exports only public funding/transaction fields, raw transactions, txid/wtxid, exact digests, internal/output/refund public keys, leaf/root, and control block. Txids are in conventional display order. The fixture's output key has odd parity, encoded by the control block's initial `c1` byte. Tests regenerate public values in memory and require an exact match, without rewriting files.

These finite checks do not validate a complete cross-chain swap, durable nonce state, chain funding, mempool policy, MTP finality, reorg behavior, fee replacement, or network liveness. The refund's timestamp is a fixed test vector rather than a usable deadline. Actual Bitcoin script execution is delegated to the separate pinned Go txscript harness; signature success here is not an execution result from that harness.

## Candidate constraints retained by the harness

The `musig2` single-signer API derives its pre-nonce without including the adaptor point. A deliberately unsafe regression case confirms that repeating its key/message/nonce-seed tuple under a changed adaptor point repeats the pre-nonce. A fresh seed changes it. The regression uses public examples and does not attempt secret recovery. Any application must prevent such seed reuse, including across ordinary/adaptor signing; the harness does not provide a production nonce manager.

The tested `schnorr_fun` feature selection provides typed adaptor components without selecting a general adaptor wire format. Tests exercise invalid point/scalar components and parity, not a newly invented serialized adaptor format. Only final 64-byte BIP340 signatures are cross-verified between candidates. Pre-signature encodings are not assumed interchangeable.

Malformed final-signature lengths are rejected by the harness's shared 64-byte boundary before invoking the fixed-size verifier APIs. Those length cases establish the harness boundary, not three separate candidate parser behaviors. Explicit malformed adaptor parsing exercises the `musig2` parser; out-of-range final-signature cases reach the available candidate parsing and verification paths.

The wrong-witness test also captures an API difference: `musig2::AdaptorSignature::reveal_secret` can return the different witness used to create an invalid completion. It does not take the expected adaptor point or message. The test requires the recovered point to differ from the committed point and all final verifiers to reject that completion. `schnorr_fun` recovery receives the expected adaptor point and returns no witness in this case. An application must validate the exact final-signature context and recovered witness commitment rather than treating extraction success as authorization.

Test assertions do not supply crash recovery, secure random generation, secret zeroization, malicious concurrent-session safety, or audit coverage. In particular, the Rust aggregate test is not a durable nonce-state implementation. The candidates remain subject to the independent review requirements in [the cryptography assessment](../docs/CRYPTOGRAPHY.md).

## Ephemeral nonce ownership qualification

`tests/nonce_lifecycle.rs` adds seven tests over a local wrapper around the pinned library nonce that does not expose copying. Sealing consumes the generated owner and fixes the complete public round. Signing takes the ready owner's nonce before request checks and backend work, so errors and an unwinding panic cannot retry through that owner. The tests exercise actual foreign-thread refusal; the PID guard is source-inspected, not fork-tested. This is private test code, with no production API or connection to the Python journal.

The public [nonce-round fixture](fixtures/nonce_rounds.json) includes two actual nonce pairs, partial signatures, verified pre-signatures and completed signatures. Both existing chain-message/key contexts are used, including the Bitcoin Taproot tweak. Python independently reproduces its commitment hashes; the separate Go modules verify final signatures and execute the replacement Bitcoin claim witness. The old fixtures are unchanged. A repeated-seed regression explicitly shows that reconstructing the same inputs repeats a nonce; the wrapper does not provide fresh entropy, secure erasure or clone protection.

The Stage 3 final locked offline run passed **24 tests, 0 failed, 0 ignored**, and formatting passed. The initial test-side Taproot array-type compile error and full evidence limits are recorded in [STAGE3_VALIDATION.md](../docs/STAGE3_VALIDATION.md).

## Public interoperability fixture

The later public-only example `examples/verify_exchange.rs` verifies strict canonical requests for Alice partials and complete two-party bundles. It recomputes the ordered aggregate key/tweak and verifies actual partial/pre-signature math. It supplies no signing, wallet, chain observation or identity authentication API. Its six tests bring the Stage 4 locked offline suite to **30 passed, 0 failed, 0 ignored**. No manifest or lockfile change was needed. See the [exchange design](../docs/ARTIFACT_EXCHANGE.md) for the request/response boundary and the [Stage 4 report](../docs/STAGE4_VALIDATION.md) for actual subprocess integration and its limits.

Stage 5 adds `examples/complete_exchange.rs`, which reuses the bundle verifier, verifies a final Zenon signature before witness extraction, checks its exact adaptor point, and adapts/verifies the Bitcoin signature from public inputs. It returns no extracted scalar and accepts no signing key or secret nonce input. Seven new completion tests bring the locked offline suite to **37 passed, 0 failed, 0 ignored**. The manifest, lockfile and public fixtures are unchanged. Alice private signing remains disconnected. See the [completion lifecycle](../docs/COMPLETION_LIFECYCLE.md) and [Stage 5 report](../docs/STAGE5_VALIDATION.md) for integration, intermediate failures and limits.

Stage 9 adds `examples/verify_authentication.rs`: a public-only BIP340 verifier for exact completion-envelope bytes and supplied authentication context. Ten new tests bring the suite to **47 passed**. Both pins are parsed as curve points; the signature binds the session, terms digest, roles, purpose, both pins and exact payload. Synthetic signing occurs only in tests. The new public fixture includes a correctly authenticated but invalid inner completion to expose the distinction. Python separately requires local context agreement; the executable alone cannot establish pin provenance. Journal enforcement and freshness are absent. See the [envelope design](../docs/COMPLETION_AUTHENTICATION.md) and [Stage 9 report](../docs/STAGE9_VALIDATION.md).

[`fixtures/completed_signatures.json`](fixtures/completed_signatures.json) contains four valid fixed-32-byte-message examples:

1. `musig2-single`.
2. `schnorr-fun-single`.
3. `musig2-aggregate-btc-synthetic`.
4. `musig2-aggregate-znn-contract-digest`.

Each entry has `id`, `public_key_hex`, `message_hex`, `signature_hex`, and `valid`. There are no private scalars, nonce seeds, or witnesses in this export. It is suitable as public input for a separately pinned Go verifier; passing the Rust tests does not itself report the outcome of that Go check.

## Reproduction

Stage 18 adds `examples/verify_observation.rs`, a public-only normal-verdict
worker. A complete Zenon-only request-shape guard precedes reuse of the unchanged
pure completion predicate. Normal invalid inputs return an exact request-bound
`rejected` result with zero exit; shape, I/O and panic failures return no normal
verdict. Eight new Rust tests bring the suite to 55 cases. No dependency, fixture,
arithmetic or private signing API changes. Python separately pins the selected
entry file and maps operational/result failure to `unknown`; source/host trust,
durable evidence and journal admission remain separate. See the
[verifier contract](../docs/OBSERVATION_VERIFIER.md) and
[Stage 18 validation](../docs/STAGE18_VALIDATION.md).

Use a configured Rust toolchain with Cargo available. The manifest requires Rust 1.85 or newer; this validation used Rust/Cargo 1.90.0. An isolated cache and target directory can be selected with `CARGO_HOME` and `CARGO_TARGET_DIR` without changing the commands below.

From the repository root, populate an approved dependency cache once:

```sh
cargo fetch --locked --manifest-path qualification/Cargo.toml
```

Then build and run without dependency network access:

```sh
cargo test --locked --offline --manifest-path qualification/Cargo.toml
```

The official verification corpus is read from `tests/fixtures/bip340_public_vectors.json` in the parent repository. Run within the complete checkout so that fixture remains available.

## Validation history

The first offline compile stopped on test-side Rust error `E0283`: an invalid-scalar assertion lacked an explicit marker type. Adding an `Option<FunScalar>` annotation resolved it. No candidate cryptographic implementation was modified. The next offline run passed all 12 tests then present. A targeted public-fixture generation run subsequently passed; the final fixture is now an immutable expected-output assertion rather than an exporter. After the extraction-boundary assertions and formatting changes, the final locked offline run passed **13 tests, 0 failed, 0 ignored**. `cargo fmt --check` also passed. The initially absent formatter was installed in the isolated toolchain before that check.

For the Bitcoin transaction milestone, dependency fetching completed before any offline test invocation. The first compile and run passed all four new tests without a failed intermediate compile or assertion. A targeted run produced the public fixture; that temporary print was replaced by an exact expected-fixture assertion. The original four-signature fixture stayed unchanged. After extending the parity loop through full claim signing and formatting the source, the final locked offline run passed **17 tests, 0 failed, 0 ignored** (13 primitive tests and 4 transaction tests); `cargo fmt --check` also passed. Final combined results are recorded in the repository's validation report. The bounded checks do not establish transaction-level atomicity, full Taproot conformance, live-chain acceptance, finality, or mainnet readiness.
