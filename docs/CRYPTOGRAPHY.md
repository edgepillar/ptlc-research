# Cryptography qualification plan

Status: Stage 1 offline qualification. Two pinned candidates have been built and exercised with synthetic inputs; no production signing backend is selected. See [the harness](../qualification/README.md) and [executed results](STAGE1_VALIDATION.md).

Stage 2 adds [public session and journal qualification](SESSION_JOURNAL.md), without wiring either cryptographic candidate into that lifecycle. Its public nonce tags are not library nonce objects or evidence of cryptographic freshness.

Assessment date: 2026-10-03. Repository revisions below were resolved through the public GitHub API and inspected as source. Package versions are manifest values at those revisions, not claims about the latest published release. This repository's qualification tests have run; the full upstream test suites and hosted CI have not been qualified.

## Decision and scope

Use secp256k1 and BIP340-compatible final signatures for the first Bitcoin/Zenon experiment. This avoids making an Ed25519/secp256k1 cross-curve proof another initial dependency. It does not change the signature scheme used by ordinary Zenon accounts.

Do not translate the existing experimental Ed25519 signing exchange into secp256k1. Do not implement production curve arithmetic, a new adaptor construction, or unreviewed additive key aggregation in this repository. Preserve the scalar-exposure example only as a test-only regression that demonstrates the unsafe protocol pattern.

The offline harness qualifies single-signer encoding, verification, adaptation and extraction, and includes one two-party aggregate linkage exercise. [CANDIDATE-01](TRANSACTION_GRAPH.md) selects aggregate success keys so neither recipient alone can bypass witness disclosure with an unrelated signature. Ordinary BIP327 compatibility does not establish security of the complete adaptor extension or swap.

## Source-pinned shortlist

| Candidate | Inspected revision and package metadata | Relevant capability | Stage 0 disposition |
| --- | --- | --- | --- |
| `conduition/musig2` | [`5a09b1197b1b5c621a5a9abc60fa95fa84a1da30`][musig-revision]; manifest `0.4.1`; Unlicense | Single-signer BIP340 adaptor signing as well as aggregated MuSig2 adaptor signing. Ordinary final signatures use a BIP340 verifier. | Evaluate the single-signer API first for an application-facing harness. The package name does not require adopting MuSig2. Beta status, nonce handling, and exact adaptor code still require independent review. |
| `LLFourn/secp256kfun`, package `schnorr_fun` | [`74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce`][fun-revision]; manifest `0.13.0`; 0BSD, with separate vendored licenses | Dedicated encrypted signing, pre-signature verification, adaptation, and witness recovery; explicit parity handling. | Useful independent experimental comparator. Upstream explicitly cautions about limited review, side-channel evidence, and secret zeroization. Do not infer suitability for custody or production signing. |
| `BlockstreamResearch/secp256k1-zkp` | [`8e1f96c20e16bf960be6caec7f3c94acb360cdf2`][zkp-revision]; MIT | MuSig adaptor support in the public C API, in addition to a separate ECDSA adaptor module. | Qualify if the chosen protocol needs aggregated signing; retain as a C interoperability candidate. Do not introduce MuSig2 only to use this library. The selected extension and any binding require review separately from the underlying curve library. |

These are candidates for qualification, not three interchangeable approved backends. There is no identified commit-scoped independent audit report for these exact adaptor paths in the sources examined. This is **unknown audit coverage**, not a finding that no audit exists. Before selection, obtain the report and establish its scope, covered revision, unresolved findings, and changes since review. Repository popularity, a security reporting policy, a mathematical protocol proof, and BIP compliance are different kinds of evidence.

### Candidate API and test evidence

**`musig2`:** The [adaptor documentation][musig-adaptor] exposes `adaptor::sign_solo` and `adaptor::verify_single`, followed by `AdaptorSignature::adapt` and `reveal_secret`. The [implementation][musig-bip340] includes BIP340 vectors and adaptor round trips. The [reference comparison test][musig-reference-tests] exists for ordinary aggregation/signing; it is not evidence of an independent adaptor-protocol proof. The [README][musig-readme] identifies beta status and selectable `libsecp256k1`/`k256` arithmetic. Verify the actual feature selection and full dependency lock before any future build. See its [manifest][musig-manifest] and [license][musig-license].

Specific review point: in the inspected single-signer implementation, the pre-nonce derivation takes the key, message, and nonce seed; the adaptor point is added afterward. Reusing a seed across otherwise identical requests with different adaptor points or across ordinary/adaptor signing must therefore be excluded by the application design and negative tests. This is a source-level API constraint requiring review, not an executed exploit claim. [Source][musig-bip340]

**`schnorr_fun`:** The [adaptor module][fun-adaptor] supplies `encrypted_sign`, `verify_encrypted_signature`, `decrypt_signature`, and `recover_decryption_key`. It derives the nonce using the encryption point as an input and tracks the sign adjustment needed for an even-Y final nonce. Its in-module property tests exercise deterministic and synthetic nonce variants, final verification, and recovery. Separate [BIP340 vectors][fun-bip340-tests] and [C-library comparisons][fun-c-tests] cover ordinary signatures; they do not establish that adaptor encodings interoperate between libraries. The [upstream caveats][fun-readme] remain material despite those tests. See the [manifest][fun-manifest], [package license][fun-license], and [vendored license inventory][fun-vendor].

**`secp256k1-zkp`:** The [public MuSig header][zkp-header] accepts an adaptor point in `secp256k1_musig_nonce_process`, exposes session nonce parity, and provides `secp256k1_musig_adapt` and `secp256k1_musig_extract_adaptor`. Its [API notes][zkp-musig-doc] require verification of every partial signature when adaptors are used. A successful adaptation/extraction API return does not by itself establish a valid signature or correct witness. The [test source][zkp-tests] contains adaptation/extraction, final Schnorr verification, and a linked-signature swap exercise. These are cryptographic tests, not a Bitcoin/Zenon swap. The [README][zkp-readme] distinguishes experimental extensions; the [security policy][zkp-security] is a reporting route, not an audit certificate. See the [license][zkp-license].

It would be incorrect to classify this inspected `secp256k1-zkp` revision as ECDSA-adaptor-only. It would also be incorrect to use the ECDSA adaptor API as though it produced BIP340 signatures.

## Required qualification properties

The protocol specification and future harness must establish all of the following before a backend is selected:

1. **Fixed statement and transcript.** Bind the pre-signature to the expected signer key, adaptor point, exact message, role, protocol version, network, and session. The signed message must commit to the correct deposit and recipient. Use the actual Bitcoin sighash for Bitcoin signing; application domain separation must not silently alter a Bitcoin consensus message.
2. **BIP340 compatibility.** Use the prescribed challenge hash, x-only public-key rules, scalar ranges, and final 64-byte signature encoding. Distinguish an adaptor's library-specific encoding from a final Bitcoin signature. Check the completed signature using an independent BIP340 verifier. [Specification][bip340]
3. **Parity and Taproot.** Exercise both public-key and nonce parities and their sign corrections. Verify the exact Taproot output key and script commitment, including any refund leaf. An untweaked internal key is not the output signing key. Test the chosen key-path or script-path construction, not an unspecified mixture. [Taproot specification][bip341]
4. **Verified adaptation and extraction.** A verified pre-signature plus the correct nonzero witness must produce a valid final signature. The corresponding final signature must recover the agreed witness, checked against `T = tG`. Unrelated final signatures, wrong keys/messages/points, malformed encodings, infinity, invalid scalars, or an incorrect parity context must fail at a specified boundary. Successful parsing or a nonempty extraction result alone is insufficient.
5. **Key ownership and bypass resistance.** Explain who can sign every success and refund spend. If a party can make an unrelated valid success signature, show why this cannot bypass the extraction condition. If aggregation is selected, use a reviewed rogue-key-resistant construction and verify its complete adaptor extension; ordinary BIP327 compatibility does not standardize that extension. [MuSig2 specification][bip327]
6. **Independent evidence.** Positive self-tests are insufficient. Produce a fixed vector corpus covering verification failures, parity combinations, altered adaptor points, and wrong transcript contexts. Cross-check final signatures with a separate BIP340 implementation. Cross-library pre-signature tests need an explicit format mapping; do not assume encodings match.

## Nonce and signing-state contract

Signing-state handling is part of the security design, not a convenience added during wallet integration.

- Use fresh cryptographic randomness according to the selected API. Do not substitute a timestamp, process-local counter, repeated test seed, or ordinary BIP340 deterministic signing recipe for an adaptor/multiparty nonce scheme.
- Freeze the complete signing context before approving a signing operation. Review the selected algorithm's binding of the adaptor point, message, keys, tweaks, and role; an application session identifier does not repair an unsafe nonce derivation by itself.
- Permit at most one signing use of a secret nonce. A retry may resend an already persisted, identical outbound message when the protocol permits it; it must not recompute a signature with a previously used nonce.
- Define the crash boundary before exposing any signature or partial signature: no restart, backup restoration, cloned process, or concurrent worker may cause a second signing use. Durably mark a reservation consumed before releasing its signing output. If completion is uncertain, retire that reservation and reconcile the session; do not silently resume signing from a restored secret nonce.
- Follow the library's stronger restrictions. In particular, the inspected C MuSig API forbids copying/serializing its secret nonce object. Recovery must not depend on restoring that object. A Rust ownership API likewise cannot prevent copies made through backups or another process. [C API requirements][zkp-musig-doc]
- Keep public pre-signatures, parity context, and recovery information available for extraction. Record possible witness disclosure monotonically: direct delivery of a completed signature may disclose the witness before any chain confirmation. A reorg must not reset that fact.
- Define secret-memory handling, log redaction, and protected storage. A mnemonic or ordinary wallet seed alone does not necessarily reconstruct a swap transcript, pre-signatures, fee strategy, or refund authorization.

## Exit conditions and next review

The production-backend decision remains **selection pending**. Passing the synthetic qualification tests does not select a dependency for custody or network integration.

The candidate graph now requires two-party signing on both success paths and distinct per-leg keys/nonces. A separate finite transaction harness binds the Bitcoin side to a real synthetic Taproot output/tweak and sighash, with independent Go script execution. The next work is to connect these examples through the full session transcript and establish durable exchange and nonce ownership. The current Rust feature selection and lockfile are recorded; independent review of the exact adaptor path, dependency risks and application protocol remains required. `schnorr_fun` is currently a single-signer experimental comparator, not an alternative implementation of the entire aggregate swap.

Passing this gate supplies the evidence needed to implement the reviewed primitive boundary. It does not establish cross-chain atomicity, safe timeouts, fee-bump behavior, production readiness, or permission to activate PTLC on a live network.

[Stage 3](NONCE_ROUNDS.md) adds public nonce-round bindings and a separate ephemeral test owner for the pinned `musig2` API. The Python journal remains public metadata only; returning fixture bytes from its callbacks is not signing integration. The Rust wrapper avoids exposing nonce cloning/serialization but cannot prevent copied memory or deterministic reconstruction. Fresh entropy, secure memory, clone protection and the actual durable worker boundary remain unresolved.

[Stage 4](ARTIFACT_EXCHANGE.md) connects a public-only Rust verifier to managed artifact retention. It verifies ordered partials and exact aggregate pre-signatures with the pinned library. Its supplied Bitcoin message/root and opaque context digest are narrower inputs than independently verified chain/transaction state. No signing capability or production cryptographic backend selection follows from this bridge.

[Stage 5](COMPLETION_LIFECYCLE.md) adds an actual public-input completion worker: it verifies the final Zenon signature before extraction, checks the extracted nonzero witness against the retained adaptor point, verifies both retained bundles, adapts the Bitcoin pre-signature and verifies the final result. It returns only the Bitcoin signature, not the extracted scalar. This does not establish memory zeroization or host protection. Alice still copies a public fixture through the durable producer interface; no private signing backend is connected.

[musig-revision]: https://github.com/conduition/musig2/tree/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30
[musig-adaptor]: https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/doc/adaptor_signatures.md
[musig-bip340]: https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/bip340.rs
[musig-reference-tests]: https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/tests/fuzz_against_reference_impl.rs
[musig-readme]: https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/README.md
[musig-manifest]: https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/Cargo.toml
[musig-license]: https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/LICENSE
[fun-revision]: https://github.com/LLFourn/secp256kfun/tree/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce
[fun-adaptor]: https://github.com/LLFourn/secp256kfun/blob/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/schnorr_fun/src/adaptor/mod.rs
[fun-bip340-tests]: https://github.com/LLFourn/secp256kfun/blob/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/schnorr_fun/tests/bip340.rs
[fun-c-tests]: https://github.com/LLFourn/secp256kfun/blob/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/schnorr_fun/tests/against_c_lib.rs
[fun-readme]: https://github.com/LLFourn/secp256kfun/blob/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/README.md
[fun-manifest]: https://github.com/LLFourn/secp256kfun/blob/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/schnorr_fun/Cargo.toml
[fun-license]: https://github.com/LLFourn/secp256kfun/blob/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/schnorr_fun/LICENSE
[fun-vendor]: https://github.com/LLFourn/secp256kfun/tree/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/secp256kfun/src/vendor
[zkp-revision]: https://github.com/BlockstreamResearch/secp256k1-zkp/tree/8e1f96c20e16bf960be6caec7f3c94acb360cdf2
[zkp-header]: https://github.com/BlockstreamResearch/secp256k1-zkp/blob/8e1f96c20e16bf960be6caec7f3c94acb360cdf2/include/secp256k1_musig.h
[zkp-musig-doc]: https://github.com/BlockstreamResearch/secp256k1-zkp/blob/8e1f96c20e16bf960be6caec7f3c94acb360cdf2/doc/musig.md
[zkp-tests]: https://github.com/BlockstreamResearch/secp256k1-zkp/blob/8e1f96c20e16bf960be6caec7f3c94acb360cdf2/src/modules/musig/tests_impl.h
[zkp-readme]: https://github.com/BlockstreamResearch/secp256k1-zkp/blob/8e1f96c20e16bf960be6caec7f3c94acb360cdf2/README.md
[zkp-security]: https://github.com/BlockstreamResearch/secp256k1-zkp/blob/8e1f96c20e16bf960be6caec7f3c94acb360cdf2/SECURITY.md
[zkp-license]: https://github.com/BlockstreamResearch/secp256k1-zkp/blob/8e1f96c20e16bf960be6caec7f3c94acb360cdf2/COPYING
[bip340]: https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0340.mediawiki
[bip341]: https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0341.mediawiki
[bip327]: https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0327.mediawiki
