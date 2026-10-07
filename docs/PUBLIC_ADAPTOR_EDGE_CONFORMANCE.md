# Public partial and adaptor boundary conformance

This construction adds public-only regression controls to the preserved
[public intent conformance](PUBLIC_NONCE_INTENT_CONFORMANCE.md) and
[nonce edge conformance](PUBLIC_NONCE_EDGE_CONFORMANCE.md). Nine Rust tests
use existing Bitcoin and Zenon public nonce rounds, public partials and
adaptor pre-signatures. Three Python tests rebuild complete cancellation
contexts through the existing transcript and intent factories. No private
key, secret nonce, signing operation or application interface is added.

## Selected public controls

The Rust target recomputes ordered key aggregation, the selected Bitcoin
Taproot tweak, the message and aggregate nonce. Each original partial verifies
in its original role; their aggregate equals the preserved public
pre-signature byte for byte and passes the backend public adaptor verifier.

| Public input or mutation | Pinned backend result | Scope |
| --- | --- | --- |
| Original two partials in original roles | Both partials and aggregate verify | Positive control against existing public fixtures |
| Partial scalar zero, one or group order minus one | Decodes; refuses each original partial equation | Parsing does not establish partial validity |
| Scalar at/above group order; wrong byte length | Refuses partial decoding | Canonical scalar range and exact 32-byte length |
| One changed scalar; empty, missing or duplicated original shares | Refuses original aggregate equation | Observed outcomes for selected fixtures |
| Reversed original share collection | Same valid aggregate; refuses both wrong-role equations | Aggregation sums scalars and does not associate a supplied share with a role |
| Add a public nonzero delta to one original share and subtract it from the other | Both changed partials refuse individually; aggregate is identical and verifies | Aggregate validity alone does not prove validity of each supplied partial |
| Adaptor point equal to negative actual final nonce | Valid point; adapted nonce is infinity; original partials and original aggregate refuse in changed context | No universal infinity-rejection policy is inferred |
| Both aggregate nonce components cancel, then adaptor is negative generator | Existing generator fallback remains; adapted nonce is infinity; original partials/aggregate refuse | Individual points, aggregate components and adapted nonce are distinct |
| Existing pre-signature with infinity nonce or zero scalar | Decodes; refuses original public verifier | Pre-signature parsing is separate from validity |
| Pre-signature out-of-range scalar or wrong byte length | Refuses decoding | Selected 65-byte representation boundaries |

Compensation uses only public scalars through the pinned backend with deltas
one and group order minus one. It performs no signing and recovers no secret.
The changed scalar encodings are invalid in the selected individual equations;
the resulting valid aggregate is the original fixture.
To establish validity of each received partial, check it against its
independently selected signer and public nonce. Those equations still do not
authenticate a participant or prove private nonce ownership. Partial
signatures are not unforgeable credentials.

The Python tests select the cancelling point by flipping the parity of the
existing public pre-signature nonce, or use negative generator with the
preserved both-component cancellation pair. They rebuild terms, bindings,
role commitments, reveals, signing contexts and exact factory intents. The
new contexts pass the existing shape checks; old role openings fail after
adaptor terms change and old selected intents cannot be replaced. Python
does not compute final nonces or detect the adapted point at infinity.
The Rust tests recompute that separate public curve result.

## Pinned implementation behavior

The selected backend remains musig2 commit
`5a09b1197b1b5c621a5a9abc60fa95fa84a1da30`. Its
[partial verifier](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/signing.rs),
[aggregation](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/sig_agg.rs),
[public adaptor verifier](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/bip340.rs)
and [encoding](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/signature.rs)
remain unchanged. The cached source bytes are compared with the immutable
Git objects before qualification. The existing
[dependency attribution](../THIRD_PARTY_NOTICES.md) records its Unlicense.
No upstream code, prose or test vector is copied by this construction.

The point and scalar parser source files in the selected secp 0.7.0 cache
also match members of its original package archive, whose SHA-256 matches
the existing [lockfile checksum](../qualification/Cargo.lock). This is a
declared-content comparison; it does not authenticate the package producer.
The source archive is inspected without extracting it or installing a package.

PartialSignature is MaybeScalar: zero is representable but a supplied scalar
still must satisfy the selected partial equation. AdaptorSignature stores a
MaybePoint and a MaybeScalar; its decoder permits the infinity representation.
The partial and aggregate verifiers compute the adapted nonce as final nonce
plus adaptor point. The selected dependency represents infinity as zero
x-only bytes and even parity. These functions have no explicit rejection at
that boundary before evaluating their equations. The fixture refusals above
must not be described as a guarantee that every infinity case is rejected.
The behavior of adapting with a private witness is outside this public-only
target. The application policy for an unusable adapted nonce remains
**UNRESOLVED**; neither backend replacement nor protocol rejection is selected.

## Acceptance boundaries

The [validation record](STAGE76_VALIDATION.md) distinguishes local checks from
new hosted checks. The new target uses the existing locked C-backed musig2
construction. It is not independent arithmetic or independent implementation
review. All preceding implementations, fixtures, finite models, four fixed
inventories, three unfilled reports and the complete eight-job workflow retain
their bytes. Existing native worker profiles retain their original scope.

No public equation supplies source/producer authentication, actual private
signer consumed-input evidence, fresh entropy, secure memory, nonrollback
custody or physical failure recovery. Neither nonce model's ideal custody
premise is implemented. Independent construction and implementation review
remain open. Source-to-worker and reproducibility remain **NOT VERIFIED**;
independent privacy remains **NOT ASSESSED**. Application and core progression
remain **NO-GO**. No reviewer is contacted.

No private signer, application cryptography, chain observer, wallet access,
authoritative recovery, protected-use adapter, core integration, deployment,
activation, transaction broadcast or real funds is included. All test values
are synthetic public fixtures. No artifact release is qualified.
