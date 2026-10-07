# Public nonce intent backend conformance

Status: test-only public conformance for `CANDIDATE-01`. Application and core
progression remain **NO-GO**. No signing or private nonce interface is added.

## Selected scope

The preceding source `76de8c01b7737769bdea00bb6fe7c02a7bfb9130` defines a complete
[public intent](PUBLIC_NONCE_INTENT.md), with an explicit projection of the
public backend arguments. Its factory validates the existing transcript and
encoding shapes; it does not recompute aggregation or parse curve points.

The new [corpus](../qualification/fixtures/public_nonce_intents.json) retains the
four fixed factory outputs in Bitcoin/Zenon and Alice/Bob order, including each
complete signing context. The [Python control](../tests/test_public_nonce_intent_corpus.py)
independently rebuilds their complete contexts from the preceding public terms
and nonce fixtures. Each packet's compact canonical encoding must equal the
existing factory bytes. No opaque digest replaces the context, and the corpus
wrapper is not a peer protocol or a credential.

The [Rust tests](../qualification/tests/public_nonce_intent.rs) consume these
checked-in public projections with the existing locked `musig2` dependency at
[`5a09b1197b1b5c621a5a9abc60fa95fa84a1da30`](https://github.com/conduition/musig2/tree/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30).
Its Unlicense is already recorded in the [qualification inventory](../qualification/README.md)
and [third-party notices](../THIRD_PARTY_NOTICES.md). No new dependency,
third-party source or prose is copied. The new corpus is original project data
derived from existing public synthetic fixtures and retains the project MIT
license. No source or binary release is qualified by adding these tests.

## Actual public checks

The private test helper builds `KeyAggContext` from the two ordered, compressed
signer keys parsed by the existing backend. It compares the aggregate x-only
key with the declared base key before applying any tweak. The separately
selected Bitcoin profile applies `with_taproot_tweak` to the supplied 32-byte
Merkle root, then compares the resulting signing key with the declared output
key. The separately selected Zenon profile requires the untweaked declaration
and compares its declared signing key. The helper does not infer its profile
from an untrusted operation string.

The helper parses the adaptor point and both complete public nonces using the
backend. Each public nonce contains two compressed points. It retains both
participants' nonces in their supplied order and requires an integer index in
the two-party range. It then verifies the corresponding *existing public
partial-signature fixture* using the actual context, summed public nonce,
adaptor, indexed signer key, indexed public nonce and supplied message.

These tests call no signing or secret-nonce generation API. The new binary has
no private key, secret nonce, entropy, storage, worker, network or recovery
entry point. No application module or exported verifier API is added.

## Negative controls and their meaning

The tests reject changed declared base/signing keys, reversed signer order with
the original declarations, a changed Bitcoin root with the original output
key, the wrong leg's tweak profile, malformed signer/adaptor points and either
malformed public nonce component. Invalid widths and participant indices also
refuse in the private test helper.

Valid but different adaptor points and messages pass their structural checks
but reject the old partial fixture. Changing the participant index also
rejects that participant's old partial. Swapping full valid public nonces
preserves `AggNonce::sum` but rejects each old partial because the indexed
individual nonce changes. Thus an aggregate nonce alone is insufficient to
express the individual verification inputs. A changed partial scalar refuses
in the original context.

A reversed signer order with consistently recomputed public key declarations
can pass public conformance while rejecting the original partial. This is a
different self-selected context, not approval by the original participants.
The helper deliberately reads only the projected public inputs. Altering a
retained context field while leaving the projection unchanged is not detected
by that helper; its old partial can still verify. Complete transcript binding
continues to belong to the existing Python factory and exact comparison, not
to this subset of public mathematics. These layers cannot be omitted from a
future independently reviewed construction.

## Open boundaries

Successful partial verification establishes the selected verification equation
for these fixture values. It establishes neither participant identity nor
ownership of signer keys. The pinned [verification API](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/signing.rs)
also distinguishes partial validity from an unforgeability property. This is
not an authenticated approval, an actual signer's consumed-input measurement,
a producer attestation or an independent cryptographic review.

The message remains supplied public input. These tests do not recompute a
Bitcoin transaction sighash, Tapleaf/script tree, funding or chain state. The
existing independent transaction qualification retains its own scope. The
Rust checks share the already selected curve backend; another entry point to
that backend is not independent arithmetic verification.

Conformance supplies no nonce freshness or consumption registry. Repeated
public checks, saved copies and stale self-selected contexts can pass without
proving real nonce custody. The two finite nonce models retain their original
unimplemented custody premises. Fresh entropy, secure memory, restored-copy
protection, nonexportable authority through the effect, physical failure and
independent construction/implementation review remain unresolved.

All four fixed source inventories, three unfilled assessments, public fixtures,
existing implementations and the complete prior workflow remain preserved.
The frozen worker review subject is not retargeted to this new test source.
Source-to-worker and reproducibility remain **NOT VERIFIED**; independent
privacy remains **NOT ASSESSED**. No reviewer is contacted. No wallet, core
integration, deployment, activation, transaction or real funds is selected.
See [Stage 74 validation](STAGE74_VALIDATION.md).
