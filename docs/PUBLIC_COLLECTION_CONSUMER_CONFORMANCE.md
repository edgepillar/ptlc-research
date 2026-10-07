# Public collection consumer conformance

The existing public consumers already select the required collection shape
and check individual role equations. This slice adds seven Rust and two Python
regressions for aggregate-valid collections with invalid shape or role binding.
It extends the [lower-level collection controls](PUBLIC_PARTIAL_COLLECTION_CONFORMANCE.md)
without changing either consumer, any public grammar or any fixture.

## Selected controls

The Rust test binary calls the unchanged
[public artifact verifier](../qualification/examples/verify_exchange.rs).
Its independently selected original Bitcoin and Zenon test contexts each retain
two keys, two public nonces, the original message, adaptor point and key tweak.
Every mutation first reproduces the exact original valid pre-signature through
the backend aggregate equation. The original selected consumer request must
pass before only its supplied scalar collection is changed.

| Supplied collection | Preserved consumer result | Separate evidence |
| --- | --- | --- |
| Sum of the original partials as one scalar | Bundle and Alice-only forms refuse | Aggregate still matches; combined scalar fails each original role |
| Split either original partial using one or order minus one | Three-item bundle refuses | Same aggregate; neither split piece satisfies that role |
| Original partials followed by zero | Three-item bundle refuses | Original role equations remain valid |
| Original partials followed by one and order minus one | Four-item bundle refuses | Added pair cancels in the aggregate |
| Add a nonzero offset to Alice and subtract it from Bob | Two-item bundle refuses | Count is correct; both original role equations fail |
| Combined scalar and zero, in either order | Two-item bundle refuses | Count is correct; both original role equations fail |
| Original Alice-only and two-item bundle requests | Exact bound success receipts | Positive controls for both legs and request kinds |

The verifier returns a generic refusal. These tests do not instrument or infer
an internal rejection location from that response. Source inspection separately
shows that kind selects one or two items and that each selected role is checked
before bundle aggregation. No new role set or nonce aggregation is inferred
from the received scalar count. The public backend remains musig2 commit
`5a09b1197b1b5c621a5a9abc60fa95fa84a1da30`; existing
[source and license attribution](PUBLIC_PARTIAL_COLLECTION_CONFORMANCE.md#requirements-and-pinned-implementation)
remain unchanged. No upstream code, prose or vector is copied.

The new [Python controls](../tests/test_public_collection_consumer.py) use
complete dynamic contexts reconstructed by the existing factories. Selected
one-, three- and four-item equal-total bundles refuse request construction and
both exchange retention paths before any verifier callback. State remains
unchanged and valid. Test-only integer operations transform public fixture
scalars; they are never used for application cryptography. Mock receipts set
up exchange ordering only and are not cryptographic certificates.

## Context ownership and limits

The Rust helper selects the existing factory corpus before any artifact
mutation and checks its public projection against the retained complete
context. It computes that context's existing transcript digest for the test
request. It does not independently implement complete staged reconstruction.
The preserved [corpus check](../tests/test_public_nonce_intent_corpus.py) proves
that all four packets equal Python factory outputs; the preserved Python
request wrapper derives cryptographic inputs from a validated complete context.

The Rust verifier's context digest remains an opaque caller binding. Passing
an equation does not establish that a received context is the locally selected
session, authenticate its producer, or prove actual private consumed inputs.
This slice adds no peer transport, context-validation service, signing API or
application collection policy. All mutations use synthetic public artifacts.

Selected local checks passed. The [validation record](STAGE78_VALIDATION.md)
keeps new exact-candidate hosted checks separate.
Both finite models, four fixed inventories, three unfilled assessment reports,
dependency records and the complete eight-job workflow remain byte-exact.
Historical Linux and Apple worker profiles keep their separate scopes.

Public equation conformance, source/producer authentication, actual private
consumption and nonce custody remain separate gates. Fresh entropy, secure
memory, physical failure, nonrollback custody, adapted-infinity application
policy and independent construction/implementation review remain unresolved.
Source-to-worker and reproducibility remain **NOT VERIFIED**; independent
privacy remains **NOT ASSESSED**. Application and core progression remain
**NO-GO**. No artifact release is qualified and no reviewer is contacted.

No private signer, wallet access, chain observer, authoritative recovery,
protected-use adapter, core integration, deployment, activation, transaction
broadcast or real funds is included.
