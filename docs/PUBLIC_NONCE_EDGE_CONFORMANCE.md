# Public nonce component and infinity boundaries

Status: offline, public-only test conformance for `CANDIDATE-01`. Application
and core progression remain **NO-GO**. No signing or private nonce interface is
added. These controls characterize existing behavior; they select no new
application policy for component reuse or aggregate infinity.

The preceding source `759d39da16b98887b3fb6e462430a080315f6ee9` separates complete
[public intent binding](PUBLIC_NONCE_INTENT.md) from fixed
[public backend conformance](PUBLIC_NONCE_INTENT_CONFORMANCE.md). The next
boundary is the distinction between equality of a full nonce, equality of one
component, validity of an individual point and cancellation in an aggregate.

## Shared public corpus

The [edge corpus](../qualification/fixtures/public_nonce_edges.json) has eight
cases for each of the existing Bitcoin and Zenon public nonce pairs: baseline,
equal full nonces, shared first components, shared second components, repeated
components within Alice's nonce, first-component cancellation,
second-component cancellation and both-component cancellation. Cancellation
inputs flip a compressed public point's parity prefix; the backend tests must
confirm actual negation. No secret scalar or nonce seed is reconstructed.

The [eight Python controls](../tests/test_public_nonce_edges.py) independently
derive the exact corpus bytes from the preserved public nonce fixtures and
rebuild commitments, openings, complete rounds and both roles' signing
contexts. Every accepted context is revalidated and its canonical intent is
compared with the existing factory. This remains shape and transcript
validation; Python performs no curve arithmetic here.

The [eleven Rust controls](../qualification/tests/public_nonce_edges.rs) parse
the same corpus with the already locked backend, check aggregate component
infinity and round-trip the aggregate encoding. Existing ordered keys and the
selected Bitcoin Taproot tweak or untweaked Zenon key are reconstructed and
checked against their original declarations. Each baseline pair verifies both
existing public partial fixtures. Every changed pair rejects both of those
original partials in the changed context. This says nothing about a new
partial's validity or the identity of a participant.

## Observable boundaries

| Public input | Existing Python round | Pinned public backend | Evidence limit |
| --- | --- | --- | --- |
| Baseline pair | Accepts complete openings/context | Parses; original partials verify | Existing fixed public equation only |
| Equal full nonces | Refuses despite distinct correct role openings | Parses individual points and their aggregate; original partials fail | The protocol reflection rule is distinct from curve parsing |
| Shared first/second component or repeated components within one nonce | Accepts correct complete openings/context | Parses; original partials fail | Neither parser supplies a component freshness registry |
| One or both aggregate components cancel | Accepts correct complete openings/context | Parses individual points; permits aggregate infinity; original partials fail | Infinity at aggregation is distinct from an invalid individual nonce |
| All-zero 33-byte individual component | Refuses encoding shape | `PubNonce` refuses; `AggNonce` permits that component | The aggregate type is unsuitable for parsing a participant's nonce |
| Nonzero in-field noncurve coordinate with either compressed prefix | Accepts shape when commitments/context are consistently rebuilt | Point/`PubNonce` parsing refuses | A field bound and compressed prefix do not establish curve membership |

The noncurve coordinate is read from row 5 of the existing
[public BIP340 fixture](../tests/fixtures/bip340_public_vectors.json), rather
than copied into a new fixture. Both compressed prefixes are exercised in
each participant's two nonce components, each ordered signer position and the
adaptor point. The nonzero coordinate is below the secp256k1 field modulus;
the rejection therefore distinguishes curve membership from a field overflow
or an all-zero encoding. The existing
[CC0-1.0 attribution and immutable source](../THIRD_PARTY_NOTICES.md#bip340-verification-vectors)
remain in force. The new edge corpus contains original project mutations of
existing synthetic public nonces and retains the project MIT license.

## Aggregate infinity is explicitly supported by this backend

The pinned [`musig2` nonce types and methods](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/nonces.rs)
distinguish non-infinity `Point` components in `PubNonce` from `MaybePoint`
components in `AggNonce`. `AggNonce::sum` permits cancellation, and
`final_nonce` returns the generator when the final aggregate point is
infinity. The both-components-cancel case checks that fallback using the
coefficient computed with each original signing key and supplied message.
The same all-zero aggregate encoding must refuse as a `PubNonce`.

This fallback is preserved backend behavior, not evidence that an altered
swap protocol is secure. No rule rejecting all aggregate infinity is invented
here. A future independently reviewed construction must decide its component
reuse, malformed input, aggregate failure and participant accountability
policies. Changing public nonce pairs cannot reuse their original committed
openings or replace a locally selected baseline intent; the Python controls
also require those existing binding refusals.

## Open gates

Neither component equality nor cancellation proves that a private nonce was
reused, consumed, leaked or owned by any identified participant. Conversely,
absence of equal public encodings is no freshness proof. Partial validity is
not participant authentication. No private signer, entropy source, secure
memory, consumption registry, journal bridge, worker, recovery or chain
observer is measured or added. The tests share the existing curve backend and
are not independent arithmetic review.

All preceding implementations, fixtures, dependency records, finite models
and the complete eight-job workflow retain their bytes. All four fixed source
inventories and three unfilled independent reports remain unchanged; the
worker review subject is not retargeted. Source/producer authentication,
actual consumed-input evidence, fresh entropy, physical failure,
nonexportable/nonrollback custody and independent construction/implementation
review remain unresolved. Source-to-worker and reproducibility remain
**NOT VERIFIED**; independent privacy remains **NOT ASSESSED**.

No reviewer is contacted. No wallet, core integration, deployment, activation,
transaction broadcast or real funds is selected. See
[Stage 75 validation](STAGE75_VALIDATION.md).
