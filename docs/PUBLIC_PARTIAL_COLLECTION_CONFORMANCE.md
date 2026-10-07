# Public partial collection cardinality conformance

Five public-only Rust controls extend the preserved
[partial and adaptor conformance](PUBLIC_ADAPTOR_EDGE_CONFORMANCE.md).
The selected Bitcoin and Zenon contexts still have exactly two ordered keys,
two public nonces and two original role partials. Only the collection supplied
to the aggregate adaptor API changes. Complete factory binding remains covered
by the existing [public intent controls](PUBLIC_NONCE_INTENT_CONFORMANCE.md).
No protocol, Python grammar, application interface or fixture changes.

## Selected controls

Each test recomputes key aggregation, the Bitcoin Taproot tweak, the message
and aggregate public nonce. Both original partials must verify under their
original selected key and public nonce. The original two-item aggregate must
match the retained public pre-signature and pass public adaptor verification.
The mutation controls use public scalar operations in the pinned backend.

| Supplied collection | Pinned backend result | Role boundary |
| --- | --- | --- |
| One item equal to the sum of the two original partials | Same pre-signature bytes and valid aggregate | Combined item fails both original individual equations |
| Three items obtained by splitting either original partial into one or order minus one and its remainder | Same pre-signature bytes and valid aggregate | Both pieces fail the split role's equation; untouched role stays valid |
| Original partials followed by zero | Same pre-signature bytes and valid aggregate | Original role partials stay valid; added zero fails either original role |
| Original partials followed by one and order minus one | Same pre-signature bytes and valid aggregate | Added nonzero pair cancels; neither added item verifies under either original role |
| One, three or four items with a changed total | Original aggregate equation refuses | Cardinality alone does not determine the result |

These selected local results passed; the [validation record](STAGE77_VALIDATION.md)
keeps new exact-candidate hosted checks separate.

All collections retain the same independently selected original aggregate
nonce, adaptor point, message, key order and tweak. These tests do not choose
a new nonce aggregation or signer set from the supplied scalar count. They do
not generate partial signatures, adapt a pre-signature or recover a witness.

An aggregate verifier receives the resulting pre-signature; it does not
receive the supplied collection or establish its cardinality. The aggregate
construction API receives the collection but sums its scalars without binding
items to roles. Equal totals can therefore yield the same aggregate result.
Checking each received item against its selected role is a separate obligation
when individual contribution validity is required. A complete two-role exchange
would also need its independently selected collection structure. This slice
adds no exchange adapter or universal cardinality-rejection rule. Even a valid
individual equation does not authenticate a participant or prove nonce custody.

The preserved [Python exchange bundle guard](../offline_session/exchange.py)
already requires exactly two ordered partials. The preserved
[public artifact verifier](../qualification/examples/verify_exchange.rs)
selects one partial for its Alice-only request or two for a bundle and verifies
each supplied role before aggregation. This slice exercises the lower-level
backend directly. It does not establish a bypass of those existing consumers
or newly execute these mutations through their wire interfaces. The verifier's
context digest remains an opaque caller binding; complete local expectation
ownership is a separate boundary.

## Requirements and pinned implementation

The selected backend remains musig2 commit
`5a09b1197b1b5c621a5a9abc60fa95fa84a1da30`. Its unchanged
[aggregation source](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/sig_agg.rs)
accepts an iterator of partial scalars, adds the tweak term once and checks
the aggregate equation. The API has no supplied-share role map or explicit
collection-length gate. Its
[partial verifier](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/signing.rs)
uses the separately supplied signer key and individual public nonce.
Cached source bytes are compared with immutable Git objects before native
qualification. Existing [Unlicense attribution](../THIRD_PARTY_NOTICES.md)
remains unchanged. No upstream code or vector is copied.

[BIP327 at the pinned Bitcoin BIPs revision](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0327.mediawiki#partial-signature-aggregation)
describes aggregation of u partials alongside a session context containing
u ordered individual keys. It specifies separate individual verification for
identifying disruptive contributions and does not treat partials as
authentication credentials. That ordinary MuSig2 specification and its
protocol inputs remain separate from this backend's adaptor primitive.
The referenced document is version 1.0.4 under BSD-3-Clause; no prose,
reference implementation or vector is copied. These observations establish
neither an adaptor protocol security proof nor a backend vulnerability.

## Acceptance boundaries

The [validation record](STAGE77_VALIDATION.md) separates local checks from
new exact-candidate hosted checks. No preceding implementation, public grammar,
fixture, dependency, finite model, fixed inventory, unfilled assessment or
eight-job workflow changes. Historical native worker profiles keep their
existing scope. The new test helper is private to its public test binary.

Public aggregate validity does not supply source/producer authentication,
actual private signer consumed-input evidence, fresh entropy, secure memory,
nonrollback custody or physical failure recovery. Neither finite nonce model's
ideal custody premise is implemented. Independent construction and
implementation review remain open. Source-to-worker and reproducibility remain
**NOT VERIFIED**; independent privacy remains **NOT ASSESSED**. All three
independent reports remain unfilled. Application and core progression remain
**NO-GO**. No artifact release is qualified and no reviewer is contacted.

No private signer, application cryptography, chain observer, wallet access,
authoritative recovery, protected-use adapter, core integration, deployment,
activation, transaction broadcast or real funds is included. All values are
synthetic public fixtures.
