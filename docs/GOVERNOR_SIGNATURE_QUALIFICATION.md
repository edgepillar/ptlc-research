# Public issuer and v2 owner signature qualification

Status: **Stage 38 offline public verification of the Stage 37 candidate bytes.
Two signature facts are separate from trusted issuer provisioning, current
authority, scope/source truth, enrollment, quota and actual-use permission. No
application admission path or private signer is connected.**

The [unsigned assignment/intent contract](GOVERNOR_ASSIGNMENT_CONTRACT.md) fixes
the complete 14-field profile inside a five-field assignment, then binds its
digest into a separate nine-field owner intent. This stage selects BIP340 checks
over those exact messages. This is one candidate construction, not a universal
protocol requirement or an independently assessed swap protocol.

## Exact mathematical statements

| Public check | Key | Exact 32-byte message |
| --- | --- | --- |
| Issuer assignment | Independently selected `issuer_auth_key_hex` | `SHA256("PTLC/observation-governor-assignment/v1" || NUL || canonical assignment)` |
| Owner v2 intent | Independently selected `owner_auth_key_hex`, equal to the complete profile's owner | `SHA256("PTLC/observation-enrollment-owner-intent/v2" || NUL || canonical bound intent)` |

Both signatures must verify. Issuer and owner are separate statements; this
selected codec permits equal keys without treating that as separation of duties.
An opaque authority profile pin is not replaced with a self-referential assignment
hash. Broader caps change the assignment and v2 message while the old requested
scope and v1 message can remain unchanged. Old signatures cannot follow this
change. The old v1 messages, signature fixture and worker remain separate.

## Packet and result binding

The new envelope/request has exactly five fields:

| Field | Selected value |
| --- | --- |
| `schema` | `ptlc-observation-governor-signature-envelope-v1` or separate `ptlc-observation-governor-signature-request-v1` |
| `assignment` | Complete five-field assignment, including the full profile |
| `bound_intent` | Complete nine-field v2 intent |
| `issuer_signature_hex` | Exact 64-byte lowercase public signature encoding |
| `owner_signature_hex` | Exact 64-byte lowercase public signature encoding |

Encoding is sorted-key compact ASCII JSON. The Python envelope requires no LF;
the worker accepts at most one trailing LF. Input is bounded to 8,192 bytes and
output to 512 bytes. Duplicate keys, escaped aliases, whitespace/deep variants,
non-ASCII, missing/extra fields and numeric aliases are refused. Profile epoch
is an exact integer in `1..2^53-1`; each maximum is in `1..64`. Keys must be valid
x-only curve points in the actual worker, beyond the codec's encoding checks.

```text
request digest = SHA256("PTLC/observation-governor-signature-request/v1" || NUL || canonical complete request)
```

The result has exactly `schema: ptlc-observation-governor-signature-result-v1`,
`request_digest_hex`, `issuer_signature_valid: true` and
`owner_signature_valid: true`. Changing either signature changes the complete
result binding, including when both signature variants are valid. This result
never includes `authorized`, `enrolled`, `permit` or a quota decision.

## Independent local expectation and worker boundary

[Python framing](../offline_session/governor_authentication.py) requires an exact
independently prepared `BoundEnrollmentIntent`. Its existing preparation and
revalidation check the retained source framing, local owner/resource, all six
scope pins and both requested caps against the complete selected profile. The
incoming issuer, owner or profile cannot become the expectation. All incoming
messages must match that complete expectation before the selected verifier runs;
the expectation is revalidated after the callback. The same unsigned object is
returned, without new authority properties or persistent state.

[The Rust public-only worker](../qualification/examples/verify_governor.rs)
checks exact packet/profile/intent shape, integer/hex/curve constraints, internal
assignment-to-intent digest binding and owner/resource consistency, then performs
both BIP340 checks through the existing locked dependency. It does not receive
the decoded scope, source artifacts, trusted roots or current-world evidence.
Its positive means only these two selected mathematical statements succeeded.

In particular, a signed profile with maximum one can accompany the opaque hash
of a scope requesting two: the raw worker can verify both signatures, because
it cannot decode that hash. The complete Python expectation refuses the packet
before work, and cannot prepare such an inconsistent proposal from that scope.
Bypassing this expectation is not an application authorization mechanism.

[The separate adapter](../offline_session/governor_verifier.py) requires an
explicit entry-file SHA256, repeats measurement and reuses the existing bounded
pipe runner. It accepts only the complete exact result for its request. This
is not atomic measured launch, provenance, dependency measurement or a sandbox.
The selected executable, runtime and host remain trusted; existing escaped
descendant and containment limitations are unchanged. A malicious selected
callback can forge the matching positive shape for zero signatures. Tests retain
that counterexample alongside actual mathematical refusal.

## Executed qualification and limits

[The public synthetic fixture](../qualification/fixtures/governor_signature.json)
contains seven vectors: primary, alternate issuer, alternate owner, broader caps,
new epoch, opaque scope under smaller caps and equal issuer/owner keys. It also
contains valid alternate signatures and signatures for wrong message domains.
There are no secret-key fields, wallet inputs or private production signatures.
Fixed public test scalar tags occur only in the Rust qualification tests, where
they reproducibly generate these values through the locked library. They must
never secure funds. No signing or test arithmetic enters `offline_session`.

[Rust qualification](../qualification/tests/governor_signature.rs) reproduces
all public vectors, every assignment/profile/intent mutation, numeric boundaries,
wrong-key/domain/role/legacy signatures, scalar/encoding errors and all 128
single-byte signature mutations. [Independent Go checks](../qualification-go/governor_signature_test.go)
rehash the exact messages and complete requests with `json.Number` preserving
integer bytes, then verify both signatures through the existing separate backend.
These are synthetic compatibility checks, not construction review or hostile
input application parsing. [The actual-worker qualifier](../scripts/qualify_governor_signature.py)
also exercises complete expected selections, stale state, transport refusal and
real exhausted-journal preservation. [Validation](STAGE38_VALIDATION.md) records
executed evidence and the first Go setup failure separately from hosted CI.

The implementation reuses the project's MIT framing/runner patterns at parent
commit [`392d5204ce0223b375d1c651408556a9522cef63`](https://github.com/edgepillar/ptlc-research/tree/392d5204ce0223b375d1c651408556a9522cef63).
No external implementation is copied and no dependency is added. Existing
[locked versions and license notices](../THIRD_PARTY_NOTICES.md) apply to the
called Rust/Go libraries. The original unsigned fixture remains byte-for-byte
unchanged; this new fixture is a separate public verification asset.

## Remaining gates

A stale correctly signed assignment remains mathematically valid. Selecting a
new epoch refuses old bytes relative to that new expectation, but retaining or
coherently restoring the old selection still verifies them. There is no trusted
latest head, issuer provisioning, authenticated role issuance, revocation source,
non-rollbackable lineage or indivisible current-state/use check. Valid signatures
over self-selected commitments also establish no canonical source or chain truth.
The [finite authority model](GOVERNOR_AUTHORITY_MODEL.md) keeps these premises
and counterexamples explicit. Repeated requests still succeed; request IDs are
not a registry's scoped idempotency rule.

Both fixed source inventories, manifests and unfilled independent assessments
are unchanged. This later delta needs its own review. Specify trusted issuer
selection, role/scope policy, key rotation/revocation and current-authority
evidence before any runtime admission. Establish exact use ordering, ownership,
non-rollbackable charging, unique dispatch and source equivalence separately.

**GO:** further offline review and trusted-current authority design.
**NO-GO:** interpret signature success as current permission, connect an
unreviewed registry/dispatcher or private signer, port current-node core rules,
deploy or use real funds.
