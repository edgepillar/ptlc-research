# Independent public enrollment signature checks

Status: **Stage 34 public fixture qualification through a separate Go BIP340
implementation. No application verifier, governor policy or registry is added.**
All inputs are unchanged public synthetic values. This cross-check is not an
independent security assessment of the swap, dependencies or enrollment design.

## Requirement, construction and evidence

| Requirement | Selected check | Evidence boundary |
| --- | --- | --- |
| Check the existing signed bytes independently | Rebuild sorted-key compact JSON and SHA256 using the Go standard library | All three existing fixture messages and complete request digests match |
| Separate content identity from requested authority | Reconstruct the seven source commitments and all 18 scope fields | Seven source changes affect both hashes; nine authority selections affect only scope; the primary signature rejects all 16 changes |
| Bind each intent field and message domain | Recompute messages after all eight field changes, a missing NUL, changed serialization and another domain | Original signatures reject; the public wrong-domain signature verifies for its other message and rejects under the intended one |
| Use separate signature arithmetic | Call the existing Go parser/verifier instead of the Rust worker or Python callback | Primary, alternate-owner, self-selected-source and alternate-signature positives verify; malformed and mutated controls reject |
| Distinguish intent signing from transport binding | Hash the complete request separately, including signature encoding | Another valid signature has a different request digest; changed outer fields leave intent mathematics valid but are invalid application packets |
| Expose missing authority and freshness | Repeat valid checks under reused request IDs and self-asserted roles | No role assignment, provenance, unique registration, quota or replay defense follows |

## Exact subject and independent path

The new [test-only Go file](../qualification-go/enrollment_signature_test.go)
reads the unchanged
[Stage 33 fixture at its parent commit](https://github.com/edgepillar/ptlc-research/blob/c847b5b5d45cd9039bc12ec79e43831955d11db4/qualification/fixtures/enrollment_signature.json).
It imports no Python helper, runs no Rust executable, generates no key or signature,
and contacts no node. It rebuilds the unsigned intent, complete request, retained
resource and authority-scope hash framing rather than trusting the fixture's
precomputed messages. The resource is also reconstructed independently from scope.
None of these synthetic fixture commitments proves authenticated source provenance;
the self-selected-source positive exposes that absence.

```text
intent message = SHA256("PTLC/observation-enrollment-owner-intent/v1" || NUL || canonical intent)
request digest = SHA256("PTLC/observation-enrollment-signature-request/v1" || NUL || canonical request)
resource digest = SHA256("PTLC/observation-retained-resource/v1" || NUL || canonical resource)
scope digest = SHA256("PTLC/observation-authority-scope/v1" || NUL || canonical scope)
```

Go maps provide sorted-key JSON for these restricted ASCII fixture values. The
test uses a map for canonical request order; marshaling a struct in declaration
order would produce different bytes. Scope numeric values remain exact JSON
numbers. This fixture decoder is not a hostile-input application codec, and the
new tests do not replace Stage 33's exact parser and bounded worker checks.

The existing internal MIT
[Go helper at the parent commit](https://github.com/edgepillar/ptlc-research/blob/c847b5b5d45cd9039bc12ec79e43831955d11db4/qualification-go/verifier_test.go)
calls `schnorr.ParsePubKey`, `schnorr.ParseSignature` and `Signature.Verify` through
the unchanged `btcec/v2 v2.3.2` module and its Decred arithmetic dependency.
That path differs from the Rust worker's locked C `libsecp256k1` backend. The
[pinned Go verifier source](https://github.com/btcsuite/btcd/blob/4350859a7b9f7d744c1ee717e60cd29e466e2a25/btcec/schnorr/signature.go)
requires a 32-byte message, matching this SHA256 framing. As the
[existing Go qualification](../qualification-go/README.md) records, its historical
version rejects the newer variable-length positive BIP340 vectors. It remains a
test subject, not a production dependency recommendation or complete current
BIP340 conformance claim. Existing [licenses and attribution](../THIRD_PARTY_NOTICES.md)
apply; no external implementation, fixture or arithmetic is copied in this stage.

## Negative controls and trust limits

Seven new top-level tests include 106 named subtests. Controls cover five malformed
key shapes/points, seven invalid signature encodings/point/scalar bounds, every
one of 64 signature-byte mutations and the historical message-length boundary.
All eight signed fields and all 16 mutable source/scope selections have independent
negative checks. The original and alternate valid signatures both verify the same
intent while producing different full request hashes.

The intent signs its eight fields, not a free-standing permission or arbitrary
outer packet. Changing the outer schema, upper-casing signature hex or adding an
authorization field changes request bytes without invalidating the intent's raw
mathematics. The unchanged application parser must refuse all three forms. This
Go primitive check parses and authorizes none of them; it demonstrates why exact
framing and local expectation checks remain separate requirements.

Both alternate-owner and self-selected-source signatures verify independently;
they do not match the primary independently prepared local intent. Repeated valid
checks and reused IDs remain positives. Agreement between implementations tests
public mathematics and framing only, not expectation provenance, governor-role
assignment, authenticated economic equivalence, latest-source freshness, registry
uniqueness, non-rollbackable lineage, idempotency or dispatch ownership.

The application modules, public fixture and worker, journals, models, codecs,
dependencies, workflow and both fixed review subjects/reports are unchanged.
The existing Go CI job discovers the new tests automatically; it creates no
application path or new service. See [Stage 34 validation](STAGE34_VALIDATION.md).
Define and assess governor bootstrap/role policy and canonical source authority
before selecting any enrollment backend. Private signing, funded recovery and a
core PTLC port remain **NO-GO**.
