# Public enrollment signature qualification

Status: **Stage 33 stateless public signature check relative to an independently
prepared local intent. No governor-role authority, registry, signer integration
or runtime admission is implemented.** All executed values are synthetic.

The [Stage 32 intent](RETAINED_RESOURCE_INTENT.md) and its message are unchanged.
This separate public BIP340 verifier adds exact input/result binding and an
explicit executable pin. A valid signature does not establish who may govern
the content class, whether its source is authentic or who may allocate allowance.

## Requirements, choices and evidence

| Requirement | Selected construction | Executed boundary |
| --- | --- | --- |
| Peer input cannot replace local selections | Match all eight intent fields to an exact prepared `EnrollmentIntent` before invocation | Correctly signed alternate-owner/source packets refuse before work relative to the independent expectation |
| Verify the exact proposed source, scope and role | BIP340 over the unchanged Stage 32 message using the locked backend | Actual checks reject old signatures under all nine changed scope selections, corrupted signatures and another message domain |
| Bind a result to the complete signature request | Separate request hash including the signature | Another valid signature has another transport hash; no registry idempotency follows |
| Deliberately select the verifier | Required entry-file SHA256 pin, repeated bounded measurement and pipe exchange | Changed files refuse before launch; no atomic measured launch, build provenance, host attestation or sandbox follows |
| Preserve recovery/storage boundaries | No journal/store integration; return the same unsigned intent | Actual checks after exhausted reopen preserve candidate, allowance and files; replay and stale expectations remain accepted |

The pure [framing helper](../offline_session/enrollment_authentication.py) performs
no signing, curve arithmetic, storage or process launch. The separate
[adapter](../offline_session/enrollment_verifier.py) invokes only the explicitly
selected [public worker](../qualification/examples/verify_enrollment.rs).

## Message and backend

```text
message = SHA256("PTLC/observation-enrollment-owner-intent/v1" || NUL || canonical intent)
request digest = SHA256("PTLC/observation-enrollment-signature-request/v1" || NUL || canonical request)
```

The unchanged eight-field intent commits schema, purpose `observation-enrollment`,
role `enrollment-governor`, algorithm, selected resource digest, complete requested
scope digest, independently selected owner key and request ID. All nine external
scope selections are bound through the scope digest. A changed scope requires
another signature even when the selected content key is unchanged.

The worker uses `XOnlyPublicKey::from_slice` and `verify_schnorr` through unchanged
locked `bitcoin` 0.32.7 and its `secp256k1` 0.29.1 backend. It parses a 32-byte
x-only key and 64-byte signature, as specified in
[BIP340 at an immutable commit](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0340.mediawiki).
The specification is BSD-2-Clause, with its code under BSD-2-Clause, MIT or CC0;
no external source or reference arithmetic was copied for this stage.

The worker adapts the internal MIT
[earlier completion verifier](https://github.com/edgepillar/ptlc-research/blob/43c2463b4d3ac1fa3817c24d867a9dfe7efbfc33/qualification/examples/verify_authentication.rs),
using the distinct enrollment domain and role. Completion authentication and
Alice's completion role establish no governor authority. The adapter reuses the
unchanged bounded entry measurement and pipe runner. Dependencies, lock files,
[third-party notices](../THIRD_PARTY_NOTICES.md) and prior workers are unchanged.
Synthetic signing exists only in the Rust test harness to reproduce public
vectors. Fixed public scalar tags must never secure funds. The temporary vector
generator was removed before validation/publication. Application modules and
the public worker contain no signing or nonce owner.

## Wire and result boundaries

| Object | Exact fields | Schema |
| --- | --- | --- |
| Envelope | `schema`, `intent`, `signature_hex` | `ptlc-observation-enrollment-signature-envelope-v1` |
| Worker request | `schema`, `intent`, `signature_hex` | `ptlc-observation-enrollment-signature-request-v1` |
| Positive result | `schema`, `request_digest_hex`, `signature_valid` | `ptlc-observation-enrollment-signature-result-v1` |

Envelope/request bytes are bounded at 8,192 bytes, result capture at 512 bytes.
The detached signature is exactly 64 bytes with lower-case hex encoding. The
intent retains its exact eight-field shape and fixed strings/digests. Sorted-key
compact ASCII JSON rejects duplicate/escaped fields, aliases, extra/missing keys,
non-string bindings, noncanonical whitespace and deep/malformed values. The pure
helper accepts no trailing LF; worker stdio accepts at most one LF.

The adapter accepts only the exact canonical three-field result with the full
request digest and JSON `true`, optionally followed by one LF. Stale digests,
numeric aliases, extra permission fields and other schemas refuse. Ordinary
process/protocol failure supplies no signature fact; an exit status is not a
normal negative signature statement. Worker diagnostics expose no request bytes
or paths. Cancellation propagates after existing runner cleanup attempts.

## Trust, replay and work

Independently prepare the source, requested scope and owner public-key selection
through the unchanged Stage 32 factory. Never derive them from an incoming
envelope. Package an externally supplied public signature, match the incoming
intent to that expectation, and explicitly select the executable and expected
hash. `verify_signature` returns the same unsigned `EnrollmentIntent`, with no
authorization, enrollment, quota or worker-permission properties.

The standalone worker sees only supplied commitments and key. It can accept valid
signatures over arbitrary correctly encoded sources or another self-selected key;
the actual qualifier demonstrates both. The local helper stops substitution
relative to its expectation, but neither path proves expectation provenance.

A malicious selected executable or fake callback can forge matching positive
bytes. Python tests demonstrate this boundary; only actual locked-worker tests
supply executed signature evidence. They are not an independent implementation
or cryptographic assessment. The entry pin measures neither libraries/runtime,
source/build provenance nor host integrity. Measurement and launch are not atomic.

The same signed intent verifies repeatedly, even against an old expectation after
its mutable source copy has changed. A fresh factory call can refuse that changed
snapshot while the old signature still verifies. No current role roster, revocation
state, registry, chain source, clock or authoritative head is consulted. Alternate
valid signatures have distinct request hashes; reused request IDs do not supply
registry idempotency. Source/economic equivalence and first-registration capture
remain unresolved, with no uniqueness, rotation, reset or retry rule implemented.

The adapter uses the existing legacy bounded pipe path. It acquires no store
lease, pool slot, CPU/address-space cap or durable attempt record. Verification
is outside recovery allowances; repeated valid or invalid envelopes can start
repeated work. The transfer/direct-child deadline retains existing scheduling,
cleanup, escaped-descendant and trusted-host limits. Aggregate rate/resource
policy and trusted backend admission require separate qualification.

## Evidence and next gates

See [Stage 33 validation](STAGE33_VALIDATION.md), including the initial qualifier
startup failure and the separation of local and hosted execution. New
[Python tests](../tests/test_enrollment_signature.py),
[Rust tests](../qualification/tests/enrollment_signature.rs),
[public vectors](../qualification/fixtures/enrollment_signature.json) and
[actual qualifier](../scripts/qualify_enrollment_signature.py) lie outside both
fixed [original](INDEPENDENT_REVIEW.md) and [observation](OBSERVATION_REVIEW.md)
subjects. Neither unfilled assessment is completed or expanded.

1. Independently assess the exact framing/verifier delta and reused backend.
2. Define trustworthy pins, governor/namespace identity, role assignment,
   compromise/rotation/revocation, authenticated source/economic equivalence and
   first-registration capture before allocation.
3. Select non-rollbackable atomic enrollment, authorized reset and scoped duplicate
   lookup. Qualify concurrent copies, uncertain replies, coherent restores and
   storage/power failures with charged lineage preserved.
4. Qualify bounded owner-check admission and trusted one-use dispatch before
   connecting an authority to source journals or observation work.

**Go:** further offline qualification of this exact public signature check.
**No-go:** treat positive bytes as governor authorization, allocate fresh quota,
claim authenticated canonical source or restore/clone defense, integrate private
signing, select production activation, port core rules or use real funds.

The later [Stage 34 Go cross-check](INDEPENDENT_ENROLLMENT_SIGNATURES.md) rebuilds
these unchanged public fixture messages/resource/scope/request digests and verifies
their signatures with separate arithmetic. That test-only path adds no application
parser or service. Exact framing, trusted expectations and governor/bootstrap
policy remain separate requirements; repeated IDs and self-selected source/key
positives remain. See [validation](STAGE34_VALIDATION.md).
