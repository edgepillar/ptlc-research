# Sealed public verifier submitted-wire ownership

Status: selected opt-in reference construction. Application and core progression
remain **NO-GO**. The selected parent is
`31a5bc8f310c0636a4be36d347b0439c6bbcc6c6`.
The preceding [sealed entry](SEALED_PUBLIC_VERIFIER.md) and
[acceptance cutoff](SEALED_VERIFIER_ACCEPTANCE.md) retain their trust boundaries.

## Requirement and selected construction

A successful receipt must bind the complete public request actually submitted
to the selected worker. Later changes to the caller's Python object must not
replace that expectation or require re-encoding that object after transport.
This is a direct-adapter requirement, not participant authentication or evidence
about private inputs consumed by a signing process.

The preceding optional adapter serialized a bounded request before launch but
recomputed its expected digest from the mutable caller object after transport.
A same-process modeled change could refuse an otherwise valid original receipt;
an unsupported later object could produce an unsanitized TypeError. These
observations establish neither a malicious native worker nor a cryptographic
false positive. The existing exchange consumer already derives its own original
expectation, passes a deep copy to the callback and translates callback failures.
Its complete bytes remain unchanged.

The selected adapter retains the existing canonical request bytes and 32768-byte
bound. After the original monotonic deadline starts, and before acquiring a
snapshot, it computes the complete expected result once from those immutable
bytes. The existing digest framing is unchanged:

```text
SHA256("PTLC/artifact-verification/v1" || NUL || canonical_request_bytes)
```

The stored expected result survives snapshot acquisition, transport and cleanup.
Receipt schema, exact true value, digest, canonical bytes and optional single LF
must still agree. A receipt rebound to a later changed request refuses. Later
unsupported, cyclic or oversized caller data is not submitted or re-encoded.
Each call derives a fresh expectation; a preceding receipt cannot substitute for
a distinct later request. The adapter does not promise that the caller object
remains unchanged or implement a lock over concurrent serialization.

The original cutoff still begins after serialization and the byte bound. Digest
preparation is inside that budget; snapshot acquisition checks remaining time
before file I/O. Runner return, snapshot cleanup and complete result validation
retain their existing checks. No hard syscall, scheduling, process-creation or
caller-delivery bound is established. Snapshot descriptor isolation, seals,
cleanup and the existing public runner retain their complete statements.

## Immutable local protocol evidence

The digest domain and public worker behavior are pinned to the selected parent:

- [Existing canonical encoding, digest and protected consumer](https://github.com/edgepillar/ptlc-research/blob/31a5bc8f310c0636a4be36d347b0439c6bbcc6c6/offline_session/exchange.py).
- [Existing native public verifier](https://github.com/edgepillar/ptlc-research/blob/31a5bc8f310c0636a4be36d347b0439c6bbcc6c6/qualification/examples/verify_exchange.rs).
- [Preceding optional sealed adapter](https://github.com/edgepillar/ptlc-research/blob/31a5bc8f310c0636a4be36d347b0439c6bbcc6c6/offline_session/sealed_artifact_verifier.py).

These are repository protocol sources, not proof of authenticated distribution
or source-to-worker correspondence. No upstream implementation is copied. The
preceding external license and semantic source reviews retain their scope.

## Qualification and unresolved authority

Seven new portable methods cover nested caller mutation, later unsupported and
cyclic data, a substituted changed-request receipt, mutation during snapshot
preparation, later growth past the original request bound, fresh per-call
expectations and digest-preparation expiry before acquisition. All 28 preceding
sealed method IDs remain present. Twenty-seven retain their bytes; the existing
result-binding/canonical-delay method retains its canonical-result delay case.
Its removed late mutable-digest patch is replaced by the new submitted-digest
cutoff control. Modeled APIs and clocks do not prove native or kernel behavior.

One appended actual method retains all eighteen preceding exchange methods and
the complete CLI. On Linux it repeats the same three original positive public
requests through unchanged native equations. Three unchanged and nine mutated
caller schedules must accept the original receipts; three changed-digest receipt
substitutions must refuse after the real worker returned original positives.
All fifteen actual per-call snapshots must close. These are selected same-process
caller schedules, not new crypto vectors, private-input measurements or exchange
state advancement. Unsupported macOS explicitly refuses without skips or native
snapshot launch. See [validation](STAGE86_VALIDATION.md) for separate local and
hosted evidence.

Legacy/measured adapters, consumers, public runner, guarded profiles, native
sources, actors, fixtures, dependencies, workflow, finite models, four fixed
inventories and three unfilled assessment reports retain exact bytes.
Source-to-worker and reproducibility remain **NOT VERIFIED**; producer origin,
private consumed inputs and runtime closure remain **NOT AUTHENTICATED**;
independent privacy remains **NOT ASSESSED**. Durable nonce custody,
restored-copy protection, independent review and application policy remain open.
No wallet, signing, transaction, chain, funds, broadcast, deployment, activation,
reviewer contact or core change is selected.
