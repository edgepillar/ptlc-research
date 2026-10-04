# Explicit local observation verdicts

Status: **Stage 18 offline public-only producer and adapter. No observation
source, negative cache, durable evidence store or journal admission is selected.**

Source parent: [`aa447e6bfabc5b968d4c63d480bdaf4f498263fc`](https://github.com/edgepillar/ptlc-research/tree/aa447e6bfabc5b968d4c63d480bdaf4f498263fc).
The [Stage 17 contract](OBSERVATION_EVIDENCE_CONTRACT.md) defines the exact local
target and statement vocabulary. Parsing such a statement alone establishes no
mathematical truth. Stage 18 adds a specifically selected local producer whose
normal verdict channel is distinct from request, process and transport failure.

## Requirement, construction and evidence

| Requirement | Selected implementation | Evidence and remaining obligation |
| --- | --- | --- |
| Decide the same public predicate for positive and negative results | New Rust worker reuses unchanged pure completion verification after a complete shape check | Synthetic fixture positives and adversarial negatives; independent construction/delta review pending |
| Do not convert incomplete work into rejection | Shape/I/O/panic failures exit nonzero; Python maps worker and result failures to `unknown` | Actual invalid-request exits plus synthetic deadline/output/exit cases; no durable attempt record |
| Bind normal results to exact local inputs | Exact Zenon-only request digest plus existing full-target statement fields | Cross-request and retained-journal checks; source authority remains separate |
| Locally select verifier semantics | Required expected entry-file SHA256, contract/version fields and domain-separated profile | Measurement tests; trusted provisioning, build provenance and host remain external |
| Avoid exporting signing or extraction material | Public-only request and four-field verdict, no recovered scalar or Bitcoin signature | Exact output assertions; no private signing or funded acceptance |

## Worker domain and normal results

[`verify_observation.rs`](../qualification/examples/verify_observation.rs)
accepts at most 65536 bytes of compact sorted-key ASCII JSON, optionally followed
by one LF. Duplicate keys, including nested duplicates, are rejected by exact
canonical comparison. Its request has exactly five fields:

- `schema`: `ptlc-completion-request-v1`.
- `kind`: `verify-zenon-completion`.
- `bitcoin`: null.
- `zenon_signature_hex`: lowercase hex encoding exactly 64 bytes.
- `zenon`: an exact `ptlc-artifact-verification-v1` Zenon `bundle`.

The bundle has the unchanged artifact verifier's twelve fields, with an empty
Taproot root. Context digest, aggregate key and message are exactly 32-byte hex;
adaptor point is 33 bytes; pre-signature is 65 bytes. Ordered signer keys, public
nonces and partials are arrays of exactly two encodings of 33, 66 and 32 bytes
respectively. Every hex field is plain lowercase text of its exact width. Wrong
schemas, modes, types, widths, array lengths or fields are unavailable requests,
not mathematical negatives. Bitcoin recovery requests are unsupported here.

Only after that complete shape check does the worker invoke the unchanged pure
`complete_exchange::verify_request` function. On this fixed domain, its failed
checks mean the public predicate is false: invalid point/scalar encodings,
duplicate or inconsistent keys/nonces, invalid ordered partials, wrong aggregate
key/pre-signature, invalid final key/message signature or a missing/nonzero
witness-to-adaptor relation. Fixed-width zero or out-of-range signature bytes
therefore produce a normal negative. A negative concerns the entire predicate;
it need not mean the final signature alone failed ordinary verification.

The reused function has no file, subprocess or network access. Its fallible
encoding/shape checks are covered by the new outer domain. A library panic
propagates to the executable boundary; it is never converted by `is_ok()` into
`rejected`. Any change to that reused function, its error partition or the
selected backend requires review of this normal-negative interpretation.

Normal responses contain exactly four string fields:

| Field | Meaning |
| --- | --- |
| `schema` | `ptlc-observation-verifier-result-v1` |
| `predicate` | `zenon-completion-v1` |
| `request_digest_hex` | Existing completion-domain SHA256 of exact canonical request bytes |
| `outcome` | `verified` or `rejected` |

Normal positive and negative responses both exit zero after writing and flushing
the canonical response plus LF. Request/read/write errors and caught panics exit
nonzero with fixed sanitized stderr. Crashes, aborts and missing output also
supply no normal verdict. The worker exports neither the extracted scalar nor
a Bitcoin signature. Its internal reused verification may compute the public
extraction witness in memory to check the adaptor relation, as before.

The worker treats the context digest as an opaque binding. Changing that digest
while retaining valid mathematical bytes can yield another positive result for
a different request hash. Neither this worker nor its hash authenticates the
context, source, inclusion, timing, funding or counterparty.

## Explicit local selection and adapter

[`SubprocessObservation`](../offline_session/observation_verifier.py) requires an
existing absolute executable, an explicitly supplied expected 32-byte lowercase
SHA256 and a deadline greater than zero and at most 30 seconds. Booleans and
non-finite deadlines are rejected. Entry-file measurement is bounded to a
nonempty regular file of at most 64 MiB, read in bounded chunks. Nonblocking open
and a regular-file check reject a replaced FIFO without waiting for a writer.
The file must match the supplied hash at construction and again before launch.
Mismatch at construction is a sanitized configuration error; later mismatch or
read failure yields an exact `unknown` statement without launching a worker.

The locally derived profile contains exactly:

| Field | Selected value |
| --- | --- |
| `schema` | `ptlc-observation-verifier-profile-v1` |
| `construction` | `CANDIDATE-01` |
| `predicate` | `zenon-completion-v1` |
| `request_schema` | `ptlc-completion-request-v1` |
| `result_schema` | `ptlc-observation-verifier-result-v1` |
| `statement_schema` | `ptlc-observation-math-statement-v1` |
| `adapter` | `ptlc-observation-adapter-v1` |
| `executable_sha256_hex` | Caller-provisioned expected entry-file measurement |

Its digest is SHA256 of `PTLC/observation-verifier-profile/v1`, a zero byte and
the canonical profile JSON. The response cannot select that profile. Changing
the entry file changes the profile and evidence key. Adapter semantics changes
need a new adapter version; labels alone cannot establish that a particular
Python implementation actually implements the named version.

The adapter first derives a Stage 17 immutable target from a validated local
snapshot and exact signature bytes. Invalid local input raises `EvidenceError`
before any launch; an unidentified target cannot receive a bound statement.
It then passes only the target's Zenon-only request to the existing bounded
[public pipe runner](PUBLIC_WORKERS.md). A normal result must have the exact
four fields, plain strings, expected schema/predicate/request digest, one of the
two normal outcomes and canonical bytes with at most one optional LF.

A matching result is encoded locally into the existing seven-field mathematical
statement, binding both retained legs and the selected profile. Nonzero exit,
timeout, stdout overflow, missing/malformed output, alternate encoding, legacy
result or mismatched digest becomes `unknown`. Stderr and exception values never
enter the statement. No error text is interpreted as rejection. Caller
`KeyboardInterrupt` and `SystemExit` propagate after runner cleanup and produce
no statement, especially no negative. They create no durable attempt record.

Consumers must still use `parse_statement` with their fresh local state and
expected profile. A peer can forge identical statement fields. Only invoking an
independently trusted local implementation under its explicit assumptions gives
the outcome its intended local meaning; parsing a received claim supplies none.

## Host, resources and future policy

The expected file hash must be established independently of peer input. It
identifies entry-file bytes, not reviewed source, compiler provenance, an
attestation, interpreter, dynamic libraries or transitive runtime behavior.
Different locally built binaries can have different profiles. A script's hash
does not measure its interpreter or files that script loads. The host, local
adapter, selected executable and runtime remain trusted. Path replacement
between measurement and launch is not prevented atomically. This is no hostile
filesystem defense, sandbox or reproducible-build claim.

The worker retains existing per-invocation input/output/transfer/exit limits.
Entry-file measurement has a separate byte bound, not a guaranteed storage-time
deadline. CPU/memory isolation, escaped descendants and aggregate admission or
rate control remain outside this adapter. Repeated distinct candidates or
interrupted work can still consume resources even if a future cache deduplicates
some normal negatives.

No statement is persisted, cached or applied to a journal. Real-worker tests
after reopen preserve database/checkpoint bytes, sequence, authentication pins,
exposure, consumed allowance and retained candidate exactly. A valid candidate
verdict neither replaces an invalid original nor bypasses exhaustion, and it
contains no Bitcoin recovery output. Durable attempt/outcome ordering, conflicting
verdicts, cache ownership, retention, profile changes and restored copies require
a separate policy and implementation before journal integration.

**Go:** independently review this producer's fixed domain, reused error paths,
local profile/provisioning and bounded tests, then specify durable evidence and
aggregate resource policy separately. **No-go:** connect a verdict cache or
admission policy as a funded guarantee, authenticate an observation using hashes,
introduce private signing, activate a contract or port this client work into the
core node. The frozen Stage 12 subject remains unchanged; Stage 18 needs a
separately identified delta assessment. See [validation](STAGE18_VALIDATION.md).

[Stage 19](OBSERVATION_RECORDS.md) now defines a separate pure bounded history
for these statements and unknown attempts. Its canonical values and actual
verdict exercises implement no owned persistent cache or journal policy. The
required disk ownership and commit ordering remain a separate next-stage gate.

[Stage 20](OBSERVATION_STORE.md) originally added a separate offline disk owner
around this mathematical profile. It commits pending work before invocation and a
bound result before return; restart recovers unfinished publication as charged
unknown. Record-writer exclusion does not contain orphan workers or establish
paired-restore protection, source authority or recovery admission. The producer
alone still performs no persistence, and both deltas need separate assessment.

[Stage 21](OBSERVATION_LEASES.md) adds an explicit observe_owned method that uses
the same mathematical profile with two inherited store lock references and a
parent-watching guard. Invalid/missing descriptors yield unknown without legacy
fallback. The guard remeasures the selected entry; interpreter/modules/runtime
remain separately trusted. The ordinary callable retains its unowned path and
supplies no lifetime supervision. Store v2 identifies the new ownership epoch
and quarantines old v1 pairs without migration. Cooperative exclusion is neither
arbitrary containment nor aggregate resource or paired-restore protection.
