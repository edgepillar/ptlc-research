# Stage 33 validation

Status: **Required local offline, public-signature and candidate checks passed.
New hosted exact-head evidence is pending and must be reported separately.**

This stage qualifies the [public enrollment signature layer](PUBLIC_ENROLLMENT_SIGNATURES.md)
relative to the unchanged Stage 32 intent. It implements no governor-role policy,
enrollment registry, source authority, signer, quota allocation or recovery rule.
All fixtures and operations are synthetic and offline.

## Executed local checks

| Check | Command or selected path | Result |
| --- | --- | --- |
| First Python signature/adapter suite | `python3 -B -m unittest discover -s tests -p test_enrollment_signature.py -v` | 26 passed in 6.199 seconds; no skips |
| Locked Rust suite | `cargo test --locked --offline --manifest-path qualification/Cargo.toml` with Rust 1.90.0 | 67 passed, including 12 new enrollment signature tests; no failed or ignored tests |
| Public examples | `cargo build --locked --offline --manifest-path qualification/Cargo.toml --examples` | Passed; no manifest/lock/dependency change |
| Actual public signature integration | `python3 -B scripts/qualify_enrollment_signature.py --enrollment <public-enrollment-worker> --verifier <public-artifact-worker> --completion <public-completion-worker>` | 10 passed in 5.232 seconds; no skips |
| Required OpenSSL full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 770 passed in 910.080 seconds; no skips |
| Artifact hygiene | `python3 -B scripts/check_artifacts.py` after staging | 446 index/worktree versions; 223 tracked files |
| Fixed source inventory | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline; both manifest hashes unchanged |
| Candidate structure | Exact staged-byte, whitespace, Python AST and relative file-link checks | 18 changed files; four new Python ASTs; 734 relative file links |
| Rust formatting | `cargo fmt --manifest-path qualification/Cargo.toml -- --check` with Rust 1.90.0 | Passed |

Artifact checks are limited ASCII/disclosure/path hygiene, not a language classifier,
secret scanner or anonymity guarantee. Source inventories identify immutable
bytes, not independent review, source authority or runtime trust. New tests retain
all 26 Stage 32 contract, 29 authority contract and 26 enrollment model methods.
The [parent draft PR](https://github.com/edgepillar/ptlc-research/pull/27) has separate
[seven-job CI](https://github.com/edgepillar/ptlc-research/actions/runs/37223714470)
at `43c2463b4d3ac1fa3817c24d867a9dfe7efbfc33`; that historical evidence does not
validate this new verifier delta. New exact-head CI must be checked independently.

One initial actual-qualifier invocation failed before test discovery: it imported
a nonexistent helper module instead of the existing artifact verifier. The import
was corrected and the actual 10-test run above passed. No assertion, guard,
existing application module or mathematical predicate was weakened or changed.
The Python target and Rust suite passed on their first test runs.

## Coverage and practical limits

The 26 new Python methods qualify exact local intent/source/scope/key/message
bindings, all nine scope selection changes, candidate/copy stability, canonical
field/type/size/domain guards, hostile object refusal without hooks, defensive
copies and sanitized failure/cancellation. Exact results include the complete
signature request hash, refuse numeric `true` aliases and extra permission fields,
and require an explicitly selected executable pin. Repeated entry measurement
refuses changed, missing, nonregular, empty or oversized files before launch.

Those Python callbacks and mocked outputs are sequencing tests, not BIP340 or
curve evidence. A forged matching positive from a malicious selected verifier is
accepted deliberately to expose that trust boundary. An old independently prepared
expectation also remains replayable and stale after signature verification.

The 12 new Rust tests reproduce the public fixture, message domains, source/scope
hashes, deterministic synthetic signatures and result digests. They execute the
locked verifier against all intent bindings, shape/canonical/depth/byte guards,
noncurve keys, invalid signature encoding/scalar bounds, every signature-byte
mutation and another message domain. Alternative valid signatures, self-selected
sources, replay and reused IDs remain positives with no registry authority.

The 10 actual executable methods check valid/repeated signatures, malformed curve
keys/signatures, old signatures under every new scope selection, wrong-domain
signatures and another valid signature's distinct request hash. Correctly signed
alternate owner/source packets refuse before work relative to the local expectation,
although the standalone worker verifies them. Old expectations still verify after
their mutable source copy changes. A modified actual entry refuses before launch.

The actual exhausted-journal case uses unchanged public artifact/completion workers.
Repeated valid and invalid signature checks after reopen leave candidate, consumed
allowance, journal sequence, SQLite and checkpoint bytes unchanged. Recovery still
refuses before its callback; no quota is added.

Existing codecs, runtime/journal/store formats, models, mathematical predicates,
previous qualifiers and dependencies are unchanged. CI adds the signature qualifier
to the existing Linux actual-worker job, retaining all prior groups and the seven-job
matrix. Existing Go primitives and older Linux-only qualifiers are not rerun locally
on macOS for this delta; new hosted execution must be reported separately. The
actual signature check is neither an independent implementation nor an independent
security assessment.

Both fixed manifests and both unfilled reports remain unchanged. This later delta
needs a separate assessment. Source/economic equivalence, governor-role trust,
enrollment uniqueness, non-rollbackable lineage, idempotency, aggregate verification
resources and trusted dispatch are unresolved. Private signing, funded recovery and
a core port remain **NO-GO**.
