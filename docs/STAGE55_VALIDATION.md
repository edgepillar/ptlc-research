# Stage 55 validation: owned witness transaction experiment

Parent candidate: `22d02ec4731d34c406a77cc601bb9b8132cef281`.
Parent draft: [PR 49](https://github.com/edgepillar/ptlc-research/pull/49).
This delta adds a test-only owned SQLite witness helper, synthetic child actor,
33 normal regressions, a 37-case actual-worker qualifier, two documents, four
append-only references and one focused actual-worker CI step. No application
storage or authoritative source/recovery construction is selected.

## Local execution

| Check | Observed result |
| --- | --- |
| Corrected witness regressions | 33 passed in 13.845 s; recorded runner 13.941 s. |
| Actual public-worker witness qualifier | 37 passed in 18.891 s; recorded runner 18.998 s. |
| Complete offline Python suite | 1375 passed in 950.921 s; recorded runner 951.203 s. Every discovered method id passed; zero skips, failures and ResourceWarning lines. |
| Fixed inventories | Complete observation subject: 189 files; frozen baseline: 119 files. |
| Safe SQLite runtime | SQLite 3.54.0, DELETE journal, synchronous EXTRA (3); authentication and physical entry false. |
| Artifact hygiene and relative file links | 710 index/worktree versions across 355 tracked files; 1170 relative file links resolve. |

**All required local checks passed.**

The first targeted run had one error in the malicious callback test: it placed
the Root signature at the response envelope level, adding a forbidden field.
The packet therefore correctly refused before any callback. The test now
changes the existing nested Root signature. The corrected targeted suite and
the actual-worker qualifier must pass before the complete candidate is tested.
This was a test control error, not a demonstrated transaction implementation
failure. The failed run remains recorded; no warning suppression is added.

Normal callback controls are not mathematical verification. The actual
qualifier inherits all 33 regressions and adds four actual-only controls; its
explicit forged-callback case remains intentionally untrusted. Actual worker
measurement is local executable identity only, not authenticated provenance.

The transaction experiment tests selected writer and process-death cuts,
SQLite read-only write refusal, rollback/fault/lost-result paths, two-process
stale-writer rejection and coherent consumer/source restore counterexamples.
It does not claim exhaustive crash cuts, actual ENOSPC, power-loss durability,
application integration or independent assessment.

The unchanged Rust 123 tests and Go 55 top-level tests are not rerun locally
for this Python/storage-only delta. The existing 18 actual-worker groups / 164
cases are not all rerun locally; they and the new 37-case group are required
on the new hosted candidate. Earlier standalone model comparisons are not
rerun locally; their regression methods remain in the full Python suite and
their existing CLI steps remain required in hosted CI. No earlier hosted
result is claimed as evidence for the new candidate.

## Preservation and publication gates

All 349 prior files remain byte-preserved outside four append-only documents
and the one workflow insertion. Application, source/store, journal, sampler,
opening/prefix/composition helpers, worker, grammar, fixtures, dependencies,
earlier models, workflow steps/pins/matrix/timeouts, licenses and attribution
remain unchanged. No external code, signer or private/key fixture is added.

The frozen baseline remains `e592633e4c630cfe3f4669876f6f63b80d2e33d6` / 119 files;
the observation subject remains `f81e376e96e339647bb065739b4461235f865d2c` / 189 files.
Inventory hashes remain `df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295`
and `2f463071bc4f96ba1adaa8e8eb206d47e51845170ca2efe0f2b58182559afd6f`.
Both independent reports remain unfilled. This new experiment is outside both
fixed subjects and has no independent assessment.

Snapshot-input SHA-256 remains
`0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01`;
public snapshot-response SHA-256 remains
`2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb`.
Public worker source SHA-256 remains
`e96a8219e500cd0f79716796c146f64ce22e5f95bd3af26ccd2ad8a208c4834e`.
Native executable measurements are separate platform/runtime evidence.

Public content remains English ASCII and synthetic. Before publication verify
the owned destination, parent state, overlap and explicit generic project
author/committer metadata, UTC dates and unsigned commits. After publication
verify rendered body, immutable server blobs, metadata and all seven jobs on
the exact executed checkout/tree/parents. Hosted evidence belongs in the PR
body rather than a source change that would invalidate its measured tree.

## Decision

**GO** for the separate bounded offline transaction experiment and review.
**NO-GO** for application witness integration, current/canonical source claims,
private signing, nonrollback source/consumer guarantees, authoritative outcome
reconciliation, protected use, core port, activation, broadcast or funded use.

See [ownership, observed behavior and restore limits](ORIGINAL_WITNESS_STORE_EXPERIMENT.md).
