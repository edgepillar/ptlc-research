# Stage 39 validation

Status: **All required local checks passed, with no failed or skipped tests.
Hosted exact-head CI evidence must be verified separately in the draft PR.**

This stage adds [current-authority requirements and read-claim framing](CURRENT_AUTHORITY_EVIDENCE.md).
It implements no source authenticator, current-state service, registry, protected
use, signer or runtime connection. Both fixed subjects and unfilled reports remain
unchanged; the later source/framing delta needs separate independent assessment.

## Executed local checks

| Check | Command or selected path | Result |
| --- | --- | --- |
| First affected suite | `python3 -B -m unittest discover -s tests -p test_current_authority_contract.py -v` | 32 passed in 4.083 seconds; no failures or skips |
| Final affected suite after damaged-expectation numeric-alias controls | Same affected command | 32 passed in 4.086 seconds; no failures or skips |
| Required full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 909 passed in 910.090 seconds; no failures or skips |
| Fixed source inventories | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline |
| Artifact hygiene | `python3 -B scripts/check_artifacts.py` after staging | 510 index/worktree versions; 255 tracked files |
| Exact candidate and relative file links | Staged-byte, whitespace, AST, unchanged-pin and public-vector checks | 13 changed files, including five new files; complete staged/worktree equality; two new Python ASTs parse; both new digests independently rehashed; old governor packet unchanged; 880 relative file links |

The first affected, strengthened affected and full runs passed without a failed
assertion or skipped test. The source inventory is separate evidence about the
pinned objects. Artifact hygiene checks are limited ASCII/disclosure-pattern
checks, not proof of anonymity or independent security review.

The unchanged Rust, Go and actual-worker suites are not rerun locally in this
stage. Their earlier passing results are not new execution evidence; new hosted
execution must be checked at the exact candidate head.

## Scope and evidence limits

The vector contains existing synthetic public governor messages/signatures and
new synthetic source/checkpoint/challenge pins with unauthenticated claims. It
introduces no secret signing material, external dataset or dependency. Matching
a query revalidates complete local scope, profile pins, caps and retained-resource
framing. Parsing a claim verifies no mathematical signature, source delegation,
current head, lineage or permission. Active, revoked, absent and unavailable
remain forgeable public labels. The source root is distinct from the assignment
issuer; neither pin proves its selected role.

Directed controls retain old-policy matching, coherent old-context restore,
replayed challenges, fresh-challenge forged replies, distinct incarnation with
reused revision, exact checkpoint replacement refusal and outage shapes. Real
exhausted-journal state/sequence/database/anchor and consumed recovery allowance
remain unchanged; recovery refuses before its callback. These passing
counterexamples are evidence of the boundary, not runtime restore protection.

The existing finite governor model supplies separate conditional check/use
witnesses under ideal trusted-current assumptions. The new read framing does
not implement that oracle or choose a real protected-use cutoff. Source
provisioning, authentication, live-read semantics, rotation/compromise recovery,
atomic use/lineage/dispatch and independent assessment remain gates. Existing
crypto, workers, journals, dependencies and workflow are unchanged. Core port,
activation, private signing, deployment and funded recovery remain **NO-GO**.
