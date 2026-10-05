# Stage 40 validation

Status: **All required local checks passed, with no failed or skipped tests.
Hosted exact-head CI evidence must be verified separately in the draft PR.**

This stage adds a [policy-source/use ordering model](POLICY_SOURCE_USE_MODEL.md),
its directed controls and one CLI comparison step in each existing Python CI
job. It implements no source authentication, registry service, operation
backend, dispatcher, worker fence or runtime connection. Both fixed subjects
and unfilled reports remain unchanged.

## Executed local checks

The first affected run passed 33 tests in 2.851 seconds. After consistent
charge/entry audit validation and its regression control were added, 34 tests
passed in 3.143 seconds. The final run, with an explicit CLI operation-variant
label, passed the same 34 tests in 3.148 seconds. No run failed or skipped a test.

All eight final CLI comparisons completed: 6,580 selected schedules and 62,580
transitions each, totaling 52,640 schedules and 500,640 transitions. The earlier
eight-comparison run also passed, before the audit/label strengthening. Cached
reads expose current-policy violations. The two candidate cutoff policies have
no violation under the ideal premises in these selected schedules. The unsafe
source-restoration policy has no selected-schedule violation but fails its
separate directed restore control.

| Check | Command or selected path | Result |
| --- | --- | --- |
| Final affected suite | `python3 -B -m unittest discover -s tests -p test_policy_source_use_model.py -v` | 34 passed in 3.148 seconds; no failures or skips |
| Required full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 943 passed in 915.665 seconds; no failures or skips |
| Final selected CLI comparisons | Four policies, each with same-slot and distinct-slot callers | Eight complete comparisons, 52,640 selected schedules and 500,640 transitions |
| Fixed source inventories | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline |
| Artifact hygiene | `python3 -B scripts/check_artifacts.py` after staging | 518 index/worktree versions; 259 tracked files |
| Exact candidate and relative file links | Staged-byte, whitespace, AST, unchanged-pin and workflow-delta checks | 14 changed files, including four new files; exact staged/worktree equality; two new Python ASTs parse; one exact workflow step; 902 relative file links |

All required local runs passed without failures or skips. Source inventories and
limited artifact checks are separate from model correctness and independent
security review.

The unchanged Rust, Go and actual-worker suites are not rerun locally in this
stage. Their earlier results are not new execution evidence; new hosted runs
must be checked at the exact candidate head.

## Evidence limits

The model has two callers, two scoped operation slots, four complete-profile
symbols, one retained canonical resource/namespace and five ordered world
phases. Trusted provisioning, complete scope, credential validity, current
source truth, serialized durable records and abstract entry are ideal premises.
The selected enumeration omits outage, forged read, lost reply and restore
events; the directed tests cover only their stated bounded cases. It is not a
full action-graph exploration or an independent protocol assessment.

Commit and entry cutoffs intentionally give different revocation behavior.
Original-operation reconciliation supplies no refund or replacement identity.
Local caller restoration cannot rewind the assumed independent source, while
source-ledger restoration can repeat the same operation despite current policy.
Distinct operation IDs can allocate twice for the same proposal under its cap.
A charge proves no actual dispatch, worker entry or completion. No production
cutoff, backend, source authenticator or compromise-recovery mechanism is selected.

The original model and tests use only Python standard-library modules, synthetic
integer symbols and project MIT code; no third-party code, dataset, credential,
private signing material or dependency is added. Existing credential fixtures,
cryptographic checks, workers, journals and pinned CI actions are preserved.
One comparison step is added to the existing Python jobs. Artifact hygiene is a
limited ASCII/disclosure-pattern check, not proof of anonymity or security.

The 119-file baseline and 189-file observation subject remain fixed, with both
reports unfilled. Assess this exact later delta independently. Offline
qualification is **GO**; current-authority integration, core port, activation,
deployment, private signing and funded recovery remain **NO-GO**.
