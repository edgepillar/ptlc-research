# Stage 36 validation

Status: **Affected model, all seven CLI searches, required full offline suite
and candidate checks passed. New hosted exact-head evidence must be verified
separately in the draft PR.**

This stage adds a [finite governor authority comparison](GOVERNOR_AUTHORITY_MODEL.md).
Root/assignment/intent validity and current state are ideal independent inputs;
profile binding is hypothetical. No credential bytes, provisioning, signature
worker, application enforcement or backend is implemented.

## Executed local checks

| Check | Command or selected path | Result |
| --- | --- | --- |
| Affected model suite | `python3 -B -m unittest discover -s tests -p test_governor_authority_model.py -v` | 24 passed in 1.158 seconds; no failures or skips |
| Seven complete finite searches | `python3 -B scripts/model_governor_authority.py --policy POLICY` for all seven named policies | All `bounded-complete`, exit zero; aggregate 126,610 states and 188,143 transitions; CLI cohort completed in 1.379 seconds |
| Deliberate search cap | `python3 -B scripts/model_governor_authority.py --max-states 1` | Expected `incomplete`, exit two; no safety claim |
| Required full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 818 passed in 938.518 seconds; no failures or skips |
| Artifact hygiene | `python3 -B scripts/check_artifacts.py` after staging | 470 index/worktree versions; 235 tracked files |
| Fixed source inventories | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline; both manifest hashes unchanged |
| Exact candidate and relative file links | Staged-byte, whitespace, AST, file-set and relative link checks | 12 changed files, including four new files; staged bytes equal worktree; two new Python ASTs parse; 799 relative file links |

The affected suite, complete CLI cohort and required full offline suite passed
on their first runs. The intentional capped probe is an expected incomplete
result, not a failed test or complete security search. There were no failed or
skipped test runs. Artifact checks are limited ASCII/disclosure/path hygiene, not a
language classifier, secret scanner or anonymity guarantee. Source inventories
identify immutable bytes, not authority, source trust or independent review.

The [parent draft PR](https://github.com/edgepillar/ptlc-research/pull/30) has
separate [seven-job CI](https://github.com/edgepillar/ptlc-research/actions/runs/37237224011)
at `1c44c8b834b4c3032ae5362bca6f98fb977a2856`. Those historical results do not
validate this new model. Unchanged workflow discovery includes the new methods;
configured CI alone is not evidence they ran.

## Scope and evidence limits

Self-selected/key-only policies admit untrusted assignment and scope/role
controls. Complete scoped assignment still permits unbound intent and old
authority. Profile binding adds no freshness. A checked-current positive can
survive policy/key change and revocation; coherent local anchor restore defeats
even a use-time rule that trusts its old view. Only an ideal non-rollbackable
current oracle with an indivisible use-time check has no selected safety finding.

Every policy still permits the same packet to be admitted twice. That is a
boundary of the abstract gate, not duplicate registration or actual work. Stale
cached negatives/views can refuse currently valid proposals. Audit judgments
use the instant of each decision and do not retroactively revoke earlier valid
ones. Every returned safety/boundary witness replays through validated public
transitions in the affected suite. None of this executes signature mathematics,
issues certificates or tests a native service transaction.

Existing application helpers/codecs, v1 intent/message, public signature fixture,
workers, models, journals, dependencies and workflow are unchanged. Rust/Go and
actual-worker suites are not rerun locally for this standalone model delta;
new exact-head hosted execution must be checked separately. Both fixed subjects
and unfilled reports remain unchanged; the later delta needs its own assessment.
Trusted provisioning/current-state evidence, reviewed credential construction,
source equivalence, registry lineage and dispatch remain open. Private signing,
funded recovery and a current-node core port remain **NO-GO**.
