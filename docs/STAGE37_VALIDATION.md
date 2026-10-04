# Stage 37 validation

Status: **Affected unsigned-contract checks passed after correcting one test
fixture selection. Required full offline suite and candidate checks passed.
New hosted exact-head evidence must be verified separately in the draft PR.**

This stage adds the [unsigned assignment and v2 intent contract](GOVERNOR_ASSIGNMENT_CONTRACT.md),
one synthetic unsigned fixture and 30 affected test methods. No signature math,
issued credential, authenticated provisioning or current-state service is tested.

## Executed local checks

| Check | Command or selected path | Result |
| --- | --- | --- |
| First affected suite | `python3 -B -m unittest discover -s tests -p test_governor_contract.py -v` | 29 passed and one failed in 5.465 seconds; no skips |
| Corrected affected suite | Same command after selecting the intended invalid-source control | 30 passed in 6.007 seconds; no failures or skips |
| Required full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 848 passed in 922.645 seconds; no failures or skips |
| Fixed source inventories | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline; both manifest hashes and old public signature fixture hash unchanged |
| Artifact hygiene | `python3 -B scripts/check_artifacts.py` after staging | 480 index/worktree versions; 240 tracked files |
| Exact candidate and relative file links | Staged-byte, whitespace, AST, fixture and file-set checks | 15 changed files, including five new files; staged bytes equal worktree; two new Python ASTs parse; new unsigned vector independently rehashed; 829 relative file links |

The first run failed only in
`test_structurally_retained_invalid_source_math_remains_unverified`: it selected
the ordinary valid released fixture while asserting an all-zero invalid
pre-signature. The correction uses the existing explicitly invalid
`changed_source("zenon_bundle")` control, builds a matching independently selected
profile/assignment/intent, and confirms these pure bytes still establish no
source math. No implementation check was relaxed. The original failure is
reported here; the repeat passed. No test was skipped.

The new unsigned vector pins the five-field assignment, complete 14-field profile,
nine-field v2 intent, exact SHA256 domains and legacy-message separation. It is
not an executed root/owner signature, independent cross-language result or real
source/currentness proof. Artifact hygiene is limited ASCII/disclosure/path
checking, not a language classifier, secret scanner or anonymity guarantee.

The [parent draft PR](https://github.com/edgepillar/ptlc-research/pull/31) has
separate [seven-job CI](https://github.com/edgepillar/ptlc-research/actions/runs/37241348955)
at `a61a9947970a3b4843580ae1bb67a9df4d0705ce`. Historical evidence does not qualify
this new contract. The unchanged workflow discovers the new methods; configured
discovery is not execution evidence.

## Scope and evidence limits

Broader caps or another issuer now change the new assignment and owner message,
while the old scope and v1 message can remain unchanged. Peers cannot replace
the complete local expectation. Epoch changes reject old bytes under the newly
selected expectation, but keeping an old expectation still matches old bytes.
No trustworthy latest head, revocation source or atomic use-time check exists.

The real exhausted journal test establishes unchanged bytes, charged allowance
and recovery behavior after repeated unsigned construction/parsing. It implements
no enrollment, quota or permission. Old codecs, signature fixture, workers,
models, journals, dependencies and workflow are unchanged. Rust/Go and
actual-worker suites are not rerun locally for this pure codec delta; new hosted
results must be checked separately. The fixed subjects and unfilled assessments
remain unchanged. Root/owner signature construction, authenticated provisioning,
current-authority enforcement and independent review remain gates. Private
signing, funded recovery and a current-node core port remain **NO-GO**.
