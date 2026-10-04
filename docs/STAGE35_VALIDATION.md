# Stage 35 validation

Status: **Required local offline, affected actual-worker and candidate checks
passed. New hosted exact-head evidence is pending at this local checkpoint and
must be verified and reported separately in the draft PR.**

This stage adds [explicit local governor-role rules](LOCAL_GOVERNOR_PROFILE.md)
and an optional pure match against the unchanged unsigned enrollment intent.
All inputs are public synthetic values. There is no governor assignment,
enrollment backend, private signing, journal integration or node access.

## Executed local checks

| Check | Command or selected path | Result |
| --- | --- | --- |
| Affected local profile suite | `python3 -B -m unittest discover -s tests -p test_governor_profile.py -v` | 24 passed in 4.271 seconds; no failures or skips |
| Locked public executables | Rust 1.90.0 `cargo build --locked --offline --manifest-path qualification/Cargo.toml --examples` using the previously acquired locked cache | Passed; unchanged public executables rebuilt |
| Actual governor-profile qualifier | `python3 -B scripts/qualify_governor_profile.py --enrollment qualification/target/debug/examples/verify_enrollment --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange` with the selected target directory | 7 passed in 4.159 seconds; no failures or skips |
| Required full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 794 passed in 885.825 seconds; no failures or skips |
| Artifact hygiene | `python3 -B scripts/check_artifacts.py` after staging | 462 index/worktree versions; 231 tracked files |
| Fixed source inventories | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline; both manifest hashes unchanged |
| Exact candidate and relative file links | Staged-byte, whitespace, AST, file-set and relative link checks | 14 changed files, including five new files; staged bytes equal worktree; three new Python ASTs parse; 779 relative file links |

All three local test suites passed on their first runs. This stage had no failed
or skipped test runs. Artifact checks are limited
ASCII/disclosure/path hygiene, not a language classifier, secret scanner or
anonymity guarantee. Inventories identify immutable source bytes, not authority
or independent review. The public signature fixture and both fixed manifests
and report templates remain unchanged.

The [parent draft PR](https://github.com/edgepillar/ptlc-research/pull/29) has
separate [seven-job CI](https://github.com/edgepillar/ptlc-research/actions/runs/37232189217)
at `b877b3a22004236569042aa5b647cc5d84dd522f`. That historical evidence does not
validate this delta. Configured new CI adds the seven actual governor-profile
cases alongside all prior worker groups; configured jobs alone are not evidence
that they ran.

## Scope and evidence limits

The 24 unit methods check exact 14-field framing, separate digest domains,
independently selected key/resource/six scope pins, separate cap bounds, hostile
types and parser replacement refusal. Matching returns the same unsigned intent
with no permission or journal writes. Format-valid non-curve keys, structurally
invalid source artifacts, replay, new IDs, stale expectations and broader local
caps remain explicit positives without authority. A forged selected verifier
callback is deliberately accepted by its unchanged trust interface; that unit
control proves no signature math.

Seven actual-worker methods verify a primary and alternate public signature,
refuse wrong local roles before work, and preserve scope/cap refusal despite a
valid signature. Selecting a peer key as new local rules remains a mathematical
positive with no bootstrap proof. Broader local rules change the profile digest
while the unchanged signed intent still verifies; policy-version binding is not
implemented. Actual key/signature checks reject malformed mathematical inputs.
Repeated profile and signature checks preserve the byte-identical exhausted
reopened journal, checkpoint, sequence and consumed allowance; subsequent
recovery refuses before its callback. This does not authenticate live source,
grant fresh quota or enforce profile use in any existing entry point.

Unchanged Rust and Go suites and the prior Linux actual-worker groups are not
rerun locally for this pure helper delta. New exact-head hosted execution must
be verified separately. No earlier model, journal, packet, dependency, fixture,
worker or fixed assessment subject is changed. Trusted role/bootstrap, current
policy and source authority, atomic registration, non-rollbackable lineage,
bounded work and unique dispatch remain unresolved. Private signing, funded
recovery and a current-node core port remain **NO-GO**.
