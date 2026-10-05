# Stage 41 validation

Status: **All required local checks passed, with no failed or skipped tests.
Hosted exact-head CI evidence must be verified separately in the draft PR.**

This stage adds an [isolated policy/effect store](OFFLINE_POLICY_EFFECT_STORE.md),
its ordinary and native controls, a synthetic process actor and one safe SQLite
runtime probe in each existing Python CI job. The only protected effect is a
synthetic row committed in the same local database. No current-source
authentication, admission connection, dispatcher or physical worker fence is
implemented. Both fixed subjects and unfilled reports remain unchanged.

## Executed affected checks

The first run passed 44 tests in 2.019 seconds. Separating common fixtures from
the two test classes and strengthening native distinct-operation cap contention
produced 45 passing tests in 2.003 seconds. Adding post-commit refusal and
inconclusive rollback controls produced 47 passing tests in 1.990 seconds. The
release run, after explicitly closing temporary SQLite connections, passed
47 tests in 1.986 seconds. No affected run failed or skipped a test.

The final collection contains 36 ordinary tests and 11 native test methods.
Native actors receive actual POSIX `SIGKILL` at allocation, policy and effect
writes and immediately before/after commit. Separate native writers exercise
same-operation reconciliation, distinct-operation contention at a cap of one,
and both policy/effect orderings. An inherited native connection refuses before
SQL and leaves the parent usable. These tests exercise real temporary-file
SQLite and native process locks; no fake host selector substitutes for them.

The local safe runtime probe reports SQLite `3.54.0`, journal `delete` and
synchronous level 3, with authentication and physical entry explicitly false.
This is a runtime observation, not an independently reproduced upstream build.

| Check | Command or selected path | Result |
| --- | --- | --- |
| Final affected suite | `python3 -B -m unittest discover -s tests -p test_policy_effect_store.py -v` | 47 passed in 1.986 seconds, including 11 native methods; no failures or skips |
| Required full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 990 passed in 935.213 seconds; no failures or skips |
| Safe runtime probe | `python3 -B -m qualification.policy_effect_store` | SQLite 3.54.0; delete journal, synchronous 3; authentication and physical entry false |
| Fixed source inventories | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline |
| Artifact hygiene | `python3 -B scripts/check_artifacts.py` after staging | 528 index/worktree versions; 264 tracked files |
| Exact candidate and relative file links | Staged-byte, whitespace, compiled Python, unchanged-pin and workflow-delta checks | 15 changed files, five new; exact staged/worktree equality; three Python files compile; one exact workflow runtime probe; 928 relative file links |

All required local checks passed without failures or skips. Source inventory and
limited disclosure checks are separate from protocol correctness, provenance
and independent security review.

The unchanged Rust, Go and actual-worker suites are not rerun locally in this
stage. Their previous runs are not new execution evidence. Hosted runs must be
checked at the exact candidate head, including their full test logs and the
retained Stage 40 comparison outputs.

## Evidence limits

Policy revisions, complete profiles, original operation bindings and event
history are checked before and after each selected SQLite transaction. Charges
survive cap drops, owner changes and revocation. A new effect requires the same
current active revision/profile, while a historical completed effect remains
the same original record after revocation. Source mode labels and administrator
authority are local premises; no signature or current-source proof is checked.
An opaque proposal is not decoded resource usage. Distinct operation IDs can
repeat the same proposal under its cap.

Actual coherent file restore repeats the same effect, and coherent copies
split the cap. These passing unsafe controls demonstrate missing rollback/copy
protection. Partial corruption refusal is not evidence of external lineage.
In-process exceptions and rollback fault responses are synthetic controls;
native full-disk, I/O-error, OS crash, power loss and dishonest hardware/VFS
behavior are not tested. POSIX process controls do not qualify Windows. An atomic
synthetic database row is not physical worker entry, remote dispatch or signing.

Only original project MIT code and existing pure profile decoding are reused.
SQLite and Python remain external runtime components, without copied dependency
source or immutable build provenance. Existing fixtures, cryptographic checks,
workers, journals, action pins and workflow timeouts are preserved. Artifact
hygiene checks ASCII and limited disclosure patterns; it is not an anonymity
or protocol-security proof.

The 119-file baseline and 189-file observation subject remain fixed, with both
reports unfilled. Assess this later delta independently. Offline qualification
is **GO**; source integration, core port, activation, deployment, private signing
and funded recovery remain **NO-GO**.
