# Stage 34 validation

Status: **Required local offline, independent Go and candidate checks passed.
New hosted exact-head evidence is pending at this local checkpoint and must be
verified and reported separately in the draft PR.**

This stage independently cross-checks the unchanged
[public enrollment signatures](INDEPENDENT_ENROLLMENT_SIGNATURES.md) through the
existing locked Go BIP340 dependency. It changes test/documentation content only.
All inputs are public synthetic fixtures; no signing, registry or node is added.

## Executed local checks

| Check | Command or selected path | Result |
| --- | --- | --- |
| Affected Go module | `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -mod=readonly -count=1 -json ./...` in `qualification-go`, using Go 1.23.12 | 12 top-level tests and 161 subtests passed in 0.491 seconds; seven new top-level tests with 106 subtests; no failures or skips |
| Go formatting | `gofmt -l qualification-go` from Go 1.23.12 | Passed; no output |
| Required full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 770 passed in 883.875 seconds; no failures or skips |
| Artifact hygiene | `python3 -B scripts/check_artifacts.py` after staging | 452 index/worktree versions; 226 tracked files |
| Fixed source inventories | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline; both manifest hashes unchanged |
| Exact candidate and relative file links | Staged-byte, whitespace, file-set and relative link checks | 12 changed files, including three new files; staged bytes equal worktree; 756 relative file links |

Both test suites passed on their first runs. This stage had no failed or skipped
test runs. Artifact checks are limited ASCII/disclosure/path hygiene, not a
language classifier, secret scanner or anonymity guarantee. Source inventories
identify immutable bytes, not source authority, independent review or runtime
trust. The public enrollment fixture remains byte-for-byte unchanged.

The [parent draft PR](https://github.com/edgepillar/ptlc-research/pull/28) has
separate [seven-job CI](https://github.com/edgepillar/ptlc-research/actions/runs/37228282593)
at `c847b5b5d45cd9039bc12ec79e43831955d11db4`. That historical evidence does not
validate this new Go delta; new exact-head CI must be checked separately.

## Scope and evidence limits

Independent Go SHA256/JSON reconstruction matches all three fixture messages and
request digests, retained-resource content and complete requested scope. Separate
signature arithmetic verifies the primary, alternate-owner, self-selected-source,
alternate-signature and wrong-domain controls. All 16 source/scope changes, eight
intent-field changes, invalid encodings/bounds, all signature-byte mutations and
changed serialized message/domain bytes reject the old intended signature.

Raw mathematical positives after outer schema/encoding/permission changes do not
establish valid application packets. The unchanged exact Python/Rust codec must
refuse those forms. Self-selected source/key signatures, reused IDs and repeated
checks remain valid public mathematics with no governor-role or registry authority.

No application, fixture, worker, model, journal, codec, dependency, workflow or
fixed review inventory/report is changed. The unchanged Rust, Bitcoin-Go and
Linux actual-worker qualifiers are not rerun locally for this test-only delta.
New exact-head hosted execution must be verified and reported separately; parent
results are historical evidence. This stage is separate from both fixed review
subjects and supplies neither an independent security assessment nor role/source
trust, replay defense, registry lineage or resource allocation. Private signing,
funded recovery and a current-node core port remain **NO-GO**.
