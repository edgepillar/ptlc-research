# Stage 38 validation

Status: **All required local checks passed. The first Go selection failed before
tests; the corrected full runs passed. Hosted exact-head CI evidence must be
verified separately in the draft PR.**

This stage adds [public issuer and v2 owner signature qualification](GOVERNOR_SIGNATURE_QUALIFICATION.md)
for the unchanged Stage 37 messages. There is no private signing, issuer
provisioning, current-state service, registry or application admission integration.

## Executed local checks

| Check | Command or selected path | Result |
| --- | --- | --- |
| First affected Python suite | `python3 -B -m unittest discover -s tests -p test_governor_signature.py -v` | 29 passed in 2.330 seconds; no failures or skips |
| Required full offline suite | `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v` | 877 passed in 931.976 seconds; no failures or skips |
| First affected Rust suite | `cargo test --locked --offline --manifest-path qualification/Cargo.toml --test governor_signature` | 10 passed; no failures or ignored tests |
| Locked full Rust qualification after stronger curve/wrong-key controls | `cargo test --locked --offline --manifest-path qualification/Cargo.toml` | 77 passed; no failures or ignored tests |
| First Go selection | `go test -mod=readonly -count=1 -v -run TestGovernor ./...` in `qualification-go` | Setup failed before tests: offline lookup could not find two dependencies because the existing module cache was not selected |
| Corrected full Go qualification | `go test -mod=readonly -count=1 -v ./...` in both modules, with the existing ignored module cache selected | 18 core-verifier and eight Bitcoin top-level tests passed; no failures or skips |
| Actual issuer/owner worker | `python3 -B scripts/qualify_governor_signature.py --governor qualification/target/debug/examples/verify_governor --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange` | 12 passed in 7.753 seconds; no failures or skips |
| Rust/Go formatting | Pinned Rust 1.90.0 and Go 1.23.12 format checks | Passed |
| Fixed source inventories | `python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c` | Complete 189-file observation subject and 119-file baseline |
| Artifact hygiene | `python3 -B scripts/check_artifacts.py` after staging | 500 index/worktree versions; 250 tracked files |
| Exact candidate and relative file links | Staged-byte, whitespace, AST, public-vector and file-set checks | 20 changed files, including ten new files; complete staged/worktree equality; four new Python ASTs parse; seven vectors independently rehashed; 858 relative file links |

The first Go run did not compile or execute a test. It used `GOPROXY=off` but did
not select the already populated ignored module cache, so two existing pinned
dependencies were unavailable to that process. Selecting the existing cache
corrected the environment; no dependency, checksum, network setting or source
guard was relaxed. The failure and corrected repeat are distinct evidence.
Additional unsigned-vector preservation and exact integer-boundary controls
were then added to Go, and the full 18-method module passed again. No test was
skipped or failing assertion removed. New Python/Rust/actual-worker tests passed
on their first run, and the required full offline suite passed on its first run.

Synthetic fixture generation uses the existing locked library and reproducible
public test tags only in Rust qualification. The seven vectors contain public
keys/messages/signatures, not secret-key fields or wallet material. Rust exactly
reproduces them; independent Go rehashes messages and full requests using exact
integers and checks both signatures. This proves synthetic compatibility within
these selected library/runtime assumptions, not independent construction review.

The actual qualifier checks both selected mathematical statements, exact local
expectations before work, every signature-byte mutation, scalar limits, wrong
domains/roles/v1 signatures, curve-invalid keys, alternate result bindings, stale
expectations, opaque-scope limits, forged selected-verifier positives and actual
exhausted-journal preservation. It also exercises the actual entry pin and
bounded/sanitized wire refusal. This is not a hostile-runtime sandbox or process
containment proof. Other unchanged actual-worker suites are not rerun locally;
their new hosted execution must be checked separately.

## Scope and evidence limits

The raw mathematical worker can verify a signed scope hash under an assigned
cap smaller than the actual request behind that hash. It has no decoded scope.
Complete independent preparation refuses that mismatch and incoming replacements
before work. Neither layer establishes trusted issuer provisioning, current
authority, chain/source truth, registry membership, quota or actual-use permission.

A new expected epoch rejects old packets, but a retained old selection continues
to verify them. Replay still succeeds, and an explicitly selected malicious
verifier can forge an exact positive for zero signatures. These counterexamples
remain part of the passing evidence. Real exhausted source journals retain their
bytes, consumed allowance and recovery refusal; no enrollment or permission is
implemented by the same unsigned returned object.

Both fixed manifests, source inventories, unfilled reports, the old v1 public
signature fixture and the Stage 37 unsigned vector remain unchanged. Old codecs,
workers, finite models, journals and dependency selections are unchanged. The
workflow adds one separate actual-worker step while retaining all old steps.
This later delta requires separate independent assessment. Trusted-current/use
ordering, authenticated issuer provisioning, non-rollbackable lineage and secure
signer design remain gates. Current-node core work, private signing, deployment
and funded recovery remain **NO-GO**.
