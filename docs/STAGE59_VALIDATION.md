# Stage 59: Selected installed dependency contents

Status: local checks passed; exact candidate hosted checks required; independent review NOT ASSESSED.

The selected construction compares fixed Cargo registry archives with complete
installed trees, two pinned Git inventories with checkouts, and declared Go
module ZIP/installed/definition contents with fixed source `h1` records. It adds
no application cryptography or build attestation. See the
[construction and trust boundary](OFFLINE_DEPENDENCY_CONTENTS.md).

## Preserved scope

All 371 prior files remain exact outside four append-only documents and a workflow
change adding two content steps and isolating Go acquisition. All earlier implementation, workers, helpers, tests,
qualifiers, models, dependency records, licenses and fixtures are retained.
The 119/189/360-file manifests and three unfilled reports retain exact bytes.
Seven jobs, prior action/toolchain pins, matrix, timeouts and twenty actual-worker
groups / 224 cases remain required.

## Local evidence

- 35 new content controls passed in 12.664 s; runner 12.749 s. They cover changed/missing/extra files, unsafe paths, type/link changes, aliases, archive and payload bounds, fake cache metadata, independently rehashed Git commit/tree/blob identities, forged object bytes under old names and ambiguous selection, Go content/definition sums, corrupted ZIPs and sanitized CLI output.
- Full offline Python: 1472 tests passed in 1125.499 s; runner 1125.939 s. Every discovered unique ID passed and all 1437 prior methods are retained. Skips, failures and ResourceWarning lines are zero; required OpenSSL verification was enabled.
- Final-source real cached comparison passed in 43.937 s: 68 registry archives/trees, 3400 files / 51,596,440 payload bytes; two pinned Git trees, 168 entries / 1,376,517 bytes including one internal tracked symlink. Archive bytes retain all selected lock checksums.
- The two Go profiles verified six and nine declared requirements against fixed content and definition sums: 13 distinct cached modules. Their selected file sets agree between ZIPs and installed trees. Other checksum history remains unmeasured: one record in the first module and 101 in the second; no resolved or compiled closure is claimed.
- The first 32-control synthetic run failed at the missing Git metadata case because the library exposed a low-level unavailable-directory exception. That case now produces the consistent sanitized inspection error; a fresh expanded 35-control run and the final full suite passed. The first hardened-object fixture run then failed before corruption because Git created read-only loose objects; the synthetic fixture now explicitly restores its write permission and original mode. The earlier 1471-test suite remains separately recorded before object-identity hardening; the final source is qualified by a fresh 1472-test suite. No failure or skip is omitted from the final evidence.
- Artifact hygiene passed 752 index/worktree versions across 376 tracked files; 1257 relative file links resolve. All 371 prior files are exact outside four append-only documents and two workflow insertions. All three manifests and all three unfilled reports retain exact bytes.
- Go 55 top-level tests additionally passed against the original fixed records: 47 in the first module (runner 3.019 s) and eight in the second (runner 1.423 s). Neither source definition nor checksum file changed. Rust 123 tests, twenty actual-worker groups / 224 cases and standalone model CLIs were not rerun locally in full; all remain required in the new exact-candidate hosted run. No third-party code, cache contents or native binaries are republished.
- All required local checks passed. Acquisition authenticity, repository ownership, license compliance, resolved/compiled closure, toolchain origin, build environment, source-to-binary provenance, reproducibility and independent assessment remain unverified. Application/core remain NO-GO.

## Initial hosted failure and acquisition correction

The first candidate at `df2433cee649e1819c718de7b27a9d88299f8374`,
[run 37428971024](https://github.com/edgepillar/ptlc-research/actions/runs/37428971024),
passed its ordinary Go tests but rejected both new Go content entries. Its Cargo
content step passed. The acquisition command can rewrite source sums before
inspection. An offline attempt to reproduce the complete real download closure
refused because the local cache lacked some unmeasured graph modules; it acquired
nothing and did not change the source records. That attempt is not a successful
real-closure reproduction or conclusive diagnosis of the hosted rejection.

A fully synthetic local file proxy then verified that `go mod download all` can
add two checksum records to its working module and that acquiring in a separate
definition/sum copy leaves the original source byte-identical. It executed no
third-party code and contacted no network or checksum database. The final Go
acquisition step uses that isolation. The checker, fixed expectations, 35 new
controls and all prior implementation/tests are unchanged. The 1472-test suite
therefore covers the same final checker/test code; this workflow-only correction
is separately qualified by the synthetic acquisition proof, both offline Go
suites, artifact/preservation checks and a fresh required hosted run. No checker
rule is weakened and no source file is restored or repaired after acquisition.

The first run and every failed or skipped job/step remain separate evidence;
only all seven passing jobs at the corrected immutable candidate can satisfy
hosted acceptance. No incomplete earlier run is a success claim.


## Hosted acceptance boundary

Acceptance requires all seven jobs at the immutable candidate, with the actual
executed checkout's tree and ordered parents checked separately from a displayed
merge ref. Each Python matrix job must retain all 1437 prior unique test IDs and
pass every new control with no skips or ResourceWarning lines. Existing Rust 123,
Go 55 top-level tests, twenty actual-worker groups / 224 cases and standalone
model/inspection entries remain required. The adaptor job additionally compares
68 registry trees and both Git trees; each Go job compares its selected six or
nine declared module contents. Fixed digests and logical inventories must agree
with local evidence. Green checks do not supply independent review, release
provenance, ownership or operational authority.

## Outcome

Content qualification may proceed after required local and exact candidate hosted
checks pass. All three assessments remain unfilled. Application and core remain
**NO-GO**. Acquisition authenticity, source ownership, resolved/compiled closure,
build environment, toolchain origin, source-to-binary provenance, reproducibility
and independent assessment remain unverified, as do existing authentication,
current/canonical selection, nonrollback ownership, signer custody,
lookup/disclosure, original recovery and protected-use gates.
