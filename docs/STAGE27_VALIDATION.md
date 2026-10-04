# Stage 27 validation: separate observation review packaging

Scope: a complete source-pinned observation inventory, offline object/index and
optional archive checker, synthetic integrity regressions, separate assessment
brief and unfilled report. Application code, journal, mathematical records,
cryptography, worker/store/pool/resource formats and locked dependencies are
unchanged. This is preparation, not an independent assessment.

Selected source: [`f81e376e96e339647bb065739b4461235f865d2c`](https://github.com/edgepillar/ptlc-research/tree/f81e376e96e339647bb065739b4461235f865d2c),
tree `aef1822a1ffa242d7987aa3a8ecfd2081a610be1`, 189 regular files. The complete
delta from the original 119-file subject is 70 added, 10 changed, 109 unchanged
and zero removed. The new manifest SHA256 is
`2f463071bc4f96ba1adaa8e8eb206d47e51845170ca2efe0f2b58182559afd6f`.
The original manifest SHA256 remains
`df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295`.
This later packaging is outside both source inventories.

## Local checks

| Check | Result | Boundary |
| --- | --- | --- |
| Initial integrity suite | 25 passed in 37.534 seconds, no skips | Real synthetic Git objects, working/index mismatches, promisor negative control and plain tar input |
| Expanded integrity suite | 27 passed in 39.504 seconds, no skips | Adds manifest/blob/archive size limits and boolean/integer delta alias refusal |
| Full required offline suite | 636 passed in 712.980 seconds, no skips | Required OpenSSL; all existing lifecycle and native/refusal cases remain included |
| Complete new inventory and frozen baseline | PASS: 189 and 119 files | Local exact Git objects, canonical working/index bytes; no lazy fetch or replacement refs |
| Optional actual source archive | PASS | Complete 189-file Git archive; exact bytes and executable classes, no extraction or publication |
| Artifact, local links and whitespace | 390 index/worktree versions, 195 tracked files, 598 valid local Markdown links; whitespace clean | English/ASCII and disclosure checks; two new Python files parse; both exact manifest hashes verified |

No failed regression run occurred during this stage's local validation. Neither
inventory changed during generation or verification; the source archive remains
an ignored local reproduction artifact, not a release.

A post-suite log audit initially rejected the local class-only unittest display
because it expected the older repeated-method display. The audit parser was
corrected to accept both formats; the completed 636-test suite remained successful
and unchanged. This audit failure is distinct from a regression failure.

The promisor negative control deliberately invokes a local marker helper with
ordinary Git after removing a synthetic loose object, then requires the offline
checker to refuse without invoking it. No network or external object source is
used. Replacement refs cannot substitute the synthetic source. Other negative
cases cover changed source/tree/hash/mode/size/status, omitted/extra/duplicate
files, duplicate JSON keys, extensions, unsafe paths, unresolved or nonregular
index entries, and clean working files hiding changed indexed manifests.

Archive cases require complete bytes and executable classes, reject links,
special permissions, payload changes, duplicates/omissions and extra members
appended after tar end markers. Sparse oversized regular files test early input
refusal. The parser is the standard library on a trusted local host, not a new
hostile-format sandbox or provenance service. Fixture commits are raw synthetic
Git objects with explicitly assembled public fixture metadata; no installed Git
identity, commit hooks, real signer or application backend is selected.

## Hosted and independent gates

The selected source has [seven completed successful jobs](https://github.com/edgepillar/ptlc-research/actions/runs/37199301500):
609 Python tests in each Linux/macOS 3.11/3.13 job, required OpenSSL and no skips,
55 Rust tests, 13 Go top-level tests and nine actual-worker groups with 64 cases,
including all 13 v4 cases. [Stage 26 validation](STAGE26_VALIDATION.md) retains
the initial incomplete CI job-limit attempt. This parent execution is not
execution of the Stage 27 packaging.

CI acquires the two exact source commits as an explicit network step before
invoking the offline checker and discovery. The checker itself performs no
fetch. A supporting Git version is required; no unsupported-flag fallback is
selected. All four Python jobs must check the complete inventory and run the
expanded required suite. Completed exact-head logs for all seven jobs remain
required and must be recorded separately from this source report. Rust/Go and
actual-worker sources are unchanged and are not rerun locally for this packaging
delta. The hosted jobs retain those checks and native Linux gates.

No independent assessor or backend review is supplied by this package. The
[separate brief](OBSERVATION_REVIEW.md) and [unfilled report](OBSERVATION_REVIEW_REPORT_TEMPLATE.md)
preserve source, restore, native storage, aggregate-resource, construction and
availability obligations. Both independent subjects remain pending. Private
signing, chain observation, funded recovery, core port and activation remain
no-go.
