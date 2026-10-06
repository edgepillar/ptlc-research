# Stage 62: Selected private-prefix and artifact-byte observations

Status: local checks passed; exact candidate hosted checks required;
independent review NOT ASSESSED.

## Changed boundary

Add the [read-only construction](OFFLINE_ARTIFACT_PREFIXES.md) outside all three
preserved review subjects. It consumes two bounded regular files, explicit
expected hashes/sizes and four private exact byte prefixes per file. It hashes
and compares both complete streams, including bytes after all selected matches.
Its logical output contains no copied private prefix, occurrence position,
context, prefix length or prefix/selection fingerprint. Neither equal bytes nor
a negative scan qualifies an artifact for publication or proves provenance.

The checker invokes no Git, Cargo, compiler, build script or worker. No new build
profile, remapping, native reconstruction, artifact upload, signer/backend,
application cryptography or core integration is selected. The full inherited
workflow is byte preserved; native workers and mathematics remain separate
existing checks.

## Focused and real-file observations

The 32 new synthetic controls cover exact role/type/length and duplicate
selection refusal, bounded private JSON/depth/encoding, private input
permissions, same-file and hard-link alias refusal, linked immediate parent
refusal, trusted higher-ancestor gaps, independent hash/size mismatch, empty and
oversized input refusal, overlapping and maximum-length chunk crossings, full
stream comparison, equal-file copies without provenance, changed selections
without authenticated origin, mid-read changes and sanitized CLI failures.
Cancellation propagates. The CLI creates no files, preserves selected input
content/mtime and launches no native tool or network interface.

A synthetic equal-hash stub with different bytes still produces `DIFFER`:
comparison is not inferred from a hash claim. A zero-match artifact containing
unselected identifying text remains `KEEP BOTH ARTIFACTS PRIVATE` and
`NOT ASSESSED`. Copies of the same bytes can match without independent builds.
These are explicit counterexamples to stronger interpretations of the output.

- Final 32 focused controls passed in 0.230 s; runner 0.309 s. Source bytes are frozen and unchanged for the complete suite.

- The new CLI read two existing native Apple debug artifacts against the expected hashes already retained by the preceding build reports. Complete files measured 2408256 and 2408464 bytes; all four selected prefixes were present in each, and complete streams differ. The corrected read-only harness passed in 0.099 s. There was no new native build or worker launch, no byte/prefix mutation and no artifact upload. Private selections and raw bytes remain private; the cause of the difference is not isolated.

The initial private real-file harness requested an obsolete digest field from
the preceding stored measurement report and stopped before invoking the new
checker. The corrected harness uses the report's already selected expected hash.
It neither recalculates an expectation from the current artifact nor rebuilds
or launches it. No focused regression or qualifying full-suite test failed.

- Full offline Python: 1588 tests passed in 1081.288 s; runner 1081.603 s. All 1556 prior unique IDs and 32 new controls passed. Skips, failures and ResourceWarning lines are zero; required OpenSSL was enabled.

- Artifact hygiene passed 784 index/worktree versions across 392 tracked files; 1290 relative file links resolve. All 388 prior files remain exact outside four append-only documents; 384 are byte preserved, including the complete workflow. All three subjects and unfilled reports retain exact bytes. An initial private preservation helper used an incorrect report pathname after completing the prior-file comparisons; its corrected complete preservation check passed.

Unchanged Rust 123 tests, Go 55 top-level tests, the existing 21 actual-worker
groups / 238 cases and standalone models are not rerun locally in full at this
stage. They remain required in exact candidate hosted checks. The two native
artifacts were only read locally; raw bytes, private selections and their paths
are not hosted inputs and are not republished.

## Required exact candidate hosted evidence

All seven jobs must complete on the new candidate; an earlier green run is not
substituted. Four Python platform/version jobs must run all 1588 unique IDs,
including all 1556 prior and 32 new controls, without skips, failures or
ResourceWarning lines. Preserve Rust 123, Go 55, the existing 21 actual-worker
groups / 238 cases, complete source/content/resolution checks and fresh selected
Linux worker build. The new artifact scanner is exercised against synthetic
inputs in each Python job; no native artifact comparison is claimed there.

Check each actual immutable checkout's exact tree and ordered base/head parents,
separately from the displayed merge. Compare all expected source blobs, all
three manifests, unfilled reports, generic UTC unsigned unlinked metadata,
English ASCII rendered body, owned destination, unchanged parent draft and
absence of reviewer/comment actions. Inspect both index and worktree versions
for accidental disclosure patterns. These checks do not prove anonymity.

## Preserved limits

Prefix absence only concerns four exact selected strings per file. Search does
not cover alternate encodings, unselected identifying material or all metadata.
Positive roles can overlap; they are not independent evidence. Both files stay
private under either result. Different bytes do not isolate a build input or
cause, and equal bytes can be selected arbitrary copies.

The file reads require owned quiescent inputs and trusted ancestors. They check
descriptor/path stability but provide no hostile-filesystem exclusion,
multi-file atomic snapshot, lock or future-launch binding. Higher-ancestor
symlinks can remain outside the selected fence. Caller expectations and prefix
selection are not authenticated. Source-to-worker provenance, reproducibility
and independent privacy assessment remain unverified/unassessed.

All three review reports remain unfilled. No reviewer is contacted. Application
and core progression remain **NO-GO** pending the unchanged authentication,
current/canonical source selection, nonrollback ownership, signer custody,
lookup/disclosure, original recovery and protected-use gates. No deployment,
node activation, wallet access, transaction broadcast or funds is involved.
