# Local NoM recovery delta packaging qualification

Status: **LOCAL_SOURCE_IDENTITY_AND_REGRESSION_VERIFIED; HOSTED_PENDING**. This is a local qualification snapshot. It accepts no hosted attempt and records no independent assessment, operational service, signer, observer or recovery permission. Application/core remain **NO-GO**, recovery **NONE**, and all seven service gates **UNFILLED**.

## Exact implementation and source subject

The tested packaging implementation is `acefeedd7d3d3be72d70e671e25af6aeed101583`, tree `f8310df66a0c7a67b8f9d6fcce854d6bb584e792`: 974 tracked files, including the new reader, twelve controls, manifest, brief and unfilled report. The complete tested-source SHA-256 map is `da5f4b5f8dabff91a1f91e843b852116c258ce097ebf48ac1216e95dab89b3f9`. It is distinct from the 969-file review subject `a98dfe7b2fbfc8f8c2b378b34a524e1c1cdff8e7`.

The [review inventory](../review/nom-recovery-delta-subject.json) is 289,462 bytes, SHA-256 `d08cd8c85c04a0f4bbb8568ef3f87b5302f597686d520b2e208d99b993deb372`. Actual offline reconstruction accepted all 969 regular Git blobs, 32,689,521 source bytes and the complete delta from the earlier 620-file NoM inventory: 349 added, 9 changed, 611 unchanged, no removals. Eleven earlier review artifacts/report inputs remain unchanged. Inventory identity is not independent review, source authenticity or compiled dependency closure.

## Executed local checks

| Check | Observed result |
| --- | --- |
| Focused new and preserved NoM source controls | 21 tests passed in 52.437 seconds |
| Complete offline regression | 3,646 tests passed in 3780.984 seconds |
| Required directed identities | 1,220, each exactly once |
| OpenSSL, skipped tests and ResourceWarnings | OpenSSL required; zero skips; zero ResourceWarnings |
| Selected Python | 3.12.14; executable SHA-256 `7a314947596fc484d4ec36ffc28e843b78d6d749c68736f8b5c24e7333f418eb` |
| Complete original regression stderr | 698987 bytes; SHA-256 `c3f3e1d2521419ed098d20760db307daff77b336e7a2f90bb9033b47ab7ef1ec` |
| New reader on the actual fixed source | Actual zero exit and complete output before full regression |
| Artifact check at tested implementation | 1,948 index/worktree versions passed |

Controls include complete non-build coverage, executable mode, omitted rows and removed history, forged prior inventories, changed report/source/index inputs, noncanonical/duplicate-key data, source size bounds, links, case aliases, missing objects, mutable refs and disclosure bytes. The larger bounded reader does not change the older 2 MiB/16 MiB readers.

All 245 existing native SQLite profile inputs remain byte-identical to their previously qualified versions. This increment performs no additional local native SQLite comparison and reclassifies no earlier native result. Its new source-reader tests and actual inventory comparison are separate from the native engine and protocol assessments.

## Retained failed and auxiliary evidence

The first focused run executed 21 tests and failed one negative-control assertion: it targeted a row already marked unchanged. The corrected control targets the known added fixture. The original failed stderr remains retained, SHA-256 `44be96fbe9dfbf985bfde02ad1fee0050d937d8e37730cb5ea0b8b1b394df5d3`; the later passing focus/full runs are separate results.

A local evidence helper also failed a post-commit UTC display assertion because Git rendered UTC as Z. Another read-only helper refused packaging references not yet retained by that task. Both original failed tasks remain unchanged. A separate read-only reconciliation checked the existing generic unsigned commit, raw UTC metadata and complete source bytes with explicit current-task references; it created no replacement commit or public mutation. These were auxiliary evidence failures, not successful regression runs.

## Later documentation and hosted packaging

This report, a README link and one workflow step are later packaging. No tested Python/Rust/Go implementation, test, source inventory or measured native input changes. The new four-profile hosted step acquires only the two immutable NoM source commits and runs the same actual source-identity comparison. Job count, existing checks, timeouts and artifact retention stay unchanged. The complete source bridge is checked separately; no full local suite is claimed for these later documentation/workflow bytes.

Fresh exact-head PR checks, the new identity step on all four profiles, original console correlation and original native artifacts are still required before normal main integration. Exact published main and its later push/main attempt remain separate acceptance gates. The [independent report](NOM_RECOVERY_DELTA_REVIEW_REPORT_TEMPLATE.md) remains UNFILLED. Hosted CI, hashes and finite unsafe controls cannot supply independent authority, nonrollback retention, physical power-loss qualification or application signing.
