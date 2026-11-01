# Candidate native comparison at 18c048a

This M1 D6 slice adds a finite comparison for the separately tracked
[`18c048abb3f825274fa7b6900b65bd691ced15ef`](https://github.com/zenon-network/go-zenon/tree/18c048abb3f825274fa7b6900b65bd691ced15ef)
source. Native compatibility remains **UNFILLED** until fresh originals pass
their own source-bound acceptance. The behavior and journal selection remains
`77ba9c7`; the historical [821bdd2 comparison](NOM_DEV_821BDD2_NATIVE.md) and
its evidence remain unchanged. Application/core acceptance stays **NO-GO** and
independent assessment stays **UNFILLED**.

The [complete source inventory](NOM_DEV_18C048A.md) pins 525 upstream files,
their Git tree, archive and GPL version 3 license. The source and its tests are
acquired separately, not vendored or relicensed. The two original project
producers below are added only to one newly prepared qualification source view.

## Finite selection

The [frozen plan](../compatibility/nom_dev_18c048a_plan_v1.json) requires exact
JSON contents, scalar types, order, producer hashes and command selection.

| Stage | Scope | Required accounting |
| --- | --- | --- |
| Baseline | Preserve all 36 previous profiles; add five shared-component groups | 525 upstream files and 27 project producers: 552 files; 41 profiles and 45 commands |
| Fee originals | Append the unchanged fee producer and use the same two public synthetic originals | 553 files; 14 cases, 15 outcomes and two commands; no new key, signature or replacement |
| Complete planned attempt | Both stages in one fresh compiler workspace and one physical source view | 42 profiles, 47 commands and 813 finite profile outcomes: 642 reference, 58 prior runtime, 98 upstream/research and 15 fee outcomes |
| Complementary definition regression | Eight remaining upstream test roots and every observed descendant | Separate from the 813 profile outcomes; no overlap with the 11 per-entity, three tombstone and two project collection roots, for 24 definition roots in total |

Reference fixtures retain their `661b5ef` labels. Those labels describe fixture
constructions, not compilation inputs. Actual native receipts and source
snapshots must bind `18c048a`; no earlier result qualifies that source.

The five added groups select:

- `upstream-db-tombstones`: six pinned parents covering iterator deletion
  filtering in `Next`, `Prev`, `Last`, all-deleted input, manager `Pop` and reopen.
- `upstream-definition-tombstones`: three pinned parents for Sentinel enumeration,
  its callback iterator and project enumeration with empty stored values.
- `upstream-protocol-shutdown`: the two pinned mock-component Start/Stop tests.
  The upstream goroutine-growth observation only logs; it is not a leak-freedom,
  shutdown-deadline or running-node proof.
- `research-storage-composition`: two original parents and nine children for
  snapshot masking, nested delete/restore/delete views, a live empty value,
  complete prefixes, unsupported merged reverse iteration, manager historical
  views/`Pop`/reopen and scripted iterator-error forwarding. Existing pinned
  upstream `keyedTransaction` is called as a test helper; its code is not copied.
- `research-collection-boundaries`: two original parents and seven children for
  live versus empty post-wrapper rows, callback refusal, and the existing panic
  plus iterator-release boundary on database iterator errors. A database error
  is not accepted as a successful empty collection.

The injected iterator faults are scripted interface failures, not physical IO
faults. Closing and reopening LevelDB is not crash-durability evidence. The
selection supplies no canonicality, finality, chain observation, signing,
nonce-custody, malformed-row, storage-key/value-mismatch or exact accelerator
deadline qualification. Unchanged direct PTLC files do not establish that all
shared storage changes are consensus-neutral.

## Execution and originals

| Entry point | Purpose |
| --- | --- |
| [Source preparation](../scripts/prepare_nom_18c048a.py) | Check the exact archive and every blob before writing one new 552-file view |
| [Two-stage runner](../scripts/qualify_nom_18c048a_bundle.py) | Execute the baseline, freeze originals, append the fee producer and reuse only this invocation's live compiler cache |
| [Baseline reader](../scripts/check_nom_18c048a_evidence.py) | Check receipts, exact source/count types, finite values, cold-package nonexecution and complementary test framing |
| [Bundle reader](../scripts/check_nom_18c048a_bundle.py) | Check both stages and the explicit privacy-safe original file selection, including honest incomplete retention |
| [Isolated Linux workflow](../.github/workflows/nom-18c048a-native.yml) | Acquire pinned Go and source inputs, then run the declared comparison offline |

The caller must admit owned storage with a 10 GiB floor plus allocations and
reservations. Hosted setup keeps its 4 GiB allocation allowance; the runner
keeps its 2 GiB reservation. These checks are not OS filesystem quotas. A local
refusal authorizes no fallback cache, reservation reduction, cleanup or policy
change. The first actual candidate execution is selected on isolated hosted
Linux; local controls exercise synthetic streams and mocked compiler stages.

Go remains pinned to 1.23.12. Default vet, read-only modules, `-count=1`, local
toolchain selection and an offline dependency proxy remain required. No completed
test result or historical compiler cache is adopted. Removing the overlapping
whole-package second execution preserves all pinned definition roots while
avoiding their duplicate execution. This is a command-selection improvement,
not a measured timing or storage-saving claim.

Cold-build JSON must contain each selected package and zero test roots. The
complementary regression must complete every required root and observed child.
Failed, skipped, duplicated, foreign or incomplete frames refuse. Slash-labelled
children do not create fictitious intermediate parents. Both data checks are
stored inline in the native result and rederived from original streams.

A complete planned bundle selects 94 original command streams and eight JSON
documents: 102 files. The public manifest excludes private argv receipts, caches
and generated handoffs. Original output is never redacted, rewritten or replaced.
Unsafe output refuses publication and remains private. An absent or refused
artifact is missing evidence, even if a later job or run succeeds.

The unchanged trusted-base policy selects full CI for this adoption. A future
eligible public-client-only PR explicitly skips native work; unknown selection
conservatively runs it. The existing full and 821bdd2 workflows are preserved.
Green results for those older native subjects cannot qualify this new candidate.

Local regression, actual native values, original artifact custody, hosted PR
acceptance, normal history-preserving main integration and main's own push
acceptance remain separate gates. Linux success would not establish Darwin
behavior, compiler-build authentication or independent protocol assessment.
No node, activation, wallet, signature, broadcast or funds action is authorized.
