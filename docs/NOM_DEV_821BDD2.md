# Tracked go-zenon dev source at 821bdd2

This D6 work item records complete source bytes and the changed shared paths.
It does not change the client's selected behavior source, authorize an adapter
or itself qualify native execution. The separately
[recorded finite Linux comparison](NOM_DEV_821BDD2_NATIVE.md) retains its exact
research source, PR/main attempts and exclusions. Application/core remain **NO-GO**, recovery
authority **NONE**, and independent assessment **UNFILLED**.

## Source subjects and acquisition

| Subject | Immutable selection |
| --- | --- |
| Newly tracked source | [`821bdd25eabacbf8a07b6310986f38713f27b4e3`](https://github.com/zenon-network/go-zenon/tree/821bdd25eabacbf8a07b6310986f38713f27b4e3), tree `c6625d9fae0dcf77cb60b5e1572402e8b565d9c6` |
| Last qualified behavior source | [`77ba9c7ee8c881e90911946756cdb67d8b586043`](https://github.com/zenon-network/go-zenon/tree/77ba9c7ee8c881e90911946756cdb67d8b586043); existing source and native evidence retain that subject |
| Previously tracked source | [`5bf75c8139e192cefaa7a9da441610f1c43622ab`](https://github.com/zenon-network/go-zenon/tree/5bf75c8139e192cefaa7a9da441610f1c43622ab); tracking did not upgrade the behavior selection |

The 523-file inventory is
[`compatibility/nom_dev_821bdd2_source_v1.json`](../compatibility/nom_dev_821bdd2_source_v1.json),
107,481 bytes, SHA-256
`f1f7d10dc42239e335d57b24224c22e823dd190ca77f79446b38ab79a72d024b`.
The separately retained source archive is 2,072,870 bytes, SHA-256
`f2a566981fc469b1b60416ac7e943307fb6a01288e6d29ac4258941941ab7308`.
Its regular source members total 8,538,502 bytes.

One bounded archive stream was checked against every Git blob, SHA-256 and
logical mode, then the complete Git tree was recomputed. No source extraction,
materialized build tree or native process was needed. The acquisition's opening
and terminal observations both selected this dev head. That is an observation,
not a promise that a moving branch will stay there. HTTPS and Git content IDs
provide no independent producer, compiler or release attestation.

The first local metadata evaluation refused valid UTF-8 through an ASCII-only
application-profile reader. Its successful original transport and failed task
remain preserved. The corrected metadata reader reused those seven original
responses; it retained duplicate-key/nonfinite refusals and added strict UTF-8
controls. No completed archive transport, native test or hosted run was retried.
The source archive reader and its existing two positive and 16 negative controls
were reused unchanged. The new seven JSON refusals and 16 metadata substitutions
are reader controls only.

The inventory reader reuses the existing strict schema/tree checks for both
immutable inventories. It opens neither the retained archive nor a compiler.
Passing it verifies the recorded inventory bindings, not source execution.
Upstream GPL version 3 source remains separately obtained and is not vendored
or relicensed. Original project inventories and historical failures are retained.

## Complete delta and shared-path impact

Relative to 77ba9c7, this subject is seven commits ahead: two files added, five
modified, no files removed, and 516 files byte-identical. Relative to the prior
tracked 5bf75c8, the metadata comparison reports five commits and four affected
paths. All 18 PTLC-named paths, `LICENSE`, `go.mod` and `go.sum` are unchanged.
This equality alone does not qualify compatibility.

| Changed surface | Source reading and consequence |
| --- | --- |
| `definition/stake.go`, `definition/liquidity.go` | Address-specific list getters now select the full address prefix before iteration. Their parsers recover address/id from keys; active-entry filtering and totals remain. The production call sites are the corresponding stake/liquidity RPC list methods. Unrelated addresses' rows and parse failures are no longer visited, so equivalence assumes valid stored rows and the declared iterator semantics. |
| `definition/common.go` | Pillar-vote iteration now selects the full poll-id prefix and removes the decoded-value id filter. Normal writes build key and value from the same vote. That invariant, iterator errors and malformed/mismatched storage require separate consideration; this is not a proof of equivalence on corrupted state. Callers include vote breakdown, accelerator decisions, phase vote deletion and accelerator RPC output. |
| `implementation/accelerator.go`, `implementation/common.go` | [PR #237](https://github.com/zenon-network/go-zenon/pull/237) adds a Dynamic Plasma gated final tally after project voting expiry and rejects later project votes through both voting methods. Phase votes remain separate. This is a spork-dependent behavior change, not merely a performance change. |
| Added definition and accelerator test files | [PR #236](https://github.com/zenon-network/go-zenon/pull/236) supplies 11 iteration test parents, including empty entities and actual shared address/id prefixes. The final-tally file supplies seven parents and eight named children. Their presence establishes no execution result. The final-tally context reports PTLC spork enforcement as false. |

The two modified `common.go` files were examined by changed function and call
site, rather than classified by filename alone. The voting methods are registered
on the accelerator contract; the PTLC method registry and PTLC implementation are
unchanged. The inspected changes introduce no direct PTLC ABI, witness, hash or
fee-policy delta. This is a scoped source finding, not a general security or
consensus-neutrality claim.

The complete inventory also covers verifier/VM entry points, account sequencing,
pool behavior, insertion/rollback, momentum/time, ABI/RPC, Plasma/spork and
serialization/dependency inputs. Outside the five listed modified paths and two
added tests, these inputs retain their prior bytes. Shared package compilation
and actual contract behavior still need their selected runtime evidence.

## Finite candidate selection and separate behavior upgrade

The [candidate native selection and runner](NOM_DEV_821BDD2_NATIVE.md) freeze the
following scope. Its declared finite Linux comparison was accepted for research
source `0081896` in [PR #222](https://github.com/edgepillar/ptlc-research/pull/222),
with separate PR and main originals. This does not select 821bdd2 as the client's
behavior or journal source.

1. Run the existing 31 reference profiles and the three 77ba9c7 boundary profiles
   against the new complete source, preserving their reference fixture labels.
   Old streams cannot be relabeled as new-source results.
2. Add the two changed upstream components: the 11 iteration parents and seven
   final-tally parents with their eight children. Preserve pre/post-spork
   distinctions. These accelerator tests do not exercise an enforced PTLC spork.
3. Keep the separate 14-case fee-original stage and its exact two signed
   synthetic originals. No refusal may be repaired by replacing, re-signing or
   broadcasting an original.
4. Use one newly admitted owned compiler workspace and sequential source stages.
   Reuse verified compiler/module inputs and the same owned compiler cache;
   retain each stage's exact snapshot and original streams. Count-one tests and
   default vet remain required. Do not adopt closed historical caches or rerun
   completed tests to repair evidence bookkeeping.

The declared malformed-row, key/value mismatch, iterator-failure and exact
voting-deadline exclusions remain. Do not infer those cases from ordinary
shared-prefix tests. A local comparison,
hosted PR acceptance, main integration and main-push acceptance remain separate
gates. The accepted finite comparison leaves complete admission, operational
and independent-review requirements unchanged.
