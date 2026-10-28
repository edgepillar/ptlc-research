# Pinned go-zenon dev source at 77ba9c7

This is an additive source compatibility corpus. It preserves the preceding
661b5ef selection, original command streams, failed attempts and historical
assessments. Application and core remain **NO-GO**, recovery action is **NONE**,
and independent assessment remains **UNFILLED**.

## Exact source subject

The selected upstream is
[`77ba9c7ee8c881e90911946756cdb67d8b586043`](https://github.com/zenon-network/go-zenon/tree/77ba9c7ee8c881e90911946756cdb67d8b586043),
Git tree `57da4b9588e053facfdb8299181fe15a8ad2a223`. Its complete 521-file
inventory is `compatibility/nom_dev_77ba9c7_source_v1.json`, SHA-256
`bcc25ea431a467dd4381b47132ae96491bf382f5bbd6e823215b087e6c13de6c`. The separately retained source archive has
2,065,721 bytes and SHA-256 `e2ab3ce231adc571f60bb6fc1ef680acd1138819cbf14ef1ea5eec60ff322b80`.

Acquisition checked every regular file against both its Git blob identity and
SHA-256, then recomputed the complete Git tree. It used one bounded archive
stream and no extraction or materialized source copy. These content checks
provide no independent producer attestation, compiler authentication or native
execution result. The upstream GPL version 3 source remains separately obtained;
this repository does not vendor or relicense it.

The baseline is
[`661b5ef404487cd41685654bf87530f10adebbe4`](https://github.com/zenon-network/go-zenon/tree/661b5ef404487cd41685654bf87530f10adebbe4),
tree `78937597e8e0e5835a8856cb44d592e349451d9f`. The new subject is 13 commits
ahead with 12 changed files, three added files, 506 byte-identical files and no
removed file. All 18 paths containing `ptlc` are byte-identical, as are `LICENSE`,
`go.mod` and `go.sum`. File equality is insufficient to qualify behavior through
changed VM entry points.

## Changes relevant to the next qualification

| Merged change | Relevant surface | Consequence for this workspace |
| --- | --- | --- |
| [PR 233](https://github.com/zenon-network/go-zenon/pull/233), merge `3e0f13e65373423d9a9db912d30eb9d6283dbbb6` | Bridge/liquidity guardian nomination, majority arithmetic and VM checks | Recheck the changed shared entry paths; unchanged PTLC files do not establish entry-path compatibility. |
| [PR 234](https://github.com/zenon-network/go-zenon/pull/234), merge `514beda348b8fadc47f5cfd791d162c5d861261d` | Dynamic Plasma gated reward epoch bounds | Include the new boundary tests and preserve the selected spork context in runtime evidence. |
| [PR 235](https://github.com/zenon-network/go-zenon/pull/235), merge `77ba9c7ee8c881e90911946756cdb67d8b586043` | Bridge RPC embedded marshal pointer initialization | Exercise the added JSON regression; it is separate from PTLC witness or account authorization. |

The added upstream files are
`rpc/api/embedded/bridge_unmarshal_test.go`,
`vm/embedded/implementation/epoch_reward_bound_test.go` and
`vm/embedded/implementation/guardian_majority_test.go`. Their presence does not
establish that any test has run in this workspace.

## Required next evidence

The new source reader checks inventory, changed paths and complete source bytes.
Its small synthetic refusal controls establish parser behavior only. It runs no
Go process and selects no operational adapter. The existing native results for
661b5ef retain that exact source scope; none is relabeled as a result for 77ba9c7.

Fresh current-source native comparison remains **UNFILLED**. That comparison
must cover the existing 31 selected profiles and the newly changed upstream
boundaries. The separate 14-case
[fee-original corpus](NOM_FEE_ORIGINAL_BOUNDARY.md) must preserve the two exact
signed originals and its six fee, four hash and four signature refusals. It may
not repair a refusal by replacing an original, creating a signature or choosing
a different transaction.

Qualification should use one newly admitted compiler workspace and sequential
owned source stages. Retain the original 31-profile result before adding the
fee producer, then run the separate component with count-one tests and default
vet in the same owned compiler cache. Each stage needs its own exact source
snapshot, complete original streams and honest exit/completeness evidence.
Historical closed caches are not adopted, test results are not cached, and a
failed stage is not retried or rewritten as a success. This is the next
implementation requirement, not a claim that the shared-cache extension exists.

Source-bound local regression, privacy checks, hosted PR qualification, normal
main integration and main-push qualification remain separate gates. Source
equality does not fill protocol, custody, chain currentness, AS-1 through AS-7 or
independent review requirements.
