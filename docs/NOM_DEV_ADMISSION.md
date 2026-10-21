# Separately selected dev admission components

Application/core remain **NO-GO**, combined admission remains **UNFILLED**, and
independent assessment remains **UNFILLED**. This additive corpus checks selected
offline components. It does not upgrade a recovery journal or authorize an action.

## Immutable source and preserved earlier subjects

The selected source is
[go-zenon 5e65a0b](https://github.com/zenon-network/go-zenon/tree/5e65a0bdb83700aa1d15b17456a17352b7d04ea9),
tree `3668425af59cfe9b88d8b8818b4467ce3f527d73`, with 474 files.
The [complete inventory](../compatibility/nom_dev_admission_source_v1.json) has
SHA-256 `2f031704a76b772f66736dadd5d9a7c0d5e3e2e07d97a2b2364cf072fe63b298`.
The separately retained source archive has SHA-256
`3db43d54bf05cf7f02d7a4cb26dcb5310575a09ee320cb8e996e17f9d0676407`
and 1,926,371 bytes. The GPL-3.0 node source is acquired separately; this MIT
workspace adds source metadata and independently written test producers.

Relative to the [earlier 444-file subject](NOM_CURRENT_ADMISSION.md), 232 files
retain exact contents, 212 change and 30 are added. The tree comparison is
complete. The comparison reports 128 commits ahead, but a bounded 100-entry
commit page does not constitute an individual review of all those commits.
`go.mod`, `go.sum` and the license remain identical to the earlier selection.
Message construction and hash code also retain their parsed Go structure outside
comments and positions; this static observation is not a semantic or security proof.

[Upstream PR #152](https://github.com/zenon-network/go-zenon/pull/152) is merged
and its public message/hash tests are present in this source. Those tests were
already present in the earlier subject; the new dev delta is substantially wider
than that contribution. Merge status supplies no hosted execution or independent
protocol assessment.

The old source inventories, producers, fixtures and review subjects remain
unchanged. The [new selection](../compatibility/nom_dev_admission_manifest.json)
binds a new source and reader rather than repinning a historical result.

## Three explicit producer API variants

The selected source returns an error from `SequencerFront` and
`SequencerByHeight`. Three separate producer files adapt that return arity:

| Earlier producer | Separate dev producer | Adaptation |
| --- | --- | --- |
| nom_account_context_test.go.txt | nom_dev_account_context_test.go.txt | Read the mailbox header and fail on any error. |
| nom_bilateral_graph_test.go.txt | nom_dev_bilateral_graph_test.go.txt | Read the sequence head and fail on any error. |
| nom_supervisor_plasma_test.go.txt | nom_dev_supervisor_plasma_test.go.txt | Read the sequence head and fail on any error. |

The reader verifies that each variant contains exactly this small substitution
and its error guard. No expected value, existing assertion, fixture, runtime
algorithm or earlier producer changes. The other thirteen producers are selected
unchanged. An old producer cannot fill one of the three new source slots.

## Selected native comparison and its limits

The retained author replay used Go 1.23.12 on macOS with a read-only offline
module proxy and one owned compiler workspace. All sixteen producers compiled
together before the selected scenarios. Its original complete streams passed
all sixteen finite component profiles: 342 stateful parent/subtest outcomes,
45 separate wire outcomes and the PR #138 parent covering its existing vectors.
The earlier explicit C25 pool-value oracle remains unchanged. These component
passes are not a composition proof, exhaustive dev regression or live admission.

The upstream message/hash parent and eleven children passed with normal default
vet. The complete definition package also passed twenty outcomes, including
those same twelve; the counts overlap. The project overlay profiles used their
declared `-vet=off` mode because synthetic overlay destinations are not physical
test source files. They are not a normal-vet claim.

The first native attempt failed to compile account context because the original
producer still expected one `SequencerByHeight` return value. Its failed task,
complete exit-1 output and earlier passing components remain preserved as a
separate failed attempt. The subsequent complete attempt uses the third explicit
API variant and the early full-producer compile. No original failed outcome was
reclassified, and no earlier fixture was substituted for a failed execution.

This local execution is separate from synthetic Python controls, hosted CI,
dependency closure, source/build authentication and independent assessment.
Existing hosted native jobs retain their earlier source pins. Their passing
results must not be described as a hosted replay of this dev selection.

## Read-only reproduction boundary

The [reader](../qualification/nom_dev_admission.py) requires exactly 474 upstream
files plus the sixteen selected producers, for 490 files in a clean source view.
It checks bounded regular files, content digests, Git blobs and the complete
inventory tree. Filesystem executable-mode equality and producer authentication
are not established. Source is acquired by the caller; the reader downloads and
executes nothing.

The [same sixteen profile names](NOM_CURRENT_ADMISSION.md#selected-cases-and-value-origins)
provide sixteen stdout files and sixteen separate stderr files. Bounds, selected
test identities, handoffs and complete-value comparisons retain the earlier
reader's rules. Missing streams, changed records, extra outcomes, source aliases
and an ignored sequencer error refuse. A manufactured stream can match these
finite values: this reader cannot establish actual exits or execution origin.

```text
python3 -B -m qualification.nom_dev_admission \
  --source OWNED_PINNED_SOURCE_WITH_SELECTED_PRODUCERS \
  --streams OWNED_ORIGINAL_STREAM_DIRECTORY
```

For independent execution, use the existing component launch and handoff recipe
in [the earlier subject](NOM_CURRENT_ADMISSION.md#independent-reproduction-and-retained-local-scope)
with this exact source and the destinations from
`qualification.nom_dev_admission.probes`. Select the three explicit variants
instead of modifying earlier files. Retain actual commands, all separate streams,
the measured compiler and exact inputs; parser-control fixtures cannot replace
native handoffs. Normal default vet is available when producers are installed as
physical files in a separately owned clean source view.

## Next obligations

Review the additional ABI and account-verifier behavior on this immutable source,
including trailing data, receive data and Dynamic Plasma activation boundaries.
Passing the finite selected components does not qualify every new dev behavior.
Original custody, inclusion/timeout guarantees, reorg/finality, source authority
and the independent construction/runtime reviews remain separate requirements.
The signed-original journal context is not upgraded by this corpus.

External assessment and [AS-1 through AS-7](NOM_ANCHOR_SERVICE_ACCEPTANCE.md)
remain unfilled. No wallet, application signer, broadcast, node activation,
deployment or real funds are connected.
