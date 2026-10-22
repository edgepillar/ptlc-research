# Finite 5cb source and original-byte comparisons

This additive corpus selects go-zenon
[`5cb5aac3bb21d012111d87466f946cbdccd344f6`](https://github.com/zenon-network/go-zenon/tree/5cb5aac3bb21d012111d87466f946cbdccd344f6)
and Git tree `08c40433726d40dd84116bca4811c1a998417498`. The complete
[inventory](../compatibility/nom_dev_5cb_source_v1.json) binds 482 upstream
files by size, SHA-256, Git blob and mode. Its SHA-256 is
`8e038bcf5ad3f9c668f6b887b2c88cc2a6a05339a0262c0c37871f620de8dd4f`.
The pinned source, rather than a moving branch name, defines this subject.

The upstream GPL-3.0 source remains a separate acquired input. The project adds
MIT-licensed research producers; it copies no node implementation into this
repository. The selected `LICENSE`, `go.mod` and `go.sum` match the earlier
`5e65a0b` source. Earlier inventories, producers, fixtures and source subjects
remain unchanged. This selection does not upgrade the recovery journal source.

## Explicit source differences

The [producer variants](../compatibility/nom_dev_5cb_variants_v1.json) bind seven
selected producers to their exact historical parents. Each inverse edit must
restore its parent byte for byte. Other selected producers remain unchanged.

| Selected comparison | Explicit change from its historical producer/value subject |
| --- | --- |
| Account context, pool dependencies, momentum admission | Read the new sequencer size/error pair; fail on an error. |
| VM receipt verifier | Supply the selected chain identifier through the memory ledger; expect receiver mismatch in both prior pre-enforcement helper cases. |
| Account context values | Four wrong-recipient observations now require `ErrABFromBlockReceiverMismatch`; the declared chain remains 69. |
| Receive data and ABI boundary | Select the new source label; all finite values remain unchanged. |
| Direct send caller | Select the new source and add one dynamic-plasma query to twelve declared paths that reach balance access. |

The selected receiver exception applies to chain identifier 1; the synthetic
chain-69 cases must not borrow that exception. Structural refusal and missing
transaction signatures remain separate results. The extra query observations
do not establish real pricing, complete dispatch coverage or account admission.
These finite comparisons do not cover every change in the upstream commit.

## Selected profiles

The [selection manifest](../compatibility/nom_dev_5cb_manifest.json) pins the
public readers, producers, fixtures, tests and frozen reader dependencies.

| Family | Finite selection |
| --- | --- |
| Sixteen component profiles | 342 stateful parent/subtest outcomes, 45 wire outcomes and the separate PR #138 parent |
| Receive data | 14 cases, 15 outcomes including the parent |
| ABI boundary | 26 cases, 27 outcomes including the parent |
| Direct send caller | 23 cases, 24 outcomes including the parent |
| Keyless Supervisor | 24 cases, 25 outcomes including the parent |

The sixteen component names and scopes are preserved from the earlier
[admission corpus](NOM_CURRENT_ADMISSION.md#selected-cases-and-value-origins).
Twenty selected test commands cover 479 parent/subtest outcomes in total.
Compilation and a separate upstream definition-package check are additional
checks, not replacements for any selected profile.

## Supervisor comparison with existing originals

The [declared input](../compatibility/fixtures/nom_dev_5cb_keyless_inputs_v1.json)
selects the two existing public synthetic Unlock-send originals and their exact
memory checkpoints. The new producer calls the real selected Supervisor and
transaction verifier without generating a key or signature. It observes the
canonical original, a repeated protobuf version field before decoding, a
trailing ABI byte, a changed witness byte, an absent outer signature and a
corrupted outer signature. Both legs run with the declared dynamic-plasma flag
off and on. Comparison copies never replace the immutable originals.

The [independent byte reader](../qualification/nom_keyless_supervisor.py)
computes outer protobuf replacements, original/entry/post-call hashes,
signature preservation, returned wire, verifier trace and packed state delta.
It compares those values with the retained output. The
[critical-value fixture](../compatibility/fixtures/nom_dev_5cb_keyless_values_v1.json)
is a declaration of expectations, not an execution record.

The finite result has ten passes, two trailing-data refusals, four hash
refusals, four missing-signature refusals and four invalid-signature refusals.
With the declared flag off, the selected trailing-byte input normalizes back
to the original signed wire; with it on, the Supervisor refuses that input.
Raw protobuf input, decoded entry and post-call bytes remain distinct.
Spork-read order is retained observation only; its exact order is not qualified.

The frozen `private-nom-...` schema identifiers are retained for byte compatibility
with the executed producer. These public fixtures contain synthetic data only.
They contain no private acquisition IDs, keys or environment diagnostics.

A UserSend Supervisor result does not prove PTLC receive execution, point-lock
or witness validity, pool admission, chain insertion or confirmation before
timeout. The new probe calls no application signer, generation-from-template
path, pool admission, journal transition or broadcast operation.

## Reproduction with owned offline storage

Acquire the exact source and a measured Go 1.23.12 separately. Verify the whole
inventory, tree and license. Use approved owned task storage with declared
resource limits, one source view and one compiler/module/temp workspace per
attempt. Select a separately verified read-only offline module proxy. Retain
the measured compiler/platform/environment pins privately. Keep read-only
modules, `GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`, `GOSUMDB=off`,
`GOVCS=*:off`, disabled telemetry and normal default vet. Do not publish raw
environment or command diagnostics.

`python3 -B -m qualification.nom_dev_5cb_reproduction` emits a read-only plan.
It performs no acquisition, file creation, native execution or signing. Its
`plan(root, profile)` returns every selected package, anchored parent, exact
arguments, outcome count and producer destination. Install the selected
`.go.txt` bytes as physical `.go` files at those destinations, without replacing
an upstream file. The `all` view has 482+20 files; `components` has 482+19;
`keyless` has 482+2, including the unchanged Supervisor memory-view helper.

For each planned unit, `input_bindings(unit, prior, root)` returns environment
bindings as relative repository files/directories or generated JSON values.
Materialize generated values only through the caller's approved manager.
The caller resolves each binding to its retained input path and supplies only
the selected environment. No embedded private storage path is required.

Execute in plan order. Preserve the complete original stdout and stderr of
each command as `UNIT.stdout` and `UNIT.stderr`, along with actual exit and
capture-completeness receipts. Supply the actual `vm-path.stdout` for the VM
verifier and authorization handoffs; supply that stream plus actual
`account-authorization.stdout` for account context. These handoffs use the
selected four changed context expectations. Missing or foreign handoffs refuse;
the parser-control VM fixture must never replace an execution stream. An
optional cold compile can select `-run '^$'` across the four selected packages.
It does not count as a test profile.

After source verification before and after execution, compare the original
streams with the read-only CLI:

```text
python3 -B -m qualification.nom_dev_5cb --source OWNED_SOURCE --streams ORIGINAL_STREAMS --profile all
```

The stream directory must contain exactly forty selected files for `all`,
thirty-eight for `components`, or two for `keyless`. No missing stderr,
cross-profile substitution, extra stream, source alias, hard link or unselected
file may satisfy the complete comparison. The reader does not authenticate
the compiler, command exit, native execution origin or stream custody. Those
remain separate evidence requirements. Synthetic test events can pass value
readers and must never be described as native execution.

## Retained local execution and remaining gates

The local author qualification used Go 1.23.12 on darwin/arm64 with physically
installed producers and normal default vet. All sixteen selected component
profiles, all three auxiliary families and the separate 24-case Supervisor
probe passed. Original exits, complete streams and the selected source remain
retained separately from this declaration and from hosted CI.

An earlier VM-verifier attempt panicked because its memory ledger did not
implement the newly exercised chain-identifier read. That failed attempt remains
failed. Three successful profiles from that same source were retained, with
no credit for the partial failing profile. The corrected producer then passed;
unchanged successful native profiles were not rerun merely for publication.
Public selected Go bytes equal the executed producers. A private unused
acquisition field was removed from the public input; all Go-consumed fields
remain equal. No native rerun is implied by public reader reconciliation.

The remaining requirements include independent protocol/recovery assessment,
authenticated source/build/chain observation, complete combined admission,
timeout/inclusion evidence and an independently reviewed journal transition
binding. AS1-AS7 remain unfilled. Local tests, synthetic framing controls,
hosted CI and a merged research PR cannot discharge these requirements.
Application/core remain **NO-GO**.
