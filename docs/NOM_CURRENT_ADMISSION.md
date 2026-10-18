# Selected current-source account, pool and momentum components

This is an offline component comparison. Application/core remain **NO-GO**,
combined admission remains **UNFILLED**, and independent assessment remains
**UNFILLED**. A source-content match, passing source tests or matching public
reference values supplies no recovery authorization.

## Requirement and selected source

The [price and custody HOLD model](NOM_PRICE_RECOVERY_HOLD.md) preserves an
already signed original when its allowance or custody is insufficient. The
next obligation is to replay the separately selected account/VM, pool and
momentum subjects on an explicit source. This comparison selects
[go-zenon 85c3979](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe),
tree `cdeb5b6276c13447197c829c5855faa72afd86b9`, with 444 upstream files.

The complete [source inventory](../compatibility/nom_current_admission_source_v1.json)
has SHA-256 `6168b36ee6487272bf128862f141093db4d47c411a5d551fb132de5d9ab8890a`.
It retains Git blob, byte-count, SHA-256 and selected Git-mode metadata. The
native source archive has SHA-256
`54336f7c1f75f84d0f513d3b22da135bebf62d8da84b776e961b0c3f52f8e1c9`
and 1,705,302 bytes. Source is acquired separately under GPL-3.0; no node
implementation is copied into this MIT workspace. The existing, independently
written public synthetic project producers remain unchanged.

Relative to the preserved C25 source, three files are added and fourteen change.
Those changes include account serialization, address decoding, Plasma RPC and
principal handling, and tests. Pool, momentum, `go.mod` and `go.sum` contents
remain identical to that source. This content comparison is not a dependency
closure, loaded-runtime, source-producer or canonical-chain attestation.

The [selection](../compatibility/nom_current_admission_manifest.json) binds the
new source and reader separately. The original 133 producer/fixture inputs
retain their [C25 selection](NOM_DEV_REBASE_COMPARISON.md). No old source
manifest, prior result, journal or independently reviewed subject is repinned.

## Selected cases and value origins

| Selected component | Test/subtest outcomes, including parents |
| --- | ---: |
| VM path and separate receipt verifier | 58 |
| Account authorization | 127 |
| Account context | 85 |
| Bilateral graph and supervisor/Plasma | 8 |
| Account pool, forks and dependent eviction | 13 |
| Momentum admission, batched rollback, content cap, multi-rollback and refusal | 51 |
| Total selected stateful outcomes | 342 |

The separate wire/ABI/hash selection has 45 outcomes, including its parent.
The PR #138 corpus has one selected Go parent test covering its existing 48
messages, 26 witnesses, 15 destination cases and two completions. Vector counts
and Go parent/subtest counts describe different things and must not be added
together as independent results.

Most values retain their historical public fixture expectations. The account
pool and dependency pair instead compares against the explicit C25 value
oracle: four removed-child aliases become absent and seven surviving prefix
views retain their admitted original patch. These are the same 23 selected
field changes described by that earlier comparison. The old historical
projections still refuse them. The new source identity belongs to this subject;
the C25 oracle's source selection remains unchanged.

The [VM reference fixture](../compatibility/fixtures/nom_current_admission_vm_reference_v1.json)
contains only public synthetic record values for parser controls. It contains
no acquired console or environment log. It is not an original execution stream,
authenticated source patch, independently observed state or durable custody.

## Reader boundary

The [reader](../qualification/nom_current_admission.py) requires all sixteen
selected stdout streams and their sixteen separate stderr streams. It verifies
the exact selected package and test identities, one successful package terminal,
no missing or duplicate outcomes, event types and selected record framing.
The existing source-value comparators retain their VM/account handoffs and
pool/momentum checks. Account context must bind the supplied VM receipt patches;
the reader does not replace a missing handoff with its reference fixture.

Inputs are bounded at 16 MiB per stdout, 2 MiB per stderr and 64 MiB in total.
Duplicate JSON keys, nonfinite values, extra stream names and missing streams
refuse. Physical paths, bounded regular files and single file links are required.
Source comparison requires exactly the 444 unchanged upstream files plus the
sixteen selected project producer files, with exact content and Git blob checks.
Filesystem executable-mode equality is not asserted. Root Git metadata is not
part of that clean source view.

The reader starts no compiler, subprocess, network request, signer or journal.
A manufactured transcript can satisfy finite value and pass-label checks. The
result therefore leaves execution origin and actual command exits unestablished.
Stderr is fingerprinted diagnostic data; an empty stream is not a zero exit.
Actual controlled execution and complete original streams must be retained and
bound separately. A matching source view does not prove that it produced them.

For explicitly owned originals and a clean selected source view:

```text
python3 -B -m qualification.nom_current_admission \
  --source OWNED_CURRENT_SOURCE_WITH_PRODUCERS \
  --streams OWNED_ORIGINAL_STREAM_DIRECTORY
```

Every stream filename is a selected unit below followed by `.stdout` or
`.stderr`; the directory must contain exactly those 32 files.

| Unit | Package | Selected Go test |
| --- | --- | --- |
| pr138-corpus | vm/embedded/implementation | TestResearchPR138CompatibilityCorpus |
| wire-corpus | vm/embedded/implementation | TestResearchNoMWireCorpus |
| vm-path | vm | TestResearchNoMVMPath |
| vm-verifier | verifier | TestResearchNoMVMReceiptVerifier |
| account-authorization | verifier | TestResearchNoMAccountAuthorization |
| account-context | verifier | TestResearchNoMAccountContext |
| bilateral-graph | vm | TestResearchNoMBilateralGraph |
| supervisor-plasma | vm | TestResearchNoMSupervisorPlasma |
| account-pool | vm | TestResearchNoMAccountPool |
| pool-forks | vm | TestResearchNoMPoolForks |
| pool-dependencies | vm | TestResearchNoMPoolDependencies |
| momentum-admission | vm | TestResearchNoMMomentumAdmission |
| batched-rollback | vm | TestResearchNoMBatchedRollback |
| content-cap | vm | TestResearchNoMContentCap |
| multi-rollback | vm | TestResearchNoMMultiRollback |
| rollback-refusal | vm | TestResearchNoMRollbackRefusal |

## Independent reproduction and retained local scope

Acquire the exact upstream source and a measured Go 1.23.12 in owned task
storage. Verify the archive, complete inventory and GPL-3.0 license. Install
each unchanged project producer once at the destination returned by
`qualification.nom_current_admission.probes`; no upstream file may be replaced.
Use a fresh owned compiler/module/temp workspace, a separately verified
read-only offline module proxy, read-only modules and normal default vet.

Each table entry uses this command, selecting only its named parent and children:

```text
GO_EXECUTABLE test -json -mod=readonly -count=1 -run '^SELECTED_TEST$' ./SELECTED_PACKAGE
```

The VM fixture/funding/completion inputs and record collectors are in
`scripts.qualify_nom_vm_path`. Its **actual** long/short direct-success records
form the verifier baseline. `scripts.qualify_nom_account_authorization` supplies
the authorization plan; its actual records and the actual VM receipt patches
form the account-context handoff and plan. The bilateral/supervisor producers
select their unchanged public input and completion fixtures. The pool producer
selects the supervisor fixture. The batched, cap, multi and refusal input
payloads come from their respective `selected_inputs` helpers. Retain those
exact handoffs; the parser-control VM reference fixture cannot replace them as
execution evidence. The existing producer sources and qualifiers define the
individual schemas and environment-variable names. Their historical `qualify`
entry points still select their old sources; they are not current-source launchers.

The separately retained local author replay executed these selections with
normal default vet: 342 selected stateful outcomes, the separate 45 wire
outcomes and the PR #138 parent. All selected original values matched, with the
explicit C25 pool pair above. It retained 444 upstream files and sixteen project
producers unchanged before and after execution, and complete actual command
exits and original streams. This is local author evidence. The regular Python
tests use synthetic framing controls and do not execute that native replay.
Fresh reader qualification, complete regression, artifact checks and separate
hosted acceptance remain their own requirements. Existing hosted native source
profiles keep their original pins; green hosted CI is not this new native result.

One new owned source view and compiler workspace served the selected processes.
No source download, historical cleanup or second copy of an original CI archive
was required. Only that task's new reproducible compiler output was removed
after original streams, input pins and process completion were retained.
No physical disk reclaim or cross-machine timing improvement is asserted.

## Remaining obligations

These selected components are not complete account, pool, momentum or inclusion
coverage. Their separate passes do not compose a complete admission or recovery
proof. The price HOLD obligation still needs assessment alongside account order,
unavailable originals, disclosure timing, timeout margins, reorg/finality and
availability. A later favorable component result cannot authorize signing,
retrying, replenishing UNKNOWN work, releasing an original or broadcasting.

Written external assessment and [AS-1 through AS-7](NOM_ANCHOR_SERVICE_ACCEPTANCE.md)
remain unfilled. Deployment, node activation, wallet access, application signing,
transaction broadcast and real funds remain outside this offline workspace.
