# One-workspace native comparison for the pinned 5cb corpus

This construction selects go-zenon
[`5cb5aac3bb21d012111d87466f946cbdccd344f6`](https://github.com/zenon-network/go-zenon/tree/5cb5aac3bb21d012111d87466f946cbdccd344f6)
and the existing [finite corpus](NOM_DEV_5CB.md). It adds an execution and
retention path for the twenty planned profiles. This document asserts no local
or hosted execution result.

The preparation command verifies the complete original archive before creating
one new source directory. All 482 upstream files and twenty selected project
producers are checked by content, producing one 502-file view. The source and
compiler executable digests are checked before and after native execution.
Original upstream licensing and all historical source subjects remain intact.

The native command uses one new compiler workspace for all profiles. An initial
cold compilation installs every selected producer in the same view; subsequent
profile commands can reuse those compiled packages. Every test command retains
normal default vet and `-count=1`. No verification result is cached between
attempts. Module, build, temporary and home directories belong to this attempt.

The existing CI job already acquires the pinned Go 1.23.12 installation and
verifies its full module graph. The selected `go.mod` and `go.sum` byte pins
match that input exactly. The new steps can therefore use the same toolchain
and a read-only file proxy from that job, while using a new native compiler
cache. No additional toolchain installation or module acquisition is selected.
The earlier job steps remain present, with a larger finite job deadline.

## Execution and custody

Replace the placeholders below with absolute physical paths in approved owned
storage. Keep those private paths out of repository content and reports.
Acquire and retain the immutable source archive, compiler and verified module
input separately. Configure quotas and reserve expected allocations before
starting. The production free-space floor remains 10 GiB; this construction
requires a further 2 GiB reservation at admission and claims no operating-system
filesystem quota or hostile-process sandbox.

```text
python3 -B scripts/prepare_nom_5cb.py --archive ORIGINAL_ARCHIVE --destination NEW_SOURCE
python3 -B scripts/qualify_nom_5cb_native.py --source NEW_SOURCE --workspace EMPTY_OWNED_WORKSPACE --go VERIFIED_GO --expect-go-sha256 SELECTED_GO_SHA256 --offline-proxy READ_ONLY_PROXY --cc SELECTED_C_COMPILER
python3 -B scripts/check_nom_5cb_evidence.py --workspace OWNED_WORKSPACE
```

On macOS, a compiler that needs an explicit SDK can additionally select
`--sdk-root SELECTED_PHYSICAL_SDK`. This sets only the selected `SDKROOT` value;
no SDK path is inherited from the parent environment or exported in the report.
The SDK must be an existing physical directory outside both the source and
writable workspace. The report records the selection with an unauthenticated
content marker. SDK contents and the transitive toolchain remain outside the
measured executable digests and do not fill source/build authentication.

Twenty profile commands must yield forty complete original streams and all 479
selected parent/subtest outcomes. Compiler version, cold compilation, the
upstream definition-package check and module verification are four additional
commands. They do not replace or increase the twenty-profile count. The caller
must bind this attempt to its exact source, platform, actual exits and complete
capture receipts.

VM and authorization handoffs come from the actual earlier streams of this
attempt. Parser-control fixtures never substitute for those streams. The
source/value readers remain separate from command-exit and custody evidence.

The transport retains bounded stdout and stderr, actual exits, completeness and
private process-group receipts. A timeout, nonzero exit, stream limit or
uncertain cleanup refuses success and does not launch a replacement. Retain all
originals before retiring a new regenerable cache. Unknown processes, aliases,
ownership or incomplete output remain held for separate reconciliation.

## Explicit sharing selection

The retention checker reads the original files without replacing them. It
inspects escaped JSON representations as well as raw text. Unknown metadata
fields, unselected filenames, private paths, host identifiers and disclosure
patterns block export. Private argv/process receipts, generated handoff paths
and compiler caches are excluded from the public selection.

`--artifact-files` explicitly creates one new retention manifest and emits only
the checked relative original filenames plus that manifest. It does not create
a recursive workspace archive or another copy of stdout. Incomplete selection
requires `--allow-incomplete-for-retention`; missing streams and missing receipts
remain unknown, with no manufactured empty output, exit or executed arguments.

Sensitive or unverified output must not be uploaded. A missing artifact or a
failed upload leaves hosted acceptance unfilled. A selection manifest, reported
total or zero exit does not substitute for the original hosted evidence.

Complete local module/regression checks, a combined native attempt and fresh
hosted qualification are separate gates. A prior local component run, synthetic
reader control, source inspection or merged research PR cannot fill them.
Independent assessment and AS1-AS7 remain unfilled. No application signer,
wallet, node activation, transaction broadcast or funded operation is selected.
Application/core remain **NO-GO**; recovery authority remains **NONE**.
