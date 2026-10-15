# Selected NoM anchor transition retention experiment

Baseline:
[`4105577f0b5d87b44ae9c00f4cb332d1fecd0dc4`](https://github.com/edgepillar/ptlc-research/tree/4105577f0b5d87b44ae9c00f4cb332d1fecd0dc4).
The [finite anchor lifecycle](NOM_ANCHOR_LIFECYCLE.md) remains unchanged. This
additive POSIX experiment retains exactly one selected reference transition and
its caller-declared lost-acknowledgment hold. It is local reference retention,
not the independent anchor service required by the protocol. Application/core
remain **NO-GO**, publication **UNKNOWN**, recovery **NONE**.

## Required boundary

Explicit local file creation must remain separate from opening an existing
record. Missing files, outage, interrupted creation and a selected empty directory
establish no global absence, unique enrollment, fresh allowance or absence of an
earlier tombstone. A local fsync acknowledgment establishes neither service
publication nor durable current independent authority. These obligations remain
external even when complete bytes reopen successfully.

An operational service still needs independently provisioned identity/epoch,
authenticated current lookup, nonrollback retention, shared atomic transitions,
original-operation entry and independent assessment. Actual custody must survive
independently of public descriptors. Physical power loss and hostile host/runtime
behavior require separate qualification. This experiment selects no such service.

## Selected finite construction

`AnchorTransitionJournal.create` exclusively creates one file with `O_EXCL`.
`open_existing` opens only an existing file; it has no create, repair, truncate,
replacement or write-retry path. Both require the complete actual preceding
`ReferenceAnchorState` and actual `AnchorAcknowledgmentHold`, including the exact
original request, actual ordered trace and earlier contexts. Dictionaries,
digests and public bytes cannot reconstruct missing actual custody.

The first canonical record retains the complete public before-state descriptor,
request and held acknowledgment. A second optional record retains the one fixed
functional reference transition. Each record binds its position, preceding record
digest and payload under a distinct SHA-256 domain. The selected limits are two
records, 96 KiB per record and 192 KiB per file. The only valid complete images
are the exact first record or the exact first plus second record rebuilt from
the supplied actual custody. No permissive descriptor parser, history trimming,
silent repair or partial-tail removal exists.

`commit_retained_reference` appends the fixed second record once. Duplicate calls
refuse. It performs no original operation, worker, signer, network dispatch or
service CAS. A retirement transition retains its terminal tombstone and every
earlier transition in the supplied actual reference. The finite file cannot
advance again, rotate identity, change epoch or enroll another request.

One cooperating owner holds a nonblocking lifetime `flock`. The selected parent
directory must be owned and mode 0700; the file must be regular, owned, mode 0600,
single-linked and match the selected directory entry. Every operation checks the
complete retained image, process/thread ownership and fresh actual input bindings.
An inherited owner cannot write. Closing a fork-inherited descriptor does not
explicitly unlock its parent's file. The complete parent pathname, host, filesystem
and selected fsync implementation are trusted; this is no adversarial path sandbox.

## Interrupted writes and lost acknowledgments

Each selected local acknowledgment follows complete file write and file fsync.
Creation also fsyncs the selected parent directory. Any write-phase exception
poisons the owner and reports an unknown local outcome. The handle cannot retry
or return a cached positive result. Interrupted and malformed bytes remain intact.

After process death, `open_existing` accepts only an exact complete selected image
and fsyncs the file and directory before returning. A complete image may have
survived before the old fsync or acknowledgment; successful reopen establishes
only the newly selected local synchronization. Partial or unexpected images
refuse without repair. Opening a missing file never creates a replacement.

`inspect` compares the original held request with the retained functional
reference. Before the second record it reports reference request not found;
afterward it reports an exact retained reference request. Both preserve all
effective UNKNOWN work. Neither observation grants new work, automatic retry,
same-request republication, replacement, replenishment, bootstrap or reenrollment.
Inspection never appends the missing second record. It is no current service
lookup, operational acknowledgment or authorized recovery.

## Deliberately unfilled guarantees

A coherent old file plus matching old actual inputs can reopen. Two copies at
different paths can independently append the fixed transition. Restoring an
earlier complete image can hide a later retirement record. Explicit creation in
another directory can select the old request again. These successful unsafe
controls expose missing independent enrollment and nonrollback authority; local
locks and hash commitments supply neither. No operational work is permitted.

Directed process-death cuts establish only selected process-restart behavior on
the tested host. They are not hardware power-loss, crash-consistent filesystem,
distributed service or independent-machine evidence. See the separate
[validation scope](NOM_ANCHOR_TRANSITION_JOURNAL_VALIDATION.md).
