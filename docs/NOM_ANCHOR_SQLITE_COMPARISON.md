# Finite NoM anchor SQLite comparison

Research baseline:
[`981a11dec4075ceb9096e4f75e74708daf971601`](https://github.com/edgepillar/ptlc-research/tree/981a11dec4075ceb9096e4f75e74708daf971601).
The [service candidate](NOM_ANCHOR_SERVICE_CANDIDATE.md) proposes a trusted
administrative ledger. This increment prepares one offline storage comparison
with the unchanged functional reference. Its current execution disposition is
[NOT_RUN](NOM_ANCHOR_SQLITE_COMPARISON_VALIDATION.md). Source preparation and
golden values do not qualify the changed implementation.

There is no service, network listener, authentication role, application signer,
work-entry adapter, retry mechanism or operational acknowledgment. All seven
[service acceptance gates](NOM_ANCHOR_SERVICE_ACCEPTANCE.md) remain UNFILLED.
Application/core remain NO-GO, publication outcomes UNKNOWN and recovery NONE.

## Selected engine and source preparation

The experiment selects SQLite 3.54.0 from the official
[release description](https://www.sqlite.org/releaselog/3_54_0.html), with
`SQLITE_SOURCE_ID`:

```text
2026-10-09 15:46:58 be8d059e9a49089ab2dce5ed26dd87aaf598fdc5fbe0b107c0dd758464bcd5e3
```

The [source preparer](../scripts/prepare_nom_anchor_sqlite_engine.py) accepts an
explicit offline archive. It performs no download. The selected official
[amalgamation archive](https://www.sqlite.org/2026/sqlite-amalgamation-3540000.zip)
is 2,990,479 bytes, SHA-256
`68e913b0fe8ec6b4e5f391c594a28872884e80d6cd042a1e50c957be46b5aa4d`,
SHA3-256
`7b670a62fdfbd672b75fef004cb703c8a3e87d3a5cc7d675b4a08337004a2d93`.
The preparer verifies the complete fixed archive layout, CRC, four file lengths
and SHA-256 digests before compiling. The amalgamation SHA3-256 is
`8efd453d08a7cfc4c79de5923153036cdc4dcaa254d4f1e617be6a2a98828f9e`,
also published in the release description. Source bytes are not vendored. SQLite
deliverable code is [public domain](https://www.sqlite.org/copyright.html);
that upstream status does not qualify the engine's safety for this application.

Build flags select `-O0`, `-g0`, `THREADSAFE=1`, `OMIT_LOAD_EXTENSION=1`,
`DQS=0` and `MAX_MMAP_SIZE=0`. An explicit C compiler is required. macOS also
selects an explicit SDK. Original compiler/probe streams remain in the newly
owned output, separately from the public engine record. The record pins the
actual binary and compiler executable digests, source ID, compile options,
platform, architecture, flags and actual exits. It is a description of one local
build, not independent compiler or machine attestation. A preexisting output is
never adopted, including after a refused source input.

The separate native runner uses that exact binary instead of Python's installed
SQLite module. Initializers and ambient SQL configuration are disabled. Only
fixed synthetic relative database names enter CLI error output. The profile is
limited to the selected POSIX platforms and a trusted nonforking CLI. It is not
a hostile process sandbox or a portable general database driver.

## Complete reference bytes and finite schema

The [material codec](../qualification/nom_anchor_sqlite_material.py) first
validates actual typed reference anchors and requests. Each stored anchor
contains the complete initial trace, retained events and recursively complete
checkpoint openings, including the policy, source context, role declaration,
capsule, original query and source claim. Each stored request retains its exact
reference request, both complete states and pending UNKNOWN hold. Digests and
revision numbers do not replace these bytes.

Five complete anchors and four requests are freshly generated from the earlier
synthetic corpus. The selected golden lengths/digests precede any native write.
Actual reference custody remains separately available during the comparison.
No byte decoder, database image or evidence manifest can reconstruct missing
actual custody or confer the reference objects' permissions.

The [schema](../qualification/nom_anchor_sqlite_schema.sql) selects one enrollment,
one complete current anchor and an ordered retained request history. A selected
capacity is 1 through 16 transitions. Complete states are bounded at 2 MiB and
requests at 4 MiB. STRICT tables, uniqueness and trigger checks retain the exact
expected before-state, one revision extension, unused nonce and request ID,
terminal retirement and complete retained history. The caller supplies the
already validated functional transition; SQL equality is not an independent
implementation of the reference protocol or cryptographic verification.

Every ordinary connection sets and checks DELETE journal mode, EXTRA
synchronization, zero busy timeout, foreign keys, disabled trusted schema,
in-memory temporary storage, 4096-byte pages and an 8192-page limit. The limit is
selected on each connection; the profile explicitly probes a differently opened
connection instead of assuming the setting persists. A deliberately wrong
synchronization configuration must refuse before a transition. A selected page
capacity failure retains its original error and pre-reopen image.

Only explicit synthetic creation initializes an enrollment. Existing-file opens
use `mode=rw` or `mode=ro` and never create a missing database. No migration,
compaction, deletion of charges, automatic enrollment, failover or backup
promotion is implemented.

## Selected comparisons and retained failures

The [qualifier](../scripts/qualify_nom_anchor_sqlite.py) selects 22 comparisons,
53 supervised captures and 54 actual CLI invocations; the contention capture
contains a second native invocation. These are intended execution requirements,
not current PASS evidence.

| Selected boundary | Required retained observation |
| --- | --- |
| Complete expected-state transition | Exact complete before/after bytes, with earlier history unchanged. |
| Stale head, conflicting equal ID, reused nonce or trimming | Original native refusal and unchanged selected current head. |
| Missing existing database | Original refusal without a new file or bootstrap. |
| Two processes, one selected database | First process holds the write transaction; the second refuses under zero busy timeout. No automatic retry. |
| Capacity or deliberately wrong connection settings | Original refusal, preserved request and local before-state observation. |
| Selected death before/after commit | Actual SIGKILL exit, complete original streams and original database/journal images before engine reopen. |
| Exact request lookup and later committed state | An observation at its selected position; no currentness at delivery or original-operation settlement. |
| Terminal retirement | All retained requests remain; later transition refuses without resetting the enrollment. |
| Coherent old restore, independent writable copies, explicit research reenrollment and hidden retirement | Four successful unsafe controls; local SQL transactions supply no external nonrollback authority. |

An engine exit of 1 with a selected message is retained as that actual CLI exit.
The CLI does not capture a numeric SQLite error code. FULL/BUSY descriptions are
classifications from the selected messages and experiment, never an invented
numeric engine status. A successful wrapper capture is distinct from a successful
database operation. Selected death, capture truncation, timeouts and uncertain
reaping remain separate from expected native refusals.

Reopening may observe revision 0 before commit or revision 1 after commit. Neither
observation settles the original publication outcome, proves global absence,
creates an earlier acknowledgment or authorizes another operation. Process death
is not physical power loss, and EXTRA is not independently qualified hardware
durability. The authoritative service, lookup authentication, administrator
nonrollback obligation and original work-entry boundary remain absent.

## Original output and acceptance

The [output format](../qualification/nom_anchor_sqlite_evidence.py) creates a new
exclusive finite directory, with immutable labels, retention-intent/completion
events and one object per digest. It refuses existing outputs, links and changed
identities. It offers no adoption, general storage management, cleanup or resume
API. Callers must admit the source/build/fixture work under their approved
resource and storage lifecycle. Limits are 32 MiB per object, 128 MiB retained
objects, 256 objects, 2048 events and a separately bounded 256 MiB synthetic
database workspace. These application checks are not an OS filesystem quota.

Original SQL, captures, nested contender output, complete material and explicit
image-group references are retained before reducing a result. Cleanup concerns
only the newly owned reproducible fixture after all selected children are
confirmed reaped and original images are retained. Uncertain supervision keeps
the original fixture under HOLD. There is no cleanup of historical data.

The [read-only reviewer](../scripts/check_nom_anchor_sqlite_evidence.py) checks
the bounded manifest/event graph, hashes, source bindings, golden complete bytes,
all selected command identities/exits, original refusal/death streams, complete
HEAD observations and image retention before reopen. It also scans original
bytes and bounded hex openings for disclosure patterns. This is a limited
sharing check, not a guarantee of anonymity, artifact authenticity or external
service correctness. Review performs no native execution or state repair.
An incomplete graph may be retained only as NOT_QUALIFIED; allowing retention
does not waive complete comparison acceptance.

The proposed hosted profile acquires the one bounded pinned source archive,
then runs offline build/comparison/review on Linux and macOS. It publishes only
the checked synthetic graph. Build SDK-path output and arbitrary environment logs
are excluded; safe original compiler/probe streams are separately retained in
the original job log. A withheld stream or missing artifact is an incomplete
acceptance gate. Artifact names include the run attempt and never overwrite an
earlier failed artifact. Fresh exact-head PR and push/main checks, original CI
archives and downloaded native evidence are separate requirements. Nothing in
this prepared source admits application signing, wallet access, node activation,
deployment, transaction broadcast or funds.
