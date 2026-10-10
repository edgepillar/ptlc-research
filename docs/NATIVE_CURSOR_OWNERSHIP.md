# Selected cooperative cursor ownership and disposal

This is a bounded offline experiment. The requirements below precede the chosen
test fixture; the measured behavior is recorded separately. No store, actor,
existing guard, worker, cryptography or CI workflow adopts this construction.
Independent assessment is absent; application/core remain **NO-GO**.

## Requirements and selected scope

1. Name one component that invokes the connection creator and admits every
   cursor it exposes. A factory return is a selected cooperative premise, not
   authenticated ownership, lineage or a complete native-resource inventory.
2. Retain each just-created cursor before registration, then register before
   exposure. State what happens if registration escapes before mutation. A
   cursor returned directly by a connection alias lies outside this interface.
3. Attempt registered cursor closes while the connection API is usable, then
   attempt connection close independently. Keep retained references available
   for separate lifetime observations. No close attempt is automatically retried.
4. Preserve the scope exception separately from cleanup escapes. State the
   chosen normal-exit policy rather than silently treating a report as success.
5. Keep API return, invalidation, weak-reference lifetime, selected peer locks
   and exact original accounting separate. None authorizes another operation.

The [test-only owner](../tests/selected_cursor_owner.py) invokes one selected
connection factory and supports one cooperative scope. Its cursor interface
retains a pending reference before registration and returns only after admission.
Successful admission clears the pending slot. Retirement in this experiment
means attempting cursor close during disposal; registered references remain held
until explicit fixture release afterward. Borrowed references grant no separate
disposal responsibility or claim of isolation.

On an injected registration exception before list mutation, the owner attempts
pending cursor close once. A returned close clears the pending slot; an escaped
close keeps that reference and its raw secondary exception. The admission
exception propagates unchanged. The later scope disposal attempts the parent
without retrying that pending close. A retained failed handle is an unresolved
outcome, not a release certificate. The new control measures the escaped-close
branch; it does not independently qualify the returned-close branch.

Disposal attempts registered cursor closes in reverse admission order and then
connection close, even if a selected cursor callback escapes. Each selected
attempt has a separate returned/escaped observation. With a primary scope
exception, the same object propagates and cleanup exceptions remain diagnostics.
On normal exit, the first cleanup exception in attempted order propagates after
all selected attempts; an earlier admission-close exception takes precedence if
the caller caught its admission exception. That caught-admission normal-exit
branch is not independently exercised by these controls. Raw exception objects
have no serializer and may contain private runtime data.

This selection qualifies escapes from the invoked callbacks. It does not qualify
arbitrary interruption between native creation, reference assignment,
registration, exposure, phase changes or report construction. A factory failure
before returning a connection, cursor creation before returning a handle and a
registry that mutates before raising remain unqualified. Accessible private
fields permit deliberate fixture bypasses;
Python naming is not an ownership enforcement mechanism.

## Selected controls and distinct outcomes

The [four methods](../tests/test_selected_cursor_owner.py) contain two native
controls and two separate injected exception controls. They form no Cartesian
matrix. Both native controls use a separate three-row synthetic database,
CPython, URI read/write, zero timeout, DELETE journal mode, synchronous EXTRA,
foreign keys and a one-entry owner statement cache. The peer selects no cache.
One registered setup cursor configures the owner; partially consumed same-SQL
readers are separate handles. Peer transactions roll back without writing.

| Control | Selected boundary |
| --- | --- |
| All selected readers admitted; scope raises a synthetic error | Three registered cursor closes return before parent close. The same primary propagates. Peer BEGIN EXCLUSIVE changes from exact SQLITE_BUSY to returned while the closed cursor objects remain retained |
| One reader deliberately bypasses admission; normal scope exit | Both registered closes and parent close return, but peer remains exact SQLITE_BUSY. Owner SELECT and missing cursor close are refused with exact ProgrammingError. Explicit missing-reference release permits the peer while the closed tracked reader remains retained |
| Registration fails before mutation; pending close escapes | No cursor is exposed. The same admission error propagates; the pending reference and close error remain separate. Parent close is attempted once; pending close is not retried |
| One registered close and parent close escape | The sibling close still runs. A failed scope preserves its primary; a normal scope surfaces the first cursor-close error after the parent attempt. Both secondary identities remain diagnostic |

Native positive control checks both files' bytes, mode, device/inode and directory
entries at four checkpoints: before disposal, after disposal, after explicit
registered-reference release and after peer close. The missing-admission control
checks five, adding the checkpoint after missing-reference release while the
tracked closed reader is retained. Complete local/reopened original readback
stays exact: one original, one charge/event, no effect. Injected controls check
the original file bytes and the same complete accounting separately from mocks.

## Partial admission requirements and counterexample

The pre-mutation control above assumes registration has not inserted the handle
when it raises. Registration before exposure does not itself establish atomic
insertion. Before selecting another construction, require separate observations
for handle creation, pending retention, registry insertion, exposure, each close
invocation and the outcome of each invocation. A handle retained in both pending
and registered storage must not authorize another close. An escaped attempt
remains unresolved even if a later callback returns; preserve the original
admission error and first cleanup error separately from that later return.

One [injected counterexample](../tests/test_selected_cursor_admission_mutation.py)
leaves the owner source unchanged. The selected registration callback appends the
pending handle and then raises. The first pending close raises another synthetic
error. Scope disposal finds that same handle in the registry and invokes close
again; this later callback returns. The control observes the following sequence:

| Selected event | Retained observation |
| --- | --- |
| Creation and insertion | One handle occupies both pending and registered storage |
| Admission escape | No handle is exposed; the original error remains the scope primary |
| First close invocation | The cleanup error is retained as an escaped admission-close attempt |
| Registered disposal | A second invocation on the same Python object returns |
| Parent disposal and report | Parent close returns once; the first error and later return remain separate |

This is a counterexample to extending the pre-mutation no-retry claim to partial
registration. It is not a naturally occurring SQLite fault or a native release
measurement. The fixture compares exact original file bytes, mode, device/inode,
directory entries and complete local/reopened accounting before and after the
selected sequence: one original, one charge/event and no effect. It adds no
native pointer, weak-reference or peer-lock observations. A returned second
callback does not prove retirement, native release or safe reconciliation.
No at-most-once attempt ledger or application cleanup policy is selected here.
Interruption during insertion, attempt recording or report construction remains
unqualified. See the [Stage 123 snapshot](STAGE123_VALIDATION.md).

Cursor ordinals identify selected registration order only. A returned close is
not native pointer instrumentation. Weak-reference timing is limited to the
selected CPython profile; explicit fixture release is not a portable cleanup
contract. Peer lock availability is a checkpoint observation, not permanent
availability or global disposal. File comparisons are not atomic path continuity,
race resistance, custody, secure erasure or physical durability.

## Separate cooperative attempt record

The [separate attempt owner](../tests/selected_cursor_attempt_owner.py) retains
a creation record before its selected registration callback. It marks that
record `attempted` before looking up or invoking close, then records `returned`
or `escaped` separately. Disposal visits retained creation records in reverse
creation order, rather than using admission-registry entries as authority.
Repeated visits to an attempted record preserve its first outcome without
another call. Pending and registry aliases of that record supply no additional
invocation. The preceding owner and its counterexample remain unchanged.

This construction requires cooperative factory return, successful creation-record
retention and uninterrupted record writes. The selected callback may mutate its
admission registry, but must not mutate creation or attempt records. A repeated
factory return of the same retained Python object is refused without closing it
again. Python object identity is not a native pointer or opaque-alias inventory.
Record allocation before retention, callback corruption, interruption around the
attempt mark or outcome writes, and interrupted report construction remain
unqualified. The fixture does not implement an atomic or durable attempt ledger.
Selected callers and callbacks also do not re-enter admission or scope disposal;
reentrant lifecycle behavior and thread/fork ownership are unqualified.

Two [synthetic controls](../tests/test_selected_cursor_attempt_owner.py) select
materially different exception boundaries without expanding a Cartesian matrix:

| Control | Selected observation |
| --- | --- |
| Partial registry insertion, admission escape and first close escape | The callback sees an already retained creation record. Close sees `attempted` before it raises. No cursor is exposed; pending and registry share the record, but scope disposal does not call close again. The admission primary and first cleanup error remain separate; parent close returns once |
| Normal exit, two admitted creation records and duplicate registry entries | The last-created cursor close escapes, its sibling close returns, and parent close still runs and escapes. Each cursor callback sees `attempted`; each is invoked once despite duplicate registry entries. Normal exit raises the first cursor error after all attempts |

The report retains creation ordinals, first outcomes and raw diagnostic errors.
An escaped attempt remains incomplete; a returned API callback is not evidence
of native retirement. Both controls compare original file bytes, mode,
device/inode, directory entries and complete local/reopened accounting before
and after: one original, one charge/event and no effect. They add no new native
invalidation, weak-reference or peer-lock measurements. Raw records are not
serialized, and no report grants retry, recovery or application authority.
See the [Stage 124 validation snapshot](STAGE124_VALIDATION.md). Application/core
remain **NO-GO**; adoption and independent assessment remain separate requirements.

## Native checkpoints for attempt records

Native qualification of the separate attempt owner requires independent
observations of recorded invocation/outcome, API availability, selected Python
reference lifetime and a peer's lock acquisition. Neither a creation count nor
a returned close is an exhaustive ownership or native-retirement certificate.
The existing owner, attempt owner, synthetic controls and previous counterexample
remain unchanged. No application cleanup policy is adopted.

Two [new native controls](../tests/test_selected_cursor_attempt_native.py) use
the unchanged attempt owner with a test-only native `sqlite3.Cursor` subclass.
Its close method checks `attempted` through a weak owner reference, records a
creation ordinal and delegates once to `sqlite3.Cursor.close` on the same object.
This instrumentation observes the selected call boundary; it does not inventory
native pointers or attest the loaded build. Only non-test checkpoint helpers
are reused from the earlier native controls; no test methods are inherited.

The selected CPython profile uses a separate rollback-journal probe, autocommit,
zero busy timeout, one prepared-statement cache entry for the owner and zero for
the peer. Same-SQL readers consume one row before disposal. Cooperative record
writes, no reentrant lifecycle calls and no creation-record corruption remain
premises. The second control deliberately violates creation ownership.

| Control | Independent selected checkpoints |
| --- | --- |
| Duplicate admission aliases; every reader has a creation record; scope primary retained | Three reverse-order calls observe `attempted`, then report `returned`; parent close returns. Owner and cursor APIs refuse access while the peer transaction succeeds and weak references remain live. Releasing borrowed/admission aliases alone retains those objects through creation records. Explicit creation-record release empties the selected weak references |
| One reader bypasses creation records; admission aliases removed before disposal | Two tracked calls observe `attempted` and return despite the empty admission registry; parent close returns. Owner and bypass close APIs refuse access, yet the peer remains exact `SQLITE_BUSY`. Explicit bypass-reference release permits the peer while tracked objects remain live; subsequent tracked-reference release is measured separately |

Each sequence checks five checkpoints against exact original/probe bytes, modes,
device/inode and directory entries. Complete local/reopened original allocation
accounting remains one original, one charge/event and no effect. A peer
transaction that returns is rolled back without writes. Explicit test-reference
release is an observation step, never automatic cleanup or recovery authority.
These controls do not exercise natural I/O faults, arbitrary interruption,
partial record writes, reentrancy, opaque aliases or exhaustive ownership.
See the [Stage 125 validation snapshot](STAGE125_VALIDATION.md). Source-to-loaded-
build identity remains **NOT VERIFIED**, independent assessment is absent and
application/core remain **NO-GO**.

## Creation-record retention escape requirements

Handle creation, creation-record retention, pending assignment, admission and
exposure are distinct boundaries. A failure after factory return but before
record retention violates this owner's cooperative retention premise. An empty
pending/admission field or missing creation record cannot certify that no native
handle exists and supplies no permission to close, retry or recover it. Existing
records and the parent must still have their own selected attempt observations;
the original creation/retention error must remain separate from those outcomes.

Two [selected controls](../tests/test_selected_cursor_retention_escape_native.py)
compare an idle native Cursor with a Cursor whose
test-only factory consumes one row before returning. Both deliberately fail
the second creation-record append before insertion, pending assignment,
registration or exposure. The requirements compare primary traceback references,
API availability, existing-record/parent calls and peer locks independently.
Completed-frame release and explicit retained-record release are diagnostic
operations, never disposal or recovery authority. These controls do not select
natural allocation faults, interrupted writes, append-after-insertion failures,
opaque aliases, exhaustive ownership or application adoption. Both owner helpers
and all previous controls remain unchanged. Application/core remain **NO-GO**.

The test-only list raises the same synthetic `MemoryError` before inserting
creation record 1. The selected native factory has already returned that Cursor;
only control 2 deliberately reads one row before factory return. Both scopes
retain one setup record, have no pending/admission record or exposed candidate,
call setup close once with `attempted` visible, and call the parent once. Both
returning calls remain separate from the unchanged scope primary. Its completed
`run_scope`, `cursor` and `append` frames retain the unrecorded candidate and its
not-attempted record. This is a deliberate premise violation, not a repair or
evidence of a natural allocator failure.

| Selected control | Observation after parent return | Explicit diagnostic release |
| --- | --- | --- |
| Idle factory return | Parent and candidate APIs refuse access; both selected Cursor weak references remain live; peer acquires and rolls back an exclusive transaction | Clearing completed primary traceback frames empties the unrecorded candidate/record weak references while the closed setup Cursor remains through its creation record |
| Factory consumes one row before returning | The same API invalidation and recorded outcomes coexist with a busy peer; no unrecorded close invocation occurs | Clearing the same completed frames empties candidate/record weak references and frees the peer while the closed setup Cursor remains live |

Admission-alias release alone changes neither path. Separate setup-record release
empties its weak reference; the same primary, traceback chain and disposal report
remain retained. Eight checkpoints per control compare exact original/probe
bytes, mode, device/inode, directory entries and complete local/reopened
accounting: one original, one charge/event and no effect. Probe rows remain
unchanged and peer transactions perform no writes. No extra owner or candidate
close is invoked. These are observations of selected CPython objects, not native
pointer retirement, build attestation or an exhaustive reference inventory.
See the [Stage 127 validation snapshot](STAGE127_VALIDATION.md).

## Injected pre-native escape requirements and reference paths

A close callback can escape before native delegation. Requirements must retain
that first attempted/escaped outcome, attempt siblings and the parent
independently, and compare API invalidation, reference lifetime and peer locks
without treating any outcome as retirement. Raw exception traceback frames can
retain a reader after creation, admission and borrowed aliases are removed.
Conversely, clearing completed frames cannot discharge a separate borrowed
reference. Neither operation supplies automatic retry or recovery authority.

Two [separate native controls](../tests/test_selected_cursor_preclose_escape_native.py)
exercise the unchanged attempt owner. A test-only native Cursor subclass checks
`attempted` through a weak owner reference. The last-created reader deliberately
raises a synthetic `OSError` before `sqlite3.Cursor.close`; unaffected cursor
calls delegate once. A native Connection subclass observes the independent
parent call before delegating. These are selected Python call boundaries, not
native pointer or loaded-build attestations. Both owners, prior synthetic
counterexample and all earlier controls remain exact.

The selected CPython profile uses a separate rollback-journal probe, autocommit,
zero busy timeout, prepared-statement caches of one for the owner and zero for
the peer, and two same-SQL readers that each consume one row. Successful
factory/setup, single-thread use, uninterrupted creation/attempt/outcome writes,
uncorrupted records and nonreentrant callbacks remain cooperative premises.
The injected escape is deliberate; it is not evidence of a natural SQLite
close fault. A helper catches the propagated exception without stripping its
traceback and completes before the selected frame-release steps.

| Control | Required selected observations |
| --- | --- |
| Scope primary preserved; explicit cursor aliases removed before frame release | The secondary first escape remains recorded, sibling/parent calls return and APIs invalidate while the peer stays exact `SQLITE_BUSY`. Creation/admission/borrowed aliases are then empty; the failed reader remains live through its secondary traceback, and the successful setup cursor through a back-link to the completed disposal frame. The successful sibling reader is released. Clearing secondary traceback frame locals releases the failed reader and permits the peer while the closed setup cursor remains live; separate completed back-frame clearing releases that object without another close call |
| Normal exit surfaces the first cleanup escape; borrower retained during frame release | The first escape propagates after sibling/parent attempts, with no scope primary. Creation/admission aliases and completed traceback frame locals are cleared; the borrowed reader remains live and the peer remains exact `SQLITE_BUSY`. Explicit borrowed-reference release empties the selected weak references and permits the peer without retry |

The primary sequence checks six checkpoints and normal exit five against exact
original/probe bytes, modes,
device/inode and directory entries. Complete local/reopened accounting must
remain one original, one charge/event and no effect. Peer lock probes roll back
without writes. Raw exceptions remain private and are not serialized. Explicit
frame clearing and reference release are test observations, never application
cleanup policy. See the [Stage 126 validation snapshot](STAGE126_VALIDATION.md)
for executed results and separate gates. Natural faults, interruption,
reentrancy, opaque aliases, exhaustive ownership and independent assessment
remain unresolved. Source/build identity is **NOT VERIFIED**; application/core
remain **NO-GO**.

## Source and application boundaries

The preceding [resource inventory](NATIVE_RESOURCE_INVENTORY.md) and
[native release requirements](NATIVE_RELEASE_REQUIREMENTS.md) pin CPython and
SQLite source behavior, attribution and license review. Their inspected commits
are unchanged. This construction and its controls are original fixture code;
no third-party implementation is copied and the project license is unchanged.
Source-to-loaded-build identity remains **NOT VERIFIED**. Matching version strings
and fresh hosted results do not establish a build attestation.

The registry covers only these cooperative cursor admissions. Opaque statements,
BLOB/backup handles, callbacks, cycles, malicious drivers and independently
created aliases require their own inventory. Natural I/O faults, cancellation,
signals, process death, thread/fork behavior, restore resistance and independent
assessment remain unresolved. No selected callback, report or disposal result
authorizes retry, refund, replacement, another charge, recovery, an effect,
deployment, node activation, wallet use, signing, broadcast or real funds.

See the [Stage 122 validation snapshot](STAGE122_VALIDATION.md) for actual local
results and separate hosted/main acceptance gates.
