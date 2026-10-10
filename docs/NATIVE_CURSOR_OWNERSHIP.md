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

Cursor ordinals identify selected registration order only. A returned close is
not native pointer instrumentation. Weak-reference timing is limited to the
selected CPython profile; explicit fixture release is not a portable cleanup
contract. Peer lock availability is a checkpoint observation, not permanent
availability or global disposal. File comparisons are not atomic path continuity,
race resistance, custody, secure erasure or physical durability.

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
