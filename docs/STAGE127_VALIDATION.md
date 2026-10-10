# Stage 127 validation snapshot

Scope: a deliberately failed creation-record retention step, separate from
admission, exposure, parent disposal, raw exception references and native lock
observations. The selected baseline is
`29df012998a178c7ad9032e9a0cbf4ba8243420a` with tree
`ce2eba59fc2b686fdb1ab5df0b56d0f05c7dd3b4` and parent
`3fed9040dc31ffd002c90c7dd77ddaf6322c5489`.

Requirements precede construction. The two
[new controls](../tests/test_selected_cursor_retention_escape_native.py) inherit
only the common case and reuse non-test invariant helpers. Both owner helpers,
all earlier synthetic/native controls and counterexamples, store, actor, guard,
worker, cryptography and workflow sources remain exact. No external
implementation is copied; previously pinned CPython/SQLite sources and licenses
remain retained. Loaded source/build identity is **NOT VERIFIED**.

## Selected requirements and construction

The helper requires successful, uninterrupted creation-record retention. A
test-only list deliberately raises a preconstructed synthetic `MemoryError`
before appending record 1, after a selected native factory has returned its
Cursor and the record has been constructed. Pending assignment, registration
and exposure have not occurred. This explicitly violates the retention premise;
it neither repairs the helper nor establishes a natural allocation failure.

The paired controls select different native workloads rather than a Cartesian
matrix. The first factory returns an idle Cursor. Only the second factory
executes a SELECT and consumes one row before returning. Both use a separate
DELETE-journal probe, autocommit, zero busy timeout, prepared-statement cache one
for the owner and zero for the peer, and three synthetic integer rows. Native
Cursor/Connection subclasses observe selected Python invocation boundaries
through weak owner references and delegate unchanged successful calls once.
No opaque native alias or pointer instrumentation is added.

## Focused observations

One original focused run passes both methods in 0.033 s (runner 0.248 s),
CPython 3.12.14, SQLite 3.53.1, required OpenSSL and
`-Werror::ResourceWarning`. There are no skips, failures or ResourceWarnings.
Neither test source nor owner is corrected after that focus.

Both scopes retain only setup record 0, have no pending/admission record and
expose no candidate. Setup close observes `attempted` and returns once; parent
close returns once independently; the same primary propagates with unchanged
context, cause and suppression state. The report includes setup's returned
outcome, no candidate close outcome, and the exact primary. Candidate's weakly
observed record remains not-attempted with no secondary. Absence from the report
does not establish handle absence or authorize another close.

After parent return, owner and candidate APIs refuse access while both Cursor
weak references remain live. The idle control's peer succeeds; the primed
control's peer is busy. Admission-alias release changes neither result.
Completed primary traceback frames named `run_scope`, `cursor` and `append`
retain the candidate and its unrecorded record. Explicit frame clearing retains
the same traceback chain, error and report but empties both weak references.
The closed setup Cursor remains live through its separate creation record.
Both peers are then free; explicit setup-record release empties its weak
reference without another owner/cursor close invocation.

Eight selected checkpoints per control compare original/probe bytes, mode,
device/inode, directory entries and complete local/reopened accounting: one
original, one charge/event and no effect. Probe rows remain unchanged. Peer
exclusive transactions roll back without writes; final peer close and API
invalidation are separate observations. Raw exceptions/references remain private
and are never serialized as recovery tokens.

## Remaining gates

Complete frozen-source local regression, artifact/privacy checks, fresh hosted
PR checks and exact main-push checks are separate gates. Prior successful checks
are not current candidate acceptance. Historical failed tests/helpers, metadata
derivations and original CI archives remain pinned; the earlier failed main
child cause remains **UNRESOLVED**.

Natural allocator/interpreter failure, record-allocation failure, append after
partial insertion, interrupted writes, reentrancy, corrupt records, opaque
aliases, exhaustive ownership, concurrency, thread/fork ownership, restore
resistance, custody, secure erasure and physical durability remain unqualified.
No independent assessment is added. Application/core remain **NO-GO**. No missing
record, raw traceback, report or explicit frame/reference release authorizes
automatic cleanup, retry, refund, replacement, another charge, recovery, an
effect, deployment, activation, wallet access, signing, broadcast or real funds.

## Complete frozen-source local result

One original focus passes both methods in 0.033 s
(runner 0.248 s). One complete frozen-source run
passes all 2308 exact unique methods in 977.699 s (runner 978.169 s),
required OpenSSL, no skips, failures or ResourceWarnings. All 2306 prior IDs
and 345 prior source files remain exact. Two disjoint methods and one new source
bring the source inventory to 346. All 589 unmodified prior files remain exact.
The candidate contains 594 files and 1188 index/worktree artifact versions.
No focus correction, source change after focus, complete regression retry or
workflow rerun occurs. One private semantic review fails an overbroad counter
predicate before qualification or publication; its original source/log/result
remain exact. A separate review restricts the predicate to actual state counters
and corrects an unexecuted chained-assertion shape check. One pre-execution
private publication-text revision records that observation. Historical failed
tests/helpers and metadata
derivations remain exact. The earlier failed main child cause remains
UNRESOLVED. Full Rust/Go/Linux/Apple profiles are not rerun locally.
The local profile is CPython 3.12.14 and SQLite 3.53.1.
Fresh hosted PR checks and exact main-push checks remain separate gates.
Source-to-loaded-build identity is NOT VERIFIED; independent assessment is absent;
application/core remain NO-GO.
