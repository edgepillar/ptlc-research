# Stage 121: native ownership and statement-cache limits

This is an offline source inventory and a single native counterexample control.
Existing store, selected cleanup guard, actor, worker, cryptography and CI workflow
remain unchanged. Independent assessment is absent; application/core remain
**NO-GO**. No application cleanup construction or recovery policy is selected.

The base is [the accepted research main commit](https://github.com/edgepillar/ptlc-research/commit/07081224b430d39ac358942057f4ef0bb8ed999f).
Its [independent main-push checks](https://github.com/edgepillar/ptlc-research/actions/runs/38010535774)
pass eight jobs. The accepted source inventory contains 337 sources, 576 files and
2294 unique Python methods. Earlier failed evidence and original CI archives are
retained; the original failed main child cause remains **UNRESOLVED**.

## Requirement and scoped source inspection

The [native resource inventory](NATIVE_RESOURCE_INVENTORY.md) pins the unchanged
store, original actor, execute observer, contention actor and rollback actor to
the accepted commit. It identifies creators, consumers, aliases and disposal
boundaries. Inline cursor consumption, Python closed/transaction flags and a
forwarding wrapper do not form an independently verified ownership registry.

The store omits `cached_statements`. The actor selects SQLite page-cache/spill
settings, which are different from Python's prepared-statement cache. Pinned
CPython source declares a default of 128, uses an LRU cache and creates another
statement when the selected cached statement is busy. The default is a source
fact, not an attested runtime or portable guarantee. The new control explicitly
selects one entry, rather than inferring the store's loaded default.

The inspected CPython and SQLite source/licenses remain pinned, with one additional
SQLite `pragma.c` source pin for the page-cache distinction. No third-party
implementation is copied. Source inspection, selected configuration and measured
native behavior remain separate from source-to-loaded-build identity.

## One material control

One [native control](../tests/test_selected_statement_cache.py) derives only from
the common policy-store fixture. It neither inherits another test class nor
expands a cache/cursor/error matrix. A separate probe database contains three
synthetic integer rows. Owner/peer connections use zero timeout, DELETE mode,
synchronous EXTRA and foreign keys; owner statement cache is explicitly one,
peer cache is zero. Two distinct cursor objects execute exactly the same SQL.

The first reader advances independently. After it closes, the second reader
returns its next row, while a peer's BEGIN EXCLUSIVE remains busy. The owner
connection close then returns, owner SELECT and second cursor close report exact
ProgrammingError, and the peer still reports SQLITE_BUSY. Releasing the second
cursor reference permits a peer transaction even while the closed first cursor
object remains retained. Releasing the first reference permits another peer
transaction. Both successful transactions roll back without writing.

| Counted observation | Count |
| --- | --- |
| Owner connection close returned | 1 |
| First cursor close returned | 1 |
| Second cursor close refused after connection close | 1 |
| Peer exact SQLITE_BUSY | 3 |
| Peer successful BEGIN EXCLUSIVE followed by ROLLBACK | 2 |
| Explicit fixture cursor reference release | 2 |
| Fixture additional owner close / peer close | 0 / 1 |

Exact exception types, SQLite error code/name, absent context/cause and no
suppression are checked separately. Weak references become empty in the selected
CPython profile; no portable garbage-collection or secure-erasure claim follows.
The observed cursor objects and locks are not native statement-pointer inventory.

Five checkpoints compare complete local/reopened original readback, exact file
bytes, mode 0600, device/inode and directory entries: first cursor close,
connection close, second reference release, first reference release and peer close.
Each retains one exact original, charge/event sequence 1 and zero effects. The
three probe rows remain unchanged. These comparisons do not prove atomic path
continuity, race resistance or physical durability. Fixture cleanup remains
separate from selected owner close and original-operation accounting.

## Validation record and remaining gates

An initial private native probe passes. Before the first focused execution, a
source review simplifies the control to keep the second reader partially consumed
without re-executing SQL; the earlier unexecuted draft is retained privately.
This is one pre-focus construction revision, not a failed test or qualification
retry. The first focused run passes one method in 0.012 s (runner 0.154 s), with
ResourceWarning treated as an error, no skips or failures. The local profile is
CPython 3.12.14 and SQLite 3.53.1. Source-build/runtime identity is **NOT VERIFIED**.

One initial read-only inventory command includes a nonexistent `tools` directory
and emits an inspection error. The enclosing command returns zero; the failing
search subcommand's status was not separately returned. Its command/error-line
excerpt is retained privately; the complete tool output was not saved as a local
file. Corrected source inventory reads succeed. No public source correction after
focused execution or test retry follows from that read-only miss.

One document patch fails because its expected context line is absent. The tool
reports a script error, without a process exit code; no document or test is changed
by that failed patch. The original tool call remains in task history and an error
excerpt is retained privately, but a complete patch file was not saved locally.
A separately reviewed patch adds the documents using the actual file context.
This is not a failed test or a qualification retry.

All 2294 prior method IDs and 337 prior sources must remain exact, with one disjoint
method and one new test source. Complete frozen-source regression, artifact/privacy
checks and fresh hosted PR checks are separate gates. Normal main integration,
when qualified, still requires exact published head verification and independent
main-push checks. Full Rust/Go/Linux/Apple profiles are not rerun locally.

This stage does not resolve admitted driver/build identity, exhaustive ownership,
wrapper/alias retirement, callbacks/cycles, BLOB/backup objects, cache eviction,
application exception/cancellation policy, arbitrary interruption, natural I/O
faults, signals, thread/fork behavior, process death, malicious drivers, custody,
restore resistance or physical durability. An application owner-side construction
requires separate design and assessment. No cache count, lock probe, diagnostic or
unknown cleanup outcome authorizes retry, refund, replacement, recovery, another
allocation or an effect. Deployment, activation, wallet access, signing, broadcast,
real funds and application/core integration remain outside scope.

## Complete frozen-source local result

One complete run passes all 2295 exact unique methods in 975.781 s
(runner 976.252 s), required OpenSSL, no skips, failures or
ResourceWarnings. All 2294 prior IDs and 337 prior sources remain exact; one
disjoint method and one new test source bring the source inventory to 338. All
574 unmodified prior files remain exact. The candidate contains 579 files and
1158 index/worktree artifact versions. The test source is unchanged after its
first focused execution; no qualification or final-source regression retry occurs.
The earlier unexecuted draft, read-only inventory miss, failed document patch
and original historical failed evidence remain separately retained. No helper
preparation, focused or regression failure occurs in this completed local gate.
Full Rust/Go/Linux/Apple profiles are not rerun locally; fresh hosted checks and
independent assessment remain separate gates. Application/core remain NO-GO.

The first private link preflight rejects valid Markdown fragment links by treating
the fragment as part of a filename. Its source is retained; the returned tool output
is explicitly truncated, and a separate error-class summary is not a complete
original process-output archive. The first publication helper is launched after
that failed preflight and also exits with the same file/fragment mistake. Its full
original source, output and exit result remain exact. A derived helper separates
the file path from the fragment before checking local-file existence. Artifact
hygiene is rechecked after this explanatory document edit. This correction does
not validate arbitrary Markdown anchors, change a test source, repeat focus or
rerun the complete regression. The corrected helper is a separate acceptance gate.
