# Stage 116: retained reservation rollback interruptions

This is offline synthetic qualification. Protocol requirements, construction
choices and observed behavior remain separate. Independent assessment is absent;
application/core remain **NO-GO**.

The base is [the accepted research main commit](https://github.com/edgepillar/ptlc-research/commit/b564d5343e34a769a991612c47ced28e84bc6217).
Its [separate main-push checks](https://github.com/edgepillar/ptlc-research/actions/runs/37965430883)
pass all eight jobs. Those observations qualify the preceding snapshot; fresh
candidate regression and hosted checks remain separate gates.

## Selected construction

Twelve methods select SQLite OperationalError, OSError or KeyboardInterrupt
after one successful native BEGIN. Each is exercised through direct constructor
entry or the original actor entry in the same process. A separate SQLite
OperationalError is selected before forwarding ROLLBACK, or after one successful
native SQL ROLLBACK. These wrappers do not establish natural native faults or
arbitrary interruption inside SQLite.

The same retained empty reservation remains after initial successful native
exclusive creation, descriptor close and a selected URI EIO. The explicit
followup uses no provisioning profile or replacement. Native connect and
required PRAGMAs are forwarded, and schema validation is never reached.

## Focused observations

One focused final-source run on the accepted base passes all twelve methods in
0.078 seconds (runner 0.236 seconds), with ResourceWarning treated as an error,
no skips or failures. The preserved older private candidate has a separate
twelve-method observation. Before the current first execution, one construction
revision adds helper results, disposal busy states and native closed-property
refusals. The older source and result are preserved and are not substituted for
the current final-source execution.

Every selected followup invokes three rollback helpers and two constructor
disposals. Before-ROLLBACK controls select two SQL ROLLBACK attempts, no successful
native SQL rollback and exact helper results False/False/False. After-ROLLBACK
controls select one SQL ROLLBACK attempt, one successful native SQL rollback and
exact helper results False/True/False. The first disposal observes busy state
True; the second observes False. Disposal receives the original primary first
and the outward outcome second.

Two native close calls return successfully. One releases the owned connection;
one is a subsequent call on the already closed connection. These counts do not
represent two owned resources being released. The first close observes an active
native transaction only in the before-ROLLBACK controls. Fixture cleanup owns no
native handle and performs no additional native close.

One native transaction-property access on the closed connection raises the exact
ProgrammingError class. Its context is the outward outcome, with no explicit
cause or context suppression. A separate native SELECT probe refuses after
cleanup. Private closed state is True and busy state is False; database object,
owner and labels remain exact selected local observations, not protocol authority.

Eight SQLite/OSError selections yield the exact StoreOutcomeUnknown class with
the original primary as context, no explicit cause and suppressed context.
Four cancellations rethrow the exact original KeyboardInterrupt. The selected
rollback error retains the original primary as context, with no explicit cause
or context suppression. Original primaries have no context or cause and do not
suppress context. Cleanup does not replace those selected outward outcomes.

The constructor never returns or allocates, never invokes public close, never
installs the actor observer and emits no actor stdout. Original bytes, retained
reservation bytes, directory entries, mode 0600 and checkpoint stat identity
remain exact before complete local and reopened original readback. One original
and charge/event sequence 1 remain, with zero synthetic effects. Checkpoint
identity does not establish atomic path continuity or race resistance.

## Remaining gates and limits

All preceding 2220 method IDs must remain, with twelve disjoint additions for
2232 total. The new test adds one source for 332; all preceding 331 sources
must stay exact. Complete final-source regression, artifact checks and fresh
hosted checks remain pending at this initial snapshot.

Only controlled SQLite OperationalError rollback interruptions are selected.
OSError or cancellation during rollback, compound native close failures, natural
I/O faults, arbitrary scheduling, signals, process termination, child diagnostic
delivery, atomic path continuity, authenticated authority, restore resistance
and physical durability remain unqualified. Full Rust/Go/Linux/Apple profiles
are not rerun locally; fresh hosted checks and independent assessment remain
separate gates.

Earlier failed measurements, helper preparation, read-only API observations and
the original failed main archive remain preserved. The original hosted child
cause stays **UNRESOLVED**. No failed source, result or archive is removed or
reclassified as success.

No store, actor, worker, cryptography or CI workflow behavior changes. No result
authorizes another payment attempt, replacement, automatic recovery, signing,
broadcast, deployment or a physical effect. Application/core remain **NO-GO**.

One complete frozen-source local run passes all 2232 exact unique methods in 957.771 s
(runner 958.245 s), required OpenSSL, no skips, failures or ResourceWarnings.
All 2220 preceding IDs remain; twelve disjoint IDs are added. One focused
run passes twelve methods on the accepted main base, with no later test-source
change. All 331 prior sources and 563 prior files remain exact. There are 566
current files and 1132 index/worktree artifact versions. No final-source
regression retry occurs. Full Rust/Go/Linux/Apple profiles are not rerun
locally. Fresh hosted checks and independent assessment remain separate gates.
One private helper-generation guard fails before helper execution; its
original source and diagnostic are preserved. The corrected helper is
reviewed separately; no test source or running regression is affected.
Earlier failed measurements and the original failed main archive remain
preserved; the original hosted child cause stays UNRESOLVED.
