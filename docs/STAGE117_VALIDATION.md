# Stage 117: non-SQLite reservation rollback boundaries

This is offline synthetic qualification of a cleanup boundary, not a safe
recovery implementation. Protocol requirements, selected construction and
observed behavior remain separate. Independent assessment is absent;
application/core remain **NO-GO**.

The base is [the accepted research main commit](https://github.com/edgepillar/ptlc-research/commit/a662a5ddbf72e162d4451af16a2de2c6aa1ece23).
Its [separate main-push checks](https://github.com/edgepillar/ptlc-research/actions/runs/37975680013)
pass all eight jobs. Those checks qualify the preceding snapshot; fresh candidate
regression and hosted checks remain separate gates.

## Selected construction

Twenty-four methods carry the same retained empty reservation into direct
constructor or original actor entry. One native BEGIN succeeds, followed by a
selected SQLite OperationalError, OSError or KeyboardInterrupt. A separate
OSError or KeyboardInterrupt is selected before forwarding SQL ROLLBACK, or after
one successful native SQL ROLLBACK. All errors and labels are synthetic; these
wrappers do not establish natural native faults or arbitrary interruption inside
SQLite.

The retained reservation follows successful exclusive creation, descriptor close
and a selected initial URI EIO. The explicit followup does not provision,
replace, reconstruct or automatically retry an operation. Native connection and
required PRAGMAs are forwarded; schema validation is never reached.

## Preserved failed observation and corrected construction

The initial source executes 24 methods in 0.143 seconds and fails twelve
before-ROLLBACK methods. Every failure reaches the checkpoint that incorrectly
requires unchanged directory entries while an active native transaction remains
open. The selected reservation journal is an additional entry at that checkpoint.
The twelve after-ROLLBACK methods pass. Complete original readback for the twelve
failed methods is not established by that run.

The original failed source, result, log and exact failed method IDs remain
preserved. One source correction requires the selected journal before fixture
cleanup, then checks its removal separately after fixture close. The corrected
final source passes all 24 methods in 0.143 seconds (runner 0.259 seconds), with
ResourceWarning treated as an error, no skips or failures. This does not rewrite
the initial run as success or fix the reference store.

## Observed boundary

The secondary outcome replaces the original primary as the outward result in all
24 selections. The original primary remains the secondary's exception context,
with no explicit cause or context suppression. Six after-ROLLBACK OSError cases
produce the exact StoreOutcomeUnknown class with the secondary as context, no
explicit cause and suppressed context. The other eighteen selections rethrow
the exact secondary OSError or KeyboardInterrupt, including a distinct secondary
cancellation when the original primary was also a cancellation.

Every constructor invokes two rollback helpers and one disposal. Disposal observes
busy state False and the secondary as the active exception. Before-ROLLBACK
controls attempt SQL rollback twice, execute no native SQL rollback, record two
helper exceptions and no helper result. They invoke no wrapper or native close.
The constructor fails while private closed state is False, the owned native
connection remains active and a native SELECT still works. The selected journal
exists with mode 0600. These are unsafe cleanup observations, not successful
constructor disposal.

After-ROLLBACK controls attempt SQL rollback once and execute one native SQL
rollback. One helper raises the secondary; the disposal helper returns True.
One native close returns, releasing one owned connection. Private closed state is
True; fixture cleanup performs no additional close and no journal remains.

Before-ROLLBACK fixtures explicitly close the one still-owned native connection
only after observing the open transaction and journal. The fixture observes an
active transaction before that close. The journal then disappears and a separate
native SELECT probe refuses with the exact ProgrammingError class, absent context
and cause, and no context suppression. The private closed flag stays False;
fixture release is not constructor cleanup or an authorized recovery operation.

The constructor never returns or allocates, never calls public close, never
installs the actor observer and emits no actor stdout. Original database bytes,
reservation bytes, checkpoint stat identity and mode 0600 remain exact before
and after fixture cleanup. Directory entries are measured separately while the
selected journal exists and after it disappears. Complete local and reopened
original readback retains one original, charge/event sequence 1 and zero
synthetic effects. Checkpoint identity establishes neither atomic path continuity
nor race resistance. Owner and labels remain selected local state, not protocol
authority.

## Remaining requirements and gates

Passing controls record the unsafe boundary; they do not satisfy a requirement
that constructor cleanup reliably release a resource despite secondary failures
or preserve a chosen outward primary. The required exception-priority policy,
cleanup guarantees and independent assessment remain unresolved. No production
store, actor, worker, cryptography or CI workflow behavior changes.

All preceding 2232 method IDs must remain, with 24 disjoint additions for 2256.
One test source adds a source for 333; all preceding 332 sources must stay exact.
Complete final-source regression, index/worktree artifact checks and fresh hosted
checks remain pending at this initial snapshot. Full Rust/Go/Linux/Apple profiles
are not rerun locally.

Repeated native close failures, compound property-access failures, natural I/O
faults, arbitrary scheduling, signals, process termination, child diagnostic
delivery, authenticated authority, restore resistance and physical durability
remain unqualified. Earlier failed helper preparation, measurements, private
permission checks, read-only API observations and the original failed main
archive remain preserved. The original hosted child cause stays **UNRESOLVED**.

No result authorizes another payment attempt, replacement, automatic recovery,
signing, broadcast, deployment or a physical effect. Application/core remain
**NO-GO**.

One complete final-source local run passes all 2256 exact unique methods in 954.739 s
(runner 955.208 s), required OpenSSL, no skips, failures or ResourceWarnings.
All 2232 preceding IDs remain; 24 disjoint IDs are added. The corrected
focus passes 24 methods after one preserved initial failed focus with
twelve failed methods and one source correction. No source changes
follow the corrected focus. All 332 prior sources and 565 prior files
remain exact. There are 568 current files and 1136 index/worktree
artifact versions. The complete final-source regression is a first run,
with no full-regression retry. Full Rust/Go/Linux/Apple profiles are not
rerun locally. Fresh hosted checks and independent assessment remain
separate gates. Earlier failed private observations and the original
failed main archive remain preserved; its child cause stays UNRESOLVED.
