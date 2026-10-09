# Stage 118: isolated selected failure-cleanup guard

This is a separate offline reference construction. The existing store and its
unsafe disposal observations remain unchanged. No actor, worker, signer,
application or core path uses the new guard. Independent assessment is absent;
application/core remain **NO-GO**.

The base is [the accepted research main commit](https://github.com/edgepillar/ptlc-research/commit/82016f070aa3e32661426a01b1b1035819b7e1f1).
Its [separate main-push checks](https://github.com/edgepillar/ptlc-research/actions/runs/37986185841)
pass eight jobs. They qualify the preceding snapshot, not this new construction.

## Candidate requirements and selected policy

These are explicit requirements for this selected experiment. They do not select
an application-wide exception policy or establish protocol guarantees.

| Candidate requirement | Selected construction | Measured limit |
| --- | --- | --- |
| Attempt close after selected rollback return or escape | One close callback in a finally branch | Callback entry is separate from native release |
| Preserve the first outward exception | Return False from the failed context-manager exit; retain secondary exceptions separately | Selected SQLite error, OSError and cancellation objects; ordinary scope exit only |
| Distinguish callback outcome from native state | A report records returned, escaped or not-attempted for each callback | Returned is not proof of native close; escaped can follow a successful native close |
| Avoid implicit repeated operations | One selected rollback and close attempt; cooperative one-entry guard | No retry, replacement, allocation, restored-copy or authenticated authority |

The selected policy gives the original scope exception priority over later
callback failures, including a later cancellation. This is an experimental
choice, not approval to suppress a cancellation in an application. Callback
faults remain exact private exception objects in the report; report repr excludes
those objects and no serialization, logging or transport is provided. Callback
return values are discarded and confer no authority.

Normal exit invokes neither callback. Normal resource management remains the
caller's separate obligation. Reuse or exit without entry refuses, and two
callable selections are required before scope entry. Mutable Python fields and
cooperative scope entry do not provide a security fence or durable ownership.

## Observed controls

Thirty-two explicit methods pass on the accepted base in 0.178 seconds (runner
0.343 seconds), ResourceWarning treated as an error, no skips
or failures. There is no focused source correction or later model/test-source
change at this snapshot.

Twenty-eight file controls retain an empty reservation from successful exclusive
creation and descriptor close followed by a selected initial URI EIO. They
connect the same file using native SQLite, retain DELETE journal mode,
synchronous EXTRA and foreign keys, and perform one successful native BEGIN.
They do not use the existing store constructor for the new cleanup behavior.

Twelve fault controls combine an original SQLite OperationalError, OSError or
KeyboardInterrupt with a separate OSError or KeyboardInterrupt before forwarding
SQL ROLLBACK or after one successful explicit SQL ROLLBACK. Every selected failed
scope attempts one rollback callback and one close callback. One native close
returns in all twelve, and no fixture close is needed. Close can release an
active transaction when no explicit SQL rollback was forwarded; these counters
do not deny SQLite's implicit close behavior.

Twelve compound controls add a selected SQLite OperationalError, OSError or
KeyboardInterrupt before native close or after one successful native close.
The close callback escapes in all twelve. Six before-close controls leave an
owned connection available until explicit fixture cleanup; three of those retain
an active transaction and journal. Six after-close controls release the native
connection despite an escaped callback. The report records escape in both groups
without asserting that the native resource is closed.

Three failed-scope controls have both callbacks return. A normal-scope control
attempts neither callback and retains an active connection and journal until
explicit fixture close. Four guard-only controls separately measure reused entry,
exit without entry and noncallable selections; they invoke no cleanup callback.
Complete original database readback is measured in the 28 file controls, not
claimed for the four guard-only controls.

All 27 failed file scopes propagate the exact first exception object with absent
context/cause and no suppression. Callback-active exception observations retain
that first primary. Selected secondary errors have that primary as context, no
explicit cause and no suppression; they remain separate report fields. Both
stdout and stderr stay empty and report repr omits the synthetic diagnostic
marker. These selected observations are not a general error-redaction guarantee.

Before fixture cleanup, original bytes, reservation bytes, mode 0600 and checkpoint
stat identity remain exact. Directory entries are checked separately while a
selected journal exists and after it disappears. Fixture close occurs only after
observations and only for a still-owned handle; it is not guard cleanup or
protocol recovery. A subsequent native SELECT refuses with the exact
ProgrammingError class, absent context/cause and no suppression. Complete local
and reopened original readback retains one original, charge/event sequence 1 and
zero synthetic effects. Checkpoint identity establishes neither atomic path
continuity nor race resistance; selected owner/labels are not authority.

## Unresolved decisions and gates

The reference model satisfies a selected close-attempt rule, not unconditional
resource release. It is not wired into the store; the Stage 117 unsafe behavior
remains measured there. Application exception priority, required cancellation
behavior, native-close ambiguity and integration requirements remain unresolved.

Arbitrary interruption inside guard bookkeeping, report allocation, property
access, recursive/malicious callbacks, reset or cloned guards, fork/thread use,
natural I/O faults, signals, process termination, child delivery, authenticated
ownership, restore resistance and physical durability are unqualified. There is
no secure erasure or independent native-profile, worker-identity or custody
assessment. No application cryptography or CI workflow behavior changes.

All 2256 prior method IDs must remain, with 32 disjoint additions for 2288. Two
new Python sources bring the frozen inventory to 335; all 333 preceding sources
must remain exact. Complete final-source regression, index/worktree artifact
checks and fresh hosted checks remain pending at this initial snapshot. Full
Rust/Go/Linux/Apple profiles are not rerun locally.

The earlier initial focused failure, private helper/measurement/permission/API
failures and original failed main archive remain preserved. The original hosted
child cause stays **UNRESOLVED**. No result authorizes a payment attempt,
replacement, automatic recovery, signing, broadcast, deployment or physical
entry. Application/core remain **NO-GO**.

One complete frozen-source local run passes all 2288 exact unique methods in 1008.481 s
(runner 1008.956 s), required OpenSSL, no skips, failures or ResourceWarnings.
All 2256 prior IDs remain; 32 disjoint IDs are added. One focused run
passes 32 methods with no source correction or later model/test-source
change. All 333 prior sources and 567 prior files remain exact. Two
new Python sources bring the inventory to 335. There are 571 files
and 1142 index/worktree artifact versions. No final-source regression
retry occurs. Full Rust/Go/Linux/Apple profiles are not rerun locally.
Fresh hosted checks and independent assessment remain separate gates.
The original Stage 117 failed focus and source are preserved; its
separate correction is not a failure or retry of this construction.
Earlier failed private observations and the original failed main
archive stay exact; the original hosted child cause is UNRESOLVED.
