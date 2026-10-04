# Owned observation worker leases

Status: **Stage 21 offline ownership qualification for a selected cooperative,
nonforking public worker on a trusted local Linux/macOS host. No signing,
chain source, funded admission or global resource policy is connected.**

Source parent: [`652e54824d32d4f230de822b2432becb20a01917`](https://github.com/edgepillar/ptlc-research/tree/652e54824d32d4f230de822b2432becb20a01917).
The [disk owner](OBSERVATION_STORE.md) now uses store version 2 and an internal
[guard](../offline_session/worker_guard.py). The pure record contract,
mathematical predicate, verifier profile, public schemas, session journal and
frozen review manifest remain unchanged. Stage 20's original version 1 remains
historical evidence; this change does not upgrade existing pairs.

## Requirement and selected construction

Stage 20 excluded stale record publishers but could reopen while an orphaned
worker still computed. The current construction makes the two already-held
ownership locks follow the selected worker's lifetime. A guard also watches the
record owner's actual parent relationship and stops its owned direct worker
when that owner disappears. These are separate properties: worker-held locks
preserve exclusion even if the guard itself is killed and cannot stop work.

| Requirement | Construction | Boundary |
| --- | --- | --- |
| Exclude reopening while prior selected work remains live | Owner, guard and worker share the two locked open-file descriptions | Cooperative holders must retain them without explicit unlock; local advisory locks only |
| Stop ordinary work after owner death | Guard checks its actual parent relationship while receiving input, transferring worker pipes and waiting after EOF | Polling and scheduling are not a hard elapsed-time guarantee; guard death can leave work alive |
| Keep storage writes with one owner | Pass two lock descriptors only, with other descriptors closed | Neither database nor checkpoint connections are inherited; host and executable remain trusted |
| Preserve durable admission/result rules | Pending commit precedes guard launch; result commit precedes statement return | Missing result stays charged unknown; no worker replay or refund |
| Avoid unsafe late signaling | Outer runner owns the unreaped guard/group; guard owns its unreaped direct child | No cached group is signaled after a known reap; exclusive reaping remains required |
| Keep unresolved work distinct from rejection | Invalid leases, pin mismatch, guard/worker failure and unavailable cleanup become unknown | A normal negative still requires the unchanged exact mathematical verdict |

This is a conditional implementation of the record contract's lifetime
requirement, not containment of arbitrary process trees. The selected worker
must not fork, escape its group, close the lease descriptors or unlock them.
A malicious executable can violate those conditions and forge verdicts; entry
measurement does not establish trustworthy behavior.

## Handoff and cleanup

`ObservationStore` acquires its persistent database-directory lock and separate
checkpoint lock before reading storage. After committing one pending attempt,
it calls `SubprocessObservation.observe_owned` with exactly those two open
descriptors. The guarded runner checks that they are distinct plain integers
referring to distinct private regular files owned by the effective user. Such
metadata checks do not prove an arbitrary caller actually locked the files;
the managed store supplies that ownership premise.

The outer runner starts a fresh Python guard in its own POSIX session/group,
using `pass_fds` for just the leases and `close_fds=True`. The guard receives at
most 65,536 public request bytes, remeasures the selected entry, then starts the
nonforking public worker in the guard's group, passing the same lease references.
Worker stdout is bounded at 4,096 bytes; the outer allowance can be smaller.
The two transports retain concurrent bounded pipe transfer and require EOF,
complete delivery and zero exit before accepting output.

The guard checks `getppid()` against its original owning parent during input,
pipe exchange and direct-child wait, including after worker stdout EOF. It does
not test a cached parent PID with `kill(pid, 0)` or enumerate a process tree.
The polling interval is at most 0.05 seconds when those loops are scheduled;
it is not a maximum cleanup latency. Owner loss or guard-side failure kills
only the guard's exclusively owned unreaped direct worker. The outer runner
uses its exclusively owned unreaped guard group for cancellation/deadline
cleanup. Known reaped group identifiers are never reused for signaling.

The guard resets its own SIGCHLD disposition before spawning the worker. The
calling process must still neither independently reap the outer guard nor
enable automatic SIGCHLD reaping. No `preexec_fn`, parent-death Linux-only
signal facility, background reaper thread or detached PID signaling is used.

Closing the owner's store closes its own lock references; it never issues
`LOCK_UN`. Explicit unlock on a shared description would also drop a live
worker's exclusion. A cooperative remaining guard/worker therefore holds both
locks until its own references close. Managed code never replaces or unlinks
lock files. An unauthorized external replacement remains a hostile-host case.

Control arguments contain runtime paths, descriptor numbers and the parent PID.
They are internal launch inputs and are never serialized into statements,
records or checkpoints. Failures print only a fixed guard diagnostic, which
the outer transport discards. The Python interpreter, guard/module files,
libraries and inherited environment remain trusted separately from the selected
entry-file hash; neither repeated measurement nor that hash is build/runtime
attestation or an atomic measure-and-execute operation.

## Failure states and format boundary

| Event | Work/ownership result | Record result |
| --- | --- | --- |
| Owner dies before selected worker starts | Guard observes owner loss and exits; no selected work starts in the covered boundary test | Matching pending state becomes charged unknown on locked reopen |
| Owner dies during cooperative selected work | Guard attempts direct-child kill/reap; references close on exit | Reopen remains blocked until holders exit; pending becomes unknown without replay |
| Guard dies before worker launch | No selected worker holds a lease | Live owner records unknown if persistence succeeds |
| Guard dies after worker launch | Cooperative worker can keep computing and holding both leases | Owner records unknown; a new owner gets busy before SQLite access until worker exit |
| Deadline or caller cancellation | Outer group cleanup attempts to stop/reap guarded work | Charged unknown commits before cancellation propagates when persistence succeeds |
| Worker fails or emits unavailable/malformed output | Exact response acceptance fails; no negative is inferred | Charged unknown, preserving any earlier normal claim |
| Kernel does not complete termination | Lease holders may remain indefinitely | No reopening or availability guarantee is promised |

Store version 2 uses checkpoint domain `PTLC/observation-store-checkpoint/v2`
followed by a NUL byte. A consistent old version 1 pair, including pending work,
is quarantined without migration, pending recovery, rewrite or worker invocation.
An old unleased worker cannot be retroactively excluded by reading old files.
There is no reset, repair, migration or quota-restoration helper.

`SubprocessObservation.__call__` retains the earlier unowned transport for
direct qualification; it inherits no store leases and has no owner guard.
Only the store's explicit owned method selects the new path. Missing or invalid
owned descriptors never fall back to the legacy path. Supervision and deadlines
are runtime policy, separate from the unchanged mathematical profile identity;
the store version identifies the changed persistence/ownership epoch.

## Evidence and primary references

Native tests exercise real owner SIGKILL during output wait, after stdout EOF,
while the worker refuses full input, and before input handoff. Guard SIGKILL
after launch demonstrates continued worker-held exclusion even after the owner
returns unknown and closes its own references. Deadline and cancellation tests
exercise group cleanup. A separately selected actual Rust qualifier continues
to establish mathematical positive/negative behavior and restart ordering.
Synthetic process actors establish no cryptographic validity. See
[Stage 21 validation](STAGE21_VALIDATION.md).

| Primary reference | Checked premise | Source boundary |
| --- | --- | --- |
| [Linux flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html) | Duplicated/fork-inherited descriptors share an advisory lock; explicit unlock or last close releases it | man-pages 6.19, inspected 2026-10-04; filesystem semantics can vary |
| [Apple archived flock(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/flock.2.html) | Shared descriptor references make explicit unlock affect the inherited lock | Historical official manual, not current macOS validation; native tests supply measured evidence |
| [Pinned CPython subprocess documentation](https://github.com/python/cpython/blob/de54cf5be371a6f5e2e9f208c38def5f81d3ef02/Doc/library/subprocess.rst) | POSIX pass_fds/close_fds and new-session launch options; preexec_fn thread hazard | v3.11.9 commit; documentation premise, not execution evidence on every interpreter |
| [Linux getpid/getppid(2)](https://man7.org/linux/man-pages/man2/getppid.2.html) | Parent identity changes on reparenting after parent termination | man-pages 6.19; PID namespace alterations and arbitrary host behavior are outside this construction |

These references are attributed documentation, not copied implementation or a
general portability proof. Linux/macOS hosted execution must be reported
separately from local checks. Network filesystems, power loss, hostile lock
replacement, malicious or escaped descendants, uninterruptible tasks, aggregate
CPU/memory/process limits, fairness, new-history admission and paired rollback
remain unresolved. Matching older pairs can still replenish finite quota.

**Go:** assess the exact guard/lease/storage delta and define aggregate resource
admission plus external restore handling independently. **No-go:** rely on this
as funded recovery availability, connect private signing or chain submission,
port the client store into core or activate PTLC. Independent construction and
later-delta review remain pending; the frozen 119-file subject is unchanged.
