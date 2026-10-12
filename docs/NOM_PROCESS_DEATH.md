# Selected reference-journal process death

This separate offline qualification extends the controlled interruption evidence
at research baseline `1b79d4f6e39fa30b9944c3164ae64b04a880c6c2`.
It runs five disposable Python owners with an actual selected public Rust worker,
then observes `os._exit(72)` at an explicit boundary. It preserves the original
actor and worker streams, requests, exits, and journal files. Earlier exception
cuts and deliberately withheld replies remain separately qualified and unchanged.

| Selected exit boundary | Charged recovery work | Actual recovery calls | Journal result | Journal long original |
| --- | --- | --- | --- | --- |
| After remote-short fsync | 0 | 0 | Absent | Absent |
| After recovery-admitted fsync | 1 | 0 | Absent | Absent |
| After public recovery reply, before result append | 1 | 1 | Absent | Absent |
| After recovered fsync | 1 | 1 | Retained | Absent |
| After long original fsync | 1 | 1 | Retained | Retained |

The four journal hooks run after the reference write loop, file fsync and owner
state update. The reply cut runs after the selected public recovery call has
returned, before long verification and the recovered append. Every selected
worker has already exited and its original streams have been retained when the
Python owner exits. This is actual process termination without Python context
cleanup; it does not interrupt a worker in flight or inject interior write/fsync
faults. It does not qualify power-loss behavior or arbitrary descendants.

The parent opens the same original journal file after each owner exits. Successful
reopen also exercises release of that disposable owner's cooperative file lock.
It reads status only. It does not call recovery, prepare an attempt, construct a
missing long original, replenish the charged counter, or admit a partial hold.
Retained results receive a separate actual public-worker check after reopen.
The unchanged result-only open still checks encoding, pair and remote short;
it does not independently verify the retained long result. Changing that behavior
requires a subsequent scoped source change and manifest migration.

A returned public completion is retained in separate diagnostic evidence even
when absent from the original journal. The missing journal result is therefore
not evidence of globally lost output. A result record is also not custody of a
long original. Missing values stay null and are never filled from a known fixture.
The zero-charge remote-short case remains outside the admitted partial profile.

All observations use exactly three disclosed synthetic allowlist entries from
the existing public fixtures. Replayed observations do not reinvoke a rejecting
observer; they establish historical journal content only. No authenticated
current chain, funding, source authority or restore fence is supplied here.
Self-hashes are continuity checks, not an external authentication authority.

Before the first actor or worker spawn, the qualifier retains all 153 selected
source/fixture/manifest inputs, the exact selected public executable, and the
exact Python executable bytes. Each actor's selected private configuration is
retained before its spawn. Original streams are kept even on a failed attempt;
the native qualification uses no cleanup that deletes failed evidence. Public
reports contain disclosed synthetic values and stream bytes, not private paths.
Runtime executable pins detect changed bytes but do not authenticate the loader,
libraries, interpreter dependencies, host or independent machine.

The separate capture transport selects an empty environment and uses bounded
waits for trusted children. It retains whole observed streams in memory before
size checks. Process creation, aggregate memory and escaped descendants remain
uncontained. This transport is qualification code, not an application runner.

The 29 Python controls run an exact-request fixture worker with no cryptographic
arithmetic. Their explicit process exits exercise custody and refusal behavior;
they are not Rust mathematical evidence. The separate native qualifier performs
29 actual Rust requests: 16 before actor death and 13 during read-only reopen and
separate result verification. All original requests and replies remain retained.
The existing 342 unchanged core source outcomes are rerun independently; this
profile adds zero new core source outcomes and copies no core implementation.

Application and core remain **NO-GO**; recovery action is **NONE**. Hold admission,
complete-query composition, current source authentication, external durable
custody, restore authority, atomic work admission and independent runtime
assessment remain unfilled. No wallet, signing, broadcast or real funds occur.
