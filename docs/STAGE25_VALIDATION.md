# Stage 25 validation: explicit resource-store process death

Scope: test-only controlled v4 initialization, admission/result and recovery cuts,
plus actual limited-Rust result/recheck loss. Runtime, journal, pure mathematical
records, selected cryptography, store/pool/resource formats and dependencies are
unchanged.

Source parent: [`8817589397c6697ac4aed003af19aff760cdf598`](https://github.com/edgepillar/ptlc-research/tree/8817589397c6697ac4aed003af19aff760cdf598).
That parent had [seven successful hosted jobs](https://github.com/edgepillar/ptlc-research/actions/runs/37192198840):
592 Python tests in each Linux/macOS 3.11/3.13 job, required OpenSSL, 55 Rust
checks, 13 Go top-level tests and 59 selected-worker qualifier cases. Parent
evidence does not execute or independently assess this new delta.

## Local checks

| Check | Result | Boundary |
| --- | --- | --- |
| First new crash-suite run | 8 tests in 29.260 seconds; three failing hot-journal subcases | Cache-size selection alone did not spill the small rows; header was zero |
| Corrected new crash suite | 8 passed in 32.344 seconds, no skips | Adds real uncommitted fixture-page pressure; retains header and database-change assertions |
| Combined v3/v4 crash and continuity suites | 44 passed in 58.499 seconds, no skips | Real macOS POSIX/SQLite cuts; v4 host selector and normal verdicts are synthetic |
| Full required offline suite | 600 passed in 619.957 seconds, no skips | OpenSSL required; macOS native resource cases assert refusal, not Linux enforcement |
| Existing actual v3 store qualifier | 6 passed in 16.104 seconds, no skips | Shared actor regression with real selected Rust public verdicts |
| Artifact, local links and whitespace | 370 index/worktree versions, 185 tracked files, 510 valid local Markdown links; final whitespace clean | English/ASCII and disclosure checks, frozen subject unchanged |

The initial three failures were fixture qualification failures, not a claimed
runtime safety finding. A tiny cache did not force a hot journal for the small
managed rows. The corrected actor adds a clearly synthetic uncommitted 128 KiB
table before the tracked owner's SIGKILL; SQLite creates the real header and
dirty pages. No journal bytes are fabricated. Mathematical results in discovery
remain synthetic; actual-verdict qualification is separate. The original strong
assertions remain. No production code is changed.

## Covered behavior

Eight Python test methods cover all nineteen named initial/admission/worker/
result/recovery cuts, real hot admission/result/recovery journals, cross-process
CPU/address-space/mode refusal before SQLite connect, repeated death during
recovery, retained old normal claims after recheck, exhausted allowance and live
owner exclusion. Successful matched reopen retains policy and charge, clears
pending as unknown without replay and performs no additional write on another
reopen. Torn or incomplete pairs quarantine unchanged.

On local macOS, only the supported-host selector is simulated; processes,
SIGKILL, SQLite, rollback and locks are real. Mathematical outcomes in discovery
are synthetic and establish no cap or signature truth. The independent Linux
native and actual-worker gates cannot be substituted by that simulation.

## Actual Linux and hosted gate

The expanded [actual v4 qualifier](../scripts/qualify_observation_resource_store.py)
has ten top-level tests, including two new methods with six actual result cuts
and four recovery cuts after an actual interrupted recheck. Each work-related
death requires an actual `verified` adapter marker first. A real hot result
journal also rejects wrong CPU/address-space/v3 selection before connect. Reopen
does not replay either worker path or launch a subprocess. Source journal state,
sequence, database and checkpoint bytes remain exact throughout every case.

This Linux-only qualifier and native cap enforcement are not run locally.
The configured Rust job runs all nine selected-worker groups; its step label now
identifies actual process-death recovery. Only completed exact-head hosted logs
establish execution. Hosted results must be recorded separately, with all seven
jobs and native Linux paths checked; configuration is not successful evidence.
Rust/Go primitives and dependencies are unchanged and are not rerun locally for
this test delta; their exact-head hosted checks remain required.

## Progression decision

The [cut design and matrix](RESOURCE_STORE_CRASH_CUTS.md) establish only executed
local process-death behavior. They add no power-cut, hostile storage, effective-cap,
aggregate-budget, clone/restore, source authority or funded availability proof.
Next qualify controlled write/sync/replace failures and uncertain outcomes before
considering rotation or wider resource admission. Independent assessment remains
pending; the frozen 119-file Stage 12 subject and manifest are unchanged.
