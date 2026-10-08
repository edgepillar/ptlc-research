# Stage 102 original allocation evidence validation

Status: **ORIGINAL ALLOCATION EVIDENCE AND COMPLETE LOCAL REGRESSION PASS;
FRESH HOSTED QUALIFICATION PENDING AT THIS LOCAL SNAPSHOT.** Application/core remain NO-GO.

## Subject and selected change

The immutable parent is `347c7a476091e3189f186a9ece3e840f6adf2a3a`, tree
`5467c1c182f1b4a0cb04c7f1221cdcfdf4fd4e3a`. This stage deliberately revises
one original test harness and adds a separate diagnostic test file. The original
store and actor, both contention helper sources, workflows, dependencies,
fixtures, primitive/journal bytes, review packets and custody proposals remain
exact. No external implementation is copied.

The [experiment note](POLICY_EFFECT_CONTENTION.md#original-allocation-failure-evidence)
defines the narrower scope: original replies and read-only exact-request state
are collected after both child replies complete and before the strict failure
can discard them. The assertion still requires `[0,20]`, exactly one retained
original and one charge. The report omits raw bytes and exception messages;
failed readback is `unavailable`, never an assumed zero. Native SQLite phases
and codes are not emitted by the unchanged actor and remain unobserved. Timeout
and interrupted collection are not newly qualified. No signer or permission
interface consumes this test report.

## Retained failures and focused result

One new method first ran against the unchanged original harness in 0.107 s
(runner 0.353 s). The deliberately held-reader scenario triggered the required
strict assertion, but its message contained no diagnostic evidence. The new
method failed that missing-evidence expectation; the original source, test
source and failed log remain retained.

The first eight-method focus ran in 0.234 s (runner 0.364 s): seven methods
passed, while the controlled-reader method errored when its expected row fields
were unavailable. Its reader remained open during readback. The report correctly
declared unavailable state rather than inventing zero rows. That source and log
remain retained. The corrected control releases the fixture reader after both
children are reaped and before observation; store/actor behavior is unchanged.

All eight diagnostic methods then passed in 0.235 s (runner 0.378 s), with no
skips, errors or ResourceWarnings. The 68-method policy-store/contention/diagnostic
focus passed in 7.443 s (runner 7.574 s). Its two added native scenarios execute
four original actor children: a controlled `[20,20]` failure with zero retained
charges after reader release, and acknowledged postcommit SIGKILL with one
retained original, followed by distinct-peer refusal. Other methods exercise
fixed reply shapes, complete original bindings, private-output omission,
unavailable observation and cancellation. Synthetic effects remain zero.

A supplemental classifier probe found that a 3001-byte deeply nested reply
raised RecursionError on local Python 3.9.6, while selected Python 3.12.14 already
classified it as unrecognized. The classifier now also sanitizes RecursionError
and the existing reply-shape method includes that control. The final eight-method
focus passes in 0.235 s (runner 0.469 s); the supplemental legacy classifier
probe also passes. This is not a complete-suite Python 3.9 qualification; the
complete-suite minimum remains 3.11. The earlier 68-method result preceded this
parsing case; the current complete suite must validate the final source bytes.

The selected local runtime is Python 3.12.14 / SQLite 3.53.1. These selected
scenarios do not resolve the Stage 99 failure cause, which remains UNRESOLVED.

## Remaining acceptance scope

The first complete local attempt aborted amid ENOSPC. Its retained partial log
has 104 method headers and 42 ERROR labels; individual exception details were
not completely retained. The runner exited 1, but the child exit and completed
result summary were not retained. No full-suite pass is claimed for that run.
A supplemental probe runner could not create its log in the same environment
and did not execute its qualification command. Five read-only path lookups
missed files; a slow read-only cache inventory was stopped before mutation.
One private watcher-preparation script had a syntax error and was corrected
before watcher execution. Its failed source/log remain retained; no repository
source, original platform log or hosted qualification was changed by that repair.

Only 6995 owned, unreferenced regenerable Rust linker objects were removed,
294960848 apparent bytes. Cleanup checked 317 current source pins, 7145 existing
evidence files and 4752 retained executable/library/object files before and
afterward. No unique executable, source archive or original log was removed.
Those preservation checks apply to the cleanup cut, not future binary identity.
The final classifier source and supplemental probe are separately retained;
a fresh complete local run is required after the failed environmental attempt.

The fresh complete local run on the final source passes all 2091 exact unique
methods in 990.083 s (runner 990.558 s), required OpenSSL, no
skips, failures or ResourceWarnings. All 2083 preceding IDs remain with eight
disjoint additions. All 317 current sources are frozen; 315 preceding
non-document sources remain byte exact, one original test source is deliberately
revised, and one diagnostic source is added. Forty-six of the original 47 test
method bodies remain exact; the revised method preserves the strict assertions.
Of 535 preceding files, 532 remain exact and three are modified; two additions
give 537 files. Artifact checks pass 1074 index/worktree versions and 1909 resolved
relative links. Both historical author packets, four fixed inventories, three
UNFILLED reports and the license remain exact. This is one local complete-run
restart after the environmental failure; its partial evidence is not overwritten.
Fresh exact-head Linux/macOS Python 3.11/3.13 and the existing Rust/Go/Linux/Apple
profiles are separate hosted scopes. Full native profiles have not been rerun
locally in this stage. Independent assessment is absent. SC01-SC12 remain OPEN;
physical F1-F4 and future A01-A12 remain NOT EXECUTED. Signer, custody,
current-policy owner and nonrollback anchor remain UNSELECTED / NOT IMPLEMENTED.
No wallet, funds, broadcast, deployed contract, node activation, hardware/cloud
custody, main merge, release or reviewer contact occurs.
