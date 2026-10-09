# Stage 113: retained reservation disposal boundaries

Status: FINAL-SOURCE LOCAL REGRESSION PASSES; FRESH HOSTED QUALIFICATION PENDING AT THIS SNAPSHOT.
Independent assessment is absent. Application/core remain **NO-GO**.

This snapshot qualifies selected in-process forwarding-wrapper behavior.
It adds no store/actor behavior, recovery policy, signing or live-chain action.
Protocol requirements and construction decisions remain separate from these
measured implementation boundaries.

## Retained source and selected scope

The preceding source is commit
`61cd6d30446fa047c0251b66ff9b9999e51d8dc2`, tree
`6c5c80dc86cd7f7d315aebc9381724c2b0d3da41`.
All 2194 preceding method IDs and 329 source files are retained. One new source,
[reservation disposal controls](../tests/test_policy_effect_reservation_disposal.py),
adds twelve disjoint methods; no preceding method is replaced or source revised.
The actor, store, observer, classifiers, strict tests and native authorizer
fixture remain exact. No external code is copied; MIT attribution is unchanged.

Each fixture has one separately retained charged original with no effect. The
preceding path helper creates the same empty mode-0600 reservation using native
exclusive provisioning and successful descriptor close before selected URI EIO.
The followup does not remove, replace or reconstruct that file. Native SQLite
connect, BEGIN IMMEDIATE, empty-schema StoreRefused and successful ROLLBACK precede
one disposal close-wrapper selection. This is one explicit test action, not an
automatic application retry.

Six original actor and six direct entries cover SQLite OperationalError,
OSError and KeyboardInterrupt, before native close or after successful native
close. Successful native close is counted after it returns. The selections are
synthetic; no natural native-close failure is established.

## Separate exception, state and native observations

SQLite secondaries are caught and the exact primary StoreRefused remains
outward. The private closed flag becomes true even in the before-close cases,
where a direct native SELECT 1 still succeeds. OSError and cancellation escape
as the exact secondary with primary context and leave the closed flag false,
including the after-close cases where native SELECT 1 raises ProgrammingError.
The same retained database object is checked separately from handle usability.
Every secondary has exact primary context, no explicit cause and no suppression;
the primary has no context/cause/suppression. No exception becomes permission
for another attempt, replacement, refund, nonce allocation or a physical effect.

Each followup constructs once and disposes once, with one close-wrapper call,
no return, allocation or public close. Current labels/owner remain exact and
busy remains false. Original actor cases reach neither observer installation
nor the response guard and emit no stdout. Child status, stderr delivery and
authenticated diagnostics are not established by these in-process controls.

Before readback, each method checks byte-exact original data, empty reservation
bytes, mode 0600, stat identity at checkpoints and exact directory entries.
Complete local/reopened views agree on one original, charge/event sequence 1
and zero effects. These observations establish no atomic path continuity,
descriptor/symlink race resistance, restoration safety or physical durability.

Native ownership remains separate from private state: the six before-close
fixtures retain their live handle until verification finishes, then release it
once directly. The six after-close cases perform no fixture native close.
Registered cleanup never repeats a successful close. A direct closed-handle
probe verifies the fixture release without repairing the private closed flag.

## Qualification gates and limits

The final source passes one focused run: twelve methods in 0.080 s on Python
3.12.14 / SQLite 3.53.1, required OpenSSL, no skips, failures or ResourceWarnings.
The earlier unexecuted draft and twelve separate local exploratory helper
executions remain preserved; those exploratory calls executed no test method.
One inline helper-preparation SyntaxError is retained as a diagnostic excerpt
and incident record, then corrected without changing the test source. No focused
qualification retry or source revision after focused execution occurred.
Complete final-source regression is recorded below; source preservation and
artifact hygiene remain separate gates.

Open/rollback interruption, natural close faults, arbitrary paths,
descriptor/symlink races, signals, child delivery, authenticated diagnostics,
restores and physical durability remain unqualified. Stage 99's original cause
stays UNRESOLVED. SC01-SC12 stay OPEN; physical F1-F4/future A01-A12 stay
NOT EXECUTED. Signer/custody, current-policy ownership and a nonrollback anchor
remain UNSELECTED / NOT IMPLEMENTED. Independent native-profile, worker-identity
and custody assessment remain absent. Full Rust/Go/Linux/Apple profiles are not
rerun locally for this source-only qualification addition; fresh hosted execution
is a separate gate. Earlier failed sources, logs and original archives remain
preserved without cleanup. Application/core remain **NO-GO**.

One complete run on frozen final sources passes 2206 exact unique methods in
1014.624 s (runner 1015.257 s), required OpenSSL,
no skips, failures or ResourceWarnings. All 2194 preceding IDs and 329 sources
remain exact; twelve disjoint methods give 330 frozen sources. Two document
modifications and two additions give 561 files, with 557 of 559 preceding files
exact. One focused run passed the final source; the earlier unexecuted draft and
twelve local exploratory helper executions remain separately recorded. There is no
final-source full-regression or hosted workflow retry, qualification or
unrecorded preparatory failure at this snapshot. One inline helper-preparation
SyntaxError is preserved and corrected; it caused no test-source change or
qualification retry. Full Rust/Go/Linux/Apple profiles were
not rerun locally; fresh hosted execution and independent assessment remain
separate. Earlier failed sources, logs and original archives remain preserved
without cleanup.
