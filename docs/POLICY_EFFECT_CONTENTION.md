# Controlled policy-store contention and ambiguous replies

Status: **PUBLIC SYNTHETIC OFFLINE CONTROLS. THE INITIAL STAGE 99 CI CAUSE
REMAINS UNRESOLVED.** These controls distinguish observed actor replies from
retained synthetic allocation rows. They do not implement a signer, current
authority, protected physical effect or unknown-outcome recovery protocol.

## Historical observation and selected source

The [initial Stage 99 hosted attempt](https://github.com/edgepillar/ptlc-research/actions/runs/37823515360/attempts/1)
failed the existing distinct-request native regression on macOS/Python 3.11:
two actor exit codes were `[20,20]`, rather than its required `[0,20]`.
That assertion discarded actor stdout and preceded retained-row inspection.
Its response classes, native SQLite errors and retained allocation count were
not recorded. Thirty unchanged local repetitions and one job-specific hosted
retry passed; neither resolves the initial occurrence. The original failed
archive and successful retry remain distinct evidence.

The selected local MIT source is immutable commit
`5ed0f032a94e9dd28ad4218c9fbde624b9e4ed20`, tree
`6920e0c090264e16abd9ad3b17e5c65d94c09ada`. These hashes identify the three
original files at that immutable source. The store remains byte exact. Stage 102
deliberately revises the test harness, and Stage 103 revises the actor for optional
execute observation; the historical actor/test hashes are not current-source claims.

| Selected file | SHA256 |
| --- | --- |
| [Store](../qualification/policy_effect_store.py) | `9d5236d7bbc7ae1211b272f495026ae5b7f5825d02149cde0aaad6e062d97623` |
| [Original actor](../tests/policy_effect_store_actor.py) | `5a07b1e90f6d2a875586fc58e4a816631b11d9b477eb17786087918f41b96af8` |
| [Original tests](../tests/test_policy_effect_store.py) | `fa5f8bb317e72f057f9fce6f2faf96a845ef02511686069df94f37e22fb1d94b` |

The strict original `[0,20]` assertion is preserved. New controls add explicit
reader and reply-loss premises; they are not a reproduction of the unrecorded
original environment or a repair for its failure.

## Nine fixed scenarios in eight methods

The [new tests](../tests/test_policy_effect_contention.py) use disposable local
databases, the fixed public governor profile, two fixed operation IDs and
synthetic rows. Child readiness and acknowledged SQL/commit cuts determine
ordering. No scheduler sleep, busy-timeout increase or automatic retry is used.

| Control | Actor observations | Retained charges after child exit and reopen |
| --- | --- | --- |
| Unchanged original actors plus an explicit third shared reader, in both request orders | Two `StoreOutcomeUnknown` replies and `[20,20]` | Zero in each independent database |
| Small cache, reader admitted after BEGIN and before first write | One actual native BUSY at a write or COMMIT, then unknown | Zero |
| Buffered writes with spill disabled, reader held through COMMIT | Native BUSY specifically at COMMIT, then unknown | Zero |
| Earlier writer held before commit, competing writer started while it is held | Native BUSY at BEGIN for the peer; earlier writer commits and returns its record | One |
| Explicit reply loss after commit, distinct peer checks exhausted cap | Unknown committed reply plus `StoreRefused`, both exit 20 | One |
| Explicit reply loss before commit, peer attempts BEGIN while writer is held | Two unknown replies, both exit 20; peer has native BEGIN BUSY | Zero |
| Exact original lookup following committed reply loss | Unknown reply, then repeated exact original lookup only | One, with no synthetic effect |
| Same original peer following committed reply loss | Peer returns the retained original; first reply is unknown | One, with no new charge or effect |

Thus `[20,20]` is compatible with either zero or one retained charge in these
different controlled scenarios. Even two unknown replies do not establish a
particular durable outcome. The fixtures assert raw row counts, complete store
views, exact original lookup, child exit/reaping and reopen separately. They
never infer a refund, new operation, replacement nonce or recovery permission
from an exit code. No synthetic effect is applied in any new scenario.

The [separate observed actor](../tests/policy_effect_contention_actor.py)
delegates the original SQL unchanged. It emits only a fixed outcome schema,
public charge/effect counters, a transaction-state flag and allowlisted SQL
phase/numeric BUSY diagnostics. SQLite exception text, parameters, paths and
process identifiers are not output fields. Fixed control-frame refusal is
handled as a helper error with exit 30, separately from store outcomes as
described below. Intentional before/after-commit
reply-loss hooks are explicit test premises; they are not actual network-loss
or private worker evidence. The original actor is separately exercised without
this observer.

## Fixed control-frame refusal

The Stage 100 helper at immutable commit
`0eb96fe71c897cd9e20ad811494a8d298a73baa7` could have a transactional cut's
framing exception wrapped as `StoreOutcomeUnknown`, returning exit 20. Its
eight valid-frame methods did not qualify the broader framing-refusal claim.
Two separate local diagnostics retained zero charges before commit and one
after commit for invalid frames; neither explains the earlier Stage 99 failure.

The helper now reads at most four bytes per control frame and requires exactly
`go` followed by LF. It retains a framing-refusal flag outside the store's
exception wrapper and checks it before emitting a store result. This changes
only the test helper: store SQL, rollback handling, timeout, allocation cap,
original request bindings and the original strict availability assertion stay
unchanged. Valid frames still reach the eight preceding contention methods and
their explicit synthetic reply-loss controls.

Five added negative methods use 28 independent disposable databases and child
executions. Six invalid inputs (wrong token, CRLF, missing newline, EOF,
non-ASCII and an overlong line) are tested at initial readiness, before first
write, before commit and after commit. A separate four-cut method requires
refusal of a four-byte invalid frame before its newline or input close, checking
the read bound while the pipe remains open. A shorter incomplete input can
still wait for more bytes or EOF; this is not a transport deadline guarantee.

Every malformed-frame child emits only the fixed helper-refusal line and exits
30. Raw operation/effect counts, complete validated store view, exact original
lookup and reopen remain independent assertions. The 21 precommit cases retain
zero charges. The seven postcommit cases retain the one original charge and no
effect. **Helper refusal after commit does not mean rollback or permission to
refund, replace or retry the original.** See the separate
[Stage 101 validation snapshot](STAGE101_VALIDATION.md) for executed scopes and
the retained failing regression before the helper fix.

## Runtime and documentation limits

The numeric-error profile requires Python 3.11 or later and POSIX child
processes. The local selected profile is Python 3.12; hosted Python 3.11/3.13
and Linux/macOS are separate scopes. Python 3.9 lacks the required SQLite error
attributes/constants and is not a complete profile for these additional tests.
The [Python 3.11 SQLite error documentation](https://docs.python.org/3.11/library/sqlite3.html#sqlite3.Error)
describes that API boundary.

SQLite documents that [cache spill can acquire an exclusive lock](https://www.sqlite.org/pragma.html#pragma_cache_spill)
and that [COMMIT can fail while another reader remains active](https://www.sqlite.org/lang_transaction.html).
The [BUSY result code](https://www.sqlite.org/rescode.html#busy) describes a
concurrent-connection conflict. These are mutable documentation snapshots
accessed on 2026-10-08, not immutable implementation pins. No third-party code
or dataset is copied. Actual code/phase assertions and retained rows establish
the narrower selected execution observations; documentation does not prove
that the initial hosted failure had the same cause.

The small-cache fixture does not guarantee a mid-transaction spill. Its
observed local refusal was at COMMIT. A first test that assumed a write-phase
refusal failed and was corrected to require BUSY after the acknowledged BEGIN,
retain its actual write/commit phase and inspect rollback/reopen. It does not
claim an early spill occurred. The explicit buffered control independently
requires COMMIT BUSY. Failed local runs remain disclosed in the
[execution snapshot](STAGE100_VALIDATION.md).

## Original allocation failure evidence

Stage 102 deliberately revises the original distinct-request test harness from
parent `347c7a476091e3189f186a9ece3e840f6adf2a3a`. After both children complete
their existing bounded `communicate` calls, it preserves fixed reply classes,
exit codes and stderr presence, raw row counts, validated store counts, exact
original lookups and separately reopened observations in the assertion message.
Request IDs, profile/proposal bytes, raw output, error text and environment
details are not emitted. This report is synthetic test evidence only.

At the Stage 102 snapshot the actor and store remained byte exact, including SQL, timeout, cap and
original request bindings. The test still requires `[0,20]`, exactly one retained
original and one charge. Row/effect and reopen checks are additional assertions.
The required empty stderr check now tests presence, so an unexpected stderr
cannot be quoted by unittest. Failed readback is explicitly `unavailable`;
it never becomes zero rows. Cancellation propagates. No retry, replacement,
effect, nonce work or capacity recovery is added to the original test.

That snapshot's unchanged actor emits response classes but no native error phase or code.
The report labels those details `not-emitted-by-original-actor`; it never
infers BUSY, a commit phase or a retained charge from an exit code. Completed
child observations do not qualify the timeout or interrupted collection path.

The [diagnostic tests](../tests/test_policy_effect_diagnostics.py) first catch
the strict assertion under a deliberately held reader, then require the report
to survive that failure. They release the fixture reader after the two children
are reaped and before readback. A separate SIGKILL after an acknowledged commit
retains one original, while a distinct peer is refused by the unchanged cap.
These four native child executions exercise fixed controls, not the historical
CI schedule. A first focused run kept the reader open during observation and
produced unavailable readback; its failed expectation is retained. The corrected
fixture releases its reader at the specified observation cut. See the
[Stage 102 validation snapshot](STAGE102_VALIDATION.md).

## Remaining work

Retain the original failure as UNRESOLVED. Completed original actor replies and
readback now survive the strict assertion. The bounded Stage 103 option below
retains selected native execute details before exception wrapping while preserving
command/context bindings and all strict safety assertions. Distinguish the
availability expectation from the one-charge
safety invariant. A controlled later reproduction cannot recover missing
evidence about the old run. Do not add retry/replacement behavior merely to
make the assertion pass.

All historical review packets, primitive/journal bytes, dependencies, workflows
and custody proposals remain unchanged. Independent assessment is absent.
Physical F1-F4 and construction A01-A12 remain NOT EXECUTED; all SC01-SC12 stay
OPEN. Application/core, private signing and funded execution remain NO-GO.

## Bounded original native execute observation

Stage 103 selects parent `05ed20ad1093b54912279d24e060096e9cee0e67`, tree
`9414031dd69f6b3c3db0ffa4a08e17aad5108f0f`. The original actor accepts exactly
the additional test-only argument `native-execute-errors-v1`. Its original
arguments, request context, readiness/cut behavior, PRAGMAs, SQL, timeout,
store calls, output first line and exit classes remain unchanged. Without the
option it retains the legacy wire. The strict distinct-request test selects the
option; its `[0,20]`, exactly-one original, one-charge and readback checks remain.

A [test-only connection observer](../tests/policy_effect_native_observation.py)
forwards the command's execute calls and records errors before the unchanged
store wraps them. It emits only six fixed phase labels, at most four entries,
an explicit overflow flag and exact native BUSY code 5 or null. Null means the
code was unavailable or outside this selected allowlist; extended BUSY codes
are not collapsed into 5. Foreign exception subclasses cannot supply diagnostic
attribute hooks. Exception messages, SQL, parameters, request bytes and locations
are omitted. No retry or compensating SQL is added. Cancellation propagates.

The second stdout line is a bounded canonical synthetic report. The classifier
accepts it only with a recognized original first line and preserves legacy
classification otherwise. An invalid suffix is unrecognized, never partially
accepted. A missing report after SIGKILL is explicitly incomplete when another
reply has a report. An empty error list means no error was observed at execute;
it does not mean an absent charge, a known cause or a safe retry.
The retained legacy no-report label records classifier absence, not proof that
no native error or bytes were emitted. Only a complete validated report qualifies
the new observation.
Cursor fetching, initial open/setup, close, interrupted collection and a lost report are outside
the new observation scope. Reports are unauthenticated test evidence, not signer
permissions or trusted application results.

Actual controls observe original-actor BEGIN BUSY, buffered COMMIT BUSY with
rollback, and the strict original two-child held-reader failure. In that last
schedule one child may receive BEGIN BUSY while another is blocked later; no
single phase is inferred for both actors. Postcommit non-native loss and SIGKILL
controls retain one charge without inventing a native cause. These selected
later schedules do not resolve the historical Stage 99 occurrence. See the
[ten new methods](../tests/test_policy_effect_native_observation.py) and
[Stage 103 validation](STAGE103_VALIDATION.md).

## Native rollback and secondary cleanup

At the Stage 104 snapshot, the selected immutable parent was
`3cbd6845962e90469e10dd7b1bce05cb56f18f9b`, tree
`60bffb361eea423617be2ab9bdf2873bfdf197ed`. The store, original actor,
observer, classifiers and all preceding tests were byte exact. A separate
[delegating fixture](../tests/policy_effect_rollback_actor.py) selects a native
SQLite authorizer which denies event insertion and rollback. It runs the actual
original actor with unchanged arguments/context and no replacement SQL. Its
exception hook emits a fixed synthetic stderr label instead of traceback data;
it does not catch the terminal exception or select the process exit code.
The authorizer is an explicit test premise, not a naturally reproduced fault or
evidence about the historical worker.

The [eight new methods](../tests/test_policy_effect_rollback_observation.py)
separate the following observed boundaries:

| Explicit control | Execute observations at the command cut | Separate terminal/readback observations |
| --- | --- | --- |
| Buffered native COMMIT BUSY, both rollback attempts denied | COMMIT code 5, then two rollback entries with null codes | Closed handle; unavailable local readback; zero rows after reopen |
| Native event insertion denied, both rollback attempts denied | Event insertion, then two rollback entries, all null | Unknown command outcome; closed handle; zero rows after reopen |
| Stale policy request and both rollback attempts denied | Two rollback entries with null codes | Policy refusal becomes unknown; closed handle; zero rows after reopen |
| Non-native precommit failure, first rollback denied and disposal rollback allowed | One rollback entry with null code | Both cleanup attempts occur; handle closes; zero rows after reopen; no allocation retry |
| Cancellation and both rollback attempts denied | Two rollback entries with null codes | The same cancellation object propagates from the command; closed handle; zero rows after reopen |
| Delegated original actor under event/rollback denial, legacy and observed modes | Observed mode reports event insertion and both rollback failures | Unknown first line precedes secondary context-exit refusal and process exit 1; fixed stderr label; zero rows after reopen |
| Postcommit refusal with rollback denial selected | Empty execute-error list; no rollback statement occurs | Unknown command outcome, open handle, one original charge and zero effects before/after reopen |
| Native closed-cursor fetch and transaction-state access | Empty execute-error list | Both fail outside execute observation; neither error is reported as an execute error |

The selected observer still emits only exact BUSY code 5 or null. Native
authorization refusal is outside that numeric allowlist; null is not a BUSY
classification. Consecutive rollback entries are the unchanged store's command
cleanup and disposal cleanup, not allocation retries. Connection close is outside
the execute observer. The zero-row observation after close/reopen applies to
these explicit controls and is not a general durability or rollback guarantee.
Reading the closed connection later can append an `execute-other` error to the
observer; the test preserves the earlier command report as a defensive snapshot.
Unavailable readback never becomes an absent original.

The actor fixture's complete report survives classification alongside its
nonstandard exit and stderr presence. A recognized first line or valid report
does not qualify normal process completion. The earlier first-line/exit
preservation statement applies to the selected completed Stage 103 controls;
it is not a universal claim about secondary cleanup failures. The direct
cancellation test qualifies the command boundary only, not an outer context
manager or process interruption protocol. No terminal behavior was repaired
at that snapshot.
Reports remain unauthenticated synthetic evidence. None permits a replacement,
retry, refund, new nonce, signing or physical effect. See the separate
[Stage 104 validation snapshot](STAGE104_VALIDATION.md). The initial Stage 99
cause remains UNRESOLVED; all independent assessment and custody gates remain open.

## Original actor terminal cleanup

Stage 105 selects immutable parent `e1f472d0ca5c7ba585ceab5ac81b767cf24cd7a7`,
tree `4b5ad3e0c90371c4f4f13793ec78d27f2e0f605e`. The
[original test actor](../tests/policy_effect_store_actor.py) replaces unconditional
context exit with a `finally` block which closes the store only while its private
`_closed` flag is false. This is an isolated test actor using this exact store;
it is not a generic connection-owner API. Store SQL, disposal, rollback handling,
timeouts, caps, request bindings, the observer, classifiers, delegating authorizer
fixture and strict original contention controls remain byte exact.

The two native-authorizer child executions now require exit 20 and empty stderr,
with the same unknown first line, bounded native report and zero reopened rows.
The corresponding Stage 104 method is deliberately renamed and revised. Its
seven companion methods and all other preceding test sources remain exact.
The historical Stage 104 exit-1 snapshot above is preserved as prior evidence,
not the current terminal behavior.

[Eight added methods](../tests/test_policy_effect_actor_cleanup.py) invoke the
actual actor with a real native store and synthetic controls. They separately
assert constructor count, terminal close count, native transaction order,
disposed-state refusal, emitted bytes and reopened original/effect counts:

| Selected control | Terminal boundary | Separate retained rows |
| --- | --- | --- |
| Successful allocation | One close on an open handle; return 0; empty native report | One original charge, zero effects |
| Stale policy request | One close; return 20 with unchanged refusal and empty report | Zero originals/effects |
| Cancellation before commit with successful rollback | Same cancellation object; one close; no outcome/report emission | Zero originals/effects |
| Cancellation before commit with both native rollbacks denied | Same cancellation object; disposed handle skips terminal close; two bounded null rollback observations | Zero originals/effects |
| Native setup pragma refusal | Native exception propagates; one close before observer installation; no reply | Zero originals/effects |
| Selected terminal-close cancellation after native close | Same cancellation object propagates after a reply/report was already emitted | One original charge, zero effects |
| Readiness cancellation before a command | Same cancellation object; one close; no transaction or outcome/report | Zero originals/effects |
| Cancellation after commit | Same cancellation object; one close; no rollback statement or outcome/report | One original charge, zero effects |

The terminal cancellation uses a test wrapper which closes the real connection
then raises a selected `KeyboardInterrupt`. It is not a natural native-close
fault or process-signal experiment. Cancellation methods qualify the in-process
actor boundary and object identity, not a process exit code. There is no broad
exception catch, cancellation conversion or outcome retry. A reply emitted
before a terminal cancellation is not proof of normal completion. Simultaneous
primary and terminal failures, arbitrary close faults and interruption of the
constructor remain unqualified. The guard depends on the selected store's
disposal flag; it adds no general resource-lifecycle or durability guarantee.
Native error reports remain command-cut evidence, unauthenticated and separate
from readback and terminal success. No observation authorizes replacement,
retry, refund, nonce allocation, signing or physical effect. See the separate
[Stage 105 validation snapshot](STAGE105_VALIDATION.md). Stage 99's original cause
remains UNRESOLVED and application/core remain NO-GO.

## Original actor output loss

Stage 106 selects parent `ed9a6cf1edffef2c295d9e7541ab91c69a9ce913`, tree
`a970c31b0444c48f2d4592b41739de4ef36adf2c`. The original actor and all preceding
sources remain exact. [Eight new controls](../tests/test_policy_effect_output_loss.py)
qualify existing output boundaries without changing transaction handling or
adding a retry.

Six in-process controls use real SQLite and operating-system pipes: successful
delivery, a closed reader at the first reply or report write, two explicitly
synthetic flush faults after local delivery, and closed-pipe refusal output.
They preserve the same output exception object and separately assert one actor
allocation, one close, transaction authorizer trace, local observer contents,
locally received bytes and exact local/reopened rows. Committed controls retain
one original charge and no effect. The stale-policy refusal control rolls back
and retains zero originals/effects despite the same absent output class.

Two controls execute the unchanged actor directly with Python `-u`, in legacy
and observed modes. After readiness, the parent closes the stdout reader before
releasing the command. Both actors commit, then naturally exit 1 on native
BrokenPipeError, without a readable outcome or native report. Separate readback
retains one original charge and no effect. No exception hook or status override
changes the child. This selected unbuffered invocation does not qualify default
buffered shutdown, signal behavior or arbitrary concurrent faults.

An empty execute report held locally is separate from an emitted report; output
errors are outside native execute observation. A record or report received
before an explicit flush fault is separate from normal completion. In-process
exception identity is separate from subprocess status, and readback is separate
from physical durability. No observation authorizes retry, replacement, refund,
signing or a physical effect. See the
[Stage 106 validation snapshot](STAGE106_VALIDATION.md). Application/core remain
NO-GO and Stage 99's original cause remains UNRESOLVED.

## Original actor buffered shutdown

Stage 107 selects parent `e0fb3e9492e8bfb50040f341ccbb4ab4f5763e89`, tree
`120bbe9f7b4fe2075aac8ed204d39240bed4017e`. The actor, store, observer,
classifiers, strict controls and all preceding sources remain byte exact.
[Ten direct-child controls](../tests/test_policy_effect_buffered_shutdown.py)
qualify selected POSIX CPython behavior without wrapping the actor, changing its
exception hook, catching its output fault, replacing stdout or assigning a
process exit status. Default buffered invocation omits `-u` and removes the
inherited `PYTHONUNBUFFERED` override; the paired invocation explicitly uses
`-u` with the same removal. These are selected launch profiles, not a general
guarantee for every interpreter, environment, stream or transport.

Each child reaches an exact readiness fence before command release. Four
buffered baselines keep the reader open: successful allocation exits 0 with an
exact record; stale-policy refusal exits 20 with its exact label. Observed mode
adds the exact empty native execute report. Four buffered fault controls close
the only stdout reader before releasing the command. Native primary output
failure is followed by a separate interpreter-shutdown diagnostic; two
BrokenPipeError labels, a primary traceback, an ignored-exception marker and
actual exit 120 are asserted without echoing raw stderr. Neither a reply nor a
report is readable. Separate local/reopened readback retains one original
charge after committed allocation, and zero after refusal; all controls retain
zero effects. Two unbuffered refusal controls instead expose one primary
BrokenPipeError label, no ignored-exception marker, exit 1 and zero charges.

The static mechanism is consistent with pinned CPython 3.13.0
[finalization status handling](https://github.com/python/cpython/blob/60403a5409ff2c3f3b07dd2ca91a7a3e096839c7/Modules/main.c)
and [standard-stream flushing](https://github.com/python/cpython/blob/60403a5409ff2c3f3b07dd2ca91a7a3e096839c7/Python/pylifecycle.c).
Those references explain a mechanism; they are not evidence of the exact source
or build provenance of each executed runtime. No CPython code is copied.
Diagnostic labels and process status do not measure flush-call count, buffer
contents, actor cleanup order, exception-object identity across processes or
native execute observations which never reached the consumer.

Readback is separate from output delivery, terminal status and physical
durability. No observation authorizes a replacement request, retry, refund,
nonce allocation, signing or effect. Arbitrary concurrent terminal faults,
signals, fragmentation, authenticated remote receipt and physical durability
remain unqualified. See the [Stage 107 snapshot](STAGE107_VALIDATION.md).
Stage 99's original cause remains UNRESOLVED; application/core remain NO-GO.

## Original actor compound faults

Stage 108 selects parent `f5d814d797f2833ac581c3cfd342d68c1d3bea0c`, tree
`0108f468ce971c5c82cb117f8c18a54cefb8c659`. The actor, store, observer,
classifiers, strict controls and all 324 preceding sources remain byte exact.
[Ten in-process controls](../tests/test_policy_effect_compound_faults.py)
select primary faults and a separate terminal fault without changing the
original actor's error handling or adding an allocation retry. The harness calls
the actual store close first, then raises a fresh selected terminal exception.
This is an explicit synthetic post-successful-close fault, not qualification of
a naturally failing SQLite close or an operating-system signal.

Nine paired controls reach terminal close with an active primary exception.
Readiness cancellation has no transaction; precommit cancellation rolls back;
postcommit cancellation retains one original charge. A real SQLite authorizer
denial during setup occurs before observer installation. Native EPIPE controls
lose either the first reply, refusal reply or observed report. Two separate
synthetic EIO flush controls follow local delivery of the allocation record or
both the record and report. Each pair asserts the exact outward terminal object,
the exact primary object recorded at close, identity through `__context__`, no
explicit `__cause__`, and no context suppression. Refusal output loss retains
the separate StoreRefused object beneath the native BrokenPipeError and terminal
fault. No exception is converted into a successful reply or retry instruction.

The tenth control selects precommit cancellation with two native rollback
authorizer denials. The store disposes its connection and the actor's guard skips
terminal close. The outward exception remains the exact primary cancellation;
the selected terminal object is never raised. The observed native execute report
retains two rollback entries with null codes, not a fabricated busy code. The
authorizer trace counts selected transaction callbacks, not completed statements
or exact disposal calls.

All controls check the disposed actor handle, exact locally received bytes and
separate local/reopened state. They retain zero synthetic effects. Readiness,
pause markers, allocation output and report delivery remain distinct. A locally
held native report cannot fill in an absent emitted report; the setup fault has
no observer installed. Process status is unavailable for these in-process
controls. Received bytes before a selected flush fault do not establish normal
completion, authenticated remote receipt or physical durability. Arbitrary
fault combinations, interrupted construction, natural native-close failures,
process signals and chain behavior remain unqualified. See the
[Stage 108 snapshot](STAGE108_VALIDATION.md). No observation authorizes
replacement, retry, refund, signing or a physical effect. Stage 99's original
cause remains UNRESOLVED; application/core remain NO-GO.

## Original actor constructor interruptions

Stage 109 selects parent `f60f37a5408d6646a8eb69d0bdb5d8f927198252`, tree
`d7e19e1f1f09c8943985673ae23909a8d83ee4b3`. The actor, store, observer,
classifiers, strict controls and all 325 preceding sources remain byte exact.
[Fourteen in-process controls](../tests/test_policy_effect_actor_constructor.py)
execute the original constructor through forwarding test hooks. Each starts
with one separately seeded original charge, sequence 1, and zero effects. The
actor constructs its store before entering its exception and terminal-cleanup
guard. A constructor failure therefore precedes observer installation,
allocation, reply delivery and the actor's public close call.

Native controls use an actual missing-path SQLite open, a setup PRAGMA denial,
an open-transaction BEGIN denial, a source-label refusal and one or two rollback
authorizer denials. Selected cancellation controls raise a fresh test exception
before connection or at the existing open-before/open-after-commit cut. An open
transaction commit is not an allocation charge. The rollback-denial selections
measure two disposal calls, first during the busy transaction and then in the
constructor, and two native close calls. They preserve the exact cancellation
object; a repeated close after actual closure does not create another original.

Three paired controls raise an explicit non-SQLite terminal fault only after
native close succeeds. That terminal object is outward. Setup denial then keeps
the native error directly as context because constructor normalization never
executes; open cancellation keeps the exact selected primary object. BEGIN
denial keeps a three-object chain through an already normalized unknown outcome
whose native context remains suppressed. A fourth selection raises a synthetic
SQLite exception class after successful close; disposal swallows that class,
marks the handle closed and preserves the primary cancellation. None qualifies
a naturally failing SQLite close. In the three non-SQLite pairs the native
handle is confirmed closed even though the interrupted private closed flag
remains false. The partial object is retained only by the harness; construction
did not return a usable actor store.

Direct native open/setup failures become a new unknown-outcome object with the
native object as suppressed context. The BEGIN-denial unknown is constructed
inside the transaction and reraised exactly by the constructor. Source refusal
and selected cancellation remain their exact unsuppressed objects. Object
identity, cause and suppression are asserted separately; a retained context
object does not prove that a diagnostic was rendered or delivered.

All thirteen interrupted controls have empty actor output, zero allocation
calls and zero public actor close calls. Separate local/reopened readback keeps
the seeded original, its charge sequence 1, event sequence 1 and zero effects.
The healthy baseline returns function value 0, delivers the original record and
an empty native report, and closes the actual handle. It executes four forwarded
transaction calls but observes two native authorizer callbacks; those counters
are measured separately and do not establish completed-statement count. The
inherited classifier records process status as unavailable for every in-process
control. No selected constructor failure has an installed actor observer or
an emitted native report.

The first focused run failed one new healthy-baseline assertion that equated
SQL-call and authorizer-callback counts. The original failed source, log and
result remain preserved. Separate forwarding-call instrumentation corrected
that assertion; the corrected focused run passes all fourteen methods. Full
final-source regression, artifact checks and fresh hosted execution are separate
gates recorded in the [Stage 109 snapshot](STAGE109_VALIDATION.md) and candidate
qualification. This correction adds no actor/store behavior change or retry.

Child/process status, operating-system signals, natural close failures, arbitrary
fault combinations, authenticated remote receipt, physical durability and chain
behavior remain unqualified. No output, exception chain, private flag or readback
observation authorizes replacement, retry, refund, nonce allocation, signing or
a physical effect. Stage 99's original cause remains UNRESOLVED;
application/core remain NO-GO.

## Constructor preconnection refusals

Stage 110 selects parent `cbf1b9e799071cddf65057e14a380f90ac900e87`, tree
`9f653a2481843a28873bd074dbc08957b58531db`. The original actor, store,
observer, classifiers and all 326 preceding sources remain unchanged.
[Twelve new in-process controls](../tests/test_policy_effect_constructor_preflight.py)
retain one previously charged original while selecting existing input guards.

Six controls enter the actual original actor with uppercase or numeric labels,
an empty or overbound string path, or an existing or dangling symlink. The
actor's constructor precedes its exception and cleanup guard: these refusals
produce no actor allocation, observer installation, reply or public close.
Process status is unavailable for this in-process harness. Empty output does
not mean that the independently seeded original was absent or refunded.

Six controls enter the actual store constructor directly with inexact labels,
a foreign path object, a string subclass, a bytearray provisioning profile,
noncanonical profile bytes, or a valid profile with a different authority
namespace. Foreign attribute, filesystem conversion and length hooks must
not run. These direct API cases do not assert that the actor accepts arbitrary
path objects or provisioning profiles; the actor passes a string and no initial
profile. Profile refusal is distinct from a failed attempt to recreate an
existing database. Native file provisioning and SQLite connect are never called.

Ten cases refuse before owner, labels, busy, closed and database fields exist.
Both symlink cases refuse after those fields exist: busy and closed are false,
database is None, and constructor disposal is never called. That partial
object is retained only by test instrumentation; no usable store is returned.
An absent disposal call at these guards is not evidence of a leaked connection.
The existing symlink and dangling symlink remain intact, and the latter's
target is not created. Paths and labels are temporary synthetic inputs.

The exact outward refusal survives the forwarding constructor wrapper. All
cases have no explicit cause; noncanonical profile bytes retain a suppressed
decode ValueError context while the other refusals have no context. Context
retention does not establish a rendered or delivered diagnostic. Each control
checks unchanged existing database bytes and directory entries, then separately
reads the complete local and reopened original: charge/event sequence 1,
one operation, zero synthetic effects and no effect sequence.

The first focused run failed only a new symlink assertion comparing a resolved
alias with an unresolved temporary-directory path. Its source, log and result
remain preserved. Resolving both sides corrects that test expectation; one
corrected focused run passes all twelve methods. No store or actor behavior
changes. Complete regression and artifact/source checks are separate gates
in the [Stage 110 snapshot](STAGE110_VALIDATION.md).

Symlink replacement races, native path-processing faults, operating-system
signals, child exit status, arbitrary inputs, authenticated delivery and physical
durability remain unqualified. No observation authorizes replacement, retry,
refund, nonce allocation, signing or a physical effect. Stage 99's original
failure cause remains UNRESOLVED; application/core remain NO-GO.

## Constructor path and provisioning boundaries

Stage 111 selects parent `41f83c46b693003f4c84ec1dd4da5e0f79245a44`, tree
`d93505337b4c7d079f7612ca703b3148cd624f94`. All 327 preceding sources,
including the original actor, store and observer, remain byte exact.
[Fourteen new controls](../tests/test_policy_effect_constructor_paths.py)
qualify eight original actor entries and six direct provisioning entries.

Selected EIO and cancellation at path absolute conversion or symlink inspection
precede the constructor's disposal guard. The exact primary survives, no
disposal or connection occurs, and the partial object's closed flag stays false
with a None database. The same selected classes at URI conversion follow the
guard: EIO becomes an unknown with suppressed exact primary context;
cancellation survives exactly. Both invoke disposal and set closed true without
a native SQLite handle. These method selections are explicit synthetic faults,
with actual pathlib calls forwarded at other boundaries. They do not qualify
natural filesystem EIO or operating-system signals.

Two actual actor paths target an owned directory or a child of a regular file.
Native SQLite open fails with primary CANTOPEN, normalized to an unknown with
the exact native error retained as suppressed context. No constructor returns,
observer installs, actor allocation/public close runs or actor reply is emitted.
In-process status is unavailable; empty output is not a refund or proof of zero
previous charges. Error-context retention is not diagnostic delivery.

Three direct valid-profile paths exercise actual exclusive file provisioning:
an existing source or directory produces EEXIST; a regular-file parent produces
ENOTDIR. One native file-open attempt, zero native file-close/SQLite-connect
calls and one disposal occur. Existing bytes and directory entries are unchanged.
These cases do not assert that the actor supports an initial profile.

Three further direct selections create a new synthetic file with mode 0600 and
successfully close its native descriptor before selecting post-close EIO or
URI EIO/cancellation. The closed descriptor is independently checked with
fstat/EBADF before readback. The new file remains present and empty; construction
does not return, no SQLite connection or original operation is allocated, and
disposal sets the store closed with no database. An empty reservation is not an
initialized store, a charge, a completion or permission to retry. The post-close
EIO is synthetic after successful native close, not a natural close failure.
Fixture cleanup closes only descriptors still owned by the test; it does not
replay a selected close or close an already released numeric descriptor.

Each control separately checks original database bytes, expected directory
entries, then complete local/reopened readback: one original, charge/event
sequence 1, zero effects and no effect sequence. A six-case local exploratory
run preceded these tests. Its overlong-component case is excluded from the
selected matrix inventory; no cross-runtime native path-error conclusion is
drawn from that local observation. Both focused versions passed fourteen
methods. The first successful source/log/result remain preserved after the
descriptor-ownership review; final-source regression is a separate gate in the
[Stage 111 snapshot](STAGE111_VALIDATION.md).

Arbitrary paths, descriptor-reuse races, symlink races, natural close failures,
signals, child status, authenticated delivery and physical durability remain
unqualified. No observation authorizes replacement, retry, refund, signing,
nonce allocation or a physical effect. Stage 99's original cause remains
UNRESOLVED; application/core remain NO-GO.


## Retained empty reservation refusal boundaries

Stage 112 carries the actual empty reservation from three selected direct
constructor interruptions into one explicit followup call. It reuses the
preceding control helper without altering its source or the actor/store/
observer behavior. The first synthetic selection follows successful native
provisioning and descriptor close; it is not a natural close fault. No file
is removed, replaced or reconstructed between the two phases. Each fixture
already contains one separately retained charged original with no effect.

Nine disjoint in-process methods cover three direct opens, three original
actor opens and three direct exclusive provisioning attempts. Opens execute
native SQLite connect, BEGIN IMMEDIATE, empty-schema validation, ROLLBACK and
one successful native close. The exact schema StoreRefused survives disposal
with no context/cause/suppression. The disposed database object remains present;
a direct native probe refuses on its closed connection. Provisioning instead
has one real EEXIST before SQLite connect: the outward StoreOutcomeUnknown
suppresses the exact FileExistsError context. Its database remains None.
Each followup disposes once, with no return, allocation or public close.

The actor is invoked in process with the same public-synthetic request form.
Its constructor refuses before observer installation and the actor's response
exception guard. Empty stdout and no observer call are checked; subprocess
status and delivered diagnostics are unavailable. Direct provisioning has no
actor initial-profile support. No exception or empty output becomes permission
for retry, replacement or treating the original as absent.

Every method checks unchanged original bytes and expected directory entries
before complete original readback. The reservation remains byte-exact empty,
mode 0600, with matching stat identity at the measured checkpoints. This does
not authenticate a path or qualify races between those checkpoints. Local and
reopened reads agree on one retained original, charge/event sequence 1 and
zero effects; the reservation is never an initialized replacement source.
Fixture cleanup owns unexpected native descriptors and connections without
replaying successful closes; normal fixture removal occurs after verification.

Earlier private unexecuted drafts and ownership review are preserved. Nine
separate local exploratory executions measure bytes and native paths on the
selected Python/SQLite runtime before final assertions; they are not independent
assessment or matrix evidence. The [validation snapshot](STAGE112_VALIDATION.md)
separates focused, complete local and fresh hosted gates.

Interrupted followup open/rollback/close, natural close failure, arbitrary
paths, descriptor/symlink races, signals, child delivery, authenticated
diagnostics, restores and physical durability remain unqualified. The original
Stage 99 failure cause remains UNRESOLVED. SC01-SC12 stay OPEN; physical
F1-F4/future A01-A12 stay NOT EXECUTED. Signer/custody, current-policy ownership
and a nonrollback anchor remain UNSELECTED / NOT IMPLEMENTED. Application/core
remain NO-GO; no runtime cleanup or automatic recovery policy is added.

## Retained reservation disposal boundaries

Stage 113 adds twelve disjoint in-process controls: six original actor entries
and six direct constructor entries. Each carries the same actual empty file
from successful native provisioning and descriptor close followed by selected
URI EIO into one explicit followup open. The preceding helper remains exact.
No file is removed, replaced or reconstructed between phases. Native connect,
BEGIN IMMEDIATE, empty-schema StoreRefused and successful ROLLBACK occur before
the disposal close wrapper selects a secondary error.

Three secondary kinds are selected before native close or after successful
native close. These are synthetic forwarding-wrapper selections, not naturally
failing native close calls. The measured distinctions are:

| Selected secondary | Timing | Outward exception | Private closed flag | Native handle before fixture release |
| --- | --- | --- | --- | --- |
| SQLite OperationalError | Before native close | Exact primary StoreRefused | True | SELECT 1 succeeds |
| SQLite OperationalError | After native close | Exact primary StoreRefused | True | ProgrammingError |
| OSError | Before native close | Exact secondary OSError | False | SELECT 1 succeeds |
| OSError | After native close | Exact secondary OSError | False | ProgrammingError |
| KeyboardInterrupt | Before native close | Exact secondary KeyboardInterrupt | False | SELECT 1 succeeds |
| KeyboardInterrupt | After native close | Exact secondary KeyboardInterrupt | False | ProgrammingError |

Each row is measured for both entries. SQLite secondaries are caught inside
disposal; the same primary survives outward without context, cause or
suppression. The fixture retains the caught secondary and verifies its exact
primary context, no explicit cause and no suppression. OSError and cancellation
escape with that same primary context instead. They interrupt the closed-flag
assignment even when the native connection was successfully closed. The stored
database object remains present in every case. A closed flag alone therefore
does not establish native closure; native closure alone does not establish
completion of the private disposal fields.

Each followup attempts construction once, disposes once and invokes the close
wrapper once. It never returns, allocates or invokes public close. Busy remains
false and current labels/process/thread owner remain exact. Actor cases execute
the original main with public-synthetic inputs, before observer installation and
the response guard. Empty stdout is checked; child status and diagnostic delivery
remain unavailable. The selected cancellation is an in-process object, not a
signal or interrupted child.

All methods compare original bytes, empty reservation bytes, mode 0600, stat
identity at checkpoints and exact directory entries before complete readback.
Local/reopened views agree on one original, charge/event sequence 1 and zero
effects. These are checkpoint observations, not atomic path continuity, physical
durability or race qualification. The reservation is never an initialized
replacement source.

Fixture ownership is separate from constructor state. Six before-close cases
retain a native handle until all observations and original readback finish; the
fixture then closes that handle once directly. Six after-close cases perform no
fixture native close. Registered cleanup never repeats a successful close. A
native closed-handle probe verifies the release without repairing store flags.
This test-only release adds no runtime cleanup, retry or recovery policy.

The earlier unexecuted draft and twelve local exploratory helper executions
remain separately recorded. One inline helper-preparation SyntaxError is retained
as a diagnostic excerpt and incident record; it did not alter final test sources
or cause a qualification retry. Focused, complete local and fresh hosted gates
are separated in the [Stage 113 snapshot](STAGE113_VALIDATION.md).

Interruption during open/rollback, natural close faults, arbitrary paths,
descriptor/symlink races, signals, child delivery, authenticated diagnostics,
restores and physical durability remain unqualified. Stage 99's original cause
remains UNRESOLVED. SC01-SC12 remain OPEN; physical F1-F4/future A01-A12 remain
NOT EXECUTED. Signer/custody, current-policy ownership and a nonrollback anchor
remain UNSELECTED / NOT IMPLEMENTED. Independent assessment is absent and
application/core remain NO-GO.
