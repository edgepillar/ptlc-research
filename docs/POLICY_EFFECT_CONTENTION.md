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

Stage 104 selects immutable parent `3cbd6845962e90469e10dd7b1bce05cb56f18f9b`,
tree `60bffb361eea423617be2ab9bdf2873bfdf197ed`. The store, original actor,
observer, classifiers and all preceding tests remain byte exact. A separate
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
manager or process interruption protocol. No terminal behavior is repaired here.
Reports remain unauthenticated synthetic evidence. None permits a replacement,
retry, refund, new nonce, signing or physical effect. See the separate
[Stage 104 validation snapshot](STAGE104_VALIDATION.md). The initial Stage 99
cause remains UNRESOLVED; all independent assessment and custody gates remain open.
