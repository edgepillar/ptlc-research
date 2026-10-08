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
`6920e0c090264e16abd9ad3b17e5c65d94c09ada`. Three original files remain byte exact:

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

## Remaining work

Retain the original failure as UNRESOLVED. Before attributing it, preserve the
failed original actors' response classes, native error phases/codes, complete
original request bindings and rows after bounded child termination. A future
diagnostic change must preserve the strict original safety assertions and
distinguish an availability expectation from the one-charge safety invariant.
Do not add retry/replacement behavior merely to make the assertion pass.

All historical review packets, primitive/journal bytes, dependencies, workflows
and custody proposals remain unchanged. Independent assessment is absent.
Physical F1-F4 and construction A01-A12 remain NOT EXECUTED; all SC01-SC12 stay
OPEN. Application/core, private signing and funded execution remain NO-GO.
