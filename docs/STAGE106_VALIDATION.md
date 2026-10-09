# Stage 106 original actor output loss

FINAL-SOURCE LOCAL REGRESSION PASSES; FRESH HOSTED QUALIFICATION PENDING AT THIS SNAPSHOT.

The selected immutable parent is `ed9a6cf1edffef2c295d9e7541ab91c69a9ce913`,
tree `a970c31b0444c48f2d4592b41739de4ef36adf2c`. The original actor, store SQL,
observer, classifiers, rollback fixture and all 322 preceding sources remain
byte exact. This stage adds eight methods in one test source and documents
existing behavior. There is no outcome conversion, retry or signing change.

Six controls call the actual actor in process with a real SQLite store and
locally drained operating-system pipes. They verify one constructor and one
allocation call, transaction authorizer trace, one terminal close on an open handle,
closed-handle refusal, separate local and reopened original/effect rows, and
the distinction between locally received bytes and normal completion.

| Selected control | Output and terminal boundary | Separate readback |
| --- | --- | --- |
| Real pipe baseline | Allocation record and empty native report; return 0 | One original charge, no effect |
| Reader closed before first reply write | Native EPIPE propagates as the same exception object; no reply/report | One original charge, no effect |
| Synthetic first flush fault after local delivery | Same selected EIO object propagates; record received, no report | One original charge, no effect |
| Reader closed before report write | Native EPIPE propagates; first record received, no report | One original charge, no effect |
| Synthetic report flush fault after local delivery | Same selected EIO object propagates; record and report received | One original charge, no effect |
| Reader closed before stale-policy refusal output | Native EPIPE propagates; no reply/report; native rollback completes | Zero originals and effects |

The two EIO controls are explicit synthetic flush faults. Writes are actually
drained by a local test receiver before the selected flush exception; this is
not qualification of a buffered transport, an authenticated peer, remote
receipt or a natural filesystem EIO. The EPIPE controls use an actual closed
pipe reader. An in-memory empty native execute report is asserted separately
from whether that report reached the output channel. Output exceptions are
outside the SQLite execute observer.

Two further methods launch the unchanged original actor directly in legacy
and observed modes with explicit Python `-u`. A readiness fence precedes the
command. The parent closes the only stdout reader before releasing that
command. Allocation commits before the subsequent native output write fails.
Both children naturally exit 1 with native `BrokenPipeError` stderr, no readable
outcome/report, one original charge and no effect after separate local and
reopened readback. No exception hook, status override, replacement actor,
authorizer denial or child retry selects that result. Children are reaped;
raw stderr is not echoed into public test diagnostics. In-process close counts
are not promoted into an observation of child cleanup before process exit.

The focused run passes eight methods in 0.145 s (runner 0.429 s), with required
OpenSSL and ResourceWarnings treated as errors. Complete final-source regression is recorded below; source preservation
and artifact hygiene remain separate gates.
There were no focused qualification failures or retries.

The [scope note](POLICY_EFFECT_CONTENTION.md#original-actor-output-loss)
distinguishes output delivery, command-cut reports, process status and retained
rows. Default buffered Python shutdown, process signals, simultaneous primary
and terminal faults, interrupted construction, arbitrary write fragmentation,
remote transport, restored copies and physical durability remain unqualified.
Neither missing output nor an exit code proves rollback, and a valid reply or
report does not prove normal completion. No observation authorizes a replacement
operation, refund, retry, nonce allocation, signing or physical effect.

Stage 99's original failure cause remains UNRESOLVED. SC01-SC12 remain OPEN;
physical F1-F4 and future A01-A12 remain NOT EXECUTED. Signer, custody,
current-policy ownership and a nonrollback anchor remain UNSELECTED /
NOT IMPLEMENTED. Independent assessment is absent. Application/core remain
NO-GO; this is offline synthetic research.

One complete run on the frozen final sources passes 2125 exact unique methods
in 1034.387 s (runner 1034.894 s), required OpenSSL,
no skips, failures or ResourceWarnings. All 2117 preceding IDs are retained and
eight disjoint IDs are added. All 322 preceding sources remain exact; one new
test source gives 323 frozen sources. Two documentation modifications and two
additions give 547 files, with 543 of 545 preceding files exact. There were no
preparatory or qualification failures and no qualification retry. Full
Rust/Go/Linux/Apple profiles were not rerun locally; fresh hosted execution and
independent assessment remain separate. Earlier failed logs and original
archives remain preserved without source or evidence cleanup.
