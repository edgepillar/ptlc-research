# Stage 107 original actor buffered shutdown

FINAL-SOURCE LOCAL REGRESSION PASSES; FRESH HOSTED QUALIFICATION PENDING AT THIS SNAPSHOT.

The selected immutable parent is `e0fb3e9492e8bfb50040f341ccbb4ab4f5763e89`,
tree `120bbe9f7b4fe2075aac8ed204d39240bed4017e`. The unchanged original actor,
store, observer, classifiers, strict tests and all 323 preceding sources remain
byte exact. One new source adds ten unique methods which qualify selected
POSIX CPython child behavior. There is no application, signing, transaction,
cleanup or retry change.

Default buffered launch omits `-u` and removes `PYTHONUNBUFFERED` from the child
environment. Paired unbuffered launch explicitly adds `-u` with the same
override removal. Both execute the actual original actor directly with
ResourceWarnings treated as errors. A readiness fence precedes command release;
selected loss controls close the only stdout reader before releasing it.
No actor wrapper, exception hook, stdout replacement, selected exit override,
SQL denial or child retry chooses the result.

| Selected invocation, each in legacy and observed modes | Output and actual status | Separate local/reopened readback |
| --- | --- | --- |
| Buffered successful allocation, reader open | Exact record; observed mode adds empty report; exit 0, no stderr | One original charge, zero effects |
| Buffered stale-policy refusal, reader open | Exact refusal; observed mode adds empty report; exit 20, no stderr | Zero originals/effects |
| Buffered successful allocation, reader lost | Primary traceback and separate ignored-exception diagnostic, two BrokenPipeError labels; exit 120; no readable outcome/report | One original charge, zero effects |
| Buffered stale-policy refusal, reader lost | Same selected diagnostic classes and exit 120; no readable outcome/report | Zero originals/effects |
| Unbuffered stale-policy refusal, reader lost | One primary BrokenPipeError label, no ignored-exception marker; exit 1; no readable outcome/report | Zero originals/effects |

These ten controls keep process status, output classification and separately
retained rows distinct. The same empty response class and exit 120 occur both
with and without a retained original charge. Exit 1 on the new unbuffered
refusal controls is separate from Stage 106's unchanged unbuffered committed
allocation controls. The observed-mode fault controls have no received native
report; an empty report from a baseline cannot fill in that missing observation.
Children are bounded and reaped; raw stderr is retained only in private process
memory and never echoed into public test diagnostics. Failed assertions expose
fixed labels, counts or synthetic output rather than a raw native traceback.

Pinned upstream CPython 3.13.0
[finalization handling](https://github.com/python/cpython/blob/60403a5409ff2c3f3b07dd2ca91a7a3e096839c7/Modules/main.c)
and [stream flushing](https://github.com/python/cpython/blob/60403a5409ff2c3f3b07dd2ca91a7a3e096839c7/Python/pylifecycle.c)
provide static mechanism context. No external source code is copied, and this
pin does not establish the build provenance of any executed interpreter.
The diagnostics do not establish exact flush-call count, native buffer contents,
cross-process exception identity or actor cleanup order. Readback does not
establish physical durability or authenticated remote receipt.

The focused run passes ten methods in 0.536 s (runner 0.77 s), with required
OpenSSL and ResourceWarnings treated as errors. There were no focused failures
or retries. Complete final-source regression is recorded below; source preservation
and artifact hygiene remain separate gates.

The [scope note](POLICY_EFFECT_CONTENTION.md#original-actor-buffered-shutdown)
keeps selected launch behavior separate from arbitrary simultaneous terminal
faults, process signals, fragmented transport, restored copies and physical
durability, which remain unqualified. No missing output, exit code or readback
observation authorizes replacement, retry, refund, nonce allocation, signing or
a physical effect.

Stage 99's original failure cause remains UNRESOLVED. SC01-SC12 remain OPEN;
physical F1-F4 and future A01-A12 remain NOT EXECUTED. Signer, custody,
current-policy ownership and a nonrollback anchor remain UNSELECTED /
NOT IMPLEMENTED. Independent assessment is absent. Application/core remain
NO-GO; this is offline synthetic research.

One complete run on the frozen final sources passes 2135 exact unique methods
in 1011.017 s (runner 1011.508 s), required OpenSSL,
no skips, failures or ResourceWarnings. All 2125 preceding IDs are retained and
ten disjoint IDs are added. All 323 preceding sources remain exact; one new
test source gives 324 frozen sources. Two documentation modifications and two
additions give 549 files, with 545 of 547 preceding files exact. There were no
qualification failures or qualification retries. A private publication-body
preview started before local commit metadata was available and failed; its
dependent read also failed. Original diagnostics and the executed helper are
preserved. The unpublished local commit was amended once to record these two
preparation failures before the first push; tested sources remain exact. Full
Rust/Go/Linux/Apple profiles were not rerun locally; fresh hosted execution and
independent assessment remain separate. Earlier failed logs and original
archives remain preserved without source or evidence cleanup.
