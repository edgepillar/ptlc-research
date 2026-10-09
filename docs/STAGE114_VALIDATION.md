# Stage 114: synthetic lease fixture input lifetime

This is offline synthetic qualification. Protocol requirements, construction
choices and observed implementation behavior remain separate. Independent
assessment is absent; application/core remain **NO-GO**.

The [main-push workflow](https://github.com/edgepillar/ptlc-research/actions/runs/37942867329)
for [the Stage 113 commit](https://github.com/edgepillar/ptlc-research/commit/ea2c96a574f1f39b6182df2c8c2674010edc1f6f)
completed with seven successful jobs and one failed Ubuntu/Python 3.11 job. Its 2206-method run
reported one error in the admitted lease transport positive test. The outward
error was WorkerError("public worker rejected the request"). Original child
diagnostics were discarded by the existing transport. The original full archive
and failure remain preserved; the original cause is **UNRESOLVED**.

## Selected fixture correction

The positive shell fixture previously printed and exited without consuming its
request. An independent controlled local native inner-transport experiment
reaped that child before input delivery and observed BrokenPipeError. A separate
fixture using only shell builtins to drain input until EOF remained alive before
delivery and returned the same exact synthetic output after delivery. This
demonstrates a selected fixture race; it does not establish the cause of the
earlier hosted error or a full guard-chain failure.

The positive lease transport fixture now drains input until EOF before printing
its unchanged synthetic output. The overflow control writes the same fixture,
preserving its measured pin and actual output-overflow path. No runtime, guard,
admission, timeout, ownership, cryptography or CI workflow behavior changes.

Two added controls exercise the real native inner pipe transport. One waits for
the nonreading child to exit successfully before delivering input and requires
the exact BrokenPipeError context, absent cause and suppressed context. The other
uses a bounded native wait to check that the draining child stays live before
delivery, then requires exact synthetic output and successful child exit.
Both assert one selected child, one controlled boundary and no group signal after
the known reap. These controls select explicit schedules; they establish no
arbitrary scheduling, hard process-creation bound or natural hosted reproduction.

## Validation gates

Focused final-source execution, complete frozen-source regression, artifact
checks and fresh hosted checks remain pending at this initial snapshot. All
preceding 2206 method IDs must remain, with two disjoint additions for 2208 total.
The preceding 330 source inventory intentionally revises only the lease test
fixture source; the remaining 329 sources must stay exact. No failed source,
log or original archive is removed, replaced or reclassified as success.

The separately prepared reservation-BEGIN candidate is deferred while this
observed main validation gate is addressed. Its private focused results are not
part of this stage's public method inventory or acceptance claim. Earlier
unresolved causes, open custody requirements and absent independent native
assessment remain unchanged. No observation authorizes signing, another payment
attempt, replacement, refund, broadcast, deployment or a physical effect.

Application/core remain **NO-GO**.

One complete final-source local run passes all 2208 exact unique methods in 965.719 s
(runner 966.183 s), required OpenSSL, no skips, failures or ResourceWarnings.
All 2206 preceding IDs remain; two disjoint IDs are added. One focused module
run passes 28 methods before source freeze, with no later test-source change.
All 329 other sources and 559 other prior files remain exact; 562 current files
require 1124 index/worktree checks. There is no final-source regression retry.
Full Rust/Go/Linux/Apple profiles are not rerun locally. Fresh hosted checks and
independent assessment remain separate gates. The earlier main workflow failure,
API poll error, helper-preparation SyntaxError and deferred candidate measurement
failure remain preserved. The original hosted child cause stays UNRESOLVED.
