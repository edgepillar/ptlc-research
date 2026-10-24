# Complete offline regression with bounded CI module shards

The workflow schedules complete module groups for all four CI profiles. Module
weights use normalized case-clock measurements; the matrix include order retains
the separate historical ordering refresh below. A weight changes module placement.
Every test, verifier, fixture, source pin and native evidence gate is preserved.
Application/core remain **NO-GO** and independent assessment remains **UNFILLED**.

## Normalized module weights

The hint table uses the four Ubuntu/macOS and Python 3.11/3.13 profiles in
[attempt 39997915069/1](https://github.com/edgepillar/ptlc-research/actions/runs/39997915069/attempts/1)
at source [`88ae2fc`](https://github.com/edgepillar/ptlc-research/tree/88ae2fcf219c8bd6154d77c2068b6c5c2ad7b867).
Each original profile reports the complete 4,322-case inventory across 211
modules. The retained original console archive has SHA-256
`46f345fddda5b4a48cb4dfe9b88c193e0cb505524c241ecac997786f296e8fcd`.
These are source-selected clock data, not independent execution authentication.

For each profile, divide a module's recorded case seconds by the sum of that
profile's module case seconds. Take the mean of the four fractions, multiply
by 1,000,000 and round upward to a positive integer. Normalizing before averaging
keeps a slower profile from dominating the table solely through its overall
elapsed time. All 211 measured modules have explicit hints. Future modules still
run with the existing default weight of one.

The deterministic greedy partitioner, four groups, discovered module suites,
test order inside each module, assertions and complete case counters are unchanged.
No test result is cached and no native input or verifier is replaced.

Reassigning these same recorded case times gives the following **retrospective
case-load model**, expressed as the largest group divided by the mean group:

| Clock profile | Previous weights | Refreshed weights |
| --- | ---: | ---: |
| macOS / Python 3.11 | 1.163241 | 1.048157 |
| macOS / Python 3.13 | 1.297800 | 1.077317 |
| Ubuntu / Python 3.11 | 1.245905 | 1.038534 |
| Ubuntu / Python 3.13 | 1.258937 | 1.059353 |

Class setup, teardown outside case clocks, runner availability, queueing and
other-job interactions are excluded. This is calibration against existing data,
not a future wall-time prediction or measured speedup. Fresh complete local
regression, artifact checks, exact-head PR CI and separate push/main acceptance
remain required. Current workflow acceptance includes the eighth
[explicit 5cb original-artifact family](NOM_DEV_5CB_NATIVE.md).

## Measured baseline and scheduling choice

The complete serial price-checkpoint regression ran 3799 tests in 3793.736
seconds, with no skipped tests or ResourceWarnings. Its original output remains
retained. In the separately accepted
[main run 39129729442](https://github.com/edgepillar/ptlc-research/actions/runs/39129729442),
the Ubuntu/Python 3.13 completed-test output spans approximately 152 minutes.
Inter-completion timestamps attribute most of that span to six checkpoint/anchor
modules. Buffering and class setup affect this attribution; these are scheduling
hints, not a complete per-test CPU profile or a speed guarantee.

The [runner](../scripts/run_offline_shard.py) assigns complete test files to four
groups, using deterministic greedy balancing and explicit historical weights.
Every unmeasured or new test file still runs. A weight changes only placement;
it cannot make an assertion pass, remove a case or supply verification evidence.
The frozen historical tests, fixtures and source-selection manifests stay intact.

Module suites retain their discovered structure, setup and teardown. Cases in
one module keep their normal order and process. The runner does not cache a
validation result, share writable fixture owners or replace a test's verifier.
Each selected case executes through the normal unittest machinery.

## Completed Python 3.11 scheduling evidence

In the completed [predecessor run 39176682345, attempt 1](https://github.com/edgepillar/ptlc-research/actions/runs/39176682345),
each serial Python 3.11 regression covered 3866 tests. The selected test-step wall
times were 5311 seconds on Ubuntu and 5534 seconds on macOS. The original
nineteen-job archive was separately accepted with four complete profiles and
seven original artifact families. These values exclude setup outside that step;
they are neither CPU measurements nor a controlled comparison across Python
versions or hosts. No speedup is established for this new scheduling subject.

The follow-up matrix applies the existing four-module-group plan to both Python
versions. It adds no result cache, test filter, relaxed assertion or verifier
substitution. New hosted timing and complete case coverage must be measured on
the exact new subject before claiming an improvement.

## CI coverage and avoiding duplicate work

Each of the four Ubuntu/macOS and Python 3.11/3.13 profiles uses four separate
CI jobs. All sixteen actual regression streams must combine into four complete
case counters, one per platform/version, with no missing, additional or duplicated
execution. The serial `--shard all` command remains available for local diagnosis;
historical serial results keep their original scopes and are not relabeled as
new executions.

The workflow still declares eight job definitions; matrix expansion produces
25 jobs instead of 19. Offline jobs retain the existing maximum of eight
simultaneous matrix slots. The include list places larger observed jobs first,
using the larger whole-job wall time for each combination in the current
same-source timing pair below. These static weights change only job creation order. GitHub's
[matrix documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations)
does not guarantee runner start order or a timing improvement. Actual wall time
depends on runner capacity, queueing and the selected source. All 25 jobs, four
complete profiles, sixteen original regression streams and eight original native
artifact families remain required. Only a fresh completed run can establish a
timing improvement.

The extra post-regression comparisons execute once per platform/version, in
the `all` or `0` job. They are not repeated in the other three shards. Every
shard still checks artifact hygiene. Other native job definitions, source
profiles and original artifact families remain unchanged. No additional copy
of a full source tree or compiler cache is required by the shard runner.

## Historical ordering model and its limits

The selected samples are the completed
[main attempt 39327752895/2](https://github.com/edgepillar/ptlc-research/actions/runs/39327752895/attempts/2)
at `5ed6b08e278a33805dde12f8f1813fc935cb375b` and
[PR attempt 39350748946/1](https://github.com/edgepillar/ptlc-research/actions/runs/39350748946/attempts/1)
at `20a9c0740547a8df12d0b66a93301e46b01366fd`. Their complete profiles contain
3977 and 4023 cases respectively. This is a scheduling heuristic across different
subjects and hosts, not a controlled performance comparison.

In a simulation with eight identical, continuously available slots, each job
uses its original whole-job elapsed time from the selected attempt:

| Timing sample | Previous include order | Proposed include order |
| --- | ---: | ---: |
| Main attempt 39327752895/2 | 4227 seconds | 3773 seconds |
| PR attempt 39350748946/1 | 4412 seconds | 3992 seconds |

These are simulated matrix completion times, not observed runs of the new
workflow. Ordering from only the older sample would instead model 4465 seconds
on the newer sample, so a single observed ranking is not treated as stable.
The selected order uses the maximum of the two observations for each job.
Two samples do not establish that this heuristic will improve future runs.

The model excludes runner availability, scheduling guarantees, interactions with
the other workflow jobs and future source effects. The longest non-matrix jobs
took 4316 and 2279 seconds in those attempts. In particular, the older attempt's
non-matrix job already exceeds both simulated matrix times, so a shorter matrix
alone would not reduce that model's whole-workflow bound. No future speedup,
runner-minute saving or storage reduction is claimed from this permutation.
No test selection, timeout, assertion, concurrency limit or artifact gate changes.

## Previous same-source ordering refresh

The previous order used two separately accepted attempts at the identical
[`9564b1f` source](https://github.com/edgepillar/ptlc-research/tree/9564b1f297b65c3a15d2834f6f143468fd042581):
[PR run 39539404914/1](https://github.com/edgepillar/ptlc-research/actions/runs/39539404914/attempts/1)
and [main run 39543559956/1](https://github.com/edgepillar/ptlc-research/actions/runs/39543559956/attempts/1).
Each passed all 25 jobs; original archives bound four complete 4,079-case profiles,
sixteen regression streams and seven artifact families. The source and test bodies
match between these timing samples. Their original archives and failures from
other attempts remain separate.

Sort the same sixteen include entries by the larger observed whole-job duration
in this pair, with the job name as a deterministic tie-break. The eight-slot limit,
module partitions, commands, assertions, timeouts, source pins and artifact gates
are unchanged. The former samples and model above remain historical evidence;
they no longer determine the current include order.

| Same-source timing sample | Previous include order | Refreshed include order |
| --- | ---: | ---: |
| PR attempt 39539404914/1 | 1984 seconds | 1748 seconds |
| Main attempt 39543559956/1 | 2015 seconds | 1823 seconds |

These are **simulations with eight identical available slots**, using fixed
historical whole-job durations. They are not observed executions of the new
order or a controlled speedup. The longest other jobs took 1409 and 1022 seconds
respectively; those durations also do not predict future workflow time.

GitHub documents matrix job creation and the concurrency bound, while runner
start order and availability remain external scheduling conditions. Fresh PR and
separate main-push acceptance must still establish exact source and complete case
coverage. This permutation adds no source-tree or compiler-cache copy, removes no
test execution and claims no runner-minute saving or physical disk reclaim.
Application/core remain NO-GO; independent assessment and AS1-AS7 remain UNFILLED.

## Historical ABI-source ordering refresh

The retained include order uses the separately accepted
[PR attempt 39679784309/1](https://github.com/edgepillar/ptlc-research/actions/runs/39679784309/attempts/1)
and [main attempt 39688222624/1](https://github.com/edgepillar/ptlc-research/actions/runs/39688222624/attempts/1)
at the identical [`062585f` source](https://github.com/edgepillar/ptlc-research/tree/062585f2ca6587fc7b8b894b587c74ff3e270a38).
Both passed all 25 jobs. Their original archives bound four complete 4,158-case
profiles, sixteen actual regression streams and seven original artifact families.
The module weights, test bodies and module assignments match between the pair.
The earlier orders above remain historical evidence.

The same sixteen include entries were sorted by the larger observed whole-job
duration in this pair, with the job name as a deterministic tie-break. That
ordering refresh kept module weights and partitions unchanged: a separate
median-normalized proposal projected a 2.25% and 2.87% case-clock maximum increase
for the two macOS Python 3.11 samples. That proposal was not selected by the
ordering refresh. The normalized module table above is a separate later change.
Case clocks exclude class setup and are not complete job timings.

| Same-source timing sample | Previous include order | Refreshed include order |
| --- | ---: | ---: |
| PR attempt 39679784309/1 | 2058 seconds | 1916 seconds |
| Main attempt 39688222624/1 | 2025 seconds | 1935 seconds |

These are simulations using eight identical, continuously available slots and
fixed original whole-job durations. The longest other jobs took
1787 and 1898 seconds respectively.
The model excludes runner availability, queueing, actual start order, other-job
interactions and future source effects. It is not an observed execution of the
new order or a controlled speedup. GitHub's
[matrix documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations)
describes job creation and the concurrency bound; those mechanisms do not qualify
future runner availability or this model's assumptions.

The eight-slot limit, all sixteen combinations, assertions, timeouts, source pins,
commands and artifact gates remain unchanged. Fresh PR acceptance and a separate
main-push acceptance remain required, including all four complete case counters.
This permutation introduces no source-tree or compiler-cache copy and makes no
runner-minute saving or physical disk reclaim claim. Application/core remain
NO-GO; independent assessment and AS1-AS7 remain UNFILLED.

## Actual outcome protocol

Each case emits one complete `PTLC_CASE=` JSON array containing its unittest
identifier and final status. A final `PTLC_SHARD_RESULT=` record binds the plan,
complete and selected case-counter digests, test-source digest, selected modules,
actual counters, status counts and elapsed time. Case clocks exclude class
setup; the complete elapsed clock includes it. These timings are diagnostic.

Successful qualification requires every selected case to finish with exact status
`ok`, the exact declared multiplicities and the declared count. Skips, expected
failures, unexpected successes, failed subtests, class setup errors, missing
outcomes and duplicate executions cannot provide a passing shard. Standard
unittest errors and tracebacks remain available. Optimization is refused before
discovery because disabling assertions would alter the tests being qualified.

The counter digest is not source authentication or proof that a producer ran
the tests. Hosted acceptance must separately bind the immutable project subject,
workflow, run/attempt, all required jobs and complete original logs. The existing
native original-artifact checks still apply. A larger matrix, matching counters
or a passing scheduler unit test does not discharge independent assessment.

## Local use and storage scope

Discover the complete plan without running test methods:

```text
python3 -B scripts/run_offline_shard.py --plan
```

Run one explicitly selected group, or the complete inventory:

```text
python3 -B scripts/run_offline_shard.py --shard 0
python3 -B scripts/run_offline_shard.py --shard all
```

Use owned qualification storage and explicit resource reservations for local
execution. Independent jobs need separate mutable temporary fixtures. Count
their combined reservations and retain the production free-space floor; do not
lower quotas or interrupt another owner to start a shard. A partial or failed
shard remains unqualified, with its actual exit and available original output.

This scheduling change deletes no historical cache, failed evidence or original
CI archive. It does not claim physical disk reclaim. Original transcripts and
newly generated, reproducible derived summaries remain different retention roles.
Any separate lossless encoding of operator-generated summaries must preserve all
bytes and retain its own bounded decoder, integrity and failure qualification.
