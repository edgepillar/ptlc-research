# Complete offline regression with bounded CI module shards

This extends complete module scheduling to the Python 3.11 CI profiles. It
preserves every test, verifier, fixture, source pin and native evidence gate.
Only the workflow matrix and scheduling documentation change.
Application/core remain **NO-GO** and independent assessment remains **UNFILLED**.

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
simultaneous matrix slots. Rows interleave the four profiles within each shard
number so one Python version is not a separate first wave. Actual wall time
depends on runner capacity, queueing and the selected source. All 25 jobs, four
complete profiles, sixteen original regression streams and seven original native
artifact families remain required. Only a fresh completed run can establish a
timing improvement.

The extra post-regression comparisons execute once per platform/version, in
the `all` or `0` job. They are not repeated in the other three shards. Every
shard still checks artifact hygiene. Other native job definitions, source
profiles and original artifact families remain unchanged. No additional copy
of a full source tree or compiler cache is required by the shard runner.

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
