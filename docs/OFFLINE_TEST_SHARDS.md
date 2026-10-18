# Complete offline regression with bounded CI module shards

This changes test scheduling and outcome reporting. It changes no protocol,
cryptography, journal, fixture, original allowance or acceptance requirement.
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

## CI coverage and avoiding duplicate work

The two Python 3.11 profiles retain their complete serial unittest command, one
on Ubuntu and one on macOS. The two Python 3.13 profiles each use four separate
CI jobs. Their declared case counters must combine to exactly the complete
inventory for that platform/version, with no missing or additional executions.
This retains complete serial runs while partitioning the slower profiles.

The workflow still declares eight job definitions; matrix expansion now produces
19 jobs instead of 13. Offline jobs use at most eight simultaneous matrix slots.
Actual wall time depends on runner capacity, queueing and the selected source.
Only a fresh completed run can establish a timing improvement.

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
