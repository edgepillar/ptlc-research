# Bounded local supervision of the complete module shards

The additive [local supervisor](../scripts/run_offline_shards.py) runs the four
existing module shard commands with an explicit limit of one to four child
processes. The default is two. It changes no existing test, fixture, verifier,
source-selection manifest, workflow job or assertion. It supplies no test result
cache. Each shard still uses the unchanged runner and its actual case events.

## Ownership and original streams

An enclosing qualification task must first reserve the combined fixture and
output allocation and provide an owned fixture parent. It must create eight
empty, private, independently owned regular output files: `0.stdout`, `0.stderr`
through `3.stdout`, `3.stderr`. Existing contents, symlinks, hard-link aliases
and publicly readable output files refuse before any child starts. Do not place
these files in a repository or reuse original evidence as an output target.

```text
python3 -B scripts/run_offline_shards.py \
  --streams owned-empty-stream-directory \
  --fixtures owned-fixture-parent --workers 2 --timeout 3600
```

The supervisor checks the empty output inodes and writes each child's raw pipe
bytes directly to its own file, with separate 4 MiB stdout and stderr caps. It
does not combine or re-encode those original streams. Its own stdout contains
only a bounded process summary with original stream hashes, lengths, capture
state and observed child exits. Retain each original once in the enclosing
task's object store and use manifest references, rather than a recursive ZIP.

Each child receives a distinct new temporary directory. Only an unchanged,
empty directory from a successfully completed child is removed. Nonempty,
failed or interrupted fixture directories remain held. The supervisor never
recursively cleans a fixture tree. A task manager must retain its ownership,
mount, quota, free-space and failure checks. This script is not an OS quota or
a sandbox for hostile child programs.

Children keep the enclosing process group and inheritable ownership leases.
On timeout, interruption or a stream cap, the supervisor stops launching queued
children, signals its own direct children, retains bounded output and records
actual wait status where observed. It never signals an unrelated process or
retries a shard. A descendant retaining a pipe past the bounded drain period
leaves incomplete capture. Direct-child termination does not prove that every
descendant is gone; uncertain ownership remains a hold for the enclosing task.

## Separate test acceptance

`PROCESS_EXITS_ZERO` means that all four direct children returned zero, their
streams reached EOF within the bounds and their temporary directories were
empty. A zero-exit program producing no test events can receive that process
summary. It cannot supply a passing complete regression.

Qualification must independently read all eight original files, verify hashes
and byte counts, and consume each unchanged shard's case events and final plan.
The four actual counters must have disjoint identities and equal the complete
discovered counter exactly, with only `ok` statuses. Reject missing, duplicate,
failed or skipped cases, partial output and ResourceWarnings. Bind the complete
source before and after execution. No serialized synthetic replacement for the
original shard streams supplies this evidence.

The [process controls](../tests/test_offline_shard_supervisor.py) exercise real
overlapping children, separate binary pipe bytes, bounded bursts, exact failure
exits, launch refusal, timeout, interruption before launch, the poll/signal exit
race, temporary isolation, held fixtures and output-path refusals. They establish
their selected process behaviors, not a complete protocol regression, hosted CI
acceptance or a whole-suite timing improvement.

Actual wall time depends on CPU, memory, filesystem and competing work. Reserve
for the combined peak before execution and measure complete fresh shard output
before claiming a timing improvement. No historical serial execution is relabeled
as a parallel run. Independent assessment remains **UNFILLED**; application and
core remain **NO-GO**.
