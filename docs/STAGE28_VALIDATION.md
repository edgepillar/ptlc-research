# Stage 28 validation: explicit v4 restore counterexamples

Scope: test-only coherent pair rewind, copied history, conflict retention and
single-sided quarantine; four added actual-Linux qualification methods.
Application code, journal, mathematical records, cryptography, worker/store/
pool/resource formats and locked dependencies are unchanged. No restore,
migration, reset, enrollment or monotonic authority is implemented.

Source parent: [`421cdabb21473c0a4746faafd6c53b27d4c60aaf`](https://github.com/edgepillar/ptlc-research/tree/421cdabb21473c0a4746faafd6c53b27d4c60aaf).
Its [seven successful exact-head jobs](https://github.com/edgepillar/ptlc-research/actions/runs/37203390291)
ran 636 Python tests per Linux/macOS 3.11/3.13 job, required OpenSSL, 55 Rust
tests, 13 Go top-level tests and 64 actual-worker cases including 13 v4 cases.
This prior execution does not execute the new restore delta.

## Local checks

| Check | Result | Boundary |
| --- | --- | --- |
| First new restore suite | 7 ran in 11.343 seconds; 6 passed, 1 failed | A fixture expected conflicting targets to count as both unambiguous normal totals; application behavior was correct |
| Corrected restore suite | 7 passed in 12.181 seconds, no skips | Correct summary partition plus both persisted contradictory outcomes and unchanged conflicting-history reopen |
| Full required offline suite | 643 passed in 715.350 seconds, no skips | OpenSSL required; existing lifecycle, process-death, native/refusal and complete-inventory checks remain included |
| Artifact, local links and whitespace | 396 index/worktree versions, 198 tracked files, 620 valid local Markdown links; whitespace clean | English/ASCII and disclosure checks; two affected Python files parse; both exact frozen manifest hashes unchanged |

The failed fixture expected `(verified_claims, rejected_claims) == (1, 1)` for
one contradictory target. The record summary intentionally reports `(0, 0)`
and one conflict; SQLite retains both outcomes. The corrected test requires both
persisted outcomes, conflict on healthy reopen, no rewrite and loss of the later
conflict only after coherent old-pair rewind. No application behavior or normal
verdict requirement was weakened to pass the suite.

The seven methods separately cover empty-pair quota replenishment, erasure of a
later charged unknown recheck, erasure of a synthetic normal conflict, both
single-sided mismatches, same-pool copied histories, repeat pending recovery
without replay/refund and wrong mode/resource refusal before SQLite. Real local
files, SQLite and locks are exercised; host selection and verdict callbacks are
synthetic. Neither mathematical validity nor native Linux enforcement follows.
An unchanged healthy reopen still performs no extra write or work.

## Hosted and independent gates

The [expanded actual qualifier](../scripts/qualify_observation_resource_store.py)
has 17 top-level methods, including four restore methods that require actual
limited Rust positives. The normal-history rewind case injects publication loss
only after an actual verified return, then requires another actual positive
after restore. All four cases separately preserve source-journal state,
sequence and both file bytes. Identical-profile copies use the same physical
pool and sequential work, not a simultaneous-computation or global-capacity test.

Native Linux actual verdict/resource checks are not run locally on macOS.
Rust/Go primitives and dependencies are unchanged and are not rerun locally for
this qualification delta. Completed exact-head logs must establish all seven
hosted jobs, including four required Python/OpenSSL jobs and all nine actual
worker groups with 68 cases. Configured workflow, a fixture positive or a parent
run supplies no execution of this delta; hosted results must be recorded
separately from this source report.

The original 119-file construction subject and separate 189-file observation
subject are unchanged. This later qualification lies outside both inventories
and does not extend either unfilled independent assessment. The
[restore design](RESOURCE_STORE_RESTORES.md) preserves external freshness,
enrollment, native storage, aggregate-resource, construction and funded
availability obligations. Private signing, chain integration, core port and
activation remain no-go.
