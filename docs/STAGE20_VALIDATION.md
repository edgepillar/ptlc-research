# Stage 20 validation: separately owned observation storage

Historical version 1 evidence. [Stage 21](STAGE21_VALIDATION.md) changes the
current module to version 2 with cooperative worker-held leases and an owner
guard; existing version 1 pairs quarantine without migration or recovery.
The original checks and limitations below describe the Stage 20 source only.

Scope: add a separate local disk owner around the unchanged bounded record
contract and explicitly selected public observation adapter. Source parent:
`eda29365089ebf99008e779afaffbcbc3299015c`.

The store holds cooperating process/thread ownership before load and through
admission, selected work, result persistence and return. Matching pending state
recovers as charged unknown without worker replay; divergent pairs quarantine.
It accepts no peer statement or arbitrary callback and changes no journal or
recovery allowance. Record publishing is excluded after owner death; an orphan
public worker can still compute. This stage supplies no containment, power-loss,
paired-restore, hostile-host, source-authority or funded-availability proof.

Existing public verifiers, pipe runner, candidate/statement/record codec, session
journal, recovery models, fixtures, dependencies and frozen review manifest are
unchanged. CI adds one actual-store qualifier to the existing Rust integration
job; the seven-job matrix, toolchain pins and deadlines remain unchanged.

## Executed checks

| Check | Result | Boundary |
| --- | --- | --- |
| Initial focused storage suite | 37 passed in 34.155 seconds, no skips | Synthetic worker sequencing plus real SIGKILL, locks and fork/thread ownership |
| Final focused storage suite | 40 passed in 36.714 seconds, no skips | Additional target quota, cancellation checkpoint gap and pre-connect database bound; all BaseException cancellation persists unknown |
| Initial actual-store qualifier | 5 passed in 13.438 seconds, no skips | Selected existing local Rust executables and synthetic public inputs |
| Required full offline Python suite | 483 passed in 542.055 seconds, no skips | Prior 443 cases plus 40 new storage/ownership cases; required independent OpenSSL mode |
| Intermediate actual-store qualifier | 5 passed in 13.738 seconds, no skips | Recheck after cancellation handling was generalized |
| Final actual-store qualifier | 5 passed in 13.860 seconds, no skips | Result-loss marker records the actual verified outcome before SIGKILL |
| Artifact, links and whitespace | Passed; 318 index/worktree file versions, 402 local links | Limited disclosure and consistency checks |

Both focused suites passed their first run; no failed assertion or production
repair was needed. The initial 37 cases are a subset of the final 40, not 77
unique tests. The final pass generalizes committed cancellation from
KeyboardInterrupt/SystemExit to every non-Exception BaseException, including
GeneratorExit. New cases cover cancellation combined with a checkpoint gap,
target-slot exhaustion without eviction, and oversized databases rejected before
SQLite connect. Actual-worker qualification is separate from synthetic returns.

Source review also strengthened the actual result-loss actor's marker: it now
records the original adapter's returned outcome before the result boundary.
The final qualifier requires `verified` before SIGKILL, rather than observing
only that a worker call returned. This is additional test observability, not a
change to the store, mathematical worker or synthetic crash-matrix behavior.
All three actual-qualifier runs passed and cover the same five cases, not 15
independent cases.

## Covered behavior

- Pending records are visible in both database/checkpoint before a synthetic
  worker runs; result revision is committed before a normal can return. Actual
  mathematical positives and negatives are retained and reused after restart.
- Required local ID/profile/limits, bounded canonical history and pair equality
  precede retained-claim exposure and pending recovery. Invalid local targets,
  recheck choice, known targets and exhausted quotas invoke no worker and mutate
  no stored history. Attempt and target quotas never refund or evict records.
- Unknown retry/recheck preserves a prior normal. Contradictory synthetic normal
  decisions are both committed, then no claim or further work is selected.
  Malformed/cross-target worker returns become charged unknowns with no admitted
  foreign claim or normal negative inferred from failure.
- Caller cancellation commits unknown before propagating if storage succeeds.
  Uncertain persistence instead quarantines the handle and can quarantine the
  pair; worker diagnostics are not retained. A poisoned handle cannot retry,
  inspect or expose a claim before a separately successful locked reopen.
- An 11-point real SIGKILL matrix spans admission database/checkpoint commit,
  worker return and result database/checkpoint commit. Consistent pending work
  becomes charged unknown; database/checkpoint gaps quarantine. Existing normal
  claims survive a killed recheck and still drain the finite attempt budget.
- Lifetime locks precede SQLite reads and block another owner, another
  checkpoint for the same database, or another database for the same checkpoint.
  Owner death releases the tested persistent lock files without replacing them.
  Partial lock acquisition cleans up. A live paused publisher cannot be recovered
  by another owner; allowing it to resume retains its normal result exactly once.
- Foreign-thread, forked, closed and reentrant handles cannot inspect, mutate or
  close while violating ownership. A fork child's cleanup cannot unlock its
  parent's file description; the separate process probe remains blocked.
- Missing pair halves, wrong ID/profile/limits, malformed/oversized checkpoints,
  invalid database version/records, symlinks, nonprivate files and unsupported
  WAL/SHM sidecars fail closed. Oversized database files reject before connect;
  record BLOB length is checked before the bounded fetch.
- One-sided restores quarantine in both directions. A matching older pair
  explicitly replenishes quota and permits another synthetic call. This negative
  result demonstrates the unresolved rollback/clone boundary, not protection.
- Actual qualifiers exercise deadline unknown, restart/retry/recheck, changed
  selected entry rejection before launch, and owner death after actual worker
  return but before result persistence. Reopen never replays that lost result.
- An actual retained positive leaves a reopened exhausted recovery journal's
  exact state, database/checkpoint bytes, sequence, candidate and allowance
  unchanged; exhaustion still rejects reconciliation before any callback.

## Execution and remaining gates

Local Python execution uses Python 3.9.6 on macOS, with required full mode
`REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q` and artifact check
`python3 -B scripts/check_artifacts.py`. Focused suites discover
`test_observation_store*.py`. The actual qualifier selects already built artifact,
completion and observation executables explicitly; test-time entry measurement
is not trusted production enrollment or source/build/runtime attestation.

The unchanged Rust/Go suites and prior actual-worker qualifiers are not rerun
locally for this separate Python store. Hosted CI runs them, including the
55-case Rust suite, both Go modules and all earlier qualifiers, plus the new
actual-store cases. Preparing that CI definition is not hosted execution.

Process termination preserves the running host/filesystem and is not a power
cut. The tests exclude cooperating managed publishers; they do not establish
that every orphan/escaped descendant stops, hostile users cannot replace locks
or directories, or a network filesystem has the same behavior. Pairing hashes
and an expected public ID establish consistency only. Global resources, new
history admission, source authority, external restored-copy protection and
independent construction/producer/storage delta review remain open.

The [storage design](OBSERVATION_STORE.md) explicitly identifies the stronger
Stage 19 worker-containment requirement as unmet. No private signer, wallet,
node/chain access, funded settlement, core port, activation or upstream outreach
is exercised. The Stage 12 subject remains 119 files at
`e592633e4c630cfe3f4669876f6f63b80d2e33d6`; its manifest SHA256 remains
`df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295`.
