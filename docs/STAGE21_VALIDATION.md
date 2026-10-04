# Stage 21 validation: owned observation worker leases

Historical version 2 evidence. [Stage 22](STAGE22_VALIDATION.md) adds an explicit
shared admission pool and store version 3. Existing v1/v2 pairs quarantine without
migration or recovery. The original checks below describe the Stage 21 source.

Scope: retain the disk owner's two lock descriptions in a parent-watching guard
and selected cooperative nonforking public worker. Source parent:
`652e54824d32d4f230de822b2432becb20a01917`.

The store now uses version 2 and the v2 checkpoint domain. A consistent old v1
pending pair quarantines without automatic migration, recovery or rewrite.
Pending-before-work/result-before-return ordering, pure record transitions,
mathematical profile/predicate, Rust/Go sources, session journal, dependencies
and frozen review manifest remain unchanged. Legacy unowned adapters retain
their original path. No private signer, live RPC, network observation, funded
settlement, core port, activation or upstream outreach is exercised.

## Executed checks

| Check | Result | Boundary |
| --- | --- | --- |
| Initial legacy pipe suite | 15 passed in 3.626 seconds, no skips | Existing unowned transport after internal refactor |
| Initial adapted store suite | 40 passed in 37.773 seconds, no skips | Existing storage/ownership cases through the explicit owned method |
| Initial actual-store qualifier | 5 passed in 14.498 seconds, no skips | Existing selected local Rust executables with the guarded path |
| Initial new lease-suite launch | Failed before case execution | Test helper named run shadowed unittest.TestCase.run; corrected to run_guard |
| First new lease suite | 21 passed in 9.127 seconds, no skips | Native cooperative ownership and guard/owner death, plus invalid owned leases |
| Expanded lease suite | 23 passed in 13.237 seconds, no skips | Added guarded deadline and store cancellation cleanup |
| Final focused store suite | 41 passed in 37.413 seconds, no skips | Added valid old-v1 pending-pair quarantine without migration |
| Final focused lease suite | 23 passed in 13.237 seconds, no skips | Legacy control acknowledges leaving its hold loop before temporary cleanup |
| Final legacy pipe suite | 15 passed in 3.424 seconds, no skips | Compatibility with the unchanged direct adapter path |
| Required full offline Python suite | 507 passed in 556.267 seconds, no skips | Prior 483 plus 23 lease cases and 1 v1-pair quarantine; required OpenSSL mode |
| All seven actual-worker qualifiers | 47 passed, no skips | Existing local artifact/completion/authentication/observation executables |
| Artifact, links and whitespace | Passed; 330 index/worktree file versions, 421 local links | Exact publication candidates; limited disclosure/consistency checks |

The final actual-worker runs passed exchange 2 in 1.390 seconds, completion 9
in 34.370 seconds, authentication 11 in 23.785 seconds, recovery-model replay 9
in 51.731 seconds, observation 7 in 13.257 seconds, pure records 4 in 11.884
seconds and owned store 5 in 14.308 seconds. They exercise the refactored
legacy runner and guarded store separately; none failed or skipped. Rust/Go
primitive source tests are unchanged and are left for hosted execution.

The failed initial lease-suite command executed no test case and supplied no
implementation evidence. The corrected initial 21 cases are a subset of the
final 23; repeated passes are not additional unique cases. Source review also
fixed a potential missing-descriptor fallback before the new adapter test was
run: observe_owned uses an explicit owned flag, so None never selects legacy
transport. The guard resets its own SIGCHLD handling; the outer caller's
exclusive reaping premise remains required. No failed cryptographic assertion
or cryptographic implementation repair is involved.

## Covered behavior and evidence limits

- A normal controlled worker receives exactly two expected private lock
  descriptors, not an unrelated open file. Parent inheritable flags remain
  unchanged. Invalid types/counts, duplicate file identity, nonprivate files,
  pipes, invalid pins and bounds reject before guard launch where applicable.
- The guard repeats selected-entry measurement. Pin mismatch, spawn failure,
  invalid guard arguments and output overflow are unavailable work with
  sanitized errors. A successful/reaped guard is never signaled via a cached
  group identifier. Owned None/invalid leases cannot launch or fall back.
- Native owner SIGKILL stops cooperative work while waiting for output, after
  stdout EOF, and while the worker never consumes a full input request. These
  tests require lease release without creating the worker's cooperative release
  file, so ordinary completion is not substituted for owner-loss cleanup.
- Native guard SIGKILL after worker launch deliberately leaves a worker holding
  the two leases. The owner's own reference close must not unlock them. Store
  reopen returns busy before SQLite connect until the controlled worker exits;
  the charged unknown then reopens without replay or a retained normal claim.
- Killing either process before input handoff produces no selected-worker
  marker and preserves charged unknown ordering. Guarded deadline and caller
  cancellation exercise cleanup, retaining charges without normal negatives.
- The legacy control receives zero lease descriptors and remains unguarded.
  Its private release acknowledgment prevents deleting the test directory while
  its hold loop can still access it. Test controllers signal only their owned
  unreaped child; they never kill a cached worker/guard PID from a marker.
- A consistent synthetic old-v1 pair containing pending work remains byte-for-
  byte unchanged on quarantine, with no invocation or automatic conversion.
  Earlier crash/configuration/rollback tests continue to exercise the v2 owner.

Runtime marker PIDs and temporary paths remain private test coordination, never
checked-in fixture values, statement fields, record metadata or public logs.
Synthetic actors prove ownership/transport only; actual Rust qualification is
the separate mathematical evidence. Process termination preserves the running
host/filesystem and establishes no power-loss durability.

## Execution and remaining gates

Local Python is 3.9.6 on macOS. Full mode is
`REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q`. Focused discovery
selects test_worker_leases.py, test_observation_store*.py and test_public_worker.py.
Actual qualifiers select already built local executable paths explicitly;
their entry measurement is not trusted provisioning or build/runtime attestation.
The unchanged seven-job CI matrix covers Linux/macOS Python 3.11/3.13, Rust 1.90.0
and both Go modules. Preparing a matrix or running locally is not hosted evidence.

The [lease design](OBSERVATION_LEASES.md) distinguishes owner-death monitoring
from retained worker exclusion. A killed guard or an uninterruptible worker can
leave computation and ownership alive. A malicious worker can close/unlock its
leases or escape; no sandbox, arbitrary-tree containment or hard wall-clock
bound is supplied. Host/runtime trust, filesystem behavior, aggregate resources,
fair scheduling, new-history admission, matching pair rollback, source authority
and funded recovery policy remain independent open gates.

The Stage 12 subject remains 119 files at
`e592633e4c630cfe3f4669876f6f63b80d2e33d6`; manifest SHA256 remains
`df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295`.
External independent assessment and the later producer/storage/guard delta
assessment remain pending. This stage supplies no production or activation
approval.
