# Stage 19 validation: bounded observation records

Scope: define and implement pure attempt/claim history transitions before an
owned durable evidence backend is selected. Source parent:
`5c47ac8e715a4902f337d3837512f6ad9dc9c4ff`.

The new module handles canonical bytes, exact profile/target matching, finite
history, explicit unknowns and conflicting normal claims. It opens no files or
workers and modifies no recovery journal. This stage implements no durable
cache, owner lock, checkpoint, crash recovery or aggregate verification policy.
Canonical roundtrip is serialization evidence, not a filesystem/restart test.

Existing public verifiers, pipe runner, candidate/statement codec, journal,
recovery models, fixtures, dependencies and frozen review manifest are unchanged.
CI adds one actual-record qualifier to its existing Rust integration job; the
seven-job matrix, toolchain pins and deadlines stay unchanged.

## Executed checks

| Check | Result | Boundary |
| --- | --- | --- |
| Initial focused record suite | 34 tests, one failed subcase in 16.368 seconds | Test helper substituted a valid signature for explicit None |
| Corrected focused record suite | 34 passed in 16.480 seconds, no skips | Invalid-input test now calls the API directly |
| Actual record qualifier | 4 passed in 11.733 seconds | Selected existing local artifact/completion/observation workers and synthetic public inputs |
| Required full offline Python suite | 443 passed in 497.540 seconds, no skips | Prior 409 tests plus 34 new tests, required independent OpenSSL mode |
| Artifact, links and whitespace | Passed; 302 index/worktree file versions, 385 local links | Limited disclosure and consistency checks |

The first focused run failed only the explicit `None` subcase. Its test helper
used `None` to choose the default valid fixture, so that invalid input never
reached the API. The correction invokes `records.begin` directly for invalid
inputs. No production-module change was needed to resolve that failure. The
second focused run passed all 34 tests. Those runs cover the same cases, not 68
unique tests. The actual qualifier passed its first run without skips.

## Covered behavior

- Exact canonical schema, local profile and target fields, with independent
  evidence-key reconstruction and immutable summaries/byte values.
- Begin-before-result ordering, monotonic IDs and complete revision replay;
  duplicate pending work, wrong/late results, gaps, overlap and unreachable
  rechecks are rejected. Distinct targets can finish in another order.
- Pending and all finished outcomes consume quota. The exact 64-attempt boundary
  and target limits retain all history, with no reset, eviction or refund.
  Exhaustion rejects before local target preparation.
- Known normal claims need an explicit recheck. Pending/unknown rechecks preserve
  previous normal claims; equal normal decisions retain both attempts. Conflicts
  retain both decisions, return no selected claim and prohibit another begin for
  that key. These conflict tests use deliberately forged fixture claims.
- Malformed results leave pending work charged; interruption explicitly records
  unknown. Invalid signature/state, unsupported types, profile mismatch,
  malformed history, duplicate keys and alternate/oversized encodings fail.
- Pure transition/lookup tests forbid file open and worker creation. Actual
  qualifiers separately use real mathematical positives/negatives and actual
  process timeouts under a deliberately tiny configured deadline. This is not
  a throughput measurement or guaranteed hard wall-clock bound.
- Record operations preserve a reopened exhausted recovery journal's exact
  database/checkpoint bytes, sequence, retained candidate and consumed allowance.
  A recorded positive cannot invoke reconciliation under exhaustion.
- A forged positive for invalid bytes is accepted as a bound claim, exposing the
  producer-trust obligation. Restoring a valid earlier byte value replenishes
  pure quota, explicitly demonstrating the absence of anti-rollback/owner proof.

The finite quota tests use clearly labeled normalized-target oracles to avoid
repeating unrelated transcript validation in 64-step loops. These fixtures prove
record transitions only. Real-target binding cases and the separate actual
qualifier supply their own bounded evidence; neither supplies source authority.

## Execution and remaining gates

Local Python runs use Python 3.9.6 on macOS. Required full execution uses
`REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q`; artifact checks
use `python3 -B scripts/check_artifacts.py`.

The unchanged Rust/Go suites and prior actual-worker qualifiers are not rerun
locally for this pure record change. Hosted CI runs them, including the unchanged
55-case Rust suite, both Go modules and all earlier qualifiers. The new actual
qualifier selects already built local executables explicitly; test-time hash
measurement is not production enrollment or source/build attestation.

No disk evidence-store death, owner/concurrent-writer, storage divergence or
restore test is claimed here. Existing recovery-journal tests exercise their
own unchanged implementation. The [record contract](OBSERVATION_RECORDS.md)
states the required owned-backend ordering and failure cases for the next stage.
Trusted producer provisioning, source authority, aggregate resources, restored
copies and independent construction/delta assessment remain open. No private
signer, wallet, chain access, funded settlement or core activation is exercised.
