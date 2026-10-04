# Stage 18 validation: explicit local observation verdicts

Scope: qualify a separate public-only normal-positive/normal-negative worker and
an explicitly pinned local adapter for the Stage 17 statement contract.
Source parent: `aa447e6bfabc5b968d4c63d480bdaf4f498263fc`.

The existing completion and artifact verifier source, journal, candidate codec,
recovery models, public fixtures, dependency manifests/locks and frozen review
manifest are unchanged. The new worker reuses existing pure cryptographic
checks after a complete shape guard; no arithmetic or signing API is added.
CI adds one actual-worker qualifier to its existing Rust job, with the same
seven-job matrix, toolchain pins and deadlines.

## Executed checks

| Check | Result | Boundary |
| --- | --- | --- |
| Focused Python adapter/process suite | 13 passed in 23.295 seconds (final focused run) | Synthetic actors establish transport and binding behavior, not mathematical truth |
| New Rust verdict suite | 8 passed, 0 failed/ignored | Public fixtures and fixed-domain adversarial checks |
| Full locked offline Rust suite and formatting | 55 passed, 0 failed/ignored; formatting passed | Prior 47 tests plus 8 new tests; existing examples also built |
| Actual observation qualifier | 7 passed in 13.531 seconds | Selected locally built artifact/completion/observation workers, public fixtures and temporary journals |
| Required full offline Python suite | 409 passed in 477.496 seconds, no skips | Prior 396 tests plus 13 new tests, required independent OpenSSL mode |
| Artifact, links and whitespace | Passed; 292 index/worktree file versions, 370 local links | Limited disclosure and consistency checks |

All completed focused, Rust and actual-observation runs passed with no failed
or skipped cases. The initial Python focused run passed the same 13 tests in
23.711 seconds; the final run follows a sanitized constructor-error refinement.
Repeated focused runs and focused/full Rust runs cover the same cases, not new
unique tests. No intermediate compile or assertion failure occurred. The required full run
passed without skips; the final focused run also covers the later constructor
error-message refinement. No local test was removed or made optional.

## Covered behavior

- Exact positive/negative result schemas, request hash and optional single LF.
  No witness, Bitcoin signature or response-selected profile is exported.
- Fixed-width zero, out-of-range and foreign-leg signatures yield normal
  negatives; the same legacy completion invocation fails without a verdict.
  Invalid keys, nonce/partial roles, bundle values and aggregation also reject.
- Unsupported schemas/modes, malformed hex widths/types, array shapes,
  duplicate keys, alternate encoding, non-ASCII and oversized requests are
  unavailable, not normal negatives. Actual process failures confirm the exit
  distinction; no observed panic injection or allocator-failure claim is made.
- Explicit expected entry-file hash and independently reconstructed profile;
  changed/removed/FIFO entries become unknown without launch. Empty/oversized
  measurements and invalid local selection/deadlines are rejected.
- Actual synthetic pipes cover malformed/legacy/cross-request responses,
  nonzero exit even with matching negative stdout, timeout with direct-child
  reaping, stderr suppression, overflow and exact request delivery. Adapter
  cancellation tests inject caller cancellation and require propagation; the
  existing pipe suite separately tests cleanup at its own process boundary.
- Real verdicts after reopen preserve exact public database/checkpoint bytes,
  sequence, pins, budget, exposure and retained history. A normal positive for a
  replacement cannot invoke recovery under exhaustion or change the original.
- Context digest rebinding changes the request hash without preventing a
  mathematical positive, making the separate source/authentication obligation
  explicit. Matching statement hashes remain forgeable claims when received.

## Execution and independent limits

The local runs use Python 3.9.6 on macOS and the existing Rust/Cargo 1.90.0 cache.
Rust commands use `--locked --offline`; no dependency or fixture changes occur.
The new qualifier measures explicitly selected local builds only for its offline
exercise. That measurement is neither production enrollment nor a source/build
attestation. Reproduce using the commands in [README](../README.md) with paths
corresponding to any explicitly configured target directory.

The required Python command is
`REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q`; artifact checks
use `python3 -B scripts/check_artifacts.py`. Unchanged Go compatibility and prior
actual-worker qualifiers are not repeated locally; hosted CI runs those checks
alongside the new qualifier. Local Rust runs exercise the reused pure predicates
and their earlier regressions. Hosted results are separate from local execution.

No external assessment, hostile-host containment, durable statement/cache policy,
source enrollment, authenticated chain evidence, private signer, funded regtest,
devnet, live-chain transaction or core activation is exercised. See the
[selected verifier and trust boundary](OBSERVATION_VERIFIER.md). Those omissions
remain explicit no-go gates; passing these bounded tests does not establish
atomic-swap security or funded recovery availability.
