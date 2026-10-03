# Stage 12 validation: public signature candidates

Scope: construct the existing canonical completion packet from a structurally
validated retained Bob snapshot and exactly 64 public signature bytes. This
pure helper writes nothing and grants no verification or admission authority.
The journal, wire schemas, cryptographic dependencies and fixtures are unchanged.

## Executed checks

| Check | Result | Evidence boundary |
| --- | --- | --- |
| New candidate regression suite | 11 passed in 8.658 seconds | Strict inputs, local reconstruction, unchanged state/storage, candidate/CAS and allowance boundaries |
| Required-mode full Python suite | 313 passed in 351.526 seconds, no skips | Prior 302 tests plus 11 candidate regressions |
| Actual completion subprocess integration | 9 passed in 36.210 seconds | Existing 6 cases plus 3 raw-signature construction/recovery cases |
| Actual artifact subprocess integration | 2 passed in 1.562 seconds | Existing public artifact checks with the current module |
| Actual authentication subprocess integration | 11 passed in 24.817 seconds | Existing authentication, pin and raw-recovery boundaries |
| Artifact hygiene, local links and whitespace | Passed | Limited checks, not comprehensive secret detection or anonymity |

Execution uses Python 3.9.6 on macOS and previously built pinned public Rust
executables. All 22 actual subprocess integration tests run separately from
Python discovery. The full required-mode suite includes the independent
OpenSSL regression verifier. Unchanged Rust/Go sources, fixtures and dependency
suites were not independently rerun locally for this Python helper change;
existing hosted CI runs them at the corresponding commit.

## Construction and persistence evidence

The known public signature produces the exact existing fixture packet. Tests
reject non-plain bytes, incorrect sizes, unsupported overrides, early/completed
states, corrupt receipts and malformed nested contexts. Locally reconstructed
terms, session metadata and nonce rounds determine the output fields; the raw
signature does not import or authenticate any of those labels.

The helper does not invoke cryptographic callbacks. Correctly sized all-zero,
all-ones and wrong-leg bytes remain packageable candidates.
Unit callbacks used to assemble synthetic contexts are explicitly fake and do
not establish validity of signatures under rewritten contexts.

After reopening a Bob journal, successful and rejected construction leave
database/anchor bytes, sequence, complete session state, pins, allowance and
exposure unchanged. Construction cannot replace a retained invalid candidate,
reset an allowance or bypass stale comparison. It can construct a valid
replacement even after exhaustion, but actual recovery still refuses admission
without invoking its worker.

## Actual verifier evidence

The three new integration cases demonstrate:

1. A reopened Bob with configured pins can construct a candidate without an
   auxiliary envelope or storage mutation. Actual recovery returns the exact
   expected Bitcoin packet, spends one allowance and supports durable replay.
2. Zero signature bytes and the existing signature valid for the Bitcoin leg
   are both rejected as Zenon recovery inputs by the actual worker. The original
   candidate stays retained, no archive/receipt is created, and the two admitted
   failures exhaust the shared allowance. Later valid construction does not
   bypass that exhaustion.
3. A newly constructed valid replacement cannot use ordinary recovery or a
   stale comparison digest to replace a retained invalid candidate. Exact
   comparison plus actual verification completes reconciliation, preserves the
   original archive and produces replayable Bitcoin output.

The foreign-leg case has different cryptographic key/message inputs. It is not
evidence that an arbitrary change to an application session label would make a
chain signature invalid. These tests establish neither who transmitted the
signature nor whether it was included in any chain.

## Intermediate findings

No focused, actual-integration or full-suite test run failed. Parallel code/test review
found no material implementation issue. Documentation explicitly distinguishes
the locally constructed role labels, trusted retained snapshot and actual
cryptographic result from source provenance and recovery authorization. This
review is not an independent human construction or security audit.

## Evidence and remaining gates

The [construction contract](PUBLIC_SIGNATURE_CANDIDATES.md) separates formatting
from actual signature verification, source authorization and recovery admission.
A packet may carry Alice/Bob role labels without being an authenticated message
from Alice. A structurally accepted candidate may still be cryptographically
invalid and consume allowance if the caller later admits it to recovery.

Snapshot validation relies on existing trusted local ownership and stored
artifact checks. It does not establish hostile-snapshot integrity, chain
identity or freshness. Source selection, evidence retention, budget exhaustion,
private signing and restored-copy protection remain unresolved. Live swaps and
a core port remain no-go.
