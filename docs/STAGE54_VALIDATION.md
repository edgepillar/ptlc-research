# Stage 54 validation: bounded consumer retention

Parent candidate: `3a088245aa6d75847a68a6b1e30a8a8349062861`.
Parent draft: [PR 48](https://github.com/edgepillar/ptlc-research/pull/48).
This delta adds one pure test-only model, 26 regressions, two documents, four
append-only document references and one focused Python CI comparison step.
It selects no application storage, signer, current-head or recovery adapter.

## Local execution

| Check | Observed result |
| --- | --- |
| New consumer-model regressions | 26 passed in 1.245 s; recorded runner 1.335 s. |
| Selected retention comparisons | All three policies complete: 2130 selected schedules / 15960 transitions; recorded runner 0.511 s. |
| Complete offline Python suite | 1342 passed in 931.980 s; recorded runner 932.289 s. Every discovered method id passed; zero skips, failures and ResourceWarning lines. |
| Fixed inventories | Complete observation subject: 189 files; frozen baseline: 119 files. |
| Safe SQLite runtime | SQLite 3.54.0, DELETE journal, synchronous EXTRA (3); authentication and physical entry false. |
| Artifact hygiene and relative file links | 698 index/worktree versions across 349 tracked files; 1157 relative file links resolve. |

**All required local checks passed.**
The new targeted suite passed its first run, with no skips or failed methods.
The complete run must preserve every prior discovered method and native/refusal
control. No warning filter, suppression or runtime selection is introduced.

The model compares three policies over exactly 710 schedules and 5320 transitions
each. Four selected stream sets contribute 30, 30, 560 and 90 schedules. Directed
controls reproduce actual owned-store forks, a still-openable fresh old absence,
signed unavailable null facts and source restore with repeated synthetic effects.
All 81 live pair relations match the unchanged complete-opening prefix helper.
These are bounded trace/retention checks; model signature symbols and callback
flags are not mathematical verification. A cap result remains incomplete.

Rust 123 tests, Go 55 top-level tests and all 18 actual-worker groups / 164 cases
are not rerun locally for this pure-model delta. They are required on the new
hosted candidate, including the retained 12-case actual signed-prefix group.
Eight prior source/use and three prior original-read standalone comparisons are
not rerun locally; their regression methods remain in the full Python suite and
their original CLI steps remain required in hosted CI. No previous hosted result
is claimed as evidence for the new candidate.

## Preservation and publication gates

The prior 345-file candidate remains byte-preserved outside four append-only
documents and the workflow insertion. Existing application, source/store,
journal, sampler, helper, worker, grammar, fixture, dependency, earlier workflow
step, action pin, matrix, timeout, license and third-party attribution content
is unchanged. There is no new third-party code or private/key fixture material.

The frozen baseline remains `e592633e4c630cfe3f4669876f6f63b80d2e33d6` / 119 files;
the observation subject remains `f81e376e96e339647bb065739b4461235f865d2c` / 189 files.
Inventory hashes remain `df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295`
and `2f463071bc4f96ba1adaa8e8eb206d47e51845170ca2efe0f2b58182559afd6f`.
Both independent reports remain unfilled. The new model is outside both fixed
subjects; no independent security or privacy assessment is claimed.

Snapshot-input SHA-256 remains
`0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01`;
public snapshot-response SHA-256 remains
`2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb`.
Both helpers and the public worker source retain their prior pins. Worker source
and native executable measurements remain different evidence categories.

Public content must remain English ASCII and synthetic, with explicit generic
project author/committer metadata, UTC dates and unsigned commits. Verify owned
destination, parent state and overlap before posting; verify rendered body,
immutable server blobs, public metadata, exact executed checkout/tree/parents
and all seven hosted jobs afterward. Hosted run evidence belongs in the PR body,
not a source revision that would invalidate the measured candidate.

## Decision

**GO** for this separate bounded offline model and its review.
**NO-GO** for application witness integration, authenticated canonical/latest
heads, source/private signing, historical issuance, minimal-disclosure lookup,
nonrollback source or consumer guarantees, authoritative reconciliation,
protected use, core port, activation, broadcast or funded use.

See [model scope and observed behavior](ORIGINAL_CONSUMER_RETENTION_MODEL.md).
