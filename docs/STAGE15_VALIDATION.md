# Stage 15 validation: offline public recovery reserve experiment

Scope: compare shared and reserved recovery allowances in a separate finite
model using the unchanged baseline candidate/worker engine. Execution code in
`offline_session`, baseline model rules, journal v7, fixtures, cryptographic
dependencies, actual-worker qualifiers and the fixed review manifest are
unchanged. Existing Python discovery includes the new model tests.

## Executed checks

| Check | Result | Boundary |
| --- | --- | --- |
| New reserve-model discovery suite | 22 passed in 4.539 seconds | Ideal validity/authority, explicit interruption assumptions |
| Required-mode full Python suite | 348 passed in 400.704 seconds, no skips | Prior 326 tests plus 22 reserve-model tests |
| Comparison matrix | 32 complete configured searches, no integrity findings | Availability findings and conditional absence are reported separately |
| Shared projection | Matched the unchanged baseline state/edge graph at total limit 2 | Projection omits wrapper resource history |
| Constructive reserved paths | Passed for every reachable idle authorized uncompleted state at G=2, R=2, F=1 | Explicit finite scheduling, not eventual completion |
| Artifact hygiene, links and whitespace | Passed; 317 local Markdown links resolve | Limited disclosure and consistency checks |

The local runs used Python 3.9.6 on macOS and OpenSSL 3.6.3. Required validation
used `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q` and passed
without failed or skipped cases. Artifact checks used
`python3 -B scripts/check_artifacts.py`; relative Markdown targets and Git
whitespace checks passed.

Unchanged Rust/Go suites and actual subprocess integrations are not
independently rerun locally for this pure model/documentation change; existing
hosted CI runs them. No new actual-worker reserve qualifier is claimed because
the journal implements no reserve policy.

## Behavior and assumptions

The [experiment report](RECOVERY_RESERVE_MODEL.md) records exact bounds, counts,
counterexamples and CLI outcomes. It includes both a protected public path after
general peer poisoning and exhaustion after public failure, cancellation or
modeled post-admission process death. Actual process death, power loss, real
signing, node integration, hostile storage and chain evidence are not tested by
the new model.

Independent state/edge checks detect lane refunds, total mismatches, peer reserve
theft, missing public authority, hidden interruptions, worker reclassification,
premature or invalid completion, lost original history and bypass of the
explicit environment bound. Tests exercise pending-worker exclusion, exact
reconciliation comparison, envelope-free authorized public retry, reorg and free
completed replay, malformed parameters and incomplete searches with findings.

The interruption limit is an external restriction. In the searched graphs,
`R > F` leaves a possible reserved path, while an unrestricted finite reserve
still admits blockage. This is not an implemented way to ensure that valid
public work succeeds. Public validity and authorization are ideal premises;
invalid/misclassified public observations and fair scheduling remain outside
the abstraction.

## Intermediate failure and correction

The first focused discovery failed during import, before any model case ran.
The `State.core` field shadowed the imported module while its annotation was
being evaluated. Deferred annotations corrected the import; all 22 focused
cases then passed. No baseline engine, journal or cryptographic behavior changed.

## Remaining gates

No funded admission policy, resource-reset policy or observation trust mechanism
is selected. The live-swap/core-port no-go remains. The independent review
subject and manifest stay frozen; external assessment and later delta review
are still pending. Reserving more attempts does not resolve public authority,
restored-copy protection, private nonce ownership, aggregate resource pressure,
funding/time authorization or eventual worker availability.
