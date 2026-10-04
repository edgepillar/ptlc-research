# Stage 16 validation: exact public authority and inner validity

Scope: weaken the reserve experiment's fixed-valid-public-witness premise in a
separate model. Both fixed public IDs have independent observation/authorization
facts. Their inner validity remains an ideal oracle, while invalid rejection is
counted separately from public and total worker interruption.

The earlier admission/reserve engines, `offline_session`, journal v7,
cryptographic fixtures/dependencies, actual-worker qualifiers, CI definition
and frozen review manifest are unchanged. No trust source, observation adapter,
reserve or new journal counter is implemented.

## Executed checks

| Check | Result | Boundary |
| --- | --- | --- |
| Initial behavioral subset | 11 passed in 0.004 seconds | Included in the expanded suite, not additional cases |
| Initial expanded observation-model suite | 22 passed in 31.289 seconds | Before the final additional independent binding checks |
| Final expanded observation-model suite | 22 passed in 31.899 seconds | Includes exact admitted identity/source binding and retained authority |
| Final required-mode full Python suite | 370 passed in 428.248 seconds, no skips | Prior 348 tests plus 22 new model tests |
| Policy comparisons | Six complete searches with no integrity findings | Conditional path evidence and recovery blockages reported separately |
| Valid-observation subset projection | Matched the unchanged Stage 15 state/edge graph at G=1, R=1, F=0 | Extra observation and telemetry fields are projected away |
| Constructive ideal-filter paths | Passed from every reachable idle authorized uncompleted state at G=1, R=1, F=0 | Explicit finite scheduling under the oracle premise |
| Artifact hygiene, links and whitespace | Passed; 332 local Markdown links resolve | Limited disclosure and consistency checks |

The local runs used Python 3.9.6 on macOS and OpenSSL 3.6.3. Required validation
used `REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q` and passed
without failed or skipped cases. Artifact checks used
`python3 -B scripts/check_artifacts.py`; relative Markdown targets and Git
whitespace checks passed.

Unchanged Rust/Go suites and actual subprocess integrations are not independently
rerun locally for this pure model/documentation change; existing hosted CI runs
them. No actual-worker qualification of the generalized observation policy is
claimed because it has no journal implementation.

## Evidence and independent checks

The [experiment report](PUBLIC_OBSERVATION_MODEL.md) records exact bounds,
state/transition counts, interpretation and reproduction commands. Both reserved
`authorized-bytes` cases produce shortest zero-interruption blockages: eight
events at G=1/R=1/F=0 and ten at G=1/R=2/F=1. Their traces replay exactly, with
no `worker_fail`, `worker_cancel` or `worker_crash` event. Failure or cancellation
cannot be used to explain away the normal invalid-verification result.

State/edge checks detect authority attached during observation, authority for a
different ID, false valid-witness knowledge, changed envelope flags, resource
refunds, hidden reserve rejections, public-worker reclassification, bypass of
the interruption bound, admitted candidate/source substitution, erased retained
authority, outcomes without admission, incorrect normal verdicts,
premature/invalid completion and lost original history.
Tests also cover pending exclusion, exact reconciliation comparison, valid
replacement with remaining reserve, free replay, both modeled reorg labels,
invalid parameters and truncated search retaining a concrete finding.

The initial behavioral subset and expanded suite passed. Counterexample CLI
exits and explicitly truncated searches are expected model outcomes asserted
by tests, not failed validation runs.

An initial required full suite passed 370 cases in 429.821 seconds before the
final independent binding cases were added. The focused 22-case suite was then
rerun successfully, and the required full suite passed against those final
files. These runs are repeated evidence, not additional unique test cases.

## Limits and progression

The stronger `ideal-valid` policy remains an unimplemented pre-admission oracle.
Per-ID authority is an explicit model event, not a trusted node, chain proof,
transport identity or operator workflow. Claimed inclusion/reorg events remain
external labels. More candidate families, actual arithmetic, process death,
power loss, fairness, hostile storage and chain/funded behavior are outside the
new tests.

The fixed review subject and manifest remain unchanged. External assessment and
later delta review are pending; no funded admission policy or source mechanism
is selected. Next offline work should make the observation-evidence obligations
concrete before any adapter or journal enforcement is connected. Live swaps,
private signing and a core port remain no-go.
