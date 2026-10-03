# Stage 11 validation: bounded recovery admission model

Scope: a separate pure offline model of candidate selection, recovery admission,
interrupted work and explicit observation authorization. No journal, wire,
cryptographic, dependency or fixture behavior changes. Journal v7 and its
existing recovery APIs remain unchanged.

## Executed checks

| Check | Result | Evidence boundary |
| --- | --- | --- |
| New model regression suite | 20 passed | Independent concrete traces, mutant counterexamples, forged-edge checks and CLI outcomes |
| Required-mode full Python suite | 302 passed, no skips | Prior 282 tests plus 20 model regressions |
| CLI policy/bound matrix | 9 complete searches with expected findings | Three policies at attempt limits 1, 2 and 3, with a 50,000-state cap |
| CLI truncation and invalid bounds | 3 expected incomplete results | State cap, invalid attempt limit and counterexample retained at truncation |
| Artifact hygiene, local links and whitespace | Passed | Limited source checks, not comprehensive secret detection or anonymity |

Execution uses Python 3.9.6 on macOS. The final required-mode suite includes
the independent OpenSSL regression verifier and passed in 334.890 seconds.
The focused 20-test model suite passed in 0.374 seconds. Rust/Go, actual worker integration,
journal and cryptographic code are unchanged; their separate suites were not
independently rerun locally for this model-only change. Existing hosted CI
continues to run those checks; its results belong to the corresponding commit.

## Complete finite exploration

All nine searches exhausted their configured graph. `S` counts distinct
states; `E` counts generated legal transitions, including multiple worker
failure outcomes and completed replay self-loops.

| Policy | Limit 1: S / E | Limit 2: S / E | Limit 3: S / E | Findings |
| --- | --- | --- | --- | --- |
| `baseline` | 118 / 375 | 282 / 1034 | 446 / 1693 | No modeled safety violation; recovery allowance can be exhausted |
| `universal-envelope` | 106 / 342 | 246 / 915 | 386 / 1488 | No modeled safety violation; withheld envelope and exhausted allowance can block recovery |
| `auth-is-valid` | 135 / 414 | 333 / 1151 | 531 / 1888 | Invalid inner completion can be accepted; allowance can also be exhausted |

Each command exits 1 because it produces a concrete counterexample. These are
expected research outcomes, not failing regression runs. Exploration continues
after finding them; a complete report does not mean the policy is safe.

With the default limit of 2, the shortest withheld-envelope example is simply
an unauthenticated public observation followed by explicit local authorization.
It has no retained valid candidate to retry. The shortest invalid-completion
example admits an authenticated invalid peer candidate and then substitutes
authentication for inner verification. Both take two model transitions; the
tests replay them and check shortest depth separately.

An exhausted-allowance example first observes and authorizes the public
witness, admits a valid peer candidate whose worker fails, and spends the last
attempt on unsuccessful reconciliation. A separate regression spends both
attempts on the same authenticated invalid candidate. Valid-input interruption
can exhaust the allowance as well. None of these outcomes authorizes replacing
the original, refunding an attempt or signing again.

## Truncation and invariant evidence

The CLI returns status `incomplete` and exit 2 for a state budget of 1, an
attempt limit of 0, and the `auth-is-valid` policy capped at 16 states. The last
case retains its already discovered invalid-completion trace while explicitly
reporting the unexplored graph. It cannot be mistaken for a completed search.

Tests show that public source/inclusion/authentication labels do not replace
the explicit local-authorization event, and that an unauthenticated peer offer
rejects even when its inner candidate is valid. They cover exact comparison,
original retention, successful-only archiving, shared pre-worker debit,
interrupted work, free completed replay, sealed results and reorg-resistant
disclosure/ownership. The independent checker is also tested against forged
edges that bypass verification or alter a completed result.

## Intermediate findings and checks

No failed test run occurred. Parallel review found two model issues before
validation was finalized:

1. An availability predicate originally reported envelope blockage even when
   a valid retained candidate could still retry. It now accounts for that path,
   with a regression demonstrating successful recovery.
2. Independent edge checks originally missed a forged valid completion during
   admission and later changes to sealed output. New checks require positive
   worker verification of the pending candidate and preserve completed records;
   direct mutation regressions exercise both cases.

The transition implementation did not perform those forged completion changes.
Exposure/knowledge descriptions were clarified to distinguish model disclosure
facts from Alice's journal marker and from actually computing a scalar. Review
found no further material issue; it is not an independent human security audit.

## Evidence and remaining gates

The [model design](RECOVERY_ADMISSION_MODEL.md) separates invariant violations
from recovery blockage. Authentication and inner validity are ideal independent
oracle inputs. Authorization of a public observation is an explicit external
event, not a conclusion drawn from a source label or claimed inclusion.

Complete exploration applies only to the reported finite graph and bounds.
Counterexamples are replayable transition sequences within that graph. They
do not establish principal loss, timing safety, chain identity or a complete
atomic-swap argument. An incomplete search is reported separately and is never
evidence that the unexplored states satisfy the checked properties.

The reference policy remains susceptible to exhaustion; no funded admission
or emergency recovery policy is selected. Private signing, trusted observation
authorization, restored-copy protection and independent construction review
remain unresolved. Live swaps and a core port remain no-go.
