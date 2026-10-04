# Offline public recovery reserve experiment

Status: **Stage 15 model evidence only. No reserve is implemented in the journal,
and no funded recovery policy is selected.**

The [baseline admission model](RECOVERY_ADMISSION_MODEL.md) and
[selected journal correspondence](RECOVERY_MODEL_CORRESPONDENCE.md) establish
that a finite shared allowance can block a later authorized valid public
witness. This experiment asks whether separating an emergency allowance removes
that blockage, including when the public worker fails, is cancelled or suffers
modeled process death after admission.

## Relationship to existing behavior

The [new wrapper](../scripts/model_recovery_reserve.py) reuses the unchanged
baseline candidate, authorization, worker and archive transitions. Its general
and reserve counters are additional model fields. An admission's total counter
is their sum; candidate retention, exact comparison before replacement,
positive verification before completion, original archival and free completed
replay remain baseline rules. Nothing is connected to `offline_session`.

The source parent is Stage 14 commit
`6721ff919fb54d98edb228ffd09b37b62612392c`. The Stage 12
[independent review subject](INDEPENDENT_REVIEW.md) and its manifest are unchanged.
This experiment is a later delta needing its own assessment; preparing or testing
it does not extend an independent security verdict to either subject.

## Two policies and equal aggregate budgets

Let `G` be the general limit and `R` the reserve. Inputs require exact integers,
`G >= 1`, `R >= 0` and `G + R <= 64`.

| Policy | Ordinary/shared allowance | Protected public allowance |
| --- | --- | --- |
| `shared` | All eligible attempts use one pool of `G + R` | None; `R` is folded into that pool |
| `reserved` | General attempts use `G` | Explicitly selected public attempts use `R` |

An admission explicitly names its resource lane. Each lane is charged before
the worker and remains charged after rejection, failure, cancellation or modeled
crash. There is no refund, refill, borrowing, reset or reactivation of Alice.
The unchanged aggregate counter cannot exceed `G + R`. Public attempts may use
the general lane if it still has capacity.

Reserve admission requires the baseline's separately observed, explicitly
authorized fixed valid public witness. A peer candidate, authentication label or
claimed inclusion cannot supply this authority. Authentication of the public
witness is optional; the exact modeled envelope flag must match its observation.
When the retained bytes already equal the valid witness, an explicit reserve
retry requires public authorization even if those bytes originally arrived
from an authenticated peer. An invalid retained candidate instead requires
public reconciliation with the exact original comparison identity.

These are ideal premises, not implemented observation filters. The baseline
public source offers one fixed valid candidate. Multiple witnesses, invalid
public observations, malicious local authorization and a real mechanism that
selects trustworthy chain evidence are outside the model. A protected budget
cannot establish those premises or prevent a compromised classifier from
misusing it.

## Optional interruption assumption

`--public-failure-limit F` explicitly restricts the modeled environment to at
most `F` interrupted authorized public worker calls over the session. All three
outcomes, `worker_fail`, `worker_cancel` and `worker_crash`, spend one such event.
Calls sourced from the public witness in either lane count, as do reserve
retries of identical retained bytes. General retained retries and peer-sourced
work are not classified as public calls, even when their inner bytes are valid.
They still spend their selected recovery allowance.

Once `F` is reached, another public interruption is excluded from the graph.
This is an environment restriction, not a property implemented by resource
accounting. Omitting the flag imposes no interruption restriction beyond the
finite attempt budgets. Failure does not establish that the candidate is invalid.

An outcome can still be delayed forever, and a general pending worker blocks
overlapping recovery in either lane. Scheduling fairness, eventual worker exit,
deadlines, restart availability and a mechanism guaranteeing `F` are absent.
An available finite recovery path is therefore not an eventual-completion proof.

## Findings at recorded bounds

All searches below completed their configured graph with no candidate/history
or resource-integrity findings. `Blocked` denotes an authorized valid public
witness with no active worker and no remaining admissible allowance. It does
not denote principal loss. Counts include legal replay transitions and wrapper
resource history, so shared counts need not equal the older core model's counts.

| Policy | G | R | F | States | Transitions | Blocked |
| --- | --- | --- | --- | --- | --- | --- |
| shared | 2 | 1 | absent | 542 | 1985 | Yes |
| reserved | 2 | 1 | absent | 606 | 2121 | Yes |
| shared | 2 | 1 | 0 | 410 | 1506 | Yes |
| reserved | 2 | 1 | 0 | 342 | 1107 | No |
| shared | 2 | 1 | 1 | 534 | 1955 | Yes |
| reserved | 2 | 1 | 1 | 558 | 1901 | Yes |
| shared | 2 | 2 | 1 | 758 | 2811 | Yes |
| reserved | 2 | 2 | 1 | 654 | 2117 | No |
| shared | 2 | 2 | 2 | 810 | 3006 | Yes |
| reserved | 2 | 2 | 2 | 870 | 2983 | Yes |

The test matrix also checks `G/R` pairs `1/0`, `1/1`, `2/1` and `2/2`, each with
`F` absent, 0, 1 and 2, under both policies: 32 complete searches. At those
bounds, shared recovery is blockable even with zero public interruptions because
peer work can drain the whole pool. Reserved recovery remains blockable without
an interruption bound, when `R = 0`, or when `F >= R`. Where `R > F`, those
searched graphs have no blocked state. This finite evidence is not a proof for
arbitrary parameters or an implementable funded policy.

For the complete `G = 2`, `R = 2`, `F = 1` reserved graph, a separate test visits
every reachable idle, authorized, uncompleted state and explicitly constructs
a path: schedule any remaining allowed public interruptions, then a positively
verified reserve attempt. This checks a finite path under the stated assumptions;
it supplies neither fairness nor actual verification/authorization evidence.

## Replayable exhaustion example

The shortest reserved counterexample at `G = 2`, `R = 1`, with no interruption
bound, is eight events:

1. Observe the fixed valid public witness without an envelope.
2. Explicitly authorize its public recovery.
3. Begin an authenticated valid peer candidate using the general lane.
4. The worker fails; that admission stays consumed.
5. Admit an authenticated invalid replacement using the general lane, comparing
   against the exact retained valid candidate.
6. Inner verification rejects it; the valid original stays retained.
7. Retry that same retained valid witness through the authorized reserve lane.
8. The public worker fails; both general attempts and the reserve are consumed.

No invalid completion, premature replacement, archive loss or Alice reset is
needed to block recovery. Separate traces poison the retained candidate with
invalid peer bytes, then demonstrate successful public replacement through an
unused reserve and blockage after each permitted interruption outcome.

## Reproduction and decision

```sh
python3 -B scripts/model_recovery_reserve.py --policy shared --general-limit 2 --public-reserve 1 --public-failure-limit 0
python3 -B scripts/model_recovery_reserve.py --policy reserved --general-limit 2 --public-reserve 1
python3 -B scripts/model_recovery_reserve.py --policy reserved --general-limit 2 --public-reserve 2 --public-failure-limit 1
python3 -B -m unittest discover -s tests -p test_recovery_reserve_model.py -v
```

JSON reports the policy, bounds, environment restriction, completeness, counts
and shortest findings with replayable choices. Exit 0 means a complete configured
graph with no findings, 1 means a complete graph with findings, and 2 means invalid
parameters or incomplete search. A state-budget stop remains incomplete even if
a counterexample has already been retained.

**Go:** continue offline specification of observation authorization and resource
assumptions, with explicit implementation and review obligations.
**No-go:** implement this reserve as a funded availability guarantee, refund
interrupted attempts, bypass worker verification, or proceed to live swaps/core
activation on these results. A finite reserve improves separation under ideal
authority but remains exhaustible. The existing journal's shared allowance and
its verified exhaustion behavior are unchanged.

[Stage 16's exact-observation experiment](PUBLIC_OBSERVATION_MODEL.md) deliberately
weakens this model's valid-public-witness premise. It finds reserve blockage
from normal invalid rejection even with zero interruptions. The stronger
valid-only comparison remains ideal; no journal policy is selected by either
model.
