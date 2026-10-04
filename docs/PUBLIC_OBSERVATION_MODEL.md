# Exact public authority and inner-validity experiment

Status: **Stage 16 offline model evidence. No observation trust source, reserve
or funded recovery policy is implemented.**

[Stage 15's reserve experiment](RECOVERY_RESERVE_MODEL.md) allowed only one fixed
valid public witness. Its conditional absence of blocked states depended on
that premise as well as an interruption bound. This experiment makes the public
candidate domain explicit: a known source or local authorization can also refer
to an invalid signature. Mathematical rejection is a normal verifier outcome,
not a timeout, cancellation or process death.

## Source and implementation boundary

The source parent is Stage 15 commit
`a23958b59f931869360d7bd25704903a36c8b94e`. The earlier admission and reserve
engines, `offline_session`, actual-worker qualifiers, fixtures, dependencies and
CI definition are unchanged. The fixed Stage 12 [review subject](INDEPENDENT_REVIEW.md)
and manifest are unchanged; this later experiment needs a separate delta review.

The [new model](../scripts/model_public_observation.py) reuses the core's exact
candidate/state types, peer/retry transitions and worker results. Public
begin/reconciliation admissions are explicitly generalized to either candidate
ID. They remain public inputs with independent local authority; the adapter
never relabels an invalid public candidate as an authenticated peer.

The baseline edge checker hardcodes the valid public identity. The new edge
checker therefore restates its candidate/history constraints and checks per-ID
authority independently, rather than suppressing baseline findings. A separately
enumerated valid-observation subset projects to the unchanged Stage 15 state
and edge graph at `G=1`, `R=1`, `F=0`.

## Two identities, distinct authority and ideal math

`valid` and `invalid` denote two fixed, distinct, same-context public byte
strings. Their true inner validity remains an ideal oracle. Authentication is
also ideal. Neither is implemented cryptography or a chain validation result.

Observation, its immutable envelope flag, local authorization, claimed inclusion
and modeled reorg are stored separately for each identity. Authorization of one
ID never authorizes the other. Observation and inclusion never grant authority.
An authentication flag does not make the inner candidate valid. Re-observation
cannot silently change an existing envelope flag or refill any allowance.

The inherited `core.public_*` fields refer only to the valid witness, preserving
the old model's meaning. The `invalid` observation object carries the other
identity's external facts. Seeing invalid bytes marks possible exposure but
does not establish valid-witness knowledge. Seeing the ideal valid public
witness establishes the model's availability/knowledge flag, not actual scalar
extraction, receipt, trusted chain inclusion or settlement.

| Public admission policy | Additional premise | Implemented mechanism |
| --- | --- | --- |
| `ideal-valid` | The fixed validity oracle excludes invalid public candidates before admission in either lane | None; this is the stronger comparison assumption |
| `authorized-bytes` | Each exact candidate must be observed and independently authorized; its actual validity is checked by the modeled worker | No real trust source; the authority event is still external |

Both policies keep authentication separate from validity. A public admission
must match that identity's observed envelope flag, but an envelope is optional.
A reserve retry requires authority for the exact retained ID; its original peer
authentication cannot supply public authority. The stronger policy additionally
excludes reserve retries of invalid retained bytes. General retained retries
are ordinary local work, not newly classified public calls.

## Resource and outcome accounting

`shared` pools `G+R`; `reserved` separates `G` general attempts from `R` public
attempts. Both require exact integers totaling at most 64. Every admitted call
is charged before its outcome, with no rejection/failure refund, refill or reset.
Exact completed replay remains free; reconciliation requires the exact original
comparison and positive verification before replacement/archive persistence.

| Model counter | What it counts |
| --- | --- |
| `public_failures` | Interrupted public calls, including reserve retries; subject to optional environment bound `F` |
| `worker_interruptions` | All failure/cancellation/modeled-crash events, including general peer work |
| `reserve_rejections` | Reserve calls whose normal `worker_verify` result rejects the fixed invalid candidate |

Rejecting an invalid signature spends the admitted lane but increments neither
interruption counter. A public worker with `F=0` can still return a negative
math verdict. No guard excludes that inevitable verdict or strands an invalid
pending call behind an invented successful-verification assumption.

Availability findings require an observed, authorized valid witness, no active
worker, no completion and no remaining admissible allowance. The special
`invalid_public_rejection_without_interruption` finding additionally requires
at least one rejected reserve call and zero interruptions across all workers.
These counters are model telemetry, not new journal fields or storage claims.

## Complete searches at recorded bounds

All six configured graphs completed with no candidate/history, resource or
per-ID authority integrity findings. `Blocked` is recovery blockage under the
selected assumptions, not principal loss. Counts include identity metadata and
outcome history, so they differ from the older model's counts.

| Allowance | Public policy | G | R | F | States | Transitions | Blocked |
| --- | --- | --- | --- | --- | --- | --- | --- |
| shared | ideal-valid | 1 | 1 | 0 | 6681 | 30695 | Yes |
| shared | authorized-bytes | 1 | 1 | 0 | 7325 | 33282 | Yes |
| reserved | ideal-valid | 1 | 1 | 0 | 3315 | 13028 | No |
| reserved | authorized-bytes | 1 | 1 | 0 | 5347 | 20328 | Yes |
| reserved | ideal-valid | 1 | 2 | 1 | 6239 | 25057 | No |
| reserved | authorized-bytes | 1 | 2 | 1 | 15527 | 63219 | Yes |

Both blocked reserved cases have a replayable shortest zero-interruption
counterexample. More reserve attempts alone do not exclude repeated verification
of the same authorized invalid bytes. No extra identities or worker crashes are
required. Shared blockage still needs no invalid public candidate because peer
work can consume the whole pool.

The ideal-filter graph at `G=1`, `R=1`, `F=0` also has a separate constructive
check: from every reachable idle authorized uncompleted state, explicitly
schedule a valid reserve call and positive result. This is a finite path under
the oracle assumption, not evidence that a real source implements that filter
or that a worker will eventually be scheduled.

## Zero-interruption counterexample

At `G=1`, `R=1`, `F=0`, the shortest strict finding has eight events:

1. Observe the fixed valid public candidate without an envelope.
2. Authorize that exact valid observation.
3. Observe the fixed invalid public candidate without an envelope.
4. Independently authorize that exact invalid observation.
5. Admit authenticated invalid peer bytes using the general lane.
6. The worker normally rejects them; the general attempt stays consumed.
7. Retry the identical retained invalid bytes through the authorized public
   reserve lane.
8. The worker normally rejects them; the reserve stays consumed.

The valid witness remains observed, authorized and available in the model, but
there is no remaining attempt for its positive reconciliation. Original invalid
bytes remain retained, no invalid completion is accepted, no archive is lost,
Alice stays consumed, and all worker/public interruption counters are zero.
The `G=1`, `R=2`, `F=1` strict finding repeats the reserve retry/rejection once
more and has ten events, still with zero interruptions.

Separate cases begin directly with invalid public bytes, preserve a retained
valid candidate after invalid public replacement, discover the valid witness
only after exhaustion, and succeed with one remaining reserve attempt while
archiving the invalid original. Those are ideal trace checks; no new journal
policy or actual observation adapter is being qualified.

## Reproduction and interpretation

```sh
python3 -B scripts/model_public_observation.py --policy reserved --public-policy authorized-bytes --general-limit 1 --public-reserve 1 --public-failure-limit 0
python3 -B scripts/model_public_observation.py --policy reserved --public-policy ideal-valid --general-limit 1 --public-reserve 1 --public-failure-limit 0
python3 -B scripts/model_public_observation.py --policy reserved --public-policy authorized-bytes --general-limit 1 --public-reserve 2 --public-failure-limit 1
python3 -B -m unittest discover -s tests -p test_public_observation_model.py -v
```

JSON identifies both policies, numeric bounds, the interruption environment,
completeness, counts and replayable findings. Exit 0 is a complete configured
graph with no findings, 1 is a complete graph with findings and 2 means invalid
parameters or incomplete search. A truncated graph remains incomplete even when
it has found a concrete blockage. Expected counterexample exits are not failed
regression tests.

## Decision and remaining gates

The later [Stage 17 evidence contract](OBSERVATION_EVIDENCE_CONTRACT.md) makes
the exact target and statement vocabulary concrete without selecting a source,
normal-verdict producer or negative cache. The experiments and their assumptions
remain unchanged; a parsed statement alone supplies no truth or authority.

**Go:** specify an offline observation-evidence contract with exact session,
signature identity, context bindings, source/trust assumptions, mathematical
verification and resource accounting kept distinct. A later adapter must state
what supplies each obligation and how invalid observation pressure is handled.

**No-go:** use local authorization, a source label, an envelope or an unverified
inclusion claim as proof of signature validity or funded recovery availability.
The ideal pre-admission filter is not implemented. Moving verification outside
the recovery allowance would introduce its own aggregate resource/availability
obligation, not automatically solve this result. No refund or bypass is selected.

The authorization-only policy deliberately permits retry after a normal
negative verdict. No per-candidate negative-verdict cache, deduplication policy
or separate per-ID allowance is selected. This finding does not disprove a
policy that independently supplies those mechanisms. Such a design must bind
trusted verdicts to exact bytes/context and distinguish permanent mathematical
rejection from a failed or interrupted verifier before using a negative cache.

Arbitrary observation families, a compromised authority mechanism, actual
cryptography, worker fairness, private signing, restored copies, chain evidence,
funding/time acceptance and independent construction review remain open. The
existing journal still has its shared allowance. Live swaps and a core port
remain no-go.
