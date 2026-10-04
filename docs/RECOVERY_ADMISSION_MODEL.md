# Bounded recovery admission and observation model

Stage 11 explores recovery policy choices in a separate finite offline model.
It changes neither the journal nor cryptographic verification. The model starts
after Bob has retained the required artifacts and released the Zenon bundle.
Alice's consumed signing ownership is a fixed starting premise; the model does
not implement or prove the steps that established it.
Its inputs are synthetic exact-candidate identities and explicitly idealized
authentication and inner-validity results. They are not cryptographic checks.

## Questions and evidence boundary

The model separates two questions:

- Can a transition lose the original candidate, bypass positive verification,
  reuse consumed attempts, clear exposure, or reset signing ownership?
- Can a valid, explicitly authorized public witness become unavailable for
  recovery because a policy requires a withheld envelope or has spent its
  finite allowance?

A policy can preserve the first set of constraints and still fail the second.
In particular, authenticating a peer's message does not make its inner signature
valid, and a finite shared allowance can be exhausted before a valid witness is
processed. An availability counterexample is not proof of a completed swap
loss: the model has no funding, deadlines, fees or ledger settlement.

## Authorization assumptions

Peer authentication and public-observation authorization are distinct inputs.
Local authorization of a public candidate is an explicit external decision;
the model does not derive it from a source label, claimed chain inclusion,
signature validity or the presence of an envelope. A concrete implementation
of trustworthy observation authorization remains unselected.

The model includes a valid public witness whose auxiliary envelope is withheld.
A universal envelope requirement can therefore block recovery even when local
authorization and inner validity are present. Keeping a separate public path
does not itself establish the authority, correctness or freshness of an
observation.

## Journal correspondence and exclusions

Only two fixed same-context candidate identities, `valid` and `invalid`, exist.
Their ideal inner validity never changes. Peer offers may be authenticated or
unauthenticated. A separate public event reveals the fixed valid witness, with
or without an envelope; at most one such observation and one reorganization
are modeled. Invalid public-source observations, changing authorizations,
multiple sessions and arbitrary candidate populations are outside this graph.

Ordinary admission retains the first exact candidate and spends an attempt
before computation. A retry uses the same candidate. Reconciliation compares
the expected original identity and spends an attempt before computation, but
only positive recovery may replace the original and archive it. Failure or
interruption is not a verdict that the original was invalid.

The model separates admitted work from its outcome. A crash after admission
does not refund the attempt. It cannot reset signing ownership or erase
knowledge of possible exposure. A reorganization can change an observation's
inclusion status without undoing disclosure. Exact completed-output replay
does not invoke recovery again.

`possible_exposure` concerns the model's completion-candidate disclosure facts,
not Alice's separate journal flag, which is already set when her ownership is
consumed. Initial false does not establish secrecy. `witness_known` denotes
public recoverability/disclosure, not a scalar already computed or stored by
Bob. Observation may make this true before Bob's worker succeeds, so knowledge
and completed recovery remain separate.

Candidate identities represent different fixed public byte strings, not
interchangeable labels for arbitrary incoming packets. The real journal uses
an exact-byte observation digest for its comparison guard; no hashing or
collision-resistance claim is tested here. Model state is volatile mathematical
state. Its records are not new journal evidence, durable receipts or signed
provenance.

The abstraction assumes one honest local owner, already matching session and
artifact context, ideal public verification, and matched persistence snapshots.
It omits wire parsing, signature arithmetic, filesystem durability and
quarantine, rollback/clone protection, key provisioning, network rate limits,
observation timing, chain identity and settlement. Separate tests address some
of those local implementation boundaries; they do not make this model a
cross-chain proof.

## Exploration and reproduction

```sh
python3 scripts/model_recovery_admission.py --policy baseline
python3 scripts/model_recovery_admission.py --policy universal-envelope
python3 scripts/model_recovery_admission.py --policy auth-is-valid
python3 scripts/model_recovery_admission.py --max-states 1
```

The default attempt limit is 2 and the state budget is 50,000. Both are explicit
finite exploration bounds, not production parameter recommendations. An exact
integer attempt limit from 1 through 64 and state budget from 1 through
1,000,000 may be selected. The search stops with an incomplete result if it
cannot exhaust the configured graph within its state budget.

Breadth-first exploration checks stored and edge invariants independently of
the policy's admission guards. It retains the first shortest replayable trace
for each distinct finding and continues searching after finding one. `complete`
means the graph was exhausted, not that its policies were safe. Findings and
traces survive a later state-budget cutoff; `status: incomplete` still takes
precedence over any counterexamples already found.

The baseline uses separate authenticated-peer and explicitly authorized public
paths but deliberately retains the finite shared allowance. The
`universal-envelope` variant requires an envelope for new public admissions;
an already retained valid candidate can still retry. The `auth-is-valid`
variant deliberately substitutes envelope authentication for inner verification.
Neither variant is application policy.

CLI exit status 0 requires complete exploration with no findings; 1 reports
concrete safety or availability counterexamples; 2 reports incomplete search or
invalid numeric bounds. The three default policy commands intentionally return
1, because each has an availability counterexample and the third also has a
safety counterexample. The state-budget example returns 2. These expected model
outcomes are asserted by regression tests; they are not failed test runs.

## Remaining decisions

No policy in this milestone is selected as safe for a funded application.
Public-observation authorization, candidate selection, evidence retention,
aggregate admission limits, emergency recovery and exhaustion handling still
need review. More retries or a reserved budget alone cannot establish
availability against an unbounded adversary or uncertain computation.

[Stage 14 selected trace correspondence](RECOVERY_MODEL_CORRESPONDENCE.md) now
connects some baseline traces to real journal operations and actual public
workers. It compares a documented projection, does not implement the model's
external authorization/authentication premises, and is not exhaustive refinement.

[Stage 15 reserve experiments](RECOVERY_RESERVE_MODEL.md) reuse this unchanged
engine to compare equal aggregate budgets and explicit interruption assumptions.
Protected attempts survive general exhaustion under ideal public authority,
but a finite reserve remains blockable under unrestricted public interruption.
No new policy is connected to the journal.

Private signing, restored-copy protection, authenticated chain identity and
independent construction review remain open gates. Live swaps and a core port
remain no-go.
