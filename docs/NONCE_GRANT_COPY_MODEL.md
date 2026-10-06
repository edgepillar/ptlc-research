# Post-consumption nonce grant copies

Status: finite source-only comparison. No private nonce, signer, storage bridge,
entropy source, cryptographic arithmetic or new native worker is introduced.
Application and core progression remain **NO-GO**.

## Requirement and the additional cut

The [Stage 71 comparison](NONCE_INVOCATION_MODEL.md) restores a fixed snapshot
from before nonce consumption. It deliberately does not copy an already granted
worker, an in-flight permission or post-consumption memory. This separate model
selects that missing cut. It preserves the previous model and its narrower claim.

Durable issuance before nonce-dependent work is necessary. It does not by itself
make the resulting authority noncopyable. A grant identifier, locally consumed
owner, current result epoch or deduplicated receipt cannot undo two computations
that have already used the same underlying nonce. Any real bridge must cover
the state after its durable consume step as well as the state before it.

## Selected finite construction

[`model_nonce_grant_copy.py`](../scripts/model_nonce_grant_copy.py) uses one
nonce label, one grant label, one fixed complete binding label, two worker slots,
one saved snapshot, one restoration and one optional epoch advance. `issue`
atomically marks the nonce burned and creates its only grant. Issuance is ideal,
shared, durable and outside copied state in every policy. It is never reset or
performed again. There is no pre-consumption snapshot, nonce regeneration,
second grant or authority rollback in these graphs.

The snapshot captures the original worker in `ready`, `checked` or `permitted`
state. Restoration copies exactly its grant, binding, epoch and cached phase
into the second worker. The saved snapshot can outlive the original worker's
effect, result or loss. It cannot be replaced or restored a second time. This
explicitly models a cooperating copied worker, not operating-system snapshot
acquisition, arbitrary memory inspection or a real asynchronous queue.

`work` appends an irreversible external event. Each worker can produce at most
one event. `result` is separate: it rejects an old epoch and accepts at most one
receipt for the fixed grant across both workers. Thus the negative comparisons
already have result fencing and receipt deduplication. Both work and receipt
histories stay outside snapshots. Loss never erases those histories or refunds
issuance/effect consumption. Results are symbolic receipts; this model does not
implement output storage, byte replay or delivery. Those are separate cuts in
Stage 71 and the existing public journal.

The binding and grant identity are fixed symbols in every reachable state.
Their equality supplies no canonical encoding, backend input grammar,
authentication or consumed-input evidence. No context substitution is selected
here; Stage 71 separately compares eight changed binding coordinates. Repeating
work in this fixed-context graph is a violation of the selected uniqueness
requirement, not a demonstrated cryptographic key leak or funded attack.

## Comparisons

| Policy | Selected behavior after unique durable issuance | Finite consequence |
| --- | --- | --- |
| `copyable-grant` | Each copy can execute its already issued grant | Both compute with the same nonce; at most one receipt is accepted |
| `preflight-epoch` | Check the epoch once before dispatch; the passed check is copyable | A saved checked worker can compute twice even after an epoch advance |
| `exported-permit` | Atomically mark a second shared effect word consumed, then export a permit | A snapshot after the mark copies that permit; both can still compute |
| `effect-coupled` | Assume a nonexportable, nonrollback boundary coupling the final epoch/spent check to the actual effect | No counterexample under this explicit ideal premise and finite bounds |

A snapshot taken before an exported permit cannot obtain a second permit once
the shared effect word is spent. A snapshot taken after that same mark already
contains permission. This distinction prevents a successful pre-consumption or
pre-permit control from being generalized to the later copy cut.

The `effect-coupled` reference transition is an **unimplemented premise**. It
marks effect consumption and appends work in one indivisible symbolic step.
There is no accessible permission or suspended authorized state between its
final check and effect. A real implementation must establish why secret work
cannot escape that boundary, why every usable copy must pass through it, and
why crash, cancellation or restored memory cannot replay permission. A durable
Boolean, atomic storage write, mutex or exported capability alone establishes
none of those premises. No hardware, remote service or custody construction is
selected by this comparison.

An observed loss is a precise model transition, not evidence of the cut reached
by a real lost reply. Before-effect loss may leave the ideal effect word unused;
this does not authorize real recovery or a retry from uncertain private state.
Uncertainty must remain spent unless independently qualified evidence establishes
the selected real effect and output boundaries. No recovery fallback is added.

## Audit and replay

Findings use external work history independently of current burn/effect flags,
epoch, worker phase or accepted receipts. The finite graphs exhaust even after
a counterexample. Breadth-first search retains a shortest trace for each
finding. Every trace can be replayed through `step` to the exact reported state.
Shape validation accepts only exact bounded symbolic values; it is not proof
that an externally constructed state is reachable.

Run the conditional reference comparison with:

```sh
python3 -B scripts/model_nonce_grant_copy.py --policy effect-coupled
```

Run all controls with:

```sh
python3 -B scripts/model_nonce_grant_copy.py --policy all
```

Exit zero means completed finite exploration without a finding under its
premises, one means completed comparisons containing counterexamples, and two
means argument refusal or a state cutoff. A cutoff stays `incomplete` even when
it has already found a counterexample. The all-policy command deliberately
returns one. Unknown or invalid arguments are not echoed, and option
abbreviations are refused. Output contains fixed public symbols only.

## Acceptance requirements before a private bridge

1. Inventory every state carrying permission after durable nonce consumption:
   worker memory, queued requests, serialized grants, cached checks, returned
   permits and suspended backend calls. Identify exactly which states are
   copyable and how copies can reach the actual secret-dependent operation.
2. Establish the real boundary covering those copies through the irreversible
   computation. If authorization returns before work, independently qualify
   why its already granted state cannot be replayed. Receipt identity or result
   rejection is downstream evidence, not prevention of a second computation.
3. Separate lost authorization, lost work and lost output. Preserve spent state
   on uncertainty. Qualify process death, cancellation, copied in-flight state,
   durable storage cuts and exact retained-output replay with the selected
   backend; do not infer their behavior from these atomic symbolic transitions.
4. Resolve exact input authentication, fresh entropy, secure memory,
   library-internal copies, producer/source identity and independent review of
   the adaptor construction and application protocol separately.

The requirement, four symbolic comparisons and measured exploration are three
distinct layers. No production policy is selected. Physical atomicity, memory
custody, adversarial holders, full queue semantics, related nonce components,
multiple nonces, time, network and funded outcomes remain outside these graphs.
All four immutable source inventories, historical worker profiles and three
unfilled assessment reports remain preserved. See [Stage 72 validation](STAGE72_VALIDATION.md).
