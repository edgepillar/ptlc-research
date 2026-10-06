# Nonce consumption before worker invocation

Status: finite source-only comparison. No private signer, nonce storage, new
worker, entropy source or cryptographic operation is implemented. Application
and core progression remain **NO-GO**.

## Requirement and the present gap

An uncertain response must not authorize another computation using the same
secret nonce. Rejecting an old result cannot undo nonce-dependent work that
already occurred. The requirement concerns every usable copy of the same nonce,
including a restored copy with its own valid local process and file ownership.

The [public nonce layer](NONCE_ROUNDS.md) rejects repeated complete encodings
visible in one retained journal. The separate test-only Rust owner consumes an
in-memory nonce before backend work and refuses a second invocation through that
owner. Neither provides a durable journal-to-secret-worker boundary covering
copied or restored nonce state. This model examines that missing boundary using
labels only; it does not connect the two implementations.

## Finite domain and ideal premises

[`model_nonce_invocation.py`](../scripts/model_nonce_invocation.py) explores two
callers, one original nonce label and one restoration of a fixed pre-consumption
snapshot. Both copies denote the same underlying nonce, never newly generated
randomness. Separate local lifetime locks are assumed to succeed on separate
files; this is an abstract premise, not another filesystem test. Restoration
increments an ideal external result epoch from zero to one. Epoch comparison
only controls acceptance of an already computed result.

The selected binding is a complete symbolic tuple: session, leg, role, key
aggregation, tweak, message, nonce round and adaptor. Nine fixed symbols are the
selected tuple and eight single-coordinate changes. Default exploration uses
the exact tuple and the different-message tuple. A separate regression exhausts
all nine under the reference policy. Symbol equality supplies no parsing,
authentication, source selection or agreement about real cryptographic inputs.
The eight coordinates do not define an executable backend request grammar or
exhaust every field of the application transcript.

Consumption, nonce-dependent work, result acceptance, output retention and
delivery are separate transitions. Loss can occur after a consume grant, work,
return or retention. Loss never erases the external work/delivery audit. An
accepted output is an ideal token bound to one modeled invocation; retention
and exact replay refer to that token, not measured signature bytes. Replay emits
no new work. One original delivery and one replay per caller keep the graph
finite. Lookup after loss is available only for a previously retained output.
Unretained output has no recovery or automatic signing fallback in this model.

The reference `entry-consume` policy **assumes** an atomic, durable consume
operation that every usable nonce copy must consult before work, outside the
restorable snapshot. It also assumes exact input binding and output retention
before delivery. Successful exploration depends on these premises. This
repository implements no such nonrollback authority or custody mechanism.
Only callers following the selected transitions are explored. Out-of-band
computation by a holder of an unrestricted nonce copy is outside this graph.
The model restores only the fixed pre-consumption snapshot. A granted worker,
in-flight capability or post-consumption memory snapshot is never cloned in
this graph; real custody must separately prevent such authority replay.

## Comparisons and replayable findings

Every policy retains result epoch checks. A refusal after work leaves its audit
entry intact. Findings inspect the irreversible audit independently of policy
flags, accepted outputs or current consume state.

| Policy | Deliberately selected difference | Consequence in the finite graph |
| --- | --- | --- |
| `entry-consume` | Shared atomic durable consume outside copied state | No counterexample under the stated premises and bounds |
| `journal-only` | Each copy durably consumes only its own local journal | Same nonce can be used by both locally valid owners |
| `result-fence` | Consume only while accepting a current result | Work precedes consumption; rejecting an old result still permits two computations |
| `split-entry` | Check availability, then blindly write the consumed state | Both callers can cache permission before either durable write |
| `rollbackable-entry` | Restoration also rewinds the consume authority | A second effect follows restoration despite old-result rejection |
| `context-unchecked` | Omit the exact complete input-binding comparison | Work occurs for a different selected input |
| `release-before-retain` | Permit delivery before output retention | Later retention cannot erase the earlier ordering violation |

The all-policy run exhausts each finite graph and retains a shortest trace for
each distinct finding. There are seven finding/policy witnesses: duplicate work
in four controls, work before consumption, wrong binding and premature delivery.
Each trace can be passed through `step` to reconstruct the exact reported state.
A resource cutoff reports `incomplete`, even if a counterexample was already
found; it cannot produce the conditional no-counterexample status.

Run the positive comparison with:

```sh
python3 -B scripts/model_nonce_invocation.py --policy entry-consume
```

Run all controls with:

```sh
python3 -B scripts/model_nonce_invocation.py --policy all
```

Exit zero means conditional finite completion without a finding, one means
completed comparisons containing counterexamples, and two means a cutoff or
argument refusal. The all-policy command intentionally returns one. Output
contains public symbols and bounds only; invalid arguments are not echoed.

## Before any real signer bridge

The [protocol requirement](PROTOCOL.md) remains separate from construction
selection. A candidate bridge needs an independently reviewed answer to all of
the following before private material or a funded flow is introduced:

1. Define which authority covers every usable secret-nonce copy and why a
   matching restored journal, another process, a copied machine or reconstructed
   nonce cannot bypass it. A result epoch or local file lock alone does not meet
   the modeled requirement. No hardware, remote authority or custody service is
   selected here.
2. Qualify an atomic check-and-consume before nonce-dependent work. Split reads
   followed by durable writes are insufficient in the selected race. Bind the
   complete backend-specific inputs, including aggregate context and tweak;
   a caller's descriptive digest is not consumed-input evidence.
3. Specify loss after consume, invocation and result retention. Preserve spent
   state on uncertainty. Reconcile the original retained output when available;
   distinguish exact retransmission from a new signature computation. Prove the
   real ownership and persistence cuts with process-death and storage faults.
4. Resolve fresh entropy, secure memory, library-internal copies, provisioning,
   producer/source authentication and the exact adaptor construction separately.
   Nonce-work uniqueness alone proves none of them or swap security.

This comparison selects no production policy. Real asynchronous worker queues,
forks, serialization, physical failure, hostile storage, cancellation inside a
cryptographic operation, multiple nonces, related nonce components, clocks,
network behavior and independent cryptographic assessment remain outside its
graph. No quantitative live failure or principal-loss claim follows from a
counterexample. All four immutable source inventories, all historical worker
profiles and the three unfilled assessment reports remain preserved. See
[Stage 71 validation](STAGE71_VALIDATION.md).
