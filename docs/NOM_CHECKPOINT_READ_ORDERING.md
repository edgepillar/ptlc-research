# NoM checkpoint reference read ordering

This additive offline model gives checkpoint publications and selected reads an
explicit finite order. It requires actual complete reference states and evidence
openings. It implements no service, signer, storage transaction or nonrollback
domain. Every comparison stays **HOLD**, recovery **NONE**, application/core
**NO-GO**.

Baseline:
[`c5460ad8ad46b4cf338d3163c4223ac6879de868`](https://github.com/edgepillar/ptlc-research/tree/c5460ad8ad46b4cf338d3163c4223ac6879de868).
All 213 earlier measured inputs remain unchanged. The existing
[response signature mathematics](NOM_CHECKPOINT_RESPONSE.md) remains separate:
its signature statement does not authenticate these new ordering descriptors.

## Operational requirements

A current service read must identify the serialized state at which the exact
query was evaluated. A later publication may make that result old at delivery.
A challenge, signature or larger checkpoint counter alone cannot identify this
position. The protected transition must retain the query, its complete original
evidence, evaluated head, UNKNOWN charges and possible disclosure before issuing
an operational result. Lost replies cannot justify another original operation,
automatic retry, signing, work replenishment or replacement.

The ordering domain must survive coherent consumer/source restore. Independently
provisioned service/root/key roles, external nonrollback retention, durable
acknowledgment, shared atomic state transitions, explicit lifecycle/migration and
actual original-operation entry are separate requirements. A caller selecting an
old trace as its own anchor does not meet them. This profile chooses no storage
technology, operational authority, clock, signature construction or deployment.

## Selected reference construction

`bootstrap_order_trace` explicitly retains an actual complete
`ReferenceCheckpoint`; it certifies neither safe absence nor a fresh work budget.
Each trace retains complete actual inputs and a canonical descriptor. It admits
at most 32 events and 32 KiB of canonical ASCII JSON under the existing twelve-level
decoder. Both bounds apply; a full trace refuses without truncating history.
The earlier sixteen-checkpoint bound remains unchanged.

`publish_reference` appends exactly one complete checkpoint lineage extension.
The policy, work scope and every historical source-context descriptor stay exact.
An incoming higher counter cannot replace a skipped parent, sibling or changed
source view. Both publication and read require the exact preceding trace digest.
This functional expected-state check is not a shared-server CAS or transaction.

`evaluate_reference_read` appends a READ event over the exact selected minimum,
query and complete head/opening present at that position. It retains actual before
and after states plus the opening in `OrderedCheckpointRead`. The event binds the
preceding state digest, query, evaluation head and opening commitment. A challenge
cannot be repeated anywhere in the retained finite trace, including after changing
the known minimum. No challenge uniqueness beyond that supplied trace is proved.

The new SHA-256 domains for trace, event and selected-read descriptors are distinct
from earlier source/custody/response signature domains. They create commitments,
not authentication. Public descriptors cannot reconstruct an actual trace, read
or opening. No existing signature is relabeled as permission for this new role.

Every public operation starts fresh complete-input validation. Repeated contexts
are deduplicated only inside that pure operation; no mutable global trust cache
survives to another call. Frozen objects and defensive exports detect accidental
aliasing. The model invokes no foreign callback, file/process/network entry or
clock. This is not a hostile-runtime boundary or concurrent service implementation.

## Independently selected reference prefix

`select_order_anchor` retains an actual full trace supplied independently of the
reply. `inspect_ordered_reply` requires the read's complete after-state events to
be an exact prefix of that trace and the candidate opening to equal the head
actually evaluated at the selected read. A descriptor-only anchor/read, absent
original opening, forked trace, missing read event, or reply from before/after
that evaluation refuses. The larger complete UNKNOWN list from the independently
retained anchor or local state remains charged.

| Reference order | Selected diagnostic |
| --- | --- |
| READ old head, then PUBLISH newer heads | Preserve the old read position and larger retained UNKNOWN list |
| PUBLISH newer head, then READ | An old-head reply cannot replace the evaluated newer opening |
| READ between two publications | Later events remain visible; currentness at delivery is not established |
| Restore old trace/read while retaining a newer independent trace | Refuse the mismatched event prefix |
| Outage | No read receipt, candidate head, absence claim or cached positive fallback; retain UNKNOWN work |

`inspect_ordering_outage` validates the selected minimum against complete retained
reference history and preserves the larger work list. It creates no READ event or
positive current-state verdict and mutates no trace.

## Unsafe controls and remaining acceptance

Coherently restoring an old trace, anchor and read still matches. Explicitly
bootstrapping after lost read history can reset the event count while retaining
the same checkpoint lineage. Two independently selected sibling traces can both
match without shared atomic authority. A correctly ordered read remains old at
delivery after a later publication. These successful unsafe controls establish
no real nonrollback state, unique current service or work permission.

Operational current-read authentication, independently provisioned authority,
external nonrollback storage, shared atomic transitions, actual work entry,
independent assessment and physical power-loss qualification remain unfilled.
No deployment, node activation, wallet access, application signing, transaction
construction/broadcast or real funds are connected. See the
[qualification boundary](NOM_CHECKPOINT_READ_ORDERING_VALIDATION.md).
