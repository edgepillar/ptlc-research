"""Bounded, test-only consumer retention over selected original-read histories.

Signature validity is a symbolic fixture premise, not a cryptographic check.
Two consumers retain separate witnesses. Atomic per-consumer comparison and
an ideal nonrollback witness are premises, not implemented storage. Cached
deliveries are selected independently of the modeled source copy. This is a
finite schedule experiment, not a causal message protocol or full action graph.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
import json

from scripts import model_original_read_provenance as statements


POLICIES = ("replace-witness", "retained-prefix", "ideal-nonrollback-prefix")
MAX_EVENTS = 8
MAX_DELIVERIES = 4
# Opaque complete event symbols. Tests compare all live pairs with the unchanged
# opening validator; revision numbers alone never establish this relation.
HISTORIES = {
    "initial_absent": (),
    "pending": ("charge-primary",),
    "completed": ("charge-primary", "effect-primary"),
    "revoked_absent": ("revoke",),
    "revoked_pending": ("charge-primary", "revoke"),
    "revoked_completed": ("charge-primary", "effect-primary", "revoke"),
    "replaced_completed": ("charge-primary", "effect-primary", "replace-root"),
    "reduced_pending_two_charges": ("charge-primary", "charge-secondary", "reduce-root"),
    "mode_round_trip_pending": ("charge-primary", "unavailable-mode", "live-mode"),
}
SELECTIONS = tuple(statements.SAMPLES) + tuple("fresh:" + n for n in statements.SAMPLES)


def history(selected):
    if type(selected) is not str or selected not in SELECTIONS:
        raise ValueError("an independently selected finite history is required")
    return selected.removeprefix("fresh:")


def extends(earlier, later):
    """Symbolic retained-prefix relation; no signatures, source or permission."""
    first, second = history(earlier), history(later)
    if first not in HISTORIES or second not in HISTORIES:
        return False
    a, b = statements.PACKETS[earlier].query, statements.PACKETS[later].query
    old, new = HISTORIES[first], HISTORIES[second]
    return (a.root == b.root and a.original == b.original
            and len(old) <= len(new) and new[:len(old)] == old)


def bound_read(selected, incoming, *, check="signature-premise"):
    """Full independent statement binding remains required for every policy."""
    name = history(selected)
    if not statements.accepts(selected, incoming, binding="snapshot-bound", check=check):
        return "statement-refused"
    return "no-live-opening" if name not in HISTORIES else "bound-live-read"


@dataclass(frozen=True)
class Consumer:
    witness: str = "pending"
    saved_witness: str = "pending"
    # This ideal witness is outside the copied consumer-state domain. Only the
    # ideal comparison consults or advances it; no storage adapter exists here.
    nonrollback_witness: str = "pending"
    restored: bool = False
    outcome_unknown: bool = True


@dataclass(frozen=True)
class Delivery:
    actor: int
    selected: str
    incoming: str
    prior_witness: str
    accepted: bool
    reason: str
    source_view: str
    check: str


@dataclass(frozen=True)
class State:
    source_view: str = "pending"
    saved_source: str = "pending"
    source_restored: bool = False
    external_synthetic_effects: int = 0
    consumers: tuple = (Consumer(), Consumer())
    # An observer's trace audit survives restores solely to expose lost
    # knowledge. It is never consulted by replace-witness or retained-prefix.
    deliveries: tuple = ()
    events: int = 0


@dataclass(frozen=True)
class Action:
    kind: str
    actor: int = -1
    selected: str = ""
    incoming: str = ""


@dataclass(frozen=True)
class Witness:
    name: str
    trace: tuple
    state: State


@dataclass(frozen=True)
class Comparison:
    policy: str
    complete: bool
    reason: str
    schedules: int
    transitions: int
    cases: tuple
    violations: tuple
    boundaries: tuple


def _shape(state, policy, check):
    if (type(state) is not State or type(policy) is not str or policy not in POLICIES
            or type(check) is not str or check not in statements.CHECKS
            or any(type(v) is not str or v not in statements.SAMPLES
                   for v in (state.source_view, state.saved_source))
            or type(state.source_restored) is not bool
            or type(state.external_synthetic_effects) is not int
            or not 0 <= state.external_synthetic_effects <= 2
            or type(state.events) is not int or not 0 <= state.events <= MAX_EVENTS
            or type(state.consumers) is not tuple or len(state.consumers) != 2
            or type(state.deliveries) is not tuple or len(state.deliveries) > MAX_DELIVERIES):
        raise ValueError("invalid bounded consumer state")
    for consumer in state.consumers:
        if (type(consumer) is not Consumer or type(consumer.restored) is not bool
                or consumer.outcome_unknown is not True
                or any(type(v) is not str or (v and (v not in SELECTIONS or history(v) not in HISTORIES))
                    for v in (consumer.witness, consumer.saved_witness, consumer.nonrollback_witness))):
            raise ValueError("invalid finite consumer witness")
    for delivery in state.deliveries:
        if (type(delivery) is not Delivery or type(delivery.actor) is not int
                or delivery.actor not in (0, 1) or type(delivery.selected) is not str
                or delivery.selected not in SELECTIONS or type(delivery.incoming) is not str
                or delivery.incoming not in statements.PACKETS or type(delivery.accepted) is not bool
                or type(delivery.prior_witness) is not str
                or (delivery.prior_witness and history(delivery.prior_witness) not in HISTORIES)
                or type(delivery.source_view) is not str or delivery.source_view not in statements.SAMPLES
                or type(delivery.check) is not str or delivery.check not in statements.CHECKS
                or type(delivery.reason) is not str or delivery.reason not in
                    ("statement-refused", "no-live-opening", "prefix-refused", "retained")):
            raise ValueError("invalid finite delivery audit")


def step(state, action, *, policy="retained-prefix", check="signature-premise"):
    """Apply one atomic abstract event within explicit finite budgets."""
    _shape(state, policy, check)
    if (type(action) is not Action or type(action.kind) is not str
            or type(action.actor) is not int or type(action.selected) is not str
            or type(action.incoming) is not str or state.events == MAX_EVENTS):
        raise ValueError("invalid or exhausted bounded action")
    source_events = ("charge", "complete", "revoke", "outage", "live", "restore-source", "repeat-effect")
    if action.kind in source_events:
        if action.actor != -1 or action.selected or action.incoming:
            raise ValueError("source events cannot contain delivery selections")
        if action.kind == "restore-source":
            if state.source_restored or state.source_view == state.saved_source:
                raise ValueError("only one changed coherent source restore is modeled")
            return replace(state, source_view=state.saved_source, source_restored=True, events=state.events+1)
        if action.kind == "repeat-effect":
            if (not state.source_restored or state.source_view != "pending"
                    or state.external_synthetic_effects != 1):
                raise ValueError("the repeated effect requires the selected restored pending copy")
            return replace(state, source_view="completed", external_synthetic_effects=2, events=state.events+1)
        target = {("initial_absent", "charge"): "pending", ("pending", "complete"): "completed",
            ("pending", "revoke"): "revoked_pending", ("pending", "outage"): "unavailable_pending",
            ("unavailable_pending", "live"): "mode_round_trip_pending"}.get((state.source_view, action.kind))
        if target is None or (action.kind == "complete" and state.external_synthetic_effects != 0):
            raise ValueError("source event is outside the selected finite sequence")
        return replace(state, source_view=target, events=state.events+1,
            external_synthetic_effects=state.external_synthetic_effects + (action.kind == "complete"))
    if action.actor not in (0, 1):
        raise ValueError("one of two consumers must be selected")
    consumer = state.consumers[action.actor]
    consumers = list(state.consumers)
    if action.kind == "restore-consumer":
        if action.selected or action.incoming or consumer.restored:
            raise ValueError("only one coherent restore per selected consumer is modeled")
        consumers[action.actor] = replace(consumer, witness=consumer.saved_witness, restored=True)
        return replace(state, consumers=tuple(consumers), events=state.events+1)
    if action.kind != "deliver" or len(state.deliveries) == MAX_DELIVERIES:
        raise ValueError("invalid or exhausted finite delivery")
    reason = bound_read(action.selected, action.incoming, check=check)
    prior = consumer.nonrollback_witness if policy == "ideal-nonrollback-prefix" else consumer.witness
    accepted = reason == "bound-live-read"
    if accepted and policy != "replace-witness" and prior and not extends(prior, action.selected):
        accepted, reason = False, "prefix-refused"
    if accepted:
        reason = "retained"
        consumers[action.actor] = replace(consumer, witness=action.selected,
            nonrollback_witness=action.selected if policy == "ideal-nonrollback-prefix" else consumer.nonrollback_witness)
    delivery = Delivery(action.actor, action.selected, action.incoming, prior, accepted, reason, state.source_view, check)
    return replace(state, consumers=tuple(consumers), deliveries=state.deliveries+(delivery,), events=state.events+1)


def findings(state, *, policy="retained-prefix", check="signature-premise"):
    """Classify trace observations; this audit is not a consumer authority."""
    _shape(state, policy, check)
    violations, boundaries = set(), set()
    previous = {}
    for delivery in state.deliveries:
        if delivery.reason == "no-live-opening":
            boundaries.add("signed_unavailable_has_no_live_retention_evidence")
        if not delivery.accepted:
            continue
        if not statements.PACKETS[delivery.incoming].signature_valid:
            violations.add("callback_flags_without_signature_mathematics")
        old = previous.get(delivery.actor)
        if old and not extends(old, delivery.selected):
            violations.add("accepted_older_history_after_prior_knowledge" if extends(delivery.selected, old)
                           else "accepted_incomparable_history_after_prior_knowledge")
        previous[delivery.actor] = delivery.selected
        selected, current = statements.PACKETS[delivery.selected], statements.SAMPLES[delivery.source_view]
        if replace(selected.query, challenge=0) != current.query or selected.claim != current.claim:
            boundaries.add("historical_selection_does_not_identify_source_view")
        if selected.query.challenge:
            boundaries.add("fresh_challenge_does_not_select_latest_history")
        boundaries.add("retained_history_is_not_authority_permission_or_recovery")
    first, second = (c.witness for c in state.consumers)
    if first and second and not extends(first, second) and not extends(second, first):
        boundaries.add("separate_consumers_keep_incomparable_futures")
    for index, consumer in enumerate(state.consumers):
        if consumer.restored and any(d.actor == index and d.accepted
                and d.selected != consumer.saved_witness for d in state.deliveries):
            boundaries.add("coherent_consumer_restore_can_erase_local_knowledge")
    if state.source_restored:
        boundaries.add("coherent_source_restore_does_not_rewind_external_outcome")
    if state.external_synthetic_effects == 2:
        boundaries.add("same_restored_history_can_repeat_external_synthetic_effect")
    return tuple(sorted(violations)), tuple(sorted(boundaries))


def _delivery(actor, selected, incoming=None):
    return Action("deliver", actor, selected, selected if incoming is None else incoming)


STREAMS = (
    ("opposite-fork-orders", (_delivery(0, "completed"), _delivery(0, "revoked_pending")),
        (_delivery(1, "revoked_pending"), _delivery(1, "completed")), (Action("complete"),)),
    ("delayed-fresh-old-absence", (_delivery(0, "completed"), _delivery(0, "fresh:initial_absent")),
        (_delivery(1, "completed"), _delivery(1, "fresh:initial_absent")), (Action("complete"),)),
    ("source-and-consumer-restore", (_delivery(0, "completed"), Action("restore-consumer", 0), _delivery(0, "pending")),
        (_delivery(1, "completed"), _delivery(1, "pending")),
        (Action("complete"), Action("restore-source"), Action("repeat-effect"))),
    ("outage-and-distinct-live-future", (_delivery(0, "unavailable_pending"), _delivery(0, "mode_round_trip_pending")),
        (_delivery(1, "completed"), _delivery(1, "mode_round_trip_pending")), (Action("outage"), Action("live"))),
)


def comparison(*, policy="retained-prefix", max_schedules=1000):
    if (type(policy) is not str or policy not in POLICIES or type(max_schedules) is not int
            or not 0 <= max_schedules <= 10000):
        raise ValueError("explicit finite comparison parameters are required")
    schedules = transitions = 0
    cases, violations, boundaries = [], {}, {}
    for name, *streams in STREAMS:
        count = 0
        for trace in statements.interleavings(*streams):
            if schedules == max_schedules:
                return Comparison(policy, False, "schedule-cap", schedules, transitions,
                    tuple(cases+[(name, count)]), tuple(violations.values()), tuple(boundaries.values()))
            state, prefix = State(), ()
            for action in trace:
                state = step(state, action, policy=policy)
                prefix += (action,)
                transitions += 1
                found, limited = findings(state, policy=policy)
                for table, names in ((violations, found), (boundaries, limited)):
                    for finding in names:
                        table.setdefault(finding, Witness(finding, prefix, state))
            schedules += 1
            count += 1
        cases.append((name, count))
    return Comparison(policy, True, "selected-schedules-complete", schedules, transitions,
        tuple(cases), tuple(violations.values()), tuple(boundaries.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", choices=POLICIES, default="retained-prefix")
    parser.add_argument("--max-schedules", type=int, default=1000)
    args = parser.parse_args()
    try:
        result = comparison(policy=args.policy, max_schedules=args.max_schedules)
    except ValueError:
        parser.error("invalid finite comparison parameters")
    output = asdict(result)
    output.update(status="complete" if result.complete else "incomplete",
        domain=dict(consumers=2, sample_statements=10, signed_counterclaims=6,
            selected_stream_sets=4, max_events=MAX_EVENTS, max_deliveries=MAX_DELIVERIES,
            source_restores=1, restores_per_consumer=1, full_action_graph=False),
        signature_verification="symbolic fixture premise; no signature mathematics in this model",
        atomic_retention="serialized per-consumer comparison and retention are an ideal event; no storage adapter",
        nonrollback_retention="ideal policy only; witness lies outside source and consumer copied-state domains",
        current_authority=False, global_canonical_choice=False, application_permission=False, recovery=False)
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0 if result.complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
