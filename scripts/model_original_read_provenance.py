"""Finite original-read binding and delivery comparison; no source or signer.

Signature validity is a symbolic premise associated with named public fixtures.
Current truth and serialized entry history are ideal external premises. Selected
schedules and directed traces are not a full action graph or a security proof.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
import json


BINDINGS = ("peer-selected", "query-bound", "snapshot-bound")
USES = ("no-entry", "receipt-entry", "ideal-current-entry")
CHECKS = ("signature-premise", "callback-flags")


@dataclass(frozen=True)
class Query:
    root: int
    # Complete original id, revision, historical profile and proposal symbols.
    original: tuple
    policy_head: int
    record_head: int
    challenge: int = 0


@dataclass(frozen=True)
class Claim:
    observation: str
    active: object
    head_profile: object
    charge: object
    effect: object


@dataclass(frozen=True)
class Statement:
    query: Query
    claim: Claim
    signature_valid: bool = True
    callback_flags: bool = True


# Opaque symbols represent complete objects, not hash computations or keys.
# Policy head zero repeats after the outage; record head nine does not.
_ROWS = (
    ("initial_absent", 0, 0, 0, "absent", True, 0, None, None),
    ("pending", 0, 0, 1, "pending", True, 0, 1, None),
    ("completed", 0, 0, 2, "completed", True, 0, 1, 2),
    ("revoked_absent", 0, 1, 3, "absent", False, 0, None, None),
    ("revoked_pending", 0, 1, 4, "pending", False, 0, 1, None),
    ("revoked_completed", 0, 1, 5, "completed", False, 0, 1, 2),
    ("replaced_completed", 1, 2, 6, "completed", False, 1, 1, 2),
    ("reduced_pending_two_charges", 2, 3, 7, "pending", True, 2, 1, None),
    ("unavailable_pending", 0, 4, 8, "unavailable", None, None, None, None),
    ("mode_round_trip_pending", 0, 0, 9, "pending", True, 0, 1, None),
)
SAMPLES = {name: Statement(Query(root, (0, 0, 0, 0), policy, record),
    Claim(kind, active, profile, charge, effect))
    for name, root, policy, record, kind, active, profile, charge, effect in _ROWS}
COUNTER_BASES = {
    "false_absence_at_pending_head": "pending",
    "false_completion_at_two_charge_head": "reduced_pending_two_charges",
    "false_active_at_revoked_head": "revoked_pending",
    "same_id_other_proposal": "pending",
    "same_id_other_historical_profile": "replaced_completed",
    "fresh_challenge_over_initial_absence": "initial_absent",
}
COUNTERS = {
    "false_absence_at_pending_head": replace(SAMPLES["pending"],
        claim=Claim("absent", True, 0, None, None)),
    "false_completion_at_two_charge_head": replace(SAMPLES["reduced_pending_two_charges"],
        claim=Claim("completed", True, 2, 1, 2)),
    "false_active_at_revoked_head": replace(SAMPLES["revoked_pending"],
        claim=Claim("pending", True, 0, 1, None)),
    "same_id_other_proposal": replace(SAMPLES["pending"],
        query=replace(SAMPLES["pending"].query, original=(0, 0, 0, 1))),
    "same_id_other_historical_profile": replace(SAMPLES["replaced_completed"],
        query=replace(SAMPLES["replaced_completed"].query, original=(0, 0, 3, 0))),
    "fresh_challenge_over_initial_absence": replace(SAMPLES["initial_absent"],
        query=replace(SAMPLES["initial_absent"].query, challenge=1)),
}
PACKETS = dict(SAMPLES, **COUNTERS)
PACKETS.update({"fresh:" + name: replace(value, query=replace(value.query, challenge=1))
                for name, value in SAMPLES.items()})
PACKETS["zero-signatures"] = replace(SAMPLES["pending"], signature_valid=False)


@dataclass(frozen=True)
class Actor:
    phase: int = 0
    expected: str = ""
    incoming: str = ""
    accepted: bool = False
    outcome_unknown: bool = True
    restored: bool = False


@dataclass(frozen=True)
class Entry:
    actor: int
    incoming: str
    truth: str


@dataclass(frozen=True)
class State:
    view: str = "pending"
    truth: str = "pending"
    saved_view: str = "pending"
    source_restored: bool = False
    actors: tuple = (Actor(), Actor())
    # This ideal audit is deliberately outside the modeled restore domain.
    entries: tuple = ()


@dataclass(frozen=True)
class Action:
    kind: str
    actor: int = -1
    packet: str = ""


@dataclass(frozen=True)
class Witness:
    name: str
    trace: tuple
    state: State


@dataclass(frozen=True)
class Comparison:
    binding: str
    use: str
    complete: bool
    reason: str
    schedules: int
    transitions: int
    violations: tuple
    boundaries: tuple


def accepts(expected, incoming, *, binding="snapshot-bound", check="signature-premise"):
    """Symbolic comparison only; this function performs no signature mathematics."""
    if (type(expected) is not str or expected not in PACKETS or type(incoming) is not str
            or incoming not in PACKETS or type(binding) is not str or binding not in BINDINGS
            or type(check) is not str or check not in CHECKS):
        raise ValueError("explicit finite statements and comparison policy are required")
    selected, packet = PACKETS[expected], PACKETS[incoming]
    valid = packet.signature_valid if check == "signature-premise" else packet.callback_flags
    return valid and (binding == "peer-selected" or
        (packet.query == selected.query and
         (binding == "query-bound" or packet.claim == selected.claim)))


def _shape(state, binding, use, check):
    if (type(state) is not State or type(binding) is not str or binding not in BINDINGS
            or type(use) is not str or use not in USES or type(check) is not str or check not in CHECKS
            or any(type(value) is not str or value not in SAMPLES
                   for value in (state.view, state.truth, state.saved_view))
            or type(state.source_restored) is not bool or type(state.actors) is not tuple
            or len(state.actors) != 2 or type(state.entries) is not tuple or len(state.entries) > 2):
        raise ValueError("invalid finite model state")
    for actor in state.actors:
        if (type(actor) is not Actor or type(actor.phase) is not int or not 0 <= actor.phase <= 4
                or type(actor.expected) is not str or type(actor.incoming) is not str
                or actor.expected not in ("", *PACKETS) or actor.incoming not in ("", *PACKETS)
                or type(actor.accepted) is not bool or actor.outcome_unknown is not True
                or type(actor.restored) is not bool
                or (actor.phase == 0 and (actor.expected or actor.incoming or actor.accepted))
                or (actor.phase > 0 and not actor.expected)
                or (actor.phase == 1 and (actor.incoming or actor.accepted))
                or (actor.phase in (2, 3) and not actor.incoming)
                or (actor.phase < 3 and actor.accepted)
                or (actor.accepted and not accepts(actor.expected, actor.incoming,
                                                   binding=binding, check=check))):
            raise ValueError("invalid bounded reader history")
    for entry in state.entries:
        if (type(entry) is not Entry or type(entry.actor) is not int or entry.actor not in (0, 1)
                or type(entry.incoming) is not str or entry.incoming not in PACKETS
                or type(entry.truth) is not str or entry.truth not in SAMPLES):
            raise ValueError("invalid abstract entry audit")


def _actor(state, index, value):
    actors = list(state.actors); actors[index] = value
    return replace(state, actors=tuple(actors))


def _current(packet, truth):
    current = SAMPLES[truth]
    return (replace(packet.query, challenge=0) == current.query and packet.claim == current.claim
            and current.claim.observation == "pending" and current.claim.active is True
            and truth != "reduced_pending_two_charges")


def step(state, action, *, binding="snapshot-bound", use="no-entry", check="signature-premise"):
    """Apply an abstract event; sampling and ideal entry are atomic premises."""
    _shape(state, binding, use, check)
    if type(action) is not Action or type(action.kind) is not str or type(action.packet) is not str:
        raise ValueError("invalid bounded action")
    if action.kind in ("charge", "complete", "revoke", "outage", "live", "restore-source"):
        if type(action.actor) is not int or action.actor != -1 or action.packet:
            raise ValueError("source events are not peer actions")
        if action.kind == "restore-source":
            if state.source_restored:
                raise ValueError("only one coherent source restore is modeled")
            return replace(state, view=state.saved_view, source_restored=True)
        target = {("initial_absent", "charge"): "pending", ("pending", "complete"): "completed",
            ("pending", "revoke"): "revoked_pending", ("pending", "outage"): "unavailable_pending",
            ("unavailable_pending", "live"): "mode_round_trip_pending"}.get((state.truth, action.kind))
        if target is None:
            raise ValueError("source event is outside the selected finite sequence")
        return replace(state, view=target, truth=target)
    if type(action.actor) is not int or action.actor not in (0, 1):
        raise ValueError("one of two readers must be selected")
    actor = state.actors[action.actor]
    kind = action.kind
    if kind == "sample" and actor.phase == 0 and action.packet in ("", "fresh"):
        expected = ("fresh:" if action.packet else "") + state.view
        return _actor(state, action.actor, replace(actor, phase=1, expected=expected))
    if kind == "deliver" and actor.phase == 1 and action.packet in ("sample", *PACKETS):
        incoming = actor.expected if action.packet == "sample" else action.packet
        return _actor(state, action.actor, replace(actor, phase=2, incoming=incoming))
    if action.packet:
        raise ValueError("this action accepts no packet selection")
    if kind == "lose-return" and actor.phase == 1:
        return _actor(state, action.actor, replace(actor, phase=4))
    if kind == "restore-reader" and actor.phase == 4 and not actor.restored:
        return _actor(state, action.actor, Actor(restored=True))
    if kind == "verify" and actor.phase == 2:
        return _actor(state, action.actor, replace(actor, phase=3,
            accepted=accepts(actor.expected, actor.incoming, binding=binding, check=check)))
    if kind == "enter" and actor.phase == 3:
        result = _actor(state, action.actor, replace(actor, phase=4))
        if not actor.accepted or use == "no-entry":
            return result
        packet = PACKETS[actor.incoming]
        # The unsafe control treats an active pending reply as permission.
        if packet.claim.observation != "pending" or packet.claim.active is not True:
            return result
        if use == "ideal-current-entry" and (not _current(packet, state.truth) or state.entries):
            return result
        if len(state.entries) == 2:
            raise ValueError("the abstract entry audit bound is exhausted")
        return replace(result, entries=state.entries + (Entry(action.actor, actor.incoming, state.truth),))
    raise ValueError("action does not follow the selected reader lifecycle")


def findings(state, *, binding="snapshot-bound", use="no-entry", check="signature-premise"):
    _shape(state, binding, use, check)
    violations, boundaries = set(), set()
    for actor in state.actors:
        if actor.expected and actor.outcome_unknown:
            boundaries.add("read_does_not_clear_unknown_outcome")
        if not actor.accepted:
            continue
        expected, packet = PACKETS[actor.expected], PACKETS[actor.incoming]
        if not packet.signature_valid:
            violations.add("callback_flags_without_signature_mathematics")
        if packet.query != expected.query:
            violations.add("reply_replaced_independent_query")
        elif packet.claim != expected.claim:
            violations.add("accepted_claim_differs_from_owned_sample")
        current = SAMPLES[state.truth]
        if replace(packet.query, challenge=0) != current.query or packet.claim != current.claim:
            boundaries.add("historical_read_not_current")
        if use == "no-entry":
            boundaries.add("accepted_read_not_application_permission")
    for entry in state.entries:
        if not _current(PACKETS[entry.incoming], entry.truth):
            violations.add("entry_without_current_original_and_policy")
        if SAMPLES[entry.truth].claim.active is False:
            violations.add("entry_after_revocation")
        if SAMPLES[entry.truth].claim.observation == "completed":
            violations.add("entry_after_external_completion")
    if len(state.entries) > 1:
        violations.add("same_original_entered_more_than_once")
    if state.source_restored:
        boundaries.add("restored_source_does_not_rewind_external_history")
    if any(actor.restored for actor in state.actors):
        boundaries.add("reader_restore_does_not_reconcile_original")
    return tuple(sorted(violations)), tuple(sorted(boundaries))


def interleavings(*streams):
    """All shuffles of these streams, preserving each stream's order."""
    if all(not stream for stream in streams):
        yield ()
        return
    for index, stream in enumerate(streams):
        if stream:
            remaining = list(streams); remaining[index] = stream[1:]
            for suffix in interleavings(*remaining):
                yield (stream[0], *suffix)


def comparison(*, binding="snapshot-bound", use="no-entry", max_schedules=10000):
    """Two fixed readers and three selected environment streams; not a full graph.

    Signed lies, zero signatures, fresh challenges, collisions and lost delivery
    are directed tests, not actions included in this schedule enumeration.
    """
    _shape(State(), binding, use, "signature-premise")
    if type(max_schedules) is not int or not 1 <= max_schedules <= 100000:
        raise ValueError("explicit finite schedule cap is required")
    readers = tuple(tuple(Action(kind, actor, "sample" if kind == "deliver" else "")
        for kind in ("sample", "deliver", "verify", "enter")) for actor in (0, 1))
    environments = ((Action("revoke"),), (Action("outage"), Action("live")),
                    (Action("complete"), Action("restore-source")))
    schedules, transitions, violations, boundaries = 0, 0, {}, {}
    for environment in environments:
        for trace in interleavings(*readers, environment):
            if schedules == max_schedules:
                return Comparison(binding, use, False, "schedule-cap", schedules, transitions,
                    tuple(violations.values()), tuple(boundaries.values()))
            state = State()
            for index, action in enumerate(trace):
                state = step(state, action, binding=binding, use=use); transitions += 1
                names, limits = findings(state, binding=binding, use=use)
                for name in names: violations.setdefault(name, Witness(name, trace[:index+1], state))
                for name in limits: boundaries.setdefault(name, Witness(name, trace[:index+1], state))
            schedules += 1
    return Comparison(binding, use, True, "selected-schedules-complete", schedules, transitions,
        tuple(violations.values()), tuple(boundaries.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding", choices=BINDINGS, default="snapshot-bound")
    parser.add_argument("--use", choices=USES, default="no-entry")
    parser.add_argument("--max-schedules", type=int, default=10000)
    args = parser.parse_args()
    try:
        result = comparison(binding=args.binding, use=args.use, max_schedules=args.max_schedules)
    except ValueError:
        parser.error("invalid finite comparison parameters")
    output = asdict(result)
    output.update(status="complete" if result.complete else "incomplete",
        domain=dict(readers=2, sample_statements=10, signed_counterclaims=6,
            selected_environment_streams=3, full_action_graph=False),
        signature_verification="symbolic premise tied to named executed public fixtures; no mathematics in this model",
        entry_authority="ideal current facts and serialized nonrollback original entry audit; no implemented adapter",
        source_authentication=False, application_permission=False, recovery=False)
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0 if result.complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
