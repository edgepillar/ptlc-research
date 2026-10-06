"""Finite nonce-invocation comparison using symbols, never secret material.

Two callers may own separate local copies of one pre-consumption snapshot. A
single nonce label denotes the same underlying nonce in both copies. Journal
commit, consumption, nonce-dependent work, result acceptance, output retention
and public delivery are distinct events. Result epochs fence acceptance only.

The reference policy ASSUMES an atomic durable consume operation shared by all
copies, outside the restorable snapshot, with exact binding enforced before
work. This is an unimplemented premise, not a storage design or cryptographic
worker. Alternate policies deliberately remove one premise. Audit events never
rewind, even when the modeled authority is restored. There is no arithmetic,
entropy, key, nonce bytes, signature, process, disk, transport or chain access.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json


POLICIES = (
    "entry-consume", "journal-only", "result-fence", "split-entry",
    "rollbackable-entry", "context-unchecked", "release-before-retain",
)
BINDING_FIELDS = (
    "session", "leg", "role", "key_aggregation", "tweak", "message",
    "nonce_round", "adaptor",
)
# Complete selected bindings are abstract symbols. Each alternative changes
# exactly one coordinate. Equality is ideal, not canonical parsing or authority.
BINDINGS = ((0,) * 8,) + tuple(
    tuple(int(position == changed) for position in range(8))
    for changed in range(8)
)
DEFAULT_BINDINGS = (0, 6)  # Exact selected binding, or a different message.
PHASES = (
    "absent", "idle", "requested", "checked", "authorized", "executed",
    "returned", "retained", "lost", "refused",
)
KINDS = (
    "restore-copy", "request", "claim", "check", "burn", "work", "result",
    "retain", "release", "replay", "lose", "lookup",
)


@dataclass(frozen=True)
class Action:
    kind: str
    actor: int = -1
    binding: int = -1


@dataclass(frozen=True)
class Actor:
    phase: str = "idle"
    binding: int = -1
    epoch: int = -1
    durable_grant: bool = False
    output: int = -1
    retained: bool = False
    released: bool = False
    replayed: bool = False


@dataclass(frozen=True)
class Work:
    actor: int
    nonce: int
    binding: int
    epoch: int
    durable_consumption_before_work: bool


@dataclass(frozen=True)
class Delivery:
    actor: int
    nonce: int
    binding: int
    epoch: int
    retained_before_delivery: bool
    replay: bool


@dataclass(frozen=True)
class State:
    epoch: int = 0
    consumed: bool = False
    actors: tuple = (Actor(), Actor(phase="absent"))
    # External effect history is separate from all restorable local state.
    work: tuple = ()
    deliveries: tuple = ()


@dataclass(frozen=True)
class Witness:
    name: str
    trace: tuple
    state: State


@dataclass(frozen=True)
class Comparison:
    policy: str
    bindings: tuple
    complete: bool
    reason: str
    states: int
    transitions: int
    witnesses: tuple

    @property
    def status(self):
        if not self.complete:
            return "incomplete"
        return "counterexample" if self.witnesses else "conditional-no-counterexample"


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _parameters(policy, bindings):
    if type(policy) is not str or policy not in POLICIES:
        raise ValueError("an explicit supported nonce policy is required")
    if (type(bindings) is not tuple or not 1 <= len(bindings) <= 9
            or any(not _integer(value, 0, 8) for value in bindings)
            or bindings != tuple(sorted(set(bindings))) or bindings[0] != 0):
        raise ValueError("an exact ordered finite binding domain is required")


def _state(state):
    if (type(state) is not State or not _integer(state.epoch, 0, 1)
            or type(state.consumed) is not bool or type(state.actors) is not tuple
            or len(state.actors) != 2 or type(state.work) is not tuple
            or len(state.work) > 2 or type(state.deliveries) is not tuple
            or len(state.deliveries) > 4):
        raise ValueError("invalid finite nonce state")
    for actor in state.actors:
        if (type(actor) is not Actor or type(actor.phase) is not str
                or actor.phase not in PHASES or not _integer(actor.binding, -1, 8)
                or not _integer(actor.epoch, -1, 1) or not _integer(actor.output, -1, 8)
                or any(type(getattr(actor, field)) is not bool for field in
                       ("durable_grant", "retained", "released", "replayed"))
                or ((actor.phase in ("absent", "idle")) != (actor.binding == -1))
                or ((actor.binding == -1) != (actor.epoch == -1))
                or (actor.retained and actor.output == -1)
                or (actor.released and actor.output == -1)
                or (actor.replayed and not (actor.released and actor.retained))):
            raise ValueError("invalid finite nonce caller")
    for event in state.work:
        if (type(event) is not Work or not _integer(event.actor, 0, 1)
                or type(event.nonce) is not int or event.nonce != 0
                or not _integer(event.binding, 0, 8) or not _integer(event.epoch, 0, 1)
                or type(event.durable_consumption_before_work) is not bool):
            raise ValueError("invalid finite nonce work audit")
    for event in state.deliveries:
        if (type(event) is not Delivery or not _integer(event.actor, 0, 1)
                or type(event.nonce) is not int or event.nonce != 0
                or not _integer(event.binding, 0, 8) or not _integer(event.epoch, 0, 1)
                or type(event.retained_before_delivery) is not bool
                or type(event.replay) is not bool):
            raise ValueError("invalid finite nonce delivery audit")


def _action(action):
    if (type(action) is not Action or type(action.kind) is not str
            or action.kind not in KINDS or not _integer(action.actor, -1, 1)
            or not _integer(action.binding, -1, 8)):
        raise ValueError("an exact supported finite nonce action is required")
    if action.kind == "restore-copy":
        valid = (action.actor, action.binding) == (-1, -1)
    elif action.kind == "request":
        valid = action.actor in (0, 1) and action.binding >= 0
    else:
        valid = action.actor in (0, 1) and action.binding == -1
    if not valid:
        raise ValueError("unsupported finite nonce action fields")


def _actor(state, index, following, **changes):
    actors = list(state.actors)
    actors[index] = following
    return replace(state, actors=tuple(actors), **changes)


def _transitions(state, policy, bindings):
    if state.actors[1].phase == "absent":
        # Separate lifetime locks on copied files may both succeed. The copy
        # starts from a fixed pre-consumption snapshot, never from a fresh nonce.
        yield Action("restore-copy"), _actor(
            state, 1, Actor(), epoch=1,
            consumed=False if policy == "rollbackable-entry" else state.consumed,
        )
    for index, actor in enumerate(state.actors):
        def emit(kind, following, **changes):
            return Action(kind, index), _actor(state, index, following, **changes)
        if actor.phase == "idle":
            for binding in bindings:
                yield Action("request", index, binding), _actor(
                    state, index, replace(actor, phase="requested", binding=binding, epoch=state.epoch),
                )
        if actor.phase == "requested":
            matches = actor.binding == 0 or policy == "context-unchecked"
            if policy == "split-entry":
                # Deliberately unsafe: permission is cached before the burn.
                yield emit("check", replace(actor, phase="checked" if matches and not state.consumed else "refused"))
            else:
                local_only = policy in ("journal-only", "result-fence")
                allowed = matches and (local_only or not state.consumed)
                following = replace(actor, phase="authorized" if allowed else "refused",
                                    durable_grant=allowed and policy != "result-fence")
                yield emit("claim", following, consumed=state.consumed or (allowed and not local_only))
        if actor.phase == "checked":
            # A blind durable write is not an atomic check-and-consume. Both
            # callers can already hold cached permission when this write occurs.
            yield emit("burn", replace(actor, phase="authorized", durable_grant=True), consumed=True)
        if actor.phase == "authorized":
            event = Work(index, 0, actor.binding, actor.epoch, actor.durable_grant)
            yield emit("work", replace(actor, phase="executed"), work=state.work + (event,))
        if actor.phase == "executed":
            accepted = actor.epoch == state.epoch
            if policy == "result-fence":
                accepted = accepted and not state.consumed
            following = replace(actor, phase="returned" if accepted else "refused",
                                output=actor.binding if accepted else -1)
            yield emit("result", following, consumed=state.consumed or (accepted and policy == "result-fence"))
        if actor.phase == "returned":
            yield emit("retain", replace(actor, phase="retained", retained=True))
        if (actor.phase in ("returned", "retained") and not actor.released
                and (actor.retained or policy == "release-before-retain")):
            event = Delivery(index, 0, actor.output, actor.epoch, actor.retained, False)
            yield emit("release", replace(actor, released=True), deliveries=state.deliveries + (event,))
        if actor.phase == "retained" and actor.released and not actor.replayed:
            event = Delivery(index, 0, actor.output, actor.epoch, True, True)
            yield emit("replay", replace(actor, replayed=True), deliveries=state.deliveries + (event,))
        if actor.phase in ("authorized", "executed", "returned", "retained"):
            # Loss is ambiguous about work. It never rewinds the external audit
            # or the reference consume word, and offers no automatic signing.
            yield emit("lose", replace(actor, phase="lost"))
        if actor.phase == "lost" and actor.retained:
            yield emit("lookup", replace(actor, phase="retained"))


def successors(state, *, policy="entry-consume", bindings=DEFAULT_BINDINGS):
    _parameters(policy, bindings)
    _state(state)
    yield from _transitions(state, policy, bindings)


def step(state, action, *, policy="entry-consume", bindings=tuple(range(9))):
    _parameters(policy, bindings)
    _state(state)
    _action(action)
    for candidate, following in _transitions(state, policy, bindings):
        if candidate == action:
            return following
    raise ValueError("finite nonce action is unavailable")


def findings(state):
    """Read the irreversible audit, independently of policy and action guards."""
    _state(state)
    names = []
    if len(state.work) > len({event.nonce for event in state.work}):
        names.append("same_nonce_work_repeated")
    if any(not event.durable_consumption_before_work for event in state.work):
        names.append("work_before_durable_consumption")
    if any(BINDINGS[event.binding] != BINDINGS[0] for event in state.work):
        names.append("work_outside_selected_binding")
    if any(not event.retained_before_delivery for event in state.deliveries):
        names.append("output_delivered_before_retention")
    for event in state.deliveries:
        if not any((work.actor, work.nonce, work.binding, work.epoch) ==
                   (event.actor, event.nonce, event.binding, event.epoch) for work in state.work):
            names.append("delivery_without_same_work_output")
            break
    for index, event in enumerate(state.deliveries):
        if event.replay and not any(not prior.replay and
                (prior.actor, prior.nonce, prior.binding, prior.epoch) ==
                (event.actor, event.nonce, event.binding, event.epoch)
                for prior in state.deliveries[:index]):
            names.append("replay_without_same_retained_output")
            break
    return tuple(names)


def compare(*, policy="entry-consume", bindings=DEFAULT_BINDINGS, max_states=100000):
    """Explore the entire finite graph or explicitly report a resource cutoff."""
    _parameters(policy, bindings)
    if not _integer(max_states, 1, 1000000):
        raise ValueError("a bounded exact integer search limit is required")
    start = State()
    parents = {start: None}
    queue = deque((start,))
    witnesses = {}
    transitions = 0
    while queue:
        state = queue.popleft()
        for name in findings(state):
            if name not in witnesses:
                trace = []
                cursor = state
                while parents[cursor] is not None:
                    previous, action = parents[cursor]
                    trace.append(action)
                    cursor = previous
                witnesses[name] = Witness(name, tuple(reversed(trace)), state)
        for action, following in _transitions(state, policy, bindings):
            transitions += 1
            if following not in parents:
                if len(parents) >= max_states:
                    return Comparison(policy, bindings, False, "state-limit", len(parents),
                                      transitions, tuple(witnesses.values()))
                parents[following] = (state, action)
                queue.append(following)
    return Comparison(policy, bindings, True, "finite-graph-exhausted", len(parents),
                      transitions, tuple(witnesses.values()))


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid finite nonce model arguments")


def main(argv=None):
    parser = _Parser(description="Finite symbolic nonce invocation comparison; no signer")
    parser.add_argument("--policy", choices=("all", *POLICIES), default="all")
    parser.add_argument("--max-states", type=int, default=100000)
    try:
        args = parser.parse_args(argv)
        policies = POLICIES if args.policy == "all" else (args.policy,)
        reports = tuple(compare(policy=policy, max_states=args.max_states) for policy in policies)
    except ValueError:
        print("FAIL: finite nonce model arguments rejected")
        return 2
    print(json.dumps({
        "schema": "ptlc-nonce-invocation-model-v1",
        "claim": "finite symbols only; ideal consume premise unimplemented; application and core NO-GO",
        "bounds": {"callers": 2, "restored_copies": 1, "nonce_labels": 1,
                   "request_bindings": DEFAULT_BINDINGS, "max_states": args.max_states},
        "results": [dict(asdict(report), status=report.status) for report in reports],
    }, indent=2))
    if any(not report.complete for report in reports):
        return 2
    return int(any(report.witnesses for report in reports))


if __name__ == "__main__":
    raise SystemExit(main())
