"""Finite offline comparison of canonical enrollment and quota ownership.

Protected resources and owner authorization are ideal environmental facts, not
claims decoded from a peer. Registry generations label the auditor's history;
they are not authenticated epochs. Charges are abstract reservations, not
worker entries, signatures, verdicts or durable transactions. No application,
network, journal, clock, cryptographic library or filesystem is used.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json


POLICIES = ("scope-keyed", "claimed-resource", "canonical-source", "checked-owner",
            "atomic-owner", "rollbackable-owner")
CANONICAL = POLICIES[2:]
OWNED = POLICIES[3:]
PROFILE = 0
EPOCH = 1


@dataclass(frozen=True)
class Bounds:
    attempt_limit: int = 1
    max_enrollments: int = 2
    max_charges: int = 2
    max_losses: int = 1


@dataclass(frozen=True)
class Proposal:
    resource: int = 0
    claimed_resource: int = 0
    label: int = 0
    epoch: int = EPOCH
    profile: int = PROFILE


def proposals():
    """Two resources; baseline and four single-field changes per resource."""
    values = []
    for resource in (0, 1):
        base = Proposal(resource, resource)
        values.extend((base, replace(base, label=1), replace(base, epoch=2),
                       replace(base, profile=1), replace(base, claimed_resource=1 - resource)))
    return tuple(values)


PROPOSALS = proposals()


@dataclass(frozen=True)
class Actor:
    ticket: int = 0
    binding: object = None
    checked: object = None


@dataclass(frozen=True)
class Record:
    ticket: int
    proposal: Proposal
    consumed: int = 0


@dataclass(frozen=True)
class Event:
    actor: int
    generation: int
    ticket: int
    proposal: Proposal
    owner_authorized: bool


@dataclass(frozen=True)
class State:
    actors: tuple = (Actor(), Actor())
    records: tuple = ()
    registrations: tuple = ()
    charges: tuple = ()
    generation: int = 0
    losses: int = 0
    available: bool = True


@dataclass(frozen=True)
class Action:
    kind: str
    actor: int = -1
    proposal: object = None
    owner_authorized: bool = True


@dataclass(frozen=True)
class Finding:
    name: str
    trace: tuple
    state: State


@dataclass(frozen=True)
class SearchResult:
    policy: str
    bounds: Bounds
    complete: bool
    reason: str
    states: int
    transitions: int
    safety_findings: tuple
    boundary_findings: tuple


def _int(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _parameters(bounds, policy):
    if (type(bounds) is not Bounds or not _int(bounds.attempt_limit, 1, 2)
            or not _int(bounds.max_enrollments, 2, 3)
            or not _int(bounds.max_charges, bounds.attempt_limit + 1, 3)
            or not _int(bounds.max_losses, 0, 1)
            or type(policy) is not str or policy not in POLICIES):
        raise ValueError("explicit finite enrollment bounds and policy are required")


def _proposal(value):
    if (type(value) is not Proposal or not all(_int(getattr(value, field), lower, upper)
            for field, lower, upper in (("resource", 0, 1), ("claimed_resource", 0, 1),
                                       ("label", 0, 1), ("epoch", 1, 2), ("profile", 0, 1)))
            or value not in PROPOSALS):
        raise ValueError("proposal is outside the selected finite single-field domain")


def _key(proposal, policy):
    if policy == "claimed-resource":
        return (proposal.claimed_resource,)
    if policy in CANONICAL and policy != "checked-owner":
        return (proposal.resource,)
    return (proposal.resource, proposal.claimed_resource, proposal.label, proposal.epoch, proposal.profile)


def _event(value, bounds, generation):
    if (type(value) is not Event or not _int(value.actor, 0, 1)
            or not _int(value.generation, 0, generation)
            or not _int(value.ticket, 1, bounds.max_enrollments)
            or type(value.owner_authorized) is not bool):
        raise ValueError("invalid modeled enrollment audit event")
    _proposal(value.proposal)


def _shape(state, bounds, policy):
    if (type(state) is not State or type(state.actors) is not tuple or len(state.actors) != 2
            or not _int(state.generation, 0, int(policy == "rollbackable-owner"))
            or not _int(state.losses, 0, bounds.max_losses) or type(state.available) is not bool
            or any(type(getattr(state, field)) is not tuple or len(getattr(state, field)) > maximum
                   for field, maximum in (("records", bounds.max_enrollments),
                                          ("registrations", bounds.max_enrollments),
                                          ("charges", bounds.max_charges)))):
        raise ValueError("invalid finite enrollment state")
    for actor in state.actors:
        if (type(actor) is not Actor or not _int(actor.ticket, 0, bounds.max_enrollments)
                or (actor.binding is None) != (actor.ticket == 0)
                or (actor.checked is not None and (policy != "checked-owner" or actor.ticket))):
            raise ValueError("invalid modeled caller binding")
        for value in (actor.binding, actor.checked):
            if value is not None:
                _proposal(value)
    registrations = {}
    for event in state.registrations:
        _event(event, bounds, state.generation)
        identity = (event.generation, event.ticket)
        if identity in registrations:
            raise ValueError("duplicate registration audit identity")
        registrations[identity] = event
    if state.generation and not any(event.generation == 0 for event in state.registrations):
        raise ValueError("rewound registry lacks its prior registration audit")
    for actor in state.actors:
        if actor.ticket and not any(event.ticket == actor.ticket
                and _key(event.proposal, policy) == _key(actor.binding, policy)
                for event in state.registrations):
            raise ValueError("caller binding lacks a registration audit")
    for event in state.charges:
        _event(event, bounds, state.generation)
        registered = registrations.get((event.generation, event.ticket))
        if registered is None or _key(registered.proposal, policy) != _key(event.proposal, policy):
            raise ValueError("charge lacks its modeled registration")
    for events in (state.registrations, state.charges):
        if tuple(event.generation for event in events) != tuple(sorted(event.generation for event in events)):
            raise ValueError("audit generations are out of order")
    for index, record in enumerate(state.records, 1):
        if (type(record) is not Record or type(record.ticket) is not int or record.ticket != index
                or not _int(record.consumed, 0, bounds.attempt_limit)):
            raise ValueError("invalid modeled current record")
        _proposal(record.proposal)
        registered = registrations.get((state.generation, record.ticket))
        used = sum(event.generation == state.generation and event.ticket == record.ticket
                   for event in state.charges)
        if registered is None or registered.proposal != record.proposal or used != record.consumed:
            raise ValueError("current record differs from nonrefundable audit charge")
    current = [event for event in state.registrations if event.generation == state.generation]
    if len(current) != len(state.records):
        raise ValueError("current registration partition is incomplete")


def _action(action):
    if (type(action) is not Action or type(action.kind) is not str
            or action.kind not in ("check", "enroll", "charge", "lose_binding", "service_loss", "service_return", "rewind_registry")
            or type(action.actor) is not int or type(action.owner_authorized) is not bool):
        raise ValueError("an exact finite enrollment action is required")
    if action.kind in ("check", "enroll", "charge"):
        if action.actor not in (0, 1):
            raise ValueError("a modeled caller is required")
        _proposal(action.proposal)
    elif (action.actor not in ((0, 1) if action.kind == "lose_binding" else (-1,))
          or action.proposal is not None or not action.owner_authorized):
        raise ValueError("unexpected enrollment action fields")


def _actor(state, index, value, **fields):
    actors = list(state.actors)
    actors[index] = value
    return replace(state, actors=tuple(actors), **fields)


def step(state, action, *, bounds=Bounds(), policy="atomic-owner"):
    """Apply an ideal registration/charge event, never a service operation."""
    _parameters(bounds, policy)
    _shape(state, bounds, policy)
    _action(action)
    kind = action.kind
    if kind in ("service_loss", "service_return"):
        available = kind == "service_return"
        if available == state.available:
            raise ValueError("service event changes no state")
        return replace(state, available=available)
    if kind == "rewind_registry":
        if policy != "rollbackable-owner" or state.generation or not state.records:
            raise ValueError("registry rewind is outside this policy or finite domain")
        # The auditor remembers events; the restored registry does not.
        return replace(state, records=(), generation=1)
    actor = state.actors[action.actor]
    if kind == "lose_binding":
        if actor == Actor() or state.losses >= bounds.max_losses:
            raise ValueError("no binding loss remains in this finite domain")
        return _actor(state, action.actor, Actor(), losses=state.losses + 1)
    if not state.available:
        raise ValueError("registry unavailable; no local fallback")
    proposal = action.proposal
    if policy in CANONICAL and (proposal.claimed_resource != proposal.resource
                               or proposal.epoch != EPOCH or proposal.profile != PROFILE):
        raise ValueError("canonical source or frozen selection mismatch")
    if policy in OWNED and not action.owner_authorized:
        raise ValueError("independent owner authorization is absent")
    selected = next((record for record in state.records if record.ticket == actor.ticket), None)
    if kind == "charge":
        if (selected is None or actor.binding != proposal or _key(selected.proposal, policy) != _key(proposal, policy)
                or (policy in CANONICAL and selected.proposal != proposal)
                or selected.consumed >= bounds.attempt_limit or len(state.charges) >= bounds.max_charges):
            raise ValueError("selected modeled enrollment or finite quota is unavailable")
        records = tuple(replace(record, consumed=record.consumed + 1) if record.ticket == selected.ticket
                        else record for record in state.records)
        event = Event(action.actor, state.generation, selected.ticket, proposal, action.owner_authorized)
        return replace(state, records=records, charges=state.charges + (event,))
    if selected is not None:
        raise ValueError("caller already has a live binding")
    existing = next((record for record in state.records if
        (record.proposal.resource == proposal.resource if policy == "checked-owner"
         else _key(record.proposal, policy) == _key(proposal, policy))), None)
    if kind == "check":
        if policy != "checked-owner" or existing is not None or actor.checked == proposal:
            raise ValueError("a missing-registration check is unavailable")
        return _actor(state, action.actor, Actor(checked=proposal))
    cached = policy == "checked-owner" and actor.checked == proposal
    if existing is not None and not cached:
        if policy in CANONICAL and existing.proposal != proposal:
            raise ValueError("duplicate label cannot replace the canonical enrollment")
        return _actor(state, action.actor, Actor(existing.ticket, proposal))
    if policy == "checked-owner" and not cached:
        raise ValueError("registration requires the previously checked absence")
    if len(state.registrations) >= bounds.max_enrollments:
        raise ValueError("finite enrollment event domain exhausted")
    ticket = len(state.records) + 1
    record = Record(ticket, proposal)
    event = Event(action.actor, state.generation, ticket, proposal, action.owner_authorized)
    return _actor(state, action.actor, Actor(ticket, proposal), records=state.records + (record,),
                  registrations=state.registrations + (event,))


def successors(state, *, bounds=Bounds(), policy="atomic-owner"):
    _parameters(bounds, policy)
    _shape(state, bounds, policy)
    actions = [Action("service_loss" if state.available else "service_return")]
    if policy == "rollbackable-owner" and not state.generation and state.records:
        actions.append(Action("rewind_registry"))
    for index, actor in enumerate(state.actors):
        if actor != Actor() and state.losses < bounds.max_losses:
            actions.append(Action("lose_binding", index))
        selected = next((record for record in state.records if record.ticket == actor.ticket), None)
        authorizations = (True,) if policy in OWNED else (True, False)
        if (state.available and actor.binding is not None and selected is not None
                and selected.consumed < bounds.attempt_limit and len(state.charges) < bounds.max_charges):
            actions.extend(Action("charge", index, actor.binding, authorized) for authorized in authorizations)
        if state.available and (actor.ticket == 0 or selected is None):
            for proposal in PROPOSALS:
                if policy in CANONICAL and (proposal.claimed_resource != proposal.resource
                        or proposal.epoch != EPOCH or proposal.profile != PROFILE):
                    continue
                existing = next((record for record in state.records if
                    (record.proposal.resource == proposal.resource if policy == "checked-owner"
                     else _key(record.proposal, policy) == _key(proposal, policy))), None)
                cached = policy == "checked-owner" and actor.checked == proposal
                can_enroll = (len(state.registrations) < bounds.max_enrollments
                              or (existing is not None and not cached))
                for authorized in authorizations:
                    if can_enroll:
                        actions.append(Action("enroll", index, proposal, authorized))
                    if policy == "checked-owner":
                        actions.append(Action("check", index, proposal, authorized))
    for action in actions:
        try:
            following = step(state, action, bounds=bounds, policy=policy)
        except ValueError:
            continue
        if following != state:
            yield action, following


def safety_violations(state, *, bounds=Bounds(), policy="atomic-owner"):
    _parameters(bounds, policy)
    _shape(state, bounds, policy)
    names = []
    if any(sum(event.proposal.resource == resource for event in state.charges) > bounds.attempt_limit
           for resource in (0, 1)):
        names.append("protected_resource_charge_quota_exceeded")
    if any(sum(record.proposal.resource == resource for record in state.records) > 1 for resource in (0, 1)):
        names.append("duplicate_canonical_enrollment")
    if any(not event.owner_authorized for event in state.registrations):
        names.append("unauthorized_enrollment")
    if any(not event.owner_authorized for event in state.charges):
        names.append("unauthorized_charge")
    if any(event.proposal.epoch != EPOCH or event.proposal.profile != PROFILE for event in state.registrations):
        names.append("unreviewed_epoch_or_profile_enrolled")
    registrations = {(event.generation, event.ticket):event for event in state.registrations}
    if any(registrations[(event.generation, event.ticket)].proposal.resource != event.proposal.resource
           for event in state.charges):
        names.append("charge_crossed_canonical_binding")
    identities = [(event.ticket, event.proposal) for event in state.registrations]
    if len(set(identities)) < len(identities):
        names.append("registration_identity_reused")
    return tuple(names)


def boundary_findings(state, *, bounds=Bounds(), policy="atomic-owner"):
    _parameters(bounds, policy)
    _shape(state, bounds, policy)
    names = []
    if not state.available:
        names.append("registry_outage_refuses_admission")
    if state.losses and state.charges:
        names.append("lost_binding_does_not_refund_a_charge")
    if len(state.charges) == bounds.max_charges and len({event.proposal.resource for event in state.charges}) == 2:
        names.append("distinct_resources_can_use_distinct_allowances")
    return tuple(names)


def explore(*, bounds=Bounds(), policy="atomic-owner", max_states=1000000):
    """Enumerate this selected finite domain; a cap is explicitly incomplete."""
    _parameters(bounds, policy)
    if not _int(max_states, 1, 1000000):
        raise ValueError("an explicit finite enrollment search cap is required")
    initial = State()
    queue = deque((initial,))
    parents = {initial:None}
    safety, boundaries, transitions = {}, {}, 0

    def trace(state):
        actions = []
        while parents[state] is not None:
            before, action = parents[state]
            actions.append(action)
            state = before
        return tuple(reversed(actions))

    while queue:
        state = queue.popleft()
        for names, findings in ((safety_violations(state, bounds=bounds, policy=policy), safety),
                                (boundary_findings(state, bounds=bounds, policy=policy), boundaries)):
            for name in names:
                if name not in findings:
                    findings[name] = Finding(name, trace(state), state)
        for action, following in successors(state, bounds=bounds, policy=policy):
            transitions += 1
            if following in parents:
                continue
            if len(parents) >= max_states:
                return SearchResult(policy, bounds, False, "state cap reached", len(parents), transitions,
                                    tuple(safety.values()), tuple(boundaries.values()))
            parents[following] = (state, action)
            queue.append(following)
    return SearchResult(policy, bounds, True, "finite domain exhausted", len(parents), transitions,
                        tuple(safety.values()), tuple(boundaries.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", choices=POLICIES, default="atomic-owner")
    parser.add_argument("--max-states", type=int, default=1000000)
    arguments = parser.parse_args()
    try:
        result = explore(policy=arguments.policy, max_states=arguments.max_states)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({"status":"bounded-complete" if result.complete else "incomplete", "result":asdict(result),
        "trust":"ideal canonical resource and external owner facts; atomic nonrollbackable registry premise; no backend or worker proof"}, sort_keys=True))
    return 0 if result.complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
