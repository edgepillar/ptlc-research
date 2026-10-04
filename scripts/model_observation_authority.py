"""Finite offline comparison of freshness, charged receipts and dispatch trust.

The authority is an ideal external state object, not a service or store backend.
One pre-enrolled scope and profile are premises. Worker entries and normal
results are abstract events, never executed processes or mathematical evidence.
No application, journal, signer, network, clock or filesystem is used.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json


POLICIES = ("local", "read-check", "authority-charge", "ideal-dispatch", "rollbackable-dispatch")
CHARGED = POLICIES[2:]
DISPATCHED = POLICIES[3:]
SCOPE = "enrolled-scope"
PROFILE = "fixed-profile"
LOCAL_ACTIONS = ("sync", "check", "reserve", "start", "finish_normal", "finish_unknown",
                 "lose_receipt", "restore_empty", "copy")
GLOBAL_ACTIONS = ("recover", "service_loss", "service_return", "rewind_authority")


@dataclass(frozen=True)
class Bounds:
    limit: int = 1
    max_entries: int = 2


@dataclass(frozen=True)
class Actor:
    view: int = 0
    used: int = 0
    checked: bool = False
    receipt: int = 0
    running: int = 0


@dataclass(frozen=True)
class Authority:
    revision: int = 0
    consumed: int = 0
    active: int = 0
    dispatched: tuple = ()
    normal: tuple = ()
    unknown: tuple = ()


@dataclass(frozen=True)
class Entry:
    actor: int
    ticket: int
    revision: int
    stale: bool


@dataclass(frozen=True)
class State:
    actors: tuple = (Actor(), Actor())
    authority: Authority = Authority()
    available: bool = True
    entries: tuple = ()
    peak_running: int = 0
    stale_publications: int = 0
    lost_results: int = 0


@dataclass(frozen=True)
class Action:
    kind: str
    actor: int = -1
    other: int = -1
    scope: str = SCOPE
    profile: str = PROFILE


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


def _parameters(bounds, policy):
    if (type(bounds) is not Bounds or type(bounds.limit) is not int or not 1 <= bounds.limit <= 3
            or type(bounds.max_entries) is not int or not bounds.limit + 1 <= bounds.max_entries <= 4
            or type(policy) is not str or policy not in POLICIES):
        raise ValueError("explicit finite bounds and a known policy are required")


def _shape(state, bounds, policy):
    if (type(state) is not State or type(state.actors) is not tuple or len(state.actors) != 2
            or type(state.authority) is not Authority or type(state.available) is not bool
            or type(state.entries) is not tuple or len(state.entries) > bounds.max_entries):
        raise ValueError("invalid finite authority state")
    for actor in state.actors:
        if (type(actor) is not Actor or type(actor.checked) is not bool
                or any(type(getattr(actor, field)) is not int or not 0 <= getattr(actor, field) <= maximum
                       for field, maximum in (("view", 2 * bounds.max_entries), ("used", bounds.limit),
                                              ("receipt", bounds.limit), ("running", bounds.limit)))
                or (actor.running and actor.running != actor.receipt)):
            raise ValueError("invalid modeled copy")
    authority = state.authority
    for field, maximum in (("revision", 2 * bounds.max_entries), ("consumed", bounds.limit), ("active", bounds.limit)):
        if type(getattr(authority, field)) is not int or not 0 <= getattr(authority, field) <= maximum:
            raise ValueError("invalid modeled authority")
    for field in ("dispatched", "normal", "unknown"):
        values = getattr(authority, field)
        if (type(values) is not tuple or len(values) > bounds.max_entries
                or any(type(value) is not int or not 1 <= value <= bounds.limit for value in values)):
            raise ValueError("invalid modeled authority history")
    if policy in CHARGED:
        resolved = authority.normal + authority.unknown
        if (authority.active not in (0, authority.consumed)
                or authority.revision < authority.consumed or authority.revision > 2 * bounds.limit
                or len(set(resolved)) != len(resolved)
                or len(set(authority.dispatched)) != len(authority.dispatched)
                or any(value > authority.consumed for value in resolved + authority.dispatched)
                or authority.active in resolved
                or len(resolved) + int(bool(authority.active)) != authority.consumed):
            raise ValueError("invalid pending, charged or resolved authority partition")
    for entry in state.entries:
        if (type(entry) is not Entry or type(entry.actor) is not int or entry.actor not in (0, 1)
                or type(entry.ticket) is not int or not 1 <= entry.ticket <= bounds.limit
                or type(entry.revision) is not int or not 0 <= entry.revision <= 2 * bounds.max_entries
                or type(entry.stale) is not bool):
            raise ValueError("invalid modeled worker entry")
    for field, maximum in (("peak_running", 2), ("stale_publications", bounds.max_entries),
                           ("lost_results", bounds.max_entries)):
        if type(getattr(state, field)) is not int or not 0 <= getattr(state, field) <= maximum:
            raise ValueError("invalid finite audit count")


def _action(action):
    if type(action) is not Action:
        raise ValueError("an exact modeled action is required")
    valid_other = (action.other in (0, 1) and action.other != action.actor
                   if action.kind == "copy" else action.other == -1)
    if (type(action) is not Action or type(action.kind) is not str
            or action.kind not in LOCAL_ACTIONS + GLOBAL_ACTIONS
            or type(action.actor) is not int or type(action.other) is not int
            or action.actor not in ((0, 1) if action.kind in LOCAL_ACTIONS else (-1,))
            or not valid_other
            or type(action.scope) is not str or action.scope != SCOPE
            or type(action.profile) is not str or action.profile != PROFILE):
        raise ValueError("operations require the exact pre-enrolled scope, profile and action")


def _actor(state, index, actor, **fields):
    actors = list(state.actors)
    actors[index] = actor
    return replace(state, actors=tuple(actors), **fields)


def _available(state):
    if not state.available:
        raise ValueError("external authority is unavailable; no fallback")


def step(state, action, *, bounds=Bounds(), policy="ideal-dispatch"):
    """Apply an abstract event under explicitly stronger external premises."""
    _parameters(bounds, policy)
    _shape(state, bounds, policy)
    _action(action)
    kind = action.kind
    authority = state.authority
    if kind in ("service_loss", "service_return"):
        following = kind == "service_return"
        if policy == "local" or state.available == following:
            raise ValueError("service event is unavailable")
        return replace(state, available=following)
    if kind == "rewind_authority":
        if policy != "rollbackable-dispatch" or authority == Authority():
            raise ValueError("authority rollback is excluded by this policy premise")
        return replace(state, authority=Authority())
    if kind == "recover":
        _available(state)
        if policy not in CHARGED or not authority.active:
            raise ValueError("no external pending reservation to recover")
        # Recovery resolves history; it neither kills a worker nor refunds work.
        return replace(state, authority=replace(authority, revision=authority.revision + 1,
                                               active=0, unknown=authority.unknown + (authority.active,)))

    actor = state.actors[action.actor]
    if kind in ("copy", "restore_empty"):
        if actor.running or (kind == "copy" and state.actors[action.other].running):
            raise ValueError("the model copies only idle snapshots, never a running worker")
        copied = state.actors[action.other] if kind == "copy" else Actor()
        if copied == actor:
            raise ValueError("copy does not change state")
        return _actor(state, action.actor, copied)
    if kind == "lose_receipt":
        if not actor.receipt or actor.running:
            raise ValueError("no unused receipt to lose")
        return _actor(state, action.actor, replace(actor, receipt=0, checked=False))
    if kind in ("sync", "check", "reserve"):
        if actor.receipt or actor.running:
            raise ValueError("copy already owns a pending request")
        if kind == "sync":
            _available(state)
            if policy == "local":
                raise ValueError("no external head in local policy")
            following = replace(actor, view=authority.revision, checked=False,
                                used=authority.consumed if policy in CHARGED else actor.used)
            if following == actor:
                raise ValueError("sync does not change state")
            return _actor(state, action.actor, following)
        if kind == "check":
            _available(state)
            if (policy != "read-check" or actor.checked or actor.view != authority.revision
                    or actor.used >= bounds.limit):
                raise ValueError("fresh local check is unavailable")
            return _actor(state, action.actor, replace(actor, checked=True))
        if policy in CHARGED:
            _available(state)
            if actor.view != authority.revision or authority.active or authority.consumed >= bounds.limit:
                raise ValueError("atomic expected-head reservation is unavailable")
            ticket = authority.consumed + 1
            following = replace(authority, consumed=ticket, active=ticket, revision=authority.revision + 1)
            return _actor(state, action.actor,
                          replace(actor, view=following.revision, used=ticket, receipt=ticket, checked=False),
                          authority=following)
        if actor.used >= bounds.limit or (policy == "read-check" and not actor.checked):
            raise ValueError("local allowance or cached check is unavailable")
        # A cached read is deliberately not revalidated at this admission.
        return _actor(state, action.actor, replace(actor, used=actor.used + 1,
                                                 receipt=actor.used + 1, checked=False))
    if kind == "start":
        if not actor.receipt or actor.running or len(state.entries) >= bounds.max_entries:
            raise ValueError("receipt or finite entry domain is unavailable")
        stale = (actor.view != authority.revision or
                 (policy in CHARGED and actor.receipt != authority.active)) if policy != "local" else False
        if policy in DISPATCHED:
            _available(state)
            if stale or actor.receipt in authority.dispatched:
                raise ValueError("ideal external dispatcher refuses stale or already spent receipt")
            # This indivisible event is a trusted dispatcher premise. A
            # copyable acknowledgment with a local spawn is not equivalent.
            authority = replace(authority, dispatched=authority.dispatched + (actor.receipt,))
        following = _actor(state, action.actor, replace(actor, running=actor.receipt), authority=authority,
                           entries=state.entries + (Entry(action.actor, actor.receipt, actor.view, stale),))
        return replace(following, peak_running=max(state.peak_running,
                                                  sum(bool(copy.running) for copy in following.actors)))
    if kind in ("finish_normal", "finish_unknown"):
        if not actor.running:
            raise ValueError("no abstract worker to finish")
        if policy != "local" and not state.available:
            return _actor(state, action.actor, replace(actor, receipt=0, running=0),
                          lost_results=state.lost_results + 1)
        if policy in CHARGED:
            if actor.view != authority.revision or actor.running != authority.active:
                return _actor(state, action.actor, replace(actor, receipt=0, running=0),
                              stale_publications=state.stale_publications + 1)
            field = "normal" if kind == "finish_normal" else "unknown"
            authority = replace(authority, revision=authority.revision + 1, active=0,
                                **{field: getattr(authority, field) + (actor.running,)})
        elif policy == "read-check":
            field = "normal" if kind == "finish_normal" else "unknown"
            authority = replace(authority, revision=authority.revision + 1,
                                **{field: getattr(authority, field) + (actor.running,)})
        return _actor(state, action.actor,
                      replace(actor, receipt=0, running=0,
                              view=authority.revision if policy != "local" else actor.view + 1),
                      authority=authority)
    raise ValueError("unsupported abstract transition")


def successors(state, *, bounds=Bounds(), policy="ideal-dispatch"):
    _parameters(bounds, policy)
    _shape(state, bounds, policy)
    for kind in LOCAL_ACTIONS:
        for actor in (0, 1):
            action = Action(kind, actor, 1 - actor if kind == "copy" else -1)
            try:
                following = step(state, action, bounds=bounds, policy=policy)
            except ValueError:
                continue
            yield action, following
    for kind in GLOBAL_ACTIONS:
        action = Action(kind)
        try:
            following = step(state, action, bounds=bounds, policy=policy)
        except ValueError:
            continue
        yield action, following


def safety_violations(state, *, bounds=Bounds(), policy="ideal-dispatch"):
    _parameters(bounds, policy)
    _shape(state, bounds, policy)
    names = []
    if len(state.entries) > bounds.limit:
        names.append("scope_worker_entry_quota_exceeded")
    tickets = [entry.ticket for entry in state.entries]
    if policy in CHARGED and len(set(tickets)) != len(tickets):
        names.append("receipt_reused_for_multiple_entries")
    if any(entry.stale for entry in state.entries):
        names.append("stale_worker_entry")
    return tuple(names)


def boundary_findings(state, *, bounds=Bounds(), policy="ideal-dispatch"):
    _parameters(bounds, policy)
    _shape(state, bounds, policy)
    names = []
    if state.peak_running > 1:
        names.append("history_fencing_is_not_worker_containment")
    if (policy in CHARGED and state.authority.consumed == bounds.limit
            and not state.authority.active and not state.authority.normal):
        names.append("exhausted_without_retained_normal")
    if state.stale_publications:
        names.append("stale_result_refused_without_stopping_prior_work")
    if state.lost_results:
        names.append("authority_loss_can_lose_normal_publication")
    if not state.available:
        names.append("authority_availability_is_an_external_premise")
    return tuple(names)


def explore(*, bounds=Bounds(), policy="ideal-dispatch", max_states=100000):
    """Enumerate the complete finite domain or explicitly report a search cap."""
    _parameters(bounds, policy)
    if type(max_states) is not int or not 1 <= max_states <= 1000000:
        raise ValueError("an explicit finite search cap is required")
    initial = State()
    queue = deque((initial,))
    parents = {initial: None}
    safety = {}
    boundaries = {}
    transitions = 0

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
    parser.add_argument("--policy", choices=POLICIES, default="ideal-dispatch")
    parser.add_argument("--limit", type=int, choices=(1, 2, 3), default=1)
    parser.add_argument("--max-entries", type=int, choices=(2, 3, 4))
    parser.add_argument("--max-states", type=int, default=100000)
    arguments = parser.parse_args()
    try:
        result = explore(bounds=Bounds(arguments.limit, arguments.max_entries or arguments.limit + 1),
                         policy=arguments.policy, max_states=arguments.max_states)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({"status": "bounded-complete" if result.complete else "incomplete", "result": asdict(result),
                      "trust": "pre-enrolled scope; ideal external state and dispatch premises; no implementation proof"},
                     sort_keys=True))
    return 0 if result.complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
