"""Finite offline comparison of governor provenance and current-policy checks.

Assignment and intent signature validity are ideal environmental facts, never
peer Booleans or executed cryptography. Profile IDs stand for complete immutable
profiles. The current trusted world survives local snapshot restore. Admission
is an abstract decision, not enrollment, quota, worker entry or a permit.
No application, clock, network, journal, filesystem or crypto module is used.
"""

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json


POLICIES = ("self-selected", "anchored-key", "scoped-role", "profile-bound",
            "checked-current", "atomic-current", "rollbackable-current")
UNBOUND = -1
REVOKED = 3


@dataclass(frozen=True)
class Profile:
    owner: int
    resource: int = 0
    namespace: int = 0
    role: int = 0
    attempt_cap: int = 2
    target_cap: int = 2
    opaque_authority_label: int = 0


PROFILES = (Profile(0), Profile(0, attempt_cap=3, target_cap=3),
            Profile(1, attempt_cap=3, target_cap=3), Profile(1),
            Profile(0, resource=1), Profile(0, namespace=1), Profile(0, role=1))


@dataclass(frozen=True)
class Proposal:
    name: str
    profile: int
    signed_profile: int
    issuer: int = 0
    intent_signature_valid: bool = True
    assignment_signature_valid: bool = True


PROPOSALS = (Proposal("legacy-initial", 0, UNBOUND), Proposal("bound-initial", 0, 0),
    Proposal("legacy-upgrade", 1, UNBOUND), Proposal("bound-upgrade", 1, 1),
    Proposal("bound-rotation", 2, 2), Proposal("peer-root", 3, 3, issuer=1),
    Proposal("other-resource", 4, 4), Proposal("other-namespace", 5, 5),
    Proposal("other-role", 6, 6), Proposal("invalid-intent", 0, 0, intent_signature_valid=False),
    Proposal("invalid-assignment", 0, 0, assignment_signature_valid=False),
    Proposal("swapped-profile", 1, 0))


@dataclass(frozen=True)
class Actor:
    proposal: int = -1
    checked_phase: int = -1
    cached: bool = False
    done: bool = False
    use_phase: int = -1
    use_view: int = -1
    admitted: bool = False


@dataclass(frozen=True)
class State:
    phase: int = 0
    local_view: int = 0
    restored: bool = False
    refreshed: bool = False
    actors: tuple = (Actor(), Actor())


@dataclass(frozen=True)
class Action:
    kind: str
    actor: int = -1
    proposal: int = -1


@dataclass(frozen=True)
class Finding:
    name: str
    trace: tuple
    state: State


@dataclass(frozen=True)
class SearchResult:
    policy: str
    complete: bool
    reason: str
    states: int
    transitions: int
    safety_findings: tuple
    boundary_findings: tuple


def _int(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _policy(policy):
    if type(policy) is not str or policy not in POLICIES:
        raise ValueError("an exact selected governor model policy is required")


def _static(proposal, policy):
    """Trusted signature facts are fixed model inputs, not packet claims."""
    p, profile = PROPOSALS[proposal], PROFILES[PROPOSALS[proposal].profile]
    if not p.intent_signature_valid:
        return False
    if policy == "self-selected":
        return True
    if policy == "anchored-key":
        return profile.owner == 0
    if (p.issuer != 0 or not p.assignment_signature_valid
            or (profile.resource, profile.namespace, profile.role) != (0, 0, 0)):
        return False
    if policy == "scoped-role":
        return True
    return p.signed_profile == p.profile


def _current(proposal, phase):
    return phase < REVOKED and PROPOSALS[proposal].profile == phase


def _checked(proposal, policy, phase):
    return _static(proposal, policy) and (policy != "checked-current" or _current(proposal, phase))


def _at_use(actor, policy, phase, view):
    if policy in ("atomic-current", "rollbackable-current"):
        return _static(actor.proposal, policy) and _current(actor.proposal, view)
    return actor.cached


def _shape(state, policy):
    _policy(policy)
    if (type(state) is not State or not _int(state.phase, 0, REVOKED)
            or not _int(state.local_view, 0, state.phase)
            or type(state.restored) is not bool or type(state.refreshed) is not bool
            or type(state.actors) is not tuple or len(state.actors) != 2):
        raise ValueError("invalid finite governor model state")
    if policy != "rollbackable-current":
        if state.restored or state.refreshed or state.local_view != state.phase:
            raise ValueError("this policy has no restorable current anchor")
    elif ((not state.restored and (state.local_view != state.phase or state.refreshed))
          or (state.restored and (state.phase == 0
              or state.local_view != (state.phase if state.refreshed else 0)))):
        raise ValueError("inconsistent local anchor restore history")
    for actor in state.actors:
        if type(actor) is not Actor:
            raise ValueError("exact finite model actors are required")
        if (not _int(actor.proposal, -1, len(PROPOSALS) - 1)
                or not _int(actor.checked_phase, -1, state.phase)
                or not _int(actor.use_phase, -1, state.phase)
                or not _int(actor.use_view, -1, state.phase)
                or any(type(getattr(actor, field)) is not bool for field in ("cached", "done", "admitted"))):
            raise ValueError("invalid selected model actor")
        if actor.proposal == -1:
            if actor != Actor():
                raise ValueError("empty actor contains a prior decision")
            continue
        if policy == "checked-current" and actor.checked_phase < 0:
            raise ValueError("invalid selected model actor")
        if policy != "checked-current" and (type(actor.checked_phase) is not int or actor.checked_phase != -1):
            raise ValueError("this check stores no current-state authority")
        if actor.cached != _checked(actor.proposal, policy, actor.checked_phase):
            raise ValueError("cached decision changes its selected check")
        if not actor.done:
            if (type(actor.use_phase) is not int or actor.use_phase != -1
                    or type(actor.use_view) is not int or actor.use_view != -1 or actor.admitted):
                raise ValueError("pending actor contains an admission")
        elif (not _int(actor.use_phase, max(0, actor.checked_phase), state.phase)
                or not _int(actor.use_view, 0, actor.use_phase)
                or (policy != "rollbackable-current" and actor.use_view != actor.use_phase)
                or actor.admitted != _at_use(actor, policy, actor.use_phase, actor.use_view)):
            raise ValueError("model admission changes its recorded check or instant")


def _step(state, action, policy):
    if action.kind == "advance":
        if state.phase == REVOKED:
            raise ValueError("the selected trusted world is already revoked")
        phase = state.phase + 1
        view = phase if state.local_view == state.phase else state.local_view
        return replace(state, phase=phase, local_view=view)
    if action.kind == "restore":
        if policy != "rollbackable-current" or state.restored or state.local_view == 0:
            raise ValueError("coherent local anchor restore is unavailable")
        return replace(state, local_view=0, restored=True)
    if action.kind == "refresh":
        if policy != "rollbackable-current" or state.refreshed or state.local_view == state.phase:
            raise ValueError("local anchor refresh is unavailable")
        return replace(state, local_view=state.phase, refreshed=True)
    actor = state.actors[action.actor]
    if action.kind == "check":
        if actor.proposal != -1:
            raise ValueError("this caller already selected a proposal")
        phase = state.phase if policy == "checked-current" else -1
        changed = Actor(action.proposal, phase, _checked(action.proposal, policy, phase))
    else:
        if actor.proposal == -1 or actor.done:
            raise ValueError("a pending selected proposal is required")
        view = state.local_view if policy == "rollbackable-current" else state.phase
        changed = replace(actor, done=True, use_phase=state.phase, use_view=view,
                          admitted=_at_use(actor, policy, state.phase, view))
    actors = list(state.actors); actors[action.actor] = changed
    return replace(state, actors=tuple(actors))


def step(state, action, *, policy="atomic-current"):
    """Pure finite transitions; never application authentication or admission."""
    _shape(state, policy)
    if type(action) is not Action or type(action.kind) is not str:
        raise ValueError("an exact finite model action is required")
    if action.kind in ("advance", "restore", "refresh"):
        if type(action.actor) is not int or action.actor != -1 or type(action.proposal) is not int or action.proposal != -1:
            raise ValueError("environment actions accept no caller claims")
    elif action.kind in ("check", "use"):
        if not _int(action.actor, 0, 1) or (not _int(action.proposal, 0, len(PROPOSALS) - 1) if action.kind == "check"
                                         else type(action.proposal) is not int or action.proposal != -1):
            raise ValueError("invalid finite model caller action")
    else:
        raise ValueError("unknown finite governor model action")
    result = _step(state, action, policy)
    _shape(result, policy)
    return result


def _violations(proposal, phase):
    p, profile = PROPOSALS[proposal], PROFILES[PROPOSALS[proposal].profile]
    found = []
    if not p.intent_signature_valid: found.append("invalid_intent_signature")
    if p.issuer != 0 or not p.assignment_signature_valid: found.append("untrusted_role_assignment")
    for field in ("resource", "namespace", "role"):
        if getattr(profile, field) != 0: found.append("wrong_" + field)
    if p.signed_profile != p.profile: found.append("intent_not_bound_to_selected_profile")
    if phase == REVOKED:
        found.append("admitted_after_revocation")
    else:
        if p.profile != phase: found.append("not_current_profile")
        if profile.owner != PROFILES[phase].owner: found.append("not_current_owner")
    return tuple(found)


def _findings(state):
    safety, boundary = set(), set()
    accepted = [a for a in state.actors if a.done and a.admitted]
    for actor in accepted:
        safety.update(_violations(actor.proposal, actor.use_phase))
        if actor.use_view != actor.use_phase: boundary.add("local_restore_does_not_rewind_trusted_world")
    if len(accepted) == 2 and accepted[0].proposal == accepted[1].proposal:
        boundary.add("same_proposal_can_be_admitted_twice_without_idempotency")
    if any(a.done and not a.admitted and not _violations(a.proposal, a.use_phase) for a in state.actors):
        boundary.add("stale_check_or_view_can_refuse_current_valid_proposal")
    return tuple(sorted(safety)), tuple(sorted(boundary))


def findings(state, *, policy="atomic-current"):
    _shape(state, policy)
    return _findings(state)


def _actions(state, policy):
    if state.phase < REVOKED: yield Action("advance")
    if policy == "rollbackable-current":
        if not state.restored and state.local_view > 0: yield Action("restore")
        if not state.refreshed and state.local_view != state.phase: yield Action("refresh")
    for index, actor in enumerate(state.actors):
        if actor.proposal == -1:
            for proposal in range(len(PROPOSALS)): yield Action("check", index, proposal)
        elif not actor.done:
            yield Action("use", index)


def explore(*, policy="atomic-current", max_states=250000):
    _policy(policy)
    if not _int(max_states, 1, 1000000):
        raise ValueError("an exact finite search cap from one through one million is required")
    start = State(); queue = deque([start]); parent = {start:None}
    safety, boundary, transitions = {}, {}, 0
    def trace(state):
        actions = []
        while parent[state] is not None:
            previous, action = parent[state]; actions.append(action); state = previous
        return tuple(reversed(actions))
    while queue:
        state = queue.popleft()
        selected = _findings(state)
        for found, target in zip(selected, (safety, boundary)):
            for name in found:
                if name not in target: target[name] = Finding(name, trace(state), state)
        for action in _actions(state, policy):
            changed = _step(state, action, policy); transitions += 1
            if changed in parent: continue
            if len(parent) >= max_states:
                return SearchResult(policy, False, "state-cap", len(parent), transitions,
                    tuple(safety[name] for name in sorted(safety)), tuple(boundary[name] for name in sorted(boundary)))
            parent[changed] = (state, action); queue.append(changed)
    return SearchResult(policy, True, "bounded-complete", len(parent), transitions,
        tuple(safety[name] for name in sorted(safety)), tuple(boundary[name] for name in sorted(boundary)))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Finite offline governor authority comparison; no certificate, enrollment or worker")
    parser.add_argument("--policy", choices=POLICIES, default="atomic-current")
    parser.add_argument("--max-states", type=int, default=250000)
    args = parser.parse_args(argv)
    try:
        result = explore(policy=args.policy, max_states=args.max_states)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({"status":"bounded-complete" if result.complete else "incomplete", "result":asdict(result),
        "domain":{"actors":2,"profiles":len(PROFILES),"proposals":len(PROPOSALS),"trusted_phases":4,
                  "local_restores":1 if args.policy == "rollbackable-current" else 0,"local_refreshes":1 if args.policy == "rollbackable-current" else 0},
        "trust":"ideal root/assignment/intent facts and nonrollbackable current oracle; hypothetical profile binding; no crypto, provisioning, registry or entry proof"},sort_keys=True))
    return 0 if result.complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
