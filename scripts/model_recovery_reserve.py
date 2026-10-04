"""Offline experiment comparing a shared allowance with a public recovery reserve.

This wraps the unchanged admission model's candidate and worker transitions.
The reserve is a new model policy, not a journal feature. Only an explicitly
authorized, fixed valid public witness may use it; a retained valid candidate
can be retried through that lane only after separate public authorization.
Authentication, validity and authorization remain ideal external premises.

A public failure bound is an optional environment restriction on interrupted
authorized public worker calls, including failure, cancellation and modeled
post-admission process death. It is not supplied by the reserve. A complete
finite search with no blocked state does not establish fair scheduling, an
eventual worker outcome, funding, timing, chain identity or settlement.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json

if __package__:
    from . import model_recovery_admission as core
else:
    import model_recovery_admission as core


POLICIES = ("shared", "reserved")
ADMISSIONS = ("begin", "retry", "reconcile")
INTERRUPTIONS = ("worker_fail", "worker_cancel", "worker_crash")


@dataclass(frozen=True)
class Bounds:
    general_limit: int = 2
    public_reserve: int = 1
    public_failure_limit: object = None

    @property
    def total(self):
        return self.general_limit + self.public_reserve

    def validate(self):
        if (type(self.general_limit) is not int or not 1 <= self.general_limit <= 64
                or type(self.public_reserve) is not int or not 0 <= self.public_reserve <= 63
                or self.total > 64):
            raise ValueError("general plus reserved attempts must be integers totaling 1 through 64")
        if (self.public_failure_limit is not None
                and (type(self.public_failure_limit) is not int
                     or not 0 <= self.public_failure_limit <= 64)):
            raise ValueError("public failure limit must be absent or an integer from 0 through 64")


@dataclass(frozen=True)
class Choice:
    action: core.Action
    lane: str = ""


@dataclass(frozen=True)
class State:
    core: core.State = core.State()
    general_consumed: int = 0
    reserve_consumed: int = 0
    pending_lane: str = ""
    pending_public: bool = False
    public_failures: int = 0


@dataclass(frozen=True)
class Finding:
    name: str
    trace: tuple
    state: State


@dataclass(frozen=True)
class SearchResult:
    complete: bool
    reason: str
    states: int
    transitions: int
    safety_findings: tuple
    availability_findings: tuple

    @property
    def status(self):
        if not self.complete:
            return "incomplete"
        if self.safety_findings or self.availability_findings:
            return "counterexample"
        return "complete"


def _parameters(bounds, policy):
    if type(bounds) is not Bounds or type(policy) is not str or policy not in POLICIES:
        raise ValueError("exact reserve-model bounds and a named policy are required")
    bounds.validate()


def _state_shape(state):
    if (type(state) is not State
            or any(type(getattr(state, field)) is not int
                   for field in ("general_consumed", "reserve_consumed", "public_failures"))
            or type(state.pending_lane) is not str
            or state.pending_lane not in ("", "shared", "general", "reserve")
            or type(state.pending_public) is not bool):
        raise ValueError("invalid reserve-model state")
    # These independent core checks validate exact types but report invariant
    # violations rather than hiding corrupted state from the outer checkers.
    core.safety_violations(state.core, bounds=core.Bounds(64))


def _choice_shape(choice):
    if (type(choice) is not Choice or type(choice.lane) is not str
            or choice.lane not in ("", "shared", "general", "reserve")):
        raise ValueError("invalid reserve-model choice")
    core._action_shape(choice.action)
    if (choice.action.kind in ADMISSIONS) != bool(choice.lane):
        raise ValueError("only an admission requires an explicit resource lane")


def _authorized_public_choice(state, choice):
    action = choice.action
    return (state.core.public_observed and state.core.public_authorized
            and ((action.source == "public" and action.candidate == "valid"
                  and action.authenticated == state.core.public_authenticated)
                 or (action.kind == "retry" and state.core.retained == "valid")))


def _public_worker(choice):
    return choice.action.source == "public" or choice.lane == "reserve"


def step(state, choice, *, bounds=Bounds(), policy="reserved"):
    """Charge one selected lane before a worker; interruptions never refund it."""
    _parameters(bounds, policy)
    _state_shape(state)
    _choice_shape(choice)
    kind = choice.action.kind
    if kind in ADMISSIONS:
        if policy == "shared":
            if choice.lane != "shared" or state.general_consumed >= bounds.total:
                raise ValueError("shared allowance is exhausted or the lane is unavailable")
        elif choice.lane == "general":
            if state.general_consumed >= bounds.general_limit:
                raise ValueError("general allowance is exhausted")
        elif choice.lane == "reserve":
            if (state.reserve_consumed >= bounds.public_reserve
                    or not _authorized_public_choice(state, choice)):
                raise ValueError("reserve requires an authorized public witness and remaining allowance")
        else:
            raise ValueError("selected lane is unavailable under this policy")
    if (kind in INTERRUPTIONS and state.pending_public
            and bounds.public_failure_limit is not None
            and state.public_failures >= bounds.public_failure_limit):
        raise ValueError("interruption exceeds the explicit public-worker environment bound")

    following = core.step(state.core, choice.action, bounds=core.Bounds(bounds.total))
    if kind in ADMISSIONS:
        return replace(state, core=following,
                       general_consumed=state.general_consumed + int(choice.lane != "reserve"),
                       reserve_consumed=state.reserve_consumed + int(choice.lane == "reserve"),
                       pending_lane=choice.lane, pending_public=_public_worker(choice))
    if kind in (*INTERRUPTIONS, "worker_verify"):
        return replace(state, core=following, pending_lane="", pending_public=False,
                       public_failures=state.public_failures + int(kind in INTERRUPTIONS
                                                                 and state.pending_public))
    return replace(state, core=following)


def successors(state, *, bounds=Bounds(), policy="reserved"):
    """Reuse the core event choices, adding explicit resource-lane selection."""
    _parameters(bounds, policy)
    _state_shape(state)
    for action, _ in core.successors(state.core, bounds=core.Bounds(bounds.total)):
        lanes = (("shared",) if policy == "shared" else ("general", "reserve")) if (
            action.kind in ADMISSIONS) else ("",)
        for lane in lanes:
            choice = Choice(action, lane)
            try:
                following = step(state, choice, bounds=bounds, policy=policy)
            except ValueError:
                continue
            yield choice, following


def safety_violations(state, *, bounds=Bounds(), policy="reserved"):
    """Check resource facts separately from admission guards and core integrity."""
    _parameters(bounds, policy)
    _state_shape(state)
    violations = list(core.safety_violations(state.core, bounds=core.Bounds(bounds.total)))
    general_cap = bounds.total if policy == "shared" else bounds.general_limit
    reserve_cap = 0 if policy == "shared" else bounds.public_reserve
    if not 0 <= state.general_consumed <= general_cap:
        violations.append("general_allowance_out_of_bounds")
    if not 0 <= state.reserve_consumed <= reserve_cap:
        violations.append("reserve_allowance_out_of_bounds")
    if state.core.consumed != state.general_consumed + state.reserve_consumed:
        violations.append("lane_total_mismatch")
    if (not 0 <= state.public_failures <= state.core.consumed
            or (bounds.public_failure_limit is not None
                and state.public_failures > bounds.public_failure_limit)):
        violations.append("public_failure_count_out_of_bounds")
    if state.reserve_consumed and not (state.core.public_observed and state.core.public_authorized):
        violations.append("unauthorized_reserve_charge")
    pending = state.core.pending
    if bool(state.pending_lane) != (pending is not None) or (state.pending_public and pending is None):
        violations.append("pending_lane_mismatch")
    if pending is not None:
        if state.pending_lane not in (("shared",) if policy == "shared" else ("general", "reserve")):
            violations.append("pending_policy_lane_mismatch")
        if state.pending_lane == "reserve" and not state.pending_public:
            violations.append("reserve_without_public_worker")
        if pending.source == "public" and not state.pending_public:
            violations.append("public_worker_classification_mismatch")
        if state.pending_public:
            if (pending.candidate != "valid" or not state.core.public_observed
                    or not state.core.public_authorized
                    or not (pending.source == "public"
                            or (pending.source == "retained" and pending.mode == "retry"))):
                violations.append("unauthorized_public_worker")
    return tuple(violations)


def transition_violations(before, choice, after, *, bounds=Bounds(), policy="reserved"):
    """Detect refunds, reserve theft, reclassification and altered assumptions."""
    _parameters(bounds, policy)
    _state_shape(before)
    _state_shape(after)
    _choice_shape(choice)
    violations = list(core.transition_violations(before.core, choice.action, after.core,
                                                bounds=core.Bounds(bounds.total)))
    admission = choice.action.kind in ADMISSIONS
    if (after.general_consumed != before.general_consumed + int(admission and choice.lane != "reserve")
            or after.reserve_consumed != before.reserve_consumed + int(admission and choice.lane == "reserve")):
        violations.append("lane_debit_or_refund_error")
    if admission:
        allowed = ("shared",) if policy == "shared" else ("general", "reserve")
        if choice.lane not in allowed:
            violations.append("admission_policy_lane_mismatch")
        if (choice.lane == "reserve" and not _authorized_public_choice(before, choice)):
            violations.append("unauthorized_reserve_charge")
        if after.pending_lane != choice.lane or after.pending_public != _public_worker(choice):
            violations.append("admitted_worker_classification_mismatch")
    elif choice.action.kind in (*INTERRUPTIONS, "worker_verify"):
        if after.pending_lane or after.pending_public:
            violations.append("worker_outcome_retained_lane")
    elif (after.pending_lane, after.pending_public) != (before.pending_lane, before.pending_public):
        violations.append("metadata_changed_pending_lane")
    interruption = choice.action.kind in INTERRUPTIONS and before.pending_public
    if after.public_failures != before.public_failures + int(interruption):
        violations.append("public_failure_accounting_error")
    if (interruption and bounds.public_failure_limit is not None
            and before.public_failures >= bounds.public_failure_limit):
        violations.append("public_failure_environment_bypassed")
    if choice.action.kind == "replay" and after != before:
        violations.append("completed_replay_changed_resources")
    return tuple(violations)


def availability_violations(state, *, bounds=Bounds(), policy="reserved"):
    """Report a blocked authorized witness, excluding active worker scheduling."""
    _parameters(bounds, policy)
    _state_shape(state)
    if (state.core.completed or state.core.pending is not None
            or not state.core.public_observed or not state.core.public_authorized):
        return ()
    general_cap = bounds.total if policy == "shared" else bounds.general_limit
    if state.general_consumed >= general_cap and (policy == "shared"
                                                  or state.reserve_consumed >= bounds.public_reserve):
        return ("public_recovery_allowance_exhausted",)
    return ()


def explore(*, bounds=Bounds(), policy="reserved", max_states=50_000):
    """Exhaust this finite experiment, retaining shortest replayable findings."""
    _parameters(bounds, policy)
    if type(max_states) is not int or not 1 <= max_states <= 1_000_000:
        raise ValueError("state budget must be an integer from 1 through 1000000")
    initial = State()
    queue = deque([initial])
    parents = {initial: (None, None)}
    safety, availability = {}, {}
    transitions = 0

    def trace(state):
        path = []
        while parents[state][0] is not None:
            state, choice = parents[state]
            path.append(choice)
        return tuple(reversed(path))

    def record(target, names, path, state):
        for name in names:
            if name not in target:
                target[name] = Finding(name, path, state)

    def result(complete, reason):
        return SearchResult(complete, reason, len(parents), transitions,
                            tuple(safety[name] for name in sorted(safety)),
                            tuple(availability[name] for name in sorted(availability)))

    while queue:
        state = queue.popleft()
        path = trace(state)
        record(safety, safety_violations(state, bounds=bounds, policy=policy), path, state)
        record(availability, availability_violations(state, bounds=bounds, policy=policy), path, state)
        for choice, following in successors(state, bounds=bounds, policy=policy):
            transitions += 1
            next_path = path + (choice,)
            record(safety, transition_violations(state, choice, following, bounds=bounds, policy=policy),
                   next_path, following)
            record(safety, safety_violations(following, bounds=bounds, policy=policy), next_path, following)
            record(availability, availability_violations(following, bounds=bounds, policy=policy),
                   next_path, following)
            if following not in parents:
                if len(parents) >= max_states:
                    return result(False, "state_budget_exhausted")
                parents[following] = (state, choice)
                queue.append(following)
    return result(True, "graph_exhausted")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", choices=POLICIES, default="reserved")
    parser.add_argument("--general-limit", type=int, default=2)
    parser.add_argument("--public-reserve", type=int, default=1)
    parser.add_argument("--public-failure-limit", type=int)
    parser.add_argument("--max-states", type=int, default=50_000)
    args = parser.parse_args(argv)
    try:
        bounds = Bounds(args.general_limit, args.public_reserve, args.public_failure_limit)
        result = explore(bounds=bounds, policy=args.policy, max_states=args.max_states)
    except ValueError:
        print(json.dumps({"status": "incomplete", "complete": False, "reason": "invalid_parameters"}))
        return 2
    print(json.dumps({
        "scope": "finite offline reserve experiment; no journal implementation or liveness proof",
        "policy": args.policy,
        "bounds": asdict(bounds),
        "environment": "unbounded public interruptions" if bounds.public_failure_limit is None else (
            "explicit bound on interrupted authorized public worker calls; not a reserve guarantee"),
        "status": result.status,
        **asdict(result),
    }, indent=2, sort_keys=True))
    if not result.complete:
        return 2
    return int(bool(result.safety_findings or result.availability_findings))


if __name__ == "__main__":
    raise SystemExit(main())
