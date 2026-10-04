"""Offline model separating exact public-observation authority from validity.

Both fixed candidate identities may be publicly observed and independently
authorized. An ideal-valid filter is an explicit stronger premise; the default
authorized-bytes policy does not pretend that authority proves inner validity.
Public invalid rejection is a normal worker result, not an interruption. No
observation filter, chain connection or reserve is implemented in the journal.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json

if __package__:
    from . import model_recovery_admission as core
    from . import model_recovery_reserve as reserve
else:
    import model_recovery_admission as core
    import model_recovery_reserve as reserve


Bounds = reserve.Bounds
Choice = reserve.Choice
ADMISSIONS = reserve.ADMISSIONS
INTERRUPTIONS = reserve.INTERRUPTIONS
PUBLIC_POLICIES = ("ideal-valid", "authorized-bytes")
EXTERNAL = ("observe_public", "authorize_public", "claim_inclusion", "reorg")


@dataclass(frozen=True)
class Observation:
    observed: bool = False
    authenticated: bool = False
    authorized: bool = False
    claimed_included: bool = False
    reorged: bool = False


@dataclass(frozen=True)
class State:
    core: core.State = core.State()
    invalid: Observation = Observation()
    general_consumed: int = 0
    reserve_consumed: int = 0
    pending_lane: str = ""
    pending_public: bool = False
    public_failures: int = 0
    worker_interruptions: int = 0
    reserve_rejections: int = 0


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
        return "counterexample" if self.safety_findings or self.availability_findings else "complete"


def _parameters(bounds, policy, public_policy):
    reserve._parameters(bounds, policy)
    if type(public_policy) is not str or public_policy not in PUBLIC_POLICIES:
        raise ValueError("an exact public-observation policy is required")


def _state_shape(state):
    if (type(state) is not State or type(state.invalid) is not Observation
            or any(type(getattr(state.invalid, field)) is not bool for field in Observation.__dataclass_fields__)
            or any(type(getattr(state, field)) is not int for field in
                   ("general_consumed", "reserve_consumed", "public_failures", "worker_interruptions", "reserve_rejections"))
            or type(state.pending_public) is not bool
            or type(state.pending_lane) is not str or state.pending_lane not in ("", "shared", "general", "reserve")):
        raise ValueError("invalid public-observation model state")
    core._state_shape(state.core)


def _choice_shape(choice):
    if (type(choice) is not Choice or type(choice.lane) is not str
            or choice.lane not in ("", "shared", "general", "reserve")
            or type(choice.action) is not core.Action):
        raise ValueError("invalid public-observation choice")
    action = choice.action
    if action.kind in EXTERNAL:
        if (type(action.kind) is not str or type(action.candidate) is not str
                or action.candidate not in core.VALIDITY or type(action.source) is not str or action.source
                or type(action.expected_candidate) is not str or action.expected_candidate
                or type(action.authenticated) is not bool
                or (action.kind != "observe_public" and action.authenticated)):
            raise ValueError("external events require one exact public candidate identity")
    else:
        core._action_shape(action)
    if (action.kind in ADMISSIONS) != bool(choice.lane):
        raise ValueError("only an admission requires an explicit resource lane")


def observation(state, candidate):
    """Return authority for this identity only; validity is not an observation flag."""
    if candidate == "invalid":
        return state.invalid
    if candidate != "valid":
        raise ValueError("unknown exact candidate identity")
    return Observation(state.core.public_observed, state.core.public_authenticated,
                       state.core.public_authorized, state.core.claimed_included, state.core.reorged)


def _public_candidate(state, choice):
    return state.core.retained if choice.action.kind == "retry" else choice.action.candidate


def _public_allowed(state, choice, public_policy):
    candidate = _public_candidate(state, choice)
    if candidate not in core.VALIDITY:
        return False
    observed = observation(state, candidate)
    return (observed.observed and observed.authorized
            and (choice.action.kind == "retry" or choice.action.authenticated == observed.authenticated)
            and (public_policy == "authorized-bytes" or core.VALIDITY[candidate]))


def _external_step(state, action, bounds):
    if action.candidate == "valid":
        mapped = core.Action(action.kind, authenticated=action.authenticated)
        return replace(state, core=core.step(state.core, mapped, bounds=core.Bounds(bounds.total)))
    observed = state.invalid
    kind = action.kind
    if kind == "observe_public" and not observed.observed:
        return replace(state, invalid=replace(observed, observed=True, authenticated=action.authenticated),
                       core=replace(state.core, possible_exposure=True))
    if kind == "authorize_public" and observed.observed and not observed.authorized:
        return replace(state, invalid=replace(observed, authorized=True))
    if kind == "claim_inclusion" and observed.observed and not observed.claimed_included:
        return replace(state, invalid=replace(observed, claimed_included=True))
    if kind == "reorg" and observed.claimed_included and not observed.reorged:
        return replace(state, invalid=replace(observed, claimed_included=False, reorged=True))
    raise ValueError("external event is unavailable for this observation")


def _public_admission(state, action, bounds):
    # The unchanged baseline hardcodes the fixed valid public witness. This
    # explicit generalization permits either authorized ID without relabeling
    # it as a peer input or inventing peer authentication. Worker arithmetic and
    # post-admission candidate/history transitions still use the core engine.
    before = state.core
    if before.completed or before.pending is not None or before.consumed >= bounds.total:
        raise ValueError("recovery is completed, active or exhausted")
    if action.kind == "reconcile":
        if (not before.retained or before.retained == action.candidate
                or action.expected_candidate != before.retained):
            raise ValueError("reconciliation comparison or replacement rejected")
        pending = core.Pending(action.candidate, "public", action.authenticated,
                               "reconcile", before.retained, True)
        return replace(before, consumed=before.consumed + 1, pending=pending)
    if action.kind != "begin" or before.retained:
        raise ValueError("use exact retry or explicit reconciliation")
    pending = core.Pending(action.candidate, "public", action.authenticated, "ordinary", "", True)
    return replace(before, consumed=before.consumed + 1, retained=action.candidate,
                   retained_authenticated=action.authenticated, original=action.candidate,
                   pending=pending, possible_exposure=True)


def step(state, choice, *, bounds=Bounds(), policy="reserved", public_policy="authorized-bytes"):
    """Apply exact observation authority and no-refund admission accounting."""
    _parameters(bounds, policy, public_policy)
    _state_shape(state)
    _choice_shape(choice)
    action = choice.action
    kind = action.kind
    if kind in EXTERNAL:
        return _external_step(state, action, bounds)
    if kind in ADMISSIONS:
        if policy == "shared":
            if choice.lane != "shared" or state.general_consumed >= bounds.total:
                raise ValueError("shared allowance or lane is unavailable")
        elif choice.lane == "general":
            if state.general_consumed >= bounds.general_limit:
                raise ValueError("general allowance is exhausted")
        elif choice.lane == "reserve":
            if state.reserve_consumed >= bounds.public_reserve:
                raise ValueError("reserve allowance is exhausted")
        else:
            raise ValueError("selected lane is unavailable")
        public = action.source == "public" or choice.lane == "reserve"
        if public and (action.source == "peer" or not _public_allowed(state, choice, public_policy)):
            raise ValueError("this exact public candidate lacks the selected admission premise")
    if (kind in INTERRUPTIONS and state.pending_public and bounds.public_failure_limit is not None
            and state.public_failures >= bounds.public_failure_limit):
        raise ValueError("interruption exceeds the explicit public-worker environment bound")
    following = (_public_admission(state, action, bounds) if kind in ADMISSIONS and action.source == "public"
                 else core.step(state.core, action, bounds=core.Bounds(bounds.total)))
    if kind in ADMISSIONS:
        return replace(state, core=following,
                       general_consumed=state.general_consumed + int(choice.lane != "reserve"),
                       reserve_consumed=state.reserve_consumed + int(choice.lane == "reserve"),
                       pending_lane=choice.lane, pending_public=public)
    if kind in (*INTERRUPTIONS, "worker_verify"):
        rejected_reserve = (kind == "worker_verify" and state.pending_lane == "reserve"
                            and not core.VALIDITY[state.core.pending.candidate])
        return replace(state, core=following, pending_lane="", pending_public=False,
                       public_failures=state.public_failures + int(kind in INTERRUPTIONS and state.pending_public),
                       worker_interruptions=state.worker_interruptions + int(kind in INTERRUPTIONS),
                       reserve_rejections=state.reserve_rejections + int(rejected_reserve))
    return replace(state, core=following)


def successors(state, *, bounds=Bounds(), policy="reserved", public_policy="authorized-bytes"):
    _parameters(bounds, policy, public_policy)
    _state_shape(state)

    def actions():
        for candidate in core.VALIDITY:
            for authenticated in (False, True):
                yield core.Action("observe_public", candidate=candidate, authenticated=authenticated)
            for kind in ("authorize_public", "claim_inclusion", "reorg"):
                yield core.Action(kind, candidate=candidate)
            for source in ("peer", "public"):
                for authenticated in (False, True):
                    yield core.Action("begin", candidate, source, authenticated)
                    for expected in core.VALIDITY:
                        yield core.Action("reconcile", candidate, source, authenticated, expected)
        for kind in ("retry", "worker_verify", *INTERRUPTIONS, "replay"):
            yield core.Action(kind)

    for action in actions():
        lanes = (("shared",) if policy == "shared" else ("general", "reserve")) if (
            action.kind in ADMISSIONS) else ("",)
        for lane in lanes:
            choice = Choice(action, lane)
            try:
                following = step(state, choice, bounds=bounds, policy=policy, public_policy=public_policy)
            except ValueError:
                continue
            yield choice, following


def safety_violations(state, *, bounds=Bounds(), policy="reserved", public_policy="authorized-bytes"):
    """Check stored resource facts and exact public authority independently."""
    _parameters(bounds, policy, public_policy)
    _state_shape(state)
    violations = list(core.safety_violations(state.core, bounds=core.Bounds(bounds.total)))
    valid_evidence = state.core.public_observed or state.core.completed == "valid"
    if valid_evidence != state.core.witness_known:
        violations.append("witness_knowledge_evidence_mismatch")
    general_cap = bounds.total if policy == "shared" else bounds.general_limit
    reserve_cap = 0 if policy == "shared" else bounds.public_reserve
    if not 0 <= state.general_consumed <= general_cap or not 0 <= state.reserve_consumed <= reserve_cap:
        violations.append("lane_allowance_out_of_bounds")
    if state.core.consumed != state.general_consumed + state.reserve_consumed:
        violations.append("lane_total_mismatch")
    if (not 0 <= state.public_failures <= state.worker_interruptions <= state.core.consumed
            or not 0 <= state.reserve_rejections <= state.reserve_consumed
            or (bounds.public_failure_limit is not None and state.public_failures > bounds.public_failure_limit)):
        violations.append("worker_outcome_count_out_of_bounds")
    for candidate in core.VALIDITY:
        observed = observation(state, candidate)
        if (observed.authorized or observed.authenticated or observed.claimed_included or observed.reorged) and not observed.observed:
            violations.append("public_metadata_without_observation")
    if state.reserve_consumed and not any(observation(state, candidate).authorized for candidate in core.VALIDITY):
        violations.append("reserve_without_retained_public_authority")
    pending = state.core.pending
    if bool(state.pending_lane) != (pending is not None) or (state.pending_public and pending is None):
        violations.append("pending_lane_mismatch")
    if pending is not None:
        if state.pending_lane not in (("shared",) if policy == "shared" else ("general", "reserve")):
            violations.append("pending_policy_lane_mismatch")
        expected_public = pending.source == "public" or state.pending_lane == "reserve"
        if state.pending_public != expected_public:
            violations.append("public_worker_classification_mismatch")
        if state.pending_public:
            observed = observation(state, pending.candidate)
            if (not observed.observed or not observed.authorized
                    or not (pending.source == "public" or (pending.source == "retained" and pending.mode == "retry"))
                    or (pending.source == "public" and pending.authenticated != observed.authenticated)):
                violations.append("unauthorized_public_worker")
            if public_policy == "ideal-valid" and not core.VALIDITY[pending.candidate]:
                violations.append("ideal_public_validity_premise_bypassed")
    return tuple(violations)


def transition_violations(before, choice, after, *, bounds=Bounds(), policy="reserved", public_policy="authorized-bytes"):
    """Restate integrity edges with per-ID authority, not the old valid-only guard."""
    _parameters(bounds, policy, public_policy)
    _state_shape(before)
    _state_shape(after)
    _choice_shape(choice)
    action = choice.action
    kind = action.kind
    left, right = before.core, after.core
    admission = kind in ADMISSIONS
    violations = []
    if (right.consumed != left.consumed + int(admission)
            or after.general_consumed != before.general_consumed + int(admission and choice.lane != "reserve")
            or after.reserve_consumed != before.reserve_consumed + int(admission and choice.lane == "reserve")):
        violations.append("admission_debit_or_refund_error")
    for field, name in (("possible_exposure", "exposure_cleared"), ("witness_known", "witness_knowledge_cleared"),
                        ("alice_consumed", "alice_signing_ownership_reset")):
        if getattr(left, field) and not getattr(right, field):
            violations.append(name)
    if left.original and right.original != left.original:
        violations.append("original_candidate_replaced")
    if not left.witness_known and right.witness_known:
        if not ((kind == "observe_public" and action.candidate == "valid")
                or (kind == "worker_verify" and left.pending is not None and left.pending.candidate == "valid")):
            violations.append("witness_knowledge_without_valid_evidence")
    if not left.completed and right.completed:
        if kind != "worker_verify" or left.pending is None or right.completed != left.pending.candidate:
            violations.append("completion_without_worker_verification")
    if left.completed and (right.completed, right.retained, right.retained_authenticated, right.archive) != (
            left.completed, left.retained, left.retained_authenticated, left.archive):
        violations.append("completed_result_changed")
    if kind == "reconcile":
        if not left.retained or action.expected_candidate != left.retained or action.candidate == left.retained:
            violations.append("reconciliation_cas_bypassed")
        if (right.retained, right.archive, right.completed) != (left.retained, left.archive, left.completed):
            violations.append("replacement_committed_before_verification")
    if admission:
        allowed = ("shared",) if policy == "shared" else ("general", "reserve")
        if choice.lane not in allowed:
            violations.append("admission_policy_lane_mismatch")
        expected_public = action.source == "public" or choice.lane == "reserve"
        if after.pending_lane != choice.lane or after.pending_public != expected_public:
            violations.append("admitted_worker_classification_mismatch")
        expected_candidate = left.retained if kind == "retry" else action.candidate
        expected_source = "retained" if kind == "retry" else action.source
        expected_authentication = left.retained_authenticated if kind == "retry" else action.authenticated
        expected_mode = "ordinary" if kind == "begin" else kind
        expected_prior = "" if kind == "begin" else left.retained
        expected_authority = kind != "retry" and action.source == "public"
        pending = right.pending
        if (pending is None or (pending.candidate, pending.source, pending.authenticated, pending.mode,
                               pending.prior_candidate, pending.locally_authorized) != (
                expected_candidate, expected_source, expected_authentication, expected_mode, expected_prior, expected_authority)):
            violations.append("admitted_candidate_binding_mismatch")
        if left.completed or left.pending is not None:
            violations.append("admission_overlap_or_after_completion")
        if expected_public:
            candidate = left.retained if kind == "retry" else action.candidate
            if candidate not in core.VALIDITY:
                violations.append("unauthorized_public_admission")
            else:
                observed = observation(before, candidate)
                if (not observed.observed or not observed.authorized or action.source == "peer"
                        or (kind != "retry" and action.authenticated != observed.authenticated)):
                    violations.append("unauthorized_public_admission")
                if public_policy == "ideal-valid" and not core.VALIDITY[candidate]:
                    violations.append("ideal_public_validity_premise_bypassed")
        if action.source == "peer" and not action.authenticated:
            violations.append("unauthenticated_peer_admission")
    elif kind in (*INTERRUPTIONS, "worker_verify"):
        if after.pending_lane or after.pending_public:
            violations.append("worker_outcome_retained_lane")
        if left.pending is None:
            violations.append("worker_outcome_without_admission")
        elif kind == "worker_verify":
            expected_completion = left.pending.candidate if core.VALIDITY[left.pending.candidate] else left.completed
            if right.completed != expected_completion:
                violations.append("completion_verdict_mismatch")
    elif (after.pending_lane, after.pending_public) != (before.pending_lane, before.pending_public):
        violations.append("metadata_changed_pending_lane")
    if kind in INTERRUPTIONS and (right.retained, right.archive, right.completed) != (
            left.retained, left.archive, left.completed):
        violations.append("failed_worker_changed_candidate")
    interrupted_public = kind in INTERRUPTIONS and before.pending_public
    rejected_reserve = (kind == "worker_verify" and before.pending_lane == "reserve" and left.pending is not None
                        and not core.VALIDITY[left.pending.candidate])
    if (after.public_failures != before.public_failures + int(interrupted_public)
            or after.worker_interruptions != before.worker_interruptions + int(kind in INTERRUPTIONS)
            or after.reserve_rejections != before.reserve_rejections + int(rejected_reserve)):
        violations.append("worker_outcome_accounting_error")
    if (interrupted_public and bounds.public_failure_limit is not None
            and before.public_failures >= bounds.public_failure_limit):
        violations.append("public_failure_environment_bypassed")
    for candidate in core.VALIDITY:
        old, new = observation(before, candidate), observation(after, candidate)
        if (old.observed and (not new.observed or old.authenticated != new.authenticated)) or (old.authorized and not new.authorized):
            violations.append("public_observation_or_authority_changed")
        if candidate != action.candidate or kind not in EXTERNAL:
            if old != new:
                violations.append("unrelated_public_observation_changed")
        else:
            expected = old
            available = False
            if kind == "observe_public":
                available = not old.observed
                expected = replace(old, observed=True, authenticated=action.authenticated)
            elif kind == "authorize_public":
                available = old.observed and not old.authorized
                expected = replace(old, authorized=True)
            elif kind == "claim_inclusion":
                available = old.observed and not old.claimed_included
                expected = replace(old, claimed_included=True)
            elif kind == "reorg":
                available = old.claimed_included and not old.reorged
                expected = replace(old, claimed_included=False, reorged=True)
            if not available or new != expected:
                violations.append("public_external_event_mismatch")
    if kind == "replay" and (not left.completed or after != before):
        violations.append("completed_replay_changed_state")
    return tuple(violations)


def availability_violations(state, *, bounds=Bounds(), policy="reserved", public_policy="authorized-bytes"):
    _parameters(bounds, policy, public_policy)
    _state_shape(state)
    if (state.core.completed or state.core.pending is not None
            or not state.core.public_observed or not state.core.public_authorized):
        return ()
    general_cap = bounds.total if policy == "shared" else bounds.general_limit
    if state.general_consumed < general_cap or (policy == "reserved" and state.reserve_consumed < bounds.public_reserve):
        return ()
    findings = ["public_recovery_allowance_exhausted"]
    if state.reserve_rejections:
        findings.append("invalid_public_rejection_exhausted_reserve")
        if state.worker_interruptions == 0:
            findings.append("invalid_public_rejection_without_interruption")
    return tuple(findings)


def explore(*, bounds=Bounds(), policy="reserved", public_policy="authorized-bytes", max_states=50_000):
    _parameters(bounds, policy, public_policy)
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
        record(safety, safety_violations(state, bounds=bounds, policy=policy, public_policy=public_policy), path, state)
        record(availability, availability_violations(state, bounds=bounds, policy=policy, public_policy=public_policy), path, state)
        for choice, following in successors(state, bounds=bounds, policy=policy, public_policy=public_policy):
            transitions += 1
            next_path = path + (choice,)
            record(safety, transition_violations(state, choice, following, bounds=bounds, policy=policy, public_policy=public_policy),
                   next_path, following)
            record(safety, safety_violations(following, bounds=bounds, policy=policy, public_policy=public_policy), next_path, following)
            record(availability, availability_violations(following, bounds=bounds, policy=policy, public_policy=public_policy),
                   next_path, following)
            if following not in parents:
                if len(parents) >= max_states:
                    return result(False, "state_budget_exhausted")
                parents[following] = (state, choice)
                queue.append(following)
    return result(True, "graph_exhausted")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", choices=reserve.POLICIES, default="reserved")
    parser.add_argument("--public-policy", choices=PUBLIC_POLICIES, default="authorized-bytes")
    parser.add_argument("--general-limit", type=int, default=2)
    parser.add_argument("--public-reserve", type=int, default=1)
    parser.add_argument("--public-failure-limit", type=int)
    parser.add_argument("--max-states", type=int, default=50_000)
    args = parser.parse_args(argv)
    try:
        bounds = Bounds(args.general_limit, args.public_reserve, args.public_failure_limit)
        result = explore(bounds=bounds, policy=args.policy, public_policy=args.public_policy, max_states=args.max_states)
    except ValueError:
        print(json.dumps({"status": "incomplete", "complete": False, "reason": "invalid_parameters"}))
        return 2
    print(json.dumps({"scope": "finite offline observation experiment; no trust source or liveness proof",
                      "policy": args.policy, "public_policy": args.public_policy, "bounds": asdict(bounds),
                      "environment": ("unbounded public interruptions; mathematical rejection is separate" if
                                      bounds.public_failure_limit is None else
                                      "explicit public interruption bound excludes mathematical rejection"),
                      "status": result.status, **asdict(result)}, indent=2, sort_keys=True))
    return 2 if not result.complete else int(bool(result.safety_findings or result.availability_findings))


if __name__ == "__main__":
    raise SystemExit(main())
