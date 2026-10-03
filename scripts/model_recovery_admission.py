"""Finite offline model of Bob recovery admission and observation selection.

This model starts after extraction material and Bob's release are retained and
Alice's signing ownership is consumed. Candidate IDs denote two fixed, distinct,
same-context public byte strings. Their inner validity and envelope authentication
are ideal oracles, not implemented cryptography. A public witness is separately
observed and explicitly authorized by local policy; neither a source label,
claimed inclusion, authentication nor inner validity supplies that authorization.

Admissions and worker outcomes are separate steps. Failed, cancelled or crashed
workers do not refund admissions or replace a retained candidate. The modeled
crash is after a matched durable admission; database/anchor divergence, clones,
power loss, secret storage and worker internals are outside this abstraction.
Public observation and modeled exposure/knowledge include facts outside the
journal; these state fields are not a new journal storage or authorization API.
possible_exposure concerns completion-candidate disclosure in this model. Its
initial false value is not Alice's already-consumed journal exposure marker or
proof of secrecy. witness_known means a valid revealing signature is publicly
available/recoverable, not that Bob computed, obtained or stored a secret scalar.

The finite graph has no clock, funding, principal balances, network, signer or
chain consensus. Availability findings mean an available authorized valid witness
is blocked by the modeled recovery policy, not principal loss or an atomicity
claim. In particular, the baseline finite shared allowance is exhaustible; no
safe exhaustion, fairness or future peer cooperation assumption is invented.
"""

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json


VALIDITY = {"valid": True, "invalid": False}


@dataclass(frozen=True)
class Bounds:
    attempt_limit: int = 2

    def validate(self):
        if type(self.attempt_limit) is not int or not 1 <= self.attempt_limit <= 64:
            raise ValueError("attempt limit must be an integer from 1 through 64")


@dataclass(frozen=True)
class Policy:
    require_public_envelope: bool = False
    trust_auth_as_inner_validity: bool = False


POLICIES = {
    "baseline": Policy(),
    "universal-envelope": Policy(require_public_envelope=True),
    "auth-is-valid": Policy(trust_auth_as_inner_validity=True),
}


@dataclass(frozen=True)
class Action:
    kind: str
    candidate: str = ""
    source: str = ""
    authenticated: bool = False
    expected_candidate: str = ""


@dataclass(frozen=True)
class Pending:
    candidate: str
    source: str
    authenticated: bool
    mode: str
    prior_candidate: str
    locally_authorized: bool


@dataclass(frozen=True)
class State:
    consumed: int = 0
    retained: str = ""
    retained_authenticated: bool = False
    original: str = ""
    archive: str = ""
    completed: str = ""
    pending: object = None
    possible_exposure: bool = False
    alice_consumed: bool = True
    public_observed: bool = False
    public_authorized: bool = False
    public_authenticated: bool = False
    claimed_included: bool = False
    witness_known: bool = False
    reorged: bool = False


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
    if type(bounds) is not Bounds or type(policy) is not Policy:
        raise ValueError("exact model bounds and policy are required")
    bounds.validate()
    if (type(policy.require_public_envelope) is not bool
            or type(policy.trust_auth_as_inner_validity) is not bool):
        raise ValueError("policy flags must be booleans")


def _state_shape(state):
    if type(state) is not State or type(state.consumed) is not int:
        raise ValueError("invalid model state")
    for field in ("retained", "original", "archive", "completed"):
        value = getattr(state, field)
        if type(value) is not str or value not in ("", *VALIDITY):
            raise ValueError("invalid exact candidate identity")
    for field in ("retained_authenticated", "possible_exposure", "alice_consumed",
                  "public_observed", "public_authorized", "public_authenticated",
                  "claimed_included", "witness_known", "reorged"):
        if type(getattr(state, field)) is not bool:
            raise ValueError("model state flags must be booleans")
    pending = state.pending
    if pending is not None:
        if type(pending) is not Pending:
            raise ValueError("invalid pending admission")
        if (type(pending.candidate) is not str or pending.candidate not in VALIDITY
                or type(pending.prior_candidate) is not str
                or pending.prior_candidate not in ("", *VALIDITY)
                or type(pending.source) is not str or pending.source not in ("peer", "public", "retained")
                or type(pending.mode) is not str or pending.mode not in ("ordinary", "retry", "reconcile")
                or type(pending.authenticated) is not bool or type(pending.locally_authorized) is not bool):
            raise ValueError("invalid pending admission fields")


def _action_shape(action):
    if type(action) is not Action:
        raise ValueError("an exact model action is required")
    if (any(type(getattr(action, field)) is not str
            for field in ("kind", "candidate", "source", "expected_candidate"))
            or type(action.authenticated) is not bool):
        raise ValueError("invalid action field types")
    if action.kind in ("begin", "reconcile"):
        if action.candidate not in VALIDITY or action.source not in ("peer", "public"):
            raise ValueError("invalid admission candidate or source")
        if action.kind == "reconcile":
            if action.expected_candidate not in VALIDITY:
                raise ValueError("reconciliation requires an exact comparison identity")
        elif action.expected_candidate:
            raise ValueError("ordinary admission has no comparison identity")
    elif action.kind == "observe_public":
        if action.candidate or action.source or action.expected_candidate:
            raise ValueError("public observation offers the fixed valid witness")
    elif action.kind in ("authorize_public", "claim_inclusion", "reorg", "retry",
                         "worker_verify", "worker_fail", "worker_cancel", "worker_crash", "replay"):
        if action != Action(action.kind):
            raise ValueError("unexpected action fields")
    else:
        raise ValueError("unknown model action")


def _admissible(state, action, policy):
    if action.source == "peer":
        return action.authenticated
    # Local authorization is a distinct external input, even for a valid,
    # authenticated or reportedly included public observation.
    return (state.public_observed and state.public_authorized and action.candidate == "valid"
            and action.authenticated == state.public_authenticated
            and (not policy.require_public_envelope or action.authenticated))


def step(state, action, *, bounds=Bounds(), policy=Policy()):
    """Apply one explicit event; rejected preflight raises without a new state."""
    _parameters(bounds, policy)
    _state_shape(state)
    _action_shape(action)
    kind = action.kind
    if kind == "observe_public" and not state.public_observed:
        return replace(state, public_observed=True, public_authenticated=action.authenticated,
                       witness_known=True, possible_exposure=True)
    if kind == "authorize_public" and state.public_observed and not state.public_authorized:
        return replace(state, public_authorized=True)
    if kind == "claim_inclusion" and state.public_observed and not state.claimed_included:
        return replace(state, claimed_included=True)
    if kind == "reorg" and state.claimed_included and not state.reorged:
        return replace(state, claimed_included=False, reorged=True)
    if kind in ("begin", "retry", "reconcile"):
        if state.completed or state.pending is not None or state.consumed >= bounds.attempt_limit:
            raise ValueError("recovery is completed, active or exhausted")
        if kind == "retry":
            if not state.retained:
                raise ValueError("retry requires a retained candidate")
            pending = Pending(state.retained, "retained", state.retained_authenticated,
                              "retry", state.retained, False)
            return replace(state, consumed=state.consumed + 1, pending=pending)
        if not _admissible(state, action, policy):
            raise ValueError("observation lacks its modeled admission authorization")
        if kind == "reconcile":
            if (not state.retained or state.retained == action.candidate
                    or action.expected_candidate != state.retained):
                raise ValueError("reconciliation comparison or replacement rejected")
            pending = Pending(action.candidate, action.source, action.authenticated,
                              "reconcile", state.retained, action.source == "public")
            return replace(state, consumed=state.consumed + 1, pending=pending)
        if state.retained:
            raise ValueError("use exact retry or explicit reconciliation")
        pending = Pending(action.candidate, action.source, action.authenticated,
                          "ordinary", "", action.source == "public")
        return replace(state, consumed=state.consumed + 1, retained=action.candidate,
                       retained_authenticated=action.authenticated, original=action.candidate,
                       pending=pending, possible_exposure=True)
    if kind in ("worker_verify", "worker_fail", "worker_cancel", "worker_crash"):
        pending = state.pending
        if pending is None:
            raise ValueError("worker outcome requires a durable admission")
        # worker_fail includes rejection, transport failure and timeout even for
        # a valid candidate; it is not an oracle verdict stored about its bytes.
        accepted = kind == "worker_verify" and (
            VALIDITY[pending.candidate]
            or (policy.trust_auth_as_inner_validity and pending.authenticated)
        )
        if not accepted:
            return replace(state, pending=None)
        return replace(state, pending=None, retained=pending.candidate,
                       retained_authenticated=pending.authenticated, completed=pending.candidate,
                       archive=pending.prior_candidate if pending.mode == "reconcile" else "",
                       witness_known=state.witness_known or VALIDITY[pending.candidate])
    if kind == "replay" and state.completed:
        # The exact completed candidate ID denotes the same returned output;
        # replay is a self-loop with no worker, debit or observation mutation.
        return state
    raise ValueError("action is not available in this state")


def _choices(state):
    yield Action("observe_public")
    yield Action("observe_public", authenticated=True)
    for kind in ("authorize_public", "claim_inclusion", "reorg"):
        yield Action(kind)
    for candidate in VALIDITY:
        for authenticated in (False, True):
            yield Action("begin", candidate, "peer", authenticated)
            for expected in VALIDITY:
                yield Action("reconcile", candidate, "peer", authenticated, expected)
    for authenticated in (False, True):
        yield Action("begin", "valid", "public", authenticated)
        for expected in VALIDITY:
            yield Action("reconcile", "valid", "public", authenticated, expected)
    for kind in ("retry", "worker_verify", "worker_fail", "worker_cancel", "worker_crash", "replay"):
        yield Action(kind)


def successors(state, *, bounds=Bounds(), policy=Policy()):
    """Enumerate finite legal choices, including free exact completed replay."""
    _parameters(bounds, policy)
    _state_shape(state)
    for action in _choices(state):
        try:
            next_state = step(state, action, bounds=bounds, policy=policy)
        except ValueError:
            continue
        yield action, next_state


def safety_violations(state, *, bounds=Bounds()):
    """Check stored facts against independent invariants, without admission guards."""
    _parameters(bounds, Policy())
    _state_shape(state)
    violations = []
    if not 0 <= state.consumed <= bounds.attempt_limit:
        violations.append("allowance_out_of_bounds")
    if bool(state.retained) != (state.consumed > 0) or bool(state.original) != bool(state.retained):
        violations.append("candidate_admission_mismatch")
    if not state.alice_consumed:
        violations.append("alice_signing_ownership_reset")
    if (state.consumed > 0 or state.witness_known) and not state.possible_exposure:
        violations.append("exposure_missing")
    if state.completed:
        if not VALIDITY[state.completed]:
            violations.append("invalid_inner_completion")
        if state.completed != state.retained or state.pending is not None:
            violations.append("completed_output_context_mismatch")
    if state.archive:
        if (not state.completed or state.archive != state.original
                or state.archive == state.completed or state.consumed < 2):
            violations.append("reconciliation_archive_mismatch")
    if state.retained != state.original and not state.archive:
        violations.append("original_candidate_lost")
    if state.public_authorized and not state.public_observed:
        violations.append("public_authorization_without_observation")
    pending = state.pending
    if pending is not None:
        if state.consumed < 1 or not state.retained:
            violations.append("worker_without_admission")
        if pending.mode == "reconcile":
            if pending.prior_candidate != state.retained or pending.candidate == state.retained:
                violations.append("pending_reconciliation_mismatch")
        elif pending.candidate != state.retained:
            violations.append("pending_candidate_mismatch")
        if pending.source == "public" and not pending.locally_authorized:
            violations.append("unauthorized_public_admission")
        if pending.source == "peer" and not pending.authenticated:
            violations.append("unauthenticated_peer_admission")
    return tuple(violations)


def transition_violations(before, action, after, *, bounds=Bounds()):
    """Check edge invariants independently of the selected policy's guards."""
    _parameters(bounds, Policy())
    _state_shape(before)
    _state_shape(after)
    _action_shape(action)
    violations = []
    admission = action.kind in ("begin", "retry", "reconcile")
    if after.consumed != before.consumed + int(admission):
        violations.append("admission_debit_or_refund_error")
    if before.possible_exposure and not after.possible_exposure:
        violations.append("exposure_cleared")
    if before.witness_known and not after.witness_known:
        violations.append("witness_knowledge_cleared")
    if before.alice_consumed and not after.alice_consumed:
        violations.append("alice_signing_ownership_reset")
    if before.original and after.original != before.original:
        violations.append("original_candidate_replaced")
    if not before.completed and after.completed:
        if (action.kind != "worker_verify" or before.pending is None
                or after.completed != before.pending.candidate):
            violations.append("completion_without_worker_verification")
    if before.completed:
        if (after.completed, after.retained, after.retained_authenticated, after.archive) != (
                before.completed, before.retained, before.retained_authenticated, before.archive):
            violations.append("completed_result_changed")
    if action.kind == "reconcile":
        if (action.expected_candidate != before.retained or not before.retained
                or action.candidate == before.retained):
            violations.append("reconciliation_cas_bypassed")
        if (after.retained, after.archive, after.completed) != (before.retained, before.archive, before.completed):
            violations.append("replacement_committed_before_verification")
    if admission and action.kind != "retry" and action.source == "public":
        if (not before.public_observed or not before.public_authorized
                or action.candidate != "valid" or action.authenticated != before.public_authenticated):
            violations.append("unauthorized_public_admission")
    if admission and action.source == "peer" and not action.authenticated:
        violations.append("unauthenticated_peer_admission")
    if action.kind in ("worker_fail", "worker_cancel", "worker_crash"):
        if (after.retained, after.archive, after.completed) != (before.retained, before.archive, before.completed):
            violations.append("failed_worker_changed_candidate")
    if action.kind == "replay" and (not before.completed or after != before):
        violations.append("completed_replay_changed_state")
    return tuple(violations)


def availability_violations(state, *, bounds=Bounds(), policy=Policy()):
    """Identify a currently blocked valid recovery, not a future liveness claim."""
    _parameters(bounds, policy)
    _state_shape(state)
    if (state.completed or state.pending is not None
            or not state.public_observed or not state.public_authorized):
        return ()
    violations = []
    if state.consumed >= bounds.attempt_limit:
        violations.append("recovery_allowance_exhausted")
    if (policy.require_public_envelope and not state.public_authenticated
            and state.retained != "valid"):
        violations.append("public_witness_envelope_blocked")
    return tuple(violations)


def explore(*, bounds=Bounds(), policy=Policy(), max_states=50_000):
    """Exhaust the graph, retaining a shortest trace for each distinct finding.

    Finding discovery never stops exploration. A state budget returns an explicit
    incomplete result even if a concrete counterexample was already discovered.
    """
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
            state, action = parents[state]
            path.append(action)
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
        record(safety, safety_violations(state, bounds=bounds), path, state)
        record(availability, availability_violations(state, bounds=bounds, policy=policy), path, state)
        for action, next_state in successors(state, bounds=bounds, policy=policy):
            transitions += 1
            next_path = path + (action,)
            record(safety, transition_violations(state, action, next_state, bounds=bounds), next_path, next_state)
            record(safety, safety_violations(next_state, bounds=bounds), next_path, next_state)
            record(availability, availability_violations(next_state, bounds=bounds, policy=policy),
                   next_path, next_state)
            if next_state not in parents:
                if len(parents) >= max_states:
                    return result(False, "state_budget_exhausted")
                parents[next_state] = (state, action)
                queue.append(next_state)
    return result(True, "graph_exhausted")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", choices=POLICIES, default="baseline")
    parser.add_argument("--attempt-limit", type=int, default=2)
    parser.add_argument("--max-states", type=int, default=50_000)
    args = parser.parse_args(argv)
    try:
        bounds = Bounds(args.attempt_limit)
        result = explore(bounds=bounds, policy=POLICIES[args.policy], max_states=args.max_states)
    except ValueError:
        print(json.dumps({"status": "incomplete", "complete": False, "reason": "invalid_parameters"}))
        return 2
    print(json.dumps({
        "scope": "finite offline admission policy; no cryptographic, chain or liveness proof",
        "policy": args.policy,
        "bounds": asdict(bounds),
        "status": result.status,
        **asdict(result),
    }, indent=2, sort_keys=True))
    if not result.complete:
        return 2
    return int(bool(result.safety_findings or result.availability_findings))


if __name__ == "__main__":
    raise SystemExit(main())
