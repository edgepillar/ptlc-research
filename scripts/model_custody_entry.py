"""Finite custody admission, effect and original-output recovery comparison.

All values are public symbols. Recipient admission is an assumed image check,
not attestation or key provisioning. Copies retain a released worker's local
consumption view; they never rewind the world or its irreversible effect audit.
The continuous-authority policy ASSUMES indivisible current-policy, verified
nonrewinding continuity and consumption at the actual effect, covering every
usable copy. Separately, delivery needs current authority and exactly retained
original output. Neither premise has a selected physical implementation.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json


POLICIES = ("recipient-only", "cached-current", "local-consumption",
            "work-only", "continuous-authority")
PHASES = ("absent", "released", "ready", "executed", "retained", "lost", "refused")
KINDS = ("admit", "burn", "snapshot", "restore", "revoke", "lose-continuity",
         "reanchor", "work", "retain", "lose", "deliver")


@dataclass(frozen=True)
class Action:
    kind: str
    worker: int = -1


@dataclass(frozen=True)
class Worker:
    phase: str = "absent"
    image: int = 0
    local_consumed: bool = False
    output: int = -1


@dataclass(frozen=True)
class Work:
    worker: int
    output: int
    nonce: int
    bound_epoch: int
    actual_epoch: int
    actual_continuity: int
    burned_before_work: bool
    unknown_before_work: bool


@dataclass(frozen=True)
class Output:
    # Invocation labels are not bytes, signatures or authenticated digests.
    work: int
    worker: int
    nonce: int = 0


@dataclass(frozen=True)
class Delivery:
    output: Output
    retained_at_delivery: Output | None
    actual_epoch: int
    actual_continuity: int


@dataclass(frozen=True)
class State:
    epoch: int = 0
    # 0: initially verified; 1: unavailable/conflicting; 2: ideally reanchored.
    continuity: int = 0
    burned: bool = False
    consumed: bool = False
    unknown_spent: bool = False
    workers: tuple = (Worker(), Worker())
    snapshot: Worker | None = None
    work: tuple = ()
    original: Output | None = None
    deliveries: tuple = ()


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
    states: int
    transitions: int
    witnesses: tuple

    @property
    def status(self):
        if not self.complete:
            return "incomplete"
        return "counterexample" if self.witnesses else "conditional-no-counterexample"


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _policy(policy):
    if type(policy) is not str or policy not in POLICIES:
        raise ValueError("an explicit supported custody model policy is required")


def _output(value):
    if (type(value) is not Output or not _integer(value.work, 0, 1)
            or not _integer(value.worker, 0, 1) or type(value.nonce) is not int
            or value.nonce != 0):
        raise ValueError("invalid fixed symbolic original output")


def _worker(value):
    if (type(value) is not Worker or type(value.phase) is not str or value.phase not in PHASES
            or type(value.image) is not int or value.image != 0
            or type(value.local_consumed) is not bool
            or not _integer(value.output, -1, 1)):
        raise ValueError("invalid finite custody worker")
    if value.phase in ("absent", "released", "ready") and value.output != -1:
        raise ValueError("unexpected output before a symbolic effect")
    if value.phase in ("executed", "retained") and value.output == -1:
        raise ValueError("missing symbolic effect output")


def _state(state):
    if (type(state) is not State or not _integer(state.epoch, 0, 1)
            or not _integer(state.continuity, 0, 2)
            or any(type(getattr(state, name)) is not bool
                   for name in ("burned", "consumed", "unknown_spent"))
            or type(state.workers) is not tuple or len(state.workers) != 2
            or type(state.work) is not tuple or len(state.work) > 2
            or type(state.deliveries) is not tuple or len(state.deliveries) > 2):
        raise ValueError("invalid finite custody state")
    for worker in state.workers:
        _worker(worker)
    if state.snapshot is not None:
        _worker(state.snapshot)
        if state.snapshot.phase != "ready":
            raise ValueError("invalid finite ready-worker snapshot")
    if state.original is not None:
        _output(state.original)
    for event in state.work:
        if (type(event) is not Work or not _integer(event.worker, 0, 1)
                or not _integer(event.output, 0, 1)
                or type(event.nonce) is not int or event.nonce != 0
                or type(event.bound_epoch) is not int or event.bound_epoch != 0
                or not _integer(event.actual_epoch, 0, 1)
                or not _integer(event.actual_continuity, 0, 2)
                or type(event.burned_before_work) is not bool
                or type(event.unknown_before_work) is not bool):
            raise ValueError("invalid irreversible symbolic work audit")
    for event in state.deliveries:
        if (type(event) is not Delivery or not _integer(event.actual_epoch, 0, 1)
                or not _integer(event.actual_continuity, 0, 2)):
            raise ValueError("invalid irreversible symbolic delivery audit")
        _output(event.output)
        if event.retained_at_delivery is not None:
            _output(event.retained_at_delivery)


def _action(action):
    if (type(action) is not Action or type(action.kind) is not str
            or action.kind not in KINDS or not _integer(action.worker, -1, 1)):
        raise ValueError("an exact finite custody action is required")
    if action.kind in ("admit", "burn", "snapshot"):
        valid = action.worker == 0
    elif action.kind in ("work", "retain", "lose"):
        valid = action.worker in (0, 1)
    else:
        valid = action.worker == -1
    if not valid:
        raise ValueError("unsupported finite custody action fields")


def _current(state):
    return state.epoch == 0 and state.continuity != 1


def _replace_worker(state, index, worker, **changes):
    workers = list(state.workers)
    workers[index] = worker
    return replace(state, workers=tuple(workers), **changes)


def _transitions(state, policy):
    first = state.workers[0]
    if first.phase == "absent":
        # One approved image is admitted under the initially current world.
        yield Action("admit", 0), _replace_worker(state, 0, Worker("released"))
    if first.phase == "released" and not state.burned:
        allowed = policy == "recipient-only" or _current(state)
        yield Action("burn", 0), _replace_worker(state, 0,
            replace(first, phase="ready" if allowed else "refused"), burned=allowed)
    if first.phase != "absent":
        if state.epoch == 0:
            yield Action("revoke"), replace(state, epoch=1)
        if state.continuity == 0:
            yield Action("lose-continuity"), replace(state, continuity=1)
        if state.continuity == 1:
            # Correct reanchoring is an environmental premise, not a reset or
            # rollback. No burn, consumption, output or audit is changed.
            yield Action("reanchor"), replace(state, continuity=2)
    if state.snapshot is None and first.phase == "ready":
        yield Action("snapshot", 0), replace(state, snapshot=first)
    if state.snapshot is not None and state.workers[1].phase == "absent":
        # Conditional copy of already released work, never a new key release.
        yield Action("restore"), _replace_worker(state, 1, state.snapshot)
    for index, worker in enumerate(state.workers):
        if worker.phase == "ready" and len(state.work) < 2:
            if policy == "recipient-only":
                allowed = True
            elif policy == "local-consumption":
                # Current authority is ideal here, but the consumption view
                # belongs to the copied worker rather than a shared anchor.
                allowed = _current(state) and not worker.local_consumed
            elif policy == "cached-current":
                allowed = not state.consumed and not state.unknown_spent
            else:
                allowed = _current(state) and not state.consumed and not state.unknown_spent
            if allowed:
                output = len(state.work)
                event = Work(index, output, 0, 0, state.epoch, state.continuity,
                             state.burned, state.unknown_spent)
                # In the reference this is indivisible, including ALL usable
                # copies. There is no exported checked/authorized work state.
                yield Action("work", index), _replace_worker(state, index,
                    replace(worker, phase="executed", local_consumed=True, output=output),
                    consumed=True, work=state.work + (event,))
            else:
                yield Action("work", index), _replace_worker(state, index, replace(worker, phase="refused"))
        if worker.phase == "executed":
            if state.original is None:
                original = Output(worker.output, index)
                yield Action("retain", index), _replace_worker(state, index,
                    replace(worker, phase="retained"), original=original)
            else:
                # Deduplicating retention cannot undo an extra prior effect.
                yield Action("retain", index), _replace_worker(state, index, replace(worker, phase="refused"))
        if worker.phase in ("released", "ready", "executed", "retained"):
            unknown = state.unknown_spent or (state.burned and state.original is None)
            # The lost worker's output is unusable. Other immutable originals
            # can still be reconciled; no new work repairs spent uncertainty.
            yield Action("lose", index), _replace_worker(state, index,
                replace(worker, phase="lost", output=-1), unknown_spent=unknown)
    if state.original is not None and len(state.deliveries) < 2:
        allowed = policy not in ("continuous-authority", "local-consumption") or _current(state)
        if allowed:
            event = Delivery(state.original, state.original, state.epoch, state.continuity)
            yield Action("deliver"), replace(state, deliveries=state.deliveries + (event,))


def step(state, action, *, policy="continuous-authority"):
    """Replay a chosen finite action; structural validity is not reachability."""
    _policy(policy)
    _state(state)
    _action(action)
    for candidate, following in _transitions(state, policy):
        if candidate == action:
            return following
    raise ValueError("action unavailable in the selected finite custody state")


def findings(state):
    """Read irreversible event facts, independent of present policy/cache flags."""
    _state(state)
    names = []
    if len({event.nonce for event in state.work}) != len(state.work):
        names.append("same_nonce_work_repeated")
    if any(not event.burned_before_work for event in state.work):
        names.append("work_before_durable_burn")
    if any(event.actual_epoch != event.bound_epoch for event in state.work):
        names.append("work_after_revocation")
    if any(event.actual_continuity == 1 for event in state.work):
        names.append("work_without_verified_continuity")
    if any(event.unknown_before_work for event in state.work):
        names.append("work_after_unknown_spent")
    if any(event.output != event.retained_at_delivery for event in state.deliveries):
        names.append("delivery_without_exact_original_retention")
    if any(not any((work.output, work.worker, work.nonce) ==
                   (event.output.work, event.output.worker, event.output.nonce)
                   for work in state.work) for event in state.deliveries):
        names.append("delivery_without_original_effect")
    if any(event.actual_epoch != 0 for event in state.deliveries):
        names.append("delivery_after_revocation")
    if any(event.actual_continuity == 1 for event in state.deliveries):
        names.append("delivery_without_verified_continuity")
    return tuple(names)


def compare(*, policy="continuous-authority", max_states=200000):
    """Exhaust a finite graph, recording one shortest trace per violated rule."""
    _policy(policy)
    if not _integer(max_states, 1, 1000000):
        raise ValueError("a bounded exact integer state limit is required")
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
        for action, following in _transitions(state, policy):
            transitions += 1
            if following not in parents:
                if len(parents) >= max_states:
                    return Comparison(policy, False, "state-limit", len(parents),
                                      transitions, tuple(witnesses.values()))
                parents[following] = (state, action)
                queue.append(following)
    return Comparison(policy, True, "finite-graph-exhausted", len(parents),
                      transitions, tuple(witnesses.values()))


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid finite custody model arguments")


def main(argv=None):
    parser = _Parser(description="Finite public custody symbols; no signer", allow_abbrev=False)
    parser.add_argument("--policy", choices=("all", *POLICIES), default="all")
    parser.add_argument("--max-states", type=int, default=200000)
    try:
        args = parser.parse_args(argv)
        policies = POLICIES if args.policy == "all" else (args.policy,)
        reports = tuple(compare(policy=policy, max_states=args.max_states) for policy in policies)
    except ValueError:
        print("FAIL: finite custody model arguments rejected")
        return 2
    print(json.dumps({
        "schema": "ptlc-custody-entry-model-v1",
        "claim": "finite symbols only; custody and reanchoring premises unimplemented; application and core NO-GO",
        "bounds": {"workers": 2, "images": 1, "nonce_labels": 1, "bound_epochs": 1,
                   "revocations": 1, "saved_snapshots": 1, "restorations": 1,
                   "continuity_losses": 1, "ideal_reanchors": 1, "work_events": 2,
                   "original_outputs": 1, "deliveries": 2, "max_states": args.max_states},
        "results": [dict(asdict(report), status=report.status) for report in reports],
    }, indent=2))
    if any(not report.complete for report in reports):
        return 2
    return int(any(report.witnesses for report in reports))


if __name__ == "__main__":
    raise SystemExit(main())
