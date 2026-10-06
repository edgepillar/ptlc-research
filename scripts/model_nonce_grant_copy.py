"""Finite post-consumption grant-copy comparison, with no private material.

One atomic durable issuance creates one fixed grant for one nonce label. A
snapshot can retain the already issued worker or its later cached permission.
Restoration never resets issuance, effect consumption, epochs or external audit.
All policies deduplicate result receipts and reject results from an old epoch.

The effect-coupled policy ASSUMES a nonexportable, nonrollback boundary around
the actual nonce-dependent effect. It offers no separately copyable permission
after the final check. This indivisible symbolic transition is unimplemented:
it is not a Python lock, custody design, physical atomicity or cryptographic
worker. Other policies intentionally expose a copyable gap before the effect.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass, replace
import json


POLICIES = ("copyable-grant", "preflight-epoch", "exported-permit", "effect-coupled")
PHASES = ("idle", "absent", "ready", "checked", "permitted", "executed", "done", "lost", "refused")
SNAPSHOT_PHASES = ("ready", "checked", "permitted")
KINDS = ("issue", "snapshot", "restore", "advance-epoch", "preflight", "permit", "work", "result", "lose")


@dataclass(frozen=True)
class Action:
    kind: str
    worker: int = -1


@dataclass(frozen=True)
class Grant:
    # All fields are fixed public symbols, not digests or authenticated inputs.
    identity: int = 0
    nonce: int = 0
    binding: int = 0
    epoch: int = 0


@dataclass(frozen=True)
class Worker:
    phase: str = "idle"
    grant: Grant | None = None


@dataclass(frozen=True)
class Work:
    worker: int
    nonce: int
    grant: int
    binding: int
    epoch: int
    durable_burn_before_work: bool


@dataclass(frozen=True)
class Receipt:
    worker: int
    nonce: int
    grant: int
    binding: int
    epoch: int
    result_epoch: int
    accepted: bool


@dataclass(frozen=True)
class State:
    epoch: int = 0
    burned: bool = False
    effect_consumed: bool = False
    workers: tuple = (Worker(), Worker(phase="absent"))
    snapshot: Worker | None = None
    # These histories remain outside every copied worker and saved snapshot.
    work: tuple = ()
    receipts: tuple = ()


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


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _policy(policy):
    if type(policy) is not str or policy not in POLICIES:
        raise ValueError("an explicit supported grant-copy policy is required")


def _worker(worker):
    if (type(worker) is not Worker or type(worker.phase) is not str
            or worker.phase not in PHASES):
        raise ValueError("invalid finite grant worker")
    if worker.phase in ("idle", "absent"):
        if worker.grant is not None:
            raise ValueError("unexpected finite worker grant")
    elif (type(worker.grant) is not Grant or any(type(getattr(worker.grant, name)) is not int
            or getattr(worker.grant, name) != 0 for name in ("identity", "nonce", "binding", "epoch"))):
        raise ValueError("invalid fixed symbolic grant")


def _state(state):
    if (type(state) is not State or not _integer(state.epoch, 0, 1)
            or type(state.burned) is not bool or type(state.effect_consumed) is not bool
            or type(state.workers) is not tuple or len(state.workers) != 2
            or type(state.work) is not tuple or len(state.work) > 2
            or type(state.receipts) is not tuple or len(state.receipts) > 2):
        raise ValueError("invalid finite grant-copy state")
    for worker in state.workers:
        _worker(worker)
    if state.snapshot is not None:
        _worker(state.snapshot)
        if state.snapshot.phase not in SNAPSHOT_PHASES:
            raise ValueError("invalid finite worker snapshot")
    for event in (*state.work, *state.receipts):
        if (type(event) not in (Work, Receipt) or not _integer(event.worker, 0, 1)
                or any(type(getattr(event, name)) is not int or getattr(event, name) != 0
                       for name in ("nonce", "grant", "binding", "epoch"))):
            raise ValueError("invalid finite grant-copy audit")
    for event in state.work:
        if type(event) is not Work or type(event.durable_burn_before_work) is not bool:
            raise ValueError("invalid finite grant work audit")
    for event in state.receipts:
        if (type(event) is not Receipt or not _integer(event.result_epoch, 0, 1)
                or type(event.accepted) is not bool):
            raise ValueError("invalid finite grant receipt audit")


def _action(action):
    if (type(action) is not Action or type(action.kind) is not str
            or action.kind not in KINDS or not _integer(action.worker, -1, 1)):
        raise ValueError("an exact finite grant-copy action is required")
    if action.kind in ("issue", "restore", "advance-epoch"):
        valid = action.worker == -1
    elif action.kind == "snapshot":
        valid = action.worker == 0
    else:
        valid = action.worker in (0, 1)
    if not valid:
        raise ValueError("unsupported finite grant-copy action fields")


def _replace_worker(state, index, worker, **changes):
    workers = list(state.workers)
    workers[index] = worker
    return replace(state, workers=tuple(workers), **changes)


def _transitions(state, policy):
    if not state.burned and state.workers[0].phase == "idle":
        yield Action("issue"), _replace_worker(state, 0, Worker("ready", Grant()), burned=True)
    if state.snapshot is None and state.workers[0].phase in SNAPSHOT_PHASES:
        yield Action("snapshot", 0), replace(state, snapshot=state.workers[0])
    if state.snapshot is not None and state.workers[1].phase == "absent":
        # Exactly the saved grant, epoch and cached permission are copied. No
        # nonce regeneration, new grant or reset of external state occurs.
        yield Action("restore"), _replace_worker(state, 1, state.snapshot)
    if state.burned and state.epoch == 0:
        yield Action("advance-epoch"), replace(state, epoch=1)
    for index, worker in enumerate(state.workers):
        def emit(kind, phase, **changes):
            return Action(kind, index), _replace_worker(state, index, replace(worker, phase=phase), **changes)
        if worker.phase == "ready" and policy == "preflight-epoch":
            # A passed check survives in a later copied in-flight worker.
            yield emit("preflight", "checked" if worker.grant.epoch == state.epoch else "refused")
        if worker.phase == "ready" and policy == "exported-permit":
            allowed = worker.grant.epoch == state.epoch and not state.effect_consumed
            # Even this atomic shared durable mark returns copyable permission.
            yield emit("permit", "permitted" if allowed else "refused",
                       effect_consumed=state.effect_consumed or allowed)
        work_phase = {"copyable-grant": "ready", "preflight-epoch": "checked",
                      "exported-permit": "permitted", "effect-coupled": "ready"}[policy]
        if worker.phase == work_phase and len(state.work) < 2:
            allowed = policy != "effect-coupled" or (
                worker.grant.epoch == state.epoch and not state.effect_consumed)
            if allowed:
                grant = worker.grant
                event = Work(index, grant.nonce, grant.identity, grant.binding, grant.epoch, state.burned)
                # An indivisible abstract effect is an explicit premise. No
                # accessible authorized state exists between this check/effect.
                yield emit("work", "executed", work=state.work + (event,),
                           effect_consumed=state.effect_consumed or policy == "effect-coupled")
            else:
                yield emit("work", "refused")
        if worker.phase == "executed" and len(state.receipts) < 2:
            grant = worker.grant
            accepted = grant.epoch == state.epoch and not any(event.accepted for event in state.receipts)
            receipt = Receipt(index, grant.nonce, grant.identity, grant.binding,
                              grant.epoch, state.epoch, accepted)
            yield emit("result", "done", receipts=state.receipts + (receipt,))
        if worker.phase in (*SNAPSHOT_PHASES, "executed", "done"):
            yield emit("lose", "lost")


def step(state, action, *, policy="effect-coupled"):
    """Replay one selected action. Shape validation is not reachability proof."""
    _policy(policy)
    _state(state)
    _action(action)
    for candidate, following in _transitions(state, policy):
        if candidate == action:
            return following
    raise ValueError("action unavailable in the selected finite grant state")


def findings(state):
    """Inspect external effect/receipt history independently of mutable flags."""
    _state(state)
    names = []
    if len({event.nonce for event in state.work}) != len(state.work):
        names.append("same_nonce_work_repeated")
    if any(not event.durable_burn_before_work for event in state.work):
        names.append("work_before_durable_burn")
    if any(not any((work.worker, work.nonce, work.grant, work.binding, work.epoch) ==
                   (receipt.worker, receipt.nonce, receipt.grant, receipt.binding, receipt.epoch)
                   for work in state.work) for receipt in state.receipts):
        names.append("receipt_without_same_work")
    accepted = [event.grant for event in state.receipts if event.accepted]
    if len(set(accepted)) != len(accepted):
        names.append("multiple_accepted_receipts_for_grant")
    return tuple(names)


def compare(*, policy="effect-coupled", max_states=100000):
    """Exhaust the entire bounded graph, retaining shortest finding traces."""
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
        raise ValueError("invalid finite grant-copy model arguments")


def main(argv=None):
    parser = _Parser(description="Finite symbolic post-consumption grant comparison; no signer", allow_abbrev=False)
    parser.add_argument("--policy", choices=("all", *POLICIES), default="all")
    parser.add_argument("--max-states", type=int, default=100000)
    try:
        args = parser.parse_args(argv)
        policies = POLICIES if args.policy == "all" else (args.policy,)
        reports = tuple(compare(policy=policy, max_states=args.max_states) for policy in policies)
    except ValueError:
        print("FAIL: finite grant-copy model arguments rejected")
        return 2
    print(json.dumps({
        "schema": "ptlc-nonce-grant-copy-model-v1",
        "claim": "finite symbols only; effect-coupled custody premise unimplemented; application and core NO-GO",
        "bounds": {"workers": 2, "saved_snapshots": 1, "restorations": 1, "grant_labels": 1,
                   "nonce_labels": 1, "binding_labels": 1, "epoch_advances": 1, "max_states": args.max_states},
        "results": [dict(asdict(report), status=report.status) for report in reports],
    }, indent=2))
    if any(not report.complete for report in reports):
        return 2
    return int(any(report.witnesses for report in reports))


if __name__ == "__main__":
    raise SystemExit(main())
