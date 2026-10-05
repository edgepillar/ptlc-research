"""Offline source/operation ordering comparison; no backend or worker entry.

Current policy, provisioning, canonical scope, signature facts and durable scoped
records are ideal external premises. Entries are abstract audited events. The
finite schedules do not enumerate the entire action graph or prove a protocol.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
import json


POLICIES = ("cached-read", "commit-cutoff", "entry-cutoff", "rollbackable-ledger")
PROFILES = (0, 1, 2, 4)
MODES = ("live", "unavailable", "ambiguous", "compromise-detected")
# Complete profiles are symbols, not decoded policy or authenticated wire bytes.
PROFILE_FACTS = {0: (0, 0, 2), 1: (0, 0, 1), 2: (1, 0, 1), 4: (1, 1, 1)}
LOCAL = ("read", "read-stale", "read-forged", "commit", "commit-lost",
         "lookup", "enter", "restore-client")
GLOBAL = ("advance", "unavailable", "ambiguous", "compromise-detected", "live", "restore-ledger")


@dataclass(frozen=True)
class Actor:
    profile: int = -1
    operation: int = -1
    cached_active: bool = False
    receipt_known: bool = False
    outcome_unknown: bool = False
    restored: bool = False


@dataclass(frozen=True)
class Record:
    operation: int
    profile: int
    commit_phase: int
    entry_phase: int = -1


@dataclass(frozen=True)
class Charge:
    operation: int
    profile: int
    phase: int
    mode: str = "live"


@dataclass(frozen=True)
class Entry:
    operation: int
    profile: int
    commit_phase: int
    phase: int
    mode: str = "live"


@dataclass(frozen=True)
class State:
    phase: int = 0
    mode: str = "live"
    actors: tuple = (Actor(), Actor())
    records: tuple = (None, None)
    ledger_restored: bool = False
    # Audit history is never rewound, including in the deliberately unsafe control.
    charges: tuple = ()
    entries: tuple = ()


@dataclass(frozen=True)
class Action:
    kind: str
    actor: int = -1
    profile: int = -1
    operation: int = -1


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
    schedules: int
    transitions: int
    violations: tuple
    boundaries: tuple


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _shape(state, policy):
    if type(policy) is not str or policy not in POLICIES:
        raise ValueError("an explicit source/use policy is required")
    if (type(state) is not State or not _integer(state.phase, 0, 4)
            or type(state.mode) is not str or state.mode not in MODES
            or type(state.actors) is not tuple or len(state.actors) != 2
            or type(state.records) is not tuple or len(state.records) != 2
            or type(state.ledger_restored) is not bool
            or (state.ledger_restored and policy != "rollbackable-ledger")
            or type(state.charges) is not tuple or len(state.charges) > 4
            or type(state.entries) is not tuple or len(state.entries) > 4):
        raise ValueError("invalid modeled source state")
    for actor in state.actors:
        if (type(actor) is not Actor or not _integer(actor.profile, -1, 4)
                or actor.profile not in (-1, *PROFILES)
                or not _integer(actor.operation, -1, 1)
                or any(type(getattr(actor, field)) is not bool for field in
                       ("cached_active", "receipt_known", "outcome_unknown", "restored"))
                or (actor.profile == -1) != (actor.operation == -1)
                or (actor.profile == -1 and any((actor.cached_active, actor.receipt_known,
                                               actor.outcome_unknown, actor.restored)))
                or (actor.receipt_known and actor.outcome_unknown)):
            raise ValueError("invalid modeled caller")
    for charge in state.charges:
        if (type(charge) is not Charge or not _integer(charge.operation, 0, 1)
                or not _integer(charge.profile, 0, 4) or charge.profile not in PROFILES
                or not _integer(charge.phase, 0, state.phase)
                or type(charge.mode) is not str or charge.mode not in MODES):
            raise ValueError("invalid modeled charge audit")
    if tuple(charge.phase for charge in state.charges) != tuple(sorted(charge.phase for charge in state.charges)):
        raise ValueError("invalid modeled charge order")
    for entry in state.entries:
        if (type(entry) is not Entry or not _integer(entry.operation, 0, 1)
                or not _integer(entry.profile, 0, 4) or entry.profile not in PROFILES
                or not _integer(entry.commit_phase, 0, state.phase)
                or not _integer(entry.phase, entry.commit_phase, state.phase)
                or type(entry.mode) is not str or entry.mode not in MODES
                or not any((charge.operation, charge.profile, charge.phase) ==
                           (entry.operation, entry.profile, entry.commit_phase) for charge in state.charges)):
            raise ValueError("invalid modeled entry audit")
    if tuple(entry.phase for entry in state.entries) != tuple(sorted(entry.phase for entry in state.entries)):
        raise ValueError("invalid modeled entry order")
    for operation, record in enumerate(state.records):
        if record is None:
            continue
        if (type(record) is not Record or not _integer(record.operation, 0, 1)
                or record.operation != operation or not _integer(record.profile, 0, 4)
                or record.profile not in PROFILES or not _integer(record.commit_phase, 0, 4)
                or not _integer(record.entry_phase, -1, 4)
                or (record.entry_phase != -1 and record.entry_phase < record.commit_phase)
                or record.commit_phase > state.phase or record.entry_phase > state.phase
                or not any((charge.operation, charge.profile, charge.phase) ==
                           (operation, record.profile, record.commit_phase) for charge in state.charges)):
            raise ValueError("invalid modeled operation record")
        if record.entry_phase != -1 and not any((entry.operation, entry.profile,
                entry.commit_phase, entry.phase) == (operation, record.profile,
                record.commit_phase, record.entry_phase) for entry in state.entries):
            raise ValueError("modeled entered record lacks its audited event")
    if not state.ledger_restored:
        if len(state.charges) != sum(record is not None for record in state.records):
            raise ValueError("nonrewound source lost its charge record")
        for entry in state.entries:
            record = state.records[entry.operation]
            if record is None or (record.profile, record.commit_phase, record.entry_phase) != (entry.profile, entry.commit_phase, entry.phase):
                raise ValueError("nonrewound source lost its entry record")


def _action(action):
    if (type(action) is not Action or type(action.kind) is not str
            or action.kind not in LOCAL + GLOBAL
            or not _integer(action.actor, -1, 1)
            or not _integer(action.profile, -1, 4)
            or not _integer(action.operation, -1, 1)):
        raise ValueError("an exact supported modeled action is required")
    if action.kind in GLOBAL:
        valid = (action.actor, action.profile, action.operation) == (-1, -1, -1)
    elif action.kind.startswith("read"):
        valid = action.actor in (0, 1) and action.profile in PROFILES and action.operation in (0, 1)
    else:
        valid = action.actor in (0, 1) and action.profile == action.operation == -1
    if not valid:
        raise ValueError("modeled action has invalid scope or actor fields")


def _actors(state, index, actor):
    actors = list(state.actors); actors[index] = actor
    return replace(state, actors=tuple(actors))


def _records(state, operation, record):
    records = list(state.records); records[operation] = record
    return replace(state, records=tuple(records))


def _current(state, profile):
    return state.mode == "live" and state.phase in PROFILES and profile == state.phase


def step(state, action, *, policy="commit-cutoff"):
    """Apply one abstract event; indivisible mutations are model assumptions."""
    _shape(state, policy); _action(action)
    kind = action.kind
    if kind == "advance":
        if state.phase == 4:
            raise ValueError("the finite policy sequence is exhausted")
        return replace(state, phase=state.phase + 1)
    if kind in MODES:
        if state.mode == kind:
            raise ValueError("source mode is already selected")
        return replace(state, mode=kind)
    if kind == "restore-ledger":
        if policy != "rollbackable-ledger" or state.ledger_restored or not state.charges:
            raise ValueError("source rewind is only a bounded unsafe-control event")
        return replace(state, records=(None, None), ledger_restored=True)
    actor = state.actors[action.actor]
    if kind.startswith("read"):
        if actor.profile != -1:
            raise ValueError("a caller already has an independently selected proposal")
        active = (_current(state, action.profile) if kind == "read" else
                  action.profile == 0 if kind == "read-stale" else True)
        return _actors(state, action.actor, Actor(action.profile, action.operation, active))
    if actor.profile == -1:
        raise ValueError("a caller must independently select its proposal first")
    record = state.records[actor.operation]
    if kind == "restore-client":
        if actor.restored:
            raise ValueError("only one coherent local caller restore is modeled")
        return _actors(state, action.actor, replace(actor, receipt_known=False,
            outcome_unknown=False, restored=True))
    if kind == "lookup":
        if not actor.outcome_unknown:
            raise ValueError("lookup reconciles only the original unknown operation")
        if state.mode != "live":
            return state
        known = record is not None and record.profile == actor.profile
        return _actors(state, action.actor, replace(actor, receipt_known=known, outcome_unknown=False))
    if kind in ("commit", "commit-lost"):
        reachable = state.mode == "live" or policy == "cached-read"
        if not reachable:
            return _actors(state, action.actor, replace(actor, receipt_known=False,
                outcome_unknown=kind == "commit-lost" or actor.outcome_unknown))
        if record is not None:
            known = record.profile == actor.profile
            return _actors(state, action.actor, replace(actor,
                receipt_known=known and kind == "commit", outcome_unknown=kind == "commit-lost"))
        active = actor.cached_active if policy == "cached-read" else _current(state, actor.profile)
        cap = PROFILE_FACTS[actor.profile][2]
        if not active or sum(item is not None for item in state.records) >= cap:
            return _actors(state, action.actor, replace(actor, receipt_known=False,
                outcome_unknown=kind == "commit-lost"))
        record = Record(actor.operation, actor.profile, state.phase)
        result = _records(state, actor.operation, record)
        result = replace(result, charges=result.charges +
                         (Charge(actor.operation, actor.profile, state.phase, state.mode),))
        return _actors(result, action.actor, replace(actor, receipt_known=kind == "commit",
            outcome_unknown=kind == "commit-lost"))
    # Each abstract entry is serialized with its durable operation record.
    if (not actor.receipt_known or record is None or record.profile != actor.profile
            or record.entry_phase != -1):
        return state
    if policy != "cached-read" and state.mode != "live":
        return state
    if policy in ("entry-cutoff", "rollbackable-ledger") and not _current(state, actor.profile):
        return state  # A rejected entry never refunds its earlier charge.
    result = _records(state, actor.operation, replace(record, entry_phase=state.phase))
    return replace(result, entries=result.entries +
        (Entry(actor.operation, actor.profile, record.commit_phase, state.phase, state.mode),))


def findings(state, *, policy="commit-cutoff"):
    """Audit each event at its selected cutoff; later revocation is not retroactive."""
    _shape(state, policy)
    safety, boundary = set(), set()
    if any(charge.profile != charge.phase or charge.phase == 3 for charge in state.charges):
        safety.add("charge_without_current_policy")
    if any(charge.mode != "live" for charge in state.charges):
        safety.add("charge_without_available_trusted_source")
    for entry in state.entries:
        if entry.mode != "live":
            safety.add("entry_without_available_trusted_source")
        cutoff = entry.commit_phase if policy in ("cached-read", "commit-cutoff") else entry.phase
        if entry.profile != cutoff or cutoff == 3:
            safety.add("entry_without_policy_at_selected_cutoff")
        if entry.phase != entry.commit_phase:
            boundary.add("policy_changed_between_commit_and_entry")
        if entry.phase == 3:
            boundary.add("entry_after_revocation_under_commit_cutoff")
    if any(sum(c.operation == operation for c in state.charges) > 1 for operation in (0, 1)):
        safety.add("same_operation_charged_again_after_source_restore")
    if any(sum(e.operation == operation for e in state.entries) > 1 for operation in (0, 1)):
        safety.add("same_operation_entered_again_after_source_restore")
    if len(state.charges) > sum(item is not None for item in state.records):
        safety.add("source_restore_erased_charge_lineage")
    if any(actor.outcome_unknown for actor in state.actors) and state.charges:
        boundary.add("lost_reply_does_not_prove_absence_or_refund")
    if state.charges and not state.entries:
        boundary.add("charge_does_not_prove_worker_entry")
    if any(actor.restored for actor in state.actors):
        boundary.add("local_restore_does_not_rewind_trusted_source")
    if len({c.operation for c in state.charges}) == 2 and len({c.profile for c in state.charges}) == 1:
        boundary.add("different_operation_ids_can_charge_the_same_proposal")
    if policy == "cached-read" and state.charges:
        boundary.add("cached_claim_is_not_a_use_time_authority_fact")
    return tuple(sorted(safety)), tuple(sorted(boundary))


def interleavings(*streams):
    """Enumerate all shuffles preserving each supplied stream's own order."""
    if all(not stream for stream in streams):
        yield ()
        return
    for index, stream in enumerate(streams):
        if stream:
            remaining = list(streams); remaining[index] = stream[1:]
            for suffix in interleavings(*remaining):
                yield (stream[0], *suffix)


def comparison(*, policy="commit-cutoff", max_schedules=10000, distinct_operations=False):
    """Enumerate selected complete schedules, not the full action graph.

    Two fixed callers read profile zero, commit and attempt entry. A third stream
    advances through one to four ordered policy changes. Outage, forged read,
    lost reply and restore are separate directed tests, not included here.
    """
    _shape(State(), policy)
    if (not _integer(max_schedules, 1, 100000) or type(distinct_operations) is not bool):
        raise ValueError("explicit finite schedule bounds are required")
    actors = [tuple((Action("read", actor, 0, actor if distinct_operations else 0),
                     Action("commit", actor), Action("enter", actor))) for actor in (0, 1)]
    schedules, transitions, safety, boundary = 0, 0, {}, {}
    for updates in (1, 2, 3, 4):
        for trace in interleavings(*actors, (Action("advance"),) * updates):
            if schedules == max_schedules:
                return Comparison(policy, False, "schedule-cap", schedules, transitions,
                    tuple(safety.values()), tuple(boundary.values()))
            state = State()
            for action in trace:
                state = step(state, action, policy=policy); transitions += 1
            schedules += 1
            names, limits = findings(state, policy=policy)
            for name in names: safety.setdefault(name, Witness(name, trace, state))
            for name in limits: boundary.setdefault(name, Witness(name, trace, state))
    return Comparison(policy, True, "selected-schedules-complete", schedules, transitions,
        tuple(safety.values()), tuple(boundary.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", choices=POLICIES, default="commit-cutoff")
    parser.add_argument("--max-schedules", type=int, default=10000)
    parser.add_argument("--distinct-operations", action="store_true")
    args = parser.parse_args()
    try:
        result = comparison(policy=args.policy, max_schedules=args.max_schedules,
                            distinct_operations=args.distinct_operations)
    except ValueError:
        parser.error("invalid finite comparison parameters")
    output = asdict(result)
    output.update(status="complete" if result.complete else "incomplete",
        trust="ideal independently provisioned current policy and serialized durable operation/entry records; no actual source authentication or actuation",
        domain=dict(actors=2, operation_ids=2, profiles=4, policy_phases=5,
                    selected_update_streams=4, distinct_operations=args.distinct_operations,
                    full_action_graph=False),
        policy_cutoff="entry" if args.policy in ("entry-cutoff", "rollbackable-ledger") else "commit")
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0 if result.complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
