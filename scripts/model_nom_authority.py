#!/usr/bin/env python3
"""Finite test-only NoM source/restore/entry ordering, with ideal external facts.

No cryptography, clock, persistence, source service or recovery worker runs.
The ideal world and ledger stay outside copied state by assumption only.
"""

import argparse
import json
from dataclasses import dataclass, field

from offline_session.nom_authority_contract import OBLIGATIONS


POLICIES = ("cached-claim", "check-before-entry", "rollbackable-atomic-entry", "ideal-atomic-entry")
RESOURCE = "complete-selected-fixed-terms-and-exact-originals"


@dataclass
class Consumer:
    reply: tuple | None = None
    ready: bool = False
    ledger: dict = field(default_factory=dict)


@dataclass
class World:
    revision: int = 0
    source_revision: int = 0
    fence: int = 0
    source_fence: int = 0
    facts: tuple = (True,) * len(OBLIGATIONS)
    source_facts: tuple = (True,) * len(OBLIGATIONS)
    ledger: dict = field(default_factory=dict)
    consumers: list = field(default_factory=lambda: [Consumer(), Consumer()])
    effects: int = 0
    unsafe_entries: int = 0
    unknown_replays: int = 0


def shuffles(left, right):
    """Enumerate only order-preserving shuffles of the selected two streams."""
    if not left:
        yield tuple(right)
    elif not right:
        yield tuple(left)
    else:
        for tail in shuffles(left[1:], right):
            yield (left[0],) + tail
        for tail in shuffles(left, right[1:]):
            yield (right[0],) + tail


def schedules():
    stream = ((0, "read", None), (0, "check", None), (0, "enter", None))
    for fact in (*OBLIGATIONS, "benign_extension"):
        for events in shuffles(stream, ((0, "advance", fact),)):
            yield "update-" + fact, events
    for events in shuffles(stream, tuple((1, action, value) for _, action, value in stream)):
        yield "independent-copies", events
    yield "source-restore", ((0, "advance", "live_funding_entry"), (0, "source_restore", None), *stream)
    yield "consumer-restore-before-entry", (*stream[:2], (0, "consumer_restore", None), stream[2])
    yield "consumer-restore-after-unknown", (*stream[:2], (0, "enter_unknown", None),
        (0, "consumer_restore", None), *stream)
    yield "lost-result-exact-replay", (*stream[:2], (0, "enter_unknown", None), *stream)


def transition(world, policy, event):
    """Serialize abstract entry; no returned value is an application capability."""
    if policy not in POLICIES:
        raise ValueError("unknown finite policy")
    actor, action, value = event
    consumer = world.consumers[actor]
    if action == "advance":
        world.revision += 1
        facts = list(world.facts)
        if value != "benign_extension":
            facts[OBLIGATIONS.index(value)] = False
        world.facts = tuple(facts)
        world.source_revision, world.source_facts = world.revision, world.facts
        return "UPDATED"
    if action == "source_restore":
        world.source_revision, world.source_facts, world.source_fence = 0, (True,) * len(OBLIGATIONS), 0
        return "RESTORED_SOURCE_CLAIMS"
    if action == "consumer_restore":
        # Coherent old local copy loses its ledger and retained knowledge.
        # The ideal external fence changes outside that copy, by assumption.
        consumer.ledger.clear()
        world.fence += 1
        return "RESTORED_CONSUMER"
    if action == "read":
        consumer.reply = (world.source_revision, world.source_fence, world.source_facts)
        consumer.ready = False
        return "CLAIMED_READ"
    current = consumer.reply == (world.revision, world.fence, world.facts) and all(world.facts)
    if action == "check":
        consumer.ready = current
        return "CHECKED" if current else "REFUSED"
    if action not in ("enter", "enter_unknown"):
        raise ValueError("unknown finite event")
    ledger = world.ledger if policy == "ideal-atomic-entry" else consumer.ledger
    if RESOURCE in ledger:
        if ledger[RESOURCE] == "UNKNOWN":
            world.unknown_replays += 1
        return "RETAINED_" + ledger[RESOURCE]
    supported = consumer.reply is not None and all(consumer.reply[2])
    allowed = supported and {
        "cached-claim": True,
        "check-before-entry": consumer.ready,
        "rollbackable-atomic-entry": consumer.reply == (world.source_revision, world.source_fence, world.source_facts),
        "ideal-atomic-entry": current,
    }[policy]
    if not allowed:
        return "REFUSED"
    # One indivisible modeled decision: charge before effect, retain unknown.
    # A real authority must supply this order, not merely sign a prior read.
    ledger[RESOURCE] = "UNKNOWN" if action == "enter_unknown" else "COMPLETE"
    world.effects += 1
    world.unsafe_entries += int(not current)
    return "ABSTRACT_ENTRY_" + ledger[RESOURCE]


def run_schedule(policy, events):
    world, trace = World(), []
    for event in events:
        trace.append(transition(world, policy, event))
    return world, trace


def compare(policy, *, schedule_limit=None):
    if policy not in POLICIES or (schedule_limit is not None and
            (type(schedule_limit) is not int or schedule_limit < 0)):
        raise ValueError("invalid finite selection")
    selected = tuple(schedules())
    rows = selected if schedule_limit is None else selected[:schedule_limit]
    effects = unsafe = repeated = unknown = transitions = 0
    examples = []
    for label, events in rows:
        world, trace = run_schedule(policy, events)
        transitions += len(events)
        effects += world.effects
        unsafe += world.unsafe_entries
        repeated += int(world.effects > 1)
        unknown += world.unknown_replays
        if world.unsafe_entries or world.effects > 1:
            examples.append({"scenario": label, "events": events, "trace": trace,
                             "effects": world.effects, "unsafe_entries": world.unsafe_entries})
    return {"policy": policy, "domain": "SELECTED_FINITE_SHUFFLES_ONLY", "complete": len(rows) == len(selected),
        "selected_schedules": len(selected), "executed_schedules": len(rows), "transitions": transitions,
        "abstract_effects": effects, "unsafe_entries": unsafe, "repeated_effect_schedules": repeated,
        "retained_unknown_replays": unknown, "counterexamples": examples,
        "external_facts": "IDEAL_PREMISE", "nonrollback_ledger_and_fence": "IDEAL_PREMISE",
        "signature_mathematics": "NOT_PERFORMED", "recovery_action": "NONE",
        "application": "NO-GO", "core": "NO-GO"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", choices=POLICIES, default="ideal-atomic-entry")
    parser.add_argument("--schedule-limit", type=int)
    arguments = parser.parse_args()
    try:
        result = compare(arguments.policy, schedule_limit=arguments.schedule_limit)
    except ValueError:
        parser.error("invalid finite schedule limit")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
