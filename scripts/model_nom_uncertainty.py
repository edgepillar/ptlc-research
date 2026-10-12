#!/usr/bin/env python3
"""Selected finite uncertainty policies; abstract effects never run a worker."""

import argparse
import json

from offline_session import nom_uncertainty as hold
from scripts.model_nom_authority import shuffles


POLICIES = ("forget-on-unavailable", "release-on-supported", "retain-hold")


def schedules():
    for case in hold.CASES:
        stream = (("refusal", case), ("unavailable", None), ("complete", None))
        for events in shuffles(stream, (("enter", None), ("enter", None))):
            yield case + "/ordered-updates", 1, events
        yield case + "/exact-claim-replay", 1, (stream[0], stream[0], stream[1], stream[1], ("enter", None))
        yield case + "/coherent-old-copy", 1, (*stream, ("restore", None), ("enter", None))
        for event in (stream[1], stream[2]):
            yield case + "/exhausted-work", 16, (stream[0], event, ("enter", None), ("enter", None))


def run_schedule(policy, fixture, charged, events):
    """Compare selected policy outcomes while retaining actual pure hold bytes."""
    if policy not in POLICIES or type(charged) is not int or not 0 <= charged <= 16:
        raise ValueError("invalid selected uncertainty policy")
    from scripts.qualify_nom_uncertainty import selected_hold
    initial = selected_hold(charged=charged)
    retained = initial
    held, work, effects, erased, restore_losses = True, charged, 0, 0, 0
    trace = []
    for action, value in events:
        if action == "refusal":
            retained = hold.retain_claim(retained, bytes.fromhex(fixture["refusals_hex"][value]), kind="refusal")
            held = True
        elif action in ("unavailable", "complete"):
            retained = hold.retain_claim(retained, bytes.fromhex(fixture["source_claims_hex"][action]), kind="source")
            if policy == "forget-on-unavailable" and action == "unavailable":
                erased += work
                work, held = 0, False
            elif policy == "release-on-supported" and action == "complete":
                held = False
        elif action == "restore":
            restore_losses += int(retained.canonical_bytes != initial.canonical_bytes)
            retained = initial
            # Even a coherent old copy has no recovery capability. This only
            # demonstrates that in-memory hashes cannot prove newer custody.
            hold.compare_hold(initial, initial.canonical_bytes)
        elif action == "enter":
            if not held and work < 16:
                work += 1
                effects += 1
        else:
            raise ValueError("unknown selected uncertainty event")
        trace.append({"event": action, "abstract_held": held, "abstract_charged_work": work,
            "abstract_effects": effects, "reference_recovery_action": retained.review()["recovery_action"]})
    return {"trace": trace, "abstract_effects": effects, "unsafe_entries": effects,
        "erased_charges": erased, "coherent_restore_losses": restore_losses,
        "retained_selection_hex": retained.as_dict()["selection_hex"], "reference": retained.review()}


def compare(policy, fixture, *, schedule_limit=None):
    if policy not in POLICIES or (schedule_limit is not None and
            (type(schedule_limit) is not int or schedule_limit < 0)):
        raise ValueError("invalid selected finite limit")
    selected = tuple(schedules())
    rows = selected if schedule_limit is None else selected[:schedule_limit]
    examples = []
    totals = dict(transitions=0, abstract_effects=0, unsafe_entries=0, erased_charges=0, coherent_restore_losses=0)
    for label, charged, events in rows:
        result = run_schedule(policy, fixture, charged, events)
        totals["transitions"] += len(events)
        for key in tuple(totals)[1:]:
            totals[key] += result[key]
        if result["abstract_effects"] or result["erased_charges"]:
            examples.append({"scenario": label, "initial_charged_work": charged, "events": events, **result})
    return {"policy": policy, "domain": "SELECTED_FINITE_ORDERINGS_ONLY",
        "selected_schedules": len(selected), "executed_schedules": len(rows),
        "complete": len(rows) == len(selected), **totals, "counterexamples": examples,
        "source_authentication": "NOT_PERFORMED", "restore_fence": "UNFILLED",
        "signature_mathematics": "NOT_PERFORMED", "journal_composition": "NOT_PERFORMED",
        "recovery_action": "NONE", "application": "NO-GO", "core": "NO-GO"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", choices=POLICIES, default="retain-hold")
    parser.add_argument("--schedule-limit", type=int)
    args = parser.parse_args()
    from scripts.qualify_nom_uncertainty import inputs
    try:
        result = compare(args.policy, inputs()[1], schedule_limit=args.schedule_limit)
    except ValueError:
        parser.error("invalid selected uncertainty comparison")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
