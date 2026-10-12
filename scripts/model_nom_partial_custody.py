#!/usr/bin/env python3
"""Finite absent-original policies, without a journal, worker or reconstruction."""

import argparse
import itertools
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import nom_partial_custody as hold


POLICIES = ("fill-from-fixture", "equate-public-result-with-original", "retain-partial-hold")


def compare(policy, fixture, *, schedule_limit=None):
    from scripts.qualify_nom_partial_custody import CUTS, selected_hold, source_claim
    if policy not in POLICIES or (schedule_limit is not None and
            (type(schedule_limit) is not int or schedule_limit < 0)):
        raise ValueError("invalid partial custody policy or schedule limit")
    schedules = tuple(itertools.product(CUTS, (1, 16), tuple(itertools.permutations(("refusal", "supported", "unavailable")))))
    selected = schedules if schedule_limit is None else schedules[:schedule_limit]
    invented, entries, restore_losses, transitions = 0, 0, 0, 0
    for cut, charged, events in selected:
        initial = selected_hold(cut, charged=charged)
        retained = initial
        for event in events:
            wire = (bytes.fromhex(fixture["refusals_hex"]["after-one-actual-pop"]) if event == "refusal"
                else source_claim(initial, event))
            kind = "refusal" if event == "refusal" else "source"
            retained = hold.retain_claim(retained, wire, kind=kind)
            if hold.retain_claim(retained, wire, kind=kind) is not retained:
                raise ValueError("exact partial custody replay changed retained bytes")
            transitions += 1
            if event == "supported" and initial.selection()["original_long_hex"] is None:
                supply = policy == POLICIES[0] or (policy == POLICIES[1]
                    and initial.selection()["recovered_long_signature_hex"] is not None)
                invented += int(supply)
                entries += int(supply and charged < 16)
            if retained.selection() != initial.selection() or retained.review()["recovery_action"] != "NONE":
                raise ValueError("reference partial custody changed")
        # Exact comparison rejects loss against the later independently kept
        # copy, but a coherent old object and old bytes still pass their own test.
        try:
            hold.compare_hold(retained, initial.canonical_bytes)
        except hold.PartialCustodyRefused:
            pass
        else:
            raise ValueError("later claim prefix was lost")
        hold.compare_hold(initial, initial.canonical_bytes)
        restore_losses += 1
        transitions += 2
    return {"policy": policy, "complete": len(selected) == len(schedules),
        "selected_schedules": len(selected), "required_schedules": len(schedules), "transitions": transitions,
        "invented_originals": invented, "new_worker_entries": entries, "coherent_old_copy_losses": restore_losses,
        "effects": "ABSTRACT ONLY; NO WORKER OR ORIGINAL CONSTRUCTION", "unbounded_proof": "NOT_ESTABLISHED"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--schedule-limit", type=int)
    args = parser.parse_args()
    from scripts.qualify_nom_partial_custody import FIXTURE
    fixture = json.loads((ROOT / FIXTURE).read_text("ascii"))
    rows = [compare(policy, fixture, schedule_limit=args.schedule_limit) for policy in POLICIES]
    print(json.dumps(rows, sort_keys=True))
    return 0 if all(row["complete"] for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
