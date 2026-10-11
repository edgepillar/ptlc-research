#!/usr/bin/env python3
"""Compare fresh immutable-source VM account windows with public diagnostics.

Original command evidence is retained privately. Complete selected height
coverage cannot establish admitted history, execution, authority or recovery.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import nom_account_history as history, nom_authority_contract as authority
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_vm_path as vm, qualify_nom_vm_openings as roles
from scripts.generate_nom_account_history import PROFILE, FIXTURE, BOUNDARY, corpus, query, packet
from scripts.generate_nom_vm_openings import KINDS, selection
from scripts.nom_native_command import private_create

MANIFEST = "compatibility/nom_account_history_manifest.json"
SELECTED = (FIXTURE, "offline_session/nom_account_history.py", "scripts/generate_nom_account_history.py",
            "scripts/qualify_nom_account_history.py", "tests/test_nom_account_history.py")
COUNTS = {"legs": 2, "source_case_projections": 10, "source_records_before_projection": 32,
          "auxiliary_windows": 20, "unselected_authority_grammars": 4, "source_tests_including_parents": 58}


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=vm.unique_object)
    if (manifest["schema"] != "zenon-nom-account-history-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != authority.CORE_COMMIT or manifest["expected_counts"] != COUNTS
            or set(manifest["input_sha256"]) != set(SELECTED)
            or fixture["schema"] != "zenon-nom-account-history-corpus-v1" or fixture["profile"] != PROFILE
            or fixture["core_commit"] != authority.CORE_COMMIT or fixture["boundary"] != BOUNDARY
            or set(fixture["source_cases"]) != set(KINDS)
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("selected account history subject changed")
    measured = {name: vm.digest(root / name) for name in (MANIFEST,
                *manifest["input_sha256"], *manifest["preserved_file_sha256"])}
    for name, expected in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items():
        if measured[name] != expected:
            raise ValueError("selected or preserved history input changed")
    return manifest, fixture, measured


def check_result(result, kind):
    frozen = roles.check_result(result["vm_opening_result"], kind)
    if (result["auxiliary_authority_fact"] != "NONE" or result["history_currentness"] != "UNFILLED"
            or result["history_opening"] != "BOUND_UNAUTHENTICATED_PAYLOAD"
            or (result["recovery_action"], result["application"], result["core"], result["terminal_outcome"])
               != ("NONE", "NO-GO", "NO-GO", "NOT_ESTABLISHED")):
        raise ValueError("history comparison crossed admission boundary")
    output = {}
    for leg, reports in result["history_legs"].items():
        for role in history.ACCOUNTS:
            report = reports[role]
            if (any(report[k] != "MATCH" for k in ("selected_height_coverage", "ordered_previous_links", "ordered_acknowledgements",
                    "selected_head", "selected_account_profile"))
                    or report["missing_heights"] or report["outside_window_indices"] or report["duplicate_heights"]
                    or any(item != "MATCH" for item in report["required_roles"].values())
                    or report["prior_anchor"] != ("MATCH" if role == "contract" else "PRIOR_FRONTIER_UNSELECTED")
                    or any(header["advertised_hash"] != "MATCH" or header["candidate_membership"] != "NOT_INCLUDED_CLAIM"
                           for header in report["headers"])):
                raise ValueError("source history comparison differs")
        contract, recipient = reports["contract"], reports["recipient"]
        children = contract["descendant_placement"]
        if (children["unassigned_send_indices"] or any(item["preceding_children"] != "MATCH" for item in children["receives"])
                or contract["record_count"] != (4 if kind == "unlock-at-expiry-then-reclaim" else 3)
                or recipient["record_count"] != (2 if kind == "raw-receive-replay-needs-verifier" else 1)
                or contract["repeated_receive_claims"]
                or len(recipient["repeated_receive_claims"]) != int(kind == "raw-receive-replay-needs-verifier")
                or reports["selected_unlock_frontier"] != ("DIFFERENT_ACCOUNT_SELECTION" if kind.startswith("proxy-")
                                                          else "OUTSIDE_SELECTED_WINDOW")):
            raise ValueError("source history boundary differs")
        output[leg] = {"contract_records": contract["record_count"], "recipient_records": recipient["record_count"],
            "contract_height_coverage": contract["selected_height_coverage"], "children": "MATCH",
            "repeated_receive_claims": len(recipient["repeated_receive_claims"]),
            "selected_unlock_frontier": reports["selected_unlock_frontier"], "frozen_role_comparison": frozen[leg]}
    return output


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root)
    vm.core_state(checkout, manifest)
    tool_hash = vm.digest(go)
    parent = evidence_parent or root / ".research-cache/nom-account-history-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="account-history-", dir=parent))
    record = {"schema": "zenon-nom-account-history-result-v1", "profile": PROFILE,
        "core_commit": authority.CORE_COMMIT, "outcome": "UNKNOWN", **BOUNDARY,
        "input_sha256": before, "go_executable_sha256": tool_hash,
        "stream_custody": "Original private command streams; hosted private custody may be ephemeral",
        "overlay_vet": "NOT_PERFORMED; preserved synthetic overlay paths are unavailable to Go 1.23 vet"}
    try:
        source = vm.qualify(checkout, go, root=root, evidence_parent=evidence / "source")
        children = list((evidence / "source").glob("composed-vm-*"))
        if len(children) != 1 or json.loads((children[0] / "outcome.json").read_text("ascii")) != source:
            raise ValueError("fresh original VM command custody differs")
        raw = (children[0] / "core-wire.stdout").read_bytes()
        _, vm_fixture, _ = vm.inputs(root)
        names = vm.expected_tests(vm_fixture)["github.com/zenon-network/go-zenon/vm"]
        if vm.selected_outcome(raw, {"github.com/zenon-network/go-zenon/vm": names}) != 33:
            raise ValueError("incomplete original VM outcomes")
        records = vm.collect_vm_records(raw, vm_fixture, json.loads((root / vm.FUNDING).read_text("ascii")))
        if fixture != corpus(records):
            raise ValueError("fresh source windows differ from public corpus")
        selected, comparisons = selection(root), {}
        for kind, case in fixture["source_cases"].items():
            expected = query(case, selected)
            comparisons[kind] = check_result(history.inspect_history(expected, packet(expected, case["history"])), kind)
        with private_create(evidence / "comparisons.json") as out:
            out.write((json.dumps(comparisons, sort_keys=True) + "\n").encode("ascii"))
        vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != vm.digest(go):
            raise ValueError("selected history subject changed during qualification")
        record.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=source,
            original_vm_stream_sha256=hashlib.sha256(raw).hexdigest(), comparisons=comparisons,
            fresh_projection="MATCH; 20 SELECTED WINDOWS FROM ALL 32 ACTUAL VM RECORDS",
            intermediate_receive="RECLAIM WINDOW INCLUDES ACTUAL REFUSED UNLOCK RECEIVE; FROZEN ROLE CONFLICT RETAINED",
            repeated_receive="RAW REPLAY SHARES FROM-HASH; SOURCE VERIFIER ADMISSION REMAINS SEPARATE",
            recipient_frontier="SELECTED UNLOCK SEND REMAINS OUTSIDE ACTUAL RECEIPT WINDOW OR ON A DIFFERENT ACCOUNT")
        return record
    except BaseException:
        record["outcome"] = "FAILED_OR_INCOMPLETE"
        raise
    finally:
        with private_create(evidence / "outcome.json") as out:
            out.write((json.dumps(record, sort_keys=True) + "\n").encode("ascii"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--go", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(qualify(args.checkout, args.go), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, WorkerError):
        print("FAIL: account history; preserve original private evidence", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
