#!/usr/bin/env python3
"""Compare fresh pinned-source VM projections with query-bound public openings.

This preserves original command streams and actual patch handoffs privately.
Neither an exact reproduction nor a matching structural role supplies source
authority, account admission, nonrollback custody or recovery authorization.
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
from offline_session import nom_authority_contract as authority, nom_vm_openings as opening
from offline_session.public_worker import WorkerError
from scripts.generate_nom_vm_openings import PROFILE, FIXTURE, KINDS, BOUNDARY, corpus, selection, packet
from scripts.nom_native_command import private_create
from scripts import qualify_nom_vm_path as vm

MANIFEST = "compatibility/nom_vm_openings_manifest.json"
SELECTED = (FIXTURE, "offline_session/nom_vm_openings.py", "scripts/generate_nom_vm_openings.py",
            "scripts/qualify_nom_vm_openings.py", "tests/test_nom_vm_openings.py")
COUNTS = {"legs": 2, "source_case_projections": 10, "new_opening_grammars": 4,
          "unselected_grammars": 4, "source_tests_including_parents": 58}


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=vm.unique_object)
    if (manifest["schema"] != "zenon-nom-vm-openings-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != authority.CORE_COMMIT or manifest["expected_counts"] != COUNTS
            or set(manifest["input_sha256"]) != set(SELECTED)
            or fixture["schema"] != "zenon-nom-vm-public-openings-corpus-v1"
            or fixture["profile"] != PROFILE or fixture["core_commit"] != authority.CORE_COMMIT
            or fixture["boundary"] != BOUNDARY or set(fixture["source_cases"]) != set(KINDS)
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("selected VM opening subject changed")
    measured = {name: vm.digest(root / name) for name in (MANIFEST,
                *manifest["input_sha256"], *manifest["preserved_file_sha256"])}
    for name, expected in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items():
        if measured[name] != expected:
            raise ValueError("selected or preserved opening input changed")
    return manifest, fixture, measured


def check_result(result, kind):
    if ((result["recovery_action"], result["application"], result["core"], result["terminal_outcome"])
            != ("NONE", "NO-GO", "NO-GO", "NOT_ESTABLISHED") or len(result["unselected_profiles"]) != 4
            or any(result[k] != "NOT_PERFORMED" for k in ("account_admission", "vm_execution", "proof_verification",
                   "source_authentication", "durable_retention", "network_provisioning"))
            or any(result[k] != "UNFILLED" for k in ("source_currentness", "canonicality", "finality", "restore_fence"))
            or result["atomic_entry"] != "NOT_IMPLEMENTED" or result["replenish_work"] is not False
            or result["replacement_original_allowed"] is not False):
        raise ValueError("comparison crossed an unfilled admission boundary")
    summary = {}
    for leg, roles in result["legs"].items():
        base_leg = result["base_opening_result"]["comparisons"]["funding_send"]["legs"][leg]
        if any(base_leg[k] != "MATCH" for k in ("advertised_hash", "create_terms", "send_derived_entry")):
            raise ValueError("original created funding selection differs")
        reclaim = kind == "unlock-at-expiry-then-reclaim"
        diff = "DIFFERS_FROM_SELECTION"
        expected = {"method": "Reclaim" if reclaim else "ProxyUnlock" if kind.startswith("proxy-") else "Unlock",
            "witness": diff if reclaim else "MATCH", "payout_terms": diff if reclaim else "MATCH",
            "parent_child": diff if reclaim else "MATCH", "receipt_fields": diff if reclaim else "MATCH",
            "recipient_continuity": "PRIOR_RECIPIENT_FRONTIER_UNSELECTED" if reclaim or kind.startswith("proxy-") else diff}
        actual = {"method": roles["unlock_send"]["method_claim"],
            "witness": roles["unlock_send"]["retained_inner_witness_and_call"],
            "payout_terms": roles["contract_payout"]["fixed_asset_and_recipient"],
            "parent_child": roles["contract_payout"]["parent_child_linkage"],
            "receipt_fields": roles["recipient_receipt"]["receive_fields"],
            "recipient_continuity": roles["recipient_receipt"]["recipient_account_continuity"]}
        if actual != expected or any(roles["contract_receive"][k] != "MATCH" for k in
            ("funding_linkage", "funding_acknowledgement_order", "funding_receive_fields",
             "receive_fields_and_status_claim", "send_linkage", "send_acknowledgement_order")):
            raise ValueError("source role comparison differs")
        for role in ("unlock_send", "contract_payout", "recipient_receipt"):
            if roles[role]["advertised_hash"] != "MATCH" or roles[role]["candidate_membership"] != "NOT_INCLUDED_CLAIM":
                raise ValueError("source block or selected branch differs")
            if not reclaim and roles[role]["known_acknowledgement"] != diff:
                raise ValueError("numbered ledger stubs were treated as selected momenta")
        if roles["recipient_receipt"]["payout_linkage"] != "MATCH" or roles["recipient_receipt"]["received_marker_proof"] != "ABSENT":
            raise ValueError("source recipient linkage or proof boundary differs")
        summary[leg] = actual
    return summary


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root)
    vm.core_state(checkout, manifest)
    tool_hash = vm.digest(go)
    parent = evidence_parent or root / ".research-cache/nom-vm-openings-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="vm-openings-", dir=parent))
    record = {"schema": "zenon-nom-vm-openings-result-v1", "profile": PROFILE,
        "core_commit": authority.CORE_COMMIT, "outcome": "UNKNOWN", **BOUNDARY,
        "input_sha256": before, "go_executable_sha256": tool_hash,
        "stream_custody": "Original private command streams and patches; hosted private custody may be ephemeral",
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
            raise ValueError("fresh source projection differs from selected public corpus")
        selected = selection(root)
        query = authority.read_query(**selected)
        results = {}
        for kind, legs in fixture["source_cases"].items():
            claim_wire, base_wire, opening_wire = packet(query, selected, legs)
            result = opening.inspect_vm_openings(query, claim_wire, base_wire, opening_wire)
            results[kind] = check_result(result, kind)
        with private_create(evidence / "comparisons.json") as out:
            out.write((json.dumps(results, sort_keys=True) + "\n").encode("ascii"))
        vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != vm.digest(go):
            raise ValueError("selected opening subject changed during qualification")
        record.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=source,
            original_vm_stream_sha256=hashlib.sha256(raw).hexdigest(), comparisons=results,
            fresh_projection="MATCH; 10 SELECTED CASES FROM ALL 32 ACTUAL VM RECORDS",
            recipient_frontier="DIRECT RECEIPTS DIFFER FROM SELECTED UNLOCK ACCOUNT CONTINUITY",
            selected_momentum="NUMBERED VM STUBS DO NOT MATCH THE PRESERVED MOMENTUM CANDIDATE",
            replay_boundary="FROM-HASH LINKAGE IS NOT DUPLICATE RECEIVE ADMISSION")
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
        print("FAIL: VM evidence openings; preserve original private evidence", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
