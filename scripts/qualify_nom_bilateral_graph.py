#!/usr/bin/env python3
"""Compare a new bilateral public graph with the unchanged source offline.

Raw VM operations and two public verifier entry points are explicitly selected.
They do not perform supervisor/Plasma, pool or momentum admission, authenticate
ledger facts, or authorize application signing or journal composition.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_wire import account_block_hash, encode_call
from offline_session.pr138 import CORE_COMMIT, CONTRACT_HEX, unlock_message
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_account_context as prior, qualify_nom_vm_path as vm
from scripts.generate_nom_bilateral_graph import PROFILE, INPUT, COMPLETIONS, FIXTURE, BOUNDARY, CASES, HEIGHT, inputs as public_inputs, corpus, tag
from scripts.nom_native_command import private_create, run

MANIFEST = "compatibility/nom_bilateral_graph_manifest.json"
DRIVER = "compatibility/nom_bilateral_graph_test.go.txt"
RUST = "qualification/tests/nom_bilateral_graph.rs"
TEST = "TestResearchNoMBilateralGraph"
PACKAGE = "github.com/zenon-network/go-zenon/vm"
PREFIX = "PTLC_RESEARCH_BILATERAL_RECORD "
SELECTED = (INPUT, COMPLETIONS, FIXTURE, DRIVER, RUST, "scripts/generate_nom_bilateral_graph.py",
            "scripts/qualify_nom_bilateral_graph.py", "tests/test_nom_bilateral_graph.py")
COUNTS = {"parties": 2, "shared_contract_accounts": 1, "graph_cases": 4, "graph_steps": 46,
          "verifier_refusal_controls": 24, "graph_tests_including_parent": 5,
          "preserved_source_tests_including_parents": 270, "total_source_tests_including_parents": 275}
BLOCK_FIELDS = {"hash_hex", "computed_hash_hex", "wire_hex", "wire_sha256", "roundtrip_wire_hex",
                "public_key_hex", "signature_hex", "children", "changes_hash_hex", "semantic_previous", "block"}
STEP_FIELDS = {"label", "block", "method_error", "checks", "before_frontier", "after_frontier",
               "before_patch_hex", "after_vm_patch_hex", "after_adopt_patch_hex", "before_patch_sha256",
               "after_vm_patch_sha256", "after_adopt_patch_sha256", "before_balances", "after_balances",
               "before_received_marker", "after_received_marker", "before_mailbox_head", "after_mailbox_head", "confirmation_height"}


def expected_tests():
    return {PACKAGE: {TEST, *(TEST + "/" + kind for kind in CASES)}}


def hh(hash_hex="00" * 32, height="0"):
    return {"hash_hex": hash_hex, "height": height}


def bounded(value, maximum=8192):
    return prior.auth.byte_value(value, maximum=maximum)


def validate_block(r):
    if type(r) is not dict or set(r) != BLOCK_FIELDS:
        raise ValueError("unselected bilateral block fields")
    b = r["block"]
    computed = account_block_hash(b)
    if r["computed_hash_hex"] != computed or r["hash_hex"] != computed:
        raise ValueError("actual complete account hash differs")
    w = bounded(r["wire_hex"])
    if not w or r["roundtrip_wire_hex"] != r["wire_hex"] or hashlib.sha256(w).hexdigest() != r["wire_sha256"]:
        raise ValueError("exact public block bytes differ")
    prior.auth.fixed_hex(r["changes_hash_hex"], 32)
    if type(r["children"]) is not list or len(r["children"]) > 1:
        raise ValueError("unselected descendants")
    for child in r["children"]: validate_block(child)
    if b["descendant_hashes_hex"] != [c["hash_hex"] for c in r["children"]]:
        raise ValueError("advertised child differs from actual child hash")
    prev = r["children"][0]["semantic_previous"] if r["children"] else hh(b["previous_hash_hex"], str(int(b["height"]) - 1))
    if r["semantic_previous"] != prev:
        raise ValueError("source semantic predecessor differs")
    if b["address_hex"] == CONTRACT_HEX:
        if r["public_key_hex"] or r["signature_hex"]: raise ValueError("embedded authorization must be empty")
    else:
        pub = prior.auth.byte_value(r["public_key_hex"], 32)
        prior.auth.byte_value(r["signature_hex"], 64)
        if b["address_hex"] != "00" + hashlib.sha3_256(pub).hexdigest()[:38]:
            raise ValueError("outer public key does not select this user")
    return r


def labels(kind):
    seq = ["long-funding", "short-funding", "long-create", "short-create"]
    if kind != "complete": seq += ["refused-short-send", "refused-short-receive"]
    return seq + ["short-unlock-send", "short-unlock-receive", "short-receipt", "long-unlock-send", "long-unlock-receive", "long-receipt"]


def validate_record(record, selected, completed, old):
    if (type(record) is not dict or set(record) != {"schema", "id", "trace", "controls", "final_balances", "entries_present"}
            or record["schema"] != "zenon-nom-bilateral-record-v1" or record["id"] not in CASES
            or record["entries_present"] is not False):
        raise ValueError("unselected bilateral source record")
    kind = record["id"]; terms = selected["terms"]
    addresses = {role: terms[role + "_address_hex"] for role in ("alice", "bob")}
    addresses["contract"] = CONTRACT_HEX
    roles = {a: role for role, a in addresses.items()}
    amounts = {leg: int(terms[leg]["amount"]) for leg in ("long", "short")}
    balances = {role: {leg: "0" for leg in amounts} for role in addresses}
    balances["alice"]["long"] = str(2 * amounts["long"]); balances["bob"]["short"] = str(2 * amounts["short"])
    frontiers = {a: {"identifier": hh(), "wire_hex": ""} for a in roles}
    patches = {}; blocks = {}; payouts = {}
    if type(record["trace"]) is not list or [s.get("label") for s in record["trace"]] != labels(kind):
        raise ValueError("complete ordered bilateral trace required")
    for s in record["trace"]:
        if type(s) is not dict or set(s) != STEP_FIELDS: raise ValueError("unselected step fields")
        name = s["label"]; r = validate_block(s["block"]); b = r["block"]; a = b["address_hex"]
        if a not in roles or s["checks"] != {"structural": "PASS", "transaction": "PASS"}:
            raise ValueError("unselected step account or verifier result")
        if (s["before_frontier"] != frontiers[a] or r["semantic_previous"] != frontiers[a]["identifier"]
                or s["before_balances"] != balances):
            raise ValueError("actual shared predecessor or accounting discontinuity")
        for field in ("before", "after_vm", "after_adopt"):
            p = bounded(s[field + "_patch_hex"], 65536)
            if hashlib.sha256(p).hexdigest() != s[field + "_patch_sha256"]:
                raise ValueError("retained memory patch digest differs")
        if a in patches and s["before_patch_hex"] != patches[a]:
            raise ValueError("same account memory state discontinuity")
        if s["after_adopt_patch_hex"] == s["after_vm_patch_hex"]:
            raise ValueError("selected frontier adoption is missing")
        if b["version"] != "1" or b["chain_id"] != terms["chain_id"] or b["fused_plasma"] != "0" or b["difficulty"] != "0":
            raise ValueError("selected raw VM header differs")
        index = 0 if name.endswith("funding") or name.endswith("create") else (2 if name.startswith("long-") else 1)
        if (b["momentum_hash_hex"], b["momentum_height"]) != (tag("momentum-" + str(index)), str(HEIGHT + index)):
            raise ValueError("synthetic acknowledgement selection differs")
        expected_error = "NONE"
        if name == "refused-short-receive":
            expected_error = "ErrPermissionDenied" if kind == "wrong-caller-before-valid" else "ErrInvalidPointSignature"
        if s["method_error"] != expected_error: raise ValueError("inner witness or caller refusal differs")
        if type(s["before_received_marker"]) is not bool or s["before_received_marker"]:
            raise ValueError("operation was already received before execution")
        received = b["block_type"] == "3"
        if type(s["after_received_marker"]) is not bool or s["after_received_marker"] != received:
            raise ValueError("actual marker selection differs")
        if name.endswith("funding"):
            leg = name.split("-")[0]
            if b != selected["fundings"][leg]["block"] or r["hash_hex"] != terms[leg]["entry_id_hex"]:
                raise ValueError("executed new funding differs")
            balances[roles[a]][leg] = str(int(balances[roles[a]][leg]) - amounts[leg])
        elif name.endswith("send"):
            leg = "short" if name.startswith("refused") else name.split("-")[0]
            caller = addresses["bob"] if name == "refused-short-send" and kind == "wrong-caller-before-valid" else addresses[terms[leg]["recipient"]]
            witness = completed[leg + "_signature_hex"]
            if name == "refused-short-send":
                if kind == "old-inner-before-valid": witness = old["short_signature_hex"]
                elif kind == "cross-leg-inner-before-valid": witness = completed["long_signature_hex"]
            call = {"method": "Unlock", "entry_id_hex": terms[leg]["entry_id_hex"], "witness_hex": witness}
            if (a != caller or b["block_type"] != "2" or b["to_address_hex"] != CONTRACT_HEX
                    or b["amount"] != "0" or b["token_standard_hex"] != "00" * 10 or b["data_hex"] != encode_call(call).hex()):
                raise ValueError("selected original Unlock differs")
        elif name.endswith("create") or name.endswith("receive"):
            leg = name.split("-")[0] if not name.startswith("refused") else "short"
            send_label = leg + "-funding" if name.endswith("create") else name[:-7] + "send"
            send = blocks[send_label]
            if (a != CONTRACT_HEX or b["block_type"] != "5" or b["from_block_hash_hex"] != send["hash_hex"]
                    or b["data_hex"] != ("0000000000000001" if expected_error == "NONE" else "0000000000000002")
                    or s["confirmation_height"] != b["momentum_height"]):
                raise ValueError("actual contract batch differs")
            head = {"address_hex": send["block"]["address_hex"], "identifier": hh(send["hash_hex"], send["block"]["height"])}
            if s["before_mailbox_head"] != head or s["after_mailbox_head"] is not None:
                raise ValueError("actual shared sequencer differs")
            want_children = 1 if name.endswith("unlock-receive") else 0
            if len(r["children"]) != want_children: raise ValueError("refused or successful payout count differs")
            previous, height = frontiers[a]["identifier"]["hash_hex"], int(frontiers[a]["identifier"]["height"]) + 1
            if name.endswith("create"): balances["contract"][leg] = str(int(balances["contract"][leg]) + amounts[leg])
            for child in r["children"]:
                c = child["block"]
                if (c["block_type"] != "4" or c["address_hex"] != CONTRACT_HEX or c["to_address_hex"] != addresses[terms[leg]["recipient"]]
                        or c["previous_hash_hex"] != previous or c["height"] != str(height) or c["amount"] != terms[leg]["amount"]
                        or c["token_standard_hex"] != terms[leg]["token_standard_hex"]
                        or (c["momentum_hash_hex"], c["momentum_height"]) != (b["momentum_hash_hex"], b["momentum_height"])):
                    raise ValueError("actual fixed payout ancestry or asset differs")
                previous, height = child["hash_hex"], height + 1
                payouts[leg] = child; balances["contract"][leg] = str(int(balances["contract"][leg]) - amounts[leg])
            if b["previous_hash_hex"] != previous or b["height"] != str(height):
                raise ValueError("actual batch parent ancestry differs")
        elif name.endswith("receipt"):
            leg = name.split("-")[0]; child = payouts[leg]
            if (b["block_type"] != "3" or b["from_block_hash_hex"] != child["hash_hex"]
                    or a != child["block"]["to_address_hex"] or b["amount"] != "0" or b["data_hex"]):
                raise ValueError("actual receipt differs from fixed payout")
            balances[roles[a]][leg] = str(int(balances[roles[a]][leg]) + amounts[leg])
        else: raise ValueError("unselected graph role")
        if a != CONTRACT_HEX:
            if b["height"] != str(int(frontiers[a]["identifier"]["height"]) + 1): raise ValueError("user account height discontinuity")
            if s["before_mailbox_head"] is not None or s["after_mailbox_head"] is not None: raise ValueError("user mailbox unselected")
        if s["after_balances"] != balances: raise ValueError("actual source balance differs")
        frontiers[a] = {"identifier": hh(r["hash_hex"], b["height"]), "wire_hex": r["wire_hex"]}
        if s["after_frontier"] != frontiers[a]: raise ValueError("actual adopted original differs")
        patches[a] = s["after_adopt_patch_hex"]; blocks[name] = r
    if record["final_balances"] != balances: raise ValueError("final bilateral accounting differs")
    for leg, amount in amounts.items():
        if sum(int(balances[role][leg]) for role in balances) != 2 * amount or balances["contract"][leg] != "0":
            raise ValueError("completed graph does not conserve each selected token")
    expected = ["wrong-account-predecessor", "short-wrong-receiver", "short-exact-replay", "short-new-receipt-same-payout", "long-exact-replay", "long-new-receipt-same-payout"]
    if type(record["controls"]) is not list or [c.get("id") for c in record["controls"]] != expected:
        raise ValueError("complete selected refusal controls required")
    for c in record["controls"]:
        if type(c) is not dict or set(c) != {"id", "block", "checks", "frontier", "received_marker"}: raise ValueError("unselected control fields")
        r = validate_block(c["block"]); name = c["id"]; b = r["block"]
        error = ("ErrABPreviousMissing" if name == expected[0] else "ErrABFromBlockReceiverMismatch" if name == expected[1]
                 else "ErrABPrevHasCementedOnTop" if name.endswith("exact-replay") else "ErrABFromBlockAlreadyReceived")
        tx = error if name == expected[0] or name.endswith("exact-replay") else "PASS"
        if c["checks"] != {"structural": error, "transaction": tx}: raise ValueError("selected refusal differs")
        if name == expected[0]:
            if b["previous_hash_hex"] != blocks["short-funding"]["hash_hex"] or c["frontier"] != {"identifier":hh(blocks["long-funding"]["hash_hex"],"1"),"wire_hex":blocks["long-funding"]["wire_hex"]}:
                raise ValueError("wrong account predecessor control differs")
        elif name == expected[1]:
            if b["address_hex"] != addresses["bob"] or b["from_block_hash_hex"] != payouts["short"]["hash_hex"]:
                raise ValueError("wrong receiver control differs")
        else:
            leg = name.split("-")[0]; original = blocks[leg + "-receipt"]
            if c["frontier"] != {"identifier":hh(original["hash_hex"],original["block"]["height"]),"wire_hex":original["wire_hex"]} or c["received_marker"] is not True:
                raise ValueError("actual post-receipt state differs")
            if name.endswith("exact-replay") and r != original: raise ValueError("exact replay replaced the original")
            if name.endswith("same-payout") and (r["semantic_previous"] != c["frontier"]["identifier"] or b["from_block_hash_hex"] != original["block"]["from_block_hash_hex"] or r["wire_hex"] == original["wire_hex"]):
                raise ValueError("new receipt is not a distinct refused successor")
    return record


def validate_records(records, selected, completed, old):
    if type(records) is not dict or set(records) != set(CASES): raise ValueError("complete bilateral source selection required")
    for name in CASES:
        if records[name].get("id") != name: raise ValueError("case identity differs")
        validate_record(records[name], selected, completed, old)
    return records


def collect_records(wire, selected, completed, old):
    records, pending = {}, {}
    for line in wire.splitlines():
        event = json.loads(line, object_pairs_hook=vm.unique_object)
        if type(event) is not dict or event.get("Package") != PACKAGE: raise ValueError("unselected native package")
        output, name = event.get("Output", ""), event.get("Test")
        if type(output) is not str: raise ValueError("invalid native output fragment")
        if pending and event.get("Action") == "output" and name not in pending: raise ValueError("interleaved source record")
        if PREFIX in output:
            if (output.count(PREFIX) != 1 or name in pending or event.get("Action") != "output"
                    or re.match(r"^    zz_research_nom_bilateral_graph_test.go:[0-9]+: " + PREFIX, output) is None):
                raise ValueError("ambiguous native source record")
            pending[name] = output.split(PREFIX, 1)[1]
        elif name in pending:
            if event.get("Action") != "output": raise ValueError("truncated native source record")
            pending[name] += output
        else: continue
        if len(pending[name]) > 1048576: raise ValueError("native graph record exceeds bound")
        if not pending[name].endswith("\n"): continue
        r = json.loads(pending.pop(name).strip(), object_pairs_hook=vm.unique_object)
        if type(r) is not dict or r.get("id") not in CASES or r["id"] in records or name != TEST + "/" + r["id"]:
            raise ValueError("unselected or duplicate graph record")
        records[r["id"]] = validate_record(r, selected, completed, old)
    if pending: raise ValueError("incomplete graph source framing")
    return validate_records(records, selected, completed, old)


def selected_inputs(root):
    selected = json.loads((root / INPUT).read_text("ascii"), object_pairs_hook=vm.unique_object)
    completed = json.loads((root / COMPLETIONS).read_text("ascii"), object_pairs_hook=vm.unique_object)
    old = json.loads((root / vm.COMPLETIONS).read_text("ascii"), object_pairs_hook=vm.unique_object)
    if selected != public_inputs(root): raise ValueError("new public subject differs")
    if (set(completed) != {"schema", "pair", "long_message_hex", "short_message_hex", "long_signature_hex", "short_signature_hex"}
            or completed["schema"] != "ptlc-nom-bilateral-public-completions-v1"):
        raise ValueError("unselected completion fields")
    for leg in ("long", "short"):
        term = selected["terms"][leg]
        msg = unlock_message({"profile": "zenon-ptlc-unlock:v1", "chain_id": selected["terms"]["chain_id"],
                              "point_type": 1, "entry_id_hex": term["entry_id_hex"],
                              "destination_hex": selected["terms"][term["recipient"] + "_address_hex"]})
        if completed[leg + "_message_hex"] != msg or completed[leg + "_signature_hex"] == old[leg + "_signature_hex"]:
            raise ValueError("old inner witness cannot be inherited")
        prior.auth.byte_value(completed[leg + "_signature_hex"], 64)
    return selected, completed, old


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=vm.unique_object)
    if (manifest["schema"] != "zenon-nom-bilateral-graph-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != CORE_COMMIT or manifest["expected_counts"] != COUNTS
            or set(manifest["input_sha256"]) != set(SELECTED)
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("selected bilateral manifest differs")
    prior.inputs(root); selected, completed, old = selected_inputs(root)
    if fixture != corpus(validate_records(fixture["records"], selected, completed, old)):
        raise ValueError("complete selected graph differs")
    measured = {n: vm.digest(root / n) for n in (MANIFEST, *SELECTED, *manifest["preserved_file_sha256"])}
    if any(measured[n] != h for n, h in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items()):
        raise ValueError("selected or preserved graph input changed")
    return manifest, fixture, measured


def execute(checkout, go, root, evidence):
    injected = checkout / "vm/zz_research_nom_bilateral_graph_test.go"
    if injected.exists() or injected.is_symlink(): raise ValueError("overlay would replace existing input")
    value = (json.dumps({"Replace": {str(injected): str(root / DRIVER)}}, sort_keys=True) + "\n").encode("ascii")
    with private_create(evidence / "overlay.json") as out: out.write(value)
    retained = {}
    environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
    for name, selected in (("INPUT", INPUT), ("COMPLETIONS", COMPLETIONS), ("OLD", vm.COMPLETIONS)):
        retained[name] = (root / selected).read_bytes()
        path = evidence / (name.lower() + "-handoff.json")
        with private_create(path) as out: out.write(retained[name])
        environment["PTLC_NOM_BILATERAL_" + name] = str(path)
    wire = run([str(go), "test", "-json", "-overlay", str(evidence / "overlay.json"), "-vet=off", "-mod=readonly",
                "-count=1", "-run", "^" + TEST + "$", "./vm"], environment=environment,
               directory=checkout, evidence=evidence, label="core-observation", timeout=240)
    passed = vm.selected_outcome(wire, expected_tests())
    if (evidence / "overlay.json").read_bytes() != value or any((evidence / (n.lower() + "-handoff.json")).read_bytes() != b for n, b in retained.items()):
        raise ValueError("exact graph handoff changed")
    return wire, passed


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); vm.core_state(checkout, manifest); tool_hash = vm.digest(go)
    parent = evidence_parent or root / ".research-cache/nom-bilateral-graph-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="bilateral-graph-", dir=parent))
    result = {"schema": "zenon-nom-bilateral-graph-result-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
              "outcome": "UNKNOWN", **BOUNDARY, "input_sha256": before, "go_executable_sha256": tool_hash,
              "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
              "stream_custody": "Original private streams and handoffs; hosted private custody may be ephemeral"}
    try:
        source_result = prior.qualify(checkout, go, root=root, evidence_parent=evidence / "account-context")
        wire, passed = execute(checkout, go, root, evidence)
        if (source_result["outcome"] != "PASS" or source_result["counts"] != prior.COUNTS
                or source_result["passed_context_tests_including_parent"] != 85
                or source_result["source_result"]["passed_outer_tests_including_parent"] != 127
                or source_result["source_result"]["source_result"]["passed_tests_including_parents"] != 58):
            raise ValueError("complete preserved source comparison required")
        if fixture != corpus(collect_records(wire, *selected_inputs(root))): raise ValueError("fresh graph differs from public selection")
        vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != vm.digest(go): raise ValueError("selected input changed during qualification")
        result.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=source_result,
                      graph_tests_including_parent=passed, tests_passed_including_parents=passed + 270,
                      graph_steps=46, selected_controls=24, public_recovery="SEPARATE RUST TEST COMPARISON; NO JOURNAL COMPOSITION")
        return result
    except BaseException:
        result["outcome"] = "FAILED_OR_INCOMPLETE"; raise
    finally:
        with private_create(evidence / "outcome.json") as out: out.write((json.dumps(result, sort_keys=True) + "\n").encode("ascii"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True); parser.add_argument("--go", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(qualify(args.checkout, args.go), sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, WorkerError):
        print("FAIL: bilateral graph; preserve original private evidence", file=sys.stderr); return 1


if __name__ == "__main__":
    sys.exit(main())
