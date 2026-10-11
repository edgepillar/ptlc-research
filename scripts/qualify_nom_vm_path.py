#!/usr/bin/env python3
"""Qualify composed VM accounting and selected verifier checks offline.

Actual memory stores, dispatcher, lifecycle and finalization are executed under
caller-selected ledger/spork stubs. This is not full admission, supervisor
context authentication, canonicality, atomic recovery entry or live-chain proof.
Original command streams and generated patches remain private and may be
ephemeral on hosted runners. Compiler, cache, runtime and host are trusted.
"""

import argparse
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
from offline_session.nom_wire import account_block_hash
from offline_session.pr138 import CORE_COMMIT, CONTRACT_HEX
from offline_session.public_worker import WorkerError
from scripts.generate_nom_vm_path import PROFILE, FIXTURE, corpus
from scripts.nom_native_command import private_create, run
from scripts.qualify_nom_wire_core import digest, core_state
from scripts.qualify_nom_observation_core import parse_outcome

MANIFEST = "compatibility/nom_vm_path_manifest.json"
FUNDING = "compatibility/fixtures/nom_created_funding_v1.json"
COMPLETIONS = "compatibility/fixtures/nom_created_completions_v1.json"
VM_DRIVER = "compatibility/nom_vm_path_test.go.txt"
VERIFIER_DRIVER = "compatibility/nom_vm_path_verifier_test.go.txt"
VM_TEST = "TestResearchNoMVMPath"
VERIFIER_TEST = "TestResearchNoMVMReceiptVerifier"
SELECTED = (FIXTURE, VM_DRIVER, VERIFIER_DRIVER, "scripts/generate_nom_vm_path.py", "scripts/qualify_nom_vm_path.py")
COUNTS = {"legs": 2, "vm_controls": 32, "verifier_controls": 24, "raw_replay_counterexamples": 2}
PREFIX = "PTLC_RESEARCH_VM_RECORD "


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate evidence field")
        result[key] = value
    return result


def expected_tests(fixture):
    if fixture != corpus(): raise ValueError("complete exact VM profile required")
    return {"github.com/zenon-network/go-zenon/vm": {VM_TEST, *(VM_TEST + "/" + v["id"] for v in fixture["vm_vectors"])},
            "github.com/zenon-network/go-zenon/verifier": {VERIFIER_TEST, *(VERIFIER_TEST + "/" + v["id"] for v in fixture["verifier_vectors"])}}


def selected_outcome(wire, names):
    for line in wire.splitlines():
        json.loads(line, object_pairs_hook=unique_object)
    return parse_outcome(wire, names)


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=unique_object)
    if (manifest["schema"] != "zenon-nom-vm-path-manifest-v1" or manifest["core_commit"] != CORE_COMMIT
            or manifest["profile"] != PROFILE or manifest["expected_counts"] != COUNTS
            or set(manifest["input_sha256"]) != set(SELECTED)
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("selected VM subject changed")
    expected_tests(fixture)
    for name, expected in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items():
        if digest(root / name) != expected: raise ValueError("selected or preserved input changed")
    measured = {name: digest(root / name) for name in (MANIFEST, *SELECTED, FUNDING, COMPLETIONS,
                "compatibility/fixtures/nom_completions_v1.json", "scripts/qualify_nom_observation_core.py",
                "scripts/qualify_nom_wire_core.py", "scripts/nom_native_command.py", "offline_session/nom_wire.py")}
    return manifest, fixture, measured


def expected_result(kind, amount):
    ok = lambda label, payouts=0: {"label": label, "error": "NONE", "status": "1", "payouts": payouts}
    fail = lambda label, error, payouts=0, status="2": {"label": label, "error": error, "status": status, "payouts": payouts}
    events, balances, present = [ok("create"), ok("unlock", 1)], [amount, 0, amount, 0], False
    errors = {"invalid-witness-then-valid": "ErrInvalidPointSignature", "old-witness-then-valid": "ErrInvalidPointSignature",
              "cross-leg-witness-then-valid": "ErrInvalidPointSignature", "wrong-caller-then-valid": "ErrPermissionDenied",
              "wrong-proxy-recipient-then-valid": "ErrPermissionDenied", "early-reclaim-then-unlock": "ReclaimNotDue"}
    if kind in errors: events.insert(1, fail("refused", errors[kind]))
    elif kind == "unlock-at-expiry-then-reclaim":
        events, balances = [ok("create"), fail("refused", "ErrExpired"), ok("reclaim", 1)], [2*amount, 0, 0, 0]
    elif kind in ("unlock-replay-after-deletion", "proxy-then-direct-replay"):
        events.append(fail("replay", "ErrDataNonExistent"))
    elif kind == "create-at-expiry-refunds":
        events, balances = [fail("create", "ErrInvalidExpirationTime", 1)], [2*amount, 0, 0, 0]
    elif kind == "insufficient-funding-balance":
        events, balances = [fail("funding-send", "ErrInsufficientBalance", status="0")], [amount-1, 0, 0, 0]
    elif kind == "insufficient-contract-balance-rolls-back":
        events, balances, present = [ok("create"), fail("refused", "ErrInsufficientBalance")], [amount, amount-1, 0, 0], True
    elif kind == "raw-receive-replay-needs-verifier": balances[2] = 2*amount
    elif kind not in ("direct-success", "proxy-funder-success", "proxy-third-success"):
        raise ValueError("unselected VM result kind")
    return events, dict(zip(("funder", "contract", "recipient", "third"), map(str, balances))), present


def validate_record(record, vector, funding):
    required = {"schema", "id", "leg", "kind", "funding_id_hex", "amount", "entry_present", "events", "blocks", "balances", "receipt_patches"}
    if type(record) is not dict or set(record) != required or record["schema"] != "zenon-nom-vm-path-record-v1":
        raise ValueError("unexpected VM result fields")
    if any(record[k] != vector[k] for k in ("id", "leg", "kind")):
        raise ValueError("VM result subject differs")
    selected = funding["fundings"][vector["leg"]]
    if record["funding_id_hex"] != selected["hash_hex"] or record["amount"] != selected["entry"]["amount"]:
        raise ValueError("created funding context differs")
    events, balances, present = expected_result(vector["kind"], int(record["amount"]))
    if (type(record["events"]) is not list or any(type(e) is not dict or set(e) != {"label", "error", "status", "payouts"}
            or type(e["payouts"]) is not int or any(type(e[k]) is not str for k in ("label", "error", "status"))
            for e in record["events"])):
        raise ValueError("invalid accounting event types")
    if record["events"] != events or record["balances"] != balances or type(record["entry_present"]) is not bool or record["entry_present"] != present:
        raise ValueError("actual accounting or refusal differs")
    blocks = record["blocks"]
    roles = {"funding"}
    for event in events:
        if event["status"] == "0": continue
        label = event["label"]
        roles.update((label + "-send", label + "-receive"))
        roles.update(label + "-payout-" + str(i) for i in range(event["payouts"]))
    if vector["kind"] == "create-at-expiry-refunds": roles.add("refund-recipient-receive")
    elif vector["kind"] not in ("insufficient-funding-balance", "insufficient-contract-balance-rolls-back"):
        roles.add("recipient-receive")
    if vector["kind"] == "raw-receive-replay-needs-verifier": roles.add("raw-replayed-recipient-receive")
    if type(blocks) is not dict or set(blocks) != roles: raise ValueError("incomplete or unselected source blocks")
    for r in blocks.values():
        if type(r) is not dict or set(r) != {"hash_hex", "changes_hash_hex", "block"}:
            raise ValueError("unexpected source block record")
        if type(r["changes_hash_hex"]) is not str or re.fullmatch("[0-9a-f]{64}", r["changes_hash_hex"]) is None:
            raise ValueError("invalid separate patch-hash claim")
        if account_block_hash(r["block"]) != r["hash_hex"]: raise ValueError("source account hash differs from Python")
    if blocks["funding"]["block"] != selected["block"]: raise ValueError("preserved full Create input differs")
    if "create-send" in blocks and blocks["create-send"] != blocks["funding"]:
        raise ValueError("executed Create differs from original funding")
    previous, height = "00"*32, 1
    for event in events:
        if event["status"] == "0": continue
        label = event["label"]; send, parent = blocks[label+"-send"], blocks[label+"-receive"]
        b = parent["block"]
        children = [blocks[label+"-payout-"+str(i)] for i in range(event["payouts"])]
        if (send["block"]["block_type"] != "2" or send["block"]["to_address_hex"] != CONTRACT_HEX
                or send["block"]["chain_id"] != selected["block"]["chain_id"]):
            raise ValueError("executed send type or chain differs")
        if (b["block_type"] != "5" or b["address_hex"] != CONTRACT_HEX or b["from_block_hash_hex"] != send["hash_hex"]
                or b["data_hex"] != "000000000000000" + event["status"]
                or b["descendant_hashes_hex"] != [c["hash_hex"] for c in children]):
            raise ValueError("source receive and original differ")
        for child in children:
            c = child["block"]
            destination = selected["block"]["address_hex"] if label in ("create", "reclaim") else selected["entry"]["destination_hex"]
            if (c["block_type"] != "4" or c["address_hex"] != CONTRACT_HEX or c["to_address_hex"] != destination
                    or c["amount"] != record["amount"] or c["token_standard_hex"] != selected["entry"]["token_standard_hex"]
                    or c["previous_hash_hex"] != previous or c["height"] != str(height)
                    or (c["momentum_hash_hex"],c["momentum_height"]) != (b["momentum_hash_hex"],b["momentum_height"])):
                raise ValueError("source payout ancestry or asset differs")
            previous, height = child["hash_hex"], height+1
        if b["previous_hash_hex"] != previous or b["height"] != str(height): raise ValueError("source parent ancestry differs")
        previous, height = parent["hash_hex"], height+1
    for role in roles & {"recipient-receive", "refund-recipient-receive", "raw-replayed-recipient-receive"}:
        receipt = blocks[role]["block"]
        payouts = [r for key,r in blocks.items() if "-payout-" in key]
        if (len(payouts) != 1 or receipt["from_block_hash_hex"] != payouts[0]["hash_hex"]
                or receipt["address_hex"] != payouts[0]["block"]["to_address_hex"]
                or receipt["block_type"] != "3" or receipt["amount"] != "0"
                or receipt["chain_id"] != selected["block"]["chain_id"] or receipt["version"] != "1"
                or receipt["descendant_hashes_hex"] != [] or receipt["to_address_hex"] != "00"*20
                or receipt["token_standard_hex"] != "00"*10 or receipt["data_hex"] != ""
                or receipt["fused_plasma"] != "0" or receipt["difficulty"] != "0" or receipt["nonce_hex"] != "00"*8):
            raise ValueError("actual user receipt does not reference the payout")
        replay = role == "raw-replayed-recipient-receive"
        if (receipt["height"] != ("2" if replay else "1")
                or receipt["previous_hash_hex"] != (blocks["recipient-receive"]["hash_hex"] if replay else "00"*32)):
            raise ValueError("selected recipient receipt ancestry differs")
    patches = record["receipt_patches"]
    if type(patches) is not dict or set(patches) != ({"before_hex", "after_hex"} if vector["kind"] == "direct-success" else set()):
        raise ValueError("unexpected actual VM patch handoff")
    for value in patches.values():
        if type(value) is not str or len(value)>32768 or re.fullmatch("(?:[0-9a-f]{2})+",value) is None:
            raise ValueError("invalid bounded synthetic patch dump")
    if patches and patches["before_hex"] == patches["after_hex"]: raise ValueError("VM receive did not change state")
    return record


def collect_vm_records(wire, fixture, funding):
    wanted = {v["id"]: v for v in fixture["vm_vectors"]}; records, pending = {}, {}
    for line in wire.splitlines():
        event = json.loads(line, object_pairs_hook=unique_object)
        if type(event) is not dict or event.get("Package") != "github.com/zenon-network/go-zenon/vm":
            raise ValueError("unexpected VM evidence package")
        output = event.get("Output", "")
        name = event.get("Test")
        if type(output) is not str: raise ValueError("invalid VM output fragment")
        if pending and event.get("Action") == "output" and name not in pending:
            raise ValueError("interleaved VM record subject")
        if PREFIX in output:
            if (output.count(PREFIX) != 1 or name in pending or event.get("Action") != "output"
                    or re.match(r"^    zz_research_nom_vm_path_test.go:[0-9]+: " + PREFIX, output) is None):
                raise ValueError("ambiguous VM record")
            pending[name] = output.split(PREFIX,1)[1]
        elif name in pending:
            if event.get("Action") != "output": raise ValueError("truncated VM record")
            pending[name] += output
        else: continue
        # go test -json fragments long log lines. Reassemble only the exact
        # selected test's bounded output, retaining the original stream.
        if len(pending[name]) > 65536: raise ValueError("oversized VM record")
        if not pending[name].endswith("\n"): continue
        record = json.loads(pending.pop(name).strip(), object_pairs_hook=unique_object)
        ident = record.get("id")
        if ident not in wanted or ident in records or name != VM_TEST+"/"+ident:
            raise ValueError("unselected or duplicate VM record")
        records[ident] = validate_record(record, wanted[ident], funding)
    if pending or set(records) != set(wanted): raise ValueError("incomplete VM record coverage")
    return records


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); core_state(checkout, manifest); tool_hash = digest(go)
    parent = evidence_parent or root / ".research-cache/nom-vm-path-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="composed-vm-", dir=parent))
    record = {"schema": "zenon-nom-vm-path-result-v1", "core_commit": CORE_COMMIT, "profile": PROFILE,
              "outcome": "UNKNOWN", **fixture["boundary"], "go_executable_sha256": tool_hash,
              "input_sha256": before, "verifier_patch_handoff": "ACTUAL VM PATCH DUMPS; SEPARATE SELECTED CHECKS",
              "changes_hash": "SEPARATE SOURCE CLAIM; NOT AN ACCOUNT-HASH INPUT OR AUTHENTICATED STATE PROOF",
              "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet"}
    try:
        replacements = {}
        for package, driver in (("vm", VM_DRIVER), ("verifier", VERIFIER_DRIVER)):
            selected = checkout/package/"zz_research_nom_vm_path_test.go"
            if selected.exists() or selected.is_symlink(): raise ValueError("overlay would replace existing input")
            replacements[str(selected)] = str(root/driver)
        overlay = evidence/"overlay.json"
        with private_create(overlay) as out: out.write(json.dumps({"Replace":replacements},sort_keys=True).encode("ascii"))
        environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off",
                           PTLC_NOM_VM_PATH_FIXTURE=str(root/FIXTURE), PTLC_NOM_VM_FUNDING=str(root/FUNDING),
                           PTLC_NOM_VM_COMPLETIONS=str(root/COMPLETIONS),
                           PTLC_NOM_VM_OLD_COMPLETIONS=str(root/"compatibility/fixtures/nom_completions_v1.json"))
        def execute(package, test, label):
            return run([str(go),"test","-json","-overlay",str(overlay),"-vet=off","-mod=readonly","-count=1","-run","^"+test+"$","./"+package],
                       environment=environment,directory=checkout,evidence=evidence,label=label,timeout=240)
        names = expected_tests(fixture)
        # Reuse the frozen command custodian's selected labels. Actual package
        # and test identity are required independently by parse_outcome.
        vm_wire = execute("vm", VM_TEST, "core-wire")
        vm_count = selected_outcome(vm_wire, {"github.com/zenon-network/go-zenon/vm":names["github.com/zenon-network/go-zenon/vm"]})
        records = collect_vm_records(vm_wire,fixture,json.loads((root/FUNDING).read_text("ascii")))
        baseline = {leg:records[leg+"-direct-success"] for leg in ("long","short")}
        handoff = {"schema":"zenon-nom-vm-verifier-input-v1","baseline":baseline}
        handoff_path = evidence/"vm-source-results.json"
        handoff_wire = (json.dumps(handoff,sort_keys=True)+"\n").encode("ascii")
        with private_create(handoff_path) as out: out.write(handoff_wire)
        environment["PTLC_NOM_VM_SOURCE_RESULTS"] = str(handoff_path)
        verifier_wire = execute("verifier",VERIFIER_TEST,"core-observation")
        verifier_count = selected_outcome(verifier_wire,{"github.com/zenon-network/go-zenon/verifier":names["github.com/zenon-network/go-zenon/verifier"]})
        if handoff_path.read_bytes()!=handoff_wire: raise ValueError("source patch handoff changed")
        core_state(checkout,manifest)
        if before!=inputs(root)[2] or digest(go)!=tool_hash: raise ValueError("selected source input changed")
        record.update(outcome="PASS",counts=COUNTS,source_unchanged=True,passed_tests_including_parents=vm_count+verifier_count,
                      passed_vm_including_parent=vm_count,passed_verifier_including_parent=verifier_count,
                      emitted_records=32,vm_verifier_handoff_sha256=hashlib.sha256(handoff_wire).hexdigest(),
                      vm_records_sha256=hashlib.sha256(json.dumps(records,sort_keys=True).encode("ascii")).hexdigest(),
                      raw_receipt_replay="BOTH LEGS CREDIT TWICE WHEN VERIFIER IS BYPASSED",
                      restored_actual_vm_markers="SELECTED FROM-HASH CHECK REFUSES BOTH POST-RECEIVE PATCHES",
                      legacy_wrong_recipient_helper="ALLOWS BEFORE ENFORCEMENT; REFUSES AT ENFORCEMENT",
                      stream_custody="Original private streams and patches; hosted custody is ephemeral unless independently retained")
        return record
    except BaseException:
        record["outcome"]="FAILED_OR_INCOMPLETE"; raise
    finally:
        with private_create(evidence/"outcome.json") as out: out.write((json.dumps(record,sort_keys=True)+"\n").encode("ascii"))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout",type=Path,required=True);parser.add_argument("--go",type=Path,required=True)
    args=parser.parse_args()
    try: print(json.dumps(qualify(args.checkout,args.go),sort_keys=True));return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,WorkerError):
        print("FAIL: composed VM path; preserve original private evidence",file=sys.stderr);return 1


if __name__=="__main__": sys.exit(main())
