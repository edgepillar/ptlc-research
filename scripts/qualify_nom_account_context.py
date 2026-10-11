#!/usr/bin/env python3
"""Compare fresh public account verifier entry points with exact ledger views.

Strict synthetic lookup selections, real memory account stores and mailboxes
are reproduction inputs, not authenticated chain authority. The two public
entry points are called independently; neither composes supervisor/VM/Plasma
admission. Exact original bytes and all earlier conflicts remain unchanged.
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
from offline_session.nom_wire import account_block_hash
from offline_session.pr138 import CORE_COMMIT, decimal, fixed_hex
from offline_session.public_worker import WorkerError
from scripts.generate_nom_account_context import PROFILE, FIXTURE, BOUNDARY, vectors, corpus
from scripts.nom_native_command import private_create, run
from scripts import qualify_nom_vm_path as vm, qualify_nom_account_authorization as auth

MANIFEST = "compatibility/nom_account_context_manifest.json"
DRIVER = "compatibility/nom_account_context_test.go.txt"
TEST = "TestResearchNoMAccountContext"
PACKAGE = "github.com/zenon-network/go-zenon/verifier"
PREFIX = "PTLC_RESEARCH_ACCOUNT_CONTEXT_RECORD "
SELECTED = (FIXTURE, DRIVER, "scripts/generate_nom_account_context.py",
            "scripts/qualify_nom_account_context.py", "tests/test_nom_account_context.py")
COUNTS = {"legs": 2, "source_roles": 12, "context_controls": 84, "context_tests_including_parent": 85, "source_panic_controls": 8,
          "preserved_source_tests_including_parents": 185, "total_source_tests_including_parents": 270}
ENFORCEMENT = 10109240
RECORD_FIELDS = {"schema", "id", "leg", "role", "kind", "source_hash_hex", "original_wire_hex",
    "wire_hex", "wire_sha256", "roundtrip_wire_hex", "block", "hash_hex", "computed_hash_hex", "address_hex", "height",
    "header_previous", "semantic_previous", "acknowledged", "public_key_hex", "signature_hex", "children", "context", "checks"}
CONTEXT_FIELDS = {"account_address_hex", "account_frontier", "account_frontier_wire_hex", "account_state_patch_hex",
    "account_state_patch_sha256", "vm_patch_selection", "vm_patch_sha256", "known_momentum", "frontier_momentum",
    "confirmation_height", "send_wire_hex", "received_marker", "mailbox_headers", "missing_momentum_store",
    "structural_account_queries", "transaction_account_queries"}


def expected_tests():
    return {PACKAGE: {TEST, *(TEST + "/" + v["id"] for v in vectors())}}


def source_kind(role):
    return "unsigned" if role in auth.USER_ROLES else "empty-authorization"


def selected(source, leg, role, kind=None):
    return source[leg + "-" + role + "-" + (kind or source_kind(role))]


def frozen_source(root=ROOT):
    return json.loads((root / auth.FIXTURE).read_text("ascii"))["records"]


def frozen_patches(root=ROOT):
    return json.loads((root / FIXTURE).read_text("ascii"))["source_vm_patches"]


def hh(hash_hex="00" * 32, height="0"):
    return {"hash_hex": hash_hex, "height": height}


def checked_hh(value):
    if type(value) is not dict or set(value) != {"hash_hex", "height"}:
        raise ValueError("unexpected hash-height fields")
    fixed_hex(value["hash_hex"], 32); decimal(value["height"], 64)
    return value


def flip(value):
    return (bytes([int(value[:2], 16) ^ 1]) + bytes.fromhex(value[2:])).hex()


def validate_record(record, vector, source, patches):
    if (type(record) is not dict or set(record) != RECORD_FIELDS
            or record["schema"] != "zenon-nom-account-context-record-v1"
            or any(record[k] != vector[k] for k in ("id", "leg", "role", "kind"))):
        raise ValueError("unselected account context record")
    leg, role, kind = (vector[k] for k in ("leg", "role", "kind"))
    c = record["context"]
    if type(c) is not dict or set(c) != CONTEXT_FIELDS: raise ValueError("unselected ledger context fields")
    old = selected(source, leg, role)
    if (record["source_hash_hex"] != old["hash_hex"] or record["original_wire_hex"] != old["wire_hex"]
            or record["checks"] != {"structural": vector["expect_structural"], "transaction": vector["expect_transaction"]}):
        raise ValueError("original or selected verifier result differs")
    for k in ("hash_hex", "computed_hash_hex", "wire_sha256"): fixed_hex(record[k], 32)
    wire = auth.byte_value(record["wire_hex"])
    if not wire or record["roundtrip_wire_hex"] != record["wire_hex"] or hashlib.sha256(wire).hexdigest() != record["wire_sha256"]:
        raise ValueError("exact retained context bytes differ")
    b = record["block"]
    if record["computed_hash_hex"] != account_block_hash(b):
        raise ValueError("complete account hash differs")
    if (record["height"] != b["height"] or record["address_hex"] != b["address_hex"]
            or record["header_previous"] != hh(b["previous_hash_hex"], str(int(b["height"]) - 1))
            or record["acknowledged"] != hh(b["momentum_hash_hex"], b["momentum_height"])):
        raise ValueError("public header selection differs")
    children = record["children"]
    if type(children) is not list or len(children) != len(old["block"]["descendant_hashes_hex"]):
        raise ValueError("selected descendant count differs")
    wanted_children = []
    if children:
        child = selected(source, leg, "unlock-payout-0")
        cb = copy.deepcopy(child["block"])
        advertised = child["hash_hex"]
        if kind == "child-wrong-ack": cb["momentum_hash_hex"] = flip(cb["momentum_hash_hex"])
        elif kind == "child-wrong-version": cb["version"] = "2"
        if kind in ("child-wrong-ack", "child-wrong-version"): advertised = account_block_hash(cb)
        elif kind == "child-wrong-hash": advertised = flip(advertised)
        wanted_children = [advertised]
        observed = children[0]
        if (type(observed) is not dict or set(observed) != {"block", "hash_hex", "computed_hash_hex", "wire_hex"}
                or observed["block"] != cb or observed["hash_hex"] != advertised
                or observed["computed_hash_hex"] != account_block_hash(cb) or not auth.byte_value(observed["wire_hex"])):
            raise ValueError("exact child projection differs")
        semantic = hh(cb["previous_hash_hex"], str(int(cb["height"]) - 1))
    else: semantic = record["header_previous"]
    if record["semantic_previous"] != semantic:
        raise ValueError("source semantic predecessor differs")
    wanted = copy.deepcopy(old["block"])
    if kind == "relocated": wanted = copy.deepcopy(selected(source, leg, role, "relocated-authorized")["block"])
    signed_new = role == "funding" and kind not in ("original", "relocated")
    if signed_new:
        relocated = selected(source, leg, "funding", "relocated-authorized")
        wanted["address_hex"] = relocated["block"]["address_hex"]
        wanted["height"] = "1" if kind == "reset-start" else "2"
        wanted["previous_hash_hex"] = "00" * 32 if kind == "reset-start" else record["context"]["account_frontier"]["hash_hex"]
        if kind in ("next-cemented-ancestor", "next-cemented-competitor", "next-wrong-previous"):
            first = copy.deepcopy(wanted); first["height"] = "1"; first["previous_hash_hex"] = "00" * 32
            wanted["previous_hash_hex"] = account_block_hash(first)
            if kind != "next-cemented-ancestor": wanted["previous_hash_hex"] = flip(wanted["previous_hash_hex"])
        if kind in ("next-missing-ack", "next-unsigned-missing-ack"):
            wanted["momentum_height"] = str(int(wanted["momentum_height"]) + 1)
        if kind == "next-wrong-ack-hash": wanted["momentum_hash_hex"] = flip(wanted["momentum_hash_hex"])
        if kind == "next-old-hash": wanted["data_hex"] += "7f"
    if kind == "post-vm-successor":
        wanted["height"] = "2"; wanted["previous_hash_hex"] = old["hash_hex"]
    if kind.startswith("wrong-recipient-"):
        wanted["address_hex"] = selected(source, leg, "funding")["block"]["address_hex"]
        if kind == "wrong-recipient-high-ack-low-frontier": wanted["momentum_height"] = str(ENFORCEMENT)
    if kind == "rehashed": wanted["data_hex"] = "7f"
    wanted["descendant_hashes_hex"] = wanted_children
    if b != wanted: raise ValueError("unselected account content transformation")
    expected_hash = record["computed_hash_hex"]
    if kind == "next-old-hash":
        prior = copy.deepcopy(wanted); prior["data_hex"] = prior["data_hex"][:-2]; expected_hash = account_block_hash(prior)
    if record["hash_hex"] != expected_hash: raise ValueError("advertised account hash differs")
    pub = selected(source, leg, "funding", "relocated-authorized")["public_key_hex"]
    expected_pub = pub if signed_new or kind in ("relocated", "nonempty-key") else ""
    if record["public_key_hex"] != expected_pub: raise ValueError("public test account key differs")
    sig_width = 64 if (signed_new and kind not in ("next-unsigned", "next-unsigned-missing-ack")
                       or kind in ("relocated", "nonempty-signature")) else 0
    auth.byte_value(record["signature_hex"], sig_width)
    if kind == "relocated" and record["signature_hex"] != selected(source, leg, role, "relocated-authorized")["signature_hex"]:
        raise ValueError("selected public authorization signature differs")
    if kind == "nonempty-signature" and record["signature_hex"] != "51" * 64:
        raise ValueError("embedded signature control differs")
    if c["account_address_hex"] != b["address_hex"]: raise ValueError("ledger account differs")
    for k in ("account_frontier", "known_momentum", "frontier_momentum"): checked_hh(c[k])
    expected_known = hh(old["block"]["momentum_hash_hex"], old["block"]["momentum_height"])
    if kind == "wrong-recipient-high-ack-low-frontier": expected_known["height"] = str(ENFORCEMENT)
    frontier_height = ENFORCEMENT - int(kind in ("wrong-recipient-before-enforcement", "wrong-recipient-high-ack-low-frontier"))
    if (c["known_momentum"] != expected_known or c["frontier_momentum"] != hh(hashlib.sha3_256(b"public-context-frontier").hexdigest(), str(frontier_height))):
        raise ValueError("selected momentum view differs")
    confirmation = int(old["block"]["momentum_height"]) + int(kind in ("unconfirmed-payout", "wrong-confirmation"))
    if kind == "missing-confirmation": confirmation = 0
    if c["confirmation_height"] != str(confirmation): raise ValueError("selected confirmation differs")
    send_role = {"create-receive": "funding", "unlock-receive": "unlock-send", "recipient-receive": "unlock-payout-0"}.get(role)
    send = selected(source, leg, send_role) if send_role is not None and kind != "missing-payout" else None
    if c["send_wire_hex"] != (send["wire_hex"] if send else ""): raise ValueError("exact source send differs")
    marker = kind in ("post-vm-original", "post-vm-successor", "received-marker")
    if type(c["received_marker"]) is not bool or c["received_marker"] != marker: raise ValueError("actual received marker differs")
    if type(c["missing_momentum_store"]) is not bool or c["missing_momentum_store"] != (kind == "missing-momentum-store"):
        raise ValueError("selected missing momentum store differs")
    patch_kind = "NONE"
    if role == "recipient-receive" and kind not in ("relocated", "wrong-recipient-at-enforcement", "wrong-recipient-before-enforcement", "wrong-recipient-high-ack-low-frontier"):
        patch_kind = "after_hex" if kind in ("post-vm-original", "post-vm-successor") else "before_hex"
    patch = bytes.fromhex(patches[leg][patch_kind]) if patch_kind != "NONE" else b""
    if c["vm_patch_selection"] != patch_kind or c["vm_patch_sha256"] != hashlib.sha256(patch).hexdigest():
        raise ValueError("actual VM patch handoff differs")
    state_patch = auth.byte_value(c["account_state_patch_hex"], maximum=32768)
    if c["account_state_patch_sha256"] != hashlib.sha256(state_patch).hexdigest():
        raise ValueError("actual memory state commitment differs")
    frontier_wire = auth.byte_value(c["account_frontier_wire_hex"])
    if bool(frontier_wire) != (c["account_frontier"] != hh()): raise ValueError("frontier bytes missing")
    expected_frontier = hh()
    if role == "unlock-receive":
        f = selected(source, leg, "unlock-payout-0" if kind == "header-predecessor-store" else "create-receive")
        expected_frontier = hh(f["hash_hex"], f["block"]["height"])
        if c["account_frontier_wire_hex"] != f["wire_hex"]: raise ValueError("actual embedded frontier bytes differ")
    elif kind in ("post-vm-original", "post-vm-successor"):
        expected_frontier = hh(old["hash_hex"], "1")
        if c["account_frontier_wire_hex"] != old["wire_hex"]: raise ValueError("actual received frontier bytes differ")
    elif signed_new and kind != "reset-start":
        first = copy.deepcopy(old["block"]); first.update(address_hex=pub_address(pub), height="1", previous_hash_hex="00" * 32)
        if kind == "next-ack-regression": first["momentum_height"] = str(int(first["momentum_height"]) + 1)
        expected_frontier = hh(account_block_hash(first), "1")
        if kind in ("next-cemented-ancestor", "next-cemented-competitor"):
            second = copy.deepcopy(first); second.update(height="2", previous_hash_hex=expected_frontier["hash_hex"])
            third = copy.deepcopy(second); third.update(height="3", previous_hash_hex=account_block_hash(second))
            expected_frontier = hh(account_block_hash(third), "3")
    if c["account_frontier"] != expected_frontier: raise ValueError("actual selected account frontier differs")
    queries = [] if role == "unlock-payout-0" or kind == "missing-momentum-store" else [{"address_hex": b["address_hex"], **semantic}]
    if c["structural_account_queries"] != queries or c["transaction_account_queries"] != queries:
        raise ValueError("exact account context lookup differs")
    headers = []
    if role in auth.EMBEDDED_ROLES and send is not None and kind != "empty-mailbox":
        headers = [{"address_hex": send["block"]["address_hex"], "hash_hex": send["hash_hex"], "height": send["block"]["height"]}]
        if kind == "wrong-mailbox-head": headers[0]["hash_hex"] = flip(headers[0]["hash_hex"])
    if c["mailbox_headers"] != headers: raise ValueError("actual mailbox selection differs")
    return record


def pub_address(pub):
    return "00" + hashlib.sha3_256(bytes.fromhex(pub)).hexdigest()[:38]


def validate_records(records, source, patches):
    if type(patches) is not dict or set(patches) != {"long", "short"}: raise ValueError("both fresh VM patch selections required")
    for p in patches.values():
        if type(p) is not dict or set(p) != {"before_hex", "after_hex"}: raise ValueError("complete VM patch handoff required")
        for value in p.values():
            if not auth.byte_value(value, maximum=16384): raise ValueError("empty VM patch selection")
        if p["before_hex"] == p["after_hex"]: raise ValueError("actual VM receive did not change state")
    if type(records) is not dict or set(records) != {v["id"] for v in vectors()}:
        raise ValueError("complete exact context controls required")
    for v in vectors(): validate_record(records[v["id"]], v, source, patches)
    for leg in ("long", "short"):
        baseline = records[leg + "-funding-next-after-reset"]
        first = records[leg + "-funding-reset-start"]
        if baseline["context"]["account_frontier_wire_hex"] != first["wire_hex"]:
            raise ValueError("new original is not connected to the selected signed predecessor")
        for kind in ("next-missing-ack", "next-wrong-ack-hash", "next-unsigned", "next-bad-signature", "next-old-hash", "next-unsigned-missing-ack"):
            r = records[leg + "-funding-" + kind]
            if r["context"]["account_frontier_wire_hex"] != first["wire_hex"]: raise ValueError("signed predecessor changed")
        bad = records[leg + "-funding-next-bad-signature"]
        if bad["signature_hex"] != flip(baseline["signature_hex"]): raise ValueError("bad signature control differs")
        old_hash = records[leg + "-funding-next-old-hash"]
        if old_hash["signature_hex"] != baseline["signature_hex"]: raise ValueError("old advertised hash signature changed")
    return records


def collect_records(wire, source, patches):
    wanted = {v["id"]: v for v in vectors()}; records, pending = {}, {}
    for line in wire.splitlines():
        event = json.loads(line, object_pairs_hook=vm.unique_object)
        if type(event) is not dict or event.get("Package") != PACKAGE: raise ValueError("unselected source package")
        output, name = event.get("Output", ""), event.get("Test")
        if type(output) is not str: raise ValueError("invalid source fragment")
        if pending and event.get("Action") == "output" and name not in pending: raise ValueError("interleaved source record")
        if PREFIX in output:
            if (output.count(PREFIX) != 1 or name in pending or event.get("Action") != "output"
                    or re.match(r"^    zz_research_nom_account_context_test.go:[0-9]+: " + PREFIX, output) is None):
                raise ValueError("ambiguous source record")
            pending[name] = output.split(PREFIX, 1)[1]
        elif name in pending:
            if event.get("Action") != "output": raise ValueError("truncated source record")
            pending[name] += output
        else: continue
        if len(pending[name]) > 131072: raise ValueError("oversized context record")
        if not pending[name].endswith("\n"): continue
        r = json.loads(pending.pop(name).strip(), object_pairs_hook=vm.unique_object)
        if type(r) is not dict or r.get("id") not in wanted or r["id"] in records or name != TEST + "/" + r["id"]:
            raise ValueError("unselected or duplicate record")
        records[r["id"]] = validate_record(r, wanted[r["id"]], source, patches)
    if pending: raise ValueError("incomplete source framing")
    return validate_records(records, source, patches)


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=vm.unique_object)
    if (manifest["schema"] != "zenon-nom-account-context-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != CORE_COMMIT or manifest["expected_counts"] != COUNTS
            or set(manifest["input_sha256"]) != set(SELECTED)
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("selected account context subject changed")
    auth.inputs(root)
    if fixture != corpus(validate_records(fixture["records"], frozen_source(root), frozen_patches(root)), frozen_patches(root)):
        raise ValueError("selected context corpus differs")
    measured = {n: vm.digest(root / n) for n in (MANIFEST, *SELECTED, *manifest["preserved_file_sha256"])}
    if any(measured[n] != h for n, h in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items()):
        raise ValueError("selected or preserved input changed")
    return manifest, fixture, measured


def execute(checkout, go, root, evidence, source, patches):
    injected = checkout / "verifier/zz_research_nom_account_context_test.go"
    if injected.exists() or injected.is_symlink(): raise ValueError("overlay would replace existing input")
    retained = {}
    for name, value in (("source-handoff.json", {"schema": "zenon-nom-account-context-input-v1", "records": source, "patches": patches}),
            ("plan.json", {"schema": "zenon-nom-account-context-plan-v1", "vectors": vectors()}),
            ("overlay.json", {"Replace": {str(injected): str(root / DRIVER)}})):
        retained[name] = (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
        with private_create(evidence / name) as out: out.write(retained[name])
    environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off",
        PTLC_NOM_CONTEXT_SOURCE=str(evidence / "source-handoff.json"), PTLC_NOM_CONTEXT_PLAN=str(evidence / "plan.json"))
    wire = run([str(go), "test", "-json", "-overlay", str(evidence / "overlay.json"), "-vet=off", "-mod=readonly",
                "-count=1", "-run", "^" + TEST + "$", "./verifier"], environment=environment,
               directory=checkout, evidence=evidence, label="core-observation", timeout=240)
    passed = vm.selected_outcome(wire, expected_tests())
    if any((evidence / name).read_bytes() != value for name, value in retained.items()):
        raise ValueError("fresh source handoff changed")
    return wire, passed


def fresh_source(checkout, go, root, evidence):
    result = auth.qualify(checkout, go, root=root, evidence_parent=evidence / "authorization")
    subjects = list((evidence / "authorization").glob("account-authorization-*"))
    if len(subjects) != 1 or json.loads((subjects[0] / "outcome.json").read_text("ascii")) != result:
        raise ValueError("fresh authorization custody differs")
    path = subjects[0]; source_path = list((path / "source").glob("composed-vm-*"))
    if len(source_path) != 1: raise ValueError("fresh VM custody differs")
    raw = (source_path[0] / "core-wire.stdout").read_bytes()
    _, fixture, _ = vm.inputs(root)
    vm_records = vm.collect_vm_records(raw, fixture, json.loads((root / vm.FUNDING).read_text("ascii")))
    source = auth.collect_records((path / "core-observation.stdout").read_bytes(), vm_records)
    patches = {leg: vm_records[leg + "-direct-success"]["receipt_patches"] for leg in ("long", "short")}
    return result, source, patches


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); vm.core_state(checkout, manifest); tool_hash = vm.digest(go)
    parent = evidence_parent or root / ".research-cache/nom-account-context-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="account-context-", dir=parent))
    result = {"schema": "zenon-nom-account-context-result-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
        "outcome": "UNKNOWN", **BOUNDARY, "input_sha256": before, "go_executable_sha256": tool_hash,
        "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
        "stream_custody": "Original private source streams and handoffs; hosted custody may be ephemeral"}
    try:
        source_result, source, patches = fresh_source(checkout, go, root, evidence)
        wire, passed = execute(checkout, go, root, evidence, source, patches)
        if fixture != corpus(collect_records(wire, source, patches), patches): raise ValueError("fresh context projection differs")
        vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != vm.digest(go): raise ValueError("selected subject changed during qualification")
        result.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=source_result,
            passed_context_tests_including_parent=passed, fresh_projection="MATCH; ALL 84 CONTROLS FROM FRESH AUTHORIZATION AND VM RECORDS",
            semantic_predecessor="BATCH PARENT USES FIRST CHILD PREDECESSOR; HEADER PREDECESSOR DIFFERS",
            disconnected_originals="FUNDING AND UNLOCK USER ORIGINALS HAVE NO MATCHING SELECTED ACCOUNT FRONTIER",
            signed_successors="DIFFERENT FUNDING IDS AND ORIGINALS; NO INNER WITNESSES OR VM EXECUTION FOR NEW SUBJECT",
            exact_replay="CEMENTED FRONTIER AND ACTUAL VM RECEIVED MARKER ARE SEPARATE REFUSALS",
            selected_descendant_gap="PARENT HASH BINDS ADVERTISED CHILD HASH; SELECTED CHILD STRUCTURAL CHECK DOES NOT RECOMPUTE IT",
            complete_admission="NOT ESTABLISHED; SUPERVISOR, VM, PLASMA, ACCOUNT POOL AND MOMENTUM ADMISSION ARE SEPARATE")
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
        print("FAIL: account context; preserve original private evidence", file=sys.stderr); return 1


if __name__ == "__main__":
    sys.exit(main())
