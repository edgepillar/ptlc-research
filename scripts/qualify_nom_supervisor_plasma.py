#!/usr/bin/env python3
"""Compare selected supervisor originals and per-transaction deltas offline.

Synthetic chain/cache views are not complete admission, authority, finality,
original custody, application signing or recovery permission. No fixture fallback.
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
from scripts import qualify_nom_bilateral_graph as prior, qualify_nom_vm_path as vm
from scripts.generate_nom_supervisor_plasma import PROFILE, INPUT, COMPLETIONS, FIXTURE, BOUNDARY, CASES, HEIGHT, BASES, FUSION_AMOUNT, CAPACITY, inputs as public_inputs, corpus, tag
from scripts.nom_native_command import private_create, run

MANIFEST = "compatibility/nom_supervisor_plasma_manifest.json"
DRIVER = "compatibility/nom_supervisor_plasma_test.go.txt"
RUST = "qualification/tests/nom_supervisor_graph.rs"
TEST = "TestResearchNoMSupervisorPlasma"
PACKAGE = prior.PACKAGE
PREFIX = "PTLC_RESEARCH_SUPERVISOR_RECORD "
SELECTED = (INPUT, COMPLETIONS, FIXTURE, DRIVER, RUST, "scripts/generate_nom_supervisor_plasma.py",
            "scripts/qualify_nom_supervisor_plasma.py", "tests/test_nom_supervisor_plasma.py")
COUNTS = {"parties": 2, "shared_contract_accounts": 1, "graph_cases": 2, "graph_steps": 22,
          "selected_controls": 24, "refusal_controls": 22, "unbound_user_changes_observations": 2,
          "supervisor_tests_including_parent": 3, "preserved_source_tests_including_parents": 275,
          "total_source_tests_including_parents": 278}
PATCH_FORMAT_SOURCE = {
    "repository": "https://github.com/syndtr/goleveldb", "commit": "2ae1ddf74ef7020251ff1ff0fe8daac21a157761",
    "module": "github.com/syndtr/goleveldb", "version": "v1.0.1-0.20210819022825-2ae1ddf74ef7",
    "license": "BSD-2-Clause; separately obtained, format read, no implementation copied",
    "file_sha256": {"leveldb/batch.go": "299129fbb88354f140bd7e7c83ffda6554e9af906ab68589f72e7c212f49c096",
                    "LICENSE": "7df695202f82a52f8891a9913438c7fde15bd71034fd1853b9ed46503ea52a19"},
}
STEP_FIELDS = ((prior.STEP_FIELDS - {"after_vm_patch_hex", "after_vm_patch_sha256"}) |
               {"after_commit_patch_hex", "after_commit_patch_sha256", "delta_patch_hex", "delta_patch_sha256",
                "applied_wire_hex", "applied_delta_hex", "generation_signatures", "apply_signatures", "plasma"})
CONTROL_FIELDS = {"id", "block", "returned_error", "transaction_present", "returned_delta_hex", "returned_patch_hash_hex",
                  "before_patch_hex", "after_patch_hex", "before_balances", "after_balances", "frontier",
                  "before_received_marker", "after_received_marker", "before_mailbox_head", "after_mailbox_head",
                  "fusion_depleted", "original_wire_hex"}
PLASMA_FIELDS = {"canonical_base", "base", "total", "before_used", "after_used", "available_before", "available_after",
                 "fusion_amount", "committed", "dynamic"}
hh, bounded, labels = prior.hh, prior.bounded, prior.labels


def expected_tests():
    return {PACKAGE: {TEST, *(TEST + "/" + kind for kind in CASES)}}


def decode_patch(value):
    """Independent bounded reader of selected headerless LevelDB batch records.

    Record format: one opcode, unsigned base-128 key length, key bytes, and
    for a put, unsigned base-128 value length and value bytes. This reader is
    deliberately stricter than a general native decoder. No source is copied.
    """
    data = bounded(value, 65536); pos = 0; operations = []; seen = set()

    def length():
        nonlocal pos
        number = 0
        for index in range(3):
            if pos >= len(data): raise ValueError("truncated batch length")
            byte = data[pos]; pos += 1; number |= (byte & 127) << (7 * index)
            if byte < 128:
                if (index and byte == 0) or number > 65536: raise ValueError("unselected batch length")
                return number
        raise ValueError("overlong batch length")

    def field():
        nonlocal pos
        n = length()
        if n > len(data) - pos: raise ValueError("truncated batch field")
        result = data[pos:pos+n]; pos += n; return result

    while pos < len(data):
        opcode = data[pos]; pos += 1
        if opcode not in (0, 1) or len(operations) >= 256: raise ValueError("unselected batch operation")
        key = field()
        if not key or len(key) > 8192 or key in seen: raise ValueError("unselected or duplicate batch key")
        seen.add(key); operations.append((key, field() if opcode else None))
    return operations


def replay(state, operations):
    state = dict(state)
    for key, value in operations:
        if value is None: state.pop(key, None)
        else: state[key] = value
    return state


def validate_delta(s, before_used, role, terms):
    r = s["block"]; b = r["block"]; embedded = b["address_hex"] == CONTRACT_HEX
    delta = bounded(s["delta_patch_hex"], 65536)
    if (not delta or hashlib.sha256(delta).hexdigest() != s["delta_patch_sha256"]
            or hashlib.sha3_256(delta).hexdigest() != r["changes_hash_hex"]
            or s["applied_wire_hex"] != r["wire_hex"] or s["applied_delta_hex"] != s["delta_patch_hex"]):
        raise ValueError("generated original or per-transaction patch reproduction differs")
    if (type(s["generation_signatures"]) is not int or s["generation_signatures"] != (0 if embedded else 1)
            or type(s["apply_signatures"]) is not int or s["apply_signatures"] != 0):
        raise ValueError("apply must use the preserved public original without signing")
    before = replay({}, decode_patch(s["before_patch_hex"]))
    after_commit = replay(before, decode_patch(s["delta_patch_hex"]))
    if after_commit != replay({}, decode_patch(s["after_commit_patch_hex"])):
        raise ValueError("independent delta replay differs from actual committed memory")
    height = int(b["height"]).to_bytes(8, "big"); ident = bytes.fromhex(r["hash_hex"])
    after_adopt = dict(after_commit)
    # HashHeight.Serialize is a nested protobuf HashProto, not HashHeight.Bytes.
    value = int(b["height"]); encoded_height = bytearray()
    while value > 127: encoded_height.append((value & 127) | 128); value >>= 7
    encoded_height.append(value)
    serialized_identifier = b"\x0a\x22\x0a\x20" + ident + b"\x10" + encoded_height
    after_adopt.update({b"\0": serialized_identifier, b"\1" + ident: height, b"\2" + height: bytes.fromhex(r["wire_hex"])})
    if after_adopt != replay({}, decode_patch(s["after_adopt_patch_hex"])):
        raise ValueError("frontier adoption differs from exactly three selected writes")
    base = 0 if embedded else BASES["Create" if s["label"].endswith("funding") else "Receive" if b["block_type"] == "3" else "Unlock"]
    used = before_used + base
    p = s["plasma"]
    expected = {"canonical_base": str(base), "base": str(base), "total": str(base), "before_used": str(before_used),
                "after_used": str(used), "available_before": "0" if embedded else str(CAPACITY-before_used),
                "available_after": "0" if embedded else str(CAPACITY-used), "fusion_amount": str(FUSION_AMOUNT),
                "committed": "0", "dynamic": False}
    if (type(p) is not dict or set(p) != PLASMA_FIELDS or type(p["dynamic"]) is not bool or p != expected
            or b["fused_plasma"] != str(base)):
        raise ValueError("selected canonical legacy Plasma or budget accounting differs")
    if int.from_bytes(after_commit.get(b"\5", b""), "big") != used or int.from_bytes(before.get(b"\5", b""), "big") != before_used:
        raise ValueError("actual chain Plasma memory differs")
    for leg in ("long", "short"):
        key = b"\3" + bytes.fromhex(terms[leg]["token_standard_hex"])
        if int.from_bytes(after_commit.get(key, b""), "big") != int(s["after_balances"][role][leg]):
            raise ValueError("actual patch balance differs from accounting")
    if b["block_type"] == "3" and int.from_bytes(after_commit.get(b"\6" + bytes.fromhex(b["from_block_hash_hex"]), b""), "big") != 1:
        raise ValueError("receipt marker missing from actual delta")


def validate_controls(controls, selected, blocks, payouts, raw_fixture, steps):
    expected = ["raw-original-without-plasma", "depleted-fusion-original", "unsigned-original", "bad-outer-signature",
                "insufficient-token-budget", "user-advertised-changes-unbound", "contract-advertised-changes-refuse",
                "short-wrong-receiver", "short-exact-replay", "short-new-receipt-same-payout",
                "long-exact-replay", "long-new-receipt-same-payout"]
    if type(controls) is not list or [c.get("id") for c in controls] != expected: raise ValueError("complete supervisor controls required")
    errors = ["ErrNotEnoughTotalPlasma", "ErrNotEnoughPlasma", "ErrABSignatureMissing", "ErrABSignatureInvalid",
              "ErrInsufficientBalance", "PASS", "ErrEmbeddedChangesHash", "ErrABFromBlockReceiverMismatch",
              "ErrABPrevHasCementedOnTop", "ErrABFromBlockAlreadyReceived", "ErrABPrevHasCementedOnTop", "ErrABFromBlockAlreadyReceived"]
    for c, error in zip(controls, errors):
        if type(c) is not dict or set(c) != CONTROL_FIELDS: raise ValueError("unselected supervisor control fields")
        name = c["id"]; r = c["block"]; b = r["block"]
        checked = copy.deepcopy(r)
        if name == "unsigned-original":
            if r["signature_hex"] != "": raise ValueError("unsigned control differs")
            checked["signature_hex"] = blocks["long-funding"]["signature_hex"]
        prior.validate_block(checked)
        if (c["returned_error"] != error or type(c["transaction_present"]) is not bool or c["transaction_present"] != (error == "PASS")
                or type(c["fusion_depleted"]) is not bool or c["fusion_depleted"] != (name == "depleted-fusion-original")
                or c["original_wire_hex"] != r["wire_hex"] or c["before_patch_hex"] != c["after_patch_hex"]
                or c["before_balances"] != c["after_balances"] or c["before_received_marker"] != c["after_received_marker"]
                or c["before_mailbox_head"] != c["after_mailbox_head"]
                or type(c["after_received_marker"]) is not bool):
            raise ValueError("control changed original or adopted memory state")
        decode_patch(c["before_patch_hex"])
        context = steps["long-funding"] if name in expected[:6] else steps["short-create"] if name == expected[6] else steps["short-receipt"] if name == expected[7] else steps[name.split("-")[0] + "-receipt"]
        after = name not in expected[:8]
        memory = steps["long-unlock-send"] if name == expected[7] else context
        field = "after_adopt_patch_hex" if after else "before_patch_hex"
        want_frontier = context["after_frontier" if after else "before_frontier"]
        if name == expected[7]: want_frontier = memory["before_frontier"]
        if (c["before_patch_hex"] != memory[field] or c["frontier"] != want_frontier
                or c["before_balances"] != context["after_balances" if after else "before_balances"]
                or c["before_mailbox_head"] != (context["before_mailbox_head"] if name == expected[6] else None)
                or type(c["before_received_marker"]) is not bool or c["before_received_marker"] != after):
            raise ValueError("control does not retain the actual selected trace context")
        if error == "PASS":
            delta = bounded(c["returned_delta_hex"], 65536)
            if not delta or c["returned_patch_hash_hex"] != hashlib.sha3_256(delta).hexdigest() or c["returned_patch_hash_hex"] == r["changes_hash_hex"]:
                raise ValueError("unbound user changes must remain an explicit scoped observation")
            if c["returned_delta_hex"] != steps["long-funding"]["delta_patch_hex"]:
                raise ValueError("accepted but unadopted user delta differs from the actual source delta")
        elif c["returned_delta_hex"] or c["returned_patch_hash_hex"]: raise ValueError("refusal must return no transaction")
        if name == expected[0]:
            if r != raw_fixture or r["hash_hex"] != selected["old_funding_ids_hex"]["long"]: raise ValueError("raw original was upgraded or replaced")
        elif name in expected[1:6]:
            original = blocks["long-funding"]
            want = copy.deepcopy(original["block"])
            if name == "insufficient-token-budget": want["amount"] = "201"
            if b != want or r["public_key_hex"] != original["public_key_hex"]: raise ValueError("funding control selection differs")
            if name == "depleted-fusion-original" and r != original: raise ValueError("depleted attempt replaced its exact original")
            if name == "bad-outer-signature":
                sig = bytearray.fromhex(original["signature_hex"]); sig[0] ^= 1
                if r["signature_hex"] != sig.hex(): raise ValueError("bad outer signature selection differs")
            if name == "user-advertised-changes-unbound":
                changed = bytearray.fromhex(original["changes_hash_hex"]); changed[0] ^= 1
                if r["changes_hash_hex"] != changed.hex() or r["signature_hex"] != original["signature_hex"]: raise ValueError("unbound header control differs")
        elif name == expected[6]:
            original = blocks["short-create"]; changed = bytearray.fromhex(original["changes_hash_hex"]); changed[0] ^= 1
            if b != original["block"] or r["changes_hash_hex"] != changed.hex(): raise ValueError("contract changes control differs")
        elif name == expected[7]:
            if b["address_hex"] != selected["terms"]["bob_address_hex"] or b["from_block_hash_hex"] != payouts["short"]["hash_hex"]: raise ValueError("wrong receiver selection differs")
        else:
            leg = name.split("-")[0]; original = blocks[leg + "-receipt"]
            if c["frontier"] != {"identifier": hh(original["hash_hex"], original["block"]["height"]), "wire_hex": original["wire_hex"]} or c["before_received_marker"] is not True:
                raise ValueError("post-receipt context differs")
            if name.endswith("exact-replay") and r != original: raise ValueError("receipt replay replaced original")
            if name.endswith("same-payout") and (r["semantic_previous"] != c["frontier"]["identifier"] or b["from_block_hash_hex"] != original["block"]["from_block_hash_hex"] or r["wire_hex"] == original["wire_hex"]):
                raise ValueError("new refused receipt is not a distinct successor")



def validate_record(record, selected, completed, old):
    if (type(record) is not dict or set(record) != {"schema", "id", "trace", "controls", "final_balances", "entries_present"}
            or record["schema"] != "zenon-nom-supervisor-record-v1" or record["id"] not in CASES
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
    patches = {}; blocks = {}; payouts = {}; used = {a: 0 for a in roles}
    if type(record["trace"]) is not list or [s.get("label") for s in record["trace"]] != labels(kind):
        raise ValueError("complete ordered bilateral trace required")
    for s in record["trace"]:
        if type(s) is not dict or set(s) != STEP_FIELDS: raise ValueError("unselected step fields")
        name = s["label"]; r = prior.validate_block(s["block"]); b = r["block"]; a = b["address_hex"]
        if a not in roles or s["checks"] != {"structural": "PASS", "transaction": "PASS"}:
            raise ValueError("unselected step account or verifier result")
        if (s["before_frontier"] != frontiers[a] or r["semantic_previous"] != frontiers[a]["identifier"]
                or s["before_balances"] != balances):
            raise ValueError("actual shared predecessor or accounting discontinuity")
        for field in ("before", "after_commit", "after_adopt"):
            p = bounded(s[field + "_patch_hex"], 65536)
            if hashlib.sha256(p).hexdigest() != s[field + "_patch_sha256"]:
                raise ValueError("retained memory patch digest differs")
        if a in patches and s["before_patch_hex"] != patches[a]:
            raise ValueError("same account memory state discontinuity")
        validate_delta(s, used[a], roles[a], terms)
        used[a] += int(b["fused_plasma"])
        if s["after_adopt_patch_hex"] == s["after_commit_patch_hex"]:
            raise ValueError("selected frontier adoption is missing")
        if b["version"] != "1" or b["chain_id"] != terms["chain_id"] or b["difficulty"] != "0":
            raise ValueError("selected supervisor header differs")
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
    validate_controls(record["controls"], selected, blocks, payouts, old["raw_original_block"], {s["label"]: s for s in record["trace"]})
    return record


def validate_records(records, selected, completed, old):
    if type(records) is not dict or set(records) != set(CASES): raise ValueError("complete supervisor source selection required")
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
                    or re.match(r"^    zz_research_nom_supervisor_plasma_test.go:[0-9]+: " + PREFIX, output) is None):
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
    old = json.loads((root / prior.COMPLETIONS).read_text("ascii"), object_pairs_hook=vm.unique_object)
    old["raw_original_block"] = json.loads((root / prior.FIXTURE).read_text("ascii"), object_pairs_hook=vm.unique_object)["records"]["complete"]["trace"][0]["block"]
    if selected != public_inputs(root): raise ValueError("new public subject differs")
    if (set(completed) != {"schema", "pair", "long_message_hex", "short_message_hex", "long_signature_hex", "short_signature_hex"}
            or completed["schema"] != "ptlc-nom-supervisor-public-completions-v1"):
        raise ValueError("unselected completion fields")
    for leg in ("long", "short"):
        term = selected["terms"][leg]
        msg = unlock_message({"profile": "zenon-ptlc-unlock:v1", "chain_id": selected["terms"]["chain_id"],
                              "point_type": 1, "entry_id_hex": term["entry_id_hex"],
                              "destination_hex": selected["terms"][term["recipient"] + "_address_hex"]})
        if completed[leg + "_message_hex"] != msg or completed[leg + "_signature_hex"] == old[leg + "_signature_hex"]:
            raise ValueError("old inner witness cannot be inherited")
        prior.prior.auth.byte_value(completed[leg + "_signature_hex"], 64)
    return selected, completed, old


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=vm.unique_object)
    if (manifest["schema"] != "zenon-nom-supervisor-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != CORE_COMMIT or manifest["expected_counts"] != COUNTS
            or manifest["patch_format_source"] != PATCH_FORMAT_SOURCE
            or set(manifest["input_sha256"]) != set(SELECTED)
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("selected supervisor manifest differs")
    prior.inputs(root); selected, completed, old = selected_inputs(root)
    if fixture != corpus(validate_records(fixture["records"], selected, completed, old)):
        raise ValueError("complete selected graph differs")
    measured = {n: vm.digest(root / n) for n in (MANIFEST, *SELECTED, *manifest["preserved_file_sha256"])}
    if any(measured[n] != h for n, h in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items()):
        raise ValueError("selected or preserved graph input changed")
    return manifest, fixture, measured


def execute(checkout, go, root, evidence):
    injected = checkout / "vm/zz_research_nom_supervisor_plasma_test.go"
    if injected.exists() or injected.is_symlink(): raise ValueError("overlay would replace existing input")
    value = (json.dumps({"Replace": {str(injected): str(root / DRIVER)}}, sort_keys=True) + "\n").encode("ascii")
    with private_create(evidence / "overlay.json") as out: out.write(value)
    retained = {}
    environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
    for name, selected in (("INPUT", INPUT), ("COMPLETIONS", COMPLETIONS), ("OLD", prior.COMPLETIONS), ("RAW", prior.FIXTURE)):
        retained[name] = (root / selected).read_bytes()
        path = evidence / (name.lower() + "-handoff.json")
        with private_create(path) as out: out.write(retained[name])
        environment["PTLC_NOM_SUPERVISOR_" + name] = str(path)
    wire = run([str(go), "test", "-json", "-overlay", str(evidence / "overlay.json"), "-vet=off", "-mod=readonly",
                "-count=1", "-run", "^" + TEST + "$", "./vm"], environment=environment,
               directory=checkout, evidence=evidence, label="core-observation", timeout=240)
    passed = vm.selected_outcome(wire, expected_tests())
    if (evidence / "overlay.json").read_bytes() != value or any((evidence / (n.lower() + "-handoff.json")).read_bytes() != b for n, b in retained.items()):
        raise ValueError("exact graph handoff changed")
    return wire, passed


def check_patch_format(go, manifest, evidence):
    environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
    selected = manifest["patch_format_source"]
    cache_wire = run([str(go), "env", "GOMODCACHE"], environment=environment,
                     directory=ROOT, evidence=evidence, label="build", timeout=30)
    cache = Path(cache_wire.decode("utf-8").strip())
    if not cache.is_absolute() or not cache.is_dir(): raise ValueError("selected module cache unavailable")
    directory = cache / (selected["module"] + "@" + selected["version"])
    measured = {name: vm.digest(directory / name) for name in selected["file_sha256"]}
    if measured != selected["file_sha256"]: raise ValueError("selected patch format source differs")
    return measured


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); vm.core_state(checkout, manifest); tool_hash = vm.digest(go)
    parent = evidence_parent or root / ".research-cache/nom-supervisor-graph-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="supervisor-graph-", dir=parent))
    result = {"schema": "zenon-nom-supervisor-result-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
              "outcome": "UNKNOWN", **BOUNDARY, "input_sha256": before, "go_executable_sha256": tool_hash,
              "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
              "stream_custody": "Original private streams and handoffs; hosted private custody may be ephemeral"}
    try:
        source_result = prior.qualify(checkout, go, root=root, evidence_parent=evidence / "account-context")
        patch_source = check_patch_format(go, manifest, evidence)
        wire, passed = execute(checkout, go, root, evidence)
        if (source_result["outcome"] != "PASS" or source_result["counts"] != prior.COUNTS
                or source_result["tests_passed_including_parents"] != 275):
            raise ValueError("complete preserved source comparison required")
        if fixture != corpus(collect_records(wire, *selected_inputs(root))): raise ValueError("fresh graph differs from public selection")
        vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != vm.digest(go): raise ValueError("selected input changed during qualification")
        result.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=source_result,
                      patch_format_source_sha256=patch_source,
                      supervisor_tests_including_parent=passed, tests_passed_including_parents=passed + 275,
                      graph_steps=22, selected_controls=24, refusal_controls=22, unbound_user_changes_observations=2, public_recovery="SEPARATE RUST TEST COMPARISON; NO JOURNAL COMPOSITION")
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
        print("FAIL: supervisor graph; preserve original private evidence", file=sys.stderr); return 1


if __name__ == "__main__":
    sys.exit(main())
