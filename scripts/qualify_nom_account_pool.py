#!/usr/bin/env python3
"""Compare preserved originals with actual public account-pool memory behavior.

No activation, authenticated rollback, production caller execution or recovery
authority. Failed native runs retain evidence and never fall back to a fixture.
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
from offline_session.pr138 import CORE_COMMIT, CONTRACT_HEX
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_supervisor_plasma as prior
from scripts.generate_nom_account_pool import PROFILE, BASE, FIXTURE, CASES, BOUNDARY, corpus
from scripts.nom_native_command import private_create, run

MANIFEST = "compatibility/nom_account_pool_manifest.json"
DRIVER = "compatibility/nom_account_pool_test.go.txt"
TEST = "TestResearchNoMAccountPool"
PACKAGE = prior.PACKAGE
PREFIX = "PTLC_RESEARCH_POOL_RECORD "
SELECTED = (FIXTURE, DRIVER, "scripts/generate_nom_account_pool.py",
            "scripts/qualify_nom_account_pool.py", "tests/test_nom_account_pool.py")
COUNTS = {"graph_cases": 2, "normal_admissions": 22, "exact_duplicates": 22,
          "changed_wire_same_identifier_duplicates": 13, "missing_locker_refusals": 2,
          "selected_delete_callbacks": 2, "pre_rollback_child_aliases": 4,
          "post_rollback_queries": 26, "post_rollback_child_aliases": 4,
          "pool_tests_including_parent": 3, "preserved_source_tests_including_parents": 278,
          "total_source_tests_including_parents": 281}
RECORD_FIELDS = {"schema", "id", "initial_stable_state", "final_stable_state", "trace", "before_rollback",
                 "after_rollback", "rollback_callback", "remaining_pending_wires", "post_rollback_views", "signing_calls"}
STEP_FIELDS = {"label", "original_wire_hex", "original_wire_sha256", "applied_wire_hex", "delta_patch_hex",
               "before_state_dump_hex", "after_state_dump_hex", "frontier_before", "frontier_after", "result",
               "base_plasma", "total_plasma", "transaction_changes_stolen", "retained_augmented_patch_hex",
               "stored_pool_patch_hex", "duplicate", "changed_wire_duplicate", "nil_locker", "child_views"}
VIEW_FIELDS = {"requested_identifier", "present", "patch_present", "patch_hex", "frontier", "state_dump_hex"}
DUPLICATE_FIELDS = {"result", "changes_stolen", "state_sha256_before", "state_sha256_after"}
CHANGED_FIELDS = DUPLICATE_FIELDS | {"wire_hex", "hash_hex", "signature_hex", "changes_hash_hex", "stored_wire_hex"}
CORE_FILES = {"chain/account_pool.go", "chain/interface.go", "common/db/versioned_db.go", "common/db/store.go",
              "common/db/interfaces.go", "common/db/patch.go", "common/db/enable_delete.go", "common/db/merged.go",
              "chain/account/store.go", "chain/account/keys.go", "rpc/api/ledger.go", "protocol/chain_bridge.go",
              "protocol/broadcaster.go", "chain/momentum/ledger_store.go", "verifier/momentum.go"}


def expected_tests():
    return {PACKAGE: {TEST, *(TEST + "/" + kind for kind in CASES)}}


def varint(n):
    if type(n) is not int or not 0 <= n <= 65536: raise ValueError("unselected batch length")
    result = bytearray()
    while n > 127: result.append((n & 127) | 128); n >>= 7
    result.append(n)
    return bytes(result)


def encode_operations(operations):
    result = bytearray()
    for key, value in operations:
        result.append(0 if value is None else 1)
        result.extend(varint(len(key))); result.extend(key)
        if value is not None: result.extend(varint(len(value))); result.extend(value)
    return bytes(result)


def ordered_patch(value):
    """Independent selected batch reader; repeated frontier writes retain order.

    Unlike the preserved unique-key delta reader, augmented batch records may
    contain a frontier key once for each child and once for the parent. Bounds,
    canonical lengths, complete bytes and exact operation order are required.
    """
    data = prior.bounded(value, 65536); pos = 0; operations = []
    def field():
        nonlocal pos
        n = 0
        for i in range(3):
            if pos == len(data): raise ValueError("truncated batch length")
            v = data[pos]; pos += 1; n |= (v & 127) << (7 * i)
            if v < 128:
                if (i and v == 0) or n > 65536: raise ValueError("unselected batch length")
                break
        else: raise ValueError("overlong batch length")
        if n > len(data)-pos: raise ValueError("truncated batch field")
        b = data[pos:pos+n]; pos += n
        return b
    while pos < len(data):
        opcode = data[pos]; pos += 1
        if opcode not in (0, 1) or len(operations) == 400: raise ValueError("unselected batch operation")
        key = field()
        if not key or len(key) > 8192: raise ValueError("unselected batch key")
        operations.append((key, field() if opcode else None))
    if encode_operations(operations) != data: raise ValueError("batch framing differs")
    return operations


def state(value):
    operations = prior.decode_patch(value)
    if any(v is None for _, v in operations) or [k for k, _ in operations] != sorted(k for k, _ in operations):
        raise ValueError("complete sorted logical view required")
    return dict(operations)


def frontier(r=None):
    return {"identifier": prior.hh() if r is None else prior.hh(r["hash_hex"], r["block"]["height"]),
            "wire_hex": "" if r is None else r["wire_hex"]}


def frontier_operations(r):
    height = int(r["block"]["height"]); h = bytes.fromhex(r["hash_hex"])
    # The independently selected source HashHeight protobuf wraps HashProto.
    value = b"\x0a\x22\x0a\x20" + h + b"\x10" + varint(height)
    return [(b"\0", value), (b"\1" + h, height.to_bytes(8, "big")),
            (b"\2" + height.to_bytes(8, "big"), bytes.fromhex(r["wire_hex"]))]


def check_duplicate(d, after):
    if (type(d) is not dict or set(d) != DUPLICATE_FIELDS or d["result"] != "PASS"
            or d["changes_stolen"] is not False
            or d["state_sha256_before"] != d["state_sha256_after"]
            or d["state_sha256_before"] != hashlib.sha256(bytes.fromhex(after)).hexdigest()):
        raise ValueError("duplicate changed selected state or consumed a delta")


def check_view(v, requested, returned, logical_state, patch_hex):
    if (type(v) is not dict or set(v) != VIEW_FIELDS
            or v["requested_identifier"] != frontier(requested)["identifier"]
            or v["present"] is not (returned is not None) or v["patch_present"] is not (patch_hex is not None)
            or v["patch_hex"] != (patch_hex or "")
            or v["frontier"] != (frontier(returned) if returned is not None else None)):
        raise ValueError("actual selected version lookup differs")
    if returned is None:
        if v["state_dump_hex"]: raise ValueError("missing view invented state")
    elif state(v["state_dump_hex"]) != logical_state:
        raise ValueError("lookup state differs from exact retained version")


def validate_record(record, original):
    if (type(record) is not dict or set(record) != RECORD_FIELDS
            or record["schema"] != "zenon-nom-account-pool-record-v1" or record["id"] not in CASES
            or type(record["signing_calls"]) is not int or record["signing_calls"] != 0):
        raise ValueError("unselected pool record or signing")
    roles = {original["trace"][i]["block"]["block"]["address_hex"]: role for i, role in enumerate(("alice", "bob"))}
    roles[CONTRACT_HEX] = "contract"
    initial, models, fronts, history = {}, {}, {}, {}
    for s in original["trace"]:
        role = roles[s["block"]["block"]["address_hex"]]
        if role not in models:
            initial[role] = s["before_patch_hex"]; models[role] = state(initial[role]); fronts[role] = None
    if (record["initial_stable_state"] != initial or record["final_stable_state"] != initial
            or type(record["trace"]) is not list or len(record["trace"]) != len(original["trace"])):
        raise ValueError("stable input changed or complete trace missing")
    for index, (s, old) in enumerate(zip(record["trace"], original["trace"])):
        if type(s) is not dict or set(s) != STEP_FIELDS: raise ValueError("unselected pool step fields")
        r = old["block"]; b = r["block"]; role = roles[b["address_hex"]]
        if (s["label"] != old["label"] or s["original_wire_hex"] != r["wire_hex"]
                or s["original_wire_sha256"] != r["wire_sha256"] or s["applied_wire_hex"] != r["wire_hex"]
                or s["delta_patch_hex"] != old["delta_patch_hex"] or s["result"] != "PASS"
                or s["frontier_before"] != frontier(fronts[role]) or s["frontier_after"] != frontier(r)
                or s["base_plasma"] != old["plasma"]["base"] or s["total_plasma"] != old["plasma"]["total"]
                or s["transaction_changes_stolen"] is not True or state(s["before_state_dump_hex"]) != models[role]):
            raise ValueError("original, actual delta, source Plasma or predecessor differs")
        operations = prior.decode_patch(old["delta_patch_hex"])
        for commit in (*r["children"], r): operations += frontier_operations(commit)
        expected = encode_operations(operations).hex()
        if s["retained_augmented_patch_hex"] != expected or s["stored_pool_patch_hex"] != expected:
            raise ValueError("actual augmented patch must retain exact ordered frontier writes")
        if ordered_patch(expected) != operations: raise ValueError("ordered patch differs")
        models[role] = prior.replay(models[role], operations)
        if state(s["after_state_dump_hex"]) != models[role]: raise ValueError("actual complete logical replay differs")
        check_duplicate(s["duplicate"], s["after_state_dump_hex"])
        if index == 0:
            if (s["nil_locker"] != {"error": "ErrMissingInsertLocker", "changes_stolen": False, "state_unchanged": True}
                    or s["nil_locker"]["changes_stolen"] is not False or s["nil_locker"]["state_unchanged"] is not True):
                raise ValueError("missing-locker refusal required")
        elif s["nil_locker"] is not None: raise ValueError("unselected missing-locker observation")
        changed = s["changed_wire_duplicate"]
        if b["block_type"] == "5":
            if changed is not None: raise ValueError("unselected changed contract duplicate")
        else:
            if type(changed) is not dict or set(changed) != CHANGED_FIELDS: raise ValueError("selected changed-wire observation required")
            check_duplicate({k: changed[k] for k in DUPLICATE_FIELDS}, s["after_state_dump_hex"])
            source = bytes.fromhex(r["wire_hex"]); ch = bytes.fromhex(r["changes_hash_hex"]); other = bytes([ch[0] ^ 1]) + ch[1:]
            if (source.count(ch) != 1 or changed["wire_hex"] != source.replace(ch, other).hex()
                    or changed["wire_hex"] == r["wire_hex"] or changed["hash_hex"] != r["hash_hex"]
                    or changed["signature_hex"] != r["signature_hex"] or changed["changes_hash_hex"] != other.hex()
                    or changed["stored_wire_hex"] != r["wire_hex"]):
                raise ValueError("identifier idempotence was promoted into byte identity")
        if type(s["child_views"]) is not list or len(s["child_views"]) != len(r["children"]):
            raise ValueError("complete actual child views required")
        for v, child in zip(s["child_views"], r["children"]):
            check_view(v, child, r, models[role], "")
        fronts[role] = r
        history[r["hash_hex"]] = (r, dict(models[role]), expected)
    if (type(record["before_rollback"]) is not dict or set(record["before_rollback"]) != set(models)
            or {k: state(v) for k, v in record["before_rollback"].items()} != models):
        raise ValueError("complete pre-rollback state required")
    callback = {"popped_height": "10109301", "current_height": "10109300", "included_account_blocks": 0, "authenticated": False}
    if (record["rollback_callback"] != callback or record["rollback_callback"]["authenticated"] is not False
            or type(record["rollback_callback"]["included_account_blocks"]) is not int):
        raise ValueError("selected callback became an authenticated rollback")
    retained = {role: [] for role in models}; rolled = {role: state(initial[role]) for role in models}
    expected_queries = []
    for old in original["trace"]:
        r = old["block"]; role = roles[r["block"]["address_hex"]]; _, logical, patch_hex = history[r["hash_hex"]]
        if int(r["block"]["momentum_height"]) < 10109301:
            retained[role].extend(c["wire_hex"] for c in (*r["children"], r)); rolled[role] = logical
            expected_queries.append((r, r, logical, patch_hex))
        else: expected_queries.append((r, None, None, None))
        for child in r["children"]:
            # Source manager retains child aliases after popping their parent.
            # They describe old state and must never authorize current recovery.
            expected_queries.append((child, r, logical, ""))
    if (record["remaining_pending_wires"] != retained or type(record["after_rollback"]) is not dict
            or set(record["after_rollback"]) != set(rolled)
            or {k: state(v) for k, v in record["after_rollback"].items()} != rolled):
        raise ValueError("actual suffix truncation or restored balances differ")
    if type(record["post_rollback_views"]) is not list or len(record["post_rollback_views"]) != len(expected_queries):
        raise ValueError("complete post-rollback query set required")
    for v, expected in zip(record["post_rollback_views"], expected_queries): check_view(v, *expected)
    return record


def validate_records(records, originals):
    if type(records) is not dict or set(records) != set(CASES): raise ValueError("complete pool selection required")
    for name in CASES:
        if records[name].get("id") != name: raise ValueError("case identity differs")
        validate_record(records[name], originals["records"][name])
    return records


def collect_records(wire, originals):
    records, pending = {}, {}
    for line in wire.splitlines():
        event = json.loads(line, object_pairs_hook=prior.vm.unique_object)
        if type(event) is not dict or event.get("Package") != PACKAGE: raise ValueError("unselected native package")
        output, name = event.get("Output", ""), event.get("Test")
        if type(output) is not str: raise ValueError("invalid native output fragment")
        if pending and event.get("Action") == "output" and name not in pending: raise ValueError("interleaved source record")
        if PREFIX in output:
            if (output.count(PREFIX) != 1 or name in pending or event.get("Action") != "output"
                    or re.match(r"^    zz_research_nom_account_pool_test.go:[0-9]+: " + PREFIX, output) is None):
                raise ValueError("ambiguous native source record")
            pending[name] = output.split(PREFIX, 1)[1]
        elif name in pending:
            if event.get("Action") != "output": raise ValueError("truncated native source record")
            pending[name] += output
        else: continue
        if len(pending[name]) > 4194304: raise ValueError("native pool record exceeds bound")
        if not pending[name].endswith("\n"): continue
        r = json.loads(pending.pop(name).strip(), object_pairs_hook=prior.vm.unique_object)
        if type(r) is not dict or r.get("id") not in CASES or r["id"] in records or name != TEST + "/" + r["id"]:
            raise ValueError("unselected or duplicate pool record")
        records[r["id"]] = validate_record(r, originals["records"][r["id"]])
    if pending: raise ValueError("incomplete pool source framing")
    return validate_records(records, originals)


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=prior.vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=prior.vm.unique_object)
    if (manifest["schema"] != "zenon-nom-account-pool-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != CORE_COMMIT or manifest["expected_counts"] != COUNTS
            or manifest["research_baseline_commit"] != BASE or set(manifest["input_sha256"]) != set(SELECTED)
            or manifest["patch_format_source"] != prior.PATCH_FORMAT_SOURCE
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("selected pool manifest differs")
    old_manifest, old_fixture, preserved = prior.inputs(root)
    if manifest["preserved_file_sha256"] != preserved: raise ValueError("complete preserved profile required")
    if set(manifest["core_file_sha256"]) != (set(old_manifest["core_file_sha256"]) | CORE_FILES):
        raise ValueError("complete selected source file pins required")
    if fixture != corpus(validate_records(fixture["records"], old_fixture)): raise ValueError("complete pool corpus differs")
    measured = {n: prior.vm.digest(root / n) for n in (MANIFEST, *SELECTED, *preserved)}
    if any(measured[n] != h for n, h in {**manifest["input_sha256"], **preserved}.items()):
        raise ValueError("selected or preserved input changed")
    if any(manifest["core_file_sha256"].get(n) != h for n, h in old_manifest["core_file_sha256"].items()):
        raise ValueError("preserved source file pins required")
    return manifest, fixture, measured


def execute(checkout, go, root, evidence):
    replacements = {}
    for filename, source in (("zz_research_nom_account_pool_test.go", DRIVER),
                             ("zz_research_nom_supervisor_plasma_test.go", prior.DRIVER)):
        injected = checkout / "vm" / filename
        if injected.exists() or injected.is_symlink(): raise ValueError("overlay would replace existing input")
        replacements[str(injected)] = str(root / source)
    value = (json.dumps({"Replace": replacements}, sort_keys=True) + "\n").encode("ascii")
    with private_create(evidence / "overlay.json") as out: out.write(value)
    retained = {}; environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
    for name, selected in (("INPUT", prior.INPUT), ("ORIGINALS", prior.FIXTURE)):
        retained[name] = (root / selected).read_bytes(); path = evidence / (name.lower() + "-handoff.json")
        with private_create(path) as out: out.write(retained[name])
        environment["PTLC_NOM_POOL_" + name] = str(path)
    wire = run([str(go), "test", "-json", "-overlay", str(evidence / "overlay.json"), "-vet=off", "-mod=readonly",
                "-count=1", "-run", "^" + TEST + "$", "./vm"], environment=environment,
               directory=checkout, evidence=evidence, label="core-observation", timeout=240)
    passed = prior.vm.selected_outcome(wire, expected_tests())
    if (evidence / "overlay.json").read_bytes() != value or any((evidence / (n.lower() + "-handoff.json")).read_bytes() != b for n, b in retained.items()):
        raise ValueError("exact original handoff changed")
    return wire, passed


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); prior.vm.core_state(checkout, manifest); tool_hash = prior.vm.digest(go)
    parent = evidence_parent or root / ".research-cache/nom-account-pool-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="account-pool-", dir=parent))
    result = {"schema": "zenon-nom-account-pool-result-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
              "outcome": "UNKNOWN", **BOUNDARY, "input_sha256": before, "go_executable_sha256": tool_hash,
              "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
              "stream_custody": "Original private streams and handoffs; hosted private custody may be ephemeral"}
    try:
        source_result = prior.qualify(checkout, go, root=root, evidence_parent=evidence / "supervisor-context")
        patch_source = prior.check_patch_format(go, manifest, evidence)
        wire, passed = execute(checkout, go, root, evidence)
        if (source_result["outcome"] != "PASS" or source_result["counts"] != prior.COUNTS
                or source_result["tests_passed_including_parents"] != 278):
            raise ValueError("complete preserved source comparison required")
        if fixture != corpus(collect_records(wire, prior.inputs(root)[1])): raise ValueError("fresh pool behavior differs from selection")
        prior.vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != prior.vm.digest(go): raise ValueError("selected input changed during qualification")
        result.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=source_result,
                      patch_format_source_sha256=patch_source, pool_tests_including_parent=passed,
                      tests_passed_including_parents=passed + 278,
                      current_recovery_permission="NONE; PENDING POOL AND ALIASED HISTORICAL VIEWS ARE NOT AUTHORITY")
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
        print("FAIL: account pool; preserve original private evidence", file=sys.stderr); return 1


if __name__ == "__main__":
    sys.exit(main())
