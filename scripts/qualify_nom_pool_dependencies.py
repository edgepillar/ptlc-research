#!/usr/bin/env python3
"""Compare actual dependent receive eviction after explicit state reconstitution.

No momentum admission, authenticated rollback, application signing or recovery.
Failed native runs retain original evidence and never fall back to a fixture.
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
from offline_session.pr138 import CORE_COMMIT
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_pool_forks as prior
from scripts.generate_nom_pool_dependencies import PROFILE, BASE, FIXTURE, CASES, KEYS, BOUNDARY, corpus
from scripts.nom_native_command import private_create, run

MANIFEST = "compatibility/nom_pool_dependencies_manifest.json"
DRIVER = "compatibility/nom_pool_dependencies_test.go.txt"
TEST = "TestResearchNoMPoolDependencies"
PACKAGE = prior.PACKAGE
PREFIX = "PTLC_RESEARCH_POOL_DEPENDENCY_RECORD "
SELECTED = (FIXTURE, DRIVER, "scripts/generate_nom_pool_dependencies.py", "scripts/qualify_nom_pool_dependencies.py", "tests/test_nom_pool_dependencies.py")
CORE_FILES = {"chain/account/received.go", "chain/account/mailbox/mailbox.go", "chain/account/mailbox/keys.go",
              "chain/account_pool.go", "common/db/versioned_db.go", "verifier/account_block.go", "vm/vm.go"}
COUNTS = {"control_cases": 3, "generated_public_controls": 23, "normal_admissions": 23,
          "synthetic_stable_promotions": 3, "selected_insert_callbacks": 3, "selected_delete_callbacks": 3,
          "nonempty_send_callbacks": 2, "complete_dependent_manager_evictions": 2,
          "negative_control_recipient_prefixes_retained": 1, "unrelated_originals_retained": 6,
          "unrelated_stale_suffixes_removed": 3, "post_callback_queries": 23,
          "new_tests_including_parent": 4, "preserved_source_tests_including_parents": 287,
          "total_source_tests_including_parents": 291}
RECORD_FIELDS = {"schema", "id", "candidates", "trace", "checkpoints", "promotion_patch_hex", "rollback", "views", "signing_calls", "fusion_amount", "dynamic_plasma", "post_callback_action"}
CANDIDATE_FIELDS = prior.CANDIDATE_FIELDS | {"used_before"}
STEP_FIELDS = {"label", "result", "changes_stolen", "retained_patch_hex", "frontier_before", "frontier_after"}
VIEW_FIELDS = {"label", "present", "patch_present", "patch_hex", "frontier", "state_dump_hex"}
POOL = prior.prior
SUPERVISOR = POOL.prior
BLOCK = SUPERVISOR.prior


def expected_tests():
    return {PACKAGE: {TEST, *(TEST + "/" + n for n in CASES)}}


def momentum(i):
    return SUPERVISOR.hh(hashlib.sha3_256(("public-nom-pool-dependencies-v1:momentum-" + str(i)).encode("ascii")).hexdigest(), str(10109300 + i))


def logical(model):
    return POOL.encode_operations(sorted(model.items())).hex()


def candidate(c, role, previous, used, m, from_hash=None):
    if type(c) is not dict or set(c) != CANDIDATE_FIELDS: raise ValueError("unselected source candidate fields")
    r = BLOCK.validate_block(c["block"]); b = r["block"]
    expected = {"version": "1", "chain_id": "69", "block_type": "3" if from_hash else "2", "address_hex": KEYS[role][1],
                "to_address_hex": "00" * 20 if from_hash else KEYS["recipient"][1], "height": str(int(previous["height"]) + 1),
                "previous_hash_hex": previous["hash_hex"], "momentum_hash_hex": m["hash_hex"], "momentum_height": m["height"],
                "amount": "0", "token_standard_hex": "00" * 10, "from_block_hash_hex": from_hash or "00" * 32,
                "descendant_hashes_hex": [], "data_hex": "", "fused_plasma": "21000", "difficulty": "0", "nonce_hex": "00" * 8}
    if (b != expected or r["public_key_hex"] != KEYS[role][0] or r["children"] != []
            or type(c["generation_signatures"]) is not int or c["generation_signatures"] != 1
            or type(c["apply_signatures"]) is not int or c["apply_signatures"] != 0
            or c["base_plasma"] != "21000" or c["canonical_base"] != "21000" or c["total_plasma"] != "21000"
            or c["available_before"] != str(420000 - used) or c["used_before"] != str(used) or used + 21000 > 420000):
        raise ValueError("source generation, address, predecessor, cost or budget differs")
    operations = [(b"\x03" + bytes(10), bytes(32)), (b"\x05", (used + 21000).to_bytes(32, "big"))]
    if from_hash: operations.append((b"\x06" + bytes.fromhex(from_hash), (1).to_bytes(8, "big")))
    delta = POOL.encode_operations(operations)
    if (c["delta_patch_hex"] != delta.hex() or c["applied_delta_hex"] != delta.hex()
            or r["changes_hash_hex"] != hashlib.sha3_256(delta).hexdigest()
            or c["applied_wire_hex"] != r["wire_hex"] or prior.selected_wire(r, 21000, 21000).hex() != r["wire_hex"]):
        raise ValueError("independent exact VM delta, hash or protobuf encoding differs")
    return r, operations


def validate_record(record):
    if (type(record) is not dict or set(record) != RECORD_FIELDS or record["schema"] != "zenon-nom-pool-dependencies-record-v1"
            or record["id"] not in CASES or record["fusion_amount"] != "20000000000" or record["dynamic_plasma"] is not False
            or record["post_callback_action"] != BOUNDARY["post_callback_action"]):
        raise ValueError("unselected source dependency record")
    kind = record["id"]; names = ["recipient-prefix", "unrelated-prefix", "unrelated-second", "stable-send", "sender-pending", "dependent-receive"]
    if kind != "included-send-without-suffix": names.append("recipient-suffix")
    names.append("unrelated-stale")
    selected, checks = record["candidates"], record["checkpoints"]
    if (type(selected) is not dict or set(selected) != set(names) or type(record["trace"]) is not list or len(record["trace"]) != len(names)
            or type(record["signing_calls"]) is not int or record["signing_calls"] != len(names)
            or type(checks) is not dict or set(checks) != {"initial", "before-promotion", "after-promotion", "before-rollback", "reconstituted-before-callback", "after-callback"}):
        raise ValueError("complete candidates, trace, signing and checkpoints required")
    roles = tuple(KEYS); zero = SUPERVISOR.hh(); rows = {}; patches = {}; snapshots = {}; models = {n: {} for n in roles}
    stable = {n: {} for n in roles}; pending = {n: [] for n in roles}; used = {n: 0 for n in roles}; front = {n: zero for n in roles}

    def checkpoint(label, promoted=False, read_pool=True):
        expected = {}
        for role in roles:
            expected[role] = {"stable_frontier": rows["stable-send"]["semantic_id"] if promoted and role == "sender" else zero,
                              "stable_state_dump_hex": logical(stable[role])}
            if read_pool: expected[role].update(frontier=front[role], state_dump_hex=logical(models[role]), pending_wires=[rows[n]["wire_hex"] for n in pending[role]])
        send = rows.get("stable-send"); mailbox = []
        if promoted:
            h = bytes.fromhex(send["hash_hex"]); mailbox = [(b"\x04" + h, (1).to_bytes(8, "big")), (b"\x05" + h, (1).to_bytes(8, "big"))]
        expected["ledger"] = {"momentum": momentum(1 if promoted else 0), "send_wire_hex": send["wire_hex"] if promoted else "",
                              "confirmation_height": "10109301" if promoted else "0", "mailbox_dump_hex": POOL.encode_operations(mailbox).hex(),
                              "mailbox_pending_hashes": [send["hash_hex"]] if promoted else [], "mailbox_sequencer_size": "0",
                              "known_send_count": "1" if promoted else "0", "known_confirmation_count": "1" if promoted else "0"}
        if checks[label] != expected: raise ValueError("complete independent pool, stable, lookup, confirmation or mailbox checkpoint differs")

    checkpoint("initial")
    for i, name in enumerate(names):
        if i == 4:
            checkpoint("before-promotion")
            stable["sender"] = dict(models["sender"]); pending["sender"] = []
            if record["promotion_patch_hex"] != patches["stable-send"]: raise ValueError("exact selected stable promotion patch differs")
            for n in names[:3]: patches[n] += POOL.encode_operations(POOL.frontier_operations(rows[n])).hex()
            checkpoint("after-promotion", promoted=True)
        role = "recipient" if name.startswith("recipient") or name == "dependent-receive" else "unrelated" if name.startswith("unrelated") else "sender"
        from_hash = rows["stable-send"]["hash_hex"] if name == "dependent-receive" else None
        r, operations = candidate(selected[name], role, front[role], used[role], momentum(int(i >= 4)), from_hash)
        r = {**r, "semantic_id": SUPERVISOR.hh(r["hash_hex"], r["block"]["height"])}; rows[name] = r
        operations += POOL.frontier_operations(r); patch = POOL.encode_operations(operations).hex(); patches[name] = patch
        s = record["trace"][i]
        if (type(s) is not dict or set(s) != STEP_FIELDS or s["label"] != name or s["result"] != "PASS" or s["changes_stolen"] is not True
                or s["retained_patch_hex"] != patch or s["frontier_before"] != front[role] or s["frontier_after"] != r["semantic_id"]):
            raise ValueError("normal admission, exact ordered patch, predecessor or StealChanges differs")
        models[role] = SUPERVISOR.replay(models[role], operations); used[role] += 21000; front[role] = r["semantic_id"]
        pending[role].append(name); snapshots[name] = dict(models[role])
    checkpoint("before-rollback", promoted=True)
    stable = {n: {} for n in roles}
    checkpoint("reconstituted-before-callback", read_pool=False)
    if record["rollback"] != {"momentum": momentum(1), "included_wires": [] if kind == "empty-inclusion-control" else [rows["stable-send"]["wire_hex"]]}:
        raise ValueError("exact included rolled-back send or negative callback differs")
    survivors = ["unrelated-prefix", "unrelated-second"]
    if kind == "empty-inclusion-control": survivors.append("recipient-prefix")
    pending = {n: [] for n in roles}; front = {n: zero for n in roles}; models = {n: {} for n in roles}
    for n in survivors:
        role = "recipient" if n.startswith("recipient") else "unrelated"; pending[role].append(n); front[role] = rows[n]["semantic_id"]; models[role] = snapshots[n]
    checkpoint("after-callback")
    view_names = [n for n in ["stable-send", "sender-pending", "recipient-prefix", "dependent-receive", "recipient-suffix", "unrelated-prefix", "unrelated-second", "unrelated-stale"] if n in rows]
    if type(record["views"]) is not list or len(record["views"]) != len(view_names): raise ValueError("complete post-callback original queries required")
    for v, n in zip(record["views"], view_names):
        held = n in survivors
        expected = {"label": n, "present": held, "patch_present": held, "patch_hex": patches[n] if held else "",
                    "frontier": rows[n]["semantic_id"] if held else None, "state_dump_hex": logical(snapshots[n]) if held else ""}
        if (type(v) is not dict or set(v) != VIEW_FIELDS or type(v["present"]) is not bool or type(v["patch_present"]) is not bool or v != expected):
            raise ValueError("exact retained or removed historical view, state or rebuilt patch differs")
    return record


def validate_records(records):
    if type(records) is not dict or set(records) != set(CASES): raise ValueError("complete separate dependency cases required")
    for n in CASES:
        if type(records[n]) is not dict or records[n].get("id") != n: raise ValueError("selected source case identity differs")
        validate_record(records[n])
    return records


def collect_records(wire):
    records = {}; pending = {}
    for raw in wire.splitlines():
        e = json.loads(raw, object_pairs_hook=SUPERVISOR.vm.unique_object); out = e.get("Output", ""); name = e.get("Test")
        if PREFIX in out:
            if (e.get("Action") != "output" or e.get("Package") != PACKAGE or name not in expected_tests()[PACKAGE] or name in pending
                    or re.match(r"^    zz_research_nom_pool_dependencies_test.go:[0-9]+: " + PREFIX, out) is None):
                raise ValueError("ambiguous native dependency framing")
            pending[name] = out.split(PREFIX, 1)[1]
        elif name in pending:
            if e.get("Action") != "output" or e.get("Package") != PACKAGE: raise ValueError("truncated or wrong-package native record")
            pending[name] += out
        else: continue
        if len(pending[name]) > 8 * 1024 * 1024: raise ValueError("native dependency record exceeds unchanged bound")
        if not pending[name].endswith("\n"): continue
        r = json.loads(pending.pop(name).strip(), object_pairs_hook=SUPERVISOR.vm.unique_object)
        if type(r) is not dict or r.get("id") not in CASES or r["id"] in records or name != TEST + "/" + r["id"]:
            raise ValueError("unselected or duplicate dependency record")
        records[r["id"]] = validate_record(r)
    if pending: raise ValueError("incomplete native dependency record")
    return validate_records(records)


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=SUPERVISOR.vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=SUPERVISOR.vm.unique_object)
    old, _, preserved = prior.inputs(root)
    if (set(manifest) != set(old) or manifest["schema"] != "zenon-nom-pool-dependencies-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != CORE_COMMIT or manifest["research_baseline_commit"] != BASE or manifest["expected_counts"] != COUNTS
            or any(type(n) is not int for n in manifest["expected_counts"].values())
            or manifest["preserved_file_sha256"] != preserved or set(manifest["input_sha256"]) != set(SELECTED)
            or manifest["patch_format_source"] != old["patch_format_source"]
            or set(manifest["core_file_sha256"]) != (set(old["core_file_sha256"]) | CORE_FILES)
            or any(manifest["core_file_sha256"].get(n) != h for n, h in old["core_file_sha256"].items())
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("complete selected and preserved source manifest required")
    if fixture != corpus(validate_records(fixture["records"])): raise ValueError("complete dependency corpus differs")
    measured = {n: SUPERVISOR.vm.digest(root / n) for n in (MANIFEST, *SELECTED, *preserved)}
    if any(measured[n] != h for n, h in {**manifest["input_sha256"], **preserved}.items()): raise ValueError("selected or preserved input changed")
    return manifest, fixture, measured


def execute(checkout, go, root, evidence):
    replacements = {}; sources = {}
    for name, source in (("nom_pool_dependencies", DRIVER), ("nom_pool_forks", prior.DRIVER), ("nom_account_pool", POOL.DRIVER), ("nom_supervisor_plasma", SUPERVISOR.DRIVER)):
        target = checkout / "vm" / ("zz_research_" + name + "_test.go")
        if target.exists() or target.is_symlink(): raise ValueError("overlay would replace an existing input")
        snapshot = evidence / (name + "-source.go.txt"); sources[name] = (root / source).read_bytes()
        with private_create(snapshot) as out: out.write(sources[name])
        replacements[str(target)] = str(snapshot)
    overlay = (json.dumps({"Replace": replacements}, sort_keys=True) + "\n").encode("ascii")
    with private_create(evidence / "overlay.json") as out: out.write(overlay)
    wire = run([str(go), "test", "-json", "-overlay", str(evidence / "overlay.json"), "-vet=off", "-mod=readonly", "-count=1", "-run", "^" + TEST + "$", "./vm"],
               environment=dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off"), directory=checkout, evidence=evidence, label="core-observation", timeout=240)
    passed = SUPERVISOR.vm.selected_outcome(wire, expected_tests())
    if ((evidence / "overlay.json").read_bytes() != overlay or any((evidence / (n + "-source.go.txt")).read_bytes() != b for n, b in sources.items())):
        raise ValueError("complete original overlay custody changed")
    return wire, passed


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); SUPERVISOR.vm.core_state(checkout, manifest); tool_hash = SUPERVISOR.vm.digest(go)
    parent = evidence_parent or root / ".research-cache/nom-pool-dependencies-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="pool-dependencies-", dir=parent))
    result = {"schema": "zenon-nom-pool-dependencies-result-v1", "profile": PROFILE, "core_commit": CORE_COMMIT, "outcome": "UNKNOWN", **BOUNDARY,
              "input_sha256": before, "go_executable_sha256": tool_hash, "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
              "stream_custody": "Original private streams and all selected source snapshots; hosted private custody may be ephemeral"}
    try:
        old = prior.qualify(checkout, go, root=root, evidence_parent=evidence / "preserved-forks")
        wire, passed = execute(checkout, go, root, evidence)
        if old["outcome"] != "PASS" or old["counts"] != prior.COUNTS or old["tests_passed_including_parents"] != 287: raise ValueError("complete preserved fork qualification required")
        if fixture != corpus(collect_records(wire)): raise ValueError("fresh source dependency behavior differs from selection")
        SUPERVISOR.vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != SUPERVISOR.vm.digest(go): raise ValueError("selected source changed during qualification")
        result.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=old, new_tests_including_parent=passed,
                      tests_passed_including_parents=passed + 287, current_recovery_permission="NONE; SYNTHETIC RECONSTITUTION IS NOT AUTHENTICATED ROLLBACK")
        return result
    except BaseException:
        result["outcome"] = "FAILED_OR_INCOMPLETE"; raise
    finally:
        with private_create(evidence / "outcome.json") as out: out.write((json.dumps(result, sort_keys=True) + "\n").encode("ascii"))


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--checkout", type=Path, required=True); parser.add_argument("--go", type=Path, required=True)
    args = parser.parse_args()
    try: print(json.dumps(qualify(args.checkout, args.go), sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, WorkerError):
        print("FAIL: separate pool dependency controls; preserve original private evidence", file=sys.stderr); return 1


if __name__ == "__main__": sys.exit(main())
