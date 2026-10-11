#!/usr/bin/env python3
"""Compare source-valid legacy forks and the actual 500 pending-block cap.

No old swap original is replaced. No recovery, application signing, node start,
activation or momentum admission. Failed source runs never use fixture fallback.
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
from scripts import qualify_nom_account_pool as prior
from scripts.generate_nom_pool_forks import PROFILE, BASE, FIXTURE, CASES, PUBLIC_KEY, ADDRESS, RECIPIENT, NONCE, BOUNDARY, corpus
from scripts.nom_native_command import private_create, run

MANIFEST = "compatibility/nom_pool_forks_manifest.json"
DRIVER = "compatibility/nom_pool_forks_test.go.txt"
TEST = "TestResearchNoMPoolForks"
PACKAGE = prior.PACKAGE
PREFIX = "PTLC_RESEARCH_POOL_FORK_RECORD "
SELECTED = (FIXTURE, DRIVER, "scripts/generate_nom_pool_forks.py", "scripts/qualify_nom_pool_forks.py", "tests/test_nom_pool_forks.py")
CORE_FILES = {"pow/pow.go", "common/crypto/hash.go", "chain/nom/protobuf.proto", "vm/constants/plasma.go", "vm/plasma.go", "chain/account_pool.go"}
COUNTS = {"control_cases": 5, "generated_public_controls": 522, "fork_normal_admissions": 18,
          "fork_priority_refusals": 2, "cap_normal_admissions": 501, "cap_exact_duplicates": 2,
          "cap_valid_501_refusals": 1, "historical_queries": 24, "actual_uncommitted_cap": 500,
          "new_tests_including_parent": 6, "preserved_source_tests_including_parents": 281,
          "total_source_tests_including_parents": 287}
RECORD_FIELDS = {"schema", "id", "initial_stable_state", "final_stable_state", "candidates", "trace", "checkpoints", "views", "signing_calls", "cap", "fusion_amount", "dynamic_plasma"}
CANDIDATE_FIELDS = {"block", "delta_patch_hex", "applied_wire_hex", "applied_delta_hex", "generation_signatures", "apply_signatures", "base_plasma", "total_plasma", "canonical_base", "available_before"}
STEP_FIELDS = {"label", "result", "frontier_before", "frontier_after", "changes_stolen", "retained_patch_hex", "stored_patch_hex", "pending_count"}
CHECKPOINT_FIELDS = {"frontier", "state_dump_hex", "pending_count", "pending_wire_sha256", "used_plasma"}
VIEW_FIELDS = {"label", "present", "patch_present", "patch_hex", "frontier", "state_sha256"}


def expected_tests():
    return {PACKAGE: {TEST, *(TEST + "/" + n for n in CASES)}}


def unsigned(n):
    if type(n) is not int or not 0 <= n < 1 << 64: raise ValueError("unselected unsigned protobuf integer")
    out = bytearray()
    while n > 127: out.append((n & 127) | 128); n >>= 7
    out.append(n); return bytes(out)


def proto_bytes(n, value):
    return unsigned(n * 8 + 2) + unsigned(len(value)) + value if value else b""


def proto_number(n, value):
    return unsigned(n * 8) + unsigned(value) if value else b""


def selected_wire(r, base, total):
    """Independently encode only the selected user-send protobuf shape."""
    b = r["block"]; h = lambda v: proto_bytes(1, bytes.fromhex(v))
    momentum = proto_bytes(1, h(b["momentum_hash_hex"])) + proto_number(2, int(b["momentum_height"]))
    values = [(1, int(b["version"])), (2, int(b["chain_id"])), (3, int(b["block_type"])),
              (4, h(r["hash_hex"])), (5, h(b["previous_hash_hex"])), (6, int(b["height"])), (7, momentum),
              (8, h(b["address_hex"])), (9, h(b["to_address_hex"])), (10, int(b["amount"]).to_bytes(32, "big")),
              (11, bytes.fromhex(b["token_standard_hex"])), (12, h(b["from_block_hash_hex"])),
              (14, bytes.fromhex(b["data_hex"])), (15, int(b["fused_plasma"])), (17, int(b["difficulty"])),
              (18, bytes.fromhex(b["nonce_hex"])), (19, base), (20, total), (21, h(r["changes_hash_hex"])),
              (22, bytes.fromhex(r["public_key_hex"])), (23, bytes.fromhex(r["signature_hex"]))]
    return b"".join(proto_number(n, v) if type(v) is int else proto_bytes(n, v) for n, v in values)


def logical_state(value):
    """Complete sorted checkpoint reader, with explicit larger linear bounds."""
    data = prior.prior.bounded(value, 4 * 1024 * 1024); pos = 0; result = {}
    def field():
        nonlocal pos
        n = 0
        for i in range(4):
            if pos == len(data): raise ValueError("truncated logical length")
            v = data[pos]; pos += 1; n |= (v & 127) << (7 * i)
            if v < 128:
                if i and v == 0: raise ValueError("noncanonical logical length")
                break
        else: raise ValueError("overlong logical length")
        if n > 8192 or n > len(data) - pos: raise ValueError("unselected logical field")
        v = data[pos:pos+n]; pos += n; return v
    previous = b""
    while pos < len(data):
        if data[pos] != 1 or len(result) >= 2048: raise ValueError("complete bounded puts required")
        pos += 1; key = field(); value = field()
        if not key or key <= previous: raise ValueError("sorted unique logical keys required")
        result[key] = value; previous = key
    if prior.encode_operations(result.items()) != data: raise ValueError("logical framing differs")
    return result


def candidate(c, previous, used, *, data, fused, work=False):
    if type(c) is not dict or set(c) != CANDIDATE_FIELDS: raise ValueError("unselected source candidate fields")
    r = prior.prior.prior.validate_block(c["block"]); b = r["block"]
    base = 21000 + len(data) * 68; total = fused + (21000 if work else 0)
    expected = {"version": "1", "chain_id": "69", "block_type": "2", "address_hex": ADDRESS, "to_address_hex": RECIPIENT,
                "height": str(int(previous["height"]) + 1), "previous_hash_hex": previous["hash_hex"],
                "momentum_hash_hex": hashlib.sha3_256(b"public-nom-pool-forks-v1:momentum").hexdigest(), "momentum_height": "10109300",
                "amount": "0", "token_standard_hex": "00" * 10, "from_block_hash_hex": "00" * 32, "descendant_hashes_hex": [],
                "data_hex": data.hex(), "fused_plasma": str(fused), "difficulty": "31500000" if work else "0", "nonce_hex": NONCE if work else "00" * 8}
    if (b != expected or r["public_key_hex"] != PUBLIC_KEY or r["children"] != []
            or c["generation_signatures"] != 1 or type(c["generation_signatures"]) is not int
            or c["apply_signatures"] != 0 or type(c["apply_signatures"]) is not int
            or c["base_plasma"] != str(base) or c["canonical_base"] != str(base) or c["total_plasma"] != str(total)
            or c["available_before"] != str(10500000 - used) or fused > 10500000 - used or total < base):
        raise ValueError("actual canonical source generation or budget differs")
    if work:
        subject = hashlib.sha3_256(bytes.fromhex(ADDRESS) + bytes(32)).digest()
        value = int.from_bytes(hashlib.sha3_256(bytes.fromhex(NONCE) + subject).digest()[:8], "little")
        if value < (1 << 64) - ((1 << 64) // 31500000): raise ValueError("selected source PoW nonce differs")
    delta = prior.encode_operations([(b"\x03" + bytes(10), bytes(32)), (b"\x05", (used + fused).to_bytes(32, "big"))])
    if (c["delta_patch_hex"] != delta.hex() or c["applied_delta_hex"] != delta.hex()
            or r["changes_hash_hex"] != hashlib.sha3_256(delta).hexdigest()
            or c["applied_wire_hex"] != r["wire_hex"] or selected_wire(r, base, total).hex() != r["wire_hex"]):
        raise ValueError("independent exact delta, hash or protobuf encoding differs")
    return r, delta, used + fused


def pending_digest(pending):
    wires = [bytes.fromhex(r["wire_hex"]) for r in pending]
    return hashlib.sha256(b"".join(len(w).to_bytes(4, "big") + w for w in wires)).hexdigest()


def checkpoint(c, model, pending, used):
    if (type(c) is not dict or set(c) != CHECKPOINT_FIELDS or c["frontier"] != (prior.prior.hh() if not pending else pending[-1]["semantic_id"])
            or type(c["pending_count"]) is not int or c["pending_count"] != len(pending)
            or c["pending_wire_sha256"] != pending_digest(pending) or c["used_plasma"] != str(used)
            or logical_state(c["state_dump_hex"]) != model):
        raise ValueError("complete actual logical checkpoint differs")


def validate_record(record):
    if (type(record) is not dict or set(record) != RECORD_FIELDS or record["schema"] != "zenon-nom-pool-forks-record-v1"
            or record["id"] not in CASES or type(record["cap"]) is not int or record["cap"] != 500
            or record["fusion_amount"] != "500000000000" or record["dynamic_plasma"] is not False
            or record["initial_stable_state"] != "" or record["final_stable_state"] != ""):
        raise ValueError("unselected source record or changed stable state")
    kind = record["id"]; selected = record["candidates"]; checks = record["checkpoints"]
    cap = kind == "actual-cap-500"
    names = {"block-" + str(i) for i in range(1, 502)} | {"replacement-500"} if cap else {"prefix", "candidate-a", "candidate-b", "suffix-3", "suffix-4"}
    if type(selected) is not dict or set(selected) != names: raise ValueError("complete generated candidates required")
    rows = {}; patches = {}; used_at = {}; snapshots = {}; zero = prior.prior.hh()
    def generate(name, previous, used, data=b"", fused=21000, work=False):
        r, delta, after = candidate(selected[name], previous, used, data=data, fused=fused, work=work)
        rows[name] = {**r, "semantic_id": prior.prior.hh(r["hash_hex"], r["block"]["height"])}
        patches[name] = prior.encode_operations(prior.prior.decode_patch(delta.hex()) + prior.frontier_operations(r)).hex()
        used_at[name] = after
    if cap:
        previous = zero; used = 0
        for i in range(1, 502):
            name = "block-" + str(i); generate(name, previous, used, fused=0 if i == 1 else 21000, work=i == 1)
            previous = rows[name]["semantic_id"]; used = used_at[name]
        generate("replacement-500", rows["block-499"]["semantic_id"], used_at["block-499"], fused=21001)
        order = ["block-" + str(i) for i in range(1, 501)] + ["block-501", "block-500", "replacement-500", "replacement-500"]
        outcomes = ["PASS"] * 500 + ["ErrUncommittedCap", "PASS", "PASS", "PASS"]
        checkpoints = {"initial", "block-1", "block-499", "block-500", "cap-refusal", "cap-duplicate", "cap-replacement", "replacement-duplicate"}
    else:
        generate("prefix", zero, 0); previous = rows["prefix"]["semantic_id"]
        generate("candidate-a", previous, 21000, b"\x01", 21068)
        generate("candidate-b", previous, 21000, b"\x02", 42136 if kind.startswith("ratio-") else 21068)
        first, second = "candidate-a", "candidate-b"; want = "PASS"
        if kind == "ratio-lower": first, second = second, first; want = "ErrPlasmaRatioIsWorse"
        if kind.startswith("tie-"):
            small, large = sorted((first, second), key=lambda n: rows[n]["hash_hex"]); first, second = large, small
            if kind == "tie-larger": first, second = small, large; want = "ErrHashTieBreak"
        generate("suffix-3", rows[first]["semantic_id"], used_at[first]); generate("suffix-4", rows["suffix-3"]["semantic_id"], used_at["suffix-3"])
        order = ["prefix", first, "suffix-3", "suffix-4", second]; outcomes = ["PASS"] * 4 + [want]
        checkpoints = {"initial", "before-competitor", "after-competitor"}
    if (type(checks) is not dict or set(checks) != checkpoints or type(record["trace"]) is not list
            or len(record["trace"]) != len(order) or type(record["signing_calls"]) is not int or record["signing_calls"] != len(names)):
        raise ValueError("complete trace, signing count or checkpoints required")
    model = {}; pending = []; used = 0; live = {}; checkpoint(checks["initial"], model, pending, used)
    for index, (s, name, want) in enumerate(zip(record["trace"], order, outcomes)):
        if type(s) is not dict or set(s) != STEP_FIELDS: raise ValueError("unselected admission fields")
        r = rows[name]; ident = r["semantic_id"]; before = pending[-1]["semantic_id"] if pending else zero
        duplicate = any(b["semantic_id"] == ident for b in pending); accepts = want == "PASS" and not duplicate
        if accepts:
            height = int(r["block"]["height"])
            if height <= len(pending):
                predecessor = r["semantic_previous"]; expected_prev = pending[height-2]["semantic_id"]
                if predecessor != expected_prev: raise ValueError("candidate predecessor is not retained")
                for old in pending[height-1:]: live.pop(old["hash_hex"], None)
                pending = pending[:height-1]; model = dict(snapshots[predecessor["hash_hex"]])
            model = prior.prior.replay(model, prior.ordered_patch(patches[name])); pending.append(r)
            snapshots[r["hash_hex"]] = dict(model); used = used_at[name]; live[r["hash_hex"]] = (dict(model), patches[name])
        after = pending[-1]["semantic_id"] if pending else zero
        stored = live.get(r["hash_hex"])
        if (s["label"] != name or s["result"] != want or s["frontier_before"] != before or s["frontier_after"] != after
                or s["changes_stolen"] is not accepts or s["pending_count"] != len(pending) or type(s["pending_count"]) is not int
                or s["retained_patch_hex"] != (patches[name] if accepts else selected[name]["delta_patch_hex"])
                or s["stored_patch_hex"] != (stored[1] if stored else "")):
            raise ValueError("actual source insertion, refusal, duplicate or patch differs")
        if cap:
            label = {0: "block-1", 498: "block-499", 499: "block-500", 500: "cap-refusal", 501: "cap-duplicate", 502: "cap-replacement", 503: "replacement-duplicate"}.get(index)
        else: label = "before-competitor" if index == 3 else "after-competitor" if index == 4 else None
        if label: checkpoint(checks[label], model, pending, used)
    view_names = ["block-499", "block-500", "block-501", "replacement-500"] if cap else ["prefix", "candidate-a", "candidate-b", "suffix-3", "suffix-4"]
    if type(record["views"]) is not list or len(record["views"]) != len(view_names): raise ValueError("complete selected historical views required")
    for v, name in zip(record["views"], view_names):
        r = rows[name]; held = live.get(r["hash_hex"]); digest = ""
        if held: digest = hashlib.sha256(prior.encode_operations(sorted(held[0].items()))).hexdigest()
        expected = {"label": name, "present": held is not None, "patch_present": held is not None, "patch_hex": held[1] if held else "",
                    "frontier": r["semantic_id"] if held else None, "state_sha256": digest}
        if (type(v) is not dict or set(v) != VIEW_FIELDS or type(v["present"]) is not bool or type(v["patch_present"]) is not bool or v != expected):
            raise ValueError("retained or removed historical view differs")
    return record


def validate_records(records):
    if type(records) is not dict or set(records) != set(CASES): raise ValueError("complete separate control corpus required")
    for name in CASES:
        if records[name].get("id") != name: raise ValueError("case identity differs")
        validate_record(records[name])
    return records


def collect_records(wire):
    records, pending = {}, {}
    for line in wire.splitlines():
        e = json.loads(line, object_pairs_hook=prior.prior.vm.unique_object)
        if type(e) is not dict or e.get("Package") != PACKAGE: raise ValueError("unselected source package")
        out, name = e.get("Output", ""), e.get("Test")
        if type(out) is not str: raise ValueError("invalid native fragment")
        if pending and e.get("Action") == "output" and name not in pending: raise ValueError("interleaved native record")
        if PREFIX in out:
            if (out.count(PREFIX) != 1 or name in pending or e.get("Action") != "output"
                    or re.match(r"^    zz_research_nom_pool_forks_test.go:[0-9]+: " + PREFIX, out) is None):
                raise ValueError("ambiguous native source framing")
            pending[name] = out.split(PREFIX, 1)[1]
        elif name in pending:
            if e.get("Action") != "output": raise ValueError("truncated native record")
            pending[name] += out
        else: continue
        if len(pending[name]) > 8 * 1024 * 1024: raise ValueError("native control record exceeds bound")
        if not pending[name].endswith("\n"): continue
        r = json.loads(pending.pop(name).strip(), object_pairs_hook=prior.prior.vm.unique_object)
        if type(r) is not dict or r.get("id") not in CASES or r["id"] in records or name != TEST + "/" + r["id"]:
            raise ValueError("unselected or duplicate control record")
        records[r["id"]] = validate_record(r)
    if pending: raise ValueError("incomplete native record")
    return validate_records(records)


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=prior.prior.vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=prior.prior.vm.unique_object)
    old, _, preserved = prior.inputs(root)
    if (manifest["schema"] != "zenon-nom-pool-forks-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != CORE_COMMIT or manifest["research_baseline_commit"] != BASE or manifest["expected_counts"] != COUNTS
            or manifest["preserved_file_sha256"] != preserved or set(manifest["input_sha256"]) != set(SELECTED)
            or manifest["patch_format_source"] != old["patch_format_source"]
            or set(manifest["core_file_sha256"]) != (set(old["core_file_sha256"]) | CORE_FILES)
            or any(manifest["core_file_sha256"].get(n) != h for n, h in old["core_file_sha256"].items())
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("complete selected and preserved source manifest required")
    if fixture != corpus(validate_records(fixture["records"])): raise ValueError("complete selected control corpus differs")
    measured = {n: prior.prior.vm.digest(root / n) for n in (MANIFEST, *SELECTED, *preserved)}
    if any(measured[n] != h for n, h in {**manifest["input_sha256"], **preserved}.items()): raise ValueError("selected or preserved input changed")
    return manifest, fixture, measured


def execute(checkout, go, root, evidence):
    replacements = {}; sources = {}
    for name, source in (("nom_pool_forks", DRIVER), ("nom_account_pool", prior.DRIVER), ("nom_supervisor_plasma", prior.prior.DRIVER)):
        target = checkout / "vm" / ("zz_research_" + name + "_test.go")
        if target.exists() or target.is_symlink(): raise ValueError("overlay would replace an existing input")
        snapshot = evidence / (name + "-source.go.txt"); sources[name] = (root / source).read_bytes()
        with private_create(snapshot) as out: out.write(sources[name])
        replacements[str(target)] = str(snapshot)
    overlay = (json.dumps({"Replace": replacements}, sort_keys=True) + "\n").encode("ascii")
    with private_create(evidence / "overlay.json") as out: out.write(overlay)
    wire = run([str(go), "test", "-json", "-overlay", str(evidence / "overlay.json"), "-vet=off", "-mod=readonly", "-count=1", "-run", "^" + TEST + "$", "./vm"],
               environment=dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off"), directory=checkout, evidence=evidence, label="core-observation", timeout=240)
    passed = prior.prior.vm.selected_outcome(wire, expected_tests())
    if ((evidence / "overlay.json").read_bytes() != overlay
            or any((evidence / (n + "-source.go.txt")).read_bytes() != b for n, b in sources.items())):
        raise ValueError("complete original overlay custody changed")
    return wire, passed


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root); prior.prior.vm.core_state(checkout, manifest); tool_hash = prior.prior.vm.digest(go)
    parent = evidence_parent or root / ".research-cache/nom-pool-forks-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="pool-forks-", dir=parent))
    result = {"schema": "zenon-nom-pool-forks-result-v1", "profile": PROFILE, "core_commit": CORE_COMMIT, "outcome": "UNKNOWN", **BOUNDARY,
              "input_sha256": before, "go_executable_sha256": tool_hash, "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
              "stream_custody": "Original private streams and all selected source snapshots; hosted private custody may be ephemeral"}
    try:
        old = prior.qualify(checkout, go, root=root, evidence_parent=evidence / "preserved-pool")
        wire, passed = execute(checkout, go, root, evidence)
        if old["outcome"] != "PASS" or old["counts"] != prior.COUNTS or old["tests_passed_including_parents"] != 281: raise ValueError("complete preserved pool qualification required")
        if fixture != corpus(collect_records(wire)): raise ValueError("fresh source control behavior differs from selection")
        prior.prior.vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != prior.prior.vm.digest(go): raise ValueError("selected source changed during qualification")
        result.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=old, new_tests_including_parent=passed,
                      tests_passed_including_parents=passed + 281, current_recovery_permission="NONE; SEPARATE CONTROL CHAINS ARE NOT RECOVERY AUTHORITY")
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
        print("FAIL: separate pool controls; preserve original private evidence", file=sys.stderr); return 1


if __name__ == "__main__": sys.exit(main())
