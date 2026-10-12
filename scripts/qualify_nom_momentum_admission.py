#!/usr/bin/env python3
"""Compare actual source momentum execution with a separate state projection.

The selected producer responses and synthetic base do not authenticate a chain.
No application signer, wallet, node process, broadcast or recovery is supplied.
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
from offline_session.pr138 import CORE_COMMIT
from offline_session.public_worker import WorkerError
from offline_session import nom_momentum
from scripts import qualify_nom_pool_dependencies as prior
from scripts.generate_nom_momentum_admission import PROFILE, BASE, FIXTURE, CASE, CONTROLS, PRODUCER_KEY, BOUNDARY, corpus
from scripts.nom_native_command import private_create, run

MANIFEST = "compatibility/nom_momentum_admission_manifest.json"
DRIVER = "compatibility/nom_momentum_admission_test.go.txt"
TEST = "TestResearchNoMMomentumAdmission"
PACKAGE = prior.PACKAGE
PREFIX = "PTLC_RESEARCH_MOMENTUM_ADMISSION_RECORD "
SELECTED = (FIXTURE, DRIVER, "scripts/generate_nom_momentum_admission.py", "scripts/qualify_nom_momentum_admission.py", "tests/test_nom_momentum_admission.py")
CORE_FILES = {"chain/store/genesis.go", "chain/momentum/ledger_store.go", "chain/momentum/keys.go", "chain/momentum/account_block.go",
              "chain/momentum/confirmed.go", "chain/momentum/embedded.go", "chain/momentum/balance.go", "chain/momentum/momentum.go",
              "chain/nom/momentum_content.go", "chain/nom/momentum.go", "chain/store/momentum.go", "verifier/momentum.go",
              "vm/vm_context/momentum_context.go", "consensus/consensus.go", "common/db/store.go"}
COUNTS = {"generated_public_controls": 3, "normal_pool_admissions": 3, "generated_momenta": 2, "exact_applied_momenta": 2,
          "local_memory_manager_insertions": 2, "actual_prefetches": 2, "actual_pool_insert_callbacks": 2,
          "refused_momenta": 13, "selected_producer_queries": 6, "isolated_previous_store_queries": 26,
          "new_tests_including_parent": 15, "preserved_source_tests_including_parents": 291, "total_source_tests_including_parents": 306}
STAGE_FIELDS = {"momentum", "delta_patch_hex", "exact_apply_patch_hex", "manager_patch_hex", "manager_stole_changes",
                "generation_signatures", "apply_signatures", "generation_producer_calls", "apply_producer_calls", "stable_before_hex", "prefetched_wires"}
REFUSAL_FIELDS = {"result", "error", "transaction_present", "momentum_signatures", "producer_calls", "snapshot_calls", "stable_dump_hex", "candidate", "producer_response", "prefetched_wires"}
MOMENTUM_FIELDS = {"hash_hex", "wire_hex", "roundtrip_wire_hex", "public_key_hex", "signature_hex", "momentum"}
RECORD_FIELDS = {"schema", "id", "candidates", "pool_patches", "stages", "checkpoints", "refusals", "account_signatures", "momentum_signatures", "producer_calls", "snapshot_calls"}
POOL, SUPERVISOR = prior.POOL, prior.SUPERVISOR
PB = prior.prior


def expected_tests():
    return {PACKAGE: {TEST, TEST + "/" + CASE, *(TEST + "/" + CASE + "/" + n for n in CONTROLS)}}


def u64(n): return n.to_bytes(8, "big")
def logical(model): return POOL.encode_operations(sorted(model.items())).hex()
def hp(value): return PB.proto_bytes(1, bytes.fromhex(value))
def hh_wire(h, height): return PB.proto_bytes(1, hp(h)) + PB.proto_number(2, height)


def header_wire(h):
    return PB.proto_bytes(1, hp(h["address_hex"])) + PB.proto_bytes(2, hh_wire(h["hash_hex"], int(h["height"])))


def momentum_wire(r):
    m = r["momentum"]
    values = [(1, int(m["version"])), (2, int(m["chain_id"])), (3, hp(r["hash_hex"])), (4, hp(m["previous_hash_hex"])),
              (5, int(m["height"])), (6, int(m["timestamp"])), (7, bytes.fromhex(m["data_hex"]))]
    values += [(8, header_wire(h)) for h in m["content"]]
    values += [(9, hp(m["changes_hash_hex"])), (10, bytes.fromhex(r["public_key_hex"])), (11, bytes.fromhex(r["signature_hex"])),
               (12, int(m["next_fusion_price"])), (13, int(m["next_work_price"]))]
    return b"".join(PB.proto_number(n, v) if type(v) is int else PB.proto_bytes(n, v) for n, v in values)


def frontier(r):
    height = int(r["momentum"]["height"]); h = bytes.fromhex(r["hash_hex"])
    return [(b"\x00", hh_wire(r["hash_hex"], height)), (b"\x01" + h, u64(height)),
            (b"\x02" + u64(height), bytes.fromhex(r["wire_hex"]))]


def selected_momentum(r, expected, *, anchor=False):
    if type(r) is not dict or set(r) != MOMENTUM_FIELDS or r["momentum"] != expected:
        raise ValueError("exact selected momentum fields required")
    for k, size in (("hash_hex", 32), ("public_key_hex", 0 if anchor else 32), ("signature_hex", 0 if anchor else 64)):
        if type(r[k]) is not str or re.fullmatch("[0-9a-f]{" + str(size * 2) + "}", r[k]) is None:
            raise ValueError("exact selected momentum encoding required")
    selected_hash = hashlib.sha3_256(b"public-nom-momentum-admission-v1:base").hexdigest() if anchor else nom_momentum.momentum_hash(expected)
    if (r["hash_hex"] != selected_hash or r["public_key_hex"] != ("" if anchor else PRODUCER_KEY)
            or momentum_wire(r).hex() != r["wire_hex"] or r["roundtrip_wire_hex"] != r["wire_hex"]):
        raise ValueError("independent momentum hash, protobuf or roundtrip differs")
    return r


def validate_record(r):
    if (type(r) is not dict or set(r) != RECORD_FIELDS or r["schema"] != "zenon-nom-momentum-admission-record-v1" or r["id"] != CASE
            or any(type(r[k]) is not int or r[k] != n for k, n in (("account_signatures", 3), ("momentum_signatures", 2), ("producer_calls", 6), ("snapshot_calls", 26)))):
        raise ValueError("complete selected record and exact call counts required")
    names = ("send-first", "send-second", "receive-first")
    if (type(r["candidates"]) is not dict or set(r["candidates"]) != set(names) or type(r["pool_patches"]) is not dict or set(r["pool_patches"]) != set(names)
            or type(r["stages"]) is not dict or set(r["stages"]) != {"after-sends", "after-receive"}
            or type(r["checkpoints"]) is not dict or set(r["checkpoints"]) != {"initial", "after-sends", "after-receive"}
            or type(r["refusals"]) is not dict or set(r["refusals"]) != set(CONTROLS)):
        raise ValueError("complete candidates, patches, stages, checkpoints and refusals required")
    anchor_input = {"version": "1", "chain_id": "69", "previous_hash_hex": "00" * 32, "height": "10109300", "timestamp": "100", "data_hex": "",
                    "content": [], "changes_hash_hex": "00" * 32, "next_fusion_price": "0", "next_work_price": "0"}
    anchor = selected_momentum(r["checkpoints"]["initial"]["momentum"], anchor_input, anchor=True)
    model = dict(frontier(anchor)); rows = {}; account_models = {"sender": {}, "recipient": {}}
    heads = {"sender": SUPERVISOR.hh(), "recipient": SUPERVISOR.hh()}; previous = anchor

    def check(label, included):
        expected = {"global_dump_hex": logical(model), "momentum": previous}
        for role in ("sender", "recipient"):
            address = bytes.fromhex(prior.KEYS[role][1]); prefix = b"\x04" + address
            mail = {k[len(prefix):]: v for k, v in model.items() if k.startswith(prefix)}
            pending = [k[1:].hex() for k in sorted(mail) if k.startswith(b"\x05")]
            expected[role] = {"account_dump_hex": logical(account_models[role]), "mailbox_dump_hex": logical(mail), "pending_hashes": pending, "sequencer_size": "0"}
        for name in names:
            expected[name] = {"wire_hex": rows[name]["wire_hex"] if name in included else "", "confirmation_height": "10109302" if name == "receive-first" and name in included else "10109301" if name in included else "0"}
        if r["checkpoints"][label] != expected:
            raise ValueError("complete independent stable, account, header, confirmation or mailbox view differs")

    check("initial", set())
    for label, selected in (("after-sends", names[:2]), ("after-receive", names[2:])):
        before = logical(model); changes = {}
        for name in selected:
            role = "recipient" if name == "receive-first" else "sender"; used = 21000 if name == "send-second" else 0
            ack = SUPERVISOR.hh(previous["hash_hex"], previous["momentum"]["height"])
            row, ops = prior.candidate(r["candidates"][name], role, heads[role], used, ack, rows["send-first"]["hash_hex"] if role == "recipient" else None)
            rows[name] = row; heads[role] = SUPERVISOR.hh(row["hash_hex"], row["block"]["height"])
            ops += POOL.frontier_operations(row)
            if r["pool_patches"][name] != POOL.encode_operations(ops).hex(): raise ValueError("exact normal account manager patch differs")
            account_models[role] = SUPERVISOR.replay(account_models[role], ops)
            address = bytes.fromhex(prior.KEYS[role][1]); h = bytes.fromhex(row["hash_hex"])
            for key, value in ops: changes[b"\x03" + address + key] = value
            header = {"address_hex": row["block"]["address_hex"], "height": row["block"]["height"], "hash_hex": row["hash_hex"]}
            changes[b"\x08" + address] = bytes(32)
            changes[b"\x09" + h] = header_wire(header)
            changes[b"\x05" + h] = u64(int(previous["momentum"]["height"]) + 1)
            if role == "sender":
                prefix = b"\x04" + bytes.fromhex(prior.KEYS["recipient"][1])
                changes[prefix + b"\x04" + h] = u64(1); changes[prefix + b"\x05" + h] = u64(1)
            else:
                from_hash = bytes.fromhex(rows["send-first"]["hash_hex"])
                changes[b"\x04" + bytes.fromhex(prior.KEYS["sender"][1]) + b"\x06" + from_hash] = header_wire(header)
                changes[b"\x04" + address + b"\x05" + from_hash] = None
        delta = POOL.encode_operations(sorted(changes.items())); stage = r["stages"][label]
        content = [{"address_hex": rows[n]["block"]["address_hex"], "height": rows[n]["block"]["height"], "hash_hex": rows[n]["hash_hex"]} for n in selected]
        expected = {**anchor_input, "previous_hash_hex": previous["hash_hex"], "height": str(int(previous["momentum"]["height"]) + 1),
                    "timestamp": str(int(previous["momentum"]["timestamp"]) + 1), "content": content, "changes_hash_hex": hashlib.sha3_256(delta).hexdigest()}
        if type(stage) is not dict or set(stage) != STAGE_FIELDS: raise ValueError("complete exact momentum stage required")
        current = selected_momentum(stage["momentum"], expected)
        if (stage["delta_patch_hex"] != delta.hex() or stage["exact_apply_patch_hex"] != delta.hex()
                or stage["manager_patch_hex"] != (delta + POOL.encode_operations(frontier(current))).hex()
                or stage["manager_stole_changes"] is not True or stage["stable_before_hex"] != before
                or stage["prefetched_wires"] != [rows[n]["wire_hex"] for n in selected]
                or any(type(stage[k]) is not int or stage[k] != v for k, v in (("generation_signatures", 1), ("apply_signatures", 0), ("generation_producer_calls", 1), ("apply_producer_calls", 1)))):
            raise ValueError("exact VM delta, local manager augmentation, signing, prefetch or isolated base differs")
        model = SUPERVISOR.replay(model, sorted(changes.items()) + frontier(current)); previous = current
        check(label, set(names[:2]) if label == "after-sends" else set(names))
    good = r["stages"]["after-sends"]["momentum"]
    errors = {"reversed-content": "gap in previous Expected ", "duplicate-content": "content header has no matching account-block",
              "duplicate-prefetch": "duplicate prefetched account-block: ", "nil-prefetch": "prefetched account-block is nil",
              "wrong-header-address": "content header has no matching account-block", "missing-prefetch": "momentum content size is different than the size of the prefetched account-blocks",
              "wrong-chain": "account-block chain-identifier mismatch (belongs to another chain) - expected 69 but received 70",
              "non-increasing-time": "momentum timestamp is lower than previous timestamp", "changes-hash": "momentum changes-hash is different than the one computed",
              "outer-hash": "momentum hash is different than the one computed", "outer-signature": "momentum signature is invalid",
              "producer-rejected": "momentum producer is invalid", "producer-error": "internal error while verifying - selected synthetic producer error"}
    for kind in CONTROLS:
        control = r["refusals"][kind]; candidate = copy.deepcopy(good)
        prefetched = [rows[n]["wire_hex"] for n in names[:2]]
        if kind == "duplicate-prefetch": prefetched[1] = prefetched[0]
        elif kind == "nil-prefetch": prefetched[1] = None
        elif kind == "missing-prefetch": prefetched = prefetched[:1]
        if kind == "reversed-content": candidate["momentum"]["content"].reverse()
        elif kind == "duplicate-content": candidate["momentum"]["content"][1] = candidate["momentum"]["content"][0]
        elif kind == "wrong-header-address": candidate["momentum"]["content"][0]["address_hex"] = prior.KEYS["recipient"][1]
        elif kind == "wrong-chain": candidate["momentum"]["chain_id"] = "70"
        elif kind == "non-increasing-time": candidate["momentum"]["timestamp"] = "100"
        elif kind == "changes-hash": candidate["momentum"]["changes_hash_hex"] = "00" * 32
        elif kind == "outer-hash": candidate["hash_hex"] = "00" * 32
        elif kind == "outer-signature": candidate["signature_hex"] = (bytes([int(candidate["signature_hex"][:2], 16) ^ 1]) + bytes.fromhex(candidate["signature_hex"])[1:]).hex()
        candidate["wire_hex"] = momentum_wire(candidate).hex(); candidate["roundtrip_wire_hex"] = candidate["wire_hex"]
        producer = int(kind in ("producer-rejected", "producer-error")); snapshots = 2 if kind in ("changes-hash", "outer-hash", "outer-signature", "producer-rejected", "producer-error") else 1
        if (type(control) is not dict or set(control) != REFUSAL_FIELDS or control["result"] != "REFUSED" or control["transaction_present"] is not False
                or control["candidate"] != candidate or control["stable_dump_hex"] != r["checkpoints"]["initial"]["global_dump_hex"]
                or control["prefetched_wires"] != prefetched
                or control["producer_response"] != ("reject" if kind == "producer-rejected" else "error" if kind == "producer-error" else "accept")
                or any(type(control[k]) is not int or control[k] != v for k, v in (("momentum_signatures", 0), ("producer_calls", producer), ("snapshot_calls", snapshots)))
                or type(control["error"]) is not str or not control["error"].isascii() or not 1 <= len(control["error"]) <= 1024
                or not control["error"].startswith(errors[kind])):
            raise ValueError("exact refusal, producer boundary or complete stable isolation differs")
    return r


def validate_records(records):
    if type(records) is not dict or set(records) != {CASE}: raise ValueError("complete selected execution record required")
    validate_record(records[CASE]); return records


def collect_records(wire):
    records = {}; pending = ""
    if type(wire) is not bytes or len(wire) > 16 * 1024 * 1024: raise ValueError("bounded source stream required")
    for raw in wire.splitlines():
        event = json.loads(raw, object_pairs_hook=SUPERVISOR.vm.unique_object); out = event.get("Output", "")
        if PREFIX in out:
            if (pending or records or event.get("Action") != "output" or event.get("Package") != PACKAGE or event.get("Test") != TEST + "/" + CASE
                    or re.match(r"^    zz_research_nom_momentum_admission_test.go:[0-9]+: " + PREFIX, out) is None):
                raise ValueError("ambiguous source momentum framing")
            pending = out.split(PREFIX, 1)[1]
        elif pending:
            if event.get("Action") != "output" or event.get("Package") != PACKAGE or event.get("Test") != TEST + "/" + CASE:
                raise ValueError("incomplete or wrong source momentum stream")
            pending += out
        else: continue
        if len(pending) > 2 * 1024 * 1024: raise ValueError("selected momentum record bound")
        if not pending.endswith("\n"): continue
        record = json.loads(pending.strip(), object_pairs_hook=SUPERVISOR.vm.unique_object); pending = ""
        records[record["id"]] = validate_record(record)
    if pending: raise ValueError("incomplete momentum record")
    return validate_records(records)


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=SUPERVISOR.vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=SUPERVISOR.vm.unique_object)
    old, _, preserved = prior.inputs(root)
    if (set(manifest) != set(old) or manifest["schema"] != "zenon-nom-momentum-admission-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != CORE_COMMIT or manifest["research_baseline_commit"] != BASE or manifest["expected_counts"] != COUNTS
            or any(type(n) is not int for n in manifest["expected_counts"].values())
            or manifest["preserved_file_sha256"] != preserved or set(manifest["input_sha256"]) != set(SELECTED)
            or manifest["patch_format_source"] != old["patch_format_source"]
            or set(manifest["core_file_sha256"]) != (set(old["core_file_sha256"]) | CORE_FILES)
            or any(manifest["core_file_sha256"].get(n) != h for n, h in old["core_file_sha256"].items())
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("complete selected and preserved source manifest required")
    if fixture != corpus(validate_records(fixture["records"])): raise ValueError("complete momentum admission corpus differs")
    measured = {n: SUPERVISOR.vm.digest(root / n) for n in (MANIFEST, *SELECTED, *preserved)}
    if any(measured[n] != h for n, h in {**manifest["input_sha256"], **preserved}.items()): raise ValueError("selected or preserved input changed")
    return manifest, fixture, measured


def execute(checkout, go, root, evidence):
    replacements = {}; sources = {}
    for name, source in (("nom_momentum_admission", DRIVER),):
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
    parent = evidence_parent or root / ".research-cache/nom-momentum-admission-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True); info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="momentum-admission-", dir=parent))
    result = {"schema": "zenon-nom-momentum-admission-result-v1", "profile": PROFILE, "core_commit": CORE_COMMIT, "outcome": "UNKNOWN", **BOUNDARY,
              "input_sha256": before, "go_executable_sha256": tool_hash, "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
              "stream_custody": "Original private streams and all selected source snapshots; hosted private custody may be ephemeral"}
    try:
        old = prior.qualify(checkout, go, root=root, evidence_parent=evidence / "preserved-dependencies")
        wire, passed = execute(checkout, go, root, evidence)
        if old["outcome"] != "PASS" or old["counts"] != prior.COUNTS or old["tests_passed_including_parents"] != 291: raise ValueError("complete preserved fork qualification required")
        if fixture != corpus(collect_records(wire)): raise ValueError("fresh source momentum execution differs from selection")
        SUPERVISOR.vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != SUPERVISOR.vm.digest(go): raise ValueError("selected source changed during qualification")
        result.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=old, new_tests_including_parent=passed,
                      tests_passed_including_parents=passed + 291, current_recovery_permission="NONE; LOCAL MEMORY ACCEPTANCE DOES NOT AUTHENTICATE A CHAIN")
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
        print("FAIL: separate pool momentum admission controls; preserve original private evidence", file=sys.stderr); return 1


if __name__ == "__main__": sys.exit(main())
