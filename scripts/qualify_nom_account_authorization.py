#!/usr/bin/env python3
"""Compare exact public protobuf bytes and selected outer checks with clean core.

The user-account controls relocate synthetic blocks to public test keys. They
are different originals, not authorized signatures for the frozen swap. Source
helpers and typed roundtrips are not supervisor, Plasma or account admission.
Original command streams and fresh VM handoffs remain private. Toolchain,
cache, environment and host are trusted reproduction inputs.
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
from scripts.generate_nom_account_authorization import (
    PROFILE, FIXTURE, BOUNDARY, USER_ROLES, USER_KINDS, EMBEDDED_ROLES, EMBEDDED_KINDS, vectors, corpus,
)
from scripts.nom_native_command import private_create, run
from scripts import qualify_nom_vm_path as vm

MANIFEST = "compatibility/nom_account_authorization_manifest.json"
DRIVER = "compatibility/nom_account_authorization_test.go.txt"
TEST = "TestResearchNoMAccountAuthorization"
PACKAGE = "github.com/zenon-network/go-zenon/verifier"
PREFIX = "PTLC_RESEARCH_ACCOUNT_AUTH_RECORD "
SELECTED = (FIXTURE, DRIVER, "scripts/generate_nom_account_authorization.py",
            "scripts/qualify_nom_account_authorization.py", "tests/test_nom_account_authorization.py")
COUNTS = {"legs": 2, "source_roles": 12, "user_controls": 96, "embedded_controls": 30,
          "outer_tests_including_parent": 127, "source_tests_including_parents": 58,
          "source_records": 32, "total_source_tests_including_parents": 185}
RECORD_FIELDS = {"schema", "id", "leg", "role", "kind", "block", "source_hash_hex", "hash_hex",
    "computed_hash_hex", "changes_hash_hex", "base_plasma", "total_plasma", "public_key_hex", "signature_hex",
    "wire_hex", "wire_sha256", "reencoded_wire_hex", "original_wire_hex", "checks"}


def expected_tests():
    return {PACKAGE: {TEST, *(TEST + "/" + item["id"] for item in vectors())}}


def frozen_records(root=ROOT):
    """Preserved public projections are selections, not current source facts."""
    prior = json.loads((root / "compatibility/fixtures/nom_vm_openings_v1.json").read_text("ascii"))
    result = {}
    for leg in ("long", "short"):
        old = prior["source_cases"]["direct-success"][leg]
        result[leg + "-direct-success"] = {"blocks": {
            "funding": old["funding"], "unlock-send": old["unlock_send"],
            "recipient-receive": old["recipient_receipt"],
            "create-receive": old["contract_receive"]["funding_receive"],
            "unlock-receive": old["contract_receive"]["receive"], "unlock-payout-0": old["contract_payout"],
        }}
    return result


def expected_checks(vector):
    result = {"hash": "PASS", "signature": "PASS", "producer": "PASS"}
    kind = vector["kind"]
    if vector["role"] in USER_ROLES:
        if kind == "unsigned":
            result.update(signature="ErrABSignatureMissing", producer="ErrABPublicKeyWrongAddress")
        elif kind == "foreign-signature": result["producer"] = "ErrABPublicKeyWrongAddress"
        elif kind == "changed-data-old-hash": result["hash"] = "ErrABHashInvalid"
        elif kind == "missing-signature": result["signature"] = "ErrABSignatureMissing"
        elif kind == "missing-key":
            result.update(signature="ErrABPublicKeyMissing", producer="ErrABPublicKeyWrongAddress")
        elif kind == "short-key":
            result.update(signature="ErrABSignatureInvalid", producer="ErrABPublicKeyWrongAddress")
        elif kind in ("changed-data-old-signature", "short-signature", "bad-signature"):
            result["signature"] = "ErrABSignatureInvalid"
    elif kind == "nonempty-key": result["signature"] = "ErrABPublicKeyMustBeZero"
    elif kind == "nonempty-signature": result["signature"] = "ErrABSignatureMustBeZero"
    return result


def byte_value(value, width=None, *, maximum=8192):
    if (type(value) is not str or len(value) > 2 * maximum or len(value) % 2
            or re.fullmatch("[0-9a-f]*", value) is None or (width is not None and len(value) != width * 2)):
        raise ValueError("invalid bounded public authorization bytes")
    return bytes.fromhex(value)


def validate_record(record, vector, source):
    if (type(record) is not dict or set(record) != RECORD_FIELDS
            or record["schema"] != "zenon-nom-account-authorization-record-v1"
            or any(record[key] != vector[key] for key in ("id", "leg", "role", "kind"))):
        raise ValueError("unselected authorization result")
    selected = source[vector["leg"] + "-direct-success"]["blocks"][vector["role"]]
    for key in ("source_hash_hex", "hash_hex", "computed_hash_hex", "changes_hash_hex", "wire_sha256"):
        fixed_hex(record[key], 32)
    if record["source_hash_hex"] != selected["hash_hex"]:
        raise ValueError("source original changed")
    wire = byte_value(record["wire_hex"])
    roundtrip = byte_value(record["reencoded_wire_hex"])
    original = byte_value(record["original_wire_hex"])
    if not wire or not roundtrip or not original or hashlib.sha256(wire).hexdigest() != record["wire_sha256"]:
        raise ValueError("exact byte commitment differs")
    alias = {"unknown-protobuf-field": "a00601", "duplicate-protobuf-version": "0801"}.get(vector["kind"])
    if record["wire_hex"] != record["reencoded_wire_hex"] + (alias or ""):
        raise ValueError("typed roundtrip or raw alias differs")
    if record["computed_hash_hex"] != account_block_hash(record["block"]) or record["checks"] != expected_checks(vector):
        raise ValueError("selected account hash or outer checks differ")
    for key in ("base_plasma", "total_plasma"): decimal(record[key], 64)
    if record["base_plasma"] != ("1" if vector["kind"] == "changed-base-plasma" else "0"):
        raise ValueError("base Plasma claim differs")
    if record["total_plasma"] != ("1" if vector["kind"] == "changed-total-plasma" else "0"):
        raise ValueError("used Plasma claim differs")
    wanted = copy.deepcopy(selected["block"])
    user = vector["role"] in USER_ROLES
    kind = vector["kind"]
    pub_width = 0 if kind in ("unsigned", "missing-key") or not user and kind != "nonempty-key" else 31 if kind == "short-key" else 32
    sig_width = 0 if kind in ("unsigned", "missing-signature") or not user and kind != "nonempty-signature" else 63 if kind == "short-signature" else 64
    byte_value(record["public_key_hex"], pub_width)
    byte_value(record["signature_hex"], sig_width)
    if user and kind not in ("unsigned", "foreign-signature"):
        # Missing/short keys are controls derived from the selected full key.
        if pub_width == 32:
            wanted["address_hex"] = "00" + hashlib.sha3_256(bytes.fromhex(record["public_key_hex"])).hexdigest()[:38]
        else:
            wanted["address_hex"] = record["block"]["address_hex"]
            fixed_hex(wanted["address_hex"], 20)
        if wanted["address_hex"] == selected["block"]["address_hex"]:
            raise ValueError("relocated account was relabeled as the original")
    if kind in ("changed-data-old-hash", "changed-data-old-signature", "changed-data-resigned"):
        wanted["data_hex"] += "7f"
    if record["block"] != wanted:
        raise ValueError("selected block transformation differs")
    changes = bytearray.fromhex(selected["changes_hash_hex"])
    if kind == "changed-changes-hash": changes[0] ^= 1
    if record["changes_hash_hex"] != changes.hex(): raise ValueError("separate patch claim differs")
    advertised = account_block_hash({**wanted, "data_hex": selected["block"]["data_hex"]}) if kind == "changed-data-old-hash" else account_block_hash(wanted)
    if record["hash_hex"] != advertised: raise ValueError("advertised hash differs")
    return record


def validate_records(records, source):
    if type(records) is not dict or set(records) != {v["id"] for v in vectors()}:
        raise ValueError("incomplete selected authorization records")
    for vector in vectors(): validate_record(records[vector["id"]], vector, source)
    for leg in ("long", "short"):
        keys = set()
        for role in (*USER_ROLES, *EMBEDDED_ROLES):
            group = {v["kind"]: records[v["id"]] for v in vectors() if v["leg"] == leg and v["role"] == role}
            if len({r["original_wire_hex"] for r in group.values()}) != 1:
                raise ValueError("original raw selection changed across controls")
            base = group["relocated-authorized" if role in USER_ROLES else "empty-authorization"]
            for kind in ("unknown-protobuf-field", "duplicate-protobuf-version"):
                if group[kind]["reencoded_wire_hex"] != base["wire_hex"]:
                    raise ValueError("raw alias changed its typed account")
            if role in USER_ROLES:
                keys.add(base["public_key_hex"])
                if group["unsigned"]["wire_hex"] != base["original_wire_hex"]:
                    raise ValueError("unsigned raw source differs")
                for kind in USER_KINDS:
                    r = group[kind]
                    if kind not in ("unsigned", "missing-key", "short-key") and r["public_key_hex"] != base["public_key_hex"]:
                        raise ValueError("public test key changed across controls")
                    if kind not in ("unsigned", "foreign-signature", "changed-data-resigned",
                                    "missing-signature", "short-signature", "bad-signature") and r["signature_hex"] != base["signature_hex"]:
                        raise ValueError("retained public signature changed")
                    if kind not in ("unsigned", "foreign-signature") and r["block"]["address_hex"] != base["block"]["address_hex"]:
                        raise ValueError("selected relocated account changed")
                if group["short-key"]["public_key_hex"] != base["public_key_hex"][:-2] or group["short-signature"]["signature_hex"] != base["signature_hex"][:-2]:
                    raise ValueError("short control is not the retained prefix")
                bad = bytearray.fromhex(base["signature_hex"]); bad[0] ^= 1
                if group["bad-signature"]["signature_hex"] != bad.hex(): raise ValueError("bad signature control differs")
            elif base["wire_hex"] != base["original_wire_hex"]:
                raise ValueError("embedded original bytes differ")
        if len(keys) != 1: raise ValueError("public leg key differs")
    return records


def collect_records(wire, source):
    wanted = {v["id"]: v for v in vectors()}; records, pending = {}, {}
    for line in wire.splitlines():
        event = json.loads(line, object_pairs_hook=vm.unique_object)
        if type(event) is not dict or event.get("Package") != PACKAGE: raise ValueError("unexpected authorization package")
        output, name = event.get("Output", ""), event.get("Test")
        if type(output) is not str: raise ValueError("invalid source output fragment")
        if pending and event.get("Action") == "output" and name not in pending: raise ValueError("interleaved source record")
        if PREFIX in output:
            if (output.count(PREFIX) != 1 or name in pending or event.get("Action") != "output"
                    or re.match(r"^    zz_research_nom_account_authorization_test.go:[0-9]+: " + PREFIX, output) is None):
                raise ValueError("ambiguous source record")
            pending[name] = output.split(PREFIX, 1)[1]
        elif name in pending:
            if event.get("Action") != "output": raise ValueError("truncated source record")
            pending[name] += output
        else: continue
        if len(pending[name]) > 65536: raise ValueError("oversized source record")
        if not pending[name].endswith("\n"): continue
        record = json.loads(pending.pop(name).strip(), object_pairs_hook=vm.unique_object)
        if type(record) is not dict: raise ValueError("invalid source record type")
        ident = record.get("id")
        if ident not in wanted or ident in records or name != TEST + "/" + ident:
            raise ValueError("duplicate or unselected source record")
        records[ident] = validate_record(record, wanted[ident], source)
    if pending: raise ValueError("incomplete source record framing")
    return validate_records(records, source)


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"), object_pairs_hook=vm.unique_object)
    fixture = json.loads((root / FIXTURE).read_text("ascii"), object_pairs_hook=vm.unique_object)
    if (manifest["schema"] != "zenon-nom-account-authorization-manifest-v1" or manifest["profile"] != PROFILE
            or manifest["core_commit"] != CORE_COMMIT or manifest["expected_counts"] != COUNTS
            or set(manifest["input_sha256"]) != set(SELECTED)
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("selected authorization subject changed")
    if fixture != corpus(validate_records(fixture["records"], frozen_records(root))):
        raise ValueError("selected public corpus differs")
    measured = {name: vm.digest(root / name) for name in (MANIFEST, *SELECTED, *manifest["preserved_file_sha256"])}
    if any(measured[name] != expected for name, expected in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items()):
        raise ValueError("selected or preserved input changed")
    return manifest, fixture, measured


def execute(checkout, go, root, evidence, source):
    injected = checkout / "verifier/zz_research_nom_account_authorization_test.go"
    if injected.exists() or injected.is_symlink(): raise ValueError("overlay would replace existing input")
    handoff = {"schema": "zenon-nom-vm-verifier-input-v1",
        "baseline": {leg: source[leg + "-direct-success"] for leg in ("long", "short")}}
    plan = {"schema": "zenon-nom-account-authorization-plan-v1", "vectors": vectors()}
    retained = {}
    for name, value in (("source-handoff.json", handoff), ("plan.json", plan), ("overlay.json", {
            "Replace": {str(injected): str(root / DRIVER)}})):
        retained[name] = (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
        with private_create(evidence / name) as out: out.write(retained[name])
    environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off",
        PTLC_NOM_ACCOUNT_AUTH_SOURCE=str(evidence / "source-handoff.json"), PTLC_NOM_ACCOUNT_AUTH_PLAN=str(evidence / "plan.json"))
    wire = run([str(go), "test", "-json", "-overlay", str(evidence / "overlay.json"), "-vet=off", "-mod=readonly",
                "-count=1", "-run", "^" + TEST + "$", "./verifier"], environment=environment,
               directory=checkout, evidence=evidence, label="core-observation", timeout=240)
    passed = vm.selected_outcome(wire, expected_tests())
    if any((evidence / name).read_bytes() != value for name, value in retained.items()):
        raise ValueError("fresh source handoff changed")
    return wire, passed


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root)
    vm.core_state(checkout, manifest); tool_hash = vm.digest(go)
    parent = evidence_parent or root / ".research-cache/nom-account-authorization-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="account-authorization-", dir=parent))
    result = {"schema": "zenon-nom-account-authorization-result-v1", "profile": PROFILE,
        "core_commit": CORE_COMMIT, "outcome": "UNKNOWN", **BOUNDARY,
        "input_sha256": before, "go_executable_sha256": tool_hash,
        "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
        "stream_custody": "Original private streams and fresh VM handoffs; hosted custody may be ephemeral"}
    try:
        source_result = vm.qualify(checkout, go, root=root, evidence_parent=evidence / "source")
        subjects = list((evidence / "source").glob("composed-vm-*"))
        if len(subjects) != 1 or json.loads((subjects[0] / "outcome.json").read_text("ascii")) != source_result:
            raise ValueError("fresh VM custody differs")
        raw = (subjects[0] / "core-wire.stdout").read_bytes()
        _, source_fixture, _ = vm.inputs(root)
        package = "github.com/zenon-network/go-zenon/vm"
        vm.selected_outcome(raw, {package: vm.expected_tests(source_fixture)[package]})
        source = vm.collect_vm_records(raw, source_fixture, json.loads((root / vm.FUNDING).read_text("ascii")))
        wire, passed = execute(checkout, go, root, evidence, source)
        if fixture != corpus(collect_records(wire, source)): raise ValueError("fresh authorization projection differs")
        vm.core_state(checkout, manifest)
        if before != inputs(root)[2] or tool_hash != vm.digest(go): raise ValueError("selected subject changed during qualification")
        result.update(outcome="PASS", counts=COUNTS, source_unchanged=True, source_result=source_result,
            passed_outer_tests_including_parent=passed, fresh_projection="MATCH; ALL 126 CONTROLS FROM FRESH VM RECORDS",
            unsigned_user_originals="SOURCE HASH MATCHES; ACCOUNT SIGNATURE MISSING",
            foreign_key="SIGNATURE VALIDITY DOES NOT AUTHORIZE THE SELECTED ACCOUNT",
            relocated_controls="DIFFERENT ACCOUNT AND ORIGINAL; NOT THE SELECTED FUNDING ENTRY OR RETAINED UNLOCK",
            raw_aliases="DISTINCT RAW BYTES COLLAPSE TO THE SAME SELECTED TYPED ACCOUNT",
            excluded_fields="ACCOUNT HASH DOES NOT BIND SIGNATURE, CHANGES HASH OR BASE/USED PLASMA",
            embedded_boundary="EMPTY KEY/SIGNATURE IS REQUIRED; DOES NOT AUTHORIZE AN EXTERNAL CONTRACT SEND")
        return result
    except BaseException:
        result["outcome"] = "FAILED_OR_INCOMPLETE"
        raise
    finally:
        with private_create(evidence / "outcome.json") as out: out.write((json.dumps(result, sort_keys=True) + "\n").encode("ascii"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True); parser.add_argument("--go", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(qualify(args.checkout, args.go), sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, WorkerError):
        print("FAIL: account authorization; preserve original private evidence", file=sys.stderr); return 1


if __name__ == "__main__":
    sys.exit(main())
