#!/usr/bin/env python3
"""Compare public send-derived witnesses with unchanged, isolated core methods.

Original streams remain private. Stub storage and time do not qualify full VM
admission, state proofs, balances, inclusion, finality, custody or a live swap.
The host, compiler, build cache and selected environment remain trusted.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.public_worker import WorkerError
from offline_session.pr138 import CORE_COMMIT
from scripts.generate_nom_created_funding import PROFILE, FIXTURE, COMPLETIONS, corpus
from scripts.nom_native_command import private_create, run
from scripts.qualify_nom_wire_core import digest, core_state, parse_outcome

MANIFEST = "compatibility/nom_created_funding_manifest.json"
DRIVER = "compatibility/nom_created_funding_core_test.go.txt"
TEST = "TestResearchNoMCreatedFunding"
COUNTS = {"legs": 2, "funding_hash_inputs": 20, "stateful_controls": 70, "rust_controls": 3}
SELECTED = (FIXTURE, COMPLETIONS, DRIVER, "qualification/tests/nom_created_funding.rs",
            "scripts/generate_nom_created_funding.py", "scripts/qualify_nom_created_core.py",
            "scripts/qualify_nom_created_recovery.py")


def expected_tests(fixture):
    names = {TEST}
    vectors = fixture["vectors"]
    if type(vectors) is not list or len(vectors) != 70:
        raise ValueError("complete created-funding controls required")
    for vector in vectors:
        ident = vector["id"]
        if (type(ident) is not str or not ident or not ident.isascii()
                or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in ident)):
            raise ValueError("invalid source test name")
        name = TEST + "/" + ident
        if name in names: raise ValueError("duplicate source test name")
        names.add(name)
    return names


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"))
    fixture = json.loads((root / FIXTURE).read_text("ascii"))
    if (manifest["schema"] != "zenon-nom-created-funding-manifest-v1"
            or fixture["schema"] != "zenon-nom-created-funding-corpus-v1"
            or manifest["core_commit"] != CORE_COMMIT or fixture["core_commit"] != CORE_COMMIT
            or manifest["profile"] != PROFILE or fixture["profile"] != PROFILE
            or manifest["expected_counts"] != COUNTS or manifest["input_sha256"].keys() != set(SELECTED)
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("created-funding subject changed")
    for name, selected in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items():
        if digest(root / name) != selected: raise ValueError("selected or preserved input changed")
    if fixture != corpus(root): raise ValueError("public input generation differs")
    completions = json.loads((root / COMPLETIONS).read_text("ascii"))
    if completions["schema"] != "ptlc-nom-created-public-completions-v1":
        raise ValueError("unsupported public completion profile")
    expected_tests(fixture)
    measured = {name: digest(root / name) for name in (MANIFEST, *SELECTED,
                "scripts/qualify_nom_wire_core.py", "scripts/nom_native_command.py")}
    return manifest, fixture, measured


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root)
    core_state(checkout, manifest)
    tool_hash = digest(go)
    parent = evidence_parent or root / ".research-cache/nom-created-core-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="created-core-", dir=parent))
    record = {"schema": "zenon-nom-created-core-result-v1", "core_commit": CORE_COMMIT, "profile": PROFILE,
              "outcome": "UNKNOWN", "application": "NO-GO", "core": "NO-GO",
              "witness_success_origin": "ACTUAL CREATE SEND HASH IN SYNTHETIC METHOD CONTEXTS",
              "leg_composition": "SEPARATE PER-LEG CORE CONTEXTS; NOT A SHARED LIVE SWAP",
              "account_admission": "NOT_PERFORMED", "balance_accounting": "NOT_PERFORMED",
              "activation": "NOT_PERFORMED", "chain_observation": "NOT_PERFORMED",
              "application_signing": "NOT_PERFORMED", "runtime_authentication": "UNFILLED",
              "independent_assessment": "UNFILLED", "canonicality": "UNFILLED", "finality": "UNFILLED",
              "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
              "go_executable_sha256": tool_hash, "input_sha256": before}
    try:
        injected = checkout / "vm/embedded/implementation/zz_research_nom_created_test.go"
        if injected.exists() or injected.is_symlink(): raise ValueError("overlay would replace existing input")
        with private_create(evidence / "overlay.json") as out:
            out.write(json.dumps({"Replace": {str(injected): str(root / DRIVER)}}, sort_keys=True).encode("ascii"))
        environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off",
                           PTLC_NOM_CREATED_FIXTURE=str(root / FIXTURE), PTLC_NOM_CREATED_COMPLETIONS=str(root / COMPLETIONS),
                           PTLC_NOM_OLD_COMPLETIONS=str(root / "compatibility/fixtures/nom_completions_v1.json"))
        command = [str(go), "test", "-json", "-overlay", str(evidence / "overlay.json"), "-vet=off", "-mod=readonly",
                   "-count=1", "-run", "^" + TEST + "$", "./vm/embedded/implementation"]
        wire = run(command, environment=environment, directory=checkout, evidence=evidence,
                   label="core-observation", timeout=240)
        record["passed_tests_including_parent"] = parse_outcome(wire, expected_tests(fixture))
        core_state(checkout, manifest)
        if before != inputs(root)[2] or digest(go) != tool_hash:
            raise ValueError("selected input changed during execution")
        record.update(outcome="PASS", counts=COUNTS, source_unchanged=True,
                      stream_custody="Original private files; hosted private custody is ephemeral unless independently retained")
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
    try: print(json.dumps(qualify(args.checkout, args.go), sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, WorkerError):
        print("FAIL: created-funding source comparison; preserve original private evidence", file=sys.stderr); return 1


if __name__ == "__main__": sys.exit(main())
