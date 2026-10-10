#!/usr/bin/env python3
"""Compare public momentum layouts and selected helpers on unchanged core.

Dependency content qualification is separate. The selected compiler, cache,
environment and host remain trusted; producer election, full chain admission,
canonicality, finality, durable reorg custody and recovery are unqualified.
"""

import argparse
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
from offline_session.nom_momentum import PROFILE
from offline_session.pr138 import CORE_COMMIT
from offline_session.public_worker import WorkerError
from scripts.nom_native_command import private_create, run
from scripts.qualify_nom_observation_core import parse_outcome
from scripts.qualify_nom_wire_core import digest, core_state

MANIFEST = "compatibility/nom_momentum_manifest.json"
FIXTURE = "compatibility/fixtures/nom_momentum_v1.json"
DRIVER = "compatibility/nom_momentum_core_test.go.txt"
PACKAGE = "github.com/zenon-network/go-zenon/verifier"
TEST = "TestResearchNoMMomentumCorpus"
COUNTS = {"hash_layout": 24, "source_controls": 26, "structural_claims": 32, "reorg_plans": 8}


def expected_tests(fixture):
    names = {TEST}
    for group, key in (("hash", "hash_vectors"), ("control", "source_controls")):
        for item in fixture[key]:
            ident = item["id"] if type(item) is dict else item
            if type(ident) is not str or re.fullmatch("[a-z][a-z0-9-]{0,95}", ident) is None:
                raise ValueError("invalid selected test subject")
            name = TEST + "/" + group + "/" + ident
            if name in names:
                raise ValueError("duplicate selected test subject")
            names.add(name)
    return {PACKAGE: names}


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"))
    fixture = json.loads((root / FIXTURE).read_text("ascii"))
    if (manifest["schema"] != "zenon-nom-momentum-manifest-v1" or fixture["schema"] != "zenon-nom-momentum-corpus-v1"
            or manifest["core_commit"] != CORE_COMMIT or fixture["core_commit"] != CORE_COMMIT
            or manifest["profile"] != PROFILE or fixture["profile"] != PROFILE
            or manifest["expected_counts"] != COUNTS or manifest["input_sha256"].keys() != {FIXTURE, DRIVER}
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")
            or len(fixture["hash_vectors"]) != 24 or len(fixture["source_controls"]) != 26
            or len(fixture["claim_vectors"]) != 32 or len(fixture["reorg_vectors"]) != 8):
        raise ValueError("selected momentum subject changed")
    for name, wanted in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items():
        if digest(root / name) != wanted:
            raise ValueError("selected or preserved input changed")
    expected_tests(fixture)
    measured = {name: digest(root / name) for name in (MANIFEST, FIXTURE, DRIVER,
                "offline_session/nom_momentum.py", "scripts/generate_nom_momentum.py",
                "scripts/qualify_nom_momentum_core.py", "scripts/qualify_nom_observation_core.py",
                "scripts/qualify_nom_wire_core.py", "scripts/nom_native_command.py")}
    return manifest, fixture, measured


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root)
    core_state(checkout, manifest)
    tool_hash = digest(go)
    parent = evidence_parent or root / ".research-cache/nom-momentum-core-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="core-momentum-", dir=parent))
    record = {"schema": "zenon-nom-momentum-core-result-v1", "core_commit": CORE_COMMIT, "profile": PROFILE,
              "outcome": "UNKNOWN", "activation": "NOT_PERFORMED", "account_admission": "NOT_PERFORMED",
              "producer_election": "NOT_PERFORMED", "chain_observation": "NOT_PERFORMED",
              "canonicality": "UNFILLED", "finality": "UNFILLED", "durable_reorg_custody": "UNQUALIFIED",
              "application": "NO-GO", "core": "NO-GO", "independent_assessment": "UNFILLED",
              "runtime_authentication": "UNFILLED", "go_executable_sha256": tool_hash, "input_sha256": before,
              "overlay_vet": "NOT_PERFORMED; the synthetic overlay path is unavailable to Go 1.23 vet"}
    try:
        injected = checkout / "verifier/zz_research_nom_momentum_test.go"
        if injected.exists() or injected.is_symlink():
            raise ValueError("overlay would replace an existing input")
        overlay = evidence / "overlay.json"
        with private_create(overlay) as output:
            output.write(json.dumps({"Replace": {str(injected): str(root / DRIVER)}}, sort_keys=True).encode("ascii"))
        environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off",
                           PTLC_NOM_MOMENTUM_FIXTURE=str(root / FIXTURE))
        command = [str(go), "test", "-json", "-overlay", str(overlay), "-vet=off", "-mod=readonly", "-count=1",
                   "-run", "^" + TEST + "$", "./verifier"]
        wire = run(command, environment=environment, directory=checkout, evidence=evidence, label="core-momentum", timeout=240)
        record["passed_tests_including_parent"] = parse_outcome(wire, expected_tests(fixture))
        core_state(checkout, manifest)
        if inputs(root)[2] != before or digest(go) != tool_hash:
            raise ValueError("selected subject changed during the run")
        record.update(outcome="PASS", counts=COUNTS, source_unchanged=True,
                      stream_custody="Original private files; hosted runner custody is ephemeral unless independently retained")
        return record
    except BaseException:
        record["outcome"] = "FAILED_OR_INCOMPLETE"
        raise
    finally:
        with private_create(evidence / "outcome.json") as output:
            output.write((json.dumps(record, sort_keys=True) + "\n").encode("ascii"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--go", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(qualify(args.checkout, args.go), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, WorkerError):
        print("FAIL: selected momentum differential; preserve original private evidence", file=sys.stderr)
        return 1


if __name__ == "__main__": sys.exit(main())
