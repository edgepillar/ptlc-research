#!/usr/bin/env python3
"""Retain one bounded, offline ABI/hash differential against the clean core pin.

Dependency acquisition is separate. The selected Go tool, its compiler cache,
runtime, host and environment are trusted; this is source conformance evidence,
not executable authentication, account admission, finality or a live swap.
Original command streams stay private. This driver copies no node implementation.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.pr138 import CORE_COMMIT
from offline_session.nom_wire import WIRE_PROFILE
from offline_session.public_worker import WorkerError
from scripts.nom_native_command import private_create, run

PACKAGE = "github.com/zenon-network/go-zenon/vm/embedded/implementation"
TEST = "TestResearchNoMWireCorpus"
MANIFEST = "compatibility/nom_wire_manifest.json"
FIXTURE = "compatibility/fixtures/nom_wire_v1.json"
DRIVER = "compatibility/nom_wire_core_test.go.txt"


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular selected input required")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_tests(fixture):
    names = {TEST}
    for group, key in (("abi", "abi_vectors"), ("normalize", "normalization_vectors"), ("hash", "hash_vectors")):
        for vector in fixture[key]:
            name = TEST + "/" + group + "/" + vector["id"]
            if name in names: raise ValueError("duplicate test subject")
            names.add(name)
    for control in fixture["controls"]:
        name = TEST + "/control/" + control
        if name in names: raise ValueError("duplicate test subject")
        names.add(name)
    return names


def parse_outcome(wire, names):
    """A zero exit without every exact test is incomplete evidence."""
    observed = set()
    package_passes = 0
    for line in wire.splitlines():
        event = json.loads(line)
        if type(event) is not dict or event.get("Package") != PACKAGE:
            raise ValueError("unexpected test package")
        action, name = event.get("Action"), event.get("Test")
        if action in ("skip", "fail"):
            raise ValueError("failed or skipped test evidence")
        if action == "pass":
            if name is None:
                package_passes += 1
            elif name in names and name not in observed:
                observed.add(name)
            else:
                raise ValueError("unexpected or duplicate test result")
    if observed != names or package_passes != 1:
        raise ValueError("incomplete test evidence")
    return len(observed)


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"))
    fixture = json.loads((root / FIXTURE).read_text("ascii"))
    if (manifest["schema"] != "zenon-nom-wire-manifest-v1" or manifest["core_commit"] != CORE_COMMIT
            or manifest["profile"] != WIRE_PROFILE or fixture["core_commit"] != CORE_COMMIT
            or fixture["profile"] != WIRE_PROFILE or fixture["schema"] != "zenon-nom-wire-corpus-v1"
            or manifest["expected_counts"] != {"abi": 12, "normalization": 7, "hash": 22, "controls": 3}
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")):
        raise ValueError("selected subject changed")
    if manifest["input_sha256"].keys() != {FIXTURE, DRIVER}:
        raise ValueError("unexpected manifest inputs")
    for name, wanted in manifest["input_sha256"].items():
        if digest(root / name) != wanted: raise ValueError("selected input changed")
    measured = {name: digest(root / name) for name in (MANIFEST, FIXTURE, DRIVER,
                "scripts/qualify_nom_wire_core.py", "scripts/nom_native_command.py")}
    return manifest, fixture, measured


def core_state(checkout, manifest):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(checkout), *args], stderr=subprocess.DEVNULL, timeout=10).strip()
    if (git("rev-parse", "HEAD").decode("ascii") != CORE_COMMIT
            or git("rev-parse", "HEAD^{tree}").decode("ascii") != manifest["core_tree"]
            or git("status", "--porcelain", "--untracked-files=all")):
        raise ValueError("clean exact core source required")
    for name, expected in manifest["core_file_sha256"].items():
        if digest(checkout / name) != expected: raise ValueError("core input changed")


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root)
    core_state(checkout, manifest)
    tool_hash = digest(go)
    parent = evidence_parent or root / ".research-cache/nom-wire-core-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="core-wire-", dir=parent))
    record = {"schema": "zenon-nom-wire-core-result-v1", "core_commit": CORE_COMMIT, "profile": WIRE_PROFILE,
              "outcome": "UNKNOWN", "activation": "NOT_PERFORMED", "account_admission": "NOT_PERFORMED",
              "chain_observation": "NOT_PERFORMED", "application": "NO-GO", "core": "NO-GO",
              "independent_assessment": "UNFILLED", "runtime_authentication": "UNFILLED",
              "overlay_vet": "NOT_PERFORMED; the synthetic overlay path is unavailable to Go 1.23 vet",
              "go_executable_sha256": tool_hash, "input_sha256": before}
    try:
        overlay = evidence / "overlay.json"
        injected = checkout / "vm/embedded/implementation/zz_research_nom_wire_test.go"
        if injected.exists() or injected.is_symlink(): raise ValueError("overlay would replace an existing input")
        with private_create(overlay) as output:
            output.write(json.dumps({"Replace": {str(injected): str(root / DRIVER)}}, sort_keys=True).encode("ascii"))
        environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off",
                           PTLC_NOM_WIRE_FIXTURE=str(root / FIXTURE))
        command = [str(go), "test", "-json", "-overlay", str(overlay), "-vet=off", "-mod=readonly",
                   "-count=1", "-run", "^" + TEST + "$", "./vm/embedded/implementation"]
        wire = run(command, environment=environment, directory=checkout, evidence=evidence, label="core-wire", timeout=240)
        record["passed_tests_including_parent"] = parse_outcome(wire, expected_tests(fixture))
        core_state(checkout, manifest)
        if before != inputs(root)[2] or digest(go) != tool_hash:
            raise ValueError("selected subject changed during the run")
        record.update(outcome="PASS", counts=manifest["expected_counts"], source_unchanged=True,
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
        print("FAIL: selected core wire differential; preserve original private evidence", file=sys.stderr)
        return 1


if __name__ == "__main__": sys.exit(main())
