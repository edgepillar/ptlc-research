#!/usr/bin/env python3
"""Compare bounded synthetic observations with selected unchanged core checks.

These storage/time/ledger stubs qualify selected source behavior, not a deployed
VM, full account admission, inclusion, finality, custody or recovery integration.
The tool, build cache, environment and host are trusted. Original streams remain
private; dependency acquisition and content comparison are separate steps.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_observation import PROFILE
from offline_session.pr138 import CORE_COMMIT
from offline_session.public_worker import WorkerError
from scripts.nom_native_command import private_create, run
from scripts.qualify_nom_wire_core import digest, core_state

MANIFEST = "compatibility/nom_observation_manifest.json"
FIXTURE = "compatibility/fixtures/nom_observation_v1.json"
SUBJECTS = (
    ("vm/embedded/implementation", "TestResearchNoMObservationState", "stateful_vectors", "compatibility/nom_observation_state_test.go.txt"),
    ("verifier", "TestResearchNoMObservationVerifier", "verifier_vectors", "compatibility/nom_observation_verifier_test.go.txt"),
    ("vm", "TestResearchNoMObservationVM", "vm_vectors", "compatibility/nom_observation_vm_test.go.txt"),
)
COUNTS = {"structural_claims": 48, "stateful_methods": 16, "verifier_checks": 14, "vm_finalization": 4}


def expected_tests(fixture):
    names = {}
    for package, parent, key, _ in SUBJECTS:
        selected = {parent}
        for vector in fixture[key]:
            ident = vector["id"] if type(vector) is dict else vector
            if type(ident) is not str or not ident or "/" in ident or not ident.isascii():
                raise ValueError("invalid test subject")
            name = parent + "/" + ident
            if name in selected:
                raise ValueError("duplicate test subject")
            selected.add(name)
        names["github.com/zenon-network/go-zenon/" + package] = selected
    return names


def parse_outcome(wire, names):
    """Claims must contain each exact package, parent and selected subtest."""
    observed = {package: set() for package in names}
    packages = set()
    for line in wire.splitlines():
        event = json.loads(line)
        if type(event) is not dict or event.get("Package") not in names:
            raise ValueError("unexpected package evidence")
        package, action, name = event["Package"], event.get("Action"), event.get("Test")
        if action in ("skip", "fail"):
            raise ValueError("failed or skipped evidence")
        if action == "pass":
            if name is None:
                if package in packages:
                    raise ValueError("duplicate package result")
                packages.add(package)
            elif name in names[package] and name not in observed[package]:
                observed[package].add(name)
            else:
                raise ValueError("unexpected or duplicate test result")
    if packages != names.keys() or observed != names:
        raise ValueError("incomplete source evidence")
    return sum(map(len, observed.values()))


def inputs(root):
    manifest = json.loads((root / MANIFEST).read_text("ascii"))
    fixture = json.loads((root / FIXTURE).read_text("ascii"))
    wanted = {FIXTURE, *(item[3] for item in SUBJECTS)}
    if (manifest["schema"] != "zenon-nom-observation-manifest-v1" or fixture["schema"] != "zenon-nom-observation-corpus-v1"
            or manifest["core_commit"] != CORE_COMMIT or fixture["core_commit"] != CORE_COMMIT
            or manifest["profile"] != PROFILE or fixture["profile"] != PROFILE
            or manifest["expected_counts"] != COUNTS or manifest["input_sha256"].keys() != wanted
            or (manifest["application"], manifest["core"], manifest["assessment"]) != ("NO-GO", "NO-GO", "UNFILLED")
            or len(fixture["claim_vectors"]) != 48 or len(fixture["stateful_vectors"]) != 16
            or len(fixture["verifier_vectors"]) != 14 or len(fixture["vm_vectors"]) != 4):
        raise ValueError("selected observation subject changed")
    for name, value in {**manifest["input_sha256"], **manifest["preserved_file_sha256"]}.items():
        if digest(root / name) != value:
            raise ValueError("selected or preserved input changed")
    expected_tests(fixture)
    measured = {name: digest(root / name) for name in (MANIFEST, *sorted(wanted),
                "offline_session/nom_observation.py", "scripts/generate_nom_observation.py",
                "scripts/qualify_nom_observation_core.py", "scripts/qualify_nom_wire_core.py", "scripts/nom_native_command.py")}
    return manifest, fixture, measured


def qualify(checkout, go, *, root=ROOT, evidence_parent=None):
    root, checkout, go = root.resolve(), checkout.resolve(), go.resolve()
    manifest, fixture, before = inputs(root)
    core_state(checkout, manifest)
    tool_hash = digest(go)
    parent = evidence_parent or root / ".research-cache/nom-observation-core-evidence"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private evidence ownership required")
    evidence = Path(tempfile.mkdtemp(prefix="core-observation-", dir=parent))
    record = {"schema": "zenon-nom-observation-core-result-v1", "core_commit": CORE_COMMIT, "profile": PROFILE,
              "outcome": "UNKNOWN", "application": "NO-GO", "core": "NO-GO", "account_admission": "NOT_PERFORMED",
              "activation": "NOT_PERFORMED", "chain_observation": "NOT_PERFORMED", "signing": "NOT_PERFORMED",
              "independent_assessment": "UNFILLED", "runtime_authentication": "UNFILLED",
              "execution_context": "EXPLICIT SYNTHETIC STORAGE, TIME AND LEDGER STUBS",
              "witness_success_origin": "SEEDED OLD SYNTHETIC ENTRY; NOT THE CREATED FUNDING HASH",
              "overlay_vet": "NOT_PERFORMED; synthetic overlay paths are unavailable to Go 1.23 vet",
              "go_executable_sha256": tool_hash, "input_sha256": before}
    try:
        replacements = {}
        for package, _, _, driver in SUBJECTS:
            selected = checkout / package / "zz_research_nom_observation_test.go"
            if selected.exists() or selected.is_symlink():
                raise ValueError("overlay would replace existing input")
            replacements[str(selected)] = str(root / driver)
        overlay = evidence / "overlay.json"
        with private_create(overlay) as out:
            out.write(json.dumps({"Replace": replacements}, sort_keys=True).encode("ascii"))
        environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off",
                           PTLC_NOM_OBSERVATION_FIXTURE=str(root / FIXTURE))
        command = [str(go), "test", "-json", "-overlay", str(overlay), "-vet=off", "-mod=readonly", "-count=1",
                   "-run", "^TestResearchNoMObservation", *("./" + item[0] for item in SUBJECTS)]
        wire = run(command, environment=environment, directory=checkout, evidence=evidence,
                   label="core-observation", timeout=240)
        record["passed_tests_including_parents"] = parse_outcome(wire, expected_tests(fixture))
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
    try:
        print(json.dumps(qualify(args.checkout, args.go), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, WorkerError):
        print("FAIL: selected core observation differential; preserve original private evidence", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
