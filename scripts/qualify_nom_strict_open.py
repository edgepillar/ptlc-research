#!/usr/bin/env python3
"""Qualify explicitly selected read-only open of exact reference journals.

The unchanged trusted actor supplies five actual process-death journals. Present
public results must pass the selected worker before strict open returns. Missing
results stay missing. One separately retained self-rehashed invalid copy exposes
the distinction from legacy encoding-only replay. Original streams survive each
attempt; no automatic recovery, original construction or hold admission occurs.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_recovery import NomRecovery, RecoveryError, canonical, fcntl  # noqa: E402
from offline_session.nom_strict_open import StrictNomRecovery, PROFILE as OPEN_PROFILE  # noqa: E402
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE  # noqa: E402
from scripts.nom_cut_capture import OriginalCapture, retain, sha  # noqa: E402
from scripts import qualify_nom_process_death as prior  # noqa: E402

PROFILE = "ptlc-nom-strict-open-qualification-v1"
BASE = "9a6c97054713e1075b3c159f405665d49850d2a0"
FIXTURE = "compatibility/fixtures/nom_strict_open_v1.json"
MANIFEST = "compatibility/nom_strict_open_manifest.json"
SELECTED = ("offline_session/nom_strict_open.py", "scripts/qualify_nom_strict_open.py",
            "tests/test_nom_strict_open.py", FIXTURE)
NATIVE_INPUTS = ()
CUTS = prior.CUTS
BOUNDARY = dict(prior.BOUNDARY, selected_open=OPEN_PROFILE,
    journal_access="EXISTING FILE; READ-ONLY DESCRIPTOR; NO CREATION",
    present_result="DIRECT PUBLIC VERIFICATION BEFORE OWNER RETURN",
    legacy_open="UNCHANGED; RESULT-ONLY ENCODING ACCEPTANCE PRESERVED",
    recovery_entry="REFUSED BEFORE WORKER ENTRY BY SELECTED READ-ONLY OWNER",
    current_observation_revalidation="NOT_PERFORMED; RETAINED HISTORY ONLY")


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Disclosed public synthetic journal and observation inputs only",
        cases=[dict(cut=cut, charged=0 if index == 0 else 1,
            retained_result=index >= 3, retained_long_original=index == 4,
            recovery_worker_entries=1 if index >= 2 else 0, actor_exit_code=72,
            strict_result_checks=1 if index >= 3 else 0)
            for index, cut in enumerate(CUTS)],
        adversarial_copy="SEPARATE SELF-REHASHED ZERO PUBLIC RESULT; NEVER REPLACES ORIGINAL",
        boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name: sha((root / name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-strict-open-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected,
        preserved_file_sha256=preserved, native_file_sha256={}, boundary=BOUNDARY)
    if json.loads((root / FIXTURE).read_text("ascii")) != corpus():
        raise ValueError("selected strict-open corpus changed")
    if json.loads((root / MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected strict-open inputs changed")
    return expected, {**preserved, **selected, MANIFEST: sha((root / MANIFEST).read_bytes())}


def read_calls(directory):
    """Validate retained streams without turning an expected refusal into success."""
    values = []
    for number, path in enumerate(sorted(directory.glob("call-*.receipt.json")), 1):
        row = json.loads(path.read_text("ascii"))
        if row["number"] != number or row["stream_completeness"] != "COMPLETE":
            raise ValueError("original selected worker stream is incomplete")
        for suffix, key in (("stdin", "request"), ("stdout", "stdout"), ("stderr", "stderr")):
            wire = (directory / f"call-{number:03d}.{suffix}").read_bytes()
            if wire.hex() != row[key + "_hex"] or sha(wire) != row[key + "_sha256"]:
                raise ValueError("original selected worker stream changed")
        values.append(row)
    return values


def owner_available(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    finally:
        os.close(descriptor)


def check_cases(report):
    rows = report["cases"]
    if len(rows) != len(CUTS):
        raise ValueError("missing selected strict-open case")
    for index, (row, selected) in enumerate(zip(rows, corpus()["cases"])):
        marker = canonical(dict(schema="ptlc-nom-death-actor-v1", cut=selected["cut"], method="os._exit(72)")) + b"\n"
        modes = ["verify-pair"] + (["verify-long"] if index == 4 else []) + ["verify-short"]
        modes += ["verify-long"] if index >= 3 else []
        receipt = row["death_receipt"]
        if (any(row[key] != value for key, value in selected.items()
                if key not in ("retained_result", "retained_long_original"))
                or (row["retained_result"] is not None) != selected["retained_result"]
                or (row["retained_long_original"] is not None) != selected["retained_long_original"]
                or row["reopen_modes"] != modes or row["recovery_worker_returns"] != selected["recovery_worker_entries"]
                or not row["disclosure_possible"] or not row["journal_unchanged_after_reopen"]
                or row["automatic_worker_entries_on_reopen"] != 0 or row["observer_calls_on_replay"] != 0
                or row["qualification_reply_retained"] != (index >= 2)
                or row["actor_streams"]["exit_code"] != 72
                or row["actor_streams"]["stream_completeness"] != "COMPLETE"
                or row["actor_streams"]["stdout_hex"] != marker.hex() or row["actor_streams"]["stderr_hex"] != ""
                or receipt["cut"] != selected["cut"] or receipt["method"] != "os._exit(72)"
                or row["result_check"] != ("DIRECTLY PUBLIC-WORKER VERIFIED BEFORE OWNER RETURN" if index >= 3
                                         else "ABSENT; NOT SUPPLIED FROM FIXTURE")):
            raise ValueError("selected strict-open custody or verification changed")
    negative = report["adversarial_control"]
    if (negative["legacy_modes"] != ["verify-pair", "verify-short"]
            or negative["strict_modes"] != ["verify-pair", "verify-short", "verify-long"]
            or negative["legacy_result"] != "00" * 64 or negative["charged"] != 1
            or negative["strict_outcome"] != "REFUSED BEFORE OWNER RETURN"
            or not negative["owner_released"] or not negative["copy_unchanged"]
            or negative["automatic_worker_entries"] != 0 or negative["retained_long_original"] is not None):
        raise ValueError("selected adversarial copy control changed")
    parent = report["reopen_worker_calls"]
    if len(parent) != 18 or any(row["exit_code"] != (2 if index == 17 else 0) for index, row in enumerate(parent)):
        raise ValueError("selected strict-open worker exit evidence changed")


def qualify(executable, *, evidence_directory, root=ROOT):
    manifest, measured = inputs(root)
    executable = executable.resolve(); pin = sha(executable.read_bytes())
    python = Path(sys.executable).resolve(); python_pin = sha(python.read_bytes())
    evidence_directory.mkdir(mode=0o700)
    subject = dict(input_sha256=measured, executable_sha256=pin,
        executable_bytes=executable.stat().st_size, python_executable_sha256=python_pin,
        python_executable_bytes=python.stat().st_size, before_first_actor_or_worker_spawn=True)
    retain(evidence_directory / "subject-before-first-spawn.json",
           json.dumps(subject, sort_keys=True, separators=(",", ":")).encode("ascii"))
    retain(evidence_directory / "selected-public-executable.original", executable.read_bytes())
    retain(evidence_directory / "selected-python-executable.original", python.read_bytes())
    for index, name in enumerate(measured):
        retain(evidence_directory / f"source-{index:03d}.original", (root / name).read_bytes())
    parent = evidence_directory / "reopen-worker"; parent.mkdir(mode=0o700)
    capture = OriginalCapture(parent, executable, pin)
    terms, pair, _, funded, confirmed = prior.prior.selected_inputs(root)
    verifier = NomPublicVerifier(executable, pin, terms, pair, execution_profile=CLEAN_EXECUTION_PROFILE)
    cases = []; actor_calls = {}; journals = {}
    for index, cut in enumerate(CUTS):
        directory = evidence_directory / cut; directory.mkdir(mode=0o700)
        (directory / "worker").mkdir(mode=0o700)
        config = dict(directory=str(directory.resolve()), executable=str(executable),
                      executable_sha256=pin, input_sha256=measured, cut=cut)
        streams = prior.actor(directory, config, root=root, python=python)
        if streams["exit_code"] != 72 or streams["stream_completeness"] != "COMPLETE":
            raise ValueError("selected actor death was not observed; originals retained")
        receipt = json.loads((directory / "cut-receipt.json").read_text("ascii"))
        actor_calls[cut] = prior.read_calls(directory / "worker")
        original = (directory / "journal.log").read_bytes(); journals[cut] = original
        counted = prior.prior.CountedVerifier(verifier); replay_calls = []
        def rejecting_observer(proof):
            replay_calls.append(canonical(proof).hex())
            return False
        capture.phase = cut + ":strict-open"
        with patch("offline_session.nom_verifier.run_clean_environment_public_worker", capture.run):
            with StrictNomRecovery.open(directory / "journal.log", terms, pair, role="bob",
                    verifier=counted, observation_verifier=rejecting_observer) as store:
                row = prior.prior.describe(store.status(), original)
        if (directory / "journal.log").read_bytes() != original:
            raise ValueError("original journal changed during strict open")
        row.update(cut=cut, actor_exit_code=streams["exit_code"], actor_streams=streams,
            death_receipt=receipt, recovery_worker_entries=receipt["recovery_worker_entries"],
            recovery_worker_returns=receipt["recovery_worker_returns"], reopen_modes=counted.modes,
            strict_result_checks=1 if index >= 3 else 0,
            observer_calls_before_cut=receipt["observer_calls_before_cut"], observer_calls_on_replay=len(replay_calls),
            result_check="DIRECTLY PUBLIC-WORKER VERIFIED BEFORE OWNER RETURN" if index >= 3
                         else "ABSENT; NOT SUPPLIED FROM FIXTURE",
            automatic_worker_entries_on_reopen=counted.entries, journal_unchanged_after_reopen=True,
            qualification_reply_retained=receipt["returned_result"] is not None)
        cases.append(row)
    changed = prior.prior.rewrite_self_hashes(journals["after-recovered"],
        lambda records: records[-1]["event"].update(signature_hex="00" * 64))
    target = evidence_directory / "adversarial-result-only.log"; retain(target, changed)
    legacy = prior.prior.CountedVerifier(verifier); strict = prior.prior.CountedVerifier(verifier)
    with patch("offline_session.nom_verifier.run_clean_environment_public_worker", capture.run):
        capture.phase = "invalid-result-only:legacy-open"
        with NomRecovery.open(target, terms, pair, role="bob", verifier=legacy,
                              observation_verifier=lambda proof: False) as store:
            status = store.status()
        capture.phase = "invalid-result-only:strict-open"
        try:
            store = StrictNomRecovery.open(target, terms, pair, role="bob", verifier=strict,
                                           observation_verifier=lambda proof: False)
        except RecoveryError:
            pass
        else:
            store.close()
            raise ValueError("invalid public result passed strict open")
    negative = dict(legacy_modes=legacy.modes, strict_modes=strict.modes,
        legacy_result=status["recovered_long_hex"], charged=status["recovery_count"],
        retained_long_original=status["originals"].get("long"), strict_outcome="REFUSED BEFORE OWNER RETURN",
        owner_released=owner_available(target), copy_unchanged=target.read_bytes() == changed,
        automatic_worker_entries=strict.entries, copy_hex=changed.hex(), copy_sha256=sha(changed))
    report = dict(schema="ptlc-nom-strict-open-result-v1", profile=PROFILE, outcome="PASS",
        input_sha256=measured, source_unchanged=True, executable_sha256=pin,
        python_executable_sha256=python_pin, execution_profile=CLEAN_EXECUTION_PROFILE,
        source_snapshots="BEFORE FIRST ACTOR OR WORKER SPAWN",
        original_capture="COMPLETE ACTOR AND WORKER STDOUT/STDERR/EXIT; WORKER REQUESTS; NO RETRIES",
        journal_custody="FIVE ORIGINAL FILES AND ONE SEPARATE SELF-REHASHED ADVERSARIAL COPY",
        prior_measured_inputs=len(manifest["preserved_file_sha256"]),
        preserved_core_source_outcomes=342, new_core_source_outcomes=0,
        cases=cases, actor_worker_calls=actor_calls, reopen_worker_calls=read_calls(parent),
        adversarial_control=negative,
        synthetic_allowlist_hex=sorted(canonical(proof).hex() for proof in funded + [confirmed]), **BOUNDARY)
    check_cases(report)
    if (any((evidence_directory / cut / "journal.log").read_bytes() != wire for cut, wire in journals.items())
            or measured != inputs(root)[1] or sha(executable.read_bytes()) != pin
            or sha(python.read_bytes()) != python_pin):
        raise ValueError("selected source, executables or original journals changed")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_swap")
    parser.add_argument("--evidence-directory", type=Path)
    args = parser.parse_args()
    selected = args.evidence_directory
    if selected is None:
        selected = Path(tempfile.mkdtemp(prefix="ptlc-nom-strict-open-")) / "originals"
    try:
        result = qualify(args.executable, evidence_directory=selected)
    except (OSError, RecoveryError, ValueError, KeyError, TypeError):
        print("FAIL: selected strict reference-open qualification; preserve original evidence", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
