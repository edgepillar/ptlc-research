#!/usr/bin/env python3
"""Qualify explicit actor process death using a selected public-only worker.

Original child streams and journals survive every attempted case. A complete
public response can exist in diagnostic evidence while absent from the journal.
Reopen is read-only and never supplies absent output or enters recovery again.
The selected cuts do not establish interior disk-fault or power-loss behavior.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_recovery import NomRecovery, RecoveryError, canonical, decode  # noqa: E402
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE  # noqa: E402
from scripts.nom_cut_capture import OriginalCapture, retain, sha  # noqa: E402
from scripts import qualify_nom_recovery_cuts as prior  # noqa: E402

PROFILE = "ptlc-nom-process-death-v1"
BASE = "1b79d4f6e39fa30b9944c3164ae64b04a880c6c2"
FIXTURE = "compatibility/fixtures/nom_process_death_v1.json"
MANIFEST = "compatibility/nom_process_death_manifest.json"
SELECTED = ("scripts/nom_death_actor.py", "scripts/qualify_nom_process_death.py",
            "tests/test_nom_process_death.py", FIXTURE)
NATIVE_INPUTS = ()
CUTS = ("after-remote-short", "after-recovery-admitted", "after-public-reply",
        "after-recovered", "after-original")
BOUNDARY = dict(application="NO-GO", core="NO-GO", recovery_action="NONE",
    hold_admission="NOT_COMPOSED", native_query_context="NOT_COMPOSED",
    observation_source="DISCLOSED SYNTHETIC ALLOWLIST ONLY", current_chain_authority="UNFILLED",
    restore_fence="UNFILLED", atomic_work_admission="UNFILLED", independent_runtime="UNFILLED",
    process_death="SELECTED ACTOR os._exit(72) OBSERVED",
    interior_write_or_fsync_fault="NOT_PERFORMED", power_loss="NOT_PERFORMED",
    cut_kind="EXPLICIT PROCESS EXIT AFTER COMPLETE FSYNC OR RETURNED PUBLIC REPLY",
    runner="SEPARATE TRUSTED ACTOR AND ORIGINAL-CAPTURE QUALIFICATION TRANSPORT",
    hostile_process_containment="NOT_ESTABLISHED", runtime_authentication="UNFILLED")


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Disclosed public synthetic journal and observation inputs only",
        cases=[dict(cut=cut, charged=0 if index == 0 else 1,
            retained_result=index >= 3, retained_long_original=index == 4,
            recovery_worker_entries=1 if index >= 2 else 0, actor_exit_code=72)
            for index, cut in enumerate(CUTS)], boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name: sha((root / name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-process-death-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected,
        preserved_file_sha256=preserved, native_file_sha256={}, boundary=BOUNDARY)
    if json.loads((root / FIXTURE).read_text("ascii")) != corpus():
        raise ValueError("selected process-death corpus changed")
    if json.loads((root / MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected process-death inputs changed")
    return expected, {**preserved, **selected, MANIFEST: sha((root / MANIFEST).read_bytes())}


def actor(directory, config, *, root=ROOT, python=None):
    """No retries. Whole observed streams are retained before any verdict.

    communicate uses memory before size checks; direct-child timeout cleanup is
    only for this trusted nonforking actor, not arbitrary descendant containment.
    The worker is already reaped at every selected exit boundary.
    """
    python = Path(sys.executable) if python is None else Path(python)
    # Qualification metadata is not a size-limited protocol reference value.
    config_wire = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("ascii")
    retain(directory / "configuration-before-spawn.json", config_wire)
    process = None
    output = error = b""
    row = dict(cut=config["cut"], exit_code=None, stream_completeness="NOT_ESTABLISHED")
    try:
        process = subprocess.Popen([str(python), "-B", "-u", str(root / SELECTED[0]),
            str(directory / "configuration-before-spawn.json")], env={}, close_fds=True,
            start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output, error = process.communicate(timeout=30)
            row["stream_completeness"] = "COMPLETE"
        except subprocess.TimeoutExpired:
            process.kill()
            output, error = process.communicate(timeout=1)
            row["stream_completeness"] = "COMPLETE_AFTER_TIMEOUT"
            raise ValueError("selected actor timed out") from None
        if len(output) > 4096 or len(error) > 8192:
            raise ValueError("selected actor stream exceeds the scenario boundary")
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            try:
                output, error = process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                row["stream_completeness"] = "PARTIAL; CLEANUP UNRESOLVED"
        if process is not None:
            row["exit_code"] = process.returncode
            for stream in (process.stdout, process.stderr):
                stream.close()
        row.update(stdout_hex=output.hex(), stderr_hex=error.hex(),
                   stdout_sha256=sha(output), stderr_sha256=sha(error))
        retain(directory / "actor.stdout", output)
        retain(directory / "actor.stderr", error)
        retain(directory / "actor.receipt.json", canonical(row))
    return row


def read_calls(directory):
    receipts = sorted(directory.glob("call-*.receipt.json"))
    calls = []
    for index, path in enumerate(receipts, 1):
        row = json.loads(path.read_text("ascii"))
        if row["number"] != index or row["exit_code"] != 0 or row["stream_completeness"] != "COMPLETE":
            raise ValueError("original worker response is incomplete or refused")
        for suffix, key in (("stdin", "request"), ("stdout", "stdout"), ("stderr", "stderr")):
            wire = (directory / f"call-{index:03d}.{suffix}").read_bytes()
            if wire.hex() != row[key + "_hex"] or sha(wire) != row[key + "_sha256"]:
                raise ValueError("original worker stream changed")
        calls.append(row)
    return calls


def check_cases(report):
    rows = report["cases"]
    if len(rows) != len(CUTS):
        raise ValueError("missing selected process-death case")
    for index, (row, selected) in enumerate(zip(rows, corpus()["cases"])):
        marker = canonical(dict(schema="ptlc-nom-death-actor-v1", cut=selected["cut"], method="os._exit(72)")) + b"\n"
        expected_hook = ("PUBLIC REPLY RETURNED; BEFORE RECOVERED APPEND" if index == 2
                         else selected["cut"].removeprefix("after-"))
        write_modes = ["verify-pair", "verify-short"] + (["recover-long"] if index >= 2 else [])
        write_modes += (["verify-long"] if index >= 3 else []) + (["verify-long"] if index == 4 else [])
        receipt = row["death_receipt"]
        if (any(row[key] != value for key, value in selected.items()
                if key not in ("retained_result", "retained_long_original"))
                or (row["retained_result"] is not None) != selected["retained_result"]
                or (row["retained_long_original"] is not None) != selected["retained_long_original"]
                or row["recovery_worker_returns"] != selected["recovery_worker_entries"]
                or not row["disclosure_possible"] or not row["journal_unchanged_after_reopen"]
                or row["automatic_worker_entries_on_reopen"] != 0 or row["observer_calls_on_replay"] != 0
                or row["reopen_modes"] != ["verify-pair"] + (["verify-long"] if index == 4 else []) + ["verify-short"]
                or row["qualification_reply_retained"] != (index >= 2)
                or row["actor_streams"]["exit_code"] != 72
                or row["actor_streams"]["stream_completeness"] != "COMPLETE"
                or row["actor_streams"]["stdout_hex"] != marker.hex()
                or row["actor_streams"]["stderr_hex"] != ""
                or receipt["cut"] != selected["cut"] or receipt["method"] != "os._exit(72)"
                or receipt["hook_kind"] != expected_hook or receipt["write_modes"] != write_modes
                or receipt["recovery_worker_entries"] != selected["recovery_worker_entries"]
                or receipt["recovery_worker_returns"] != selected["recovery_worker_entries"]
                or (receipt["returned_result"] is not None) != (index >= 2)):
            raise ValueError("selected process-death custody or charge changed")


def qualify(executable, *, evidence_directory, root=ROOT):
    manifest, measured = inputs(root)
    executable = executable.resolve()
    pin = sha(executable.read_bytes())
    python = Path(sys.executable).resolve()
    python_pin = sha(python.read_bytes())
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
    parent = evidence_directory / "reopen-worker"
    parent.mkdir(mode=0o700)
    capture = OriginalCapture(parent, executable, pin)
    terms, pair, _, funded, confirmed = prior.selected_inputs(root)
    verifier = NomPublicVerifier(executable, pin, terms, pair, execution_profile=CLEAN_EXECUTION_PROFILE)
    cases = []
    actor_calls = {}
    for cut in CUTS:
        directory = evidence_directory / cut
        directory.mkdir(mode=0o700)
        (directory / "worker").mkdir(mode=0o700)
        config = dict(directory=str(directory.resolve()), executable=str(executable),
                      executable_sha256=pin, input_sha256=measured, cut=cut)
        streams = actor(directory, config, root=root, python=python)
        if streams["exit_code"] != 72 or streams["stream_completeness"] != "COMPLETE":
            raise ValueError("selected actor death was not observed; originals retained")
        receipt = json.loads((directory / "cut-receipt.json").read_text("ascii"))
        calls = read_calls(directory / "worker")
        actor_calls[cut] = calls
        original = (directory / "journal.log").read_bytes()
        counted = prior.CountedVerifier(verifier)
        replay_calls = []
        def rejecting_observer(proof):
            replay_calls.append(canonical(proof).hex())
            return False
        capture.phase = cut + ":reopen"
        with patch("offline_session.nom_verifier.run_clean_environment_public_worker", capture.run):
            with NomRecovery.open(directory / "journal.log", terms, pair, role="bob",
                    verifier=counted, observation_verifier=rejecting_observer) as store:
                row = prior.describe(store.status(), original)
            reopen_modes = list(counted.modes)
            result_check = "ABSENT; NOT SUPPLIED FROM FIXTURE"
            if row["retained_result"] is not None:
                capture.phase = cut + ":separate-result-verification"
                if counted.verify_claim("long", row["retained_result"]) is not True:
                    raise ValueError("retained result failed separate public verification")
                result_check = "SEPARATELY PUBLIC-WORKER VERIFIED AFTER REOPEN"
        if (directory / "journal.log").read_bytes() != original:
            raise ValueError("original process-death journal changed on reopen")
        row.update(cut=cut, actor_exit_code=streams["exit_code"], actor_streams=streams,
            death_receipt=receipt, recovery_worker_entries=receipt["recovery_worker_entries"],
            recovery_worker_returns=receipt["recovery_worker_returns"], reopen_modes=reopen_modes,
            observer_calls_before_cut=receipt["observer_calls_before_cut"],
            observer_calls_on_replay=len(replay_calls), result_check=result_check,
            automatic_worker_entries_on_reopen=counted.entries,
            journal_unchanged_after_reopen=True,
            qualification_reply_retained=receipt["returned_result"] is not None)
        cases.append(row)
    report = dict(schema="ptlc-nom-process-death-result-v1", profile=PROFILE, outcome="PASS",
        input_sha256=measured, source_unchanged=True, executable_sha256=pin,
        python_executable_sha256=python_pin, execution_profile=CLEAN_EXECUTION_PROFILE,
        source_snapshots="BEFORE FIRST ACTOR OR WORKER SPAWN",
        original_capture="COMPLETE ACTOR AND WORKER STDOUT/STDERR/EXIT; WORKER REQUESTS; NO RETRIES",
        journal_custody="FIVE ORIGINAL FILES; RETURNED REPLIES RETAINED AS SEPARATE DIAGNOSTICS",
        prior_measured_inputs=len(manifest["preserved_file_sha256"]),
        preserved_core_source_outcomes=342, new_core_source_outcomes=0,
        cases=cases, actor_worker_calls=actor_calls, reopen_worker_calls=read_calls(parent),
        synthetic_allowlist_hex=sorted(canonical(proof).hex() for proof in funded + [confirmed]), **BOUNDARY)
    check_cases(report)
    if measured != inputs(root)[1] or sha(executable.read_bytes()) != pin or sha(python.read_bytes()) != python_pin:
        raise ValueError("selected source, public worker or actor executable changed")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_swap")
    parser.add_argument("--evidence-directory", type=Path)
    args = parser.parse_args()
    selected = args.evidence_directory
    if selected is None:
        selected = Path(tempfile.mkdtemp(prefix="ptlc-nom-death-")) / "originals"
    try:
        result = qualify(args.executable, evidence_directory=selected)
    except (OSError, RecoveryError, ValueError, KeyError, TypeError):
        print("FAIL: selected public-worker process-death qualification; preserve original evidence", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
