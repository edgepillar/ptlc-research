#!/usr/bin/env python3
"""Qualify selected read-only journal projection after actual reference actor exits.

The frozen strict-open qualification retains its original five journals and
invalid copy. Additional strict opens project four admitted cuts and one coherent
old copy into HOLD. Diagnostic replies never populate missing journal output.
All work outcomes remain UNKNOWN; this selection implements no recovery action.
"""

import argparse
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import nom_partial_custody as partial, nom_recovery as recovery  # noqa: E402
from offline_session.nom_journal_hold import (  # noqa: E402
    PROFILE as HOLD_PROFILE, WORK_DOMAIN, JournalProjectionRefused, project_partial_hold,
)
from offline_session.nom_strict_open import StrictNomRecovery  # noqa: E402
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE  # noqa: E402
from scripts.nom_cut_capture import OriginalCapture, retain, sha  # noqa: E402
from scripts import qualify_nom_strict_open as prior  # noqa: E402

PROFILE = "ptlc-nom-journal-hold-qualification-v1"
BASE = "8c4e1d2f63f1ab8d7812a242622b45f32c11f9fa"
FIXTURE = "compatibility/fixtures/nom_journal_hold_v1.json"
MANIFEST = "compatibility/nom_journal_hold_manifest.json"
SELECTED = ("offline_session/nom_journal_hold.py", "scripts/qualify_nom_journal_hold.py",
            "tests/test_nom_journal_hold.py", FIXTURE)
NATIVE_INPUTS = ()
CUTS = prior.CUTS
CHALLENGES = ("a1" * 32, "b2" * 32)
BOUNDARY = dict(prior.BOUNDARY, hold_admission="NOT_PROVIDED; READ-ONLY CUSTODY PROJECTION ONLY",
    selected_projection=HOLD_PROFILE, work_execution="UNKNOWN FOR EVERY PERSISTED CHARGED ORDINAL",
    work_identity="CONTEXT, EXACT SHORT AND ORDINAL; RESEARCH ONLY; NO AUTHENTICATED RECEIPT",
    absent_output="NULL; NEVER FILLED FROM DIAGNOSTIC REPLY",
    original_journal="FULL EXACT BYTES RETAINED SEPARATELY FROM BOUNDED PRIOR EVIDENCE",
    durable_projection="NOT_IMPLEMENTED; IN-MEMORY CUSTODY ONLY",
    complete_query_conversion="NOT_PROVIDED",
    coherent_copy_policy="ACCEPTED AS HOLD; NO CURRENTNESS OR RESTORE AUTHORITY",
    frozen_partial_review="UNCHANGED; PURE PROFILE MATH AND DURABILITY CLAIMS NOT PROMOTED")


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Disclosed public synthetic journals, public signatures and observation inputs only",
        cases=[dict(cut=cut, charged=0 if index == 0 else 1, projected=index != 0,
            retained_result=index >= 3, retained_long_original=index == 4,
            work_outcome="UNKNOWN" if index else None, actor_exit_code=72)
            for index, cut in enumerate(CUTS)], challenges_hex=list(CHALLENGES),
        prior_strict_worker_calls=34, additional_strict_worker_calls=15,
        projection_worker_calls=0, boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name: sha((root / name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-journal-hold-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected,
        preserved_file_sha256=preserved, native_file_sha256={}, boundary=BOUNDARY)
    if json.loads((root / FIXTURE).read_text("ascii")) != corpus():
        raise ValueError("selected journal HOLD corpus changed")
    if json.loads((root / MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected journal HOLD inputs changed")
    return expected, {**preserved, **selected, MANIFEST: sha((root / MANIFEST).read_bytes())}


def check_projection(value, source, challenge):
    """Check original custody and UNKNOWN selections, without signature arithmetic."""
    if type(value) is not dict or value.keys() != {
            "schema", "journal_hex", "journal_sha256", "journal_bytes", "journal_head_hex",
            "journal_sequence", "role", "partial_hold_hex", "selection_digest_hex"}:
        raise ValueError("selected full journal projection is unavailable")
    wire = bytes.fromhex(source["journal_hex"])
    records = prior.prior.prior.journal_records(wire)
    first = records[0]["event"]; terms, pair = first["terms"], first["pair"]
    held = partial._state(partial.uncertainty._decode(bytes.fromhex(value["partial_hold_hex"])))
    selection = partial._selection(partial.uncertainty._decode(bytes.fromhex(held["selection_hex"])))
    context = recovery.verification_context_digest(terms, pair)
    short_pin = partial.short_digest(bytes.fromhex(source["remote_short_hex"]))
    work = [dict(attempt_id_hex=recovery.digest(WORK_DOMAIN, dict(
        verification_context_digest_hex=context, short_original_digest_hex=short_pin,
        charged_ordinal=ordinal)), short_original_digest_hex=short_pin, outcome="UNKNOWN")
        for ordinal in range(1, source["charged"] + 1)]
    if (value != dict(schema=HOLD_PROFILE, journal_hex=wire.hex(), journal_sha256=sha(wire),
            journal_bytes=len(wire), journal_head_hex=records[-1]["hash_hex"],
            journal_sequence=len(records), role="bob", partial_hold_hex=value["partial_hold_hex"],
            selection_digest_hex=partial._selection_digest(selection))
            or held["refusal_wires_hex"] or held["source_claim_wires_hex"]
            or selection != dict(schema=partial.PROFILE, terms=terms, pair=pair,
                verification_context_digest_hex=context, remote_short_hex=source["remote_short_hex"],
                recovered_long_signature_hex=source["retained_result"],
                original_long_hex=source["retained_long_original"], charged_work=work,
                prior_evidence_hex=[], disclosure_possible=True, challenge_hex=challenge)):
        raise ValueError("selected journal custody or UNKNOWN work changed")
    return work


def check_cases(report):
    prior.check_cases(report["strict_open_result"])
    rows = report["cases"]
    if len(rows) != len(CUTS):
        raise ValueError("missing journal HOLD projection case")
    for index, (row, source) in enumerate(zip(rows, report["strict_open_result"]["cases"])):
        modes = ["verify-pair"] + (["verify-long"] if index == 4 else []) + ["verify-short"]
        modes += ["verify-long"] if index >= 3 else []
        if (row["cut"] != CUTS[index] or row["strict_open_modes"] != modes
                or row["observer_calls"] != 0 or row["projection_worker_calls"] != 0
                or row["recovery_worker_entries"] != 0 or not row["journal_unchanged"]):
            raise ValueError("journal projection entered work or changed original evidence")
        if index == 0:
            if row["projection"] is not None or row["outcome"] != "REFUSED; ZERO PERSISTED CHARGES":
                raise ValueError("zero-charge state acquired an invented work identity")
            continue
        work = check_projection(row["projection"], source, CHALLENGES[0])
        second = check_projection(row["alternate_challenge_projection"], source, CHALLENGES[1])
        review = row["review"]
        if (work != second or row["outcome"] != "HOLD" or review["state"] != "HOLD"
                or review["recovery_action"] != "NONE" or review["work_execution"] !=
                    "UNKNOWN; NO INDIVIDUAL EXECUTION RECEIPTS IN V1 JOURNAL"
                or review["frozen_partial_review"]["signature_mathematics"] != "NOT_PERFORMED"
                or review["frozen_partial_review"]["durable_retention"] != "NOT_IMPLEMENTED"
                or review["frozen_partial_review"]["charged_work"] != source["charged"]
                or review["application"] != "NO-GO" or review["core"] != "NO-GO"):
            raise ValueError("journal HOLD scope or challenge-independent work changed")
    copied = report["coherent_old_copy"]
    work = check_projection(copied["projection"], report["strict_open_result"]["cases"][1], CHALLENGES[0])
    if (copied["strict_open_modes"] != ["verify-pair", "verify-short"]
            or copied["projection"] != rows[1]["projection"] or len(work) != 1
            or copied["authority"] != "NONE; COHERENT COPY ACCEPTED ONLY AS HOLD"
            or not copied["copy_unchanged"] or copied["projection_worker_calls"] != 0):
        raise ValueError("coherent old copy supplied authority or changed custody")
    calls = report["projection_open_worker_calls"]
    if len(calls) != 15 or any(row["exit_code"] != 0 for row in calls):
        raise ValueError("additional strict-open original execution changed")


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
    strict = prior.qualify(executable, evidence_directory=evidence_directory / "strict-originals", root=root)
    directory = evidence_directory / "projection-worker"; directory.mkdir(mode=0o700)
    capture = OriginalCapture(directory, executable, pin)
    terms, pair, _, _, _ = prior.prior.prior.selected_inputs(root)
    verifier = NomPublicVerifier(executable, pin, terms, pair, execution_profile=CLEAN_EXECUTION_PROFILE)
    rows = []

    def selected(path, phase, index):
        counted = prior.prior.prior.CountedVerifier(verifier); observed = []
        def observer(proof):
            observed.append(recovery.canonical(proof).hex())
            return False
        original = path.read_bytes(); capture.phase = phase
        with patch("offline_session.nom_verifier.run_clean_environment_public_worker", capture.run):
            with StrictNomRecovery.open(path, terms, pair, role="bob", verifier=counted,
                                        observation_verifier=observer) as owner:
                opened = len(counted.modes)
                try:
                    projected = project_partial_hold(owner, challenge_hex=CHALLENGES[0])
                except JournalProjectionRefused:
                    if index != 0:
                        raise
                    row = dict(projection=None, outcome="REFUSED; ZERO PERSISTED CHARGES")
                else:
                    if index == 0:
                        raise ValueError("zero-charge journal acquired an admitted HOLD")
                    row = dict(projection=projected.as_dict(), review=projected.review(), outcome="HOLD",
                        alternate_challenge_projection=project_partial_hold(owner,
                            challenge_hex=CHALLENGES[1]).as_dict())
                row.update(strict_open_modes=counted.modes, observer_calls=len(observed),
                    projection_worker_calls=len(counted.modes) - opened, recovery_worker_entries=counted.entries,
                    journal_unchanged=path.read_bytes() == original)
        return row

    for index, cut in enumerate(CUTS):
        row = selected(evidence_directory / "strict-originals" / cut / "journal.log",
                       cut + ":projection-open", index)
        row["cut"] = cut; rows.append(row)
    copied = evidence_directory / "coherent-old-copy.log"
    retain(copied, bytes.fromhex(strict["cases"][1]["journal_hex"]))
    old = selected(copied, "coherent-old-copy:projection-open", 1)
    old_copy = dict(projection=old["projection"], strict_open_modes=old["strict_open_modes"],
        copy_unchanged=old["journal_unchanged"], projection_worker_calls=old["projection_worker_calls"],
        authority="NONE; COHERENT COPY ACCEPTED ONLY AS HOLD")
    report = dict(schema="ptlc-nom-journal-hold-result-v1", profile=PROFILE, outcome="PASS",
        input_sha256=measured, source_unchanged=True, executable_sha256=pin,
        python_executable_sha256=python_pin, execution_profile=CLEAN_EXECUTION_PROFILE,
        source_snapshots="BEFORE FIRST ACTOR OR WORKER SPAWN",
        original_capture="COMPLETE ACTOR AND WORKER STDOUT/STDERR/EXIT; WORKER REQUESTS; NO RETRIES",
        prior_measured_inputs=len(manifest["preserved_file_sha256"]),
        preserved_core_source_outcomes=342, new_core_source_outcomes=0,
        strict_open_result=strict, cases=rows, coherent_old_copy=old_copy,
        projection_open_worker_calls=prior.read_calls(directory),
        prior_strict_worker_calls=34, additional_strict_worker_calls=15,
        projection_worker_calls=0, total_worker_calls=49, **BOUNDARY)
    check_cases(report)
    if (measured != inputs(root)[1] or sha(executable.read_bytes()) != pin
            or sha(python.read_bytes()) != python_pin
            or copied.read_bytes().hex() != strict["cases"][1]["journal_hex"]
            or any((evidence_directory / "strict-originals" / cut / "journal.log").read_bytes().hex()
                   != row["journal_hex"] for cut, row in zip(CUTS, strict["cases"]))):
        raise ValueError("selected source, executable or original journal changed")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_swap")
    parser.add_argument("--evidence-directory", type=Path)
    args = parser.parse_args()
    selected = args.evidence_directory
    if selected is None:
        selected = Path(tempfile.mkdtemp(prefix="ptlc-nom-journal-hold-")) / "originals"
    try:
        result = qualify(args.executable, evidence_directory=selected)
    except (OSError, recovery.RecoveryError, ValueError, KeyError, TypeError):
        print("FAIL: selected journal HOLD qualification; preserve original evidence", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
