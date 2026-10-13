#!/usr/bin/env python3
"""Qualify create-only capsule custody after seven actual selected actor exits.

All original streams and files are retained separately from consumer authority.
Every readable view stays HOLD; copied bytes supply no currentness or restore.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import nom_capsule as capsule, nom_journal_hold as projection  # noqa: E402
from offline_session import nom_recovery as recovery  # noqa: E402
from offline_session.nom_strict_open import StrictNomRecovery  # noqa: E402
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE  # noqa: E402
from scripts.nom_cut_capture import OriginalCapture, retain, sha  # noqa: E402
from scripts import qualify_nom_journal_hold as prior  # noqa: E402

PROFILE = "ptlc-nom-capsule-qualification-v1"
BASE = "9c77941751f3b6b3f5f6bd5962d4b8b3bd30e751"
FIXTURE = "compatibility/fixtures/nom_capsule_v1.json"
MANIFEST = "compatibility/nom_capsule_manifest.json"
ACTOR = "scripts/nom_capsule_actor.py"
SELECTED = ("offline_session/nom_capsule.py", "scripts/qualify_nom_capsule.py", ACTOR,
            "tests/test_nom_capsule.py", FIXTURE)
BOUNDARY = dict(prior.BOUNDARY, selected_capsule=capsule.PROFILE,
    capsule_persistence="CREATE ONLY; OBSERVED OS FLUSH RETURNS; NO OVERWRITE OR REPAIR",
    capsule_consumer="READ ONLY; STRUCTURAL COMPARISON; ZERO WORKER ENTRY",
    capsule_math="NOT PERFORMED BY CONSUMER; PRODUCER SELECTS THE FROZEN STRICT OPEN",
    producer_origin="NOT_AUTHENTICATED", durable_projection="ORDINARY OS OBSERVATIONS ONLY",
    power_loss="NOT_QUALIFIED", interior_disk_faults="NOT_QUALIFIED; UNIT INJECTION IS SEPARATE",
    copied_capsule="HOLD; NO CURRENTNESS OR RESTORE AUTHORITY",
    frozen_partial_review="UNCHANGED; NO DURABILITY OR MATH PROMOTION")


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Disclosed public synthetic journals and capsules only",
        cases=[dict(cut=cut, actor_exit_code=73, readable=index >= 3,
            file_mode="0400" if index >= 3 else "0600",
            retained_bytes="EMPTY" if index == 0 else "COMPLETE",
            work_outcome="UNKNOWN", recovery_action="NONE")
            for index,cut in enumerate(capsule.PHASES)],
        prior_worker_calls=49, actor_worker_calls=14, successful_producer_worker_calls=4,
        consumer_worker_calls=0, total_worker_calls=67, boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name:sha((root/name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-capsule-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected,
        preserved_file_sha256=preserved, boundary=BOUNDARY)
    if json.loads((root/FIXTURE).read_text("ascii")) != corpus(): raise ValueError("capsule corpus changed")
    if json.loads((root/MANIFEST).read_text("ascii")) != expected: raise ValueError("capsule inputs changed")
    return expected, {**preserved, **selected, MANIFEST:sha((root/MANIFEST).read_bytes())}


def check_view(value, expected_projection):
    wire = bytes.fromhex(value["capsule_hex"])
    view = capsule.read_capsule(wire, expected_digest_hex=value["capsule_sha256"])
    if (view.projection() != expected_projection or value["review"] != view.review()
            or any(row["outcome"] != "UNKNOWN" for row in view.partial_hold.selection()["charged_work"])
            or value["review"]["recovery_action"] != "NONE"):
        raise ValueError("capsule view promoted authority or changed full original custody")


def check_calls(calls, source, phase, modes):
    """Check exact captured requests/replies, without a verifier process or math."""
    replay, _, _ = projection._replay(bytes.fromhex(source["journal_hex"]))
    verifier = object.__new__(NomPublicVerifier)
    verifier._terms = replay.terms; verifier._pair = replay.pair
    verifier.context_digest_hex = recovery.verification_context_digest(replay.terms, replay.pair)
    if len(calls) != len(modes): raise ValueError("capsule worker originals are missing")
    for index,(row,(mode,signature)) in enumerate(zip(calls,modes),1):
        request = recovery.canonical(verifier.request(mode, signature))
        reply = recovery.canonical(dict(schema="ptlc-nom-public-verification-result-v1",
            request_digest_hex=sha(request), valid=True, completed_long_hex=""))
        if (row["number"] != index or row["phase"] != phase or row["request_hex"] != request.hex()
                or row["request_sha256"] != sha(request) or row["stdout_hex"] != reply.hex()
                or row["stdout_sha256"] != sha(reply) or row["stderr_hex"] != ""
                or row["stderr_sha256"] != sha(b"") or row["exit_code"] != 0
                or row["stream_completeness"] != "COMPLETE"):
            raise ValueError("capsule worker request, reply or original execution changed")


def check_cases(report):
    prior.check_cases(report["journal_projection_result"])
    source = report["journal_projection_result"]["cases"][1]["projection"]
    expected = capsule._wire(dict(schema=capsule.PROFILE, selected_projection=source))
    rows = report["cases"]
    if len(rows) != 7: raise ValueError("missing capsule process cut")
    for index,row in enumerate(rows):
        if (row["cut"] != capsule.PHASES[index] or row["actor_exit_code"] != 73
                or row["actor_stream_completeness"] != "COMPLETE" or row["actor_stderr_hex"] != ""
                or row["strict_open_modes"] != ["verify-pair", "verify-short"]
                or row["consumer_worker_calls"] != 0 or row["capsule_worker_entries"] != 0
                or row["file_mode"] != ("0400" if index >= 3 else "0600")
                or bytes.fromhex(row["retained_capsule_hex"]) != (b"" if index == 0 else expected)
                or row["expected_capsule_sha256"] != sha(expected)):
            raise ValueError("capsule actor originals or work entry changed")
        replay,_,_ = projection._replay(bytes.fromhex(source["journal_hex"]))
        short = recovery.claim_signature(replay.terms, "short", bytes.fromhex(replay._state["remote_short_hex"]))
        check_calls(row["actor_worker_calls"], source, row["cut"]+":strict-projection",
                    [("verify-pair", ""), ("verify-short", short)])
        if index < 3:
            if row["consumer"] is not None or row["outcome"] != "REFUSED; INCOMPLETE OR WRITABLE SHAPE":
                raise ValueError("incomplete persistence acquired a readable view")
        else:
            check_view(row["consumer"], source)
            if row["outcome"] != "HOLD": raise ValueError("readable capsule supplied a new action")
    success = report["successful_producer"]
    source = report["journal_projection_result"]["cases"][4]["projection"]
    check_view(success["consumer"], source)
    replay,_,_ = projection._replay(bytes.fromhex(source["journal_hex"]))
    original = recovery.claim_signature(replay.terms, "long", bytes.fromhex(replay._state["originals"]["long"]))
    short = recovery.claim_signature(replay.terms, "short", bytes.fromhex(replay._state["remote_short_hex"]))
    check_calls(success["worker_calls"], source, "successful-producer:strict-projection",
                [("verify-pair", ""), ("verify-long", original),
                 ("verify-short", short),
                 ("verify-long", replay._state["recovered_long_hex"])])
    if (success["strict_open_modes"] != ["verify-pair", "verify-long", "verify-short", "verify-long"]
            or success["store_receipt"]["file_fsync"] != "RETURNED; INCLUDING READONLY METADATA"
            or success["store_receipt"]["directory_fsync"] != "RETURNED"
            or success["store_receipt"]["power_loss"] != "NOT_QUALIFIED"
            or success["consumer_worker_calls"] != 0):
        raise ValueError("successful ordinary persistence gate changed")
    check_view(report["coherent_old_copy"]["consumer"], report["journal_projection_result"]["cases"][1]["projection"])
    if (report["coherent_old_copy"]["authority"] != "NONE; HOLD ONLY"
            or report["coherent_old_copy"]["consumer_worker_calls"] != 0
            or report["total_worker_calls"] != 67):
        raise ValueError("copied capsule supplied authority or changed work")


def qualify(executable, *, evidence_directory, root=ROOT):
    manifest, measured = inputs(root); executable = executable.resolve()
    executable_pin = sha(executable.read_bytes()); python = Path(sys.executable).resolve()
    evidence_directory.mkdir(mode=0o700)
    retain(evidence_directory/"subject-before-first-spawn.json", json.dumps(dict(
        input_sha256=measured, executable_sha256=executable_pin,
        python_executable_sha256=sha(python.read_bytes()), before_first_actor_or_worker_spawn=True),
        sort_keys=True,separators=(",", ":")).encode("ascii"))
    retain(evidence_directory/"selected-public-executable.original", executable.read_bytes())
    retain(evidence_directory/"selected-python-executable.original", python.read_bytes())
    for index,name in enumerate(measured): retain(evidence_directory/f"source-{index:03d}.original", (root/name).read_bytes())
    earlier = prior.qualify(executable, evidence_directory=evidence_directory/"journal-originals", root=root)
    source_journal = evidence_directory/"journal-originals"/"strict-originals"/prior.CUTS[1]/"journal.log"
    before_journal = source_journal.read_bytes(); rows = []
    def view(owner, expected):
        selected = owner.read(expected_digest_hex=expected)
        return dict(capsule_hex=selected.canonical_bytes.hex(), capsule_sha256=selected.digest_hex, review=selected.review())
    for index,cut in enumerate(capsule.PHASES):
        directory = evidence_directory/f"capsule-cut-{index:02d}"; directory.mkdir(mode=0o700)
        (directory/"worker").mkdir(mode=0o700)
        config = dict(directory=str(directory.resolve()), executable=str(executable),
            executable_sha256=executable_pin, input_sha256=measured, cut=cut, journal=str(source_journal.resolve()))
        config_path = directory/"actor-config.json"
        retain(config_path, json.dumps(config,sort_keys=True).encode("ascii"))
        with (directory/"actor-original.stdout").open("xb") as out, (directory/"actor-original.stderr").open("xb") as err:
            result = subprocess.run([sys.executable,"-B",str(root/ACTOR),str(config_path)],stdout=out,stderr=err,timeout=30)
        retain(directory/"actor-exit.json", json.dumps(dict(exit_code=result.returncode,stream_completeness="COMPLETE")).encode("ascii"))
        receipt = json.loads((directory/"cut-receipt.json").read_text("ascii"))
        file = directory/"owner"/capsule.CAPSULE_NAME; wire = file.read_bytes()
        with capsule.CapsuleOwner.open(directory/"owner") as owner:
            try: consumed = view(owner, receipt["expected_capsule_sha256"])
            except capsule.CapsuleRefused:
                if index >= 3: raise
                consumed = None
        row = dict(cut=cut, actor_exit_code=result.returncode, actor_stream_completeness="COMPLETE",
            actor_stdout_hex=(directory/"actor-original.stdout").read_bytes().hex(),
            actor_stderr_hex=(directory/"actor-original.stderr").read_bytes().hex(),
            expected_capsule_sha256=receipt["expected_capsule_sha256"], strict_open_modes=receipt["strict_open_modes"],
            capsule_worker_entries=receipt["capsule_worker_entries"], file_mode=f"{file.stat().st_mode & 0o777:04o}",
            retained_capsule_hex=wire.hex(), consumer=consumed, consumer_worker_calls=0,
            actor_worker_calls=prior.prior.read_calls(directory/"worker"),
            outcome="HOLD" if consumed is not None else "REFUSED; INCOMPLETE OR WRITABLE SHAPE")
        if file.read_bytes() != wire: raise ValueError("capsule consumer changed original bytes")
        rows.append(row)
    terms,pair,_,_,_ = prior.prior.prior.prior.selected_inputs(root)
    successful = evidence_directory/"successful"; successful.mkdir(mode=0o700)
    (successful/"worker").mkdir(mode=0o700)
    capture = OriginalCapture(successful/"worker", executable, executable_pin); capture.phase="successful-producer:strict-projection"
    counted = prior.prior.prior.prior.CountedVerifier(NomPublicVerifier(executable, executable_pin, terms, pair, execution_profile=CLEAN_EXECUTION_PROFILE))
    complete_journal = evidence_directory/"journal-originals"/"strict-originals"/prior.CUTS[4]/"journal.log"
    with patch("offline_session.nom_verifier.run_clean_environment_public_worker", capture.run):
        with StrictNomRecovery.open(complete_journal, terms, pair, role="bob", verifier=counted, observation_verifier=lambda _:False) as journal:
            selected = projection.project_partial_hold(journal, challenge_hex=prior.CHALLENGES[0])
    with capsule.CapsuleOwner.create(successful/"owner") as owner: store_receipt = owner.store(selected)
    with capsule.CapsuleOwner.open(successful/"owner") as owner: consumed = view(owner, store_receipt["capsule_sha256"])
    success = dict(store_receipt=store_receipt, consumer=consumed, strict_open_modes=counted.modes,
        consumer_worker_calls=0, worker_calls=prior.prior.read_calls(successful/"worker"))
    copied = evidence_directory/"coherent-old-copy"
    with capsule.CapsuleOwner.create(copied): pass
    retain(copied/capsule.CAPSULE_NAME, bytes.fromhex(rows[-1]["retained_capsule_hex"]))
    (copied/capsule.CAPSULE_NAME).chmod(0o400)
    with capsule.CapsuleOwner.open(copied) as owner: old_view = view(owner, rows[-1]["expected_capsule_sha256"])
    report = dict(schema="ptlc-nom-capsule-result-v1", profile=PROFILE, outcome="PASS",
        input_sha256=measured, executable_sha256=executable_pin, python_executable_sha256=sha(python.read_bytes()),
        source_unchanged=True, source_snapshots="BEFORE FIRST ACTOR OR WORKER SPAWN",
        execution_profile=CLEAN_EXECUTION_PROFILE, journal_projection_result=earlier, cases=rows,
        successful_producer=success, coherent_old_copy=dict(consumer=old_view, authority="NONE; HOLD ONLY", consumer_worker_calls=0),
        prior_worker_calls=49, additional_worker_calls=18, total_worker_calls=67,
        consumer_worker_calls=0, preserved_core_source_outcomes=342, new_core_source_outcomes=0, **BOUNDARY)
    check_cases(report)
    if measured != inputs(root)[1] or sha(executable.read_bytes()) != executable_pin or source_journal.read_bytes() != before_journal:
        raise ValueError("capsule source, executable or original journal changed")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT/"qualification/target/debug/examples/verify_nom_swap")
    parser.add_argument("--evidence-directory", type=Path)
    args = parser.parse_args(); selected = args.evidence_directory
    if selected is None: selected = Path(tempfile.mkdtemp(prefix="ptlc-nom-capsule-")).resolve()/"originals"
    try: report = qualify(args.executable, evidence_directory=selected)
    except (OSError, recovery.RecoveryError, ValueError, KeyError, TypeError):
        print("FAIL: selected capsule qualification; preserve original evidence", file=sys.stderr)
        return 1
    print(json.dumps(report,sort_keys=True,separators=(",", ":")))
    return 0


if __name__ == "__main__": raise SystemExit(main())
