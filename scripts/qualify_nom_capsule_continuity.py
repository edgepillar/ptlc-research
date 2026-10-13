#!/usr/bin/env python3
"""Compare actual retained public journals without selecting current authority.

The separate native capsule qualifier retains its original captures first.
Continuation comparison starts no worker and implements no restore service.
"""
import argparse
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import nom_capsule as capsule, nom_capsule_continuity as continuity  # noqa: E402
from offline_session import nom_journal_hold as projection, nom_recovery as recovery  # noqa: E402
from scripts import qualify_nom_capsule as prior  # noqa: E402
from scripts.nom_cut_capture import retain, sha  # noqa: E402

PROFILE = "ptlc-nom-capsule-continuity-qualification-v1"
BASE = "a0b6aa44e8fa8775c00b1538533fc18cf4439987"
FIXTURE = "compatibility/fixtures/nom_capsule_continuity_v1.json"
MANIFEST = "compatibility/nom_capsule_continuity_manifest.json"
SELECTED = ("offline_session/nom_capsule_continuity.py", "scripts/qualify_nom_capsule_continuity.py",
            "tests/test_nom_capsule_continuity.py", FIXTURE)
BOUNDARY = dict(application="NO-GO", core="NO-GO", recovery_action="NONE",
    signature_mathematics="NOT_PERFORMED BY CONTINUATION COMPARISON",
    comparison_worker_calls=0, source_currentness="UNFILLED", consumer_restore_fence="UNFILLED",
    atomic_work_admission="UNFILLED", current_head_selection="NOT_IMPLEMENTED",
    durable_comparison_storage="NOT_IMPLEMENTED", coherent_old_pair="MATCHES; HOLD ONLY",
    original_capsules="PRESERVE BOTH; NO OVERWRITE OR REPAIR", preserved_core_source_outcomes=342,
    new_core_source_outcomes=0)


def corpus():
    labels = ("EXACT_REPLAY", "EXACT_REPLAY", "STRICT_EXTENSION", "STRICT_EXTENSION")
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Disclosed public synthetic journal originals; no chain authority",
        admitted_source_indices=[1, 2, 3, 4], relation_matrix=[list(labels), list(labels),
            ["REFUSED", "REFUSED", "EXACT_REPLAY", "STRICT_EXTENSION"],
            ["REFUSED", "REFUSED", "REFUSED", "EXACT_REPLAY"]],
        different_challenge_relation="SAME_JOURNAL", coherent_old_pair_relation="EXACT_REPLAY",
        reformatted_same_head="REFUSED", prior_worker_calls=67, comparison_worker_calls=0,
        boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name: sha((root / name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-capsule-continuity-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected, preserved_file_sha256=preserved,
        boundary=BOUNDARY)
    if json.loads((root / FIXTURE).read_text("ascii")) != corpus():
        raise ValueError("selected continuity corpus changed")
    if json.loads((root / MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected continuity inputs changed")
    return expected, {**preserved, **selected, MANIFEST: sha((root / MANIFEST).read_bytes())}


def from_journal(wire, *, challenge_hex):
    """Frame supplied raw research bytes; create no original or execution claim."""
    replay, head, sequence = projection._replay(wire)
    held = projection._hold(replay, challenge_hex)
    value = dict(schema=projection.PROFILE, journal_hex=wire.hex(), journal_sha256=sha(wire),
        journal_bytes=len(wire), journal_head_hex=head, journal_sequence=sequence, role=replay.role,
        partial_hold_hex=held.canonical_bytes.hex(), selection_digest_hex=held.selection_digest_hex)
    encoded = capsule._wire(dict(schema=capsule.PROFILE, selected_projection=value))
    return capsule.read_capsule(encoded, expected_digest_hex=sha(encoded))


def compare_report(previous):
    """Read-only comparisons of retained captures; no public worker or file entry."""
    prior.check_cases(previous)
    sources = previous["journal_projection_result"]["cases"]
    views = [from_journal(bytes.fromhex(sources[index]["projection"]["journal_hex"]),
                          challenge_hex="a1" * 32) for index in (1, 2, 3, 4)]
    matrix = []
    for retained in views:
        row = []
        for candidate in views:
            try:
                result = continuity.compare_continuation(retained, candidate.canonical_bytes,
                    expected_candidate_digest_hex=candidate.digest_hex).review()
            except continuity.ContinuityRefused:
                result = dict(journal_relation="REFUSED", state="HOLD", recovery_action="NONE")
            row.append(result)
        matrix.append(row)
    changed, reformatted, restored = [], [], []
    for retained in views:
        other = from_journal(retained.journal_bytes, challenge_hex="b2" * 32)
        changed.append(continuity.compare_continuation(retained, other.canonical_bytes,
            expected_candidate_digest_hex=other.digest_hex).review())
        alias = from_journal(retained.journal_bytes.replace(b"\n", b"\r\n"), challenge_hex="a1" * 32)
        if alias.projection()["journal_head_hex"] != retained.projection()["journal_head_hex"]:
            raise ValueError("same-head raw-byte control lost its premise")
        try:
            continuity.compare_continuation(retained, alias.canonical_bytes,
                expected_candidate_digest_hex=alias.digest_hex)
        except continuity.ContinuityRefused:
            reformatted.append(dict(same_head=True, same_sequence=True, exact_journal_bytes=False,
                                     outcome="REFUSED", recovery_action="NONE"))
        else:
            raise ValueError("same head incorrectly replaced exact retained bytes")
        restored.append(continuity.compare_continuation(retained, retained.canonical_bytes,
            expected_candidate_digest_hex=retained.digest_hex).review())
    return dict(matrix=matrix, changed_challenge=changed, same_head_raw_alias=reformatted,
        coherent_old_pairs=restored, comparison_worker_calls=0,
        original_journal_sha256=[sha(view.journal_bytes) for view in views],
        candidate_capsule_origin="IN-MEMORY STRUCTURAL FRAMING FROM RETAINED JOURNALS; NOT NEW DISK CUSTODY")


def check_cases(report):
    earlier = report["prior_capsule_result"]
    if report["comparisons"] != compare_report(earlier):
        raise ValueError("continuity comparison changed exact retained inputs")
    cases = report["comparisons"]
    selected = corpus()
    matrix = [[row["journal_relation"] for row in rows] for rows in cases["matrix"]]
    if matrix != selected["relation_matrix"]:
        raise ValueError("selected continuity relation matrix changed")
    for row in cases["changed_challenge"]:
        if row["journal_relation"] != "SAME_JOURNAL":
            raise ValueError("new challenge replaced journal continuity")
    for row in cases["coherent_old_pairs"]:
        if row["journal_relation"] != "EXACT_REPLAY" or row["consumer_restore_fence"] != "UNFILLED":
            raise ValueError("coherent old pair gained restore authority")
    if earlier["total_worker_calls"] != 67 or report["comparison_worker_calls"] != 0:
        raise ValueError("continuity comparison reentered a public worker")
    for field, value in BOUNDARY.items():
        if report[field] != value:
            raise ValueError("continuity qualification promoted authority")


def qualify(executable, *, evidence_directory, root=ROOT):
    _, measured = inputs(root)
    directory = Path(evidence_directory).resolve()
    directory.mkdir(mode=0o700)
    for index, name in enumerate(measured):
        retain(directory / f"selected-source-{index:03d}.original", (root / name).read_bytes())
    earlier = prior.qualify(executable, evidence_directory=directory / "capsule-originals", root=root)
    with patch("offline_session.nom_verifier.run_clean_environment_public_worker",
               side_effect=AssertionError("continuation comparison entered a worker")):
        compared = compare_report(earlier)
    report = dict(schema="ptlc-nom-capsule-continuity-result-v1", profile=PROFILE, outcome="PASS",
        input_sha256=measured, source_snapshots="BEFORE FIRST ACTOR OR WORKER SPAWN",
        prior_capsule_result=earlier, comparisons=compared, **BOUNDARY)
    check_cases(report)
    if measured != inputs(root)[1]:
        raise ValueError("continuity sources changed during qualification")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_swap")
    parser.add_argument("--evidence-directory", type=Path)
    args = parser.parse_args()
    directory = args.evidence_directory
    if directory is None:
        directory = Path(tempfile.mkdtemp(prefix="ptlc-nom-continuity-")).resolve() / "originals"
    try:
        report = qualify(args.executable, evidence_directory=directory)
    except (OSError, recovery.RecoveryError, ValueError, KeyError, TypeError):
        print("FAIL: selected capsule continuity; preserve original evidence", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
