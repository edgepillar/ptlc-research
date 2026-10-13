#!/usr/bin/env python3
"""Qualify exact full-capsule/read bindings without current source admission."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import enrollment_contract as codec, nom_authority_contract as authority  # noqa: E402
from offline_session import nom_capsule_query as binding, nom_recovery as recovery  # noqa: E402
from scripts import qualify_nom_capsule_continuity as prior  # noqa: E402
from scripts.nom_cut_capture import retain, sha  # noqa: E402

PROFILE = "ptlc-nom-capsule-read-qualification-v1"
BASE = "a05ef5dae6198278ff5493663a15f810dce93a45"
FIXTURE = "compatibility/fixtures/nom_capsule_query_v1.json"
MANIFEST = "compatibility/nom_capsule_query_manifest.json"
SELECTED = ("offline_session/nom_capsule_query.py", "scripts/qualify_nom_capsule_query.py",
            "tests/test_nom_capsule_query.py", FIXTURE)
BOUNDARY = dict(application="NO-GO", core="NO-GO", recovery_action="NONE", binding_worker_calls=0,
    source_authentication="NOT_PERFORMED", source_currentness="UNFILLED", restore_fence="UNFILLED",
    atomic_entry="NOT_IMPLEMENTED", missing_original_conversion="REFUSED; NO FILLING OR CONSTRUCTION",
    consumer_retention_pins="SEPARATE CALLER ASSERTIONS; NOT DERIVED FROM RECOVERY JOURNAL",
    coherent_old_pair="CAN MATCH; HOLD ONLY", native_query_pairing="NOT_COMPOSED",
    preserved_core_source_outcomes=342, new_core_source_outcomes=0)


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Retained public synthetic originals and independently selected source labels only",
        admitted_source_indices=[1, 2, 3, 4], full_binding_outcomes=["REFUSED", "REFUSED", "REFUSED", "HOLD"],
        source_coverage=["COMPLETE_CLAIM", "INCOMPLETE_CLAIM", "CONTRADICTED_CLAIM", "UNAVAILABLE_CLAIM"],
        source_authentication="NOT_PERFORMED", prior_worker_calls=67, binding_worker_calls=0,
        boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name: sha((root / name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-capsule-query-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected, preserved_file_sha256=preserved,
        boundary=BOUNDARY)
    if json.loads((root / FIXTURE).read_text("ascii")) != corpus():
        raise ValueError("selected capsule query corpus changed")
    if json.loads((root / MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected capsule query inputs changed")
    return expected, {**preserved, **selected, MANIFEST: sha((root / MANIFEST).read_bytes())}


def read_selection(retained, *, root=ROOT):
    """Disclosed test selection; retain missing bytes as missing and refuse.

    The existing opaque account headers and synthetic momenta are not composed
    with signed account originals. No source or consumer checkpoint is trusted.
    """
    selected = retained.partial_hold.selection()
    if selected["original_long_hex"] is None:
        raise ValueError("full read requires an actually retained long original")
    terms = copy.deepcopy(selected["terms"])
    momenta = json.loads((root / "compatibility/fixtures/nom_momentum_v1.json").read_text("ascii"))
    last = momenta["baseline"]["momenta"][-1]
    network = dict(schema=authority.NETWORK_SCHEMA, core_commit=authority.CORE_COMMIT,
                   chain_id=terms["chain_id"], genesis_hash_hex=terms["genesis_hash_hex"])
    for number, name in enumerate(authority._NETWORK[4:], 16):
        network[name] = bytes([number]).hex() * 32
    return dict(terms=terms, network_selection=network,
        checkpoint_selection=dict(authority_revision=7, momentum=dict(hash_hex=last["hash_hex"],
            height=last["momentum"]["height"], timestamp=last["momentum"]["timestamp"]), state_root_hex="31" * 32),
        consumer_selection=dict(retention_selection_digest_hex="32" * 32, retention_head_digest_hex="33" * 32,
            retention_sequence=4, consumer_incarnation_hex="34" * 32, external_checkpoint_digest_hex="35" * 32,
            disclosure_possible=True), selected_anchor_claim=copy.deepcopy(momenta["baseline"]["anchor"]),
        required_inclusions=copy.deepcopy(momenta["required_inclusions"]),
        candidate_wire=codec._canonical(momenta["baseline"]),
        originals=dict(long=bytes.fromhex(selected["original_long_hex"]), short=bytes.fromhex(selected["remote_short_hex"])),
        challenge_hex="36" * 32)


def claim_wire(expected, *, status="supported", availability="available"):
    """An intentionally forgeable, unsigned public claim fixture."""
    query = expected._query
    value = dict(schema=authority.CLAIM_SCHEMA, query_digest_hex=query.digest_hex,
        challenge_hex=query.as_dict()["challenge_hex"], availability=availability,
        checkpoint=query.as_dict()["checkpoint_selection"] if availability=="available" else None,
        facts={name: dict(status=status, evidence_digest_hex=None if status=="unknown" else "00" * 32)
               for name in authority.OBLIGATIONS})
    return codec._canonical(dict(schema=binding.CLAIM_SCHEMA, binding_digest_hex=expected.digest_hex,
                                 source_claim_hex=codec._canonical(value).hex()))


def compare_report(previous):
    prior.check_cases(previous)
    sources = previous["prior_capsule_result"]["journal_projection_result"]["cases"]
    views = [prior.from_journal(bytes.fromhex(sources[i]["projection"]["journal_hex"]), challenge_hex="a1" * 32)
             for i in (1, 2, 3, 4)]
    query = authority.read_query(**read_selection(views[-1]))
    outcomes = []
    for retained in views:
        try:
            result = binding.bind_read_query(retained, query)
        except binding.CapsuleQueryRefused:
            outcomes.append(dict(outcome="REFUSED", state="HOLD", recovery_action="NONE"))
        else:
            outcomes.append(dict(outcome="HOLD", binding=result.as_dict(), review=result.review()))
    expected = binding.bind_read_query(views[-1], query)
    claims = [binding.parse_claim(expected, claim_wire(expected, status=status, availability=available))
              for status, available in (("supported", "available"), ("unknown", "available"),
                                        ("contradicted", "available"), ("unknown", "unavailable"))]
    renewed = read_selection(views[-1]); renewed["challenge_hex"]="42" * 32
    other = binding.bind_read_query(views[-1], authority.read_query(**renewed))
    if expected.review()["work_scope_digest_hex"] != other.review()["work_scope_digest_hex"]:
        raise ValueError("new source challenge minted a new work scope")
    return dict(cases=outcomes, claims=claims, changed_challenge=dict(
        original_binding_digest_hex=expected.digest_hex, new_binding_digest_hex=other.digest_hex,
        work_scope_unchanged=True, charged_work_unchanged=True, recovery_action="NONE"),
        coherent_old_pair=dict(binding=expected.as_dict(), claim=binding.parse_claim(expected, claim_wire(expected)),
                              authority="NONE; HOLD ONLY"), binding_worker_calls=0)


def check_cases(report):
    if report["comparisons"] != compare_report(report["prior_continuity_result"]):
        raise ValueError("capsule query comparison changed retained knowledge")
    value=report["comparisons"]
    if ([row["outcome"] for row in value["cases"]] != corpus()["full_binding_outcomes"]
            or [row["coverage"] for row in value["claims"]] != corpus()["source_coverage"]):
        raise ValueError("capsule query missing-original or source-label boundary changed")
    if any(report[key] != expected for key,expected in BOUNDARY.items()):
        raise ValueError("capsule query qualification promoted authority")
    if report["prior_continuity_result"]["prior_capsule_result"]["total_worker_calls"] != 67:
        raise ValueError("capsule query qualification changed old work")


def qualify(executable, *, evidence_directory, root=ROOT):
    _, measured=inputs(root)
    directory=Path(evidence_directory).resolve(); directory.mkdir(mode=0o700)
    for index,name in enumerate(measured):
        retain(directory / f"selected-source-{index:03d}.original", (root / name).read_bytes())
    earlier=prior.qualify(executable, evidence_directory=directory / "continuity-originals", root=root)
    with patch("offline_session.nom_verifier.run_clean_environment_public_worker",
               side_effect=AssertionError("capsule query binding entered a worker")):
        compared=compare_report(earlier)
    report=dict(schema="ptlc-nom-capsule-query-result-v1", profile=PROFILE, outcome="PASS",
        input_sha256=measured, source_snapshots="BEFORE FIRST ACTOR OR WORKER SPAWN",
        prior_continuity_result=earlier, comparisons=compared, **BOUNDARY)
    check_cases(report)
    if measured != inputs(root)[1]:
        raise ValueError("capsule query sources changed during qualification")
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_swap")
    parser.add_argument("--evidence-directory", type=Path)
    args=parser.parse_args(); directory=args.evidence_directory
    if directory is None:
        directory=Path(tempfile.mkdtemp(prefix="ptlc-nom-capsule-query-")).resolve() / "originals"
    try:
        report=qualify(args.executable, evidence_directory=directory)
    except (OSError, recovery.RecoveryError, ValueError, KeyError, TypeError):
        print("FAIL: selected capsule query binding; preserve original evidence", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
