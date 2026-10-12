#!/usr/bin/env python3
"""Separate pure partial-custody comparison; no journal or native execution."""

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import nom_partial_custody as hold
from offline_session.nom_recovery import synthetic_claim
from scripts import qualify_nom_uncertainty as prior
from scripts import model_nom_partial_custody as model


BASE = "f518235b5726987166f984884b3cbd1897790ea0"
FIXTURE = "compatibility/fixtures/nom_partial_custody_v1.json"
MANIFEST = "compatibility/nom_partial_custody_manifest.json"
SELECTED = ("offline_session/nom_partial_custody.py", "scripts/model_nom_partial_custody.py",
    "scripts/qualify_nom_partial_custody.py", "tests/test_nom_partial_custody.py", FIXTURE)
SELECTION_INPUTS = prior.SELECTION_INPUTS[:2] + ("offline_session/nom_recovery.py", "offline_session/nom_verifier.py")
CUTS = ("admitted-result-absent", "public-result-only", "original-retained")
BOUNDARY = {**prior.BOUNDARY, "complete_query_conversion": "NOT_PROVIDED",
    "worker_execution_from_absence": "NOT_ESTABLISHED", "absent_original_reconstruction": "FORBIDDEN",
    "reference_journal_cut_execution": "NOT_PERFORMED; CALLER-SELECTED STATES ONLY",
    "public_pair_verification": "SEPARATE FRESH PUBLIC WORKER QUALIFICATION REQUIRED"}


def wire(value):
    return prior.wire(value)


def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def selected_hold(cut=CUTS[0], *, charged=1, outcome="UNKNOWN", root=ROOT):
    if cut not in CUTS or type(charged) is not int or not 1 <= charged <= 16:
        raise ValueError("invalid partial custody selection")
    terms, completions = [prior.prior.read_json(root / name) for name in SELECTION_INPUTS[:2]]
    short = synthetic_claim(terms, "short", completions["short_signature_hex"])
    # These are separate caller-selected cuts. Never consult the long fixture
    # completion for the admitted-result-absent selection, even when it exists.
    result = None if cut == CUTS[0] else completions["long_signature_hex"]
    original = synthetic_claim(terms, "long", result) if cut == CUTS[2] else None
    work = [{"attempt_id_hex": bytes([64 + i]).hex() * 32,
        "short_original_digest_hex": hold.short_digest(short), "outcome": outcome} for i in range(charged)]
    return hold.select_partial_hold(terms, completions["pair"], short, charged_work=work,
        prior_evidence=[b"public synthetic admitted work", b"public synthetic possible disclosure"],
        recovered_long_signature=result, original_long=original, challenge_hex="51" * 32)


def source_claim(selected, name):
    if name not in ("unavailable", "supported", "unknown", "contradicted"):
        raise ValueError("invalid partial custody label")
    status = "unknown" if name in ("unavailable", "unknown") else name
    return wire(dict(schema=hold.CLAIM_SCHEMA, selection_digest_hex=selected.selection_digest_hex,
        challenge_hex=selected.selection()["challenge_hex"],
        availability="unavailable" if name == "unavailable" else "available", status=status,
        evidence_digest_hex=None if status == "unknown" else "00" * 32))


def corpus(previous, *, root=ROOT):
    return {"schema": hold.PROFILE, "research_baseline_commit": BASE,
        "core_commit": prior.authority.CORE_COMMIT,
        "holds_hex": {cut: selected_hold(cut, root=root).canonical_bytes.hex() for cut in CUTS},
        "refusals_hex": previous["refusals_hex"], "boundary": BOUNDARY,
        "synthetic_notice": "Public synthetic caller selections only; no actual journal cuts or chain authority"}


def inputs(root=ROOT):
    old, previous, preserved = prior.inputs(root)
    fixture = prior.prior.read_json(root / FIXTURE)
    manifest = prior.prior.read_json(root / MANIFEST)
    selected = {name: digest(root / name) for name in SELECTED}
    selection = {name: digest(root / name) for name in SELECTION_INPUTS}
    expected = dict(schema="ptlc-nom-partial-custody-manifest-v1", profile=hold.PROFILE,
        research_baseline_commit=BASE, core_commit=prior.authority.CORE_COMMIT,
        input_sha256=selected, preserved_file_sha256=preserved, selection_file_sha256=selection,
        core_file_sha256=old["core_file_sha256"], boundary=BOUNDARY)
    if manifest != expected or fixture != corpus(previous, root=root):
        raise ValueError("exact missing and retained selections and pinned prior inputs required")
    measured = {**preserved, **selected, MANIFEST: digest(root / MANIFEST), **selection}
    return manifest, fixture, measured


def qualify(root=ROOT):
    manifest, fixture, measured = inputs(root)
    cases = []
    for cut in CUTS:
        for charged in (1, 16):
            initial = selected_hold(cut, charged=charged, root=root)
            retained = initial
            for case in prior.hold.CASES:
                claim = bytes.fromhex(fixture["refusals_hex"][case])
                retained = hold.retain_claim(retained, claim, kind="refusal")
                if hold.retain_claim(retained, claim, kind="refusal") is not retained:
                    raise ValueError("exact refusal replay adds evidence")
            for name in ("supported", "unavailable", "unknown", "contradicted"):
                claim = source_claim(initial, name)
                retained = hold.retain_claim(retained, claim, kind="source")
                if hold.retain_claim(retained, claim, kind="source") is not retained:
                    raise ValueError("exact source replay adds evidence")
            if retained.selection() != initial.selection() or retained.review()["recovery_action"] != "NONE":
                raise ValueError("known bytes or absent custody changed")
            cases.append({"cut": cut, "charged": charged, "review": retained.review(),
                "selection_digest_hex": initial.selection_digest_hex,
                "final_sha256": hashlib.sha256(retained.canonical_bytes).hexdigest()})
    models = [model.compare(policy, fixture) for policy in model.POLICIES]
    if any(not row["complete"] for row in models) or any(not row["invented_originals"] for row in models[:-1]):
        raise ValueError("selected partial custody policies lack complete counterexamples")
    if models[-1]["invented_originals"] or models[-1]["new_worker_entries"]:
        raise ValueError("pure hold supplied missing custody or work")
    if measured != inputs(root)[2]:
        raise ValueError("partial custody input changed")
    return {"schema": "ptlc-nom-partial-custody-result-v1", "profile": hold.PROFILE,
        "outcome": "PASS", "input_sha256": measured, "source_unchanged": True, **BOUNDARY,
        "cases": cases, "finite_policies": models, "preserved_source_tests_including_parents": 342,
        "new_native_outcomes": 0, "prior_input_count": len(manifest["preserved_file_sha256"])}


def main():
    try:
        print(json.dumps(qualify(), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print("FAIL: selected pure partial NoM custody comparison", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
