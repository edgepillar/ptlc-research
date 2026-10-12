#!/usr/bin/env python3
"""Pure hold comparison against pinned refusal records, not a native rerun."""

import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import nom_authority_contract as authority, nom_uncertainty as hold
from offline_session.nom_recovery import synthetic_claim
from scripts import qualify_nom_rollback_refusal as prior
from scripts import model_nom_uncertainty as model


BASE = "4b15b8c2a10575c05b166cee2993c90aabe1be94"
FIXTURE = "compatibility/fixtures/nom_uncertainty_v1.json"
MANIFEST = "compatibility/nom_uncertainty_manifest.json"
SELECTED = ("offline_session/nom_uncertainty.py", "scripts/model_nom_uncertainty.py",
    "scripts/qualify_nom_uncertainty.py", "tests/test_nom_uncertainty.py", FIXTURE)
SELECTION_INPUTS = ("compatibility/fixtures/nom_terms_v1.json", "compatibility/fixtures/nom_completions_v1.json",
    "compatibility/fixtures/nom_momentum_v1.json", "offline_session/nom_authority_contract.py",
    "offline_session/nom_recovery.py", "scripts/model_nom_authority.py")
BOUNDARY = {"native_execution": "NOT_PERFORMED; SEPARATE FRESH CORPUS QUALIFICATION REQUIRED",
    "native_query_context_pairing": "NOT_COMPOSED", "source_authentication": "NOT_PERFORMED",
    "source_currentness": "UNFILLED", "restore_fence": "UNFILLED", "durable_retention": "NOT_IMPLEMENTED",
    "journal_composition": "NOT_PERFORMED", "signature_mathematics": "NOT_PERFORMED",
    "recovery_action": "NONE", "application": "NO-GO", "core": "NO-GO"}


def wire(value):
    return authority.codec._canonical(value)


def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def query_selection(root=ROOT):
    terms, completions, momenta = [prior.read_json(root / name) for name in SELECTION_INPUTS[:3]]
    last = momenta["baseline"]["momenta"][-1]
    network = dict(schema=authority.NETWORK_SCHEMA, core_commit=authority.CORE_COMMIT,
        chain_id=terms["chain_id"], genesis_hash_hex=terms["genesis_hash_hex"])
    for number, field in enumerate(authority._NETWORK[4:], 16):
        network[field] = bytes([number]).hex() * 32
    return authority.read_query(terms, network_selection=network,
        checkpoint_selection={"authority_revision": 7, "momentum": {"hash_hex": last["hash_hex"],
            "height": last["momentum"]["height"], "timestamp": last["momentum"]["timestamp"]}, "state_root_hex": "31" * 32},
        consumer_selection={"retention_selection_digest_hex": "32" * 32, "retention_head_digest_hex": "33" * 32,
            "retention_sequence": 4, "consumer_incarnation_hex": "34" * 32,
            "external_checkpoint_digest_hex": "35" * 32, "disclosure_possible": True},
        selected_anchor_claim=momenta["baseline"]["anchor"], required_inclusions=momenta["required_inclusions"],
        candidate_wire=wire(momenta["baseline"]),
        originals={leg: synthetic_claim(terms, leg, completions[leg + "_signature_hex"]) for leg in ("long", "short")},
        challenge_hex="36" * 32)


def selected_hold(*, charged=1, root=ROOT):
    if type(charged) is not int or not 0 <= charged <= 16:
        raise ValueError("invalid selected prior work")
    query = query_selection(root)
    short = bytes.fromhex(query.as_dict()["originals_hex"]["short"])
    work = [{"attempt_id_hex": bytes([64 + i]).hex() * 32, "original_leg": "short",
        "original_digest_hex": hold.original_digest(short), "outcome": "UNKNOWN"} for i in range(charged)]
    return hold.select_hold(query, charged_work=work,
        prior_evidence=[b"public synthetic original disclosure intent", b"public synthetic worker outcome unknown"])


def corpus(records, *, root=ROOT):
    prior.validate_records(records, root)
    query = query_selection(root)
    def claim(availability, status):
        return wire(dict(schema=authority.CLAIM_SCHEMA, query_digest_hex=query.digest_hex,
            challenge_hex=query.as_dict()["challenge_hex"], availability=availability,
            checkpoint=query.as_dict()["checkpoint_selection"] if availability == "available" else None,
            facts={name: {"status": status, "evidence_digest_hex": None if status == "unknown" else "00" * 32}
                   for name in authority.OBLIGATIONS})).hex()
    return {"schema": hold.PROFILE, "research_baseline_commit": BASE, "core_commit": authority.CORE_COMMIT,
        "query_hex": query.canonical_bytes.hex(),
        "initial_hold_hex": selected_hold(root=root).canonical_bytes.hex(),
        "refusals_hex": {case: wire(dict(schema=hold.REFUSAL_SCHEMA, core_commit=authority.CORE_COMMIT,
            case_id=case, record_digest_hex=hashlib.sha256(wire(records[case])).hexdigest(),
            failure=copy.deepcopy(records[case]["failure"]))).hex() for case in hold.CASES},
        "source_claims_hex": {"unavailable": claim("unavailable", "unknown"),
            "complete": claim("available", "supported"), "contradicted": claim("available", "contradicted"),
            "unknown": claim("available", "unknown")}, "boundary": BOUNDARY}


def inputs(root=ROOT):
    old, previous, preserved = prior.inputs(root)
    fixture = prior.read_json(root / FIXTURE)
    manifest = prior.read_json(root / MANIFEST)
    selected = {name: digest(root / name) for name in SELECTED}
    selection = {name: digest(root / name) for name in SELECTION_INPUTS}
    expected = dict(schema="ptlc-nom-uncertainty-manifest-v1", profile=hold.PROFILE,
        research_baseline_commit=BASE, core_commit=authority.CORE_COMMIT,
        input_sha256=selected, preserved_file_sha256=preserved, selection_file_sha256=selection,
        core_file_sha256=old["core_file_sha256"], boundary=BOUNDARY)
    if manifest != expected or fixture != corpus(previous["records"], root=root):
        raise ValueError("exact selected hold, prior record and source inputs required")
    measured = {**preserved, **selected, MANIFEST: digest(root / MANIFEST), **selection}
    return manifest, fixture, measured


def qualify(root=ROOT):
    manifest, fixture, measured = inputs(root)
    initial = selected_hold(root=root)
    cases = []
    for case in hold.CASES:
        retained = hold.retain_claim(initial, bytes.fromhex(fixture["refusals_hex"][case]), kind="refusal")
        first = retained.canonical_bytes
        if hold.retain_claim(retained, bytes.fromhex(fixture["refusals_hex"][case]), kind="refusal") is not retained:
            raise ValueError("exact refusal replay must add no evidence or work")
        for name in ("unavailable", "complete", "unknown", "contradicted"):
            retained = hold.retain_claim(retained, bytes.fromhex(fixture["source_claims_hex"][name]), kind="source")
        if retained.as_dict()["selection_hex"] != initial.as_dict()["selection_hex"]:
            raise ValueError("prior originals, evidence, charge or disclosure changed")
        review = retained.review()
        if (review["charged_work"], review["disclosure_possible"], review["recovery_action"], review["state"]) != (1, True, "NONE", "HOLD"):
            raise ValueError("selected refusal or complete labels released work")
        cases.append({"case": case, "retained_first_refusal_sha256": hashlib.sha256(first).hexdigest(),
            "retained_final_sha256": hashlib.sha256(retained.canonical_bytes).hexdigest(), "review": review})
    results = [model.compare(policy, fixture) for policy in model.POLICIES]
    if any(not row["complete"] for row in results) or results[-1]["unsafe_entries"] or results[-1]["erased_charges"]:
        raise ValueError("selected finite hold comparison incomplete")
    if any(not row["unsafe_entries"] for row in results[:-1]):
        raise ValueError("selected unsafe policies require counterexamples")
    if measured != inputs(root)[2]:
        raise ValueError("selected comparison source changed")
    return {"schema": "ptlc-nom-uncertainty-result-v1", "profile": hold.PROFILE,
        "outcome": "PASS", "input_sha256": measured, "source_unchanged": True, **BOUNDARY,
        "cases": cases, "finite_policies": [{k: v for k, v in row.items() if k != "counterexamples"} for row in results],
        "prior_corpus_record_digest_hex": {case: json.loads(bytes.fromhex(fixture["refusals_hex"][case]))["record_digest_hex"] for case in hold.CASES},
        "prior_source_counts": prior.COUNTS, "preserved_source_tests_including_parents": 342,
        "new_native_outcomes": 0}


def main():
    try:
        print(json.dumps(qualify(), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print("FAIL: selected pure NoM uncertainty comparison", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
