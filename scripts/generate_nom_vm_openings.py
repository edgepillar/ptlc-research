#!/usr/bin/env python3
"""Project selected public synthetic blocks from complete VM command evidence.

The original stream must pass the frozen VM parser. No logs, patch dumps, private
paths or host details enter this corpus. Reproduction needs fresh source tests;
parser-only regeneration and caller labels do not authenticate a producer.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import enrollment_contract as codec, nom_authority_contract as authority
from offline_session import nom_evidence_openings as base, nom_recovery as recovery, nom_vm_openings as opening
from scripts.generate_nom_vm_path import VM_KINDS

PROFILE = "zenon-pr138-vm-public-openings-v1"
FIXTURE = "compatibility/fixtures/nom_vm_openings_v1.json"
BASE = "d4576f58b17d71a07062015e3feed9cfeaf64f58"
KINDS = ("direct-success", "proxy-funder-success", "proxy-third-success",
         "unlock-at-expiry-then-reclaim", "raw-receive-replay-needs-verifier")
BOUNDARY = {"application": "NO-GO", "core": "NO-GO", "account_admission": "NOT_PERFORMED",
    "source_authentication": "UNFILLED", "canonicality": "UNFILLED", "finality": "UNFILLED",
    "restore_fence": "UNFILLED", "atomic_entry": "NOT_IMPLEMENTED", "recovery_action": "NONE",
    "terminal_outcome": "NOT_ESTABLISHED", "independent_assessment": "UNFILLED"}


def corpus(records):
    expected = {leg + "-" + kind for leg in ("long", "short") for kind in VM_KINDS}
    if type(records) is not dict or set(records) != expected:
        raise ValueError("complete source records required before projection")
    cases = {}
    for kind in KINDS:
        legs = {}
        for leg in ("long", "short"):
            record = records[leg + "-" + kind]
            blocks = record["blocks"]
            label = "reclaim" if kind == "unlock-at-expiry-then-reclaim" else "unlock"
            receipt = "raw-replayed-recipient-receive" if kind == "raw-receive-replay-needs-verifier" else "recipient-receive"
            legs[leg] = {"funding": copy.deepcopy(blocks["funding"]),
                "unlock_send": copy.deepcopy(blocks[label + "-send"]),
                "contract_receive": {"funding_receive": copy.deepcopy(blocks["create-receive"]),
                                     "receive": copy.deepcopy(blocks[label + "-receive"])},
                "contract_payout": copy.deepcopy(blocks[label + "-payout-0"]),
                "recipient_receipt": copy.deepcopy(blocks[receipt])}
        cases[kind] = legs
    return {"schema": "zenon-nom-vm-public-openings-corpus-v1", "profile": PROFILE,
        "core_commit": authority.CORE_COMMIT, "research_baseline_commit": BASE, "source_cases": cases,
        "source_selection": "UNCHANGED SOURCE VM; INDEPENDENT SYNTHETIC ACCOUNT FRONTIERS AND LEDGER STUBS",
        "boundary": BOUNDARY}


def selection(root=ROOT):
    """Use retained created-id originals and the old raw momentum selection.

    The VM's numbered momentum stubs are intentionally not converted into a
    canonical branch or a newly trusted provisioning/restore selection.
    """
    funding = json.loads((root / "compatibility/fixtures/nom_created_funding_v1.json").read_text("ascii"))
    completions = json.loads((root / "compatibility/fixtures/nom_created_completions_v1.json").read_text("ascii"))
    momenta = json.loads((root / "compatibility/fixtures/nom_momentum_v1.json").read_text("ascii"))
    terms, last = funding["terms"], momenta["baseline"]["momenta"][-1]
    network = dict(schema=authority.NETWORK_SCHEMA, core_commit=authority.CORE_COMMIT,
                   chain_id=terms["chain_id"], genesis_hash_hex=terms["genesis_hash_hex"])
    for number, name in enumerate(authority._NETWORK[4:], 16):
        network[name] = bytes([number]).hex() * 32
    return {"terms": terms, "network_selection": network,
        "checkpoint_selection": {"authority_revision": 7, "momentum": {"hash_hex": last["hash_hex"],
            "height": last["momentum"]["height"], "timestamp": last["momentum"]["timestamp"]}, "state_root_hex": "31" * 32},
        "consumer_selection": {"retention_selection_digest_hex": "32" * 32, "retention_head_digest_hex": "33" * 32,
            "retention_sequence": 4, "consumer_incarnation_hex": "34" * 32,
            "external_checkpoint_digest_hex": "35" * 32, "disclosure_possible": True},
        "selected_anchor_claim": momenta["baseline"]["anchor"], "required_inclusions": momenta["required_inclusions"],
        "candidate_wire": codec._canonical(momenta["baseline"]),
        "originals": {leg: recovery.synthetic_claim(terms, leg, completions[leg + "_signature_hex"])
                      for leg in ("long", "short")}, "challenge_hex": "36" * 32}


def packet(query, selected, legs, *, statuses=None, missing=(), missing_base=()):
    """Create forgeable public comparison controls, never a source reply service."""
    statuses = statuses or {}
    payloads = {name: {"records": {leg: legs[leg][name] for leg in ("long", "short")}} for name in opening.SELECTED}
    base_payloads = {"funding_send": {"records": {leg: {key: legs[leg]["funding"][key] for key in ("hash_hex", "block")}
                                                  for leg in ("long", "short")}},
        "original_authorization": {"originals_hex": {leg: value.hex() for leg, value in selected["originals"].items()}},
        "momentum_lineage": {"candidate_wire_hex": selected["candidate_wire"].hex()}}
    facts = {name: {"status": "unknown", "evidence_digest_hex": None} for name in authority.OBLIGATIONS}
    for module, items in ((base, base_payloads), (opening, payloads)):
        for name, payload in items.items():
            status = statuses.get(name, "supported")
            facts[name] = {"status": status, "evidence_digest_hex": None if status == "unknown" else
                           module.opening_digest(query, name, status, payload)}
    claim_wire = codec._canonical(dict(schema=authority.CLAIM_SCHEMA, query_digest_hex=query.digest_hex,
        challenge_hex=query.as_dict()["challenge_hex"], availability="available",
        checkpoint=query.as_dict()["checkpoint_selection"], facts=facts))
    base_wire = codec._canonical(dict(schema=base.SCHEMA, query_digest_hex=query.digest_hex,
        claim_wire_digest_hex=base.claim_digest(claim_wire), openings={name: None if name in missing_base
            or statuses.get(name) == "unknown" else payload for name, payload in base_payloads.items()}))
    opening_wire = codec._canonical(dict(schema=opening.SCHEMA, query_digest_hex=query.digest_hex,
        claim_wire_digest_hex=base.claim_digest(claim_wire), base_opening_wire_digest_hex=opening.base_digest(base_wire),
        openings={name: None if name in missing or statuses.get(name) == "unknown" else payload for name, payload in payloads.items()}))
    return claim_wire, base_wire, opening_wire


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm-stream", type=Path, required=True)
    args = parser.parse_args()
    from scripts import qualify_nom_vm_path as vm
    _, fixture, _ = vm.inputs(ROOT)
    raw = args.vm_stream.read_bytes()
    vm.selected_outcome(raw, {"github.com/zenon-network/go-zenon/vm": vm.expected_tests(fixture)["github.com/zenon-network/go-zenon/vm"]})
    records = vm.collect_vm_records(raw, fixture, json.loads((ROOT / vm.FUNDING).read_text("ascii")))
    (ROOT / FIXTURE).write_text(json.dumps(corpus(records), indent=2, sort_keys=True) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
