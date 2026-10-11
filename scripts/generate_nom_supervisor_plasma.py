#!/usr/bin/env python3
"""Select separate public originals for bounded supervisor/Plasma comparison."""

import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_wire import account_block_hash
from offline_session.nom_recovery import validate_terms
from offline_session.pr138 import CORE_COMMIT

PROFILE = "zenon-pr138-supervisor-plasma-v1"
INPUT = "compatibility/fixtures/nom_supervisor_inputs_v1.json"
COMPLETIONS = "compatibility/fixtures/nom_supervisor_completions_v1.json"
FIXTURE = "compatibility/fixtures/nom_supervisor_plasma_v1.json"
BASE = "9f64e3ef808731c888b3163fd10d0502a9a14339"
HEIGHT = 10109300
CASES = ("complete", "old-inner-before-valid")
BASES = {"Create": 52500, "Unlock": 73500, "Receive": 21000}
FUSION_AMOUNT = 20000000000
CAPACITY = 420000
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO", "recovery_action": "NONE",
    "application_signing": "NOT_PERFORMED", "journal_composition": "NOT_PERFORMED",
    "supervisor_generation": "SELECTED SYNTHETIC GENERATE AND APPLY METHODS ONLY",
    "complete_admission": "UNFILLED", "account_pool_and_momentum_admission": "NOT_PERFORMED",
    "dynamic_plasma": "NOT_SELECTED; LEGACY CACHE VIEW ONLY",
    "source_authentication": "UNFILLED", "canonicality": "UNFILLED", "finality": "UNFILLED",
    "restore_fence": "UNFILLED", "independent_assessment": "UNFILLED",
    "subject": "NEW PUBLIC PLASMA-COMMITTED ORIGINALS; TWO USERS AND ONE SHARED CONTRACT",
    "execution": "PUBLIC SUPERVISOR GENERATION AND EXACT APPLY REPRODUCTION BEFORE ONE MEMORY ADOPTION",
    "ledger": "SYNTHETIC MOMENTA, CONFIRMATIONS, FUSION AND MEMORY FRONTIERS; NO NODE START",
    "test_signatures": "DISCLOSED CONSTANTS ONLY; SEPARATE OUTER ED25519 AND INNER SECP256K1 KEYS",
    "patches": "PER-TRANSACTION DELTAS AND INDEPENDENT SELECTED BATCH REPLAY; NO AUTHENTICATED STATE PROOF",
    "custody": "EXACT PUBLIC ORIGINALS PRESERVED; NO APPLICATION ORIGINAL CUSTODY",
    "construction_security": "NOT ESTABLISHED BY SYNTHETIC SUPERVISOR OR PUBLIC RECOVERY TESTS",
}


def tag(label):
    return hashlib.sha3_256(("public-nom-supervisor-v1:" + label).encode("ascii")).hexdigest()


def inputs(root=ROOT):
    old = json.loads((root / "compatibility/fixtures/nom_bilateral_inputs_v1.json").read_text("ascii"))
    terms = copy.deepcopy(old["terms"])
    terms["session_id_hex"] = tag("separate-session")
    fundings = copy.deepcopy(old["fundings"])
    for leg in ("long", "short"):
        b = fundings[leg]["block"]
        b.update(momentum_hash_hex=tag("momentum-0"), momentum_height=str(HEIGHT),
                 fused_plasma=str(BASES["Create"]))
        ident = account_block_hash(b)
        if ident == old["fundings"][leg]["hash_hex"]:
            raise ValueError("raw original cannot be silently upgraded")
        terms[leg]["entry_id_hex"] = fundings[leg]["hash_hex"] = ident
    validate_terms(terms)
    return {"schema": "zenon-nom-supervisor-inputs-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
            "research_baseline_commit": BASE, "terms": terms, "public_keys": old["public_keys"],
            "old_funding_ids_hex": {leg: old["fundings"][leg]["hash_hex"] for leg in ("long", "short")},
            "fundings": fundings, "cases": list(CASES), "canonical_base_plasma": BASES,
            "cache_selection": {"fusion_amount": str(FUSION_AMOUNT), "committed_plasma": "0",
                                "capacity": str(CAPACITY), "ptlc_spork": True, "dynamic_plasma_spork": False},
            "boundary": BOUNDARY}


def corpus(records):
    if type(records) is not dict or set(records) != set(CASES):
        raise ValueError("complete separate supervisor records required")
    return {"schema": "zenon-nom-supervisor-corpus-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
            "research_baseline_commit": BASE, "records": records, "boundary": BOUNDARY}


if __name__ == "__main__":
    (ROOT / INPUT).write_text(json.dumps(inputs(), indent=2, sort_keys=True) + "\n", encoding="ascii")
