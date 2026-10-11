#!/usr/bin/env python3
"""Select a new public two-party graph, never inherit an old original or signer."""

import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_wire import account_block_hash, encode_call
from offline_session.nom_recovery import validate_terms
from offline_session.pr138 import CORE_COMMIT, CONTRACT_HEX

PROFILE = "zenon-pr138-bilateral-graph-v1"
INPUT = "compatibility/fixtures/nom_bilateral_inputs_v1.json"
COMPLETIONS = "compatibility/fixtures/nom_bilateral_completions_v1.json"
FIXTURE = "compatibility/fixtures/nom_bilateral_graph_v1.json"
BASE = "6ea773b0efe90f74b7c952cfe03157ee4f24a981"
HEIGHT = 10109250
CASES = ("complete", "old-inner-before-valid", "cross-leg-inner-before-valid", "wrong-caller-before-valid")
PUBLIC_KEYS = {
    "alice": "db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d",
    "bob": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
}
BOUNDARY = {
    "application": "NO-GO", "core": "NO-GO", "recovery_action": "NONE",
    "application_signing": "NOT_PERFORMED", "journal_composition": "NOT_PERFORMED",
    "supervisor_and_plasma_admission": "NOT_PERFORMED", "account_pool_and_momentum_admission": "NOT_PERFORMED",
    "source_authentication": "UNFILLED", "canonicality": "UNFILLED", "finality": "UNFILLED",
    "restore_fence": "UNFILLED", "independent_assessment": "UNFILLED",
    "subject": "NEW PUBLIC ORIGINALS, TWO USER ACCOUNTS AND ONE SHARED CONTRACT ACCOUNT",
    "execution": "RAW VM SEND/RECEIVE AND EMBEDDED LIFECYCLE; SELECTED PUBLIC VERIFIER CHECKS",
    "ledger": "SYNTHETIC MOMENTA, CONFIRMATIONS AND ADOPTED MEMORY FRONTIERS; NO NODE START",
    "test_signatures": "DISCLOSED CONSTANTS ONLY; OUTER ED25519 AND INNER SECP256K1 ARE SEPARATE KEYS",
    "custody": "EXACT PUBLIC WIRES AND ACTUAL MEMORY PATCHES; NO AUTHENTICATED ORIGINAL CUSTODY",
    "construction_security": "NOT ESTABLISHED BY THIS SYNTHETIC GRAPH OR PUBLIC RECOVERY COMPARISON",
}


def tag(label):
    return hashlib.sha3_256(("public-nom-bilateral-v1:" + label).encode("ascii")).hexdigest()


def inputs(root=ROOT):
    old = json.loads((root / "compatibility/fixtures/nom_created_funding_v1.json").read_text("ascii"))
    terms = copy.deepcopy(old["terms"])
    terms["session_id_hex"] = tag("separate-session")
    for role, key in PUBLIC_KEYS.items():
        terms[role + "_address_hex"] = "00" + hashlib.sha3_256(bytes.fromhex(key)).hexdigest()[:38]
    fundings = {}
    for leg in ("long", "short"):
        selected = terms[leg]
        call = {"method": "Create", "expiration_time": selected["expires_at"], "point_type": 1,
                "point_lock_hex": selected["funder_key_xonly_hex"],
                "destination_hex": terms[selected["recipient"] + "_address_hex"]}
        block = {"version": "1", "chain_id": terms["chain_id"], "block_type": "2",
                 "address_hex": terms[selected["funder"] + "_address_hex"], "height": "1",
                 "previous_hash_hex": "00" * 32, "momentum_hash_hex": tag("momentum-0"),
                 "momentum_height": str(HEIGHT), "to_address_hex": CONTRACT_HEX,
                 "amount": selected["amount"], "token_standard_hex": selected["token_standard_hex"],
                 "from_block_hash_hex": "00" * 32, "descendant_hashes_hex": [], "data_hex": encode_call(call).hex(),
                 "fused_plasma": "0", "difficulty": "0", "nonce_hex": "00" * 8}
        ident = account_block_hash(block)
        terms[leg]["entry_id_hex"] = ident
        fundings[leg] = {"hash_hex": ident, "block": block}
        if ident == old["fundings"][leg]["hash_hex"]:
            raise ValueError("old original cannot be reused")
    validate_terms(terms)
    return {"schema": "zenon-nom-bilateral-inputs-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
            "research_baseline_commit": BASE, "terms": terms, "public_keys": PUBLIC_KEYS,
            "old_funding_ids_hex": {leg: old["fundings"][leg]["hash_hex"] for leg in ("long", "short")},
            "fundings": fundings, "cases": list(CASES), "boundary": BOUNDARY}


def corpus(records):
    if type(records) is not dict or set(records) != set(CASES):
        raise ValueError("complete new bilateral source records required")
    return {"schema": "zenon-nom-bilateral-graph-corpus-v1", "profile": PROFILE,
            "core_commit": CORE_COMMIT, "research_baseline_commit": BASE,
            "records": records, "boundary": BOUNDARY}


if __name__ == "__main__":
    (ROOT / INPUT).write_text(json.dumps(inputs(), indent=2, sort_keys=True) + "\n", encoding="ascii")
