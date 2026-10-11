#!/usr/bin/env python3
"""Build two-leg public Create inputs and isolated source execution controls.

This generator uses no signer. New public witnesses are reproduced separately
inside Rust tests using disclosed toy constants, never application credentials.
Funding records are hash inputs, not signed or admitted account blocks.
"""

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

PROFILE = "zenon-pr138-created-funding-v1"
FIXTURE = "compatibility/fixtures/nom_created_funding_v1.json"
COMPLETIONS = "compatibility/fixtures/nom_created_completions_v1.json"
MUTATIONS = ("previous", "nonce", "amount", "token", "expiry", "key", "recipient", "chain", "funder")
THIRD = "00" + "33" * 19


def tag(label):
    return hashlib.sha3_256(("public-nom-created-funding:" + label).encode("ascii")).hexdigest()


def corpus(root=ROOT):
    old = json.loads((root / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
    terms = copy.deepcopy(old)
    terms["session_id_hex"] = tag("independent-synthetic-selection")
    records = {}

    def record(leg, change="baseline"):
        selected = terms[leg]
        funder = terms[selected["funder"] + "_address_hex"]
        destination = terms[selected["recipient"] + "_address_hex"]
        call = {"method": "Create", "expiration_time": selected["expires_at"], "point_type": 1,
                "point_lock_hex": selected["funder_key_xonly_hex"], "destination_hex": destination}
        block = {"version": "1", "chain_id": terms["chain_id"], "block_type": "2",
                 "address_hex": funder, "height": "7" if leg == "long" else "9",
                 "previous_hash_hex": tag(leg + "-account-predecessor"),
                 "momentum_hash_hex": tag("untrusted-funding-ack"), "momentum_height": "99",
                 "to_address_hex": CONTRACT_HEX, "amount": selected["amount"],
                 "token_standard_hex": selected["token_standard_hex"], "from_block_hash_hex": "00" * 32,
                 "descendant_hashes_hex": [], "data_hex": "", "fused_plasma": "0", "difficulty": "0",
                 "nonce_hex": "00" * 8}
        if change == "previous": block["previous_hash_hex"] = tag(leg + "-different-predecessor")
        elif change == "nonce": block["nonce_hex"] = "00" * 7 + "01"
        elif change == "amount": block["amount"] = str(int(block["amount"]) + 1)
        elif change == "token": block["token_standard_hex"] = "03" * 10
        elif change == "expiry": call["expiration_time"] = str(int(call["expiration_time"]) + 100)
        elif change == "key": call["point_lock_hex"] = terms["short" if leg == "long" else "long"]["funder_key_xonly_hex"]
        elif change == "recipient": call["destination_hex"] = THIRD
        elif change == "chain": block["chain_id"] = "70"
        elif change == "funder": block["address_hex"] = THIRD
        elif change != "baseline": raise ValueError("unknown public funding control")
        block["data_hex"] = encode_call(call).hex()
        ident = account_block_hash(block)
        entry = {"id_hex": ident, "time_locked_hex": block["address_hex"], "amount": block["amount"],
                 "token_standard_hex": block["token_standard_hex"], "expiration_time": call["expiration_time"],
                 "point_type": 1, "point_lock_hex": call["point_lock_hex"], "destination_hex": call["destination_hex"]}
        return {"hash_hex": ident, "block": block, "entry": entry}

    for leg in ("long", "short"):
        records[leg] = record(leg)
        terms[leg]["entry_id_hex"] = records[leg]["hash_hex"]
        for change in MUTATIONS:
            records[leg + "-changed-" + change] = record(leg, change)
    validate_terms(terms)
    vectors = []
    for leg in ("long", "short"):
        expiry = int(terms[leg]["expires_at"])
        recipient = terms[terms[leg]["recipient"] + "_address_hex"]
        funder = terms[terms[leg]["funder"] + "_address_hex"]

        def op(method="Unlock", at=700, error="NONE", *, caller=None, destination=None,
               chain=None, ident="created", witness="selected", after=None, payout=None):
            if after is None: after = error != "NONE"
            if payout is None and error == "NONE": payout = funder if method == "Reclaim" else recipient
            return {"method": method, "timestamp": str(at), "caller_hex": caller or recipient,
                    "destination_hex": destination or recipient, "chain_id": chain or terms["chain_id"],
                    "id_selection": ident, "witness_selection": witness, "expect_error": error,
                    "expect_entry_after": after, "expect_payout_to_hex": payout}

        def add(name, operations=(), *, funding=None, create_at=100, create_error="NONE"):
            vectors.append({"id": leg + "-" + name, "leg": leg, "funding_key": funding or leg,
                            "create_timestamp": str(create_at), "expect_create_error": create_error,
                            "operations": list(operations)})

        add("create-stores-send-derived-id")
        add("create-at-expiry", create_at=expiry, create_error="ErrInvalidExpirationTime")
        add("create-after-expiry", create_at=expiry + 1, create_error="ErrInvalidExpirationTime")
        add("direct-at-reference-send-confirmation-time", [op(at=900)])
        add("direct-one-second-before-expiry", [op(at=expiry - 1)])
        add("direct-at-expiry", [op(at=expiry, error="ErrExpired")])
        add("direct-after-expiry", [op(at=expiry + 1, error="ErrExpired")])
        add("proxy-funder-fixed-recipient", [op("ProxyUnlock", caller=funder)])
        add("proxy-third-party-fixed-recipient", [op("ProxyUnlock", caller=THIRD)])
        add("direct-wrong-caller", [op(caller=funder, error="ErrPermissionDenied")])
        add("proxy-wrong-recipient", [op("ProxyUnlock", destination=funder, error="ErrPermissionDenied")])
        add("wrong-chain-witness", [op(chain="70", error="ErrInvalidPointSignature")])
        add("old-entry-id", [op(ident="old", error="ErrDataNonExistent")])
        add("cross-leg-witness", [op(witness="other-leg", error="ErrInvalidPointSignature")])
        add("old-synthetic-witness", [op(witness="old", error="ErrInvalidPointSignature")])
        add("corrupt-witness", [op(witness="corrupt", error="ErrInvalidPointSignature")])
        add("wrong-width-witness", [op(witness="wrong-width", error="ErrInvalidPointSignature")])
        add("reclaim-one-second-before-expiry", [op("Reclaim", at=expiry - 1, caller=funder, error="ReclaimNotDue")])
        add("reclaim-at-expiry", [op("Reclaim", at=expiry, caller=funder)])
        add("reclaim-after-expiry", [op("Reclaim", at=expiry + 1, caller=funder)])
        add("reclaim-wrong-caller", [op("Reclaim", at=expiry, error="ErrPermissionDenied")])
        add("direct-replay-after-deletion", [op(), op(error="ErrDataNonExistent", after=False)])
        add("unlock-then-reclaim", [op(), op("Reclaim", at=expiry, caller=funder, error="ErrDataNonExistent", after=False)])
        add("reclaim-then-unlock", [op("Reclaim", at=expiry, caller=funder), op(at=expiry, error="ErrDataNonExistent", after=False)])
        add("invalid-then-valid-original", [op(witness="corrupt", error="ErrInvalidPointSignature"), op()])
        add("proxy-then-direct-replay", [op("ProxyUnlock", caller=THIRD), op(error="ErrDataNonExistent", after=False)])
        for change in MUTATIONS:
            key = leg + "-changed-" + change
            changed = records[key]
            add("changed-" + change + "-refuses-baseline-witness", [op(error="ErrInvalidPointSignature",
                caller=changed["entry"]["destination_hex"], destination=changed["entry"]["destination_hex"],
                chain=changed["block"]["chain_id"])], funding=key)
    return {"schema": "zenon-nom-created-funding-corpus-v1", "profile": PROFILE, "core_commit": CORE_COMMIT,
            "research_baseline_commit": "7327a9c52d657192871f5a1958bb530d4ea63a9b", "terms": terms,
            "old_entry_ids_hex": {leg: old[leg]["entry_id_hex"] for leg in ("long", "short")},
            "fundings": records, "vectors": vectors,
            "boundary": {"account_records": "PUBLIC HASH INPUTS; NOT SIGNED OR ADMITTED",
                         "source_execution": "ISOLATED METHODS WITH SYNTHETIC STORAGE AND TIME",
                         "witness_origin": "DISCLOSED TOY CONSTANTS IN TESTS ONLY",
                         "outer_account_authorization": "NOT_PERFORMED", "balance_accounting": "NOT_PERFORMED",
                         "source_authentication": "UNFILLED", "canonicality": "UNFILLED", "finality": "UNFILLED",
                         "rollback_protection": "UNFILLED", "application": "NO-GO", "core": "NO-GO"}}


if __name__ == "__main__":
    (ROOT / FIXTURE).write_text(json.dumps(corpus(), indent=2, sort_keys=True) + "\n", encoding="ascii")
