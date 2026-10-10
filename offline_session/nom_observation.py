"""Bounded structural claims for one synthetic fixed-recipient NoM flow.

Matching hashes, supplied contexts and fields authenticate nothing. This module
does not verify signatures, momentum inclusion, canonicality, finality, VM state
or spendability. It has no I/O, journal admission or recovery capability.
"""

import json

from .nom_wire import account_block_hash, decode_call
from .pr138 import CORE_COMMIT, CONTRACT_HEX, CompatibilityError, decimal, fixed_hex, payable


PROFILE = "zenon-pr138-observation-claims-v1"
MAX_WIRE_BYTES = 32768
MAX_JSON_DEPTH = 16
ROLES = ("funding", "funding_receive", "original", "payout", "contract_receive", "recipient_receive")
TERMS = frozenset({"chain_id", "funder_hex", "recipient_hex", "token_standard_hex", "amount",
                   "expiration_time", "point_type", "point_lock_hex"})
ENTRY = frozenset({"id_hex", "time_locked_hex", "token_standard_hex", "amount", "expiration_time",
                   "point_type", "point_lock_hex", "destination_hex"})
CONTEXTS = ("funding_confirmation", "original_confirmation", "payout_confirmation", "recipient_confirmation")
CONTEXT_FIELDS = frozenset({"hash_hex", "height", "timestamp"})
CLAIM_FIELDS = frozenset({"schema", "profile", "core_commit", "records", "entry",
                          "contexts", "view", "post_entry_present"})
ZERO_HASH, ZERO_ADDRESS, ZERO_TOKEN = "00" * 32, "00" * 20, "00" * 10
SUCCESS_DATA = "0000000000000001"


class ObservationRefused(CompatibilityError):
    """Sanitized structural refusal, containing no supplied value."""


def require(condition, reason):
    if not condition:
        raise ObservationRefused(reason)


def context(value):
    require(type(value) is dict and value.keys() == CONTEXT_FIELDS, "CONTEXT_SHAPE")
    fixed_hex(value["hash_hex"], 32)
    require(value["hash_hex"] != ZERO_HASH, "CONTEXT_ZERO_HASH")
    decimal(value["height"], 64, positive=True)
    decimal(value["timestamp"], 63, positive=True)
    return value


def selected_terms(value):
    require(type(value) is dict and value.keys() == TERMS, "TERMS_SHAPE")
    decimal(value["chain_id"], 64, positive=True)
    decimal(value["amount"], 255, positive=True)
    decimal(value["expiration_time"], 63, positive=True)
    require(payable(value["funder_hex"]) and payable(value["recipient_hex"]), "TERMS_ADDRESS")
    require(value["funder_hex"] != value["recipient_hex"], "TERMS_ROLES")
    fixed_hex(value["token_standard_hex"], 10)
    require(value["token_standard_hex"] != ZERO_TOKEN, "TERMS_TOKEN")
    require(type(value["point_type"]) is int and value["point_type"] == 1, "SELECTED_BIP340_PROFILE")
    fixed_hex(value["point_lock_hex"], 32)
    return value


def inspect_claim(claim, *, terms, selected_view_claim):
    """Return a claim comparison only; even MATCH authorizes no recovery.

    Selected terms and view are caller claims, not trusted provisioning. This
    strict profile selects adjacent recipient-account blocks and exactly one
    payout. It is narrower than general node admission. Missing records remain
    incomplete; entry absence never establishes a terminal outcome.
    """
    result = {"schema": "zenon-nom-observation-result-v1", "profile": PROFILE,
              "structure": "REFUSED", "reason": "INVALID_PUBLIC_ENCODING",
              "signature_verification": "NOT_PERFORMED", "source_authentication": "NOT_PERFORMED",
              "vm_execution": "NOT_PERFORMED", "canonicality": "UNFILLED", "finality": "UNFILLED",
              "recovery_action": "NONE", "application": "NO-GO", "core": "NO-GO"}
    try:
        selected_terms(terms)
        context(selected_view_claim)
        require(type(claim) is dict and claim.keys() == CLAIM_FIELDS, "CLAIM_SHAPE")
        require(claim["schema"] == "zenon-nom-observation-claim-v1" and claim["profile"] == PROFILE
                and claim["core_commit"] == CORE_COMMIT, "CLAIM_PROFILE")
        require(type(claim["post_entry_present"]) is bool, "ENTRY_PRESENCE_SHAPE")
        require(type(claim["records"]) is dict and claim["records"].keys() == set(ROLES), "RECORD_ROLES")
        require(type(claim["contexts"]) is dict and claim["contexts"].keys() == set(CONTEXTS), "CONTEXT_ROLES")
        context(claim["view"])
        require(claim["view"] == selected_view_claim, "SELECTED_VIEW_MISMATCH")
        contexts = [context(claim["contexts"][name]) for name in CONTEXTS] + [claim["view"]]
        for earlier, later in zip(contexts, contexts[1:]):
            require(int(earlier["height"]) <= int(later["height"])
                    and int(earlier["timestamp"]) <= int(later["timestamp"]), "CONTEXT_ORDER")
            if earlier["height"] == later["height"]:
                require(earlier == later, "CONTRADICTORY_CONTEXT")
        missing = [name for name in ROLES if claim["records"][name] is None]
        if claim["entry"] is None:
            missing.append("entry")
        records = claim["records"]
        for name in ROLES:
            record = records[name]
            if record is None:
                continue
            require(type(record) is dict and record.keys() == {"hash_hex", "block"}, "RECORD_SHAPE")
            fixed_hex(record["hash_hex"], 32)
            require(account_block_hash(record["block"]) == record["hash_hex"], "ADVERTISED_HASH_MISMATCH")
            block = record["block"]
            require(block["version"] == "1" and block["chain_id"] == terms["chain_id"], "BLOCK_PROFILE")
            decimal(block["height"], 64, positive=True)
            require(block["momentum_hash_hex"] != ZERO_HASH and int(block["momentum_height"]) > 0,
                    "BLOCK_CONTEXT_MISSING")
            # This selected unmined structural profile is not a Plasma policy.
            require(block["difficulty"] == "0" and block["nonce_hex"] == "00" * 8, "SELECTED_UNMINED_PROFILE")
            if name != "contract_receive":
                require(block["descendant_hashes_hex"] == [], "UNEXPECTED_DESCENDANTS")
        if missing:
            result.update(structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME", missing_claims=missing)
            return result
        blocks = {name: records[name]["block"] for name in ROLES}
        funding, original, payout = (blocks[name] for name in ("funding", "original", "payout"))
        require(funding["block_type"] == "2" and funding["address_hex"] == terms["funder_hex"]
                and funding["to_address_hex"] == CONTRACT_HEX and funding["from_block_hash_hex"] == ZERO_HASH
                and funding["token_standard_hex"] == terms["token_standard_hex"]
                and funding["amount"] == terms["amount"], "FUNDING_TERMS")
        create = decode_call(bytes.fromhex(funding["data_hex"]))
        require(create == {"method": "Create", "expiration_time": terms["expiration_time"],
                           "point_type": terms["point_type"], "point_lock_hex": terms["point_lock_hex"],
                           "destination_hex": terms["recipient_hex"]}, "CREATE_TERMS")
        expected_entry = {"id_hex": records["funding"]["hash_hex"], "time_locked_hex": terms["funder_hex"],
                          "token_standard_hex": terms["token_standard_hex"], "amount": terms["amount"],
                          "expiration_time": terms["expiration_time"], "point_type": terms["point_type"],
                          "point_lock_hex": terms["point_lock_hex"], "destination_hex": terms["recipient_hex"]}
        require(type(claim["entry"]) is dict and claim["entry"].keys() == ENTRY
                and claim["entry"] == expected_entry, "ENTRY_TERMS")
        call = decode_call(bytes.fromhex(original["data_hex"]))
        require(call["method"] == "Unlock" and call["entry_id_hex"] == expected_entry["id_hex"]
                and len(call["witness_hex"]) == 128, "SELECTED_UNLOCK_CALL")
        require(original["block_type"] == "2" and original["address_hex"] == terms["recipient_hex"]
                and original["to_address_hex"] == CONTRACT_HEX and original["amount"] == "0"
                and original["token_standard_hex"] == ZERO_TOKEN
                and original["from_block_hash_hex"] == ZERO_HASH, "ORIGINAL_TERMS")
        for role, send, confirmed in (("funding_receive", "funding", contexts[0]),
                                       ("contract_receive", "original", contexts[1])):
            block = blocks[role]
            require(block["block_type"] == "5" and block["address_hex"] == CONTRACT_HEX
                    and block["from_block_hash_hex"] == records[send]["hash_hex"], "CONTRACT_RECEIVE_LINK")
            require(block["amount"] == "0" and block["token_standard_hex"] == ZERO_TOKEN
                    and block["to_address_hex"] == ZERO_ADDRESS, "RECEIVE_FIELDS")
            require(block["momentum_hash_hex"] == confirmed["hash_hex"]
                    and block["momentum_height"] == confirmed["height"], "CONFIRMING_CONTEXT")
            require(block["data_hex"] == SUCCESS_DATA, "EXECUTION_STATUS_CLAIM")
            require(int(blocks[send]["momentum_height"]) <= int(confirmed["height"]), "SEND_NOT_YET_CONFIRMED")
        expiry = int(terms["expiration_time"])
        require(int(contexts[0]["timestamp"]) < expiry and int(contexts[1]["timestamp"]) < expiry,
                "EXPIRED_EXECUTION_CONTEXT")
        require(payout["block_type"] == "4" and payout["address_hex"] == CONTRACT_HEX
                and payout["to_address_hex"] == terms["recipient_hex"] and payout["amount"] == terms["amount"]
                and payout["token_standard_hex"] == terms["token_standard_hex"]
                and payout["from_block_hash_hex"] == ZERO_HASH and payout["data_hex"] == "", "PAYOUT_TERMS")
        parent = blocks["contract_receive"]
        require(parent["descendant_hashes_hex"] == [records["payout"]["hash_hex"]], "DESCENDANT_CLAIMS")
        require(payout["momentum_hash_hex"] == parent["momentum_hash_hex"]
                and payout["momentum_height"] == parent["momentum_height"], "DESCENDANT_CONTEXT")
        require(payout["previous_hash_hex"] == records["funding_receive"]["hash_hex"]
                and int(payout["height"]) == int(blocks["funding_receive"]["height"]) + 1
                and parent["previous_hash_hex"] == records["payout"]["hash_hex"]
                and int(parent["height"]) == int(payout["height"]) + 1, "CONTRACT_ACCOUNT_LINK")
        receipt = blocks["recipient_receive"]
        require(receipt["block_type"] == "3" and receipt["address_hex"] == terms["recipient_hex"]
                and receipt["from_block_hash_hex"] == records["payout"]["hash_hex"], "RECIPIENT_RECEIVE_LINK")
        require(receipt["amount"] == "0" and receipt["token_standard_hex"] == ZERO_TOKEN
                and receipt["to_address_hex"] == ZERO_ADDRESS and receipt["data_hex"] == "", "RECEIVE_FIELDS")
        require(receipt["previous_hash_hex"] == records["original"]["hash_hex"]
                and int(receipt["height"]) == int(original["height"]) + 1, "RECIPIENT_ACCOUNT_LINK")
        require(int(contexts[2]["height"]) <= int(receipt["momentum_height"])
                <= int(contexts[3]["height"]), "RECEIPT_CONFIRMATION_ORDER")
        known_contexts = {value["height"]: value["hash_hex"] for value in contexts}
        for block in blocks.values():
            height = block["momentum_height"]
            if height in known_contexts:
                require(block["momentum_hash_hex"] == known_contexts[height], "ACKNOWLEDGEMENT_HASH_CLAIM")
        require(not claim["post_entry_present"], "ENTRY_STATE_CONFLICT")
        result.update(structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY")
    except ObservationRefused as failure:
        result["reason"] = str(failure)
    except (CompatibilityError, ValueError, TypeError, KeyError, OverflowError):
        pass
    return result


def parse_claim_wire(wire, *, terms, selected_view_claim):
    """Bound JSON claim parsing; duplicate keys and non-finite values fail closed."""
    require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE_BYTES, "WIRE_BOUND")
    depth, quoted, escaped = 0, False, False
    for value in wire:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in (91, 123):
            depth += 1
            require(depth <= MAX_JSON_DEPTH, "JSON_DEPTH_BOUND")
        elif value in (93, 125):
            depth -= 1
            require(depth >= 0, "INVALID_JSON")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_KEY")
            result[key] = value
        return result
    def constant(_):
        raise ObservationRefused("NONFINITE_JSON")
    try:
        claim = json.loads(wire.decode("ascii"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ObservationRefused("INVALID_JSON") from None
    return inspect_claim(claim, terms=terms, selected_view_claim=selected_view_claim)
