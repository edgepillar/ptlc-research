"""Compare query-bound public VM roles without trusting a source or admitting use.

This additive profile retains the frozen three-opening comparison. Hash inputs,
status bytes and patch-hash claims cannot authenticate account execution, a
recipient frontier, inclusion, spendability or a recoverable terminal outcome.
There is no I/O, source callback, journal entry or recovery capability.
"""

import hashlib

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_evidence_openings as base, nom_recovery as recovery, nom_wire as account
from .pr138 import CONTRACT_HEX, payable


SCHEMA = "ptlc-nom-vm-evidence-openings-v1"
PAYLOAD_SCHEMA = "ptlc-nom-vm-evidence-payload-v1"
SELECTED = ("unlock_send", "contract_receive", "contract_payout", "recipient_receipt")
MAX_WIRE_BYTES = 256 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024
_FIELDS = ("schema", "query_digest_hex", "claim_wire_digest_hex", "base_opening_wire_digest_hex", "openings")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError)
ZERO_HASH, ZERO_ADDRESS, ZERO_TOKEN = "00" * 32, "00" * 20, "00" * 10


class NoMVMOpeningRefused(ValueError):
    """Sanitized framing refusal; malformed evidence must still be retained."""


def _require(condition):
    if not condition:
        raise NoMVMOpeningRefused("NoM VM evidence opening refused")


def base_digest(wire):
    """Commit to exact base-opening bytes, without parsing or trusting them."""
    _require(type(wire) is bytes and 0 < len(wire) <= base.MAX_WIRE_BYTES)
    return hashlib.sha256(b"ptlc-nom-vm-base-openings-v1\0" + wire).hexdigest()


def _record(value):
    codec._object(value, ("hash_hex", "changes_hash_hex", "block"))
    codec._hex(value["hash_hex"])
    codec._hex(value["changes_hash_hex"])
    account.account_block_preimage(value["block"])


def _payload(name, value):
    codec._object(value, ("records",))
    codec._object(value["records"], ("long", "short"))
    for record in value["records"].values():
        if name == "contract_receive":
            codec._object(record, ("funding_receive", "receive"))
            for item in record.values():
                _record(item)
        else:
            _record(record)
    _require(len(codec._canonical(value)) <= MAX_PAYLOAD_BYTES)


def opening_digest(expected, name, status, payload):
    """Bind typed claim bytes and the complete read selection.

    A contradictory but well-shaped payload can acquire a digest. Preparation
    neither checks semantic support nor upgrades a source's supported label.
    """
    try:
        _require(type(expected) is authority.NoMReadQuery and type(name) is str and name in SELECTED
                 and type(status) is str and status in ("supported", "contradicted"))
        _payload(name, payload)
        value = dict(schema=PAYLOAD_SCHEMA, query_digest_hex=expected.digest_hex,
                     obligation=name, status=status, payload=payload)
        wire = codec._canonical(value)
        base._decode(wire)
        return hashlib.sha256(b"ptlc-nom-vm-evidence-payload-v1\0" + wire).hexdigest()
    except _ERRORS:
        raise NoMVMOpeningRefused("NoM VM commitment preparation refused") from None


def _match(condition):
    return "MATCH" if condition else "DIFFERS_FROM_SELECTION"


def _header(record, candidate):
    block = record["block"]
    computed = account.account_block_hash(block)
    confirmations, known = [], "NOT_CHECKED_MISSING_CANDIDATE"
    if candidate is not None:
        header = {"address_hex": block["address_hex"], "height": block["height"], "hash_hex": computed}
        known = "HEIGHT_NOT_PRESENT_IN_OPENED_CANDIDATE"
        for item in candidate["momenta"]:
            selected = item["momentum"]
            if header in selected["content"]:
                confirmations.append({"hash_hex": item["hash_hex"], "height": selected["height"],
                                      "timestamp": selected["timestamp"]})
            if selected["height"] == block["momentum_height"]:
                known = _match(item["hash_hex"] == block["momentum_hash_hex"])
    return {"computed_hash_hex": computed, "advertised_hash": _match(computed == record["hash_hex"]),
        "changes_hash": "OPAQUE SEPARATE CLAIM; NOT AN ACCOUNT-HASH INPUT OR EXECUTION PROOF",
        "candidate_membership": ("NOT_CHECKED_MISSING_CANDIDATE" if candidate is None else
                                 "INCLUDED_CLAIM" if confirmations else "NOT_INCLUDED_CLAIM"),
        "confirmation_claims": confirmations, "known_acknowledgement": known,
        "signed_account_wire": "ABSENT", "outer_account_authorization": "NOT_PERFORMED"}


def _profile(block, terms, block_type, address):
    return (block["version"] == "1" and block["chain_id"] == terms["chain_id"]
            and block["block_type"] == block_type and block["address_hex"] == address
            and int(block["height"]) > 0 and int(block["momentum_height"]) > 0
            and block["momentum_hash_hex"] != ZERO_HASH)


def _empty_receive(block, data):
    return (block["to_address_hex"] == ZERO_ADDRESS and block["token_standard_hex"] == ZERO_TOKEN
            and block["amount"] == "0" and block["data_hex"] == data)


def _ack(block, reference, *, equal=False):
    left, right = int(block["momentum_height"]), int(reference["momentum_height"])
    return ((left == right if equal else left >= right)
            and (left != right or block["momentum_hash_hex"] == reference["momentum_hash_hex"]))


def _legs(query, opened, base_result, candidate):
    terms, output = query["terms"], {}
    for leg in ("long", "short"):
        selected = terms[leg]
        recipient = terms[selected["recipient"] + "_address_hex"]
        records = {name: opened[name]["records"][leg] if opened[name] is not None else None for name in SELECTED}
        result = {}
        for name, record in records.items():
            if record is not None:
                result[name] = ({key: _header(value, candidate) for key, value in record.items()}
                                if name == "contract_receive" else _header(record, candidate))
        send, parents, payout, receipt = (records[name] for name in SELECTED)
        if send is not None:
            block = send["block"]
            try:
                call = account.decode_call(bytes.fromhex(block["data_hex"]))
            except ValueError:
                call = None
            signature = recovery.claim_signature(terms, leg, bytes.fromhex(query["originals_hex"][leg]))
            method = call["method"] if call is not None else "UNDECODABLE_CALL"
            accepted_call = (call == dict(method="Unlock", entry_id_hex=selected["entry_id_hex"], witness_hex=signature)
                            or call == dict(method="ProxyUnlock", entry_id_hex=selected["entry_id_hex"],
                                            destination_hex=recipient, witness_hex=signature))
            caller = block["address_hex"] == recipient if method == "Unlock" else payable(block["address_hex"])
            result["unlock_send"].update(method_claim=method, retained_inner_witness_and_call=_match(accepted_call),
                send_fields=_match(_profile(block, terms, "2", block["address_hex"]) and caller
                    and block["to_address_hex"] == CONTRACT_HEX and block["amount"] == "0"
                    and block["token_standard_hex"] == ZERO_TOKEN and block["from_block_hash_hex"] == ZERO_HASH
                    and block["descendant_hashes_hex"] == []), inner_signature_verification="NOT_PERFORMED",
                original_identity="RETAINED SYNTHETIC ENVELOPE IS NOT THE ACCOUNT-BLOCK HASH")
        if parents is not None:
            funding_parent, parent = parents["funding_receive"]["block"], parents["receive"]["block"]
            funding_opening = base_result["opening_bundle"]["openings"]["funding_send"]
            funding = funding_opening["records"][leg] if funding_opening is not None else None
            result["contract_receive"].update(
                funding_linkage=("MISSING_FUNDING_OPENING" if funding is None else _match(
                    funding_parent["from_block_hash_hex"] == account.account_block_hash(funding["block"]))),
                funding_acknowledgement_order=("MISSING_FUNDING_OPENING" if funding is None else
                    _match(_ack(funding_parent, funding["block"]))),
                funding_receive_fields=_match(_profile(funding_parent, terms, "5", CONTRACT_HEX)
                    and _empty_receive(funding_parent, "0000000000000001") and funding_parent["descendant_hashes_hex"] == []),
                receive_fields_and_status_claim=_match(_profile(parent, terms, "5", CONTRACT_HEX)
                    and _empty_receive(parent, "0000000000000001")),
                send_linkage=("MISSING_UNLOCK_OPENING" if send is None else _match(
                    parent["from_block_hash_hex"] == account.account_block_hash(send["block"]))),
                send_acknowledgement_order=("MISSING_UNLOCK_OPENING" if send is None else _match(_ack(parent, send["block"]))),
                execution_verification="NOT_PERFORMED", expiry_time_authority="UNFILLED", live_entry="NOT_PERFORMED")
        if payout is not None:
            block = payout["block"]
            result["contract_payout"].update(fixed_asset_and_recipient=_match(_profile(block, terms, "4", CONTRACT_HEX)
                and block["to_address_hex"] == recipient and block["amount"] == selected["amount"]
                and block["token_standard_hex"] == selected["token_standard_hex"]
                and block["from_block_hash_hex"] == ZERO_HASH and block["data_hex"] == ""
                and block["descendant_hashes_hex"] == []))
            if parents is None:
                result["contract_payout"]["parent_child_linkage"] = "MISSING_CONTRACT_RECEIVE_OPENING"
            else:
                funding_parent, parent = parents["funding_receive"]["block"], parents["receive"]["block"]
                computed = account.account_block_hash(block)
                result["contract_payout"]["parent_child_linkage"] = _match(
                    block["previous_hash_hex"] == account.account_block_hash(funding_parent)
                    and int(block["height"]) == int(funding_parent["height"]) + 1
                    and parent["previous_hash_hex"] == computed and int(parent["height"]) == int(block["height"]) + 1
                    and parent["descendant_hashes_hex"] == [computed] and _ack(parent, block, equal=True))
        if receipt is not None:
            block = receipt["block"]
            result["recipient_receipt"].update(receive_fields=_match(_profile(block, terms, "3", recipient)
                and _empty_receive(block, "") and block["descendant_hashes_hex"] == []),
                payout_linkage=("MISSING_PAYOUT_OPENING" if payout is None else _match(
                    block["from_block_hash_hex"] == account.account_block_hash(payout["block"]))),
                payout_acknowledgement_order=("MISSING_PAYOUT_OPENING" if payout is None else _match(_ack(block, payout["block"]))),
                recipient_account_continuity=("MISSING_UNLOCK_OPENING" if send is None else
                    "PRIOR_RECIPIENT_FRONTIER_UNSELECTED" if send["block"]["address_hex"] != recipient else _match(
                        block["previous_hash_hex"] == account.account_block_hash(send["block"])
                        and int(block["height"]) == int(send["block"]["height"]) + 1)),
                received_marker_proof="ABSENT", duplicate_receive_admission="NOT_PERFORMED", spendability="UNFILLED")
        output[leg] = result
    return output


def inspect_vm_openings(expected, claim_wire, base_wire, opening_wire):
    """Retain mismatches separately from claim labels; no match permits recovery.

    Four further grammars are selected here, not four further verified facts.
    Missing roles do not become absent remote state or a terminal outcome.
    Recipient adjacency is deliberately narrower than general account admission.
    """
    try:
        _require(type(expected) is authority.NoMReadQuery and type(opening_wire) is bytes
                 and 0 < len(opening_wire) <= MAX_WIRE_BYTES)
        base_result = base.inspect_openings(expected, claim_wire, base_wire)
        value = base._decode(opening_wire)
        codec._object(value, _FIELDS)
        _require(value["schema"] == SCHEMA and value["query_digest_hex"] == expected.digest_hex
                 and value["claim_wire_digest_hex"] == base.claim_digest(claim_wire)
                 and value["base_opening_wire_digest_hex"] == base_digest(base_wire))
        codec._object(value["openings"], SELECTED)
        facts, comparisons = base_result["claim"]["facts"], {}
        for name in SELECTED:
            payload, fact = value["openings"][name], facts[name]
            if payload is None:
                comparisons[name] = {"opening": "UNKNOWN_CLAIM" if fact["status"] == "unknown" else "MISSING_OPENING"}
            else:
                _require(fact["status"] != "unknown" and opening_digest(expected, name, fact["status"], payload)
                         == fact["evidence_digest_hex"])
                comparisons[name] = {"opening": "BOUND_UNAUTHENTICATED_PAYLOAD", "claimed_status": fact["status"]}
        query = expected.as_dict()
        candidate_payload = base_result["opening_bundle"]["openings"]["momentum_lineage"]
        candidate = base._candidate(query, candidate_payload) if candidate_payload is not None else None
        legs = _legs(query, value["openings"], base_result, candidate)
        result = {key: item for key, item in base_result.items()
                  if key not in ("comparisons", "opening_bundle", "unselected_profiles", "framing")}
        result.update(framing="BOUND_VM_PUBLIC_OPENINGS_ONLY", base_opening_result=base_result,
            opening_bundle=value, comparisons=comparisons, legs=legs,
            unselected_profiles=[name for name in authority.OBLIGATIONS if name not in (*base.SELECTED, *SELECTED)],
            vm_execution="NOT_PERFORMED", account_admission="NOT_PERFORMED", received_state_proof="ABSENT",
            terminal_outcome="NOT_ESTABLISHED", aggregate_work_budget="UNSELECTED")
        return result
    except _ERRORS:
        raise NoMVMOpeningRefused("NoM VM evidence opening refused") from None
