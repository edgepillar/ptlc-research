"""Open selected public NoM commitments, without authenticating their claims.

Only momentum bytes, two synthetic originals and two funding hash-input records
have selected payload grammars. These are not proofs of authority or execution.
Claim labels and local structural comparisons remain separate. No I/O or recovery
admission exists, including when every selected comparison matches.
"""

import hashlib
import json
import re

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_momentum as momentum, nom_recovery as recovery, nom_wire as account
from .pr138 import CONTRACT_HEX


SCHEMA = "ptlc-nom-public-evidence-openings-v1"
PAYLOAD_SCHEMA = "ptlc-nom-public-evidence-payload-v1"
SELECTED = ("funding_send", "original_authorization", "momentum_lineage")
MAX_WIRE_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 12
MAX_FUNDING_BYTES = 32768
_FIELDS = ("schema", "query_digest_hex", "claim_wire_digest_hex", "openings")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError)


class NoMOpeningRefused(ValueError):
    """Sanitized malformed opening; supplied evidence must still be retained."""


def _require(condition):
    if not condition:
        raise NoMOpeningRefused("NoM public evidence opening refused")


def _decode(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE_BYTES)
    depth, quoted, escaped = 0, False, False
    for byte in wire:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            _require(depth <= MAX_JSON_DEPTH)
        elif byte in (93, 125):
            depth -= 1
            _require(depth >= 0)
    _require(depth == 0 and not quoted)
    return codec._decode(wire, MAX_WIRE_BYTES)


def _raw_hex(value, limit):
    # Check the encoded byte boundary before allocating decoded bytes.
    _require(type(value) is str and 0 < len(value) <= 2 * limit and len(value) % 2 == 0
             and re.fullmatch("[0-9a-f]+", value) is not None)
    return bytes.fromhex(value)


def _payload(name, value):
    if name == "momentum_lineage":
        codec._object(value, ("candidate_wire_hex",))
        _raw_hex(value["candidate_wire_hex"], momentum.MAX_WIRE_BYTES)
    elif name == "original_authorization":
        codec._object(value, ("originals_hex",))
        codec._object(value["originals_hex"], ("long", "short"))
        for encoded in value["originals_hex"].values():
            _raw_hex(encoded, recovery.MAX_WIRE)
    elif name == "funding_send":
        codec._object(value, ("records",))
        codec._object(value["records"], ("long", "short"))
        for record in value["records"].values():
            codec._object(record, ("hash_hex", "block"))
            codec._hex(record["hash_hex"])
            account.account_block_preimage(record["block"])
        _require(len(codec._canonical(value)) <= MAX_FUNDING_BYTES)
    else:
        raise NoMOpeningRefused("unselected NoM opening profile")


def claim_digest(wire):
    """Commit to exact claim bytes; this alone does not parse or trust them."""
    _require(type(wire) is bytes and 0 < len(wire) <= authority.MAX_WIRE_BYTES)
    return hashlib.sha256(b"ptlc-nom-opened-claim-v1\0" + wire).hexdigest()


def opening_digest(expected, name, status, payload):
    """Bind payload grammar, complete query, fact name and untrusted status.

    This checks encodings, not semantic support. A contradictory or forged
    well-shaped payload can acquire a digest without becoming a true fact.
    """
    try:
        _require(type(expected) is authority.NoMReadQuery and type(name) is str
                 and name in SELECTED and type(status) is str and status in ("supported", "contradicted"))
        _payload(name, payload)
        value = dict(schema=PAYLOAD_SCHEMA, query_digest_hex=expected.digest_hex,
                     obligation=name, status=status, payload=payload)
        wire = codec._canonical(value)
        _decode(wire)
        return hashlib.sha256(b"ptlc-nom-evidence-payload-v1\0" + wire).hexdigest()
    except _ERRORS:
        raise NoMOpeningRefused("NoM evidence commitment preparation refused") from None


def _match(condition):
    return "MATCH" if condition else "DIFFERS_FROM_SELECTION"


def _candidate(query, payload):
    raw = _raw_hex(payload["candidate_wire_hex"], momentum.MAX_WIRE_BYTES)
    _require(authority.candidate_digest(raw) == query["candidate_wire_digest_hex"])
    result = momentum.parse_branch_wire(raw, chain_id=query["terms"]["chain_id"],
        selected_anchor_claim=query["selected_anchor_claim"], required_inclusions=query["required_inclusions"])
    _require(result["structure"] == "MATCH")
    value = json.loads(raw.decode("ascii"))
    last = value["momenta"][-1]
    _require(query["checkpoint_selection"]["momentum"] == {"hash_hex": last["hash_hex"],
        "height": last["momentum"]["height"], "timestamp": last["momentum"]["timestamp"]})
    return value


def _funding(query, payload, candidate):
    terms, results = query["terms"], {}
    for leg, record in payload["records"].items():
        block, selected = record["block"], terms[leg]
        computed = account.account_block_hash(block)
        destination = terms[selected["recipient"] + "_address_hex"]
        funder = terms[selected["funder"] + "_address_hex"]
        try:
            create = account.decode_call(bytes.fromhex(block["data_hex"]))
        except ValueError:
            create = None
        expected_call = dict(method="Create", expiration_time=selected["expires_at"], point_type=1,
                             point_lock_hex=selected["funder_key_xonly_hex"], destination_hex=destination)
        selection_matches = (block["version"] == "1" and block["chain_id"] == terms["chain_id"]
            and block["block_type"] == "2" and block["address_hex"] == funder
            and block["to_address_hex"] == CONTRACT_HEX and block["amount"] == selected["amount"]
            and block["token_standard_hex"] == selected["token_standard_hex"]
            and block["from_block_hash_hex"] == "00" * 32 and block["descendant_hashes_hex"] == []
            and create == expected_call)
        membership, confirmations = "NOT_CHECKED_MISSING_CANDIDATE", []
        if candidate is not None:
            header = {"address_hex": block["address_hex"], "height": block["height"], "hash_hex": computed}
            for item in candidate["momenta"]:
                if header in item["momentum"]["content"]:
                    confirmations.append({"hash_hex": item["hash_hex"], "height": item["momentum"]["height"],
                                          "timestamp": item["momentum"]["timestamp"]})
            membership = "INCLUDED_CLAIM" if confirmations else "NOT_INCLUDED_CLAIM"
        # A header claim cannot validate the acknowledged momentum or account admission.
        results[leg] = {"computed_hash_hex": computed,
            "advertised_hash": "MATCH" if computed == record["hash_hex"] else "DIFFERS_FROM_ADVERTISED",
            "create_terms": _match(selection_matches), "send_derived_entry": _match(computed == selected["entry_id_hex"]),
            "candidate_membership": membership, "confirmation_claims": confirmations,
            "signed_account_wire": "ABSENT", "outer_account_authorization": "NOT_PERFORMED",
            "acknowledged_momentum_admission": "NOT_PERFORMED", "live_entry": "NOT_PERFORMED"}
    return results


def inspect_openings(expected, claim_wire, opening_wire):
    """Compare three bounded public payload types and preserve claim distinctions.

    Eight evidence obligations still have no selected opening profile. Missing
    openings never erase charged work, disclosure or originals. Neither source
    labels nor successful comparisons are capabilities. The returned bundle is
    a decoded copy only: durable retention and use-time admission are absent.
    """
    try:
        _require(type(expected) is authority.NoMReadQuery)
        query = expected.as_dict()
        parsed = authority.parse_claim(expected, claim_wire)
        value = _decode(opening_wire)
        codec._object(value, _FIELDS)
        _require(value["schema"] == SCHEMA and value["query_digest_hex"] == expected.digest_hex
                 and value["claim_wire_digest_hex"] == claim_digest(claim_wire))
        codec._object(value["openings"], SELECTED)
        facts, results, candidate = parsed["claim"]["facts"], {}, None
        for name in SELECTED:
            payload, fact = value["openings"][name], facts[name]
            if payload is None:
                results[name] = {"opening": "UNKNOWN_CLAIM" if fact["status"] == "unknown" else "MISSING_OPENING"}
                continue
            _require(fact["status"] != "unknown")
            _require(opening_digest(expected, name, fact["status"], payload) == fact["evidence_digest_hex"])
            results[name] = {"opening": "BOUND_UNAUTHENTICATED_PAYLOAD", "claimed_status": fact["status"]}
        payload = value["openings"]["momentum_lineage"]
        if payload is not None:
            candidate = _candidate(query, payload)
            results["momentum_lineage"]["structural_comparison"] = "MATCH"
        payload = value["openings"]["original_authorization"]
        if payload is not None:
            for leg, encoded in payload["originals_hex"].items():
                recovery.claim_signature(query["terms"], leg, _raw_hex(encoded, recovery.MAX_WIRE))
            results["original_authorization"]["exact_originals"] = {
                leg: _match(encoded == query["originals_hex"][leg]) for leg, encoded in payload["originals_hex"].items()}
            results["original_authorization"]["inner_signature_verification"] = "NOT_PERFORMED"
            results["original_authorization"]["signed_account_wire"] = "ABSENT"
        payload = value["openings"]["funding_send"]
        if payload is not None:
            results["funding_send"]["legs"] = _funding(query, payload, candidate)
        for name in authority.OBLIGATIONS:
            if name not in SELECTED:
                results[name] = {"opening": "UNKNOWN_CLAIM" if facts[name]["status"] == "unknown"
                                else "OPENING_PROFILE_UNSELECTED"}
        return {"framing": "BOUND_PUBLIC_OPENINGS_ONLY", "claim_coverage": parsed["coverage"],
            "claim": parsed["claim"], "opening_bundle": value, "comparisons": results,
            "unselected_profiles": [name for name in authority.OBLIGATIONS if name not in SELECTED],
            "source_authentication": "NOT_PERFORMED", "source_currentness": "UNFILLED",
            "proof_verification": "NOT_PERFORMED", "canonicality": "UNFILLED", "finality": "UNFILLED",
            "network_provisioning": "NOT_PERFORMED", "restore_fence": "UNFILLED", "atomic_entry": "NOT_IMPLEMENTED",
            "retain_prior_evidence": True, "retain_original_bytes": True, "retain_possible_disclosure": True,
            "revalidate_funding_before_recovery": True, "revalidate_live_entry_before_recovery": True,
            "durable_retention": "NOT_PERFORMED", "replenish_work": False, "replacement_original_allowed": False,
            "recovery_action": "NONE", "application": "NO-GO", "core": "NO-GO"}
    except _ERRORS:
        raise NoMOpeningRefused("NoM public evidence opening refused") from None
