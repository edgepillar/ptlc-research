"""Bounded momentum, inclusion and fork claims for offline research only.

SHA3 digests and a supplied common anchor establish structural bindings only.
No producer authentication, genesis/spork authority, canonicality, finality,
account admission, persistence or recovery capability is supplied here.
"""

import hashlib
import json
import re

from .pr138 import CORE_COMMIT, CompatibilityError, decimal, fixed_hex


PROFILE = "zenon-pr138-momentum-claims-v1"
MAX_MOMENTA = 64
MAX_CONTENT = 64
MAX_INCLUSIONS = 64
MAX_DATA_BYTES = 4096
MAX_WIRE_BYTES = 512 * 1024
MAX_JSON_DEPTH = 16
HEADER_FIELDS = frozenset({"address_hex", "height", "hash_hex"})
CONTEXT_FIELDS = frozenset({"hash_hex", "height", "timestamp"})
MOMENTUM_FIELDS = frozenset({"version", "chain_id", "previous_hash_hex", "height", "timestamp",
                           "data_hex", "content", "changes_hash_hex", "next_fusion_price", "next_work_price"})
RECORD_FIELDS = frozenset({"momentum", "hash_hex", "public_key_hex", "signature_hex"})
CLAIM_FIELDS = frozenset({"schema", "profile", "core_commit", "anchor", "momenta"})
INCLUSION_FIELDS = frozenset({"id", "header", "confirmation"})


class MomentumRefused(CompatibilityError):
    """Sanitized structural refusal; no remote bytes in diagnostics."""


def require(condition, reason):
    if not condition:
        raise MomentumRefused(reason)


def header_bytes(header):
    require(type(header) is dict and header.keys() == HEADER_FIELDS, "HEADER_SHAPE")
    return (fixed_hex(header["address_hex"], 20) + decimal(header["height"], 64).to_bytes(8, "big")
            + fixed_hex(header["hash_hex"], 32))


def content_bytes(content):
    require(type(content) is list and len(content) <= MAX_CONTENT, "CONTENT_BOUND")
    # Source hashing commits to the supplied order; verification must not sort.
    return b"".join(header_bytes(header) for header in content)


def momentum_preimage(momentum):
    """Raw source hash layout, including versions not admitted by the node.

    Version >= 2 includes both prices. Version 1 ignores their values in its
    digest; the separate inspection/source version checks still refuse them.
    """
    require(type(momentum) is dict and momentum.keys() == MOMENTUM_FIELDS, "MOMENTUM_SHAPE")
    data = momentum["data_hex"]
    require(type(data) is str and len(data) <= 2 * MAX_DATA_BYTES and len(data) % 2 == 0
            and re.fullmatch("[0-9a-f]*", data) is not None, "DATA_BOUND")
    u64 = lambda name: decimal(momentum[name], 64).to_bytes(8, "big")
    prices = u64("next_fusion_price") + u64("next_work_price")
    preimage = (u64("version") + u64("chain_id") + fixed_hex(momentum["previous_hash_hex"], 32)
                + u64("height") + u64("timestamp") + hashlib.sha3_256(bytes.fromhex(data)).digest()
                + hashlib.sha3_256(content_bytes(momentum["content"])).digest()
                + fixed_hex(momentum["changes_hash_hex"], 32))
    if decimal(momentum["version"], 64) >= 2:
        preimage += prices
    return preimage


def momentum_hash(momentum):
    return hashlib.sha3_256(momentum_preimage(momentum)).hexdigest()


def context(value):
    require(type(value) is dict and value.keys() == CONTEXT_FIELDS, "CONTEXT_SHAPE")
    fixed_hex(value["hash_hex"], 32)
    decimal(value["height"], 64, positive=True)
    decimal(value["timestamp"], 63, positive=True)
    require(value["hash_hex"] != "00" * 32, "CONTEXT_HASH")
    return value


def _inclusions(values):
    require(type(values) is list and len(values) <= MAX_INCLUSIONS, "INCLUSION_BOUND")
    ids = set()
    for value in values:
        require(type(value) is dict and value.keys() == INCLUSION_FIELDS, "INCLUSION_SHAPE")
        ident = value["id"]
        require(type(ident) is str and re.fullmatch("[a-z][a-z0-9_-]{0,63}", ident) is not None
                and ident not in ids, "INCLUSION_ID")
        ids.add(ident)
        header_bytes(value["header"])
        decimal(value["header"]["height"], 64, positive=True)
        context(value["confirmation"])


def _gates():
    return {"profile": PROFILE, "producer_signature": "NOT_PERFORMED", "producer_election": "NOT_PERFORMED",
            "account_admission": "NOT_PERFORMED", "changes_execution": "NOT_PERFORMED",
            "network_genesis_spork": "UNSELECTED", "authority_assessment": "UNFILLED",
            "canonicality": "UNFILLED", "finality": "UNFILLED", "recovery_action": "NONE",
            "application": "NO-GO", "core": "NO-GO"}


def inspect_branch(claim, *, chain_id, selected_anchor_claim, required_inclusions):
    """Compare a finite supplied branch to caller claims without accepting it.

    Each required header must occur at its exact supplied confirmation context.
    Header membership does not recompute the account payload or authenticate it.
    Empty/missing coverage remains incomplete; absence is never an outcome.
    """
    result = dict(_gates(), schema="zenon-nom-momentum-result-v1", structure="REFUSED",
                  reason="INVALID_PUBLIC_ENCODING", matched_inclusions=[])
    try:
        decimal(chain_id, 64, positive=True)
        context(selected_anchor_claim)
        _inclusions(required_inclusions)
        require(type(claim) is dict and claim.keys() == CLAIM_FIELDS, "CLAIM_SHAPE")
        require(claim["schema"] == "zenon-nom-momentum-claim-v1" and claim["profile"] == PROFILE
                and claim["core_commit"] == CORE_COMMIT, "CLAIM_PROFILE")
        context(claim["anchor"])
        require(claim["anchor"] == selected_anchor_claim, "ANCHOR_MISMATCH")
        records = claim["momenta"]
        require(type(records) is list and len(records) <= MAX_MOMENTA, "LINEAGE_BOUND")
        previous = selected_anchor_claim
        known = {}
        seen_headers = set()
        for record in records:
            require(type(record) is dict and record.keys() == RECORD_FIELDS, "RECORD_SHAPE")
            fixed_hex(record["hash_hex"], 32)
            fixed_hex(record["public_key_hex"], 32)
            fixed_hex(record["signature_hex"], 64)
            block = record["momentum"]
            computed = momentum_hash(block)
            require(computed == record["hash_hex"], "ADVERTISED_HASH_MISMATCH")
            require(block["chain_id"] == chain_id, "CHAIN_ID_MISMATCH")
            version = decimal(block["version"], 64)
            require(version in (1, 2), "UNSELECTED_VERSION")
            require(block["data_hex"] == "", "SOURCE_DATA_RULE")
            prices = [decimal(block[name], 64) for name in ("next_fusion_price", "next_work_price")]
            require((version == 1 and prices == [0, 0]) or (version == 2 and min(prices) >= 1000),
                    "SOURCE_PRICE_RULE")
            current = context({"hash_hex": record["hash_hex"], "height": block["height"], "timestamp": block["timestamp"]})
            require(int(current["height"]) == int(previous["height"]) + 1
                    and block["previous_hash_hex"] == previous["hash_hex"], "PREVIOUS_CONTEXT")
            require(int(current["timestamp"]) > int(previous["timestamp"]), "TIMESTAMP_ORDER")
            identifiers = set()
            for header in block["content"]:
                decimal(header["height"], 64, positive=True)
                ident = (header["height"], header["hash_hex"])
                require(ident not in identifiers, "DUPLICATE_CONTENT_IDENTIFIER")
                identifiers.add(ident)
                exact = header_bytes(header)
                require(exact not in seen_headers, "REPEATED_BRANCH_HEADER")
                seen_headers.add(exact)
            known[current["height"]] = (current, block["content"])
            previous = current
        missing = []
        for value in required_inclusions:
            expected = value["confirmation"]
            present = known.get(expected["height"])
            if present is None:
                missing.append(value["id"])
                continue
            actual, headers = present
            require(actual == expected, "CONFIRMATION_CONTEXT_MISMATCH")
            if value["header"] not in headers:
                missing.append(value["id"])
        if missing or not records:
            result.update(structure="INCOMPLETE", reason="ABSENCE_IS_NOT_OUTCOME", missing_inclusions=missing)
        else:
            result.update(structure="MATCH", reason="STRUCTURAL_CLAIMS_ONLY",
                          matched_inclusions=[value["id"] for value in required_inclusions])
    except MomentumRefused as error:
        result["reason"] = str(error)
    except (CompatibilityError, KeyError, TypeError, ValueError, OverflowError):
        result["reason"] = "INVALID_PUBLIC_ENCODING"
    return result


def compare_candidates(previous, candidate, *, chain_id, selected_anchor_claim, retained_inclusions):
    """Return a conservative retention/recheck plan, with no state mutation.

    Both branches are claims. Never select a canonical fork, undo possible
    disclosure, restore an older journal, replenish work or choose a replacement.
    This plan provides no durable storage or rollback/clone protection.
    """
    result = dict(_gates(), schema="zenon-nom-reorg-plan-v1", relation="UNKNOWN",
                  accepted_branch="NONE", trusted_reconciliation="UNFILLED", durable_retention="NOT_IMPLEMENTED",
                  retain_previous_evidence=True, retain_candidate_evidence=True, retain_original_bytes=True,
                  retain_possible_disclosure=True, restore_older_journal=False, replenish_work=False,
                  replacement_original_allowed=False, displaced_contexts=[], recheck_inclusions=[])
    old = inspect_branch(previous, chain_id=chain_id, selected_anchor_claim=selected_anchor_claim,
                         required_inclusions=retained_inclusions)
    new = inspect_branch(candidate, chain_id=chain_id, selected_anchor_claim=selected_anchor_claim,
                         required_inclusions=[])
    result.update(previous_structure=old["structure"], candidate_structure=new["structure"])
    if old["structure"] != "MATCH" or new["structure"] != "MATCH":
        return result
    left, right = previous["momenta"], candidate["momenta"]
    shared = 0
    for first, second in zip(left, right):
        if first["hash_hex"] != second["hash_hex"]:
            break
        shared += 1
    if shared == len(left) == len(right):
        relation = "SAME"
    elif shared == len(left):
        relation = "EXTENSION"
    elif shared == len(right):
        relation = "SHORTER_PREFIX"
    else:
        relation = "FORK"
    displaced = [{"hash_hex": record["hash_hex"], "height": record["momentum"]["height"],
                  "timestamp": record["momentum"]["timestamp"]} for record in left[shared:]]
    result.update(relation=relation, shared_momenta=shared, displaced_contexts=displaced,
                  recheck_inclusions=[value["id"] for value in retained_inclusions if value["confirmation"] in displaced])
    return result


def parse_branch_wire(wire, **selection):
    """ASCII JSON is bounded before parsing; duplicate/nonfinite input is refused."""
    require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE_BYTES, "WIRE_BOUND")
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
            require(depth <= MAX_JSON_DEPTH, "JSON_DEPTH_BOUND")
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, "INVALID_JSON")
    def pairs(items):
        values = {}
        for key, value in items:
            require(key not in values, "DUPLICATE_KEY")
            values[key] = value
        return values
    def constant(_):
        raise MomentumRefused("NONFINITE_JSON")
    try:
        claim = json.loads(wire.decode("ascii"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise MomentumRefused("INVALID_JSON") from None
    return inspect_branch(claim, **selection)
