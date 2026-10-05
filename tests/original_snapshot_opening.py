"""Test-only complete synthetic opening; no source, signature, recovery or use.

The caller independently selects a complete query and two diagnostic heads.
This experiment derives an unsigned claim without consuming an incoming claim.
Opening consistency does not authenticate those selections or their currentness.
Complete retained-row disclosure is not a selected application privacy design.
"""

import hashlib
import json
import re

from offline_session import governor_profile as governor
from qualification import original_read_contract as reads


SCHEMA = "ptlc-test-only-original-snapshot-opening-v1"
PURPOSE = "synthetic-complete-retained-opening-only"
MAX_WIRE_BYTES = 262144
MAX_DEPTH = 16
MAX_REVISION = 32
MAX_EVENTS = 256
MAX_RECORDS = 64
POLICY_DOMAIN = b"PTLC/offline-local-policy-read-state/v1\0"
RECORD_DOMAIN = b"PTLC/offline-local-original-record-lineage/v1\0"
MODES = ("live", "unavailable", "ambiguous", "compromise-detected")


class OpeningRefused(ValueError):
    """Sanitized rejected test opening; no state or permission is returned."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def _require(condition):
    if not condition:
        raise OpeningRefused("invalid synthetic snapshot opening")


def _object(value, fields):
    _require(type(value) is dict and len(value) == len(fields) and set(value) == set(fields))


def _number(value, maximum, minimum=0):
    _require(type(value) is int and minimum <= value <= maximum)


def _hex(value, size):
    _require(type(value) is str and len(value) == size*2
        and re.fullmatch(r"[0-9a-f]+", value) is not None)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _integer(value):
    _require(len(value) <= 16)
    number = int(value)
    _number(number, reads.MAX_NUMBER)
    return number


def _not_integer(value):
    raise OpeningRefused("invalid synthetic snapshot number")


def _decode(wire):
    _require(type(wire) is bytes and 1 <= len(wire) <= MAX_WIRE_BYTES)
    value = json.loads(wire.decode("ascii"), object_pairs_hook=_pairs,
        parse_int=_integer, parse_float=_not_integer, parse_constant=_not_integer)
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        _require(depth <= MAX_DEPTH)
        if type(item) is dict:
            pending.extend((child, depth+1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth+1) for child in item)
    _require(canonical(value) == wire)
    return value


def _profile(wire_hex, context):
    _require(type(wire_hex) is str and 2 <= len(wire_hex) <= 2*governor.MAX_PROFILE_BYTES
        and len(wire_hex) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", wire_hex) is not None)
    profile = governor._decode(bytes.fromhex(wire_hex))
    _require(all(profile[field] == context[field]
        for field in ("authority_id_hex", "resource_digest_hex", "role")))
    return profile


def _rows(value, maximum):
    _require(type(value) is list and len(value) <= maximum)


def _history(material, query):
    _object(material, ("root_declaration", "retention_rule", "source", "policies",
        "operations", "effects", "events"))
    declaration = query._root.as_dict()
    _require(canonical(material["root_declaration"]) == canonical(declaration)
        and material["retention_rule"] == reads.RETENTION_RULE)
    source, policies = material["source"], material["policies"]
    _object(source, ("revision", "profile_hex", "active", "mode"))
    revision = source["revision"]
    _number(revision, MAX_REVISION)
    _require(type(source["active"]) is bool and type(source["mode"]) is str
        and source["mode"] in MODES)
    context = declaration["source_context"]
    _require(_profile(source["profile_hex"], context) == declaration["governor_profile"])
    _rows(policies, MAX_REVISION+1)
    _require(len(policies) == revision+1)
    profiles = []
    for index, policy in enumerate(policies):
        _object(policy, ("revision", "profile_hex", "active", "event_sequence"))
        _number(policy["revision"], MAX_REVISION)
        _number(policy["event_sequence"], MAX_EVENTS)
        _require(policy["revision"] == index and type(policy["active"]) is bool)
        profiles.append(_profile(policy["profile_hex"], context))
    _require(policies[0]["active"] is True and policies[0]["event_sequence"] == 0
        and policies[-1]["profile_hex"] == source["profile_hex"]
        and policies[-1]["active"] == source["active"])

    operations, effects, events = (material[key] for key in ("operations", "effects", "events"))
    _rows(operations, MAX_RECORDS)
    _rows(effects, MAX_RECORDS)
    _rows(events, MAX_EVENTS)
    by_id, last_id = {}, ""
    for row in operations:
        _object(row, ("original_operation", "charge_sequence", "effect_sequence"))
        original = reads._original(row["original_operation"])
        operation_id, original_revision = original["operation_id_hex"], original["expected_revision"]
        _number(original_revision, revision)
        _require(operation_id > last_id and original["governor_profile"] == profiles[original_revision])
        _number(row["charge_sequence"], MAX_EVENTS, 1)
        if row["effect_sequence"] is not None:
            _number(row["effect_sequence"], MAX_EVENTS, row["charge_sequence"]+1)
        by_id[operation_id], last_id = row, operation_id
    effect_by_id, last_id = {}, ""
    for row in effects:
        _object(row, ("operation_id_hex", "event_sequence", "payload"))
        operation_id = row["operation_id_hex"]
        _hex(operation_id, 32)
        _number(row["event_sequence"], MAX_EVENTS, 1)
        _require(operation_id > last_id and row["payload"] == "synthetic-effect")
        effect_by_id[operation_id], last_id = row, operation_id

    seen_charge, seen_effect, current, mode = set(), set(), 0, "live"
    for index, event in enumerate(events, 1):
        _object(event, ("event_sequence", "kind", "revision", "operation_id_hex", "detail"))
        _number(event["event_sequence"], MAX_EVENTS, 1)
        _number(event["revision"], MAX_REVISION)
        _require(event["event_sequence"] == index and type(event["kind"]) is str
            and type(event["detail"]) is str)
        kind, rev, operation_id, detail = (event[key] for key in
            ("kind", "revision", "operation_id_hex", "detail"))
        if kind == "policy":
            _require(operation_id is None and detail == "" and rev == current+1
                and rev <= revision and policies[rev]["event_sequence"] == index)
            current = rev
        elif kind == "mode":
            _require(operation_id is None and rev == current and detail in MODES and detail != mode)
            mode = detail
        elif kind in ("charge", "effect"):
            _hex(operation_id, 32)
            _require(operation_id in by_id and detail == "" and rev == current and mode == "live"
                and policies[current]["active"] is True)
            row = by_id[operation_id]
            _require(row["original_operation"]["expected_revision"] == current
                and row["original_operation"]["governor_profile"] == profiles[current])
            if kind == "charge":
                _require(operation_id not in seen_charge and row["charge_sequence"] == index
                    and len(seen_charge) < profiles[current]["max_attempt_limit"])
                seen_charge.add(operation_id)
            else:
                _require(operation_id in seen_charge and operation_id not in seen_effect
                    and row["effect_sequence"] == index)
                seen_effect.add(operation_id)
        else:
            raise OpeningRefused("invalid synthetic snapshot event")
    _require(current == revision and mode == source["mode"] and seen_charge == set(by_id)
        and seen_effect == {key for key, row in by_id.items() if row["effect_sequence"] is not None}
        and set(effect_by_id) == seen_effect)
    for operation_id, row in effect_by_id.items():
        _require(row["event_sequence"] == by_id[operation_id]["effect_sequence"])
    return source, profiles, by_id


def derive_claim(query, opening_wire):
    """Derive absence/pending/completion from untrusted complete synthetic rows.

    No incoming claim or verifier flags supply an expectation. Both independently
    selected heads must open, but they may describe a coherently restored past.
    Non-live modes refuse this full-row experiment; unavailable remains a separate
    null-state grammar statement without any entitlement to disclose history.
    """
    if type(query) is not reads.OriginalReadQuery:
        raise OpeningRefused("an exact independent original query is required")
    try:
        selected = reads.parse_query(query, query.canonical_bytes).as_dict()
        packet = _decode(opening_wire)
        _object(packet, ("schema", "purpose", "record_material"))
        _require(packet["schema"] == SCHEMA and packet["purpose"] == PURPOSE)
        material = packet["record_material"]
        source, profiles, by_id = _history(material, query)
        policy_material = dict(root_declaration=material["root_declaration"],
            revision=source["revision"], profile_hex=source["profile_hex"],
            active=source["active"], mode=source["mode"])
        policy_head = dict(revision=source["revision"], policy_state_digest_hex=
            hashlib.sha256(POLICY_DOMAIN+canonical(policy_material)).hexdigest())
        record_head = dict(retention_rule=reads.RETENTION_RULE, event_sequence=len(material["events"]),
            record_lineage_digest_hex=hashlib.sha256(RECORD_DOMAIN+canonical(material)).hexdigest())
        _require(policy_head == selected["expected_checkpoint"]
            and record_head == selected["expected_record_checkpoint"])
        original = selected["original_operation"]
        _number(original["expected_revision"], source["revision"])
        _require(original["governor_profile"] == profiles[original["expected_revision"]])
        row = by_id.get(original["operation_id_hex"])
        _require(row is None or row["original_operation"] == original)
        _require(source["mode"] == "live")
        observation = "absent" if row is None else "pending" if row["effect_sequence"] is None else "completed"
        claim = dict(schema=reads.CLAIM_SCHEMA, query_digest_hex=query.digest_hex,
            root_declaration_digest_hex=selected["root_declaration_digest_hex"],
            source_context_digest_hex=reads._digest(b"PTLC/observation-policy-source-context/v1\0",
                selected["source_context"]), challenge_hex=selected["challenge_hex"], observation=observation,
            claimed_checkpoint=policy_head, claimed_record_checkpoint=record_head,
            head_policy=dict(governor_profile=query._root.as_dict()["governor_profile"], active=source["active"]),
            original_record=row)
        return reads.parse_claim(query, canonical(claim))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise OpeningRefused("synthetic snapshot opening refused") from None
