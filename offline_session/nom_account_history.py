"""Compare bounded account windows without authenticating or admitting them.

This auxiliary selection binds exact frozen VM evidence bytes. It does not add
an authority fact, normalize a producer's order, establish complete chain history
or supply a recovery capability. Earlier role comparisons remain unchanged.
"""

from dataclasses import dataclass
import hashlib

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_evidence_openings as base, nom_vm_openings as vm, nom_wire as account
from .pr138 import decimal, fixed_hex


QUERY_SCHEMA = "ptlc-nom-account-history-query-v1"
SCHEMA = "ptlc-nom-account-history-claim-v1"
PAYLOAD_SCHEMA = "ptlc-nom-account-history-payload-v1"
MAX_WIRE_BYTES = 512 * 1024
MAX_QUERY_BYTES = 8192
MAX_RECORDS = 64
ACCOUNTS = ("contract", "recipient")
LEGS = ("long", "short")
_QUERY = ("schema", "read_query_digest_hex", "claim_wire_digest_hex",
          "base_wire_digest_hex", "vm_wire_digest_hex", "windows")
_FIELDS = ("schema", "query_digest_hex", "status", "evidence_digest_hex", "payload")
_WINDOW = ("address_hex", "first_height", "last_height", "head_hash_hex", "anchor")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError)


class NoMHistoryRefused(ValueError):
    """Sanitized framing refusal; callers separately retain original evidence."""


def _require(condition):
    if not condition:
        raise NoMHistoryRefused("NoM account history refused")


def _digest(domain, wire):
    return hashlib.sha256(domain + b"\0" + wire).hexdigest()


def vm_digest(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= vm.MAX_WIRE_BYTES)
    return _digest(b"ptlc-nom-account-history-vm-wire-v1", wire)


def _windows(value):
    codec._object(value, LEGS)
    for leg in value.values():
        codec._object(leg, ACCOUNTS)
        for window in leg.values():
            codec._object(window, _WINDOW)
            fixed_hex(window["address_hex"], 20)
            first = decimal(window["first_height"], 64, positive=True)
            last = decimal(window["last_height"], 64, positive=True)
            _require(first <= last and last - first < MAX_RECORDS)
            codec._hex(window["head_hash_hex"])
            anchor = window["anchor"]
            if anchor is not None:
                codec._object(anchor, ("height", "hash_hex"))
                _require(decimal(anchor["height"], 64) == first - 1)
                codec._hex(anchor["hash_hex"])


def _query(value):
    codec._object(value, _QUERY)
    _require(value["schema"] == QUERY_SCHEMA)
    for field in _QUERY[1:5]:
        codec._hex(value[field])
    _windows(value["windows"])
    return value


@dataclass(frozen=True, init=False)
class NoMHistoryQuery:
    """Immutable local byte/window selection; no trusted source identity."""

    _wire: bytes
    _read: authority.NoMReadQuery
    _claim: bytes
    _base: bytes
    _vm: bytes

    def __init__(self):
        raise TypeError("use history_query")

    def as_dict(self):
        try:
            _require(type(self) is NoMHistoryQuery and type(self._read) is authority.NoMReadQuery
                     and type(self._wire) is bytes and 0 < len(self._wire) <= MAX_QUERY_BYTES)
            value = _query(base._decode(self._wire))
            _require(value["read_query_digest_hex"] == self._read.digest_hex
                and value["claim_wire_digest_hex"] == base.claim_digest(self._claim)
                and value["base_wire_digest_hex"] == vm.base_digest(self._base)
                and value["vm_wire_digest_hex"] == vm_digest(self._vm))
            return value
        except _ERRORS:
            raise NoMHistoryRefused("NoM account history selection refused") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _digest(b"ptlc-nom-account-history-query-v1", self.canonical_bytes)


def history_query(expected, claim_wire, base_wire, vm_wire, windows):
    """Select independent bounded windows after checking frozen reply framing.

    These are additional diagnostic selections, not new source obligations or a
    repair of previously selected frontiers. Bytes are copied only in memory.
    """
    try:
        vm.inspect_vm_openings(expected, claim_wire, base_wire, vm_wire)
        value = _query(dict(schema=QUERY_SCHEMA, read_query_digest_hex=expected.digest_hex,
            claim_wire_digest_hex=base.claim_digest(claim_wire), base_wire_digest_hex=vm.base_digest(base_wire),
            vm_wire_digest_hex=vm_digest(vm_wire), windows=windows))
        wire = codec._canonical(value)
        _require(len(wire) <= MAX_QUERY_BYTES)
        base._decode(wire)
        result = object.__new__(NoMHistoryQuery)
        for name, item in (("_wire", wire), ("_read", expected), ("_claim", claim_wire),
                           ("_base", base_wire), ("_vm", vm_wire)):
            object.__setattr__(result, name, item)
        return result
    except _ERRORS:
        raise NoMHistoryRefused("NoM account history selection refused") from None


def _payload(value):
    codec._object(value, LEGS)
    for leg in value.values():
        codec._object(leg, ACCOUNTS)
        for records in leg.values():
            if records is not None:
                _require(type(records) is list and len(records) <= MAX_RECORDS)
                for record in records:
                    vm._record(record)
    _require(len(codec._canonical(value)) <= MAX_WIRE_BYTES)


def history_digest(expected, status, payload):
    """Commit to typed claims and exact selections, including contradictory ones."""
    try:
        _require(type(expected) is NoMHistoryQuery and type(status) is str
                 and status in ("supported", "contradicted"))
        _payload(payload)
        wire = codec._canonical(dict(schema=PAYLOAD_SCHEMA, query_digest_hex=expected.digest_hex,
                                     status=status, payload=payload))
        _require(len(wire) <= MAX_WIRE_BYTES)
        base._decode(wire)
        return _digest(b"ptlc-nom-account-history-payload-v1", wire)
    except _ERRORS:
        raise NoMHistoryRefused("NoM account history commitment refused") from None


def _match(value):
    return "MATCH" if value else "DIFFERS_FROM_SELECTION"


def _required(records, required):
    hashes = [account.account_block_hash(record["block"]) for record in records]
    return {name: ("ROLE_UNSELECTED" if record is None else _match(
        account.account_block_hash(record["block"]) in hashes)) for name, record in required.items()}


def _children(records):
    comparisons, assigned = [], set()
    for index, record in enumerate(records):
        parent = record["block"]
        if parent["block_type"] != "5":
            continue
        children = parent["descendant_hashes_hex"]
        count = len(children)
        positions = list(range(index - count, index)) if count <= index else []
        preceding = [records[position]["block"] for position in positions]
        match = (count <= index and children == [account.account_block_hash(block) for block in preceding]
            and all(block["block_type"] == "4" and block["address_hex"] == parent["address_hex"]
                    and vm._ack(parent, block, equal=True) for block in preceding))
        comparisons.append({"receive_index": index, "child_count": count,
            "preceding_children": "CHILDREN_OUTSIDE_SELECTED_WINDOW" if count > index else _match(match)})
        if match:
            assigned.update(positions)
    return {"receives": comparisons, "unassigned_send_indices": [index for index, record in enumerate(records)
        if record["block"]["block_type"] == "4" and index not in assigned], "vm_execution": "NOT_PERFORMED"}


def _window(window, records, required, terms, role, candidate):
    if records is None:
        return {"opening": "MISSING_WINDOW_CLAIM"}
    blocks = [record["block"] for record in records]
    hashes = [account.account_block_hash(block) for block in blocks]
    heights = [int(block["height"]) for block in blocks]
    first, last = int(window["first_height"]), int(window["last_height"])
    expected = list(range(first, last + 1))
    counts = {height: heights.count(height) for height in set(heights)}
    repeated = {}
    for index, block in enumerate(blocks):
        if block["block_type"] in ("3", "5"):
            repeated.setdefault(block["from_block_hash_hex"], []).append(index)
    duplicates = [{"from_block_hash_hex": key, "indices": indices, "comparison": "REPEATED_CLAIM"}
                  for key, indices in sorted(repeated.items()) if len(indices) > 1]
    anchor = window["anchor"]
    profile = all(block["version"] == "1" and block["chain_id"] == terms["chain_id"]
        and block["address_hex"] == window["address_hex"] and int(block["height"]) > 0
        and int(block["momentum_height"]) > 0 and block["momentum_hash_hex"] != vm.ZERO_HASH
        and block["block_type"] in (("4", "5") if role == "contract" else ("3",)) for block in blocks)
    result = {"opening": "BOUND_UNAUTHENTICATED_HISTORY", "record_count": len(records),
        "selected_height_coverage": _match(heights == expected),
        "missing_heights": [str(height) for height in expected if height not in counts],
        "outside_window_indices": [index for index, height in enumerate(heights) if not first <= height <= last],
        "duplicate_heights": [str(height) for height in sorted(counts) if counts[height] > 1],
        "ordered_previous_links": _match(all(heights[i] == heights[i - 1] + 1
            and blocks[i]["previous_hash_hex"] == hashes[i - 1] for i in range(1, len(blocks)))),
        "ordered_acknowledgements": _match(all(vm._ack(blocks[i], blocks[i - 1]) for i in range(1, len(blocks)))),
        "selected_head": _match(bool(blocks) and heights[-1] == last and hashes[-1] == window["head_hash_hex"]),
        "prior_anchor": "PRIOR_FRONTIER_UNSELECTED" if anchor is None else _match(bool(blocks)
            and heights[0] == first and blocks[0]["previous_hash_hex"] == anchor["hash_hex"]),
        "selected_account_profile": _match(bool(blocks) and profile), "required_roles": _required(records, required),
        "headers": [vm._header(record, candidate) for record in records], "repeated_receive_claims": duplicates,
        "whole_chain_coverage": "NOT_ESTABLISHED", "received_marker_proof": "ABSENT",
        "duplicate_receive_admission": "NOT_PERFORMED"}
    if role == "contract":
        result["descendant_placement"] = _children(records)
    return result


def inspect_history(expected, wire):
    """Compare raw producer order; even a complete selected interval grants no use."""
    try:
        _require(type(expected) is NoMHistoryQuery and type(wire) is bytes and 0 < len(wire) <= MAX_WIRE_BYTES)
        query = expected.as_dict()
        old = vm.inspect_vm_openings(expected._read, expected._claim, expected._base, expected._vm)
        value = base._decode(wire)
        codec._object(value, _FIELDS)
        _require(value["schema"] == SCHEMA and value["query_digest_hex"] == expected.digest_hex)
        status, payload = value["status"], value["payload"]
        _require(type(status) is str and status in ("supported", "contradicted", "unknown"))
        if status == "unknown":
            _require(payload is None and value["evidence_digest_hex"] is None)
        else:
            codec._hex(value["evidence_digest_hex"])
            if payload is not None:
                _require(history_digest(expected, status, payload) == value["evidence_digest_hex"])
        result = {key: item for key, item in old.items() if key not in ("framing", "legs", "opening_bundle", "comparisons")}
        result.update(framing="BOUND_AUXILIARY_ACCOUNT_HISTORY_ONLY", vm_opening_result=old,
            history_claim=value, auxiliary_authority_fact="NONE", history_currentness="UNFILLED",
            aggregate_work_budget="UNSELECTED", history_legs={})
        if payload is None:
            result["history_opening"] = "UNKNOWN_CLAIM" if status == "unknown" else "MISSING_HISTORY_CLAIM"
            return result
        opened = old["opening_bundle"]["openings"]
        read = expected._read.as_dict()
        candidate_payload = old["base_opening_result"]["opening_bundle"]["openings"]["momentum_lineage"]
        candidate = base._candidate(read, candidate_payload) if candidate_payload is not None else None
        for leg in LEGS:
            parents = opened["contract_receive"]
            required_contract = {name: None if parents is None else parents["records"][leg][name]
                                 for name in ("funding_receive", "receive")}
            required_contract["payout"] = None if opened["contract_payout"] is None else opened["contract_payout"]["records"][leg]
            receipt = None if opened["recipient_receipt"] is None else opened["recipient_receipt"]["records"][leg]
            reports = {role: _window(query["windows"][leg][role], payload[leg][role],
                required_contract if role == "contract" else {"receipt": receipt}, read["terms"], role, candidate)
                       for role in ACCOUNTS}
            send = None if opened["unlock_send"] is None else opened["unlock_send"]["records"][leg]
            recipient = query["windows"][leg]["recipient"]
            reports["selected_unlock_frontier"] = ("ROLE_UNSELECTED" if send is None else
                "DIFFERENT_ACCOUNT_SELECTION" if send["block"]["address_hex"] != recipient["address_hex"] else
                "OUTSIDE_SELECTED_WINDOW" if not int(recipient["first_height"]) <= int(send["block"]["height"]) <= int(recipient["last_height"]) else
                _required(payload[leg]["recipient"] or [], {"unlock_send": send})["unlock_send"])
            result["history_legs"][leg] = reports
        result["history_opening"] = "BOUND_UNAUTHENTICATED_PAYLOAD"
        return result
    except _ERRORS:
        raise NoMHistoryRefused("NoM account history refused") from None
