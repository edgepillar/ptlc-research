"""Pure retention of selected uncertainty, never recovery admission.

This immutable in-memory comparison has no journal, verifier callback, worker,
clock or source connection. Caller-selected history is not authenticated custody.
Neither a zero-pop refusal nor a typed partial rollback releases the hold.
"""

from dataclasses import dataclass
import hashlib

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_recovery as recovery


PROFILE = "ptlc-nom-uncertainty-hold-v1"
REFUSAL_SCHEMA = "ptlc-nom-selected-refusal-claim-v1"
CASES = ("before-first-pop", "after-one-actual-pop")
MAX_WIRE_BYTES = 128 * 1024
MAX_EVIDENCE = 8
MAX_PRIOR_BYTES = 512
MAX_CLAIMS = 8
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError)
_SELECTION = ("schema", "query_hex", "charged_work", "prior_evidence_hex", "disclosure_possible")
_STATE = ("selection_hex", "refusal_wires_hex", "source_claim_wires_hex")
_WORK = ("attempt_id_hex", "original_leg", "original_digest_hex", "outcome")
_REFUSAL = ("schema", "core_commit", "case_id", "record_digest_hex", "failure")


class NoMUncertaintyRefused(ValueError):
    """Sanitized comparison refusal; no failed input supplies permission."""


def _require(condition):
    if not condition:
        raise NoMUncertaintyRefused("selected NoM uncertainty comparison refused")


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
            _require(depth <= 12)
        elif byte in (93, 125):
            depth -= 1
            _require(depth >= 0)
    _require(depth == 0 and not quoted)
    return codec._decode(wire, MAX_WIRE_BYTES)


def _bytes(encoded, maximum):
    _require(type(encoded) is str and 0 < len(encoded) <= 2 * maximum)
    result = bytes.fromhex(encoded)
    _require(result.hex() == encoded)
    return result


def original_digest(wire):
    """Bind exact synthetic original bytes; this is not an account-block hash."""
    _require(type(wire) is bytes and 0 < len(wire) <= recovery.MAX_WIRE)
    return hashlib.sha256(b"ptlc-nom-held-original-v1\0" + wire).hexdigest()


def _query(wire):
    # Revalidate the frozen query encoding; do not turn it into a capability.
    result = object.__new__(authority.NoMReadQuery)
    object.__setattr__(result, "_wire", wire)
    result.as_dict()
    _require(result.canonical_bytes == wire)
    return result


def _selection(value):
    codec._object(value, _SELECTION)
    _require(value["schema"] == PROFILE)
    query = _query(_bytes(value["query_hex"], authority.MAX_WIRE_BYTES)).as_dict()
    _require(type(value["disclosure_possible"]) is bool
        and (not query["consumer_selection"]["disclosure_possible"] or value["disclosure_possible"]))
    work = value["charged_work"]
    _require(type(work) is list and len(work) <= recovery.MAX_RECOVERIES)
    identifiers = set()
    for row in work:
        codec._object(row, _WORK)
        codec._hex(row["attempt_id_hex"])
        _require(row["attempt_id_hex"] not in identifiers)
        identifiers.add(row["attempt_id_hex"])
        leg = row["original_leg"]
        _require(type(leg) is str and leg in ("long", "short"))
        _require(row["original_digest_hex"] == original_digest(bytes.fromhex(query["originals_hex"][leg])))
        _require(type(row["outcome"]) is str and row["outcome"] in ("UNKNOWN", "COMPLETE", "FAILED"))
    evidence = value["prior_evidence_hex"]
    _require(type(evidence) is list and len(evidence) <= MAX_EVIDENCE)
    for encoded in evidence:
        _bytes(encoded, MAX_PRIOR_BYTES)
    _require(len(set(evidence)) == len(evidence))
    return value


def _refusal(wire):
    value = authority._decode(wire)
    codec._object(value, _REFUSAL)
    _require(value["schema"] == REFUSAL_SCHEMA and value["core_commit"] == authority.CORE_COMMIT
        and type(value["case_id"]) is str and value["case_id"] in CASES)
    codec._hex(value["record_digest_hex"])
    # Deliberately opaque source labels. The separate corpus qualifier checks
    # the complete native record; even forged labels cannot release this hold.
    _require(type(value["failure"]) is dict and 0 < len(codec._canonical(value["failure"])) <= 4096)
    return value


def _state(value):
    codec._object(value, _STATE)
    selection = _selection(_decode(_bytes(value["selection_hex"], MAX_WIRE_BYTES)))
    query = _query(bytes.fromhex(selection["query_hex"]))
    for field, parse in (("refusal_wires_hex", _refusal),
                         ("source_claim_wires_hex", lambda wire: authority.parse_claim(query, wire))):
        rows = value[field]
        _require(type(rows) is list and len(rows) <= MAX_CLAIMS and len(set(rows)) == len(rows))
        for encoded in rows:
            parse(_bytes(encoded, authority.MAX_WIRE_BYTES))
    return value


@dataclass(frozen=True, init=False)
class NoMUncertaintyHold:
    """A local immutable selection; copies do not provide a restore fence."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use select_hold")

    def as_dict(self):
        try:
            _require(type(self) is NoMUncertaintyHold)
            return _state(_decode(self._wire))
        except _ERRORS:
            raise NoMUncertaintyRefused("invalid selected NoM hold") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    def review(self):
        """No result is accepted by the reference journal's trusted observer."""
        state = self.as_dict()
        selected = _selection(_decode(bytes.fromhex(state["selection_hex"])))
        return {"profile": PROFILE, "state": "HOLD", "charged_work": len(selected["charged_work"]),
            "disclosure_possible": selected["disclosure_possible"],
            "retained_prior_evidence": len(selected["prior_evidence_hex"]),
            "retained_refusal_claims": len(state["refusal_wires_hex"]),
            "retained_source_claims": len(state["source_claim_wires_hex"]),
            "source_authentication": "NOT_PERFORMED", "source_currentness": "UNFILLED",
            "restore_fence": "UNFILLED", "durable_retention": "NOT_IMPLEMENTED",
            "journal_composition": "NOT_PERFORMED", "signature_mathematics": "NOT_PERFORMED",
            "native_query_context_pairing": "NOT_COMPOSED",
            "replacement_original_allowed": False, "replenish_work": False,
            "automatic_retry": False, "recovery_action": "NONE", "application": "NO-GO", "core": "NO-GO"}


def _freeze(value):
    wire = codec._canonical(value)
    _state(_decode(wire))
    result = object.__new__(NoMUncertaintyHold)
    object.__setattr__(result, "_wire", wire)
    return result


def select_hold(query, *, charged_work, prior_evidence):
    """Select prior charges and evidence without authenticating their history."""
    try:
        _require(type(query) is authority.NoMReadQuery and type(prior_evidence) is list
            and all(type(wire) is bytes for wire in prior_evidence))
        selection = _selection(dict(schema=PROFILE, query_hex=query.canonical_bytes.hex(),
            charged_work=charged_work, prior_evidence_hex=[wire.hex() for wire in prior_evidence],
            disclosure_possible=query.as_dict()["consumer_selection"]["disclosure_possible"]))
        return _freeze(dict(selection_hex=codec._canonical(selection).hex(),
            refusal_wires_hex=[], source_claim_wires_hex=[]))
    except _ERRORS:
        raise NoMUncertaintyRefused("NoM hold selection refused") from None


def retain_claim(hold, wire, *, kind):
    """Keep exact framed bytes; complete claims and exact replays give no release."""
    try:
        _require(type(hold) is NoMUncertaintyHold and type(wire) is bytes
            and type(kind) is str and kind in ("refusal", "source"))
        state = hold.as_dict()
        field = "refusal_wires_hex" if kind == "refusal" else "source_claim_wires_hex"
        if wire.hex() in state[field]:
            return hold
        state[field].append(wire.hex())
        return _freeze(state)
    except _ERRORS:
        raise NoMUncertaintyRefused("NoM held claim refused") from None


def compare_hold(expected, wire):
    """Exact local replay only; an older independently selected copy still matches."""
    try:
        _require(type(expected) is NoMUncertaintyHold)
        _state(_decode(wire))
        _require(wire == expected.canonical_bytes)
        return expected
    except _ERRORS:
        raise NoMUncertaintyRefused("NoM hold differs from retained selection") from None
