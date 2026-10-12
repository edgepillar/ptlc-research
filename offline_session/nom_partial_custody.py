"""Pure comparison of incomplete original custody, never recovery admission.

Missing bytes stay missing. This separate caller-selected encoding cannot fill
the complete authority query, authenticate history or operate a recovery journal.
Public signature encodings are structural inputs; verification is a separate gate.
"""

from dataclasses import dataclass
import hashlib

from . import enrollment_contract as codec, nom_recovery as recovery
from . import nom_uncertainty as uncertainty
from .pr138 import fixed_hex


PROFILE = "ptlc-nom-partial-custody-v1"
CLAIM_SCHEMA = "ptlc-nom-partial-custody-claim-v1"
MISSING = "NOT_RETAINED_OR_NOT_CREATED"
MAX_CLAIMS = 8
MAX_WIRE_BYTES = uncertainty.MAX_WIRE_BYTES
_SELECTION = ("schema", "terms", "pair", "verification_context_digest_hex",
    "remote_short_hex", "recovered_long_signature_hex", "original_long_hex",
    "charged_work", "prior_evidence_hex", "disclosure_possible", "challenge_hex")
_STATE = ("selection_hex", "refusal_wires_hex", "source_claim_wires_hex")
_CLAIM = ("schema", "selection_digest_hex", "challenge_hex", "availability", "status", "evidence_digest_hex")
_WORK = ("attempt_id_hex", "short_original_digest_hex", "outcome")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError)


class PartialCustodyRefused(ValueError):
    """Sanitized local framing refusal; never a verdict on chain state."""


def _require(condition):
    if not condition:
        raise PartialCustodyRefused("selected partial NoM custody refused")


def short_digest(wire):
    """Bind exact public synthetic short bytes, not an account-block hash."""
    _require(type(wire) is bytes and 0 < len(wire) <= recovery.MAX_WIRE)
    return hashlib.sha256(b"ptlc-nom-partial-short-v1\0" + wire).hexdigest()


def _selection(value):
    codec._object(value, _SELECTION)
    _require(value["schema"] == PROFILE and value["disclosure_possible"] is True)
    terms, pair = recovery.validate_terms(value["terms"]), recovery.validate_pair(value["pair"])
    _require(value["verification_context_digest_hex"] == recovery.verification_context_digest(terms, pair))
    codec._hex(value["challenge_hex"])
    short = uncertainty._bytes(value["remote_short_hex"], recovery.MAX_WIRE)
    recovery.claim_signature(terms, "short", short)
    work = value["charged_work"]
    _require(type(work) is list and 1 <= len(work) <= recovery.MAX_RECOVERIES)
    identifiers = set()
    for row in work:
        codec._object(row, _WORK)
        codec._hex(row["attempt_id_hex"])
        _require(row["attempt_id_hex"] not in identifiers)
        identifiers.add(row["attempt_id_hex"])
        _require(row["short_original_digest_hex"] == short_digest(short)
            and type(row["outcome"]) is str and row["outcome"] in ("UNKNOWN", "COMPLETE", "FAILED"))
    result, original = value["recovered_long_signature_hex"], value["original_long_hex"]
    if result is not None:
        fixed_hex(result, 64)
    if original is not None:
        _require(result is not None)
        wire = uncertainty._bytes(original, recovery.MAX_WIRE)
        _require(recovery.claim_signature(terms, "long", wire) == result)
    evidence = value["prior_evidence_hex"]
    _require(type(evidence) is list and len(evidence) <= uncertainty.MAX_EVIDENCE)
    for encoded in evidence:
        uncertainty._bytes(encoded, uncertainty.MAX_PRIOR_BYTES)
    _require(len(set(evidence)) == len(evidence))
    return value


def _selection_digest(selection):
    return hashlib.sha256(b"ptlc-nom-partial-selection-v1\0" + codec._canonical(selection)).hexdigest()


def _claim(wire, selection):
    value = uncertainty._decode(wire)
    codec._object(value, _CLAIM)
    _require(value["schema"] == CLAIM_SCHEMA
        and value["selection_digest_hex"] == _selection_digest(selection)
        and value["challenge_hex"] == selection["challenge_hex"])
    _require(type(value["availability"]) is str and value["availability"] in ("available", "unavailable")
        and type(value["status"]) is str and value["status"] in ("unknown", "supported", "contradicted"))
    if value["status"] == "unknown":
        _require(value["evidence_digest_hex"] is None)
    else:
        codec._hex(value["evidence_digest_hex"])
    _require(value["availability"] != "unavailable" or value["status"] == "unknown")
    return value


def _state(value):
    codec._object(value, _STATE)
    selection = _selection(uncertainty._decode(uncertainty._bytes(value["selection_hex"], MAX_WIRE_BYTES)))
    for field in ("refusal_wires_hex", "source_claim_wires_hex"):
        rows = value[field]
        _require(type(rows) is list and len(rows) <= MAX_CLAIMS)
        _require(all(type(encoded) is str for encoded in rows) and len(set(rows)) == len(rows))
        for encoded in rows:
            wire = uncertainty._bytes(encoded, MAX_WIRE_BYTES)
            if field == "refusal_wires_hex":
                uncertainty._refusal(wire)
            else:
                _claim(wire, selection)
    return value


@dataclass(frozen=True, init=False)
class PartialCustodyHold:
    """An immutable local comparison, without custody authority or a restore fence."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use select_partial_hold")

    def as_dict(self):
        try:
            _require(type(self) is PartialCustodyHold)
            return _state(uncertainty._decode(self._wire))
        except _ERRORS:
            raise PartialCustodyRefused("invalid selected partial NoM custody") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    def selection(self):
        return _selection(uncertainty._decode(bytes.fromhex(self.as_dict()["selection_hex"])))

    @property
    def selection_digest_hex(self):
        return _selection_digest(self.selection())

    def review(self):
        state, selected = self.as_dict(), self.selection()
        return {"profile": PROFILE, "state": "HOLD", "recovery_action": "NONE",
            "short_original_custody": "EXACT_SELECTED_BYTES",
            "long_result_custody": MISSING if selected["recovered_long_signature_hex"] is None else "PUBLIC_RESULT_RETAINED",
            "long_original_custody": MISSING if selected["original_long_hex"] is None else "EXACT_SELECTED_BYTES",
            "charged_work": len(selected["charged_work"]), "disclosure_possible": True,
            "retained_prior_evidence": len(selected["prior_evidence_hex"]),
            "retained_refusal_claims": len(state["refusal_wires_hex"]),
            "retained_source_claims": len(state["source_claim_wires_hex"]),
            "worker_execution_from_absence": "NOT_ESTABLISHED", "absent_original_reconstruction": "FORBIDDEN",
            "signature_mathematics": "NOT_PERFORMED", "source_authentication": "NOT_PERFORMED",
            "source_currentness": "UNFILLED", "restore_fence": "UNFILLED",
            "durable_retention": "NOT_IMPLEMENTED", "journal_composition": "NOT_PERFORMED",
            "native_query_context_pairing": "NOT_COMPOSED", "complete_query_conversion": "NOT_PROVIDED",
            "replacement_original_allowed": False, "replenish_work": False, "automatic_retry": False,
            "application": "NO-GO", "core": "NO-GO"}


def _freeze(value):
    wire = codec._canonical(value)
    _state(uncertainty._decode(wire))
    result = object.__new__(PartialCustodyHold)
    object.__setattr__(result, "_wire", wire)
    return result


def select_partial_hold(terms, pair, remote_short, *, charged_work, prior_evidence,
                        recovered_long_signature=None, original_long=None, challenge_hex):
    """Bind exactly known public bytes; neither absent output is filled or inferred."""
    try:
        _require(type(remote_short) is bytes and (original_long is None or type(original_long) is bytes)
            and type(prior_evidence) is list and all(type(wire) is bytes for wire in prior_evidence))
        selection = _selection(dict(schema=PROFILE, terms=terms, pair=pair,
            verification_context_digest_hex=recovery.verification_context_digest(terms, pair),
            remote_short_hex=remote_short.hex(), recovered_long_signature_hex=recovered_long_signature,
            original_long_hex=None if original_long is None else original_long.hex(),
            charged_work=charged_work, prior_evidence_hex=[wire.hex() for wire in prior_evidence],
            disclosure_possible=True, challenge_hex=challenge_hex))
        return _freeze(dict(selection_hex=codec._canonical(selection).hex(),
            refusal_wires_hex=[], source_claim_wires_hex=[]))
    except _ERRORS:
        raise PartialCustodyRefused("partial NoM custody selection refused") from None


def retain_claim(hold, wire, *, kind):
    """Preserve exact raw labels; supported and unavailable claims supply no bytes."""
    try:
        _require(type(hold) is PartialCustodyHold and type(wire) is bytes
            and type(kind) is str and kind in ("refusal", "source"))
        state = hold.as_dict()
        field = "refusal_wires_hex" if kind == "refusal" else "source_claim_wires_hex"
        if wire.hex() in state[field]:
            return hold
        state[field].append(wire.hex())
        return _freeze(state)
    except _ERRORS:
        raise PartialCustodyRefused("partial NoM custody claim refused") from None


def compare_hold(expected, wire):
    """Exact local replay only; coherent old copies still lack an external fence."""
    try:
        _require(type(expected) is PartialCustodyHold)
        _state(uncertainty._decode(wire))
        _require(wire == expected.canonical_bytes)
        return expected
    except _ERRORS:
        raise PartialCustodyRefused("partial NoM custody differs from retained selection") from None
