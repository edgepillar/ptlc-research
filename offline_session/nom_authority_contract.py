"""Bounded NoM read framing, with no source authentication or recovery admission.

Every pin, position and restore witness is an independent caller selection.
Their encodings cannot establish provenance, currentness or nonrollback custody.
All-supported replies are forgeable; the result never permits a recovery action.
"""

from dataclasses import dataclass
import hashlib
import json

from . import enrollment_contract as codec, nom_momentum as momentum
from . import nom_recovery as recovery
from .pr138 import CORE_COMMIT, decimal, fixed_hex


NETWORK_SCHEMA = "ptlc-nom-network-selection-v1"
QUERY_SCHEMA = "ptlc-nom-authority-read-query-v1"
CLAIM_SCHEMA = "ptlc-nom-authority-read-claim-v1"
MAX_WIRE_BYTES = 32768
MAX_JSON_DEPTH = 12
MAX_REVISION = 9007199254740991
OBLIGATIONS = ("network_profile", "funding_send", "live_funding_entry",
    "original_authorization", "unlock_send", "contract_receive", "contract_payout",
    "recipient_receipt", "momentum_lineage", "consumer_restore_fence", "source_current_position")
_NETWORK = ("schema", "core_commit", "chain_id", "genesis_hash_hex",
    "binary_digest_hex", "spork_state_digest_hex", "authority_id_hex",
    "authority_profile_digest_hex", "authority_incarnation_hex", "provisioning_root_digest_hex",
    "canonicality_policy_digest_hex", "finality_policy_digest_hex", "freshness_policy_digest_hex",
    "restore_policy_digest_hex")
_CHECKPOINT = ("authority_revision", "momentum", "state_root_hex")
_KNOWLEDGE = ("retention_selection_digest_hex", "retention_head_digest_hex", "retention_sequence",
    "consumer_incarnation_hex", "external_checkpoint_digest_hex", "disclosure_possible")
_QUERY = ("schema", "network_selection", "checkpoint_selection", "consumer_selection",
    "terms", "selected_anchor_claim", "required_inclusions", "candidate_wire_digest_hex",
    "originals_hex", "challenge_hex", "obligations")
_CLAIM = ("schema", "query_digest_hex", "challenge_hex", "availability", "checkpoint", "facts")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError)


class NomAuthorityRefused(ValueError):
    """Sanitized framing refusal; never a verdict on a remote source."""


def _require(condition):
    if not condition:
        raise NomAuthorityRefused("NoM read selection or claim refused")


def _number(value, *, positive=False):
    _require(type(value) is int and int(positive) <= value <= MAX_REVISION)


def _decode(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE_BYTES)
    # Bound nesting before JSON decoding; quoted braces do not add depth.
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


def _digest(domain, wire):
    return hashlib.sha256(domain + b"\0" + wire).hexdigest()


def candidate_digest(wire):
    """Commit to exact raw public claim bytes, not a momentum/account hash."""
    _require(type(wire) is bytes and 0 < len(wire) <= momentum.MAX_WIRE_BYTES)
    return _digest(b"ptlc-nom-authority-candidate-v1", wire)


def _network(value, terms):
    codec._object(value, _NETWORK)
    _require(value["schema"] == NETWORK_SCHEMA and value["core_commit"] == CORE_COMMIT
        and value["chain_id"] == terms["chain_id"] and value["genesis_hash_hex"] == terms["genesis_hash_hex"])
    decimal(value["chain_id"], 64, positive=True)
    for field in _NETWORK[3:]:
        codec._hex(value[field])


def _checkpoint(value):
    codec._object(value, _CHECKPOINT)
    _number(value["authority_revision"])
    momentum.context(value["momentum"])
    codec._hex(value["state_root_hex"])


def _knowledge(value):
    codec._object(value, _KNOWLEDGE)
    for field in _KNOWLEDGE:
        if field.endswith("_hex"):
            codec._hex(value[field])
    _number(value["retention_sequence"], positive=True)
    _require(type(value["disclosure_possible"]) is bool)


def _query_fields(value):
    codec._object(value, _QUERY)
    _require(value["schema"] == QUERY_SCHEMA and type(value["obligations"]) is list
             and value["obligations"] == list(OBLIGATIONS))
    terms = recovery.validate_terms(value["terms"])
    _network(value["network_selection"], terms)
    _checkpoint(value["checkpoint_selection"])
    _knowledge(value["consumer_selection"])
    momentum.context(value["selected_anchor_claim"])
    momentum._inclusions(value["required_inclusions"])
    codec._hex(value["candidate_wire_digest_hex"])
    codec._hex(value["challenge_hex"])
    codec._object(value["originals_hex"], ("long", "short"))
    for leg, encoded in value["originals_hex"].items():
        _require(type(encoded) is str and 0 < len(encoded) <= 2 * recovery.MAX_WIRE)
        original = bytes.fromhex(encoded)
        _require(original.hex() == encoded)
        recovery.claim_signature(terms, leg, original)
    return value


@dataclass(frozen=True, init=False)
class NoMReadQuery:
    """An immutable local comparison selection, not an authenticated request."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use read_query")

    def as_dict(self):
        try:
            _require(type(self) is NoMReadQuery)
            return _query_fields(_decode(self._wire))
        except _ERRORS:
            raise NomAuthorityRefused("invalid selected NoM query") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _digest(b"ptlc-nom-authority-query-v1", self.canonical_bytes)


def read_query(terms, *, network_selection, checkpoint_selection, consumer_selection,
               selected_anchor_claim, required_inclusions, candidate_wire, originals, challenge_hex):
    """Frame independently selected bytes and their required evidence obligations.

    Structural membership is checked separately, and the final candidate context
    must equal the exact selected read position. No profile, account signature,
    execution, state root, currentness or restore authority is authenticated.
    """
    try:
        terms = recovery.validate_terms(terms)
        codec._object(originals, ("long", "short"))
        _require(all(type(wire) is bytes and 0 < len(wire) <= recovery.MAX_WIRE
                     for wire in originals.values()))
        inspection = momentum.parse_branch_wire(candidate_wire, chain_id=terms["chain_id"],
            selected_anchor_claim=selected_anchor_claim, required_inclusions=required_inclusions)
        _require(inspection["structure"] == "MATCH")
        claim = json.loads(candidate_wire.decode("ascii"))
        last = claim["momenta"][-1]
        _checkpoint(checkpoint_selection)
        _require(checkpoint_selection["momentum"] == {"hash_hex": last["hash_hex"],
            "height": last["momentum"]["height"], "timestamp": last["momentum"]["timestamp"]})
        value = _query_fields(dict(schema=QUERY_SCHEMA, network_selection=network_selection,
            checkpoint_selection=checkpoint_selection, consumer_selection=consumer_selection, terms=terms,
            selected_anchor_claim=selected_anchor_claim, required_inclusions=required_inclusions,
            candidate_wire_digest_hex=candidate_digest(candidate_wire),
            originals_hex={leg: wire.hex() for leg, wire in originals.items()},
            challenge_hex=challenge_hex, obligations=list(OBLIGATIONS)))
        wire = codec._canonical(value)
        _decode(wire)
        result = object.__new__(NoMReadQuery)
        object.__setattr__(result, "_wire", wire)
        return result
    except _ERRORS:
        raise NomAuthorityRefused("NoM query preparation refused") from None


def parse_query(expected, wire):
    """Exact replay matches; neither a challenge nor this match permits use."""
    try:
        _require(type(expected) is NoMReadQuery)
        _decode(wire)
        _require(wire == expected.canonical_bytes)
        return expected
    except _ERRORS:
        raise NomAuthorityRefused("NoM query differs from independent selection") from None


def parse_claim(expected, wire):
    """Match unauthenticated source labels without a callback or capability.

    Even an all-supported reply is forgeable and replayable. Evidence digests
    are opaque commitments, not verified openings or source signatures. Missing
    evidence leaves prior originals, disclosure and charged work untouched.
    """
    try:
        _require(type(expected) is NoMReadQuery)
        query = expected.as_dict()
        value = _decode(wire)
        codec._object(value, _CLAIM)
        _require(value["schema"] == CLAIM_SCHEMA and value["query_digest_hex"] == expected.digest_hex
            and value["challenge_hex"] == query["challenge_hex"])
        _require(type(value["availability"]) is str and value["availability"] in ("available", "unavailable"))
        codec._object(value["facts"], OBLIGATIONS)
        statuses = []
        for fact in value["facts"].values():
            codec._object(fact, ("status", "evidence_digest_hex"))
            status = fact["status"]
            _require(type(status) is str and status in ("supported", "contradicted", "unknown"))
            if status == "unknown":
                _require(fact["evidence_digest_hex"] is None)
            else:
                codec._hex(fact["evidence_digest_hex"])
            statuses.append(status)
        if value["availability"] == "unavailable":
            _require(value["checkpoint"] is None and all(status == "unknown" for status in statuses))
            coverage = "UNAVAILABLE_CLAIM"
        else:
            _checkpoint(value["checkpoint"])
            _require(value["checkpoint"] == query["checkpoint_selection"])
            coverage = ("CONTRADICTED_CLAIM" if "contradicted" in statuses else
                        "INCOMPLETE_CLAIM" if "unknown" in statuses else "COMPLETE_CLAIM")
        return {"framing": "MATCHED_UNAUTHENTICATED_CLAIM", "coverage": coverage, "claim": value,
            "source_authentication": "NOT_PERFORMED", "evidence_openings": "NOT_PERFORMED",
            "source_currentness": "UNFILLED", "restore_fence": "UNFILLED", "atomic_entry": "NOT_IMPLEMENTED",
            "retain_prior_evidence": True, "retain_original_bytes": True, "retain_possible_disclosure": True,
            "revalidate_funding_before_recovery": True, "revalidate_live_entry_before_recovery": True,
            "replenish_work": False, "replacement_original_allowed": False,
            "recovery_action": "NONE", "application": "NO-GO", "core": "NO-GO"}
    except _ERRORS:
        raise NomAuthorityRefused("NoM source claim framing refused") from None
