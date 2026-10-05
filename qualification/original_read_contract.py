"""Exact original-operation read framing, never a receipt or current truth.

Source/root/checkpoint/retention selection is an independent external premise.
These unsigned claims are forgeable. No signer, verifier, store, service, clock,
network, allocation, recovery adapter or protected-use gate is connected.
"""

from dataclasses import dataclass
import hashlib

from offline_session import current_authority_contract as current
from offline_session import enrollment_contract as enrollment
from offline_session import governor_profile as governor
from offline_session.enrollment_authentication import _canonical, _hex, _object
from qualification import source_root_roles as roots


ORIGINAL_SCHEMA = "ptlc-observation-original-operation-v1"
QUERY_SCHEMA = "ptlc-observation-original-read-query-v1"
CLAIM_SCHEMA = "ptlc-observation-original-read-claim-v1"
READ_RULE = "same-incarnation-original-lookup-v1"
RETENTION_RULE = "retained-all-originals-in-incarnation-v1"
QUERY_DOMAIN = b"PTLC/observation-original-read-query/v1\0"
CLAIM_DOMAIN = b"PTLC/observation-original-read-claim/v1\0"
MAX_WIRE_BYTES = 16384
MAX_NUMBER = (1 << 53)-1
OBSERVATIONS = ("absent", "pending", "completed", "unavailable")
_ORIGINAL_FIELDS = ("schema", "operation_id_hex", "expected_revision",
    "governor_profile", "proposal_digest_hex")
_RECORD_HEAD_FIELDS = ("retention_rule", "event_sequence", "record_lineage_digest_hex")
_QUERY_FIELDS = ("schema", "operation", "read_rule", "root_declaration_digest_hex",
    "source_context", "expected_checkpoint", "expected_record_checkpoint",
    "challenge_hex", "original_operation")
_CLAIM_FIELDS = ("schema", "query_digest_hex", "root_declaration_digest_hex",
    "source_context_digest_hex", "challenge_hex", "observation", "claimed_checkpoint",
    "claimed_record_checkpoint", "head_policy", "original_record")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError)


class OriginalReadError(ValueError):
    """Sanitized malformed selection or inconsistent unsigned read claim."""


def _number(value, minimum=0):
    if type(value) is not int or not minimum <= value <= MAX_NUMBER:
        raise OriginalReadError("invalid bounded original read number")


def _decode(wire):
    try:
        return enrollment._decode(wire, MAX_WIRE_BYTES)
    except _ERRORS:
        raise OriginalReadError("invalid canonical original read wire") from None


def _digest(domain, value):
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _original(value):
    _object(value, _ORIGINAL_FIELDS)
    if type(value["schema"]) is not str or value["schema"] != ORIGINAL_SCHEMA:
        raise OriginalReadError("unsupported original operation")
    _hex(value["operation_id_hex"], 32)
    _hex(value["proposal_digest_hex"], 32)
    _number(value["expected_revision"])
    governor._fields(value["governor_profile"])
    return value


def _record_head(value):
    _object(value, _RECORD_HEAD_FIELDS)
    if type(value["retention_rule"]) is not str or value["retention_rule"] != RETENTION_RULE:
        raise OriginalReadError("unsupported selected record retention rule")
    _number(value["event_sequence"])
    _hex(value["record_lineage_digest_hex"], 32)
    return value


@dataclass(frozen=True, init=False)
class OriginalOperation:
    """Independent complete original selection; no registration or ownership."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use original_operation")

    def as_dict(self):
        if type(self) is not OriginalOperation:
            raise OriginalReadError("an exact original operation is required")
        try:
            return _original(_decode(self._wire))
        except _ERRORS:
            raise OriginalReadError("invalid selected original operation") from None

    @property
    def canonical_bytes(self):
        return _canonical(self.as_dict())


def original_operation(*, operation_id_hex, expected_revision, profile_wire, proposal_digest_hex):
    """Select all four original bindings; a digest alone cannot select a profile."""
    try:
        value = _original(dict(schema=ORIGINAL_SCHEMA, operation_id_hex=operation_id_hex,
            expected_revision=expected_revision, governor_profile=governor._decode(profile_wire),
            proposal_digest_hex=proposal_digest_hex))
        result = object.__new__(OriginalOperation)
        object.__setattr__(result, "_wire", _canonical(value))
        return result
    except _ERRORS:
        raise OriginalReadError("original operation selection rejected") from None


@dataclass(frozen=True)
class RecordCheckpoint:
    """Selected retention position; no proof of complete or nonrollback history."""

    event_sequence: int
    record_lineage_digest_hex: str

    def __post_init__(self):
        self.as_dict()

    def as_dict(self):
        if type(self) is not RecordCheckpoint:
            raise OriginalReadError("an exact selected record checkpoint is required")
        try:
            return _record_head(dict(retention_rule=RETENTION_RULE, event_sequence=self.event_sequence,
                record_lineage_digest_hex=self.record_lineage_digest_hex))
        except _ERRORS:
            raise OriginalReadError("invalid selected record checkpoint") from None


def _selection(root, original, checkpoint, record_checkpoint, challenge):
    # Reject subclass hooks before touching any selected object.
    if (type(root) is not roots.RootDeclaration or type(original) is not OriginalOperation
            or type(checkpoint) is not current.PolicyCheckpoint
            or type(record_checkpoint) is not RecordCheckpoint):
        raise OriginalReadError("exact independent original read selections required")
    declaration, operation, head = root.as_dict(), original.as_dict(), checkpoint.as_dict()
    source, profile = declaration["source_context"], operation["governor_profile"]
    if any(source[field] != profile[field] for field in ("authority_id_hex", "resource_digest_hex", "role")):
        raise OriginalReadError("original operation changes its retained namespace")
    if operation["expected_revision"] > head["revision"]:
        raise OriginalReadError("original revision exceeds the selected policy position")
    if (operation["expected_revision"] == head["revision"]
            and profile != declaration["governor_profile"]):
        raise OriginalReadError("same revision changes its complete selected profile")
    _hex(challenge, 32)
    return dict(schema=QUERY_SCHEMA, operation="read-original-at-checkpoint", read_rule=READ_RULE,
        root_declaration_digest_hex=root.message_digest_hex, source_context=source,
        expected_checkpoint=head, expected_record_checkpoint=record_checkpoint.as_dict(),
        challenge_hex=challenge, original_operation=operation)


@dataclass(frozen=True, init=False)
class OriginalReadQuery:
    """Replayable independently selected lookup; no read authority or admission."""

    _root: roots.RootDeclaration
    _original: OriginalOperation
    _checkpoint: current.PolicyCheckpoint
    _record_checkpoint: RecordCheckpoint
    _challenge: str
    _wire: bytes

    def __init__(self):
        raise TypeError("use original_read_query")

    def as_dict(self):
        if type(self) is not OriginalReadQuery:
            raise OriginalReadError("an exact selected original read query is required")
        try:
            value = _decode(self._wire)
            _object(value, _QUERY_FIELDS)
            selected = _selection(self._root, self._original, self._checkpoint,
                self._record_checkpoint, self._challenge)
            if _canonical(value) != _canonical(selected):
                raise OriginalReadError("original query changes its complete independent selection")
            return value
        except _ERRORS:
            raise OriginalReadError("invalid selected original read query") from None

    @property
    def canonical_bytes(self):
        return _canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _digest(QUERY_DOMAIN, self.as_dict())


def original_read_query(root, original, *, checkpoint, record_checkpoint, challenge_hex):
    """Prepare before peer bytes; no governor admission packet is reinterpreted."""
    try:
        value = _selection(root, original, checkpoint, record_checkpoint, challenge_hex)
        wire = _canonical(value)
        if len(wire) > MAX_WIRE_BYTES:
            raise OriginalReadError("original read query exceeds its byte bound")
        result = object.__new__(OriginalReadQuery)
        for field, item in (("_root", root), ("_original", original), ("_checkpoint", checkpoint),
                            ("_record_checkpoint", record_checkpoint), ("_challenge", challenge_hex), ("_wire", wire)):
            object.__setattr__(result, field, item)
        return result
    except _ERRORS:
        raise OriginalReadError("original read query preparation rejected") from None


def parse_query(expected, wire):
    if type(expected) is not OriginalReadQuery:
        raise OriginalReadError("an exact selected original read query is required")
    _decode(wire)
    if wire != expected.canonical_bytes:
        raise OriginalReadError("original read query differs from independent selection")
    return expected


def _claim(expected, value):
    if type(expected) is not OriginalReadQuery:
        raise OriginalReadError("an exact selected original read query is required")
    query = expected.as_dict()
    _object(value, _CLAIM_FIELDS)
    for field, selected in (("schema", CLAIM_SCHEMA), ("query_digest_hex", expected.digest_hex),
            ("root_declaration_digest_hex", query["root_declaration_digest_hex"]),
            ("source_context_digest_hex", _digest(b"PTLC/observation-policy-source-context/v1\0",
                query["source_context"])), ("challenge_hex", query["challenge_hex"])):
        if type(value[field]) is not str or value[field] != selected:
            raise OriginalReadError("original claim changes its selected lookup")
    observation = value["observation"]
    if type(observation) is not str or observation not in OBSERVATIONS:
        raise OriginalReadError("unsupported original record observation")
    head, lineage, policy, record = (value[field] for field in
        ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record"))
    if observation == "unavailable":
        if any(item is not None for item in (head, lineage, policy, record)):
            raise OriginalReadError("unavailable original claim must assert no state")
        return value
    current._head_fields(head); _record_head(lineage)
    if head != query["expected_checkpoint"] or lineage != query["expected_record_checkpoint"]:
        raise OriginalReadError("original claim changes its selected checkpoints")
    _object(policy, ("governor_profile", "active"))
    governor._fields(policy["governor_profile"])
    if (type(policy["active"]) is not bool
            or policy["governor_profile"] != expected._root.as_dict()["governor_profile"]):
        raise OriginalReadError("original claim changes its complete head policy")
    if observation == "absent":
        if record is not None:
            raise OriginalReadError("absent original claim must assert no record")
        return value
    _object(record, ("original_operation", "charge_sequence", "effect_sequence"))
    if _original(record["original_operation"]) != query["original_operation"]:
        raise OriginalReadError("original record changes its complete original request")
    charge, effect = record["charge_sequence"], record["effect_sequence"]
    _number(charge, 1)
    if charge > lineage["event_sequence"]:
        raise OriginalReadError("original charge exceeds its selected record position")
    if observation == "pending":
        if effect is not None:
            raise OriginalReadError("pending original claim must assert no committed effect")
    else:
        _number(effect, 1)
        if not charge < effect <= lineage["event_sequence"]:
            raise OriginalReadError("completed original effect has inconsistent event order")
    return value


@dataclass(frozen=True, init=False)
class OriginalReadClaim:
    """Matched unsigned statement; anyone can forge its labels and commitments."""

    _query: OriginalReadQuery
    _wire: bytes

    def __init__(self):
        raise TypeError("use parse_claim")

    def as_dict(self):
        if type(self) is not OriginalReadClaim:
            raise OriginalReadError("an exact matched original read claim is required")
        try:
            return _claim(self._query, _decode(self._wire))
        except _ERRORS:
            raise OriginalReadError("invalid matched original read claim") from None

    @property
    def canonical_bytes(self):
        return _canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _digest(CLAIM_DOMAIN, self.as_dict())


def parse_claim(expected, wire):
    """Match framing only; loss, absence and unavailable never grant a retry."""
    try:
        _claim(expected, _decode(wire))
        result = object.__new__(OriginalReadClaim)
        object.__setattr__(result, "_query", expected)
        object.__setattr__(result, "_wire", wire)
        return result
    except _ERRORS:
        raise OriginalReadError("original read claim selection rejected") from None
