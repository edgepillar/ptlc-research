"""Checkpoint-bound public read claims, never current truth or use permission.

Source provisioning and checkpoint selection are independent external premises.
There is no source adapter, signature verification, clock, storage or use gate.
Anyone can forge these claims; coherent copies and identical queries replay.
"""

from dataclasses import dataclass
import hashlib

from . import authority_contract as authority, enrollment_contract as enrollment
from . import governor_authentication as signatures, governor_contract as governor


SOURCE_SCHEMA = "ptlc-observation-policy-source-context-v1"
QUERY_SCHEMA = "ptlc-observation-policy-read-query-v1"
CLAIM_SCHEMA = "ptlc-observation-policy-read-claim-v1"
OPERATION = "read-assignment-at-checkpoint"
MAX_WIRE_BYTES = 16384
OBSERVATIONS = ("active", "revoked", "absent", "unavailable")
_SOURCE_FIELDS = ("schema", "source_id_hex", "source_profile_digest_hex",
    "source_incarnation_hex", "provisioning_root_key_hex", "resource_digest_hex",
    "authority_id_hex", "role")
_HEAD_FIELDS = ("revision", "policy_state_digest_hex")
_QUERY_FIELDS = ("schema", "operation", "source_context", "expected_checkpoint",
    "challenge_hex", "governor_signature_request", "decoded_scope", "retained_resource")
_CLAIM_FIELDS = ("schema", "query_digest_hex", "source_context_digest_hex",
    "challenge_hex", "observation", "claimed_checkpoint", "assignment_digest_hex")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError)


class CurrentAuthorityContractError(ValueError):
    """Sanitized malformed selection or inconsistent public read claim."""


def _source_fields(value):
    enrollment._object(value, _SOURCE_FIELDS)
    if (type(value["schema"]) is not str or value["schema"] != SOURCE_SCHEMA
            or type(value["role"]) is not str or value["role"] != enrollment.ROLE):
        raise CurrentAuthorityContractError("unsupported policy source context")
    for field in _SOURCE_FIELDS[1:-1]:
        enrollment._hex(value[field])
    return value


def _head_fields(value):
    enrollment._object(value, _HEAD_FIELDS)
    if type(value["revision"]) is not int or not 0 <= value["revision"] <= authority.MAX_NUMBER:
        raise CurrentAuthorityContractError("invalid policy checkpoint revision")
    enrollment._hex(value["policy_state_digest_hex"])
    return value


def _decode(wire):
    try:
        return enrollment._decode(wire, MAX_WIRE_BYTES)
    except _ERRORS:
        raise CurrentAuthorityContractError("invalid canonical policy read wire") from None


def _digest(domain, value):
    return hashlib.sha256(domain + enrollment._canonical(value)).hexdigest()


def _bound(expected):
    if type(expected) is not governor.BoundEnrollmentIntent:
        raise CurrentAuthorityContractError("an exact independently prepared bound intent is required")
    return signatures._expected(expected)


@dataclass(frozen=True, init=False)
class SourceContext:
    """Independent local source selection, not authenticated source identity."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use source_context")

    def as_dict(self):
        if type(self) is not SourceContext:
            raise CurrentAuthorityContractError("an exact selected source context is required")
        try:
            return _source_fields(_decode(self._wire))
        except _ERRORS:
            raise CurrentAuthorityContractError("invalid selected policy source context") from None

    @property
    def canonical_bytes(self):
        return enrollment._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _digest(b"PTLC/observation-policy-source-context/v1\0", self.as_dict())


def source_context(expected, *, source_id_hex, source_profile_digest_hex,
                   source_incarnation_hex, provisioning_root_key_hex):
    """Bind independent source pins to the selected resource, namespace and role.

    The provisioning root and assignment issuer have separate meanings. Neither
    a key encoding nor equality between their bytes establishes either meaning.
    """
    try:
        assignment, intent = _bound(expected)
        value = _source_fields(dict(schema=SOURCE_SCHEMA, source_id_hex=source_id_hex,
            source_profile_digest_hex=source_profile_digest_hex,
            source_incarnation_hex=source_incarnation_hex,
            provisioning_root_key_hex=provisioning_root_key_hex,
            resource_digest_hex=intent["resource_digest_hex"],
            authority_id_hex=assignment["governor_profile"]["authority_id_hex"],
            role=intent["role"]))
        result = object.__new__(SourceContext)
        object.__setattr__(result, "_wire", enrollment._canonical(value))
        return result
    except _ERRORS:
        raise CurrentAuthorityContractError("policy source selection rejected") from None


@dataclass(frozen=True)
class PolicyCheckpoint:
    """An independently selected read position, not a latest-head assertion."""

    revision: int
    policy_state_digest_hex: str

    def __post_init__(self):
        self.as_dict()

    def as_dict(self):
        if type(self) is not PolicyCheckpoint:
            raise CurrentAuthorityContractError("an exact selected policy checkpoint is required")
        try:
            return _head_fields(dict(revision=self.revision,
                policy_state_digest_hex=self.policy_state_digest_hex))
        except _ERRORS:
            raise CurrentAuthorityContractError("invalid selected policy checkpoint") from None


def _query_fields(expected, source, checkpoint, packet, challenge):
    if type(source) is not SourceContext or type(checkpoint) is not PolicyCheckpoint:
        raise CurrentAuthorityContractError("exact independently selected source and checkpoint are required")
    assignment, intent = _bound(expected)
    selected = source.as_dict()
    if (selected["resource_digest_hex"] != intent["resource_digest_hex"]
            or selected["authority_id_hex"] != assignment["governor_profile"]["authority_id_hex"]
            or selected["role"] != intent["role"]):
        raise CurrentAuthorityContractError("policy source changes its independently selected scope")
    enrollment._hex(challenge)
    signatures._packet(packet, signatures.REQUEST_SCHEMA)
    envelope = dict(packet, schema=signatures.ENVELOPE_SCHEMA)
    prepared = signatures.request(expected, enrollment._canonical(envelope))
    return dict(schema=QUERY_SCHEMA, operation=OPERATION, source_context=selected,
        expected_checkpoint=checkpoint.as_dict(), challenge_hex=challenge,
        governor_signature_request=prepared, decoded_scope=expected._intent._scope.as_dict(),
        retained_resource=expected._intent._resource.as_dict())


@dataclass(frozen=True, init=False)
class PolicyReadQuery:
    """A replayable read request; no registration, reservation or worker entry."""

    _expected: governor.BoundEnrollmentIntent
    _source: SourceContext
    _checkpoint: PolicyCheckpoint
    _wire: bytes

    def __init__(self):
        raise TypeError("use policy_read_query")

    def as_dict(self):
        if type(self) is not PolicyReadQuery:
            raise CurrentAuthorityContractError("an exact selected policy read query is required")
        try:
            value = _decode(self._wire)
            enrollment._object(value, _QUERY_FIELDS)
            selected = _query_fields(self._expected, self._source, self._checkpoint,
                value["governor_signature_request"], value["challenge_hex"])
            if enrollment._canonical(value) != enrollment._canonical(selected):
                raise CurrentAuthorityContractError("policy read changes its complete independent selection")
            return value
        except _ERRORS:
            raise CurrentAuthorityContractError("invalid selected policy read query") from None

    @property
    def canonical_bytes(self):
        return enrollment._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _digest(b"PTLC/observation-policy-read-query/v1\0", self.as_dict())


def policy_read_query(expected, envelope_bytes, *, source, checkpoint, challenge_hex):
    """Revalidate decoded scope/caps and both public statements without math."""
    try:
        packet = signatures.request(expected, envelope_bytes)
        value = _query_fields(expected, source, checkpoint, packet, challenge_hex)
        wire = enrollment._canonical(value)
        if len(wire) > MAX_WIRE_BYTES:
            raise CurrentAuthorityContractError("policy read query exceeds its byte bound")
        result = object.__new__(PolicyReadQuery)
        for field, item in (("_expected", expected), ("_source", source),
                            ("_checkpoint", checkpoint), ("_wire", wire)):
            object.__setattr__(result, field, item)
        return result
    except _ERRORS:
        raise CurrentAuthorityContractError("policy read query preparation rejected") from None


def parse_query(expected, wire):
    """Refuse peer replacements; repeated exact queries still match."""
    if type(expected) is not PolicyReadQuery:
        raise CurrentAuthorityContractError("an exact selected policy read query is required")
    _decode(wire)
    if wire != expected.canonical_bytes:
        raise CurrentAuthorityContractError("policy read query differs from independent selection")
    return expected


@dataclass(frozen=True, init=False)
class PolicyReadClaim:
    """A forgeable matched observation, with no signature or permission fact."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use parse_claim")

    def as_dict(self):
        if type(self) is not PolicyReadClaim:
            raise CurrentAuthorityContractError("an exact matched policy read claim is required")
        try:
            return _decode(self._wire)
        except _ERRORS:
            raise CurrentAuthorityContractError("invalid matched policy read claim") from None


def parse_claim(expected, wire):
    """Match a checkpoint-bound label; never assert latest state or authorize use.

    Active, revoked, absent and unavailable are claims without source truth. An
    unavailable claim has no checkpoint or assignment. It supplies no refund,
    fallback or authority. Revision ordering and elapsed time are not inferred.
    """
    if type(expected) is not PolicyReadQuery:
        raise CurrentAuthorityContractError("an exact selected policy read query is required")
    try:
        query = expected.as_dict()
        value = _decode(wire)
        enrollment._object(value, _CLAIM_FIELDS)
        for field, selected in (("schema", CLAIM_SCHEMA), ("query_digest_hex", expected.digest_hex),
                ("source_context_digest_hex", expected._source.digest_hex),
                ("challenge_hex", query["challenge_hex"])):
            if type(value[field]) is not str or value[field] != selected:
                raise CurrentAuthorityContractError("policy claim changes its selected read")
        observation = value["observation"]
        if type(observation) is not str or observation not in OBSERVATIONS:
            raise CurrentAuthorityContractError("unsupported policy read observation")
        head, assignment = value["claimed_checkpoint"], value["assignment_digest_hex"]
        if observation == "unavailable":
            if head is not None or assignment is not None:
                raise CurrentAuthorityContractError("unavailable claim must not assert policy state")
        else:
            _head_fields(head)
            if head != query["expected_checkpoint"]:
                raise CurrentAuthorityContractError("policy claim changes its selected checkpoint")
            if observation == "absent":
                if assignment is not None:
                    raise CurrentAuthorityContractError("absent claim must not assert an assignment")
            else:
                enrollment._hex(assignment)
                selected = query["governor_signature_request"]["bound_intent"]["governor_assignment_digest_hex"]
                if assignment != selected:
                    raise CurrentAuthorityContractError("policy claim changes its complete assignment")
        result = object.__new__(PolicyReadClaim)
        object.__setattr__(result, "_wire", wire)
        return result
    except _ERRORS:
        raise CurrentAuthorityContractError("policy read claim selection rejected") from None
