"""Isolated selected checkpoint-response framing, never current authority.

Complete root, prepared read query and observation are independent selections.
No source service, application signer, policy lookup, store or use gate exists.
"""

from dataclasses import dataclass
import hashlib
import json

from offline_session import authority_contract as authority, current_authority_contract as current
from offline_session import enrollment_contract as enrollment, governor_authentication as governor
from qualification import source_root_roles as root

RESPONSE_SCHEMA = "ptlc-observation-source-response-v1"
ENVELOPE_SCHEMA = "ptlc-observation-source-response-envelope-v1"
REQUEST_SCHEMA = "ptlc-observation-source-response-request-v1"
RESULT_SCHEMA = "ptlc-observation-source-response-result-v1"
RULE = "exact-profile-checkpoint-read-v1"
RESPONSE_DOMAIN = b"PTLC/observation-source-response/v1\0"
REQUEST_DOMAIN = b"PTLC/observation-source-response-request/v1\0"
CLAIM_DOMAIN = b"PTLC/observation-policy-read-claim/v1\0"
MAX_WIRE_BYTES = 16384
_FIELDS = ("schema", "purpose", "algorithm", "read_rule", "root_declaration_digest_hex",
    "source_response_role", "source_response_key_hex", "source_context", "query", "claim", "claim_digest_hex")
_PACKET_FIELDS = ("schema", "root_envelope", "response", "response_signature_hex")
_FLAGS = ("root_signature_valid", "issuer_signature_valid", "owner_signature_valid", "response_signature_valid")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError)
_canonical, _hex, _object = root._canonical, root._hex, root._object


class SourceResponseError(ValueError):
    """Sanitized malformed historical selection or unavailable public check."""


def _digest(domain, value):
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _decode(wire):
    try:
        return enrollment._decode(wire, MAX_WIRE_BYTES)
    except _ERRORS:
        raise SourceResponseError("invalid canonical source response wire") from None


def _query(value, declaration):
    _object(value, current._QUERY_FIELDS)
    if (type(value["schema"]) is not str or value["schema"] != current.QUERY_SCHEMA
            or type(value["operation"]) is not str or value["operation"] != current.OPERATION):
        raise SourceResponseError("unsupported checkpoint read query")
    current._source_fields(value["source_context"])
    current._head_fields(value["expected_checkpoint"])
    _hex(value["challenge_hex"], 32)
    packet = governor._packet(value["governor_signature_request"], governor.REQUEST_SCHEMA)
    assignment, intent = packet["assignment"], packet["bound_intent"]
    profile = declaration["governor_profile"]
    if (value["source_context"] != declaration["source_context"]
            or assignment["governor_profile"] != profile
            or assignment["issuer_auth_key_hex"] != declaration["delegated_keys"]["governor_issuer_key_hex"]):
        raise SourceResponseError("query replaces its complete selected source or profile")
    scope = authority._scope_fields(value["decoded_scope"])
    resource = enrollment._resource_fields(value["retained_resource"])
    if (intent["scope_digest_hex"] != _digest(b"PTLC/observation-authority-scope/v1\0", scope)
            or intent["resource_digest_hex"] != _digest(b"PTLC/observation-retained-resource/v1\0", resource)
            or any(resource[f] != scope[f] for f in ("predicate", *enrollment.SOURCE_FIELDS))
            or any(scope[f] != profile[f] for f in ("authority_id_hex", "authority_epoch",
                "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex"))
            or scope["attempt_limit"] > profile["max_attempt_limit"]
            or scope["target_limit"] > profile["max_target_limit"]):
        raise SourceResponseError("query changes decoded scope, retained resource or profile rules")
    return value


def _claim(value, query):
    _object(value, current._CLAIM_FIELDS)
    for field, expected in (("schema", current.CLAIM_SCHEMA),
            ("query_digest_hex", _digest(b"PTLC/observation-policy-read-query/v1\0", query)),
            ("source_context_digest_hex", _digest(b"PTLC/observation-policy-source-context/v1\0", query["source_context"])),
            ("challenge_hex", query["challenge_hex"])):
        if type(value[field]) is not str or value[field] != expected:
            raise SourceResponseError("claim changes its complete selected query")
    observation = value["observation"]
    if type(observation) is not str or observation not in current.OBSERVATIONS:
        raise SourceResponseError("unsupported checkpoint observation")
    head, assignment = value["claimed_checkpoint"], value["assignment_digest_hex"]
    if observation == "unavailable":
        if head is not None or assignment is not None:
            raise SourceResponseError("unavailable response must not assert state")
    else:
        current._head_fields(head)
        if head != query["expected_checkpoint"]:
            raise SourceResponseError("claim replaces its selected checkpoint")
        if observation == "absent":
            if assignment is not None:
                raise SourceResponseError("absent response must not assert assignment")
        else:
            _hex(assignment, 32)
            if assignment != query["governor_signature_request"]["bound_intent"]["governor_assignment_digest_hex"]:
                raise SourceResponseError("claim replaces its complete assignment")
    return value


def _response(value, declaration):
    root._declaration(declaration)
    _object(value, _FIELDS)
    for field, fixed in (("schema", RESPONSE_SCHEMA), ("purpose", "source-checkpoint-response"),
            ("algorithm", "BIP340-SHA256"), ("read_rule", RULE), ("source_response_role", "checkpoint-responder")):
        if type(value[field]) is not str or value[field] != fixed:
            raise SourceResponseError("unsupported source response rule")
    for field in ("root_declaration_digest_hex", "source_response_key_hex", "claim_digest_hex"):
        _hex(value[field], 32)
    current._source_fields(value["source_context"])
    if (value["root_declaration_digest_hex"] != _digest(root.DECLARATION_DOMAIN, declaration)
            or value["source_response_key_hex"] != declaration["delegated_keys"]["source_response_key_hex"]
            or value["source_context"] != declaration["source_context"]):
        raise SourceResponseError("response changes its selected root or response role")
    query = _query(value["query"], declaration)
    claim = _claim(value["claim"], query)
    if value["claim_digest_hex"] != _digest(CLAIM_DOMAIN, claim):
        raise SourceResponseError("response changes its complete claim digest")
    return value


@dataclass(frozen=True, init=False)
class SourceResponse:
    """Unsigned historical selection; no truth, currentness or use capability."""

    _root_wire: bytes
    _query: current.PolicyReadQuery
    _wire: bytes

    def __init__(self):
        raise TypeError("use source_response")

    def root_dict(self):
        if type(self) is not SourceResponse:
            raise SourceResponseError("an exact independent response selection is required")
        try:
            return root._declaration(_decode(self._root_wire))
        except _ERRORS:
            raise SourceResponseError("invalid selected response root") from None

    def as_dict(self):
        if type(self) is not SourceResponse:
            raise SourceResponseError("an exact independent response selection is required")
        try:
            if type(self._query) is not current.PolicyReadQuery:
                raise SourceResponseError("an exact independently prepared query is required")
            value = _response(_decode(self._wire), self.root_dict())
            current.parse_query(self._query, _canonical(value["query"]))
            current.parse_claim(self._query, _canonical(value["claim"]))
            return value
        except _ERRORS:
            raise SourceResponseError("invalid independent response selection") from None

    @property
    def canonical_bytes(self):
        return _canonical(SourceResponse.as_dict(self))

    @property
    def message_digest_hex(self):
        return _digest(RESPONSE_DOMAIN, SourceResponse.as_dict(self))


def source_response(selected_root, query, *, observation):
    """Select the complete historical read and label before any peer packet."""
    if type(selected_root) is not root.RootDeclaration or type(query) is not current.PolicyReadQuery:
        raise SourceResponseError("exact independently prepared root and query required")
    if type(observation) is not str or observation not in current.OBSERVATIONS:
        raise SourceResponseError("a selected checkpoint observation is required")
    try:
        declaration, read = selected_root.as_dict(), query.as_dict()
        _query(read, declaration)
        claim = dict(schema=current.CLAIM_SCHEMA, query_digest_hex=query.digest_hex,
            source_context_digest_hex=query._source.digest_hex, challenge_hex=read["challenge_hex"],
            observation=observation, claimed_checkpoint=None if observation == "unavailable" else read["expected_checkpoint"],
            assignment_digest_hex=None if observation in ("absent", "unavailable") else
                read["governor_signature_request"]["bound_intent"]["governor_assignment_digest_hex"])
        value = _response(dict(schema=RESPONSE_SCHEMA, purpose="source-checkpoint-response", algorithm="BIP340-SHA256",
            read_rule=RULE, root_declaration_digest_hex=selected_root.message_digest_hex,
            source_response_role="checkpoint-responder", source_response_key_hex=declaration["delegated_keys"]["source_response_key_hex"],
            source_context=declaration["source_context"], query=read, claim=claim, claim_digest_hex=_digest(CLAIM_DOMAIN, claim)), declaration)
        wire = _canonical(value)
        if len(wire) > MAX_WIRE_BYTES:
            raise SourceResponseError("selected response exceeds byte bound")
        result = object.__new__(SourceResponse)
        for field, item in (("_root_wire", _canonical(declaration)), ("_query", query), ("_wire", wire)):
            object.__setattr__(result, field, item)
        return result
    except _ERRORS:
        raise SourceResponseError("independent source response rejected") from None


def _packet(value, schema):
    _object(value, _PACKET_FIELDS)
    if type(value["schema"]) is not str or value["schema"] != schema:
        raise SourceResponseError("unsupported source response packet")
    statement = root._packet(value["root_envelope"], root.ENVELOPE_SCHEMA)
    _response(value["response"], statement["declaration"])
    _hex(value["response_signature_hex"], 64)
    return value


def envelope(expected, *, root_signature, response_signature):
    """Package supplied public signatures; no signing or mathematical checking."""
    if (type(expected) is not SourceResponse or any(type(s) is not bytes or len(s) != 64
            for s in (root_signature, response_signature))):
        raise SourceResponseError("exact response selection and public signatures required")
    return _canonical(dict(schema=ENVELOPE_SCHEMA, root_envelope=dict(schema=root.ENVELOPE_SCHEMA,
        declaration=expected.root_dict(), root_signature_hex=root_signature.hex()),
        response=expected.as_dict(), response_signature_hex=response_signature.hex()))


def request(expected, envelope_bytes):
    if type(expected) is not SourceResponse:
        raise SourceResponseError("an exact independent response selection is required")
    try:
        value = _packet(_decode(envelope_bytes), ENVELOPE_SCHEMA)
        if (value["root_envelope"]["declaration"] != expected.root_dict()
                or _canonical(value["response"]) != expected.canonical_bytes):
            raise SourceResponseError("packet replaces its complete independent selection")
        value["schema"] = REQUEST_SCHEMA
        return value
    except _ERRORS:
        raise SourceResponseError("source response request rejected") from None


def request_digest(value):
    try:
        wire = _canonical(_packet(value, REQUEST_SCHEMA))
        if len(wire) > MAX_WIRE_BYTES:
            raise SourceResponseError("response request exceeds byte bound")
        return _digest(REQUEST_DOMAIN, value)
    except _ERRORS:
        raise SourceResponseError("invalid source response request") from None


def expected_result(digest):
    """Result shape only; a selected callback can forge all four positives."""
    _hex(digest, 32)
    return dict(schema=RESULT_SCHEMA, request_digest_hex=digest, **{f: True for f in _FLAGS})


def verify_selected_response(expected, envelope_bytes, *, verifier):
    """Return the same unsigned historical selection, never current read truth."""
    value = request(expected, envelope_bytes)
    wire, digest = _canonical(value), request_digest(value)
    selected = (expected._root_wire, expected.canonical_bytes)
    if not callable(verifier):
        raise SourceResponseError("a selected public response check is required")
    try:
        result = verifier(json.loads(wire.decode("ascii")))
    except Exception:
        raise SourceResponseError("selected response check unavailable") from None
    fields = ("schema", "request_digest_hex", *_FLAGS)
    if (type(result) is not dict or len(result) != len(fields) or any(type(k) is not str for k in result)
            or set(result) != set(fields) or type(result["schema"]) is not str
            or type(result["request_digest_hex"]) is not str or any(result[f] is not True for f in _FLAGS)
            or result != expected_result(digest)):
        raise SourceResponseError("response result does not bind the complete request")
    if (expected._root_wire, expected.canonical_bytes) != selected:
        raise SourceResponseError("independent response selection changed during check")
    return expected
