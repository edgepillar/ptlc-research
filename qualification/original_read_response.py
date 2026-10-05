"""Selected historical original-read signature framing, never current truth.

Root, query and complete claim are independent expectations. A callback result
is not authentication. No source service, lookup, recovery or signer is added.
"""

from dataclasses import dataclass
import hashlib
import json

from offline_session import current_authority_contract as current
from qualification import original_read_contract as read, source_root_roles as roots

RESPONSE_SCHEMA = "ptlc-observation-original-read-response-v1"
ENVELOPE_SCHEMA = "ptlc-observation-original-read-response-envelope-v1"
REQUEST_SCHEMA = "ptlc-observation-original-read-response-request-v1"
RESULT_SCHEMA = "ptlc-observation-original-read-response-result-v1"
RULE = "historical-original-checkpoint-read-v1"
RESPONSE_TAG = b"PTLC/observation-original-read-response/v1"
REQUEST_DOMAIN = b"PTLC/observation-original-read-response-request/v1\0"
MAX_WIRE_BYTES = 16384
_FIELDS = ("schema", "purpose", "algorithm", "read_rule", "root_declaration_digest_hex",
    "source_response_role", "source_response_key_hex", "source_context", "query", "claim", "claim_digest_hex")
_PACKET_FIELDS = ("schema", "root_envelope", "response", "response_signature_hex")
_FLAGS = ("root_signature_valid", "response_signature_valid")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError)
_canonical, _hex, _object, _decode = read._canonical, read._hex, read._object, read._decode


class OriginalResponseError(ValueError):
    """Sanitized inconsistent selection or unavailable public check."""


def _message(value):
    tag = hashlib.sha256(RESPONSE_TAG).digest()
    return hashlib.sha256(tag + tag + _canonical(value)).hexdigest()


def _prepared(declaration, query):
    """Reconstruct grammar only; packet-selected expectations are not trusted."""
    roots._declaration(declaration)
    _object(query, read._QUERY_FIELDS)
    for field, fixed in (("schema", read.QUERY_SCHEMA), ("operation", "read-original-at-checkpoint"),
            ("read_rule", read.READ_RULE)):
        if type(query[field]) is not str or query[field] != fixed:
            raise OriginalResponseError("unsupported selected original query rule")
    _hex(query["root_declaration_digest_hex"], 32)
    _hex(query["challenge_hex"], 32)
    current._source_fields(query["source_context"])
    d = roots.root_declaration(source_context=declaration["source_context"],
        governor_profile=declaration["governor_profile"], delegated_keys=declaration["delegated_keys"],
        revision=declaration["declaration_revision"])
    original = read._original(query["original_operation"])
    o = read.original_operation(operation_id_hex=original["operation_id_hex"],
        expected_revision=original["expected_revision"], profile_wire=_canonical(original["governor_profile"]),
        proposal_digest_hex=original["proposal_digest_hex"])
    current._head_fields(query["expected_checkpoint"])
    head = read._record_head(query["expected_record_checkpoint"])
    selected = read.original_read_query(d, o, checkpoint=current.PolicyCheckpoint(**query["expected_checkpoint"]),
        record_checkpoint=read.RecordCheckpoint(head["event_sequence"], head["record_lineage_digest_hex"]),
        challenge_hex=query["challenge_hex"])
    read.parse_query(selected, _canonical(query))
    return selected


def _response(value, declaration):
    _object(value, _FIELDS)
    for field, fixed in (("schema", RESPONSE_SCHEMA), ("purpose", "original-checkpoint-response"),
            ("algorithm", "BIP340-SHA256"), ("read_rule", RULE),
            ("source_response_role", "historical-original-responder")):
        if type(value[field]) is not str or value[field] != fixed:
            raise OriginalResponseError("unsupported original response rule")
    roots._declaration(declaration)
    for field in ("root_declaration_digest_hex", "source_response_key_hex", "claim_digest_hex"):
        _hex(value[field], 32)
    current._source_fields(value["source_context"])
    if (value["root_declaration_digest_hex"] != read._digest(roots.DECLARATION_DOMAIN, declaration)
            or value["source_response_key_hex"] != declaration["delegated_keys"]["source_response_key_hex"]
            or value["source_context"] != declaration["source_context"]):
        raise OriginalResponseError("original response replaces its selected root or role")
    query = _prepared(declaration, value["query"])
    read._claim(query, value["claim"])
    claim = read.parse_claim(query, _canonical(value["claim"]))
    if value["claim_digest_hex"] != claim.digest_hex:
        raise OriginalResponseError("original response replaces its complete claim digest")
    return value


@dataclass(frozen=True, init=False)
class OriginalReadResponse:
    """Unsigned historical expectation; no issuer, owner or current-use proof."""

    _root_wire: bytes
    _query: read.OriginalReadQuery
    _claim: read.OriginalReadClaim
    _wire: bytes

    def __init__(self):
        raise TypeError("use original_read_response")

    def root_dict(self):
        if type(self) is not OriginalReadResponse:
            raise OriginalResponseError("an exact independent response selection is required")
        try:
            return roots._declaration(_decode(self._root_wire))
        except _ERRORS:
            raise OriginalResponseError("invalid selected original response root") from None

    def as_dict(self):
        if type(self) is not OriginalReadResponse:
            raise OriginalResponseError("an exact independent response selection is required")
        try:
            if type(self._query) is not read.OriginalReadQuery or type(self._claim) is not read.OriginalReadClaim:
                raise OriginalResponseError("exact independently selected query and claim required")
            value = _response(_decode(self._wire), self.root_dict())
            read.parse_query(self._query, _canonical(value["query"]))
            read.parse_claim(self._query, self._claim.canonical_bytes)
            if value["claim"] != self._claim.as_dict():
                raise OriginalResponseError("original response changes its independent claim")
            return value
        except _ERRORS:
            raise OriginalResponseError("invalid independent original response selection") from None

    @property
    def canonical_bytes(self):
        return _canonical(OriginalReadResponse.as_dict(self))

    @property
    def message_digest_hex(self):
        return _message(OriginalReadResponse.as_dict(self))


def original_read_response(selected_root, query, claim):
    """Select the entire historical statement before any incoming envelope."""
    if (type(selected_root) is not roots.RootDeclaration or type(query) is not read.OriginalReadQuery
            or type(claim) is not read.OriginalReadClaim):
        raise OriginalResponseError("exact independent root, query and claim required")
    try:
        declaration, q, c = selected_root.as_dict(), query.as_dict(), claim.as_dict()
        _prepared(declaration, q)
        read.parse_claim(query, claim.canonical_bytes)
        value = _response(dict(schema=RESPONSE_SCHEMA, purpose="original-checkpoint-response",
            algorithm="BIP340-SHA256", read_rule=RULE, root_declaration_digest_hex=selected_root.message_digest_hex,
            source_response_role="historical-original-responder",
            source_response_key_hex=declaration["delegated_keys"]["source_response_key_hex"],
            source_context=declaration["source_context"], query=q, claim=c, claim_digest_hex=claim.digest_hex), declaration)
        wire = _canonical(value)
        if len(wire) > MAX_WIRE_BYTES:
            raise OriginalResponseError("original response exceeds byte bound")
        result = object.__new__(OriginalReadResponse)
        for field, item in (("_root_wire", _canonical(declaration)), ("_query", query), ("_claim", claim), ("_wire", wire)):
            object.__setattr__(result, field, item)
        return result
    except _ERRORS:
        raise OriginalResponseError("independent original response rejected") from None


def _packet(value, schema):
    _object(value, _PACKET_FIELDS)
    if type(value["schema"]) is not str or value["schema"] != schema:
        raise OriginalResponseError("unsupported original response packet")
    statement = roots._packet(value["root_envelope"], roots.ENVELOPE_SCHEMA)
    _response(value["response"], statement["declaration"])
    _hex(value["response_signature_hex"], 64)
    return value


def envelope(expected, *, root_signature, response_signature):
    """Package supplied public signatures; no signing or signature checking."""
    if (type(expected) is not OriginalReadResponse or any(type(s) is not bytes or len(s) != 64
            for s in (root_signature, response_signature))):
        raise OriginalResponseError("exact response selection and public signatures required")
    return _canonical(dict(schema=ENVELOPE_SCHEMA, root_envelope=dict(schema=roots.ENVELOPE_SCHEMA,
        declaration=expected.root_dict(), root_signature_hex=root_signature.hex()),
        response=expected.as_dict(), response_signature_hex=response_signature.hex()))


def request(expected, envelope_bytes):
    if type(expected) is not OriginalReadResponse:
        raise OriginalResponseError("an exact independent response selection is required")
    try:
        value = _packet(_decode(envelope_bytes), ENVELOPE_SCHEMA)
        if (value["root_envelope"]["declaration"] != expected.root_dict()
                or _canonical(value["response"]) != expected.canonical_bytes):
            raise OriginalResponseError("packet replaces its complete independent selection")
        value["schema"] = REQUEST_SCHEMA
        return value
    except _ERRORS:
        raise OriginalResponseError("original response request rejected") from None


def request_digest(value):
    try:
        wire = _canonical(_packet(value, REQUEST_SCHEMA))
        if len(wire) > MAX_WIRE_BYTES:
            raise OriginalResponseError("original response request exceeds byte bound")
        return read._digest(REQUEST_DOMAIN, value)
    except _ERRORS:
        raise OriginalResponseError("invalid original response request") from None


def expected_result(digest):
    """Two mathematics flags only; a selected callback can forge both."""
    _hex(digest, 32)
    return dict(schema=RESULT_SCHEMA, request_digest_hex=digest, **{f: True for f in _FLAGS})


def verify_selected_response(expected, envelope_bytes, *, verifier):
    """Return the same unsigned selection, never authority or original receipt."""
    value = request(expected, envelope_bytes)
    wire, digest = _canonical(value), request_digest(value)
    selected = (expected._root_wire, expected.canonical_bytes)
    if not callable(verifier):
        raise OriginalResponseError("a selected public original response check is required")
    try:
        result = verifier(json.loads(wire.decode("ascii")))
    except Exception:
        raise OriginalResponseError("selected original response check unavailable") from None
    fields = ("schema", "request_digest_hex", *_FLAGS)
    if (type(result) is not dict or len(result) != len(fields) or any(type(k) is not str for k in result)
            or set(result) != set(fields) or type(result["schema"]) is not str
            or type(result["request_digest_hex"]) is not str or any(result[f] is not True for f in _FLAGS)
            or result != expected_result(digest)):
        raise OriginalResponseError("original response result does not bind the complete request")
    if (expected._root_wire, expected.canonical_bytes) != selected:
        raise OriginalResponseError("independent original response selection changed during check")
    return expected
