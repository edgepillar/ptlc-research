"""Selected checkpoint response signatures, never a trusted current service.

Actual complete openings precede public signature verification. A selected root,
signed old candidate or coherent restore can still match and remains HOLD/NONE.
"""
from dataclasses import dataclass

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_checkpoint_discovery as discovery, nom_checkpoint_protocol as protocol


DECLARATION_SCHEMA = "ptlc-nom-checkpoint-response-authority-v1"
MESSAGE_SCHEMA = "ptlc-nom-checkpoint-response-signed-message-v1"
ENVELOPE_SCHEMA = "ptlc-nom-checkpoint-response-envelope-v1"
REQUEST_SCHEMA = "ptlc-nom-checkpoint-response-request-v1"
RESULT_SCHEMA = "ptlc-nom-checkpoint-response-result-v1"
DECLARATION_DOMAIN = b"ptlc-nom-checkpoint-response-authority-message-v1"
MESSAGE_DOMAIN = b"ptlc-nom-checkpoint-response-signed-message-v1"
REQUEST_DOMAIN = b"ptlc-nom-checkpoint-response-request-v1"
MAX_WIRE_BYTES = 8192
_DECLARATION = ("schema", "purpose", "algorithm", "authority_epoch", "root_key_hex",
    "service_selection", "service_selection_digest_hex", "work_scope_digest_hex", "root_transition")
_PACKET = ("schema", "declaration", "root_signature_hex", "response_signature_hex")
_REQUEST = _PACKET + ("query_digest_hex", "discovery_message_digest_hex")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError)


class CheckpointResponseRefused(ValueError):
    """Sanitized selected-role, complete-opening or verifier-result refusal."""


def _require(condition):
    if not condition:
        raise CheckpointResponseRefused("selected NoM checkpoint response refused")


def _hash(domain, value):
    return authority._digest(domain, codec._canonical(value))


def _hex_encoding(value, size):
    if size == 32:
        codec._hex(value)
    else:
        _require(size == 64 and type(value) is str and len(value) == 128
            and all(char in "0123456789abcdef" for char in value))


def _decode(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE_BYTES)
    value = authority._decode(wire)
    _require(wire == codec._canonical(value))
    return value


def _public_declaration(value):
    """Public packet shape only; this cannot provision its own root or role."""
    codec._object(value, _DECLARATION)
    _require(value["schema"] == DECLARATION_SCHEMA
        and value["purpose"] == "checkpoint-candidate-response-role"
        and value["algorithm"] == "BIP340-SHA256"
        and value["root_transition"] == "independent-reprovisioning")
    authority._number(value["authority_epoch"], positive=True)
    codec._hex(value["root_key_hex"])
    codec._hex(value["work_scope_digest_hex"])
    policy = protocol._policy(value["service_selection"])
    _require(value["service_selection_digest_hex"] == protocol._hash(protocol.POLICY_DOMAIN, policy))
    _require(value["root_key_hex"] != policy["checkpoint_key_hex"])
    return value


def _historical_keys(reference):
    """Read declared encodings from actual retained contexts, without inference."""
    keys, seen = set(), set()
    current = reference
    while current is not None:
        _require(type(current) is protocol.ReferenceCheckpoint and id(current) not in seen)
        _require(len(seen) < protocol.MAX_SNAPSHOTS)
        seen.add(id(current))
        declaration = current._context._declaration.as_dict()
        keys.update(declaration[field] for field in
            ("root_key_hex", "source_response_key_hex", "consumer_checkpoint_key_hex"))
        current = current._prior
    return keys


def _selected_declaration(read, root_key_hex, epoch):
    _require(type(read) is discovery.NoMCheckpointReadSelection)
    query = read.as_dict()
    value = _public_declaration(dict(schema=DECLARATION_SCHEMA,
        purpose="checkpoint-candidate-response-role", algorithm="BIP340-SHA256",
        authority_epoch=epoch, root_key_hex=root_key_hex,
        service_selection=query["service_selection"],
        service_selection_digest_hex=query["service_selection_digest_hex"],
        work_scope_digest_hex=query["work_scope_digest_hex"], root_transition="independent-reprovisioning"))
    _require(root_key_hex not in _historical_keys(read._minimum))
    return value


@dataclass(frozen=True, init=False)
class NoMCheckpointResponseAuthority:
    """An independently selected reference role; real provisioning is unfilled."""
    _read: discovery.NoMCheckpointReadSelection
    _root_key_hex: str
    _epoch: int
    _wire: bytes

    def __init__(self):
        raise TypeError("use select_response_authority")

    def as_dict(self):
        try:
            _require(type(self) is NoMCheckpointResponseAuthority)
            expected = _selected_declaration(self._read, self._root_key_hex, self._epoch)
            _require(self._wire == codec._canonical(expected))
            return _decode(self._wire)
        except _ERRORS:
            raise CheckpointResponseRefused("invalid selected checkpoint response authority") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    @property
    def declaration_message_digest_hex(self):
        return _hash(DECLARATION_DOMAIN, self.as_dict())


def select_response_authority(read, *, root_key_hex, epoch):
    """Select before peer input; the existing service policy fixes its signer."""
    try:
        wire = codec._canonical(_selected_declaration(read, root_key_hex, epoch))
        _decode(wire)
        value = object.__new__(NoMCheckpointResponseAuthority)
        for field, selected in (("_read", read), ("_root_key_hex", root_key_hex), ("_epoch", epoch), ("_wire", wire)):
            object.__setattr__(value, field, selected)
        return value
    except _ERRORS:
        raise CheckpointResponseRefused("checkpoint response authority selection refused") from None


def response_envelope(selected, *, root_signature_hex, response_signature_hex):
    """Frame public signatures only; this performs no signing or curve check."""
    try:
        _require(type(selected) is NoMCheckpointResponseAuthority)
        _hex_encoding(root_signature_hex, 64)
        _hex_encoding(response_signature_hex, 64)
        wire = codec._canonical(dict(schema=ENVELOPE_SCHEMA, declaration=selected.as_dict(),
            root_signature_hex=root_signature_hex, response_signature_hex=response_signature_hex))
        _decode(wire)
        return wire
    except _ERRORS:
        raise CheckpointResponseRefused("checkpoint response envelope refused") from None


def _public_request(request):
    codec._object(request, _REQUEST)
    _require(request["schema"] == REQUEST_SCHEMA)
    _public_declaration(request["declaration"])
    for field, size in (("root_signature_hex", 64), ("response_signature_hex", 64),
                        ("query_digest_hex", 32), ("discovery_message_digest_hex", 32)):
        _hex_encoding(request[field], size)
    _decode(codec._canonical(request))
    return request


def response_signature_request(selected, reply_wire, envelope_wire, opening=None):
    """Bind actual complete discovery inputs before asking a public math worker."""
    try:
        _require(type(selected) is NoMCheckpointResponseAuthority)
        declaration = selected.as_dict()
        preimage = discovery.response_message_digest(selected._read, reply_wire, opening)
        if opening is not None:
            _require(declaration["root_key_hex"] not in _historical_keys(opening._candidate))
        envelope = _decode(envelope_wire)
        codec._object(envelope, _PACKET)
        _require(envelope["schema"] == ENVELOPE_SCHEMA
            and codec._canonical(envelope["declaration"]) == codec._canonical(declaration))
        query_digest = discovery._decode(reply_wire)["query_digest_hex"]
        return _public_request(dict(schema=REQUEST_SCHEMA, declaration=declaration,
            query_digest_hex=query_digest, discovery_message_digest_hex=preimage,
            root_signature_hex=envelope["root_signature_hex"], response_signature_hex=envelope["response_signature_hex"]))
    except _ERRORS:
        raise CheckpointResponseRefused("complete selected checkpoint response refused") from None


def signed_message(request):
    """Exact public role/response statement; hashes cannot create missing custody."""
    _public_request(request)
    return dict(schema=MESSAGE_SCHEMA, purpose="checkpoint-candidate-or-outage-math-only",
        declaration=request["declaration"], query_digest_hex=request["query_digest_hex"],
        discovery_message_digest_hex=request["discovery_message_digest_hex"])


def response_signed_message_digest(request):
    return _hash(MESSAGE_DOMAIN, signed_message(request))


def request_digest(request):
    """Bind both signature encodings as well as the complete public request."""
    return _hash(REQUEST_DOMAIN, _public_request(request))


def expected_result(request_digest_hex):
    codec._hex(request_digest_hex)
    return dict(schema=RESULT_SCHEMA, request_digest_hex=request_digest_hex,
        root_signature_valid=True, response_signature_valid=True)


def inspect_signed_discovery(local, selected, reply_wire, envelope_wire, opening=None, *, verify_public):
    """Compare complete custody and one selected verifier assertion; always HOLD.

    A callback is a trust premise, not a mathematical proof. Actual native exits
    are measured separately. Neither valid signatures nor outage authorize work.
    """
    try:
        request = response_signature_request(selected, reply_wire, envelope_wire, opening)
        result = discovery.inspect_discovery(local, selected._read, reply_wire, opening)
        _require(callable(verify_public))
        wire = codec._canonical(request)
        digest = request_digest(request)
        declaration_digest = _hash(DECLARATION_DOMAIN, request["declaration"])
        message_digest = response_signed_message_digest(request)
        argument = _decode(wire)
        checked = verify_public(argument)
        _require(codec._canonical(argument) == wire)
        _require(type(checked) is dict and codec._canonical(checked) == codec._canonical(expected_result(digest)))
        result["core_worker_calls"] = result.pop("worker_calls")
        result.update(response_authentication="PUBLIC MATHEMATICS UNDER SELECTED REFERENCE ROLE; PROVISIONING_UNVERIFIED",
            signature_mathematics="VERIFIER CALLBACK ASSERTION; ACTUAL NATIVE QUALIFICATION IS SEPARATE",
            signature_verifier_calls=1, signature_request_digest_hex=digest,
            authority_declaration_message_digest_hex=declaration_digest,
            signed_response_message_digest_hex=message_digest,
            authority_epoch=request["declaration"]["authority_epoch"], root_provisioning="UNFILLED")
        return result
    except _ERRORS + (OSError, RuntimeError):
        raise CheckpointResponseRefused("checkpoint response comparison or verifier unavailable") from None
