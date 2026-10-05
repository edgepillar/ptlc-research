"""Public issuer/owner facts relative to exact independently prepared v2 bytes.

No signing, curve arithmetic, storage, current authority or admission is here.
An explicitly trusted callback may forge matching result bytes. Replay succeeds.
"""

import hashlib
import json

from . import enrollment_contract as enrollment
from . import governor_contract as contract, governor_profile as governor
from .enrollment_authentication import _canonical, _hex, _object


ENVELOPE_SCHEMA = "ptlc-observation-governor-signature-envelope-v1"
REQUEST_SCHEMA = "ptlc-observation-governor-signature-request-v1"
RESULT_SCHEMA = "ptlc-observation-governor-signature-result-v1"
MAX_WIRE_BYTES = 8192
MAX_RESULT_BYTES = 512
_PACKET_FIELDS = ("schema", "assignment", "bound_intent", "issuer_signature_hex", "owner_signature_hex")


class GovernorSignatureError(ValueError):
    """Sanitized malformed selection or unavailable public signature check."""


def _messages(assignment, intent):
    _object(assignment, contract._ASSIGNMENT_FIELDS)
    for field, expected in (("schema", contract.ASSIGNMENT_SCHEMA),
            ("purpose", contract.ASSIGNMENT_PURPOSE), ("algorithm", enrollment.ALGORITHM)):
        if type(assignment[field]) is not str or assignment[field] != expected:
            raise GovernorSignatureError("unsupported governor assignment")
    _hex(assignment["issuer_auth_key_hex"], 32)
    profile = governor._fields(assignment["governor_profile"])
    _object(intent, contract._BOUND_FIELDS)
    for field, expected in (("schema", contract.BOUND_INTENT_SCHEMA),
            ("purpose", enrollment.PURPOSE), ("role", enrollment.ROLE), ("algorithm", enrollment.ALGORITHM)):
        if type(intent[field]) is not str or intent[field] != expected:
            raise GovernorSignatureError("unsupported bound enrollment intent")
    for field in ("resource_digest_hex", "scope_digest_hex", "owner_auth_key_hex",
                  "request_id_hex", "governor_assignment_digest_hex"):
        _hex(intent[field], 32)
    digest = hashlib.sha256(b"PTLC/observation-governor-assignment/v1\0" + _canonical(assignment)).hexdigest()
    if (intent["governor_assignment_digest_hex"] != digest
            or any(intent[field] != profile[field] for field in ("owner_auth_key_hex", "resource_digest_hex"))):
        raise GovernorSignatureError("inconsistent governor signature messages")
    # A scope hash alone cannot establish its pins or compliance with these caps.
    return assignment, intent


def _expected(bound):
    if type(bound) is not contract.BoundEnrollmentIntent:
        raise GovernorSignatureError("an exact independently prepared bound intent is required")
    try:
        intent = bound.as_dict()  # Revalidates the retained scope, profile and caps.
        assignment = bound._assignment.as_dict()
        return _messages(assignment, intent)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise GovernorSignatureError("invalid independently prepared governor messages") from None


def _decode(wire):
    if type(wire) is not bytes or not 1 <= len(wire) <= MAX_WIRE_BYTES:
        raise GovernorSignatureError("invalid governor signature wire size or type")
    try:
        value = json.loads(wire.decode("ascii"))
        if _canonical(value) != wire:
            raise GovernorSignatureError("noncanonical governor signature wire")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise GovernorSignatureError("invalid canonical governor signature wire") from None


def _packet(value, schema):
    try:
        _object(value, _PACKET_FIELDS)
        if type(value["schema"]) is not str or value["schema"] != schema:
            raise GovernorSignatureError("unsupported governor signature packet")
        _messages(value["assignment"], value["bound_intent"])
        for field in ("issuer_signature_hex", "owner_signature_hex"):
            _hex(value[field], 64)
        return value
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise GovernorSignatureError("invalid governor signature packet") from None


def envelope(expected, *, issuer_signature, owner_signature):
    """Package supplied public signatures, without signing or verification."""
    assignment, intent = _expected(expected)
    for signature in (issuer_signature, owner_signature):
        if type(signature) is not bytes or len(signature) != 64:
            raise GovernorSignatureError("exact 64-byte public signatures are required")
    return _canonical(dict(schema=ENVELOPE_SCHEMA, assignment=assignment, bound_intent=intent,
        issuer_signature_hex=issuer_signature.hex(), owner_signature_hex=owner_signature.hex()))


def request(expected, envelope_bytes):
    """Reject changed complete expectations before any selected worker runs."""
    assignment, intent = _expected(expected)
    packet = _packet(_decode(envelope_bytes), ENVELOPE_SCHEMA)
    if packet["assignment"] != assignment or packet["bound_intent"] != intent:
        raise GovernorSignatureError("envelope changes its independent governor selection")
    packet["schema"] = REQUEST_SCHEMA
    return packet


def request_digest(value):
    wire = _canonical(_packet(value, REQUEST_SCHEMA))
    if len(wire) > MAX_WIRE_BYTES:
        raise GovernorSignatureError("governor signature request exceeds its byte bound")
    return hashlib.sha256(b"PTLC/observation-governor-signature-request/v1\0" + wire).hexdigest()


def result_for_digest(digest):
    """Expected transport shape only; this function supplies no signature fact."""
    _hex(digest, 32)
    return dict(schema=RESULT_SCHEMA, request_digest_hex=digest,
                issuer_signature_valid=True, owner_signature_valid=True)


def verify_signatures(expected, envelope_bytes, *, verifier):
    """Return the same unsigned intent after two explicitly trusted checks.

    No root provisioning, latest-state service, role permission or token results.
    Ordinary failures are sanitized; cancellation propagates. A malicious selected
    verifier can supply the exact expected positive shape without doing math.
    """
    value = request(expected, envelope_bytes)
    digest = request_digest(value)
    if not callable(verifier):
        raise GovernorSignatureError("an explicitly trusted public verifier is required")
    try:
        result = verifier(json.loads(_canonical(value)))
        selected = result_for_digest(digest)
        _object(result, selected)
        if (any(type(result[field]) is not str or result[field] != selected[field]
                for field in ("schema", "request_digest_hex"))
                or result["issuer_signature_valid"] is not True or result["owner_signature_valid"] is not True):
            raise GovernorSignatureError("invalid bound governor signature result")
        assignment, intent = _expected(expected)
        if assignment != value["assignment"] or intent != value["bound_intent"]:
            raise GovernorSignatureError("governor selection changed during verification")
    except Exception:
        raise GovernorSignatureError("public governor signature verification failed") from None
    return expected
