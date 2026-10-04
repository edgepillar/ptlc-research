"""Stateless public signature framing relative to an exact local intent.

The trusted verifier's signature result establishes neither the owner's role nor
source provenance, freshness, enrollment, quota or permission. Replay succeeds.
This module contains no signing, curve arithmetic, storage or worker launch.
"""

import hashlib
import json
import re

from . import enrollment_contract as contract


ENVELOPE_SCHEMA = "ptlc-observation-enrollment-signature-envelope-v1"
REQUEST_SCHEMA = "ptlc-observation-enrollment-signature-request-v1"
RESULT_SCHEMA = "ptlc-observation-enrollment-signature-result-v1"
MAX_WIRE_BYTES = 8192
MAX_RESULT_BYTES = 512
_FIXED_INTENT = {"schema": contract.INTENT_SCHEMA, "purpose": contract.PURPOSE,
                 "role": contract.ROLE, "algorithm": contract.ALGORITHM}
_DIGEST_FIELDS = ("resource_digest_hex", "scope_digest_hex", "owner_auth_key_hex", "request_id_hex")
_HEX = re.compile(r"[0-9a-f]+\Z")


class EnrollmentSignatureError(ValueError):
    """Sanitized invalid input or unavailable public signature verification."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _object(value, fields):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(key) is not str for key in value) or set(value) != set(fields)):
        raise EnrollmentSignatureError("invalid enrollment signature fields")


def _hex(value, size):
    if type(value) is not str or len(value) != size * 2 or _HEX.fullmatch(value) is None:
        raise EnrollmentSignatureError("invalid enrollment signature hex encoding")


def _intent_fields(value):
    # Shape checks precede serialization; caller objects cannot supply hooks.
    _object(value, (*_FIXED_INTENT, *_DIGEST_FIELDS))
    for field, expected in _FIXED_INTENT.items():
        if type(value[field]) is not str or value[field] != expected:
            raise EnrollmentSignatureError("unsupported enrollment signature intent")
    for field in _DIGEST_FIELDS:
        _hex(value[field], 32)
    return value.copy()


def _expected(intent):
    if type(intent) is not contract.EnrollmentIntent:
        raise EnrollmentSignatureError("an exact independently prepared intent is required")
    try:
        return _intent_fields(intent.as_dict())
    except (ValueError, AttributeError, TypeError, RecursionError):
        raise EnrollmentSignatureError("invalid independently prepared enrollment intent") from None


def _decode(wire):
    if type(wire) is not bytes or not 1 <= len(wire) <= MAX_WIRE_BYTES:
        raise EnrollmentSignatureError("invalid enrollment signature wire size or type")
    try:
        value = json.loads(wire.decode("ascii"))
        if _canonical(value) != wire:
            raise EnrollmentSignatureError("noncanonical enrollment signature wire")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise EnrollmentSignatureError("invalid canonical enrollment signature wire") from None


def _packet(value, schema):
    _object(value, ("schema", "intent", "signature_hex"))
    if type(value["schema"]) is not str or value["schema"] != schema:
        raise EnrollmentSignatureError("unsupported enrollment signature packet")
    intent = _intent_fields(value["intent"])
    _hex(value["signature_hex"], 64)
    return {"schema": schema, "intent": intent, "signature_hex": value["signature_hex"]}


def envelope(expected, signature):
    """Package a supplied synthetic/public signature without signing or checking."""
    intent = _expected(expected)
    if type(signature) is not bytes or len(signature) != 64:
        raise EnrollmentSignatureError("an exact 64-byte public signature is required")
    return _canonical({"schema": ENVELOPE_SCHEMA, "intent": intent, "signature_hex": signature.hex()})


def request(expected, envelope_bytes):
    """Reject incoming key, source, scope or role changes before verification."""
    selected = _expected(expected)
    packet = _packet(_decode(envelope_bytes), ENVELOPE_SCHEMA)
    if packet["intent"] != selected:
        raise EnrollmentSignatureError("envelope changes its independently prepared intent")
    packet["schema"] = REQUEST_SCHEMA
    return packet


def request_digest(value):
    packet = _packet(value, REQUEST_SCHEMA)
    wire = _canonical(packet)
    if len(wire) > MAX_WIRE_BYTES:
        raise EnrollmentSignatureError("enrollment signature request exceeds its byte bound")
    return hashlib.sha256(b"PTLC/observation-enrollment-signature-request/v1\x00" + wire).hexdigest()


def _result(value, digest):
    _object(value, ("schema", "request_digest_hex", "signature_valid"))
    if (type(value["schema"]) is not str or value["schema"] != RESULT_SCHEMA
            or type(value["request_digest_hex"]) is not str or value["request_digest_hex"] != digest
            or value["signature_valid"] is not True):
        raise EnrollmentSignatureError("invalid bound enrollment signature result")


def verify_signature(expected, envelope_bytes, *, verifier):
    """Return the same unsigned intent after an explicitly trusted check.

    Matching result bytes can be forged by a malicious selected verifier. This
    helper is stateless, never a governor-role check or registry admission token.
    Cancellation is propagated; ordinary failures supply no signature fact.
    """
    value = request(expected, envelope_bytes)
    digest = request_digest(value)
    if not callable(verifier):
        raise EnrollmentSignatureError("an explicitly trusted public verifier is required")
    try:
        result = verifier(json.loads(_canonical(value)))
        _result(result, digest)
        if _expected(expected) != value["intent"]:
            raise EnrollmentSignatureError("selected enrollment intent changed during verification")
    except Exception:
        raise EnrollmentSignatureError("public enrollment signature verification failed") from None
    return expected
