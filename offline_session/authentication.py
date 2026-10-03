"""Offline completion-envelope qualification relative to explicit local pins.

This supplies public verification inputs, never key enrollment or signing.
Successful authentication returns exact opaque bytes, not a valid completion,
fresh message, authenticated chain observation, or journal admission permit.
"""

from dataclasses import dataclass
import hashlib
import json
import re

from .transcript import Commitment, TranscriptError, agree_terms


MAX_PAYLOAD_BYTES = 32_000
MAX_WIRE_BYTES = 65_536
CONTEXT_SCHEMA = "ptlc-completion-auth-context-v1"
ENVELOPE_SCHEMA = "ptlc-completion-auth-envelope-v1"
REQUEST_SCHEMA = "ptlc-completion-auth-request-v1"
RESULT_SCHEMA = "ptlc-completion-auth-result-v1"
_HEX = re.compile(r"^[0-9a-f]+$")
_FIXED = {"schema": CONTEXT_SCHEMA, "algorithm": "BIP340-SHA256",
          "purpose": "zenon-completion", "sender": "alice", "recipient": "bob"}
_VARIABLE = ("session_id", "terms_digest_hex", "alice_id_hex", "bob_id_hex",
             "alice_auth_key_hex", "bob_auth_key_hex")


class AuthenticationError(ValueError):
    """The public authentication input or trusted verifier result was rejected."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _object(value, fields):
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != set(fields)):
        raise AuthenticationError("invalid authentication fields")


def _hex(value, size):
    if type(value) is not str or len(value) != 2 * size or not _HEX.fullmatch(value):
        raise AuthenticationError("invalid authentication hex encoding")


def _context_fields(value):
    _object(value, (*_FIXED, *_VARIABLE))
    for field, expected in _FIXED.items():
        if type(value[field]) is not str or value[field] != expected:
            raise AuthenticationError("unsupported authentication context")
    for field in _VARIABLE:
        _hex(value[field], 32)
    if (value["alice_id_hex"] == value["bob_id_hex"]
            or value["alice_auth_key_hex"] == value["bob_auth_key_hex"]):
        raise AuthenticationError("authentication participants and keys must differ")
    return value.copy()


def _payload(value):
    if type(value) is not bytes or not 1 <= len(value) <= MAX_PAYLOAD_BYTES:
        raise AuthenticationError("authentication payload exceeds its byte boundary")
    return value


def _parse(wire):
    if type(wire) is not bytes or not 1 <= len(wire) <= MAX_WIRE_BYTES:
        raise AuthenticationError("authentication wire exceeds its byte boundary")
    try:
        value = json.loads(wire.decode("ascii"))
        if _canonical(value) != wire:
            raise AuthenticationError("authentication wire is not canonical")
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise AuthenticationError("invalid canonical authentication wire") from None


@dataclass(frozen=True, init=False)
class AuthenticationContext:
    """A public snapshot derived from local terms and independently supplied pins."""

    _terms: Commitment
    _encoded: bytes

    def __init__(self):
        raise TypeError("use the authentication context factory")

    @property
    def canonical_bytes(self):
        return _canonical(_validated_context(self))

    def as_dict(self):
        return _validated_context(self)


def context(terms, *, alice_auth_key_hex, bob_auth_key_hex):
    """Freeze pins supplied by local policy; never source these from an envelope.

    Encoding inequality is checked here. The actual public verifier must parse
    both curve points. Neither step proves how the keys were obtained/generated.
    """
    if type(terms) is not Commitment:
        raise AuthenticationError("validated local terms are required")
    try:
        raw = terms.as_dict()
        if raw.get("stage") != "terms":
            raise AuthenticationError("a terms commitment is required")
        checked = agree_terms(raw["terms"])
        if checked.canonical_bytes != terms.canonical_bytes:
            raise AuthenticationError("local terms are not their validated reconstruction")
    except (TranscriptError, AttributeError, KeyError, TypeError, ValueError, RecursionError):
        raise AuthenticationError("invalid local terms commitment") from None
    for key in (alice_auth_key_hex, bob_auth_key_hex):
        _hex(key, 32)
    agreed = checked.as_dict()["terms"]
    btc, znn = agreed["bitcoin"], agreed["zenon"]
    reserved = {key[2:] for key in btc["signer_keys_sec1_hex"] + znn["signer_keys_sec1_hex"]}
    reserved.update(btc[field] for field in ("internal_key_xonly_hex", "output_key_xonly_hex",
                                           "refund_key_xonly_hex"))
    reserved.update((znn["aggregate_key_xonly_hex"], agreed["adaptor_point_sec1_hex"][2:]))
    if alice_auth_key_hex in reserved or bob_auth_key_hex in reserved:
        raise AuthenticationError("authentication pins must use separate encoded keys")
    value = _context_fields({**_FIXED, "session_id": checked.session_id,
                             "terms_digest_hex": checked.digest_hex,
                             "alice_id_hex": agreed["alice_id_hex"],
                             "bob_id_hex": agreed["bob_id_hex"],
                             "alice_auth_key_hex": alice_auth_key_hex,
                             "bob_auth_key_hex": bob_auth_key_hex})
    result = object.__new__(AuthenticationContext)
    object.__setattr__(result, "_terms", checked)
    object.__setattr__(result, "_encoded", _canonical(value))
    return result


def _validated_context(value):
    if type(value) is not AuthenticationContext:
        raise AuthenticationError("a locally selected authentication context is required")
    try:
        fields = _context_fields(_parse(value._encoded))
        rebuilt = context(value._terms, alice_auth_key_hex=fields["alice_auth_key_hex"],
                          bob_auth_key_hex=fields["bob_auth_key_hex"])
        if rebuilt._encoded != value._encoded:
            raise AuthenticationError("authentication context is inconsistent with its terms")
        return fields
    except AttributeError:
        raise AuthenticationError("incomplete authentication context") from None


def message_digest(expected_context, payload):
    """Return the 32-byte BIP340 message as hex, without signing it."""
    fields = _validated_context(expected_context)
    payload = _payload(payload)
    return hashlib.sha256(b"PTLC/completion-auth/signature/v1\x00" + _canonical(fields)
                          + b"\x00" + len(payload).to_bytes(4, "big") + payload).hexdigest()


def envelope(expected_context, payload, signature):
    """Package an externally supplied signature; this does not verify or sign."""
    fields = _validated_context(expected_context)
    payload = _payload(payload)
    if type(signature) is not bytes or len(signature) != 64:
        raise AuthenticationError("an exact 64-byte authentication signature is required")
    wire = _canonical({"schema": ENVELOPE_SCHEMA, "context": fields,
                       "payload_hex": payload.hex(), "signature_hex": signature.hex()})
    if len(wire) > MAX_WIRE_BYTES:
        raise AuthenticationError("authentication envelope exceeds its byte boundary")
    return wire


def _request_fields(value, schema):
    _object(value, ("schema", "context", "payload_hex", "signature_hex"))
    if type(value["schema"]) is not str or value["schema"] != schema:
        raise AuthenticationError("unsupported authentication packet schema")
    fields = _context_fields(value["context"])
    payload_hex = value["payload_hex"]
    if (type(payload_hex) is not str or not 2 <= len(payload_hex) <= MAX_PAYLOAD_BYTES * 2
            or len(payload_hex) % 2 or not _HEX.fullmatch(payload_hex)):
        raise AuthenticationError("invalid authentication payload encoding")
    _hex(value["signature_hex"], 64)
    return {"schema": schema, "context": fields, "payload_hex": payload_hex,
            "signature_hex": value["signature_hex"]}


def request(expected_context, envelope_bytes):
    fields = _validated_context(expected_context)
    packet = _request_fields(_parse(envelope_bytes), ENVELOPE_SCHEMA)
    if packet["context"] != fields:
        raise AuthenticationError("envelope does not match locally selected pins and terms")
    packet["schema"] = REQUEST_SCHEMA
    return packet


def request_digest(value):
    value = _request_fields(value, REQUEST_SCHEMA)
    return hashlib.sha256(b"PTLC/completion-auth/request/v1\x00" + _canonical(value)).hexdigest()


def _result(value, digest):
    _object(value, ("schema", "request_digest_hex", "valid"))
    if (type(value["schema"]) is not str or value["schema"] != RESULT_SCHEMA
            or type(value["request_digest_hex"]) is not str
            or value["request_digest_hex"] != digest or value["valid"] is not True):
        raise AuthenticationError("invalid bound authentication result")


def authenticate(expected_context, envelope_bytes, *, verifier):
    """Return retained exact bytes after a trusted public verifier accepts.

    This is stateless: replay succeeds. Journal APIs remain independently
    callable, so using this helper is not enforced authenticated admission.
    """
    value = request(expected_context, envelope_bytes)
    payload = bytes.fromhex(value["payload_hex"])
    digest = request_digest(value)
    if not callable(verifier):
        raise AuthenticationError("a trusted public authentication verifier is required")
    try:
        result = verifier(json.loads(_canonical(value)))
        _result(result, digest)
    except Exception:
        raise AuthenticationError("public authentication verification failed") from None
    return payload
