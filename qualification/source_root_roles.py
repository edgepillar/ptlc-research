"""Offline root-statement framing, never current source truth or admission.

Independently selecting the expected root, roles and complete policy is an
external premise. A selected callback can forge a matching mathematical result.
No source service, state store, worker adapter, signer or rotation is connected.
"""

from dataclasses import dataclass
import hashlib
import json

from offline_session import current_authority_contract as current
from offline_session import governor_profile as governor
from offline_session.enrollment_authentication import _canonical, _hex, _object


DECLARATION_SCHEMA = "ptlc-observation-source-root-declaration-v1"
ENVELOPE_SCHEMA = "ptlc-observation-source-root-envelope-v1"
REQUEST_SCHEMA = "ptlc-observation-source-root-request-v1"
RESULT_SCHEMA = "ptlc-observation-source-root-result-v1"
DECLARATION_DOMAIN = b"PTLC/observation-source-root-declaration/v1\0"
REQUEST_DOMAIN = b"PTLC/observation-source-root-request/v1\0"
MAX_WIRE_BYTES = 8192
MAX_REVISION = (1 << 53)-1
_DECLARATION_FIELDS = ("schema", "purpose", "algorithm", "declaration_revision",
    "source_context", "governor_profile", "delegated_keys", "root_transition")
_KEY_FIELDS = ("policy_admin_key_hex", "source_response_key_hex", "governor_issuer_key_hex")
_PACKET_FIELDS = ("schema", "declaration", "root_signature_hex")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError)


class RootStatementError(ValueError):
    """Sanitized malformed selection or unavailable mathematical check."""


def _declaration(value):
    _object(value, _DECLARATION_FIELDS)
    for field, fixed in (("schema", DECLARATION_SCHEMA), ("purpose", "source-role-declaration"),
            ("algorithm", "BIP340-SHA256"), ("root_transition", "independent-reprovisioning")):
        if type(value[field]) is not str or value[field] != fixed:
            raise RootStatementError("unsupported source root declaration")
    revision = value["declaration_revision"]
    if type(revision) is not int or not 1 <= revision <= MAX_REVISION:
        raise RootStatementError("invalid selected declaration revision")
    source = current._source_fields(value["source_context"])
    profile = governor._fields(value["governor_profile"])
    if any(source[field] != profile[field] for field in ("authority_id_hex", "resource_digest_hex", "role")):
        raise RootStatementError("declaration changes its retained namespace")
    keys = value["delegated_keys"]
    _object(keys, _KEY_FIELDS)
    for field in _KEY_FIELDS:
        _hex(keys[field], 32)
    selected = [source["provisioning_root_key_hex"], profile["owner_auth_key_hex"], *keys.values()]
    if len(set(selected)) != 5:
        raise RootStatementError("five distinct selected role keys required")
    return value


def _decode(wire):
    if type(wire) is not bytes or not 1 <= len(wire) <= MAX_WIRE_BYTES:
        raise RootStatementError("invalid source root wire type or size")
    try:
        value = json.loads(wire.decode("ascii"))
        if _canonical(value) != wire:
            raise RootStatementError("noncanonical source root wire")
        return value
    except _ERRORS:
        raise RootStatementError("invalid canonical source root wire") from None


@dataclass(frozen=True, init=False)
class RootDeclaration:
    """Independent historical byte selection, never a provisioned capability."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use root_declaration")

    def as_dict(self):
        if type(self) is not RootDeclaration:
            raise RootStatementError("an exact independent root declaration is required")
        try:
            return _declaration(_decode(self._wire))
        except _ERRORS:
            raise RootStatementError("invalid selected source root declaration") from None

    @property
    def canonical_bytes(self):
        return _canonical(self.as_dict())

    @property
    def message_digest_hex(self):
        return hashlib.sha256(DECLARATION_DOMAIN + self.canonical_bytes).hexdigest()


def root_declaration(*, source_context, governor_profile, delegated_keys, revision):
    """Select all expectations out of band; this factory authenticates nothing."""
    try:
        value = _declaration(dict(schema=DECLARATION_SCHEMA, purpose="source-role-declaration",
            algorithm="BIP340-SHA256", declaration_revision=revision, source_context=source_context,
            governor_profile=governor_profile, delegated_keys=delegated_keys,
            root_transition="independent-reprovisioning"))
        wire = _canonical(value)
        if len(wire) > MAX_WIRE_BYTES:
            raise RootStatementError("root declaration exceeds its byte bound")
        result = object.__new__(RootDeclaration)
        object.__setattr__(result, "_wire", wire)
        return result
    except _ERRORS:
        raise RootStatementError("independent root selection rejected") from None


def _packet(value, schema):
    _object(value, _PACKET_FIELDS)
    if type(value["schema"]) is not str or value["schema"] != schema:
        raise RootStatementError("unsupported source root packet")
    _declaration(value["declaration"])
    _hex(value["root_signature_hex"], 64)
    return value


def envelope(expected, *, root_signature):
    """Package supplied public bytes without signing or verifying them."""
    if type(expected) is not RootDeclaration or type(root_signature) is not bytes or len(root_signature) != 64:
        raise RootStatementError("exact independent selection and public signature required")
    return _canonical(dict(schema=ENVELOPE_SCHEMA, declaration=expected.as_dict(),
        root_signature_hex=root_signature.hex()))


def request(expected, envelope_bytes):
    """Refuse every peer replacement before a selected public-only check."""
    if type(expected) is not RootDeclaration:
        raise RootStatementError("an exact independent root declaration is required")
    try:
        value = _packet(_decode(envelope_bytes), ENVELOPE_SCHEMA)
        if _canonical(value["declaration"]) != expected.canonical_bytes:
            raise RootStatementError("packet replaces its independent root selection")
        value["schema"] = REQUEST_SCHEMA
        return value
    except _ERRORS:
        raise RootStatementError("source root request rejected") from None


def request_digest(value):
    try:
        wire = _canonical(_packet(value, REQUEST_SCHEMA))
        if len(wire) > MAX_WIRE_BYTES:
            raise RootStatementError("source root request exceeds its byte bound")
        return hashlib.sha256(REQUEST_DOMAIN + wire).hexdigest()
    except _ERRORS:
        raise RootStatementError("invalid source root request") from None


def expected_result(digest):
    """Transport shape only; constructing it supplies no signature fact."""
    _hex(digest, 32)
    return dict(schema=RESULT_SCHEMA, request_digest_hex=digest, root_signature_valid=True)


def verify_selected_statement(expected, envelope_bytes, *, verifier):
    """Return the same historical selection under an explicitly trusted check.

    Replay and coherent restoration still match. No current authority, role
    provisioning, quota, registry entry or permission is returned. A malicious
    selected callback can forge the complete positive without doing mathematics.
    """
    value = request(expected, envelope_bytes)
    wire = _canonical(value)
    digest = request_digest(value)
    selected = expected.canonical_bytes
    if not callable(verifier):
        raise RootStatementError("a selected public-only verifier is required")
    try:
        result = verifier(json.loads(wire.decode("ascii")))
    except Exception:
        raise RootStatementError("selected root check unavailable") from None
    if (type(result) is not dict or len(result) != 3
            or any(type(key) is not str for key in result)
            or set(result) != {"schema", "request_digest_hex", "root_signature_valid"}
            or type(result["schema"]) is not str or type(result["request_digest_hex"]) is not str
            or result["root_signature_valid"] is not True or result != expected_result(digest)):
        raise RootStatementError("root result does not bind the complete request")
    if expected.canonical_bytes != selected:
        raise RootStatementError("independent root selection changed during the check")
    return expected
