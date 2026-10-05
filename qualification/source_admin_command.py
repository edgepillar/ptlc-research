"""Isolated historical administrator command framing, never source authority.

The complete root selection and attenuation/revocation rule are independent
premises. No current revision lookup, store mutation, command deduplication,
application signer, admission or protected effect is connected.
"""

from dataclasses import dataclass
import hashlib
import json

from offline_session import governor_profile as governor
from qualification import source_root_roles as root


COMMAND_SCHEMA = "ptlc-observation-source-admin-command-v1"
ENVELOPE_SCHEMA = "ptlc-observation-source-admin-envelope-v1"
REQUEST_SCHEMA = "ptlc-observation-source-admin-request-v1"
RESULT_SCHEMA = "ptlc-observation-source-admin-result-v1"
RULE = "attenuate-or-revoke-v1"
COMMAND_DOMAIN = b"PTLC/observation-source-admin-command/v1\0"
REQUEST_DOMAIN = b"PTLC/observation-source-admin-request/v1\0"
MAX_WIRE_BYTES = 8192
MAX_EXPECTED_REVISION = (1 << 53)-2
_COMMAND_FIELDS = ("schema", "purpose", "algorithm", "administration_rule",
    "source_context", "root_declaration_digest_hex", "administrator_role",
    "administrator_key_hex", "original_command_id_hex", "expected_policy_revision",
    "old_profile", "new_profile", "old_active", "new_active", "operation")
_PACKET_FIELDS = ("schema", "root_envelope", "command", "admin_signature_hex")
_CAPS = ("max_attempt_limit", "max_target_limit")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError)
_canonical, _hex, _object = root._canonical, root._hex, root._object


class AdminCommandError(ValueError):
    """Sanitized invalid historical selection or unavailable public check."""


def _command(value, declaration):
    root._declaration(declaration)
    _object(value, _COMMAND_FIELDS)
    for field, fixed in (("schema", COMMAND_SCHEMA), ("purpose", "source-policy-command"),
            ("algorithm", "BIP340-SHA256"), ("administration_rule", RULE),
            ("administrator_role", "policy-administrator")):
        if type(value[field]) is not str or value[field] != fixed:
            raise AdminCommandError("unsupported administrator command rule")
    for field in ("root_declaration_digest_hex", "administrator_key_hex", "original_command_id_hex"):
        _hex(value[field], 32)
    if (value["root_declaration_digest_hex"] != hashlib.sha256(root.DECLARATION_DOMAIN + _canonical(declaration)).hexdigest()
            or value["administrator_key_hex"] != declaration["delegated_keys"]["policy_admin_key_hex"]):
        raise AdminCommandError("command changes its selected root or administrator")
    root.current._source_fields(value["source_context"])
    if value["source_context"] != declaration["source_context"]:
        raise AdminCommandError("command changes its complete source context")
    revision = value["expected_policy_revision"]
    if type(revision) is not int or not 0 <= revision <= MAX_EXPECTED_REVISION:
        raise AdminCommandError("invalid expected policy revision")
    old, new = governor._fields(value["old_profile"]), governor._fields(value["new_profile"])
    anchor = declaration["governor_profile"]
    for profile in (old, new):
        if (any(profile[f] != anchor[f] for f in anchor if f not in _CAPS)
                or any(profile[f] > anchor[f] for f in _CAPS)):
            raise AdminCommandError("profile exceeds the independently selected administration rule")
    if type(value["old_active"]) is not bool or type(value["new_active"]) is not bool or not value["old_active"]:
        raise AdminCommandError("only an independently selected active predecessor is supported")
    operation = value["operation"]
    if type(operation) is not str:
        raise AdminCommandError("invalid command operation")
    if operation == "reduce-limits":
        if (not value["new_active"] or any(new[f] > old[f] for f in _CAPS)
                or all(new[f] == old[f] for f in _CAPS)):
            raise AdminCommandError("limit reduction requires a strict componentwise decrease")
    elif operation == "revoke":
        if value["new_active"] or new != old:
            raise AdminCommandError("revocation preserves the complete profile")
    else:
        raise AdminCommandError("operation is outside the selected administration rule")
    return value


def _decode(wire):
    try:
        return root._decode(wire)
    except _ERRORS:
        raise AdminCommandError("invalid canonical administrator wire") from None


@dataclass(frozen=True, init=False)
class AdminCommand:
    """Independent unsigned historical selection, never an executable command."""

    _root_wire: bytes
    _wire: bytes

    def __init__(self):
        raise TypeError("use admin_command")

    def root_dict(self):
        if type(self) is not AdminCommand:
            raise AdminCommandError("an exact independent command selection is required")
        try:
            return root._declaration(_decode(self._root_wire))
        except _ERRORS:
            raise AdminCommandError("invalid independent root selection") from None

    def as_dict(self):
        if type(self) is not AdminCommand:
            raise AdminCommandError("an exact independent command selection is required")
        try:
            return _command(_decode(self._wire), self.root_dict())
        except _ERRORS:
            raise AdminCommandError("invalid independent command selection") from None

    @property
    def canonical_bytes(self):
        return _canonical(self.as_dict())

    @property
    def message_digest_hex(self):
        return hashlib.sha256(COMMAND_DOMAIN + self.canonical_bytes).hexdigest()


def admin_command(selected_root, *, operation, original_command_id_hex, expected_policy_revision,
        old_profile, new_profile, old_active, new_active):
    """Independently select one complete transition before receiving a packet."""
    if type(selected_root) is not root.RootDeclaration:
        raise AdminCommandError("an exact independent root selection is required")
    try:
        declaration = selected_root.as_dict()
        value = _command(dict(schema=COMMAND_SCHEMA, purpose="source-policy-command",
            algorithm="BIP340-SHA256", administration_rule=RULE, source_context=declaration["source_context"],
            root_declaration_digest_hex=selected_root.message_digest_hex, administrator_role="policy-administrator",
            administrator_key_hex=declaration["delegated_keys"]["policy_admin_key_hex"],
            original_command_id_hex=original_command_id_hex, expected_policy_revision=expected_policy_revision,
            old_profile=old_profile, new_profile=new_profile, old_active=old_active, new_active=new_active,
            operation=operation), declaration)
        result = object.__new__(AdminCommand)
        object.__setattr__(result, "_root_wire", _canonical(declaration))
        object.__setattr__(result, "_wire", _canonical(value))
        return result
    except _ERRORS:
        raise AdminCommandError("independent administrator command rejected") from None


def _packet(value, schema):
    _object(value, _PACKET_FIELDS)
    if type(value["schema"]) is not str or value["schema"] != schema:
        raise AdminCommandError("unsupported administrator packet")
    statement = root._packet(value["root_envelope"], root.ENVELOPE_SCHEMA)
    _command(value["command"], statement["declaration"])
    _hex(value["admin_signature_hex"], 64)
    return value


def envelope(expected, *, root_signature, admin_signature):
    """Package two supplied public signatures; perform no signing or mathematics."""
    if (type(expected) is not AdminCommand or any(type(s) is not bytes or len(s) != 64
            for s in (root_signature, admin_signature))):
        raise AdminCommandError("exact command selection and public signatures required")
    return _canonical(dict(schema=ENVELOPE_SCHEMA, root_envelope=dict(schema=root.ENVELOPE_SCHEMA,
        declaration=expected.root_dict(), root_signature_hex=root_signature.hex()),
        command=expected.as_dict(), admin_signature_hex=admin_signature.hex()))


def request(expected, envelope_bytes):
    if type(expected) is not AdminCommand:
        raise AdminCommandError("an exact independent command selection is required")
    try:
        value = _packet(_decode(envelope_bytes), ENVELOPE_SCHEMA)
        if (value["root_envelope"]["declaration"] != expected.root_dict()
                or _canonical(value["command"]) != expected.canonical_bytes):
            raise AdminCommandError("packet replaces its independent complete selection")
        value["schema"] = REQUEST_SCHEMA
        return value
    except _ERRORS:
        raise AdminCommandError("administrator request rejected") from None


def request_digest(value):
    try:
        wire = _canonical(_packet(value, REQUEST_SCHEMA))
        if len(wire) > MAX_WIRE_BYTES:
            raise AdminCommandError("administrator request exceeds its byte bound")
        return hashlib.sha256(REQUEST_DOMAIN + wire).hexdigest()
    except _ERRORS:
        raise AdminCommandError("invalid administrator request") from None


def expected_result(digest):
    """Transport shape only; it establishes neither mathematics nor permission."""
    _hex(digest, 32)
    return dict(schema=RESULT_SCHEMA, request_digest_hex=digest,
        root_signature_valid=True, administrator_signature_valid=True)


def verify_selected_command(expected, envelope_bytes, *, verifier):
    """Return the same unsigned historical selection under a selected check.

    A malicious callback can forge both positives. Replayed/restored selections
    still match. No current revision, committed transition or permission results.
    """
    value = request(expected, envelope_bytes)
    wire, digest = _canonical(value), request_digest(value)
    selected = (expected._root_wire, expected.canonical_bytes)
    if not callable(verifier):
        raise AdminCommandError("a selected public-only command check is required")
    try:
        result = verifier(json.loads(wire.decode("ascii")))
    except Exception:
        raise AdminCommandError("selected command check unavailable") from None
    if (type(result) is not dict or len(result) != 4 or any(type(key) is not str for key in result)
            or set(result) != {"schema", "request_digest_hex", "root_signature_valid", "administrator_signature_valid"}
            or type(result["schema"]) is not str or type(result["request_digest_hex"]) is not str
            or result["root_signature_valid"] is not True or result["administrator_signature_valid"] is not True
            or result != expected_result(digest)):
        raise AdminCommandError("command result does not bind the complete request")
    if (expected._root_wire, expected.canonical_bytes) != selected:
        raise AdminCommandError("independent command selection changed during the check")
    return expected
