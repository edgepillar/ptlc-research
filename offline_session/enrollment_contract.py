"""Pure candidate retained-resource key and unsigned owner enrollment intent.

Exact public-source equality is a selected comparison unit, not economic or
chain-source equivalence. Pins are independently selected local inputs, not
peer claims. No signature, owner authorization, registry, worker or I/O runs.
"""

from dataclasses import dataclass
import hashlib
import json
import re

from . import authority_contract as authority


RESOURCE_SCHEMA = "ptlc-observation-retained-resource-v1"
RESOURCE_KIND = "exact-paired-release-v1"
INTENT_SCHEMA = "ptlc-observation-enrollment-intent-v1"
PURPOSE = "observation-enrollment"
ROLE = "enrollment-governor"
ALGORITHM = "BIP340-SHA256"
MAX_RESOURCE_BYTES = 4096
MAX_INTENT_BYTES = 4096
SOURCE_FIELDS = ("session_id", "terms_digest_hex", "bitcoin_context_digest_hex",
    "zenon_context_digest_hex", "bitcoin_bundle_digest_hex", "zenon_bundle_digest_hex",
    "release_digest_hex")
_SELECTION_FIELDS = ("authority_id_hex", "enrollment_id_hex", "authority_epoch",
    "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex",
    "resource_profile_digest_hex", "attempt_limit", "target_limit")
_RESOURCE_FIELDS = ("schema", "predicate", "resource_kind", *SOURCE_FIELDS)
_INTENT_FIELDS = ("schema", "purpose", "role", "algorithm", "resource_digest_hex",
    "scope_digest_hex", "owner_auth_key_hex", "request_id_hex")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class EnrollmentContractError(ValueError):
    """Sanitized malformed public bytes or mismatch to local selections."""


def _hex(value):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise EnrollmentContractError("invalid enrollment digest or public-key encoding")


def _object(value, fields):
    if type(value) is not dict or any(type(key) is not str for key in value) or set(value) != set(fields):
        raise EnrollmentContractError("invalid enrollment contract fields")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(domain, wire):
    return hashlib.sha256(domain + wire).hexdigest()


def _decode(wire, maximum):
    if type(wire) is not bytes or not 1 <= len(wire) <= maximum:
        raise EnrollmentContractError("invalid enrollment wire size or type")
    try:
        value = json.loads(wire.decode("ascii"))
        if _canonical(value) != wire:
            raise EnrollmentContractError("noncanonical enrollment wire")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise EnrollmentContractError("invalid canonical enrollment wire") from None


def _scope_fields(scope):
    if type(scope) is not authority.AuthorityScope:
        raise EnrollmentContractError("an exact locally selected authority scope is required")
    try:
        return scope.as_dict()
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise EnrollmentContractError("invalid locally selected authority scope") from None


def _resource_fields(value):
    _object(value, _RESOURCE_FIELDS)
    for key, expected in (("schema", RESOURCE_SCHEMA), ("predicate", "zenon-completion-v1"),
                          ("resource_kind", RESOURCE_KIND)):
        if type(value[key]) is not str or value[key] != expected:
            raise EnrollmentContractError("unsupported retained-resource selection")
    for key in SOURCE_FIELDS:
        _hex(value[key])
    return value


def _source_resource(scope):
    fields = _scope_fields(scope)
    return _resource_fields(dict(schema=RESOURCE_SCHEMA, predicate=fields["predicate"],
        resource_kind=RESOURCE_KIND, **{key: fields[key] for key in SOURCE_FIELDS}))


@dataclass(frozen=True, init=False)
class RetainedResource:
    """Exact public-content key, never canonical-source or enrollment evidence."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use retained_resource")

    def as_dict(self):
        if type(self) is not RetainedResource:
            raise EnrollmentContractError("an exact locally selected retained resource is required")
        try:
            return _resource_fields(_decode(self._wire, MAX_RESOURCE_BYTES))
        except AttributeError:
            raise EnrollmentContractError("incomplete selected retained resource") from None

    @property
    def canonical_bytes(self):
        return _canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _digest(b"PTLC/observation-retained-resource/v1\x00", self.canonical_bytes)


def retained_resource(scope):
    """Exclude caller selections while retaining exact paired-source bindings.

    A different retained source has a different content key. No source trust,
    semantic equivalence, owner, namespace, allocation or fresh quota follows.
    """
    wire = _canonical(_source_resource(scope))
    if len(wire) > MAX_RESOURCE_BYTES:
        raise EnrollmentContractError("retained resource exceeds its byte bound")
    result = object.__new__(RetainedResource)
    object.__setattr__(result, "_wire", wire)
    return result


def parse_retained_resource(expected, wire):
    """Match an independently prepared content key without adopting peer pins."""
    if type(expected) is not RetainedResource:
        raise EnrollmentContractError("an exact locally selected retained resource is required")
    value = _resource_fields(_decode(wire, MAX_RESOURCE_BYTES))
    if _canonical(value) != expected.canonical_bytes:
        raise EnrollmentContractError("retained resource changes its local selection")
    return expected


def _intent_fields(value, scope, resource):
    _object(value, _INTENT_FIELDS)
    selected = _scope_fields(scope)
    if type(resource) is not RetainedResource:
        raise EnrollmentContractError("an exact locally selected retained resource is required")
    if resource.canonical_bytes != _canonical(_source_resource(scope)):
        raise EnrollmentContractError("scope changes the selected retained resource")
    for key, expected in (("schema", INTENT_SCHEMA), ("purpose", PURPOSE),
                          ("role", ROLE), ("algorithm", ALGORITHM)):
        if type(value[key]) is not str or value[key] != expected:
            raise EnrollmentContractError("unsupported unsigned enrollment intent")
    for key in ("resource_digest_hex", "scope_digest_hex", "owner_auth_key_hex", "request_id_hex"):
        _hex(value[key])
    scope_digest = _digest(b"PTLC/observation-authority-scope/v1\x00", _canonical(selected))
    if value["resource_digest_hex"] != resource.digest_hex or value["scope_digest_hex"] != scope_digest:
        raise EnrollmentContractError("unsigned intent changes its selected source or scope")
    return value


@dataclass(frozen=True, init=False)
class EnrollmentIntent:
    """Unsigned locally bound proposal, never owner verification or permission."""

    _scope: authority.AuthorityScope
    _resource: RetainedResource
    _wire: bytes

    def __init__(self):
        raise TypeError("use enrollment_intent")

    def as_dict(self):
        if type(self) is not EnrollmentIntent:
            raise EnrollmentContractError("an exact locally prepared enrollment intent is required")
        try:
            return _intent_fields(_decode(self._wire, MAX_INTENT_BYTES), self._scope, self._resource)
        except AttributeError:
            raise EnrollmentContractError("incomplete selected enrollment intent") from None

    @property
    def canonical_bytes(self):
        return _canonical(self.as_dict())

    @property
    def message_digest_hex(self):
        """Candidate public BIP340 message; no curve, signature or key is used."""
        return _digest(b"PTLC/observation-enrollment-owner-intent/v1\x00", self.canonical_bytes)


def enrollment_intent(state, scope, resource, *, owner_auth_key_hex, request_id_hex):
    """Bind a live retained snapshot, expected resource and independent owner pin.

    The key encoding is checked, not curve membership, control, provenance or
    role assignment. This proposal signs/verifies nothing and applies no state.
    """
    selected = _scope_fields(scope)
    _hex(owner_auth_key_hex)
    _hex(request_id_hex)
    if type(resource) is not RetainedResource:
        raise EnrollmentContractError("an exact locally selected retained resource is required")
    value = dict(schema=INTENT_SCHEMA, purpose=PURPOSE, role=ROLE, algorithm=ALGORITHM,
        resource_digest_hex=resource.digest_hex, scope_digest_hex=scope.digest_hex,
        owner_auth_key_hex=owner_auth_key_hex, request_id_hex=request_id_hex)
    _intent_fields(value, scope, resource)
    try:
        current = authority.authority_scope(state, **{key: selected[key] for key in _SELECTION_FIELDS})
        if current.canonical_bytes != scope.canonical_bytes:
            raise EnrollmentContractError("retained source changed after local scope selection")
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise EnrollmentContractError("enrollment source binding rejected") from None
    wire = _canonical(value)
    if len(wire) > MAX_INTENT_BYTES:
        raise EnrollmentContractError("enrollment intent exceeds its byte bound")
    result = object.__new__(EnrollmentIntent)
    for name, field in (("_scope", scope), ("_resource", resource), ("_wire", wire)):
        object.__setattr__(result, name, field)
    return result


def parse_enrollment_intent(expected, wire):
    """Match unsigned bytes, allowing replay and granting no owner authority."""
    if type(expected) is not EnrollmentIntent:
        raise EnrollmentContractError("an exact locally prepared enrollment intent is required")
    selected = expected.as_dict()
    incoming = _intent_fields(_decode(wire, MAX_INTENT_BYTES), expected._scope, expected._resource)
    if _canonical(incoming) != _canonical(selected):
        raise EnrollmentContractError("unsigned intent changes its local selection")
    return expected
