"""Pure explicitly selected local governor-role rules, never role provenance.

Selecting this profile is an external trust decision. Matching returns the same
unsigned intent, not a certificate, registration, allowance or dispatch permit.
No signature, curve check, worker, journal, backend, clock or I/O runs here.
"""

from dataclasses import dataclass
import hashlib

from . import authority_contract as authority
from . import enrollment_contract as contract


SCHEMA = "ptlc-observation-governor-profile-v1"
MAX_PROFILE_BYTES = 4096
_FIXED = dict(schema=SCHEMA, purpose=contract.PURPOSE, role=contract.ROLE,
              algorithm=contract.ALGORITHM)
_SCOPE_PINS = ("authority_id_hex", "authority_epoch", "authority_profile_digest_hex",
               "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex")
_DIGESTS = ("owner_auth_key_hex", "resource_digest_hex", "authority_id_hex",
            "authority_profile_digest_hex", "verifier_profile_digest_hex",
            "pool_profile_digest_hex", "resource_profile_digest_hex")
_FIELDS = (*_FIXED, *_DIGESTS, "authority_epoch", "max_attempt_limit", "max_target_limit")


class GovernorProfileError(ValueError):
    """Sanitized malformed local profile or proposal-rule mismatch."""


def _fields(value):
    contract._object(value, _FIELDS)
    for field, expected in _FIXED.items():
        if type(value[field]) is not str or value[field] != expected:
            raise GovernorProfileError("unsupported governor profile")
    for field in _DIGESTS:
        contract._hex(value[field])
    for field, maximum in (("authority_epoch", authority.MAX_NUMBER),
                           ("max_attempt_limit", authority.MAX_LIMIT),
                           ("max_target_limit", authority.MAX_LIMIT)):
        number = value[field]
        if type(number) is not int or not 1 <= number <= maximum:
            raise GovernorProfileError("invalid governor profile number")
    return value


def _decode(wire):
    try:
        return _fields(contract._decode(wire, MAX_PROFILE_BYTES))
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise GovernorProfileError("invalid canonical governor profile") from None


@dataclass(frozen=True, init=False)
class GovernorProfile:
    """Immutable local rules; no verified governor or bootstrap authority."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use governor_profile")

    def as_dict(self):
        if type(self) is not GovernorProfile:
            raise GovernorProfileError("an exact independently selected governor profile is required")
        try:
            return _decode(self._wire)
        except AttributeError:
            raise GovernorProfileError("incomplete selected governor profile") from None

    @property
    def canonical_bytes(self):
        return contract._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return hashlib.sha256(b"PTLC/observation-governor-profile/v1\0" + self.canonical_bytes).hexdigest()


def governor_profile(resource, *, owner_auth_key_hex, authority_id_hex, authority_epoch,
                     authority_profile_digest_hex, verifier_profile_digest_hex,
                     pool_profile_digest_hex, resource_profile_digest_hex,
                     max_attempt_limit, max_target_limit):
    """Select rules independently of incoming profiles, intents or signatures.

    Key encoding and proposal bounds are checked. This does not establish curve
    membership, governor assignment, source equivalence or trustworthy selection.
    """
    if type(resource) is not contract.RetainedResource:
        raise GovernorProfileError("an exact independently selected resource is required")
    try:
        value = dict(_FIXED, resource_digest_hex=resource.digest_hex,
            owner_auth_key_hex=owner_auth_key_hex, authority_id_hex=authority_id_hex,
            authority_epoch=authority_epoch, authority_profile_digest_hex=authority_profile_digest_hex,
            verifier_profile_digest_hex=verifier_profile_digest_hex,
            pool_profile_digest_hex=pool_profile_digest_hex,
            resource_profile_digest_hex=resource_profile_digest_hex,
            max_attempt_limit=max_attempt_limit, max_target_limit=max_target_limit)
        wire = contract._canonical(_fields(value))
        if len(wire) > MAX_PROFILE_BYTES:
            raise GovernorProfileError("governor profile exceeds its byte bound")
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise GovernorProfileError("invalid independently selected governor profile") from None
    result = object.__new__(GovernorProfile)
    object.__setattr__(result, "_wire", wire)
    return result


def parse_governor_profile(expected, wire):
    """Refuse peer bootstrap/replacement; exact duplicate bytes remain replayable."""
    if type(expected) is not GovernorProfile:
        raise GovernorProfileError("an exact independently selected governor profile is required")
    incoming = contract._canonical(_decode(wire))
    if incoming != expected.canonical_bytes:
        raise GovernorProfileError("governor profile changes its local selection")
    return expected


def match_governor_profile(profile, intent):
    """Match explicit local rules and return the same unsigned proposal.

    Enrollment/request IDs are not role identity. Matching neither consumes nor
    refreshes quota. A stale or maliciously selected profile can still match;
    trusted provisioning, rotation and revocation remain external requirements.
    """
    if type(profile) is not GovernorProfile or type(intent) is not contract.EnrollmentIntent:
        raise GovernorProfileError("exact local governor profile and intent are required")
    try:
        rules, proposed = profile.as_dict(), intent.as_dict()
        scope = intent._scope.as_dict()
        if (any(proposed[field] != rules[field] for field in ("purpose", "role", "algorithm",
                "owner_auth_key_hex", "resource_digest_hex"))
                or any(scope[field] != rules[field] for field in _SCOPE_PINS)
                or scope["attempt_limit"] > rules["max_attempt_limit"]
                or scope["target_limit"] > rules["max_target_limit"]):
            raise GovernorProfileError("intent does not match local governor rules")
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise GovernorProfileError("governor proposal-rule match rejected") from None
    return intent
