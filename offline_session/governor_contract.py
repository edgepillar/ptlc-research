"""Unsigned governor assignment and complete-profile-bound owner framing.

Issuer/profile selections are external inputs, not authenticated provisioning
or current authority. Matching returns the same unsigned object. No signature,
curve arithmetic, I/O, worker, registry, quota or current-state service runs.
"""

from dataclasses import dataclass

from . import enrollment_contract as enrollment
from . import governor_profile as governor


ASSIGNMENT_SCHEMA = "ptlc-observation-governor-assignment-v1"
ASSIGNMENT_PURPOSE = "observation-governor-assignment"
BOUND_INTENT_SCHEMA = "ptlc-observation-enrollment-intent-v2"
MAX_ASSIGNMENT_BYTES = 4096
MAX_BOUND_INTENT_BYTES = 4096
_ASSIGNMENT_FIELDS = ("schema", "purpose", "algorithm", "issuer_auth_key_hex", "governor_profile")
_BOUND_FIELDS = (*enrollment._INTENT_FIELDS, "governor_assignment_digest_hex")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError)


class GovernorContractError(ValueError):
    """Sanitized malformed unsigned framing or changed independent selections."""


def _profile(profile):
    if type(profile) is not governor.GovernorProfile:
        raise GovernorContractError("an exact independently selected governor profile is required")
    return profile.as_dict()


def _assignment_fields(value, profile):
    enrollment._object(value, _ASSIGNMENT_FIELDS)
    for field, expected in (("schema", ASSIGNMENT_SCHEMA), ("purpose", ASSIGNMENT_PURPOSE),
                            ("algorithm", enrollment.ALGORITHM)):
        if type(value[field]) is not str or value[field] != expected:
            raise GovernorContractError("unsupported unsigned governor assignment")
    enrollment._hex(value["issuer_auth_key_hex"])
    selected = _profile(profile)
    governor._fields(value["governor_profile"])
    if value["governor_profile"] != selected:
        raise GovernorContractError("assignment changes its complete selected profile")
    return value


@dataclass(frozen=True, init=False)
class GovernorAssignment:
    """Candidate unsigned issuer message; never an issued role certificate."""

    _profile: governor.GovernorProfile
    _wire: bytes

    def __init__(self):
        raise TypeError("use governor_assignment")

    def as_dict(self):
        if type(self) is not GovernorAssignment:
            raise GovernorContractError("an exact independently prepared governor assignment is required")
        try:
            return _assignment_fields(enrollment._decode(self._wire, MAX_ASSIGNMENT_BYTES), self._profile)
        except _ERRORS:
            raise GovernorContractError("invalid independently prepared governor assignment") from None

    @property
    def canonical_bytes(self):
        return enrollment._canonical(self.as_dict())

    @property
    def digest_hex(self):
        """Candidate issuer message/content digest; no signature or trust fact."""
        return enrollment._digest(b"PTLC/observation-governor-assignment/v1\0", self.canonical_bytes)


def governor_assignment(profile, *, issuer_auth_key_hex):
    """Bind an independent issuer encoding to every complete local profile field.

The opaque authority profile pin is not this assignment's digest. Independent
selection, curve membership, role issuance and currentness are not established.
"""
    try:
        value = dict(schema=ASSIGNMENT_SCHEMA, purpose=ASSIGNMENT_PURPOSE,
            algorithm=enrollment.ALGORITHM, issuer_auth_key_hex=issuer_auth_key_hex,
            governor_profile=_profile(profile))
        wire = enrollment._canonical(_assignment_fields(value, profile))
        if len(wire) > MAX_ASSIGNMENT_BYTES:
            raise GovernorContractError("governor assignment exceeds its byte bound")
    except _ERRORS:
        raise GovernorContractError("governor assignment preparation rejected") from None
    result = object.__new__(GovernorAssignment)
    object.__setattr__(result, "_profile", profile)
    object.__setattr__(result, "_wire", wire)
    return result


def parse_governor_assignment(expected, wire):
    """Require the independent complete expectation; replay grants nothing."""
    if type(expected) is not GovernorAssignment:
        raise GovernorContractError("an exact independently prepared governor assignment is required")
    try:
        selected = expected.canonical_bytes
        incoming = _assignment_fields(enrollment._decode(wire, MAX_ASSIGNMENT_BYTES), expected._profile)
        if enrollment._canonical(incoming) != selected:
            raise GovernorContractError("assignment changes its independent issuer selection")
    except _ERRORS:
        raise GovernorContractError("governor assignment selection rejected") from None
    return expected


def _bound_fields(value, assignment, intent):
    enrollment._object(value, _BOUND_FIELDS)
    if type(assignment) is not GovernorAssignment or type(intent) is not enrollment.EnrollmentIntent:
        raise GovernorContractError("exact independently prepared assignment and legacy intent are required")
    assignment.as_dict()
    governor.match_governor_profile(assignment._profile, intent)
    selected = dict(intent.as_dict(), schema=BOUND_INTENT_SCHEMA,
                    governor_assignment_digest_hex=assignment.digest_hex)
    for field in _BOUND_FIELDS:
        if type(value[field]) is not str or value[field] != selected[field]:
            raise GovernorContractError("bound intent changes its complete independent selection")
    return value


@dataclass(frozen=True, init=False)
class BoundEnrollmentIntent:
    """New unsigned v2 proposal; never a verifier result or admission token."""

    _assignment: GovernorAssignment
    _intent: enrollment.EnrollmentIntent
    _wire: bytes

    def __init__(self):
        raise TypeError("use bound_enrollment_intent")

    def as_dict(self):
        if type(self) is not BoundEnrollmentIntent:
            raise GovernorContractError("an exact independently prepared bound intent is required")
        try:
            return _bound_fields(enrollment._decode(self._wire, MAX_BOUND_INTENT_BYTES), self._assignment, self._intent)
        except _ERRORS:
            raise GovernorContractError("invalid independently prepared bound intent") from None

    @property
    def canonical_bytes(self):
        return enrollment._canonical(self.as_dict())

    @property
    def message_digest_hex(self):
        return enrollment._digest(b"PTLC/observation-enrollment-owner-intent/v2\0", self.canonical_bytes)


def bound_enrollment_intent(assignment, intent):
    """Explicitly prepare separate v2 bytes; do not reinterpret a v1 signature.

The retained v1 expectation and profile are revalidated. No source is reread,
and no fresh authority, assignment signature or owner signature is established.
"""
    if type(assignment) is not GovernorAssignment or type(intent) is not enrollment.EnrollmentIntent:
        raise GovernorContractError("exact independently prepared assignment and legacy intent are required")
    try:
        value = dict(intent.as_dict(), schema=BOUND_INTENT_SCHEMA,
                    governor_assignment_digest_hex=assignment.digest_hex)
        wire = enrollment._canonical(_bound_fields(value, assignment, intent))
        if len(wire) > MAX_BOUND_INTENT_BYTES:
            raise GovernorContractError("bound enrollment intent exceeds its byte bound")
    except _ERRORS:
        raise GovernorContractError("bound enrollment intent preparation rejected") from None
    result = object.__new__(BoundEnrollmentIntent)
    for field, value in (("_assignment", assignment), ("_intent", intent), ("_wire", wire)):
        object.__setattr__(result, field, value)
    return result


def parse_bound_enrollment_intent(expected, wire):
    """Exact unsigned v2 match, not freshness, signature, replay defense or use."""
    if type(expected) is not BoundEnrollmentIntent:
        raise GovernorContractError("an exact independently prepared bound intent is required")
    try:
        selected = expected.canonical_bytes
        incoming = _bound_fields(enrollment._decode(wire, MAX_BOUND_INTENT_BYTES), expected._assignment, expected._intent)
        if enrollment._canonical(incoming) != selected:
            raise GovernorContractError("bound intent changes its local selection")
    except _ERRORS:
        raise GovernorContractError("bound enrollment intent selection rejected") from None
    return expected
