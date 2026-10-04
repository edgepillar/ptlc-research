"""Pure bounded attempt/claim records for a prospective owned evidence store.

Canonical bytes and transition history are not persistence, provenance or truth.
Only a trusted future owner may commit a begin before invoking a selected worker,
then commit its exact result before returning it. No I/O or worker is connected.
"""

from dataclasses import dataclass
import hashlib
import json

from . import exchange, observation_evidence as evidence


SCHEMA = "ptlc-observation-records-v1"
MAX_RECORD_BYTES = 1024 * 1024
MAX_ATTEMPTS = 64
MAX_TARGETS = 64
_FIELDS = {"schema", "verifier_profile_digest_hex", "attempt_limit", "target_limit",
           "revision", "targets", "attempts"}
_TARGET_FIELDS = {"schema", "predicate", "binding_digest_hex", "evidence_key_hex",
                  "verifier_profile_digest_hex", "request_digest_hex"}
_ATTEMPT_FIELDS = {"id", "evidence_key_hex", "recheck", "started_revision",
                   "finished_revision", "outcome"}


class RecordError(ValueError):
    """Sanitized invalid records, exact-target mismatch or unsupported operation."""


class RecordExhausted(RecordError):
    pass


class RecordBusy(RecordError):
    pass


class RecordKnown(RecordError):
    pass


class RecordConflict(RecordError):
    pass


class RecordClosed(RecordError):
    pass


@dataclass(frozen=True)
class RecordSummary:
    revision: int
    attempts_consumed: int
    attempts_remaining: int
    targets: int
    targets_remaining: int
    pending_attempts: int
    verified_claims: int
    rejected_claims: int
    conflicting_targets: int


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _normal(value, key):
    return {attempt["outcome"] for attempt in value["attempts"]
            if attempt["evidence_key_hex"] == key and attempt["outcome"] in ("verified", "rejected")}


def _validate(value, profile):
    if (type(value) is not dict or set(value) != _FIELDS or value["schema"] != SCHEMA
            or value["verifier_profile_digest_hex"] != profile
            or not _integer(value["attempt_limit"], 1, MAX_ATTEMPTS)
            or not _integer(value["target_limit"], 1, MAX_TARGETS)
            or not _integer(value["revision"], 0, 2 * value["attempt_limit"])
            or type(value["targets"]) is not dict or type(value["attempts"]) is not list
            or len(value["targets"]) > value["target_limit"]
            or len(value["attempts"]) > value["attempt_limit"]):
        raise RecordError("invalid observation record structure")
    for key, fields in value["targets"].items():
        evidence._profile(key)
        if (type(fields) is not dict or set(fields) != _TARGET_FIELDS
                or any(type(item) is not str for item in fields.values())
                or fields["schema"] != evidence.STATEMENT_SCHEMA or fields["predicate"] != evidence.PREDICATE
                or fields["verifier_profile_digest_hex"] != profile or fields["evidence_key_hex"] != key):
            raise RecordError("invalid recorded target")
        for field in ("binding_digest_hex", "request_digest_hex"):
            evidence._profile(fields[field])
        material = exchange.canonical({"binding_digest_hex": fields["binding_digest_hex"],
                                       "predicate": evidence.PREDICATE, "verifier_profile_digest_hex": profile})
        if hashlib.sha256(b"PTLC/observation-evidence-key/v1\x00" + material).hexdigest() != key:
            raise RecordError("invalid recorded evidence key")
    events, referenced = [], set()
    prior_start = 0
    for number, attempt in enumerate(value["attempts"], 1):
        if (type(attempt) is not dict or set(attempt) != _ATTEMPT_FIELDS
                or type(attempt["id"]) is not int or attempt["id"] != number
                or type(attempt["evidence_key_hex"]) is not str
                or attempt["evidence_key_hex"] not in value["targets"]
                or type(attempt["recheck"]) is not bool
                or not _integer(attempt["started_revision"], prior_start + 1, value["revision"])):
            raise RecordError("invalid recorded attempt")
        prior_start = attempt["started_revision"]
        referenced.add(attempt["evidence_key_hex"])
        events.append((prior_start, "begin", attempt))
        if attempt["outcome"] is None:
            if attempt["finished_revision"] is not None:
                raise RecordError("invalid pending attempt")
        else:
            if (type(attempt["outcome"]) is not str or attempt["outcome"] not in evidence.OUTCOMES
                    or not _integer(attempt["finished_revision"], prior_start + 1, value["revision"])):
                raise RecordError("invalid finished attempt")
            events.append((attempt["finished_revision"], "finish", attempt))
    if referenced != set(value["targets"]) or sorted(event[0] for event in events) != list(range(1, value["revision"] + 1)):
        raise RecordError("incomplete observation transition history")
    # Reconstruct ordering rather than trusting only a plausible final snapshot.
    pending, normal = {}, {}
    for _, kind, attempt in sorted(events, key=lambda event: event[0]):
        key = attempt["evidence_key_hex"]
        decisions = normal.setdefault(key, set())
        if kind == "begin":
            if key in pending or len(decisions) == 2 or attempt["recheck"] != bool(decisions):
                raise RecordError("unreachable observation attempt history")
            pending[key] = attempt["id"]
        else:
            if pending.get(key) != attempt["id"]:
                raise RecordError("unowned observation result")
            del pending[key]
            if attempt["outcome"] in ("verified", "rejected"):
                decisions.add(attempt["outcome"])


def _decode(records, profile):
    try:
        evidence._profile(profile)
        if type(records) is not bytes or not records or len(records) > MAX_RECORD_BYTES:
            raise RecordError("invalid observation record size or type")
        value = json.loads(records.decode("ascii"))
        if exchange.canonical(value) != records:
            raise RecordError("observation records are not canonical")
        _validate(value, profile)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RecordError("observation records rejected") from None


def _encode(value):
    wire = exchange.canonical(value)
    _decode(wire, value["verifier_profile_digest_hex"])
    return wire


def _target(state, signature, profile):
    try:
        return evidence._fields(evidence.prepare(state, signature), profile)
    except evidence.EvidenceError:
        raise RecordError("invalid local observation target") from None


def _attempt(value, number):
    if not _integer(number, 1, len(value["attempts"])):
        raise RecordError("invalid local attempt identifier")
    attempt = value["attempts"][number - 1]
    if attempt["outcome"] is not None:
        raise RecordClosed("observation attempt already finished")
    return attempt


def create(*, verifier_profile_digest_hex, attempt_limit, target_limit):
    """Create a bounded pure record value, not a persistent ownership epoch."""
    try:
        evidence._profile(verifier_profile_digest_hex)
        if not _integer(attempt_limit, 1, MAX_ATTEMPTS) or not _integer(target_limit, 1, MAX_TARGETS):
            raise RecordError("invalid observation record limits")
        return _encode({"schema": SCHEMA, "verifier_profile_digest_hex": verifier_profile_digest_hex,
                        "attempt_limit": attempt_limit, "target_limit": target_limit,
                        "revision": 0, "targets": {}, "attempts": []})
    except evidence.EvidenceError:
        raise RecordError("invalid local verifier profile") from None


def inspect(records, *, expected_verifier_profile_digest_hex):
    """Validate canonical history and summarize claims, not mathematical truth."""
    value = _decode(records, expected_verifier_profile_digest_hex)
    outcomes = [_normal(value, key) for key in value["targets"]]
    return RecordSummary(value["revision"], len(value["attempts"]),
        value["attempt_limit"] - len(value["attempts"]), len(value["targets"]),
        value["target_limit"] - len(value["targets"]),
        sum(attempt["outcome"] is None for attempt in value["attempts"]),
        outcomes.count({"verified"}), outcomes.count({"rejected"}),
        sum(len(items) == 2 for items in outcomes))


def begin(records, state, signature, *, expected_verifier_profile_digest_hex, recheck=False):
    """Return the charged pending revision and its monotonically assigned ID.

    A future owned backend must durably commit these bytes before worker start.
    Known claims require explicit recheck; unknown attempts never refund quota.
    """
    value = _decode(records, expected_verifier_profile_digest_hex)
    if type(recheck) is not bool:
        raise RecordError("an exact local recheck choice is required")
    if len(value["attempts"]) >= value["attempt_limit"]:
        raise RecordExhausted("observation attempt limit exhausted")
    fields = _target(state, signature, expected_verifier_profile_digest_hex)
    key = fields["evidence_key_hex"]
    decisions = _normal(value, key)
    if len(decisions) == 2:
        raise RecordConflict("conflicting normal observation claims")
    if any(attempt["evidence_key_hex"] == key and attempt["outcome"] is None for attempt in value["attempts"]):
        raise RecordBusy("observation target has a pending attempt")
    if decisions and not recheck:
        raise RecordKnown("normal observation claim already recorded")
    if recheck and not decisions:
        raise RecordError("recheck requires a prior normal observation claim")
    if key not in value["targets"]:
        if len(value["targets"]) >= value["target_limit"]:
            raise RecordExhausted("observation target limit exhausted")
        value["targets"][key] = fields
    elif value["targets"][key] != fields:
        raise RecordError("observation target binding mismatch")
    number = len(value["attempts"]) + 1
    value["revision"] += 1
    value["attempts"].append({"id": number, "evidence_key_hex": key, "recheck": recheck,
                              "started_revision": value["revision"], "finished_revision": None, "outcome": None})
    return _encode(value), number


def finish(records, state, signature, attempt_id, statement, *, expected_verifier_profile_digest_hex):
    """Append one exact locally supplied claim; peer claims must not be trusted.

    Invalid results leave the pending revision charged and require an owner's
    explicit unknown transition. Contradictory normal claims are both retained.
    This function authenticates neither the producer nor the caller's state.
    """
    value = _decode(records, expected_verifier_profile_digest_hex)
    attempt = _attempt(value, attempt_id)
    try:
        parsed = evidence.parse_statement(state, signature, statement,
            expected_verifier_profile_digest_hex=expected_verifier_profile_digest_hex)
    except evidence.EvidenceError:
        raise RecordError("observation result is not exactly bound") from None
    if parsed.evidence_key_hex != attempt["evidence_key_hex"]:
        raise RecordError("observation result belongs to another attempt target")
    fields = value["targets"][attempt["evidence_key_hex"]]
    result = json.loads(statement)
    if any(result[field] != item for field, item in fields.items()):
        raise RecordError("observation result target mismatch")
    value["revision"] += 1
    attempt["finished_revision"] = value["revision"]
    attempt["outcome"] = parsed.outcome
    return _encode(value)


def interrupt(records, attempt_id, *, expected_verifier_profile_digest_hex):
    """An owning caller may explicitly finish lost work as unknown, not false.

    A future backend must exclude live/stale workers before performing recovery.
    The pure record cannot detect a crash, cancellation, ownership or stale writer.
    """
    value = _decode(records, expected_verifier_profile_digest_hex)
    attempt = _attempt(value, attempt_id)
    value["revision"] += 1
    attempt["finished_revision"] = value["revision"]
    attempt["outcome"] = "unknown"
    return _encode(value)


def known_statement(records, state, signature, *, expected_verifier_profile_digest_hex):
    """Return one exact normal claim or None; conflicting claims fail closed.

    This supplies no worker authenticity, durable cache admission or authority.
    Pending/unknown rechecks cannot erase an earlier unchanged normal claim.
    """
    value = _decode(records, expected_verifier_profile_digest_hex)
    fields = _target(state, signature, expected_verifier_profile_digest_hex)
    key = fields["evidence_key_hex"]
    decisions = _normal(value, key)
    if len(decisions) == 2:
        raise RecordConflict("conflicting normal observation claims")
    if not decisions:
        return None
    if value["targets"].get(key) != fields:
        raise RecordError("observation target binding mismatch")
    return exchange.canonical(dict(fields, outcome=next(iter(decisions))))
