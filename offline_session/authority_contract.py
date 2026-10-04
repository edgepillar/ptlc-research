"""Pure candidate wire contract for a prospective observation authority.

All IDs, profiles, epochs and expected heads are selected outside this codec.
Bound requests/reply claims prove neither enrollment, authentication, freshness,
durability nor single-use dispatch. No authority, worker, journal or I/O runs.
"""

from dataclasses import dataclass
import hashlib
import json
import re

from . import completion, exchange, observation_evidence as evidence


SCOPE_SCHEMA = "ptlc-observation-authority-scope-v1"
REQUEST_SCHEMA = "ptlc-observation-authority-request-v1"
REPLY_SCHEMA = "ptlc-observation-authority-reply-claim-v1"
MAX_NUMBER = (1 << 53) - 1
MAX_LIMIT = 64
MAX_SCOPE_BYTES = 4096
MAX_WIRE_BYTES = 16384
OPERATIONS = ("reserve", "dispatch", "publish", "resolve-unknown")
SUCCESS = {"reserve": "reserved", "dispatch": "dispatch-recorded",
           "publish": "result-recorded", "resolve-unknown": "unknown-recorded"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SELECTION = ("authority_id_hex", "enrollment_id_hex", "authority_epoch",
              "authority_profile_digest_hex", "verifier_profile_digest_hex",
              "pool_profile_digest_hex", "resource_profile_digest_hex", "attempt_limit", "target_limit")
_BINDING = ("session_id", "terms_digest_hex", "bitcoin_context_digest_hex", "zenon_context_digest_hex",
            "bitcoin_bundle_digest_hex", "zenon_bundle_digest_hex", "release_digest_hex")
_HEAD = {"revision", "state_digest_hex", "consumed", "pending_attempt_id", "dispatch_recorded"}
_TARGET = {"evidence_key_hex", "binding_digest_hex", "request_digest_hex"}
_REQUEST = {"schema", "operation", "scope_digest_hex", "authority_epoch", "request_id_hex",
            "expected_head", "target", "attempt_id", "statement_hex"}
_REPLY = {"schema", "operation", "scope_digest_hex", "authority_epoch", "request_id_hex",
          "request_digest_hex", "before_head", "status", "after_head", "attempt_id"}


class AuthorityContractError(ValueError):
    """Sanitized malformed contract or mismatch to locally selected inputs."""


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _hex(value):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise AuthorityContractError("invalid authority digest encoding")


def _object(value, fields):
    if type(value) is not dict or any(type(key) is not str for key in value) or set(value) != set(fields):
        raise AuthorityContractError("invalid authority contract fields")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(domain, wire):
    return hashlib.sha256(domain + wire).hexdigest()


def _decode(wire, maximum):
    if type(wire) is not bytes or not 1 <= len(wire) <= maximum:
        raise AuthorityContractError("invalid authority wire size or type")
    try:
        value = json.loads(wire.decode("ascii"))
        if _canonical(value) != wire:
            raise AuthorityContractError("noncanonical authority wire")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise AuthorityContractError("invalid canonical authority wire") from None


def _selection(fields):
    for key in _SELECTION:
        value = fields[key]
        if key == "authority_epoch":
            if not _integer(value, 1, MAX_NUMBER):
                raise AuthorityContractError("invalid selected authority epoch")
        elif key in ("attempt_limit", "target_limit"):
            if not _integer(value, 1, MAX_LIMIT):
                raise AuthorityContractError("invalid selected authority limit")
        else:
            _hex(value)


def _scope_fields(value):
    _object(value, ("schema", "predicate", *_SELECTION, *_BINDING))
    if (type(value["schema"]) is not str or value["schema"] != SCOPE_SCHEMA
            or type(value["predicate"]) is not str or value["predicate"] != evidence.PREDICATE):
        raise AuthorityContractError("unsupported authority scope")
    _selection(value)
    for key in _BINDING:
        _hex(value[key])
    return value


@dataclass(frozen=True, init=False)
class AuthorityScope:
    """Immutable selected public context, not an enrollment certificate."""

    _wire: bytes

    def __init__(self):
        raise TypeError("use authority_scope")

    def as_dict(self):
        if type(self) is not AuthorityScope:
            raise AuthorityContractError("an exact selected authority scope is required")
        try:
            return _scope_fields(_decode(self._wire, MAX_SCOPE_BYTES))
        except AttributeError:
            raise AuthorityContractError("incomplete selected authority scope") from None

    @property
    def canonical_bytes(self):
        return _canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _digest(b"PTLC/observation-authority-scope/v1\x00", self.canonical_bytes)


def authority_scope(state, *, authority_id_hex, enrollment_id_hex, authority_epoch,
                    authority_profile_digest_hex, verifier_profile_digest_hex,
                    pool_profile_digest_hex, resource_profile_digest_hex, attempt_limit, target_limit):
    """Bind retained release context and independently selected external inputs.

    No ID is minted or accepted from a peer reply. Candidate bytes and local
    paths are excluded so that different targets/copies share the selected scope.
    Choosing a new ID or epoch here does not obtain external enrollment or quota.
    """
    fields = dict(zip(_SELECTION, (authority_id_hex, enrollment_id_hex, authority_epoch,
        authority_profile_digest_hex, verifier_profile_digest_hex, pool_profile_digest_hex,
        resource_profile_digest_hex, attempt_limit, target_limit)))
    _selection(fields)
    if type(state) is not dict:
        raise AuthorityContractError("a plain retained release snapshot is required")
    try:
        snapshot = exchange._at(state, "RELEASE_RECORDED")
        bitcoin, zenon = exchange.contexts(snapshot)
        fields.update(schema=SCOPE_SCHEMA, predicate=evidence.PREDICATE,
            session_id=bitcoin.session_id,
            terms_digest_hex=bitcoin.as_dict()["binding"]["terms_digest_hex"],
            bitcoin_context_digest_hex=bitcoin.digest_hex, zenon_context_digest_hex=zenon.digest_hex,
            bitcoin_bundle_digest_hex=_digest(b"PTLC/authority-bitcoin-bundle/v1\x00",
                                             exchange.canonical(snapshot["bitcoin_bundle"])),
            zenon_bundle_digest_hex=_digest(b"PTLC/authority-zenon-bundle/v1\x00",
                                           exchange.canonical(snapshot["zenon_bundle"])),
            release_digest_hex=_digest(b"PTLC/authority-release/v1\x00", bytes.fromhex(snapshot["release_hex"])))
        wire = _canonical(_scope_fields(fields))
        if len(wire) > MAX_SCOPE_BYTES:
            raise AuthorityContractError("authority scope exceeds its byte bound")
        result = object.__new__(AuthorityScope)
        object.__setattr__(result, "_wire", wire)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise AuthorityContractError("authority release binding rejected") from None


def _head_fields(value, limit):
    _object(value, _HEAD)
    _hex(value["state_digest_hex"])
    pending = value["pending_attempt_id"]
    if (not _integer(value["revision"], 0, MAX_NUMBER)
            or not _integer(value["consumed"], 0, limit)
            or value["revision"] < value["consumed"]
            or type(value["dispatch_recorded"]) is not bool
            or (pending is None and value["dispatch_recorded"])
            or (pending is not None and (not _integer(pending, 1, value["consumed"])
                                         or pending != value["consumed"]))):
        raise AuthorityContractError("invalid authority head claim")
    return value


@dataclass(frozen=True)
class AuthorityHead:
    """Explicit public head labels; no authenticated latest-head provenance."""

    revision: int
    state_digest_hex: str
    consumed: int
    pending_attempt_id: object = None
    dispatch_recorded: bool = False

    def __post_init__(self):
        self.as_dict()

    def as_dict(self):
        if type(self) is not AuthorityHead:
            raise AuthorityContractError("an exact authority head is required")
        try:
            return _head_fields({key: getattr(self, key) for key in _HEAD}, MAX_LIMIT)
        except AttributeError:
            raise AuthorityContractError("incomplete selected authority head") from None


def _phase(value, scope):
    _object(value, _REQUEST)
    operation = value["operation"]
    if (type(value["schema"]) is not str or value["schema"] != REQUEST_SCHEMA
            or type(operation) is not str or operation not in OPERATIONS
            or value["scope_digest_hex"] != scope.digest_hex
            or type(value["authority_epoch"]) is not int
            or value["authority_epoch"] != scope.as_dict()["authority_epoch"]):
        raise AuthorityContractError("authority request changes its selected scope")
    _hex(value["scope_digest_hex"])
    _hex(value["request_id_hex"])
    fields = scope.as_dict()
    head = _head_fields(value["expected_head"], fields["attempt_limit"])
    if head["revision"] >= MAX_NUMBER:
        raise AuthorityContractError("authority head cannot advance without reviewed epoch handling")
    _object(value["target"], _TARGET)
    for digest in value["target"].values():
        _hex(digest)
    attempt = value["attempt_id"]
    statement = value["statement_hex"]
    if operation == "reserve":
        if (attempt is not None or statement is not None or head["pending_attempt_id"] is not None
                or head["consumed"] >= fields["attempt_limit"]):
            raise AuthorityContractError("reserve requires an available nonpending head")
    elif (not _integer(attempt, 1, fields["attempt_limit"]) or attempt != head["pending_attempt_id"]
          or (operation == "dispatch" and head["dispatch_recorded"])
          or (operation == "publish" and not head["dispatch_recorded"])
          or (operation != "publish" and statement is not None)):
        raise AuthorityContractError("authority request contradicts its pending phase")
    if operation == "publish":
        if (type(statement) is not str or not 2 <= len(statement) <= 2 * evidence.MAX_STATEMENT_BYTES
                or len(statement) % 2 or re.fullmatch(r"[0-9a-f]+", statement) is None):
            raise AuthorityContractError("invalid public statement encoding")
        claim = _decode(bytes.fromhex(statement), evidence.MAX_STATEMENT_BYTES)
        _object(claim, evidence._STATEMENT_FIELDS)
        if (claim["schema"] != evidence.STATEMENT_SCHEMA or claim["predicate"] != evidence.PREDICATE
                or type(claim["outcome"]) is not str or claim["outcome"] not in evidence.OUTCOMES
                or claim["verifier_profile_digest_hex"] != fields["verifier_profile_digest_hex"]
                or any(claim[key] != digest for key, digest in value["target"].items())):
            raise AuthorityContractError("public statement changes the selected target")
    return value


@dataclass(frozen=True, init=False)
class AuthorityRequest:
    """A locally prepared exact request, never a worker-start capability."""

    _scope: AuthorityScope
    _wire: bytes

    def __init__(self):
        raise TypeError("use authority_request")

    def as_dict(self):
        if type(self) is not AuthorityRequest:
            raise AuthorityContractError("an exact locally selected request is required")
        try:
            if type(self._scope) is not AuthorityScope:
                raise AuthorityContractError("an exact selected scope is required")
            return _phase(_decode(self._wire, MAX_WIRE_BYTES), self._scope)
        except AttributeError:
            raise AuthorityContractError("incomplete selected authority request") from None

    @property
    def canonical_bytes(self):
        return _canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _digest(b"PTLC/observation-authority-request/v1\x00", self.canonical_bytes)


def authority_request(scope, state, signature, *, operation, request_id_hex, expected_head,
                      attempt_id=None, statement=None):
    """Prepare a bound operation without contacting or charging an authority."""
    if type(scope) is not AuthorityScope or type(expected_head) is not AuthorityHead:
        raise AuthorityContractError("exact selected scope and expected head are required")
    fields = scope.as_dict()
    head = _head_fields(expected_head.as_dict(), fields["attempt_limit"])
    if type(operation) is not str or operation not in OPERATIONS:
        raise AuthorityContractError("an explicit authority operation is required")
    _hex(request_id_hex)
    if statement is not None and (type(statement) is not bytes or not 1 <= len(statement) <= evidence.MAX_STATEMENT_BYTES):
        raise AuthorityContractError("invalid public statement size or type")
    try:
        fresh = authority_scope(state, **{key: fields[key] for key in _SELECTION})
        if fresh.canonical_bytes != scope.canonical_bytes:
            raise AuthorityContractError("authority scope changed its retained release")
        target = evidence.prepare(state, signature)
        target_fields = evidence._fields(target, fields["verifier_profile_digest_hex"])
        if operation == "publish":
            evidence.parse_statement(state, signature, statement,
                                     expected_verifier_profile_digest_hex=fields["verifier_profile_digest_hex"])
        value = {"schema": REQUEST_SCHEMA, "operation": operation, "scope_digest_hex": scope.digest_hex,
                 "authority_epoch": fields["authority_epoch"], "request_id_hex": request_id_hex,
                 "expected_head": head, "target": {key: target_fields[key] for key in _TARGET},
                 "attempt_id": attempt_id, "statement_hex": None if statement is None else statement.hex()}
        wire = _canonical(_phase(value, scope))
        if len(wire) > MAX_WIRE_BYTES:
            raise AuthorityContractError("authority request exceeds its byte bound")
        result = object.__new__(AuthorityRequest)
        object.__setattr__(result, "_scope", scope)
        object.__setattr__(result, "_wire", wire)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise AuthorityContractError("authority request preparation rejected") from None


def parse_request(expected_request, wire):
    """Match exact locally prepared bytes; no peer admission is authorized."""
    if type(expected_request) is not AuthorityRequest:
        raise AuthorityContractError("an exact selected authority request is required")
    _decode(wire, MAX_WIRE_BYTES)
    if wire != expected_request.canonical_bytes:
        raise AuthorityContractError("authority request differs from selected inputs")
    return expected_request


@dataclass(frozen=True)
class AuthorityReplyClaim:
    """A replayable bound claim, not authenticated truth or dispatch permission."""

    status: str
    request_digest_hex: str
    claimed_head: object
    claimed_attempt_id: object


def parse_reply(expected_request, wire):
    """Validate a reply claim's exact binding and declared no-refund transition.

    Anyone can forge a consistent reply or replay it. A changed claimed digest
    proves no actual state change; external authentication and freshness remain
    required before any future owner uses it. No worker capability is returned.
    """
    if type(expected_request) is not AuthorityRequest:
        raise AuthorityContractError("an exact selected authority request is required")
    request = expected_request.as_dict()
    value = _decode(wire, MAX_WIRE_BYTES)
    _object(value, _REPLY)
    fields = expected_request._scope.as_dict()
    _head_fields(value["before_head"], fields["attempt_limit"])
    if (type(value["schema"]) is not str or value["schema"] != REPLY_SCHEMA
            or any(value[key] != request[key] for key in
                   ("operation", "scope_digest_hex", "authority_epoch", "request_id_hex"))
            or type(value["authority_epoch"]) is not int
            or value["request_digest_hex"] != expected_request.digest_hex
            or value["before_head"] != request["expected_head"]):
        raise AuthorityContractError("authority reply changes the selected request")
    before = request["expected_head"]
    status = value["status"]
    if type(status) is not str or status not in (SUCCESS[request["operation"]], "not-applied", "unresolved"):
        raise AuthorityContractError("unsupported authority reply claim")
    attempt = value["attempt_id"]
    after = value["after_head"]
    if status == "unresolved":
        if after is not None or attempt is not None:
            raise AuthorityContractError("unresolved reply must not assert state or refund")
        return AuthorityReplyClaim(status, expected_request.digest_hex, None, None)
    after = _head_fields(after, fields["attempt_limit"])
    if status == "not-applied":
        if after != before or attempt is not None:
            raise AuthorityContractError("not-applied reply must retain the exact expected head")
    else:
        wanted = dict(before, revision=before["revision"] + 1, state_digest_hex=after["state_digest_hex"])
        if request["operation"] == "reserve":
            wanted.update(consumed=before["consumed"] + 1, pending_attempt_id=before["consumed"] + 1)
            required_attempt = wanted["pending_attempt_id"]
        else:
            required_attempt = request["attempt_id"]
            if request["operation"] == "dispatch":
                wanted.update(dispatch_recorded=True)
            else:
                wanted.update(pending_attempt_id=None, dispatch_recorded=False)
        if (not _integer(attempt, 1, fields["attempt_limit"]) or attempt != required_attempt
                or after != wanted or after["state_digest_hex"] == before["state_digest_hex"]):
            raise AuthorityContractError("authority reply contradicts its claimed transition")
    return AuthorityReplyClaim(status, expected_request.digest_hex, AuthorityHead(**after), attempt)
