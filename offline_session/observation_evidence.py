"""Pure binding and statement codec for a prospective observation evidence contract.

No worker, observation source, authority check, cache or persistence is selected.
A parsed statement is a structurally bound claim, not a verified certificate.
The caller must independently establish the local verifier and its semantics.
"""

from dataclasses import dataclass
import hashlib
import json
import re

from . import completion, exchange


BINDING_SCHEMA = "ptlc-observation-evidence-binding-v1"
STATEMENT_SCHEMA = "ptlc-observation-math-statement-v1"
PREDICATE = "zenon-completion-v1"
OUTCOMES = ("verified", "rejected", "unknown")
MAX_STATEMENT_BYTES = 4096
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_STATEMENT_FIELDS = {"schema", "predicate", "binding_digest_hex", "evidence_key_hex",
                     "verifier_profile_digest_hex", "request_digest_hex", "outcome"}
_DIGEST_FIELDS = ("binding_digest_hex", "evidence_key_hex", "verifier_profile_digest_hex", "request_digest_hex")


class EvidenceError(ValueError):
    """Sanitized invalid evidence encoding or mismatch to locally derived inputs."""


@dataclass(frozen=True)
class EvidenceTarget:
    """Immutable public bytes derived from a validated, caller-supplied snapshot."""

    candidate_packet: bytes
    verification_request: bytes
    binding: bytes

    @property
    def binding_digest_hex(self):
        return hashlib.sha256(b"PTLC/observation-evidence-binding/v1\x00" + self.binding).hexdigest()


@dataclass(frozen=True)
class MathStatement:
    """An exact claim; its outcome supplies neither trust nor application authority."""

    evidence_key_hex: str
    binding_digest_hex: str
    verifier_profile_digest_hex: str
    request_digest_hex: str
    outcome: str


def _profile(value):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise EvidenceError("an exact local verifier profile digest is required")


def prepare(state, signature):
    """Derive a predicate request and its full session target without any I/O.

    A retained different candidate uses the existing comparison-guarded request
    preparation. The resulting evidence does not authorize a later CAS or debit.
    The predicate covers the Zenon bundle, final signature and adaptor relation;
    it does not return a witness or complete the Bitcoin signature.
    """
    if type(signature) is not bytes or len(signature) != 64:
        raise EvidenceError("an exact public signature is required")
    try:
        snapshot = exchange._at(state, "RELEASE_RECORDED")
        packet = completion.bob_candidate_from_signature(snapshot, signature)
        previous_hex = snapshot["zenon_completion_packet_hex"]
        if previous_hex is None or previous_hex == packet.hex():
            recovery = completion.bob_request(snapshot, packet)
        else:
            previous = bytes.fromhex(previous_hex)
            recovery = completion.bob_reconciliation_request(
                snapshot, packet, expected_observation_digest=completion.observation_digest(previous))
        verification = dict(recovery, kind="verify-zenon-completion", bitcoin=None)
        wire = exchange.canonical(verification)
        if len(wire) > 65536:
            raise EvidenceError("observation predicate request exceeds its bound")
        value = json.loads(packet)
        binding = exchange.canonical({
            "schema": BINDING_SCHEMA,
            "session_id": value["context"]["session_id"],
            "terms_digest_hex": value["context"]["binding"]["bitcoin"]["terms_digest_hex"],
            "bitcoin_context_digest_hex": recovery["bitcoin"]["context_digest_hex"],
            "zenon_context_digest_hex": recovery["zenon"]["context_digest_hex"],
            "candidate_digest_hex": completion.observation_digest(packet),
            "signature_digest_hex": hashlib.sha256(b"PTLC/observed-signature/v1\x00" + signature).hexdigest(),
            "recovery_request_digest_hex": completion.request_digest(recovery),
            "verification_request_digest_hex": completion.request_digest(verification),
        })
        return EvidenceTarget(packet, wire, binding)
    except Exception:
        raise EvidenceError("observation evidence target rejected") from None


def _fields(target, profile_digest_hex):
    _profile(profile_digest_hex)
    binding_digest = target.binding_digest_hex
    key_input = exchange.canonical({
        "binding_digest_hex": binding_digest,
        "predicate": PREDICATE,
        "verifier_profile_digest_hex": profile_digest_hex,
    })
    return {
        "schema": STATEMENT_SCHEMA,
        "predicate": PREDICATE,
        "binding_digest_hex": binding_digest,
        "evidence_key_hex": hashlib.sha256(b"PTLC/observation-evidence-key/v1\x00" + key_input).hexdigest(),
        "verifier_profile_digest_hex": profile_digest_hex,
        "request_digest_hex": completion.request_digest(json.loads(target.verification_request)),
    }


def statement_key(state, signature, *, verifier_profile_digest_hex):
    """Identify exact inputs and selected verifier semantics, not source trust."""
    _profile(verifier_profile_digest_hex)
    return _fields(prepare(state, signature), verifier_profile_digest_hex)["evidence_key_hex"]


def unknown_statement(state, signature, *, verifier_profile_digest_hex):
    """Encode an unresolved result without exception text or worker output.

    Legacy CompletionError, nonzero exit, timeout, cancellation and malformed
    output cannot be promoted to a normal mathematical rejection by this codec.
    No helper fabricates a verified or rejected statement.
    """
    _profile(verifier_profile_digest_hex)
    return exchange.canonical(dict(_fields(prepare(state, signature), verifier_profile_digest_hex), outcome="unknown"))


def parse_statement(state, signature, response, *, expected_verifier_profile_digest_hex):
    """Check a claim against fresh local inputs and an externally selected profile.

    Only compact canonical ASCII JSON is accepted, with no optional LF. A peer
    can forge all fields; matching hashes do not authenticate the worker or make
    the outcome true. No outcome changes a journal, recovery budget or history.
    """
    _profile(expected_verifier_profile_digest_hex)
    if type(response) is not bytes or not response or len(response) > MAX_STATEMENT_BYTES:
        raise EvidenceError("invalid observation statement size or type")
    try:
        value = json.loads(response.decode("ascii"))
        if (type(value) is not dict or set(value) != _STATEMENT_FIELDS
                or any(type(item) is not str for item in value.values())
                or value["schema"] != STATEMENT_SCHEMA or value["predicate"] != PREDICATE
                or any(_HEX.fullmatch(value[field]) is None for field in _DIGEST_FIELDS)
                or value["verifier_profile_digest_hex"] != expected_verifier_profile_digest_hex
                or value["outcome"] not in OUTCOMES
                or exchange.canonical(value) != response):
            raise EvidenceError("observation statement is not exactly bound")
        # Reject malformed claims before repeatedly reconstructing public state.
        # A well-formed claim still requires fresh locally derived exact inputs.
        expected = _fields(prepare(state, signature), expected_verifier_profile_digest_hex)
        if any(value[field] != item for field, item in expected.items()):
            raise EvidenceError("observation statement is not exactly bound")
        return MathStatement(value["evidence_key_hex"], value["binding_digest_hex"],
                             value["verifier_profile_digest_hex"], value["request_digest_hex"], value["outcome"])
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise EvidenceError("observation statement rejected") from None
