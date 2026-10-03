"""Public inbound validation and completion lifecycle for offline qualification.

Alice's producer is an explicitly trusted synthetic callback, not a secret
signing backend. Bob's recovery uses only public input; no scalar is exported.
Persistence, consumption-before-callback and ownership belong to Journal.
"""

import copy
import hashlib
import json

from . import exchange
from .transcript import _restore, signing_context, validate_signing_context


RESULT_SCHEMA = "ptlc-completion-result-v1"
_STAGES = ("ALICE_PARTIAL_RETAINED", "PRESIGNATURE_RETAINED", "COMPLETION_CONSUMED",
           "OUTCOME_UNKNOWN", "COMPLETION_RECORDED")
_FIELDS = {"schema", "stage", "context", "own_partial_hex", "release_packet_hex",
           "signature_hex", "completion_packet_hex", "possible_exposure", "verification_receipts"}
MAX_PACKET_BYTES = 32_000


class CompletionError(exchange.ExchangeError):
    """Sanitized invalid public completion context or lifecycle transition."""


def request_digest(request):
    return hashlib.sha256(b"PTLC/completion/v1\x00" + exchange.canonical(request)).hexdigest()


def observation_digest(packet):
    """Bind exact public bytes for compare-and-swap; this is not authentication."""
    if type(packet) is not bytes or not packet or len(packet) > MAX_PACKET_BYTES:
        raise CompletionError("invalid observation digest input")
    return hashlib.sha256(b"PTLC/completion-observation/v1\x00" + packet).hexdigest()


def recontext(context, role, purpose):
    """Reconstruct a role/purpose change while preserving the exact binding/round."""
    try:
        validate_signing_context(context)
        data = context.as_dict()
        return signing_context(_restore(data["binding"]), role, purpose,
                               nonce_round=_restore(data["nonce_round"]))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise CompletionError("a nonce-bound completion context is required") from None


def _alice_context(context):
    expected = recontext(context, "alice", "zenon-claim-partial")
    if expected.canonical_bytes != context.canonical_bytes:
        raise CompletionError("Alice's exact Zenon partial context is required")
    return expected


def _packet(raw, fields, schema):
    if type(raw) is not bytes or len(raw) > MAX_PACKET_BYTES:
        raise CompletionError("invalid public packet size or type")
    try:
        value = json.loads(raw.decode("ascii"))
        exchange._bounded(value)
        if (type(value) is not dict or set(value) != set(fields.split())
                or value["schema"] != schema or exchange.canonical(value) != raw):
            raise CompletionError("invalid public packet schema or canonical encoding")
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise CompletionError("invalid public packet") from None


def _stored_packet(encoded):
    if (type(encoded) is not str or not encoded or len(encoded) > MAX_PACKET_BYTES * 2
            or len(encoded) % 2 or exchange._HEX.fullmatch(encoded) is None):
        raise CompletionError("invalid stored public packet")
    return bytes.fromhex(encoded)


def _release(context, raw):
    packet = _packet(raw, "schema sender_role recipient_role context adaptor_presignature_hex partial_signatures_hex",
                     "ptlc-bob-zenon-release-v2")
    expected = recontext(context, "bob", "zenon-claim-partial")
    if (packet["sender_role"] != "bob" or packet["recipient_role"] != "alice"
            or exchange.canonical(packet["context"]) != expected.canonical_bytes):
        raise CompletionError("incoming release changes its role or context")
    bundle = exchange._bundle({field: packet[field] for field in ("partial_signatures_hex", "adaptor_presignature_hex")})
    return expected, bundle


def _request(zenon, bundle, signature_hex, *, bitcoin=None, bitcoin_bundle=None):
    exchange._hex(signature_hex, 64)
    return {
        "schema": "ptlc-completion-request-v1",
        "kind": "verify-zenon-completion" if bitcoin is None else "recover-bitcoin",
        "zenon": exchange.verification_request(zenon, bundle=bundle),
        "bitcoin": None if bitcoin is None else exchange.verification_request(bitcoin, bundle=bitcoin_bundle),
        "zenon_signature_hex": signature_hex,
    }


def validate_result(request, result):
    if (type(result) is not dict
            or set(result) != {"schema", "request_digest_hex", "valid", "bitcoin_signature_hex"}
            or type(result["schema"]) is not str or result["schema"] != RESULT_SCHEMA
            or type(result["request_digest_hex"]) is not str or result["request_digest_hex"] != request_digest(request)
            or result["valid"] is not True or type(result["bitcoin_signature_hex"]) is not str):
        raise CompletionError("completion result is not bound to the request")
    if request["kind"] == "verify-zenon-completion":
        if result["bitcoin_signature_hex"] != "":
            raise CompletionError("verification unexpectedly returned a completion")
    elif request["kind"] == "recover-bitcoin":
        exchange._hex(result["bitcoin_signature_hex"], 64)
    else:
        raise CompletionError("unsupported completion result kind")


def _run(request, callback):
    if not callable(callback):
        raise CompletionError("a trusted completion verifier is required")
    try:
        result = callback(copy.deepcopy(request))
    except BaseException:
        raise CompletionError("public completion verification failed") from None
    validate_result(request, result)
    return copy.deepcopy(result)


def _alice_packet(context, signature_hex):
    return exchange.canonical({
        "schema": "ptlc-alice-zenon-completion-v1", "sender_role": "alice", "recipient_role": "bob",
        "context": recontext(context, "alice", "zenon-claim-complete").as_dict(),
        "signature_hex": signature_hex,
    })


def _bitcoin_packet(context, signature_hex):
    exchange._hex(signature_hex, 64)
    return exchange.canonical({
        "schema": "ptlc-bob-bitcoin-completion-v1",
        "context": recontext(context, "bob", "bitcoin-claim-complete").as_dict(),
        "signature_hex": signature_hex,
    })


def contexts(state):
    return [_alice_context(_restore(state["context"]))]


def validate_state(state):
    exchange._bounded(state)
    if (type(state) is not dict or set(state) != _FIELDS or state["schema"] != "ptlc-alice-completion-v1"
            or type(state["stage"]) is not str or state["stage"] not in _STAGES
            or type(state["possible_exposure"]) is not bool
            or len(exchange.canonical(state)) > exchange.MAX_EXCHANGE_BYTES):
        raise CompletionError("invalid Alice completion state")
    stage = _STAGES.index(state["stage"])
    context = contexts(state)[0]
    exchange._hex(state["own_partial_hex"], 32)
    peer = recontext(context, "bob", "zenon-claim-partial")
    receipts = {"alice_partial": exchange.request_digest(
        exchange.verification_request(peer, alice_partial=state["own_partial_hex"]))}
    if (state["release_packet_hex"] is not None) != (stage >= 1):
        raise CompletionError("release packet contradicts Alice stage")
    if state["possible_exposure"] != (stage >= 2):
        raise CompletionError("Alice exposure contradicts consumption state")
    for field in ("signature_hex", "completion_packet_hex"):
        if (state[field] is not None) != (stage == 4):
            raise CompletionError("completion output contradicts Alice stage")
    if stage >= 1:
        peer, bundle = _release(context, _stored_packet(state["release_packet_hex"]))
        if bundle["partial_signatures_hex"][0] != state["own_partial_hex"]:
            raise CompletionError("release replaced Alice's retained partial")
        receipts["zenon_bundle"] = exchange.request_digest(exchange.verification_request(peer, bundle=bundle))
    if stage == 4:
        request = _request(peer, bundle, state["signature_hex"])
        receipts["zenon_completion"] = request_digest(request)
        if state["completion_packet_hex"] != _alice_packet(context, state["signature_hex"]).hex():
            raise CompletionError("Alice output differs from the recorded context")
    if type(state["verification_receipts"]) is not dict or state["verification_receipts"] != receipts:
        raise CompletionError("Alice verification receipts differ from retained inputs")


def _at(state, stage):
    validate_state(state)
    if state["stage"] != stage:
        raise CompletionError("Alice completion transition is out of order")
    return copy.deepcopy(state)


def start(context, own_partial_hex, verifier):
    context = _alice_context(context)
    exchange._hex(own_partial_hex, 32)
    receipt = exchange._verify(recontext(context, "bob", "zenon-claim-partial"), verifier, alice_partial=own_partial_hex)
    state = {
        "schema": "ptlc-alice-completion-v1", "stage": "ALICE_PARTIAL_RETAINED", "context": context.as_dict(),
        "own_partial_hex": own_partial_hex, "release_packet_hex": None, "signature_hex": None,
        "completion_packet_hex": None, "possible_exposure": False,
        "verification_receipts": {"alice_partial": receipt},
    }
    validate_state(state)
    return state


def accept_release(state, packet, verifier):
    result = _at(state, "ALICE_PARTIAL_RETAINED")
    peer, bundle = _release(contexts(result)[0], packet)
    if bundle["partial_signatures_hex"][0] != result["own_partial_hex"]:
        raise CompletionError("release replaced Alice's retained partial")
    receipt = exchange._verify(peer, verifier, bundle=bundle)
    result.update(stage="PRESIGNATURE_RETAINED", release_packet_hex=packet.hex())
    result["verification_receipts"]["zenon_bundle"] = receipt
    validate_state(result)
    return result


def consume(state):
    result = _at(state, "PRESIGNATURE_RETAINED")
    result.update(stage="COMPLETION_CONSUMED", possible_exposure=True)
    validate_state(result)
    return result


def recover(state):
    validate_state(state)
    result = copy.deepcopy(state)
    if result["stage"] == "COMPLETION_CONSUMED":
        result["stage"] = "OUTCOME_UNKNOWN"
    return result


def record(state, signature, verifier):
    result = _at(state, "COMPLETION_CONSUMED")
    if type(signature) is not bytes or len(signature) != 64:
        raise CompletionError("producer returned an invalid final signature encoding")
    context = contexts(result)[0]
    peer, bundle = _release(context, _stored_packet(result["release_packet_hex"]))
    request = _request(peer, bundle, signature.hex())
    _run(request, verifier)
    output = _alice_packet(context, signature.hex())
    result.update(stage="COMPLETION_RECORDED", signature_hex=signature.hex(), completion_packet_hex=output.hex())
    result["verification_receipts"]["zenon_completion"] = request_digest(request)
    validate_state(result)
    return result, output


def replay(state):
    _at(state, "COMPLETION_RECORDED")
    return _stored_packet(state["completion_packet_hex"])


def _bob_request(state, packet):
    value = _packet(packet, "schema sender_role recipient_role context signature_hex", "ptlc-alice-zenon-completion-v1")
    bitcoin, zenon = exchange.contexts(state)
    if (value["sender_role"] != "alice" or value["recipient_role"] != "bob"
            or exchange.canonical(value["context"]) != recontext(zenon, "alice", "zenon-claim-complete").canonical_bytes):
        raise CompletionError("observed completion changes its role or context")
    return _request(zenon, state["zenon_bundle"], value["signature_hex"],
                    bitcoin=bitcoin, bitcoin_bundle=state["bitcoin_bundle"])


def bob_candidate_from_signature(state, signature):
    """Build unverified candidate bytes from retained Bob context and a signature.

    Role labels describe the existing packet format, not evidence that Alice
    transmitted it. This performs no authentication, cryptographic verification,
    admission or persistence. A different retained candidate still requires the
    ordinary explicit reconciliation path before it can replace that observation.
    """
    if type(signature) is not bytes or len(signature) != 64:
        raise CompletionError("an exact 64-byte public signature is required")
    try:
        snapshot = exchange._at(state, "RELEASE_RECORDED")
        packet = _alice_packet(exchange.contexts(snapshot)[1], signature.hex())
        _bob_request(snapshot, packet)
        return packet
    except Exception:
        raise CompletionError("public signature candidate rejected") from None


def bob_request(state, packet):
    exchange._at(state, "RELEASE_RECORDED")
    request = _bob_request(state, packet)
    recorded = state["zenon_completion_packet_hex"]
    if recorded is not None and _stored_packet(recorded) != packet:
        raise CompletionError("a different completion observation is already retained")
    return request


def observe_bob(state, packet):
    """Retain a structurally matched candidate, without claiming crypto validity."""
    bob_request(state, packet)
    result = copy.deepcopy(state)
    result["zenon_completion_packet_hex"] = packet.hex()
    exchange.validate_state(result)
    return result


def validate_bob_observation(state):
    _bob_request(state, _stored_packet(state["zenon_completion_packet_hex"]))


def complete_bob(state, packet, recoverer):
    request = bob_request(state, packet)
    result = _run(request, recoverer)
    bitcoin = exchange.contexts(state)[0]
    output = _bitcoin_packet(bitcoin, result["bitcoin_signature_hex"])
    state = copy.deepcopy(state)
    state.update(stage="BTC_COMPLETION_RECORDED", zenon_completion_packet_hex=packet.hex(),
                 bitcoin_completion_packet_hex=output.hex(), completion_receipt_hex=request_digest(request))
    exchange.validate_state(state)
    return state, output


def _reconciliation_inputs(state, packet, expected_observation_digest):
    state = exchange._at(state, "RELEASE_RECORDED")
    if state["zenon_completion_packet_hex"] is None:
        raise CompletionError("reconciliation requires a retained observation")
    exchange._hex(expected_observation_digest, 32)
    previous = _stored_packet(state["zenon_completion_packet_hex"])
    if observation_digest(previous) != expected_observation_digest:
        raise CompletionError("retained observation changed before reconciliation")
    request = _bob_request(state, packet)
    if packet == previous:
        raise CompletionError("the retained observation requires ordinary recovery")
    return state, previous, request


def bob_reconciliation_request(state, packet, *, expected_observation_digest):
    """Validate local reconciliation preconditions without invoking recovery.

    Journal uses the exact public request to check admission before persisting a
    consumed attempt. Preparing it neither verifies a signature nor replaces the
    retained observation.
    """
    return _reconciliation_inputs(state, packet, expected_observation_digest)[2]


def reconcile_bob(state, packet, *, expected_observation_digest, recoverer):
    """Complete a different positively verified observation, retaining the old one.

    Worker rejection or failure never proves that the retained candidate was
    invalid. A replacement is not retained until verification succeeds. Journal
    supplies durable admission and publication before returning output.
    """
    state, previous, request = _reconciliation_inputs(state, packet, expected_observation_digest)
    result = _run(request, recoverer)
    output = _bitcoin_packet(exchange.contexts(state)[0], result["bitcoin_signature_hex"])
    state.update(stage="BTC_COMPLETION_RECORDED", zenon_completion_packet_hex=packet.hex(),
                 bitcoin_completion_packet_hex=output.hex(), completion_receipt_hex=request_digest(request),
                 superseded_zenon_completion_packet_hex=previous.hex())
    exchange.validate_state(state)
    return state, output


def validate_bob_result(state):
    """Called inside exchange validation; do not recursively validate that state."""
    packet = _stored_packet(state["zenon_completion_packet_hex"])
    request = _bob_request(state, packet)
    output = _packet(_stored_packet(state["bitcoin_completion_packet_hex"]),
                     "schema context signature_hex", "ptlc-bob-bitcoin-completion-v1")
    bitcoin = exchange.contexts(state)[0]
    if (state["completion_receipt_hex"] != request_digest(request)
            or _stored_packet(state["bitcoin_completion_packet_hex"]) != _bitcoin_packet(bitcoin, output["signature_hex"])):
        raise CompletionError("stored Bitcoin completion changed its bound inputs")
    superseded = state["superseded_zenon_completion_packet_hex"]
    if superseded is not None:
        previous = _stored_packet(superseded)
        if previous == packet:
            raise CompletionError("superseded observation equals its replacement")
        # Historical evidence has the same binding, but no validity assertion.
        _bob_request(state, previous)


def replay_bob(state):
    exchange._at(state, "BTC_COMPLETION_RECORDED")
    return _stored_packet(state["bitcoin_completion_packet_hex"])
