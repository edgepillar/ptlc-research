"""Pure Bob-side public artifact sequencing, not authentication or chain policy.

Verifier callbacks are trusted local code. A receipt only records that callback's
result; it is not a peer certificate. The journal supplies persistence and release
ordering. All contexts and artifacts here are public synthetic qualification data.
"""

import copy
import hashlib
import json
import re

from .transcript import Commitment, TranscriptError, _restore, validate_signing_context


SCHEMA = "ptlc-bob-exchange-v1"
REQUEST_SCHEMA = "ptlc-artifact-verification-v1"
RESULT_SCHEMA = "ptlc-artifact-verification-result-v1"
_STAGES = (
    "BITCOIN_BOUND", "BITCOIN_RETAINED", "ZENON_BOUND", "ALICE_PARTIAL_RETAINED",
    "ZENON_RETAINED", "RELEASE_RECORDED", "BTC_COMPLETION_RECORDED",
)
_FIELDS = {
    "schema", "stage", "bitcoin_context", "zenon_context", "bitcoin_bundle",
    "alice_partial_hex", "zenon_bundle", "release_hex", "release_may_have_escaped",
    "verification_receipts",
    "zenon_completion_packet_hex", "bitcoin_completion_packet_hex", "completion_receipt_hex",
}
_HEX = re.compile(r"[0-9a-f]+\Z")
MAX_EXCHANGE_BYTES = 128_000


class ExchangeError(ValueError):
    """Sanitized failure of public artifact sequencing or validation."""


class VerificationError(ExchangeError):
    """The trusted verifier did not return an exact successful bound result."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def request_digest(request):
    return hashlib.sha256(b"PTLC/artifact-verification/v1\x00" + canonical(request)).hexdigest()


def _hex(value, size):
    if type(value) is not str or len(value) != size * 2 or _HEX.fullmatch(value) is None:
        raise ExchangeError("invalid public artifact encoding")


def _bounded(value, depth=0, budget=None):
    if budget is None:
        budget = [4096, MAX_EXCHANGE_BYTES]
    budget[0] -= 1
    if depth > 20 or budget[0] < 0:
        raise ExchangeError("exchange structure exceeds its bound")
    if type(value) is dict:
        if len(value) > 128:
            raise ExchangeError("exchange object exceeds its bound")
        for key, item in value.items():
            if type(key) is not str or not key.isascii() or len(key) > 128:
                raise ExchangeError("invalid exchange field")
            _bounded(item, depth + 1, budget)
    elif type(value) is list:
        if len(value) > 128:
            raise ExchangeError("exchange array exceeds its bound")
        for item in value:
            _bounded(item, depth + 1, budget)
    elif type(value) is str:
        budget[1] -= len(value)
        if not value.isascii() or len(value) > 64_000 or budget[1] < 0:
            raise ExchangeError("exchange string exceeds its bound")
    elif type(value) is int:
        if value.bit_length() > 256:
            raise ExchangeError("exchange integer exceeds its bound")
    elif value is not None and type(value) is not bool:
        raise ExchangeError("unsupported exchange value")


def _context(context, leg):
    try:
        validate_signing_context(context)
        data = context.as_dict()
        if (data["leg"] != leg or data["role"] != "bob"
                or data["purpose"] != leg + "-claim-partial"
                or "nonce_round" not in data):
            raise ExchangeError("managed exchange requires Bob's nonce-bound partial context")
        return data
    except (TranscriptError, TypeError, KeyError, AttributeError, RecursionError):
        raise ExchangeError("invalid exchange signing context") from None


def _restore_context(payload, leg):
    try:
        context = _restore(payload)
        _context(context, leg)
        return context
    except (TranscriptError, TypeError, KeyError, AttributeError, RecursionError):
        raise ExchangeError("invalid stored exchange context") from None


def contexts(state):
    """Rebuild stored contexts; validation of the full state is a separate step."""
    result = [_restore_context(state["bitcoin_context"], "bitcoin")]
    if state["zenon_context"] is not None:
        result.append(_restore_context(state["zenon_context"], "zenon"))
    return result


def _bundle(value):
    if type(value) is not dict or set(value) != {"partial_signatures_hex", "adaptor_presignature_hex"}:
        raise ExchangeError("invalid artifact bundle fields")
    partials = value["partial_signatures_hex"]
    if type(partials) is not list or len(partials) != 2:
        raise ExchangeError("artifact bundle requires both ordered partials")
    for partial in partials:
        _hex(partial, 32)
    _hex(value["adaptor_presignature_hex"], 65)
    return copy.deepcopy(value)


def verification_request(context, *, bundle=None, alice_partial=None):
    """Derive every cryptographic input from the exact validated public context."""
    if type(context) is not Commitment:
        raise ExchangeError("validated exchange context required")
    data = context.as_dict()
    leg = data.get("leg")
    if leg not in ("bitcoin", "zenon"):
        raise ExchangeError("invalid exchange leg")
    _context(context, leg)
    if (bundle is None) == (alice_partial is None):
        raise ExchangeError("exactly one artifact form is required")
    binding = data["binding"]
    terms = binding["terms"] if leg == "bitcoin" else binding["bitcoin"]["terms"]
    chain = terms[leg]
    if bundle is not None:
        artifact = _bundle(bundle)
        kind, partials, pre = "bundle", artifact["partial_signatures_hex"], artifact["adaptor_presignature_hex"]
    else:
        _hex(alice_partial, 32)
        kind, partials, pre = "alice-partial", [alice_partial], ""
    nonces = data["nonce_round"]["public_nonces"]
    return {
        "schema": REQUEST_SCHEMA, "kind": kind, "context_digest_hex": context.digest_hex,
        "leg": leg, "signer_keys_sec1_hex": chain["signer_keys_sec1_hex"],
        "aggregate_key_xonly_hex": chain["output_key_xonly_hex" if leg == "bitcoin" else "aggregate_key_xonly_hex"],
        "taproot_merkle_root_hex": chain["tapleaf_hash_hex"] if leg == "bitcoin" else "",
        "message_hex": binding["binding"]["claim_sighash_hex" if leg == "bitcoin" else "message_hex"],
        "adaptor_point_sec1_hex": terms["adaptor_point_sec1_hex"],
        "public_nonces_hex": [nonces["alice"], nonces["bob"]],
        "partial_signatures_hex": partials, "adaptor_presignature_hex": pre,
    }


def _verify(context, verifier, *, bundle=None, alice_partial=None):
    if not callable(verifier):
        raise VerificationError("a trusted public artifact verifier is required")
    request = verification_request(context, bundle=bundle, alice_partial=alice_partial)
    expected = request_digest(request)
    try:
        result = verifier(copy.deepcopy(request))
    except BaseException:
        raise VerificationError("public artifact verification failed") from None
    if (type(result) is not dict or set(result) != {"schema", "request_digest_hex", "valid"}
            or type(result["schema"]) is not str or result["schema"] != RESULT_SCHEMA
            or type(result["request_digest_hex"]) is not str or result["request_digest_hex"] != expected
            or result["valid"] is not True):
        raise VerificationError("public artifact verification result is not bound")
    return expected


def _release_bytes(state):
    return canonical({
        "schema": "ptlc-bob-zenon-release-v2", "sender_role": "bob", "recipient_role": "alice",
        "context": state["zenon_context"],
        "adaptor_presignature_hex": state["zenon_bundle"]["adaptor_presignature_hex"],
        "partial_signatures_hex": state["zenon_bundle"]["partial_signatures_hex"],
    })


def validate_state(state):
    """Check stored structure and causal bindings without executing a verifier.

    Checkpoint integrity and a trusted local verifier are assumed. Receipts are
    recomputed request hashes, not independently authenticated certificates.
    """
    _bounded(state)
    if (type(state) is not dict or set(state) != _FIELDS or state["schema"] != SCHEMA
            or type(state["stage"]) is not str or state["stage"] not in _STAGES
            or type(state["release_may_have_escaped"]) is not bool):
        raise ExchangeError("invalid exchange state schema")
    stage = _STAGES.index(state["stage"])
    if len(canonical(state)) > MAX_EXCHANGE_BYTES:
        raise ExchangeError("exchange state exceeds its byte bound")
    btc = _restore_context(state["bitcoin_context"], "bitcoin")
    for minimum, field in ((1, "bitcoin_bundle"), (2, "zenon_context"),
                           (3, "alice_partial_hex"), (4, "zenon_bundle"), (5, "release_hex")):
        if (state[field] is not None) != (stage >= minimum):
            raise ExchangeError("exchange artifacts do not match the required order")
    expected_receipts = {}
    if stage >= 1:
        bundle = _bundle(state["bitcoin_bundle"])
        expected_receipts["bitcoin_bundle"] = request_digest(verification_request(btc, bundle=bundle))
    if stage >= 2:
        znn = _restore_context(state["zenon_context"], "zenon")
        znn_data, btc_data = znn.as_dict(), btc.as_dict()
        if (znn.session_id != btc.session_id or znn_data["binding"]["bitcoin"] != btc_data["binding"]):
            raise ExchangeError("Zenon context changes the Bitcoin predecessor")
        btc_nonces = set(btc_data["nonce_round"]["public_nonces"].values())
        if btc_nonces.intersection(znn_data["nonce_round"]["public_nonces"].values()):
            raise ExchangeError("public nonce encoding repeated across exchange legs")
    if stage >= 3:
        _hex(state["alice_partial_hex"], 32)
        expected_receipts["zenon_alice_partial"] = request_digest(
            verification_request(znn, alice_partial=state["alice_partial_hex"]))
    if stage >= 4:
        bundle = _bundle(state["zenon_bundle"])
        if bundle["partial_signatures_hex"][0] != state["alice_partial_hex"]:
            raise ExchangeError("Zenon bundle replaces Alice's retained partial")
        expected_receipts["zenon_bundle"] = request_digest(verification_request(znn, bundle=bundle))
    if type(state["verification_receipts"]) is not dict or state["verification_receipts"] != expected_receipts:
        raise ExchangeError("verification receipts differ from retained inputs")
    if state["release_may_have_escaped"] != (stage >= 5):
        raise ExchangeError("release uncertainty marker contradicts stored state")
    if stage >= 5 and state["release_hex"] != _release_bytes(state).hex():
        raise ExchangeError("release bytes differ from the retained Zenon artifact")
    if stage < 5 and state["zenon_completion_packet_hex"] is not None:
        raise ExchangeError("Zenon completion observed before release")
    if stage == 6 and state["zenon_completion_packet_hex"] is None:
        raise ExchangeError("Bitcoin completion lacks its observed Zenon input")
    for field in ("bitcoin_completion_packet_hex", "completion_receipt_hex"):
        if (state[field] is not None) != (stage == 6):
            raise ExchangeError("Bitcoin completion fields contradict exchange stage")
    if stage == 5 and state["zenon_completion_packet_hex"] is not None:
        from .completion import validate_bob_observation
        validate_bob_observation(state)
    if stage == 6:
        from .completion import validate_bob_result
        validate_bob_result(state)


def _at(state, expected):
    validate_state(state)
    if state["stage"] != expected:
        raise ExchangeError("artifact exchange transition is out of order")
    return copy.deepcopy(state)


def start(context):
    data = _context(context, "bitcoin")
    state = {
        "schema": SCHEMA, "stage": "BITCOIN_BOUND", "bitcoin_context": data,
        "zenon_context": None, "bitcoin_bundle": None, "alice_partial_hex": None,
        "zenon_bundle": None, "release_hex": None, "release_may_have_escaped": False,
        "verification_receipts": {},
        "zenon_completion_packet_hex": None, "bitcoin_completion_packet_hex": None,
        "completion_receipt_hex": None,
    }
    validate_state(state)
    return state


def retain_bitcoin(state, bundle, verifier):
    result = _at(state, "BITCOIN_BOUND")
    bundle = _bundle(bundle)
    receipt = _verify(contexts(result)[0], verifier, bundle=bundle)
    result.update(stage="BITCOIN_RETAINED", bitcoin_bundle=bundle)
    result["verification_receipts"]["bitcoin_bundle"] = receipt
    validate_state(result)
    return result


def bind_zenon(state, context):
    result = _at(state, "BITCOIN_RETAINED")
    result.update(stage="ZENON_BOUND", zenon_context=_context(context, "zenon"))
    validate_state(result)
    return result


def retain_alice_partial(state, partial_hex, verifier):
    result = _at(state, "ZENON_BOUND")
    _hex(partial_hex, 32)
    receipt = _verify(contexts(result)[1], verifier, alice_partial=partial_hex)
    result.update(stage="ALICE_PARTIAL_RETAINED", alice_partial_hex=partial_hex)
    result["verification_receipts"]["zenon_alice_partial"] = receipt
    validate_state(result)
    return result


def retain_zenon(state, bundle, verifier):
    result = _at(state, "ALICE_PARTIAL_RETAINED")
    bundle = _bundle(bundle)
    if bundle["partial_signatures_hex"][0] != result["alice_partial_hex"]:
        raise ExchangeError("Zenon bundle replaces Alice's retained partial")
    receipt = _verify(contexts(result)[1], verifier, bundle=bundle)
    result.update(stage="ZENON_RETAINED", zenon_bundle=bundle)
    result["verification_receipts"]["zenon_bundle"] = receipt
    validate_state(result)
    return result


def release(state):
    """Prepare output; only a durable owner may return these bytes externally."""
    result = _at(state, "ZENON_RETAINED")
    output = _release_bytes(result)
    result.update(stage="RELEASE_RECORDED", release_hex=output.hex(), release_may_have_escaped=True)
    validate_state(result)
    return result, output


def replay(state):
    validate_state(state)
    if state["stage"] not in ("RELEASE_RECORDED", "BTC_COMPLETION_RECORDED"):
        raise ExchangeError("no recorded release is available")
    return bytes.fromhex(state["release_hex"])
