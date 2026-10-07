"""Public-only partial-invocation inputs, never a signing permission.

Reuse the complete validated dynamic transcript and expose the public backend
arguments it describes. Exact byte agreement proves only that these supplied
objects match. No curve arithmetic, key aggregation, tweak calculation, signer,
nonce consumption, storage, worker launch or new commitment digest occurs here.
"""

import json

from .transcript import Commitment, TranscriptError, validate_signing_context


SCHEMA = "ptlc-public-nonce-intent-v1"
MAX_WIRE_BYTES = 128_000
_REFUSAL = "public nonce intent refused"


class IntentError(ValueError):
    """A sanitized public-input refusal; no operation state is changed."""


def _context(context):
    if type(context) is not Commitment:
        raise IntentError(_REFUSAL)
    try:
        validate_signing_context(context)
        data = context.as_dict()
        if (data["purpose"] != data["leg"] + "-claim-partial"
                or "nonce_round" not in data):
            raise IntentError(_REFUSAL)
        return data
    except (TranscriptError, TypeError, ValueError, AttributeError, RecursionError):
        raise IntentError(_REFUSAL) from None


def _inputs(data):
    leg = data["leg"]
    binding = data["binding"]
    terms = binding["terms"] if leg == "bitcoin" else binding["bitcoin"]["terms"]
    agreed = terms[leg]
    if leg == "bitcoin":
        tweak = {"kind": "taproot-xonly", "merkle_root_hex": agreed["tapleaf_hash_hex"]}
        base_key = agreed["internal_key_xonly_hex"]
        signing_key = agreed["output_key_xonly_hex"]
        message = binding["binding"]["claim_sighash_hex"]
    else:
        tweak = {"kind": "none"}
        base_key = signing_key = agreed["aggregate_key_xonly_hex"]
        message = binding["binding"]["message_hex"]
    nonces = data["nonce_round"]["public_nonces"]
    return {
        "operation": "musig2-adaptor-partial",
        "key_aggregation": {
            "ordered_signer_keys_sec1_hex": agreed["signer_keys_sec1_hex"],
            "tweak": tweak,
            "declared_base_key_xonly_hex": base_key,
            "declared_signing_key_xonly_hex": signing_key,
        },
        "signer_index": ("alice", "bob").index(data["role"]),
        "message_hex": message,
        "adaptor_point_sec1_hex": terms["adaptor_point_sec1_hex"],
        "public_nonces_hex": [nonces["alice"], nonces["bob"]],
    }


def public_inputs(context):
    """Return a fresh public projection, including unverified declared keys.

    The ordered keys, tweak and messages describe the candidate's inputs. This
    does not recompute an aggregate key, Bitcoin sighash or tweak, parse curve
    points, or establish what an actual backend consumed.
    """
    return _inputs(_context(context))


def encode_intent(context):
    """Encode the complete context and its derived public projection as bytes.

    Only a revealed-round partial context is supported. Completion and static
    qualification contexts are not nonce-dependent partial invocations here.
    The schema is repository research, not a standardized signing wire protocol.
    """
    data = _context(context)
    wire = json.dumps({"schema": SCHEMA, "signing_context": data,
                       "public_inputs": _inputs(data)}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")
    if len(wire) > MAX_WIRE_BYTES:
        raise IntentError(_REFUSAL)
    return wire


def require_exact_intent(context, wire):
    """Compare bytes with an independently selected complete local context.

    No peer wire is parsed into replacement expectations. Equality against the
    bounded factory encoding also refuses duplicate keys, aliases and trailing
    bytes without traversing hostile JSON. Success returns None and grants no
    signing, freshness, one-use, authentication or recovery authority.
    """
    if type(wire) is not bytes or not 2 <= len(wire) <= MAX_WIRE_BYTES:
        raise IntentError(_REFUSAL)
    if wire != encode_intent(context):
        raise IntentError(_REFUSAL)
