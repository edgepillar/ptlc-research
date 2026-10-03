"""Strict, staged commitments to public synthetic session inputs.

Canonical ASCII JSON and domain-separated SHA256 bind supplied bytes. They do
not authenticate participants, establish chain state, validate curve points,
recompute Bitcoin sighashes, or verify signatures/adaptor pre-signatures. The
only chain-message computation here is the specified SHA3-256(entry_id32 ||
destination20) rule. No signing, nonce generation, secret storage, or I/O occurs.

Each ordered signer-key list is [Alice, Bob]. Optional nonce-round commitments
bind two supplied public nonces to a chain binding, round ID, and role. Their
pure construction validates matched openings, not the chronology of a network
exchange, nonce freshness, secret ownership, or cryptographic point validity.
Contexts without a nonce round remain the earlier static qualification form.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


SCHEMA = "ptlc-offline-transcript-v1"
_DOMAIN = b"PTLC/offline-transcript/v1\x00"
_HEX = re.compile(r"^[0-9a-f]+$")
_LABEL = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_MAX_ENCODED_BYTES = 128_000
_PURPOSES = {
    "bitcoin-claim-partial": ("bitcoin", ("alice", "bob")),
    "zenon-claim-partial": ("zenon", ("alice", "bob")),
    "zenon-claim-complete": ("zenon", ("alice",)),
    "bitcoin-claim-complete": ("bitcoin", ("bob",)),
}


class TranscriptError(ValueError):
    """A public transcript input violates this finite versioned schema."""


def _snapshot(value: Any, depth: int = 0, budget: Any = None) -> Any:
    """Copy only explicitly supported plain JSON values, before validation."""
    if budget is None:
        budget = [512, _MAX_ENCODED_BYTES]
    budget[0] -= 1
    if depth > 8 or budget[0] < 0:
        raise TranscriptError("public input exceeds the depth or node bound")
    if type(value) is dict:
        if len(value) > 128 or any(type(key) is not str or len(key) > 128
                                   or not key.isascii() for key in value):
            raise TranscriptError("object keys must be plain ASCII strings")
        return {key: _snapshot(item, depth + 1, budget) for key, item in value.items()}
    if type(value) is list:
        if len(value) > 128:
            raise TranscriptError("public array exceeds the item bound")
        return [_snapshot(item, depth + 1, budget) for item in value]
    if type(value) is str and value.isascii():
        budget[1] -= len(value)
        if len(value) > 20_000 or budget[1] < 0:
            raise TranscriptError("public strings exceed the size bound")
        return value
    if type(value) is int:
        if value.bit_length() > 256:
            raise TranscriptError("public integer exceeds the representation bound")
        return value
    raise TranscriptError("only plain objects, arrays, ASCII strings, and integers are accepted")


def _object(value: Any, keys: str, name: str) -> Dict[str, Any]:
    if type(value) is not dict or set(value) != set(keys.split()):
        raise TranscriptError(name + " has missing, unknown, or invalid fields")
    return value


def _literal(value: Any, expected: Any, name: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise TranscriptError(name + " is unsupported or inconsistent")


def _uint(value: Any, bits: int, name: str, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value < 2 ** bits:
        raise TranscriptError(name + " must be an in-range integer")


def _hex(value: Any, size: int, name: str) -> None:
    if type(value) is not str or len(value) != size * 2 or not _HEX.fullmatch(value):
        raise TranscriptError(name + " must be exact-length lowercase hex")


def _script(value: Any, name: str) -> None:
    if (type(value) is not str or not 2 <= len(value) <= 20_000
            or len(value) % 2 or not _HEX.fullmatch(value)):
        raise TranscriptError(name + " must be bounded nonempty lowercase hex")


def _point(value: Any, name: str) -> None:
    _hex(value, 33, name)
    if value[:2] not in ("02", "03"):
        raise TranscriptError(name + " requires a compressed SEC1 encoding")
    # Encoding shape only: actual point parsing belongs to the selected backend.


def _signer_keys(value: Any, name: str) -> None:
    if type(value) is not list or len(value) != 2:
        raise TranscriptError(name + " must contain the ordered Alice and Bob keys")
    for key in value:
        _point(key, name)
    if value[0] == value[1]:
        raise TranscriptError(name + " requires distinct encoded signer keys")


def _network(value: Any, zenon: bool) -> None:
    fields = "label genesis_hash_hex" + (" chain_id" if zenon else "")
    _object(value, fields, "network")
    if type(value["label"]) is not str or not _LABEL.fullmatch(value["label"]):
        raise TranscriptError("network label must be a bounded lowercase ASCII label")
    _hex(value["genesis_hash_hex"], 32, "genesis hash")
    if zenon:
        _uint(value["chain_id"], 64, "Zenon chain ID", 1)


def _validate_terms(data: Dict[str, Any]) -> None:
    _object(data, "schema construction session_id alice_id_hex bob_id_hex bitcoin_network "
            "zenon_network adaptor_point_sec1_hex bitcoin zenon policy", "terms")
    _literal(data["schema"], "ptlc-session-terms-v1", "terms schema")
    _literal(data["construction"], "CANDIDATE-01", "construction")
    for field in ("session_id", "alice_id_hex", "bob_id_hex"):
        _hex(data[field], 32, field)
    if data["alice_id_hex"] == data["bob_id_hex"]:
        raise TranscriptError("participant identifiers must be distinct")
    _network(data["bitcoin_network"], False)
    _network(data["zenon_network"], True)
    _point(data["adaptor_point_sec1_hex"], "adaptor point")
    btc = _object(data["bitcoin"], "value_sats claim_output_value_sats "
                  "claim_destination_script_pubkey_hex refund_destination_script_pubkey_hex "
                  "funding_script_pubkey_hex signer_keys_sec1_hex internal_key_xonly_hex "
                  "output_key_xonly_hex refund_key_xonly_hex refund_leaf_script_hex "
                  "tapleaf_hash_hex refund_locktime sighash_type", "Bitcoin terms")
    for field in ("value_sats", "claim_output_value_sats"):
        _uint(btc[field], 64, field, 1)
        if btc[field] > 2_100_000_000_000_000:
            raise TranscriptError("Bitcoin amount exceeds the money range")
    if btc["claim_output_value_sats"] >= btc["value_sats"]:
        raise TranscriptError("this fixed-fee candidate requires output value below input value")
    for field in ("claim_destination_script_pubkey_hex", "refund_destination_script_pubkey_hex",
                  "funding_script_pubkey_hex", "refund_leaf_script_hex"):
        _script(btc[field], field)
    for field in ("internal_key_xonly_hex", "output_key_xonly_hex", "refund_key_xonly_hex",
                  "tapleaf_hash_hex"):
        _hex(btc[field], 32, field)
    _signer_keys(btc["signer_keys_sec1_hex"], "Bitcoin signer keys")
    _uint(btc["refund_locktime"], 32, "Bitcoin time-based refund locktime", 500_000_000)
    _literal(btc["sighash_type"], "DEFAULT", "Bitcoin sighash type")
    znn = _object(data["zenon"], "amount_base_units token_standard_hex destination_hex "
                  "refund_owner_hex expiry signer_keys_sec1_hex aggregate_key_xonly_hex "
                  "point_type message_rule", "Zenon terms")
    _uint(znn["amount_base_units"], 256, "Zenon amount", 1)
    _hex(znn["token_standard_hex"], 10, "Zenon token standard")
    for field in ("destination_hex", "refund_owner_hex"):
        _hex(znn[field], 20, field)
    _uint(znn["expiry"], 63, "positive signed-int64 Zenon expiry", 1)
    _signer_keys(znn["signer_keys_sec1_hex"], "Zenon signer keys")
    if set(btc["signer_keys_sec1_hex"]) & set(znn["signer_keys_sec1_hex"]):
        raise TranscriptError("this candidate requires distinct encoded keys across legs")
    _hex(znn["aggregate_key_xonly_hex"], 32, "Zenon aggregate key")
    _literal(znn["point_type"], 1, "proposed core BIP340 point type")
    _literal(znn["message_rule"], "SHA3-256(entry_id32 || destination20)", "Zenon message rule")
    policy = _object(data["policy"], "bitcoin_confirmations zenon_confirmations "
                     "minimum_claim_margin_seconds", "synthetic policy")
    for field, value in policy.items():
        _uint(value, 32, field, 1)


@dataclass(frozen=True, init=False)
class Commitment:
    """An immutable public snapshot, created only by the module's factories."""

    _encoded: bytes

    def __init__(self) -> None:
        raise TypeError("use the validated transcript factory functions")

    @property
    def canonical_bytes(self) -> bytes:
        return self._encoded

    @property
    def stage(self) -> str:
        return self.as_dict().get("stage")

    @property
    def session_id(self) -> str:
        return self.as_dict()["session_id"]

    @property
    def digest_hex(self) -> str:
        return hashlib.sha256(
            _DOMAIN + self.stage.encode("ascii") + b"\x00" + self._encoded
        ).hexdigest()

    def as_dict(self) -> Dict[str, Any]:
        """Return a fresh mutable copy, never an alias of committed inputs."""
        if type(self._encoded) is not bytes or len(self._encoded) > _MAX_ENCODED_BYTES:
            raise TranscriptError("serialized commitment exceeds its byte boundary")
        try:
            result = json.loads(self._encoded.decode("ascii"))
        except (ValueError, UnicodeError, RecursionError) as error:
            raise TranscriptError("serialized commitment is not bounded ASCII JSON") from error
        if type(result) is not dict:
            raise TranscriptError("serialized commitment must be an object")
        return result


def _make(stage: str, session_id: str, **fields: Any) -> Commitment:
    payload = {"schema": SCHEMA, "stage": stage, "session_id": session_id, **fields}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(encoded) > _MAX_ENCODED_BYTES:
        raise TranscriptError("canonical commitment exceeds its byte boundary")
    result = object.__new__(Commitment)
    object.__setattr__(result, "_encoded", encoded)
    return result


def agree_terms(raw: Dict[str, Any]) -> Commitment:
    """Freeze agreed public terms before either chain-specific signing binding."""
    data = _snapshot(raw)
    _validate_terms(data)
    return _make("terms", data["session_id"], terms=data)


def _require(value: Commitment, stage: str) -> None:
    if type(value) is not Commitment or value.stage != stage:
        raise TranscriptError("a validated " + stage + " commitment is required")
    reconstructed = _restore(value.as_dict())
    if reconstructed.canonical_bytes != value.canonical_bytes:
        raise TranscriptError("commitment is not its canonical validated reconstruction")


def bind_bitcoin(terms: Commitment, raw: Dict[str, Any]) -> Commitment:
    """Bind exact funding and supplied claim digest, without needing a Zenon ID."""
    _require(terms, "terms")
    data = _snapshot(raw)
    _object(data, "funding_txid_hex funding_vout value_sats script_pubkey_hex "
            "claim_txid_hex claim_sighash_hex claim_destination_script_pubkey_hex "
            "claim_output_value_sats transaction_version sequence locktime sighash_type",
            "Bitcoin binding")
    for field in ("funding_txid_hex", "claim_txid_hex", "claim_sighash_hex"):
        _hex(data[field], 32, field)
    _uint(data["funding_vout"], 32, "funding vout")
    agreed = terms.as_dict()["terms"]
    btc = agreed["bitcoin"]
    for field in ("value_sats", "claim_output_value_sats", "claim_destination_script_pubkey_hex",
                  "sighash_type"):
        _literal(data[field], btc[field], field)
    _literal(data["script_pubkey_hex"], btc["funding_script_pubkey_hex"], "funding script")
    for field, expected in (("transaction_version", 2), ("sequence", 0xFFFFFFFD), ("locktime", 0)):
        _literal(data[field], expected, field)
    return _make("bitcoin", terms.session_id, terms=agreed,
                 terms_digest_hex=terms.digest_hex, binding=data)


def bind_zenon(bitcoin: Commitment, raw: Dict[str, Any]) -> Commitment:
    """Extend a Bitcoin commitment with an actual supplied entry ID and message."""
    _require(bitcoin, "bitcoin")
    data = _snapshot(raw)
    _object(data, "entry_id_hex destination_hex message_hex amount_base_units token_standard_hex "
            "refund_owner_hex expiry aggregate_key_xonly_hex point_type", "Zenon binding")
    _hex(data["entry_id_hex"], 32, "Zenon entry ID")
    _hex(data["message_hex"], 32, "Zenon message")
    agreed = bitcoin.as_dict()["terms"]["zenon"]
    for field in ("destination_hex", "amount_base_units", "token_standard_hex", "refund_owner_hex",
                  "expiry", "aggregate_key_xonly_hex", "point_type"):
        _literal(data[field], agreed[field], field)
    expected_message = hashlib.sha3_256(
        bytes.fromhex(data["entry_id_hex"]) + bytes.fromhex(data["destination_hex"])
    ).hexdigest()
    _literal(data["message_hex"], expected_message, "Zenon consensus message")
    return _make("zenon", bitcoin.session_id, bitcoin=bitcoin.as_dict(),
                 bitcoin_digest_hex=bitcoin.digest_hex, binding=data)


def _chain_binding(binding: Commitment) -> None:
    if type(binding) is not Commitment or binding.stage not in ("bitcoin", "zenon"):
        raise TranscriptError("a validated Bitcoin or Zenon binding is required")
    _require(binding, binding.stage)


def _public_nonce(value: Any) -> None:
    """Check the 66-byte PubNonce shape, not membership on the curve.

    The pinned musig2 PubNonce encoding is compressed R1 || compressed R2;
    aggregate nonces allowing infinity have a separate backend type.
    """
    _hex(value, 66, "public nonce")
    for component in (value[:66], value[66:]):
        _point(component, "public nonce component")
        if component[2:] == "00" * 32:
            raise TranscriptError("zero public nonce component is unsupported")


def nonce_commitment(binding: Commitment, round_id: str, role: str,
                     public_nonce_hex: str) -> str:
    """Hash a supplied public nonce's role and exact binding/round context."""
    _chain_binding(binding)
    _hex(round_id, 32, "nonce round ID")
    if type(role) is not str or role not in ("alice", "bob"):
        raise TranscriptError("public nonce role must be Alice or Bob")
    _public_nonce(public_nonce_hex)
    return _make("nonce-opening", binding.session_id, leg=binding.stage,
                 binding_digest_hex=binding.digest_hex, round_id=round_id,
                 role=role, public_nonce_hex=public_nonce_hex).digest_hex


def commit_nonce_round(binding: Commitment, round_id: str,
                       alice_commitment_hex: str, bob_commitment_hex: str) -> Commitment:
    """Freeze both role-bound hashes before the reveal factory accepts openings.

    No transport or durable exchange is performed, and these hashes do not
    authenticate their claimed senders.
    """
    _chain_binding(binding)
    _hex(round_id, 32, "nonce round ID")
    _hex(alice_commitment_hex, 32, "Alice nonce commitment")
    _hex(bob_commitment_hex, 32, "Bob nonce commitment")
    if alice_commitment_hex == bob_commitment_hex:
        raise TranscriptError("reflected equal nonce commitments are unsupported")
    return _make("nonce-commitments", binding.session_id, leg=binding.stage,
                 round_id=round_id, binding_digest_hex=binding.digest_hex,
                 binding=binding.as_dict(),
                 commitments={"alice": alice_commitment_hex, "bob": bob_commitment_hex})


def reveal_nonce_round(commitments: Commitment, alice_public_nonce_hex: str,
                       bob_public_nonce_hex: str) -> Commitment:
    """Check both openings against the frozen pair and commit the public round."""
    _require(commitments, "nonce-commitments")
    _public_nonce(alice_public_nonce_hex)
    _public_nonce(bob_public_nonce_hex)
    if alice_public_nonce_hex == bob_public_nonce_hex:
        raise TranscriptError("Alice and Bob must not supply the same public nonce")
    frozen = commitments.as_dict()
    binding = _restore(frozen["binding"])
    for role, public_nonce in (("alice", alice_public_nonce_hex), ("bob", bob_public_nonce_hex)):
        opening = nonce_commitment(binding, frozen["round_id"], role, public_nonce)
        _literal(opening, frozen["commitments"][role], role + " nonce opening")
    return _make("nonce-round", binding.session_id, leg=binding.stage,
                 round_id=frozen["round_id"], binding_digest_hex=binding.digest_hex,
                 commitments_digest_hex=commitments.digest_hex,
                 commitments=frozen,
                 public_nonces={"alice": alice_public_nonce_hex, "bob": bob_public_nonce_hex})


def validate_nonce_round(nonce_round: Commitment) -> Tuple[str, str, str, str]:
    """Return (session ID, binding digest, round ID, round digest), fully rebuilt."""
    _require(nonce_round, "nonce-round")
    data = nonce_round.as_dict()
    return (nonce_round.session_id, data["binding_digest_hex"], data["round_id"],
            nonce_round.digest_hex)


def signing_context(binding: Commitment, role: str, purpose: str, *,
                    nonce_round: Optional[Commitment] = None) -> Commitment:
    """Bind one explicit signing/completion purpose and role to a staged context."""
    if type(purpose) is not str or purpose not in _PURPOSES:
        raise TranscriptError("unknown signing purpose")
    leg, roles = _PURPOSES[purpose]
    if type(role) is not str or role not in roles:
        raise TranscriptError("role is not allowed for this signing purpose")
    _require(binding, leg)
    fields = {}
    if nonce_round is not None:
        _require(nonce_round, "nonce-round")
        round_data = nonce_round.as_dict()
        _literal(round_data["binding_digest_hex"], binding.digest_hex, "nonce round binding")
        _literal(round_data["leg"], leg, "nonce round leg")
        _literal(nonce_round.session_id, binding.session_id, "nonce round session")
        fields = {"nonce_round": round_data, "nonce_round_digest_hex": nonce_round.digest_hex}
    return _make("signing-context", binding.session_id, leg=leg, role=role, purpose=purpose,
                 binding_digest_hex=binding.digest_hex, binding=binding.as_dict(), **fields)


def _restore(data: Dict[str, Any]) -> Commitment:
    """Reconstruct a finite staged snapshot; never trust supplied digest fields."""
    if type(data) is not dict or data.get("schema") != SCHEMA:
        raise TranscriptError("unsupported commitment schema")
    stage = data.get("stage")
    base = "schema stage session_id "
    if stage == "terms":
        _object(data, base + "terms", "terms commitment")
        result = agree_terms(data["terms"])
    elif stage == "bitcoin":
        _object(data, base + "terms terms_digest_hex binding", "Bitcoin commitment")
        parent = agree_terms(data["terms"])
        result = bind_bitcoin(parent, data["binding"])
    elif stage == "zenon":
        _object(data, base + "bitcoin bitcoin_digest_hex binding", "Zenon commitment")
        if type(data["bitcoin"]) is not dict or data["bitcoin"].get("stage") != "bitcoin":
            raise TranscriptError("Zenon commitment requires its Bitcoin predecessor")
        result = bind_zenon(_restore(data["bitcoin"]), data["binding"])
    elif stage == "nonce-commitments":
        _object(data, base + "leg round_id binding_digest_hex binding commitments", "nonce commitments")
        if type(data["binding"]) is not dict or data["binding"].get("stage") not in ("bitcoin", "zenon"):
            raise TranscriptError("nonce commitments require a chain binding")
        hashes = _object(data["commitments"], "alice bob", "role-bound nonce hashes")
        result = commit_nonce_round(_restore(data["binding"]), data["round_id"],
                                    hashes["alice"], hashes["bob"])
    elif stage == "nonce-round":
        _object(data, base + "leg round_id binding_digest_hex commitments_digest_hex "
                "commitments public_nonces", "nonce round")
        if (type(data["commitments"]) is not dict
                or data["commitments"].get("stage") != "nonce-commitments"):
            raise TranscriptError("nonce round requires both prior commitments")
        nonces = _object(data["public_nonces"], "alice bob", "role-bound public nonces")
        result = reveal_nonce_round(_restore(data["commitments"]), nonces["alice"], nonces["bob"])
    elif stage == "signing-context":
        dynamic = "nonce_round" in data or "nonce_round_digest_hex" in data
        extra_fields = " nonce_round nonce_round_digest_hex" if dynamic else ""
        _object(data, base + "leg role purpose binding_digest_hex binding" + extra_fields, "signing context")
        if type(data["binding"]) is not dict or data["binding"].get("stage") not in ("bitcoin", "zenon"):
            raise TranscriptError("signing context requires a chain binding")
        nonce_round = None
        if dynamic:
            if type(data["nonce_round"]) is not dict or data["nonce_round"].get("stage") != "nonce-round":
                raise TranscriptError("dynamic signing context requires a revealed nonce round")
            nonce_round = _restore(data["nonce_round"])
        result = signing_context(_restore(data["binding"]), data["role"], data["purpose"],
                                 nonce_round=nonce_round)
    else:
        raise TranscriptError("unsupported commitment stage")
    if result.as_dict() != data:
        raise TranscriptError("commitment differs from its validated staged reconstruction")
    return result


def validate_signing_context(context: Commitment) -> Tuple[str, str, str]:
    """Return (session_id, digest_hex, purpose) after full staged reconstruction.

    This is schema/context validation only. It conveys no counterparty approval,
    chain observation, usable pre-signature, or authorization to release a secret.
    """
    _require(context, "signing-context")
    return context.session_id, context.digest_hex, context.as_dict()["purpose"]
