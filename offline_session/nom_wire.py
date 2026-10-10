"""Bounded public ABI/hash conformance for the pinned PR #138 source.

This is research encoding, not a transaction builder, account signer, protobuf
serializer or authenticated chain observer. Canonical admission here is stricter
than the node ABI decoder. Descendant hashes are supplied claims, not recursively
verified blocks. Account metadata and signed wire bytes remain separate subjects.
"""

import hashlib
import re

from .pr138 import CompatibilityError, decimal, fixed_hex


WIRE_PROFILE = "zenon-pr138-public-wire-v1"
MAX_BYTES = 4096
MAX_DESCENDANTS = 64
SIGNATURES = {
    "Create": "Create(int64,uint8,bytes,address)",
    "Unlock": "Unlock(hash,bytes)",
    "ProxyUnlock": "ProxyUnlock(hash,address,bytes)",
    "Reclaim": "Reclaim(hash)",
}
CALL_FIELDS = {
    "Create": frozenset({"method", "expiration_time", "point_type", "point_lock_hex", "destination_hex"}),
    "Unlock": frozenset({"method", "entry_id_hex", "witness_hex"}),
    "ProxyUnlock": frozenset({"method", "entry_id_hex", "destination_hex", "witness_hex"}),
    "Reclaim": frozenset({"method", "entry_id_hex"}),
}
BLOCK_FIELDS = frozenset({
    "version", "chain_id", "block_type", "previous_hash_hex", "height",
    "momentum_hash_hex", "momentum_height", "address_hex", "to_address_hex",
    "amount", "token_standard_hex", "from_block_hash_hex", "descendant_hashes_hex",
    "data_hex", "fused_plasma", "difficulty", "nonce_hex",
})


def _bytes(value):
    if (type(value) is not str or len(value) > 2 * MAX_BYTES or len(value) % 2
            or re.fullmatch("[0-9a-f]*", value) is None):
        raise CompatibilityError("invalid bounded public bytes")
    return bytes.fromhex(value)


def _word(number):
    return (number % (1 << 256)).to_bytes(32, "big")


def _int64(value):
    if (type(value) is not str or len(value) > 20
            or re.fullmatch("0|[1-9][0-9]*|-[1-9][0-9]*", value) is None):
        raise CompatibilityError("invalid canonical signed integer")
    number = int(value)
    if not -(1 << 63) <= number < (1 << 63):
        raise CompatibilityError("signed integer is outside its boundary")
    return number


def _tail(raw):
    return _word(len(raw)) + raw + bytes((-len(raw)) % 32)


def method_selector(method):
    if type(method) is not str or method not in SIGNATURES:
        raise CompatibilityError("unsupported public method")
    return hashlib.sha3_256(SIGNATURES[method].encode("ascii")).digest()[:4]


def encode_call(call):
    """Canonical ABI bytes; widths do not establish contract admission."""
    if type(call) is not dict or type(call.get("method")) is not str:
        raise CompatibilityError("invalid public call")
    method = call["method"]
    if method not in CALL_FIELDS or call.keys() != CALL_FIELDS[method]:
        raise CompatibilityError("unexpected public call fields")
    selector = method_selector(method)
    if method == "Create":
        point = call["point_type"]
        if type(point) is not int or not 0 <= point <= 255:
            raise CompatibilityError("invalid wire point type")
        address = fixed_hex(call["destination_hex"], 20)
        return (selector + _word(_int64(call["expiration_time"])) + _word(point)
                + _word(128) + bytes(12) + address + _tail(_bytes(call["point_lock_hex"])))
    entry = fixed_hex(call["entry_id_hex"], 32)
    if method == "Reclaim":
        return selector + entry
    witness = _bytes(call["witness_hex"])
    if method == "Unlock":
        return selector + entry + _word(64) + _tail(witness)
    return (selector + entry + bytes(12) + fixed_hex(call["destination_hex"], 20)
            + _word(96) + _tail(witness))


def decode_call(wire):
    """Refuse aliases rather than normalize retained/disclosed original bytes."""
    if type(wire) is not bytes or not 4 < len(wire) <= MAX_BYTES + 196:
        raise CompatibilityError("invalid public ABI wire")
    methods = [name for name in SIGNATURES if method_selector(name) == wire[:4]]
    if len(methods) != 1:
        raise CompatibilityError("unsupported public selector")
    method = methods[0]
    payload = wire[4:]
    head_size = {"Create": 128, "Unlock": 64, "ProxyUnlock": 96, "Reclaim": 32}[method]
    if len(payload) < head_size:
        raise CompatibilityError("incomplete public ABI head")
    words = [payload[i:i + 32] for i in range(0, head_size, 32)]
    call = {"method": method}
    if method == "Create":
        number = int.from_bytes(words[0], "big", signed=True)
        call.update(expiration_time=str(number), point_type=int.from_bytes(words[1], "big"),
                    destination_hex=words[3][12:].hex())
    else:
        call["entry_id_hex"] = words[0].hex()
        if method == "ProxyUnlock":
            call["destination_hex"] = words[1][12:].hex()
    if method != "Reclaim":
        offset = int.from_bytes(words[2 if method == "Create" else -1], "big")
        if offset != head_size or len(payload) < offset + 32:
            raise CompatibilityError("noncanonical public ABI offset")
        length = int.from_bytes(payload[offset:offset + 32], "big")
        if length > MAX_BYTES or len(payload) != offset + 32 + ((length + 31) // 32) * 32:
            raise CompatibilityError("invalid public ABI tail boundary")
        raw = payload[offset + 32:offset + 32 + length]
        call["point_lock_hex" if method == "Create" else "witness_hex"] = raw.hex()
    if encode_call(call) != wire:
        raise CompatibilityError("noncanonical public ABI wire")
    return call


def account_block_preimage(block):
    """306 hash-input bytes; this is not AccountBlock.Serialize or RPC JSON."""
    if type(block) is not dict or block.keys() != BLOCK_FIELDS:
        raise CompatibilityError("unexpected public hash-input fields")
    u64 = lambda name: decimal(block[name], 64).to_bytes(8, "big")
    descendants = block["descendant_hashes_hex"]
    if type(descendants) is not list or len(descendants) > MAX_DESCENDANTS:
        raise CompatibilityError("invalid public descendant claims")
    descendant_bytes = b"".join(fixed_hex(value, 32) for value in descendants)
    data = _bytes(block["data_hex"])
    preimage = (u64("version") + u64("chain_id") + u64("block_type")
                + fixed_hex(block["previous_hash_hex"], 32) + u64("height")
                + fixed_hex(block["momentum_hash_hex"], 32) + u64("momentum_height")
                + fixed_hex(block["address_hex"], 20) + fixed_hex(block["to_address_hex"], 20)
                + decimal(block["amount"], 256).to_bytes(32, "big")
                + fixed_hex(block["token_standard_hex"], 10) + fixed_hex(block["from_block_hash_hex"], 32)
                + hashlib.sha3_256(descendant_bytes).digest() + hashlib.sha3_256(data).digest()
                + u64("fused_plasma") + u64("difficulty") + fixed_hex(block["nonce_hex"], 8))
    assert len(preimage) == 306
    return preimage


def account_block_hash(block):
    return hashlib.sha3_256(account_block_preimage(block)).hexdigest()
