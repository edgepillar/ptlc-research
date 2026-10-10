"""Strict public codec for one pinned PR #138 profile, independent of PR #13.

This module implements no curve arithmetic, signature verification, VM, address
ownership, activation check, or chain observation. Raw address bytes avoid an
implicit Bech32 conversion at this boundary. SHA3-256 is not legacy Keccak.
"""

import hashlib
import re


PROFILE = "zenon-ptlc-unlock:v1"
CORE_COMMIT = "45e1bbb48ce6fc19d44c5fbf59ccf5784981fced"
CONTRACT_HEX = "01b3b6e5adcb4c15ff06318c6318c6318c6318c6"
CONTEXT_FIELDS = frozenset({"profile", "chain_id", "point_type", "entry_id_hex", "destination_hex"})


class CompatibilityError(ValueError):
    """Public, sanitized profile refusal."""


def fixed_hex(value, size):
    if type(value) is not str or len(value) != 2 * size or re.fullmatch("[0-9a-f]+", value) is None:
        raise CompatibilityError("invalid canonical public encoding")
    return bytes.fromhex(value)


def decimal(value, bits, *, positive=False):
    if (type(value) is not str or len(value) > len(str((1 << bits) - 1))
            or re.fullmatch("0|[1-9][0-9]*", value) is None):
        raise CompatibilityError("invalid canonical unsigned integer")
    number = int(value)
    if number >= 1 << bits or (positive and number == 0):
        raise CompatibilityError("unsigned integer is outside its boundary")
    return number


def payable(destination_hex):
    address = fixed_hex(destination_hex, 20)
    return address[0] == 0 and any(address)


def unlock_preimage(context):
    """Encode all 101 bytes. Encoding is separate from destination admission."""
    if type(context) is not dict or context.keys() != CONTEXT_FIELDS or context["profile"] != PROFILE:
        raise CompatibilityError("unsupported unlock profile or fields")
    chain = decimal(context["chain_id"], 64)
    point = context["point_type"]
    if type(point) is not int or point not in (0, 1, 2):
        raise CompatibilityError("unsupported point type")
    entry = fixed_hex(context["entry_id_hex"], 32)
    destination = fixed_hex(context["destination_hex"], 20)
    return (PROFILE.encode("ascii") + chain.to_bytes(8, "big")
            + bytes.fromhex(CONTRACT_HEX) + bytes([point]) + entry + destination)


def unlock_message(context):
    return hashlib.sha3_256(unlock_preimage(context)).hexdigest()


def create_destination_allowed(point_type, destination_hex):
    if type(point_type) is not int or point_type not in (0, 1, 2):
        raise CompatibilityError("unsupported point type")
    destination = fixed_hex(destination_hex, 20)
    return payable(destination_hex) or (point_type in (0, 1) and not any(destination))


def send_witness_size_allowed(size):
    """Send admission is a size union; stored type controls receive verification."""
    return type(size) is int and size in (32, 64)
