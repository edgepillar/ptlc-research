#!/usr/bin/env python3
"""Generate synthetic public wire/hash controls; no key or signer is used."""

import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_wire import WIRE_PROFILE, SIGNATURES, method_selector, encode_call, account_block_preimage, account_block_hash
from offline_session.pr138 import CORE_COMMIT, CONTRACT_HEX


def corpus():
    terms = json.loads((ROOT / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
    completed = json.loads((ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
    calls = []
    def call(name, value):
        wire = encode_call(value)
        calls.append({"id": name, "call": value, "data_hex": wire.hex()})
        return wire
    for leg in ("long", "short"):
        selected = terms[leg]
        call("create-" + leg, {"method": "Create", "expiration_time": selected["expires_at"],
             "point_type": 1, "point_lock_hex": selected["funder_key_xonly_hex"],
             "destination_hex": terms[selected["recipient"] + "_address_hex"]})
        call("unlock-" + leg, {"method": "Unlock", "entry_id_hex": selected["entry_id_hex"],
             "witness_hex": completed[leg + "_signature_hex"]})
        call("proxy-" + leg, {"method": "ProxyUnlock", "entry_id_hex": selected["entry_id_hex"],
             "destination_hex": terms[selected["recipient"] + "_address_hex"],
             "witness_hex": completed[leg + "_signature_hex"]})
        call("reclaim-" + leg, {"method": "Reclaim", "entry_id_hex": selected["entry_id_hex"]})
    call("create-point-33", {"method": "Create", "expiration_time": "9223372036854775807",
         "point_type": 2, "point_lock_hex": terms["adaptor_point_sec1_hex"], "destination_hex": terms["alice_address_hex"]})
    call("create-int64-min-wire-only", {"method": "Create", "expiration_time": "-9223372036854775808",
         "point_type": 255, "point_lock_hex": "", "destination_hex": "00" * 20})
    small = call("unlock-scalar-width", {"method": "Unlock", "entry_id_hex": "aa" * 32, "witness_hex": "bb" * 32})
    short = call("unlock-invalid-witness-width", {"method": "Unlock", "entry_id_hex": "aa" * 32, "witness_hex": "bb" * 31})
    proxy = bytes.fromhex(calls[2]["data_hex"])
    normalization = []
    def variant(name, raw, normalized, accepts, strict):
        normalization.append({"id": name, "data_hex": raw.hex(), "normalized_hex": normalized.hex(),
                              "core_send_accepts": accepts, "reference_decodes": strict})
    variant("unlock-trailing-word", small + bytes(32), small, True, False)
    gap = small[:36] + (96).to_bytes(32, "big") + bytes(32) + small[68:]
    variant("unlock-offset-gap", gap, small, True, False)
    high = bytearray(proxy); high[36] = 1
    variant("proxy-address-high-padding", bytes(high), proxy, True, False)
    variant("proxy-trailing-byte", proxy + b"\x01", proxy, True, False)
    variant("unlock-wrong-selector", bytes(4) + small[4:], b"", False, False)
    variant("unlock-incomplete-head", small[:35], b"", False, False)
    variant("unlock-nonadmitted-width", short, b"", False, True)
    baseline = {"version": "1", "chain_id": "69", "block_type": "2",
                "previous_hash_hex": "31" * 32, "height": "7", "momentum_hash_hex": "32" * 32,
                "momentum_height": "100", "address_hex": terms["alice_address_hex"], "to_address_hex": CONTRACT_HEX,
                "amount": "0", "token_standard_hex": "00" * 10, "from_block_hash_hex": "00" * 32,
                "descendant_hashes_hex": [], "data_hex": calls[1]["data_hex"], "fused_plasma": "21000",
                "difficulty": "0", "nonce_hex": "00" * 8}
    blocks = []
    def block(name, value):
        blocks.append({"id": name, "block": value, "preimage_hex": account_block_preimage(value).hex(),
                       "hash_hex": account_block_hash(value)})
    block("unlock-baseline", baseline)
    mutations = {"version": "2", "chain_id": "70", "block_type": "3", "previous_hash_hex": "41" * 32,
                 "height": "8", "momentum_hash_hex": "42" * 32, "momentum_height": "101",
                 "address_hex": terms["bob_address_hex"], "to_address_hex": terms["bob_address_hex"],
                 "amount": "1", "token_standard_hex": "01" * 10, "from_block_hash_hex": "43" * 32,
                 "descendant_hashes_hex": ["44" * 32], "data_hex": calls[5]["data_hex"],
                 "fused_plasma": "21001", "difficulty": "1", "nonce_hex": "00" * 7 + "01"}
    for key, value in mutations.items():
        changed = copy.deepcopy(baseline); changed[key] = value
        block("change-" + key, changed)
    maximum = copy.deepcopy(baseline)
    for key in ("version", "chain_id", "block_type", "height", "momentum_height", "fused_plasma", "difficulty"):
        maximum[key] = str((1 << 64) - 1)
    maximum["amount"] = str((1 << 256) - 1)
    block("maximum-widths-wire-only", maximum)
    for name, descendants in (("descendants-forward", ["51" * 32, "52" * 32]),
                              ("descendants-reversed", ["52" * 32, "51" * 32])):
        changed = copy.deepcopy(baseline); changed["descendant_hashes_hex"] = descendants; block(name, changed)
    changed = copy.deepcopy(baseline); changed["data_hex"] = ""; block("empty-data", changed)
    return {"schema": "zenon-nom-wire-corpus-v1", "profile": WIRE_PROFILE, "core_commit": CORE_COMMIT,
            "origin": "Public synthetic encoding controls; no account key, nonce secret or signer input.",
            "selectors": {name: {"signature": signature, "hex": method_selector(name).hex()}
                          for name, signature in SIGNATURES.items()}, "abi_vectors": calls,
            "normalization_vectors": normalization, "hash_vectors": blocks,
            "excluded_hash_fields": ["hash", "basePlasma", "usedPlasma", "changesHash", "publicKey", "signature"],
            "controls": ["unsigned-metadata-hash-equivalence", "advertised-child-hash-not-recomputed",
                         "negative-amount-magnitude-is-not-admission"],
            "application": "NO-GO", "core": "NO-GO"}


if __name__ == "__main__":
    (ROOT / "compatibility/fixtures/nom_wire_v1.json").write_text(json.dumps(corpus(), indent=2, sort_keys=True) + "\n", encoding="ascii")
