"""Source differential boundaries for public NoM encoding, not transaction use."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

from offline_session.nom_wire import (
    WIRE_PROFILE, MAX_BYTES, MAX_DESCENDANTS, encode_call, decode_call,
    account_block_hash, account_block_preimage, method_selector,
)
from offline_session.pr138 import CORE_COMMIT, CompatibilityError

ROOT = Path(__file__).resolve().parents[1]


class NoMWireTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "compatibility/fixtures/nom_wire_v1.json").read_text("ascii"))
        self.block = self.data["hash_vectors"][0]["block"]

    def test_source_pin_and_profile_are_separate_from_application_permission(self):
        self.assertEqual((self.data["core_commit"], self.data["profile"]), (CORE_COMMIT, WIRE_PROFILE))
        self.assertEqual((self.data["application"], self.data["core"]), ("NO-GO", "NO-GO"))
        self.assertEqual(len(self.data["abi_vectors"]), 12)
        self.assertEqual(len(self.data["normalization_vectors"]), 7)
        self.assertEqual(len(self.data["hash_vectors"]), 22)

    def test_four_methods_roundtrip_all_canonical_vectors(self):
        for value in self.data["abi_vectors"]:
            with self.subTest(value=value["id"]):
                wire = encode_call(value["call"])
                self.assertEqual(wire.hex(), value["data_hex"])
                self.assertEqual(decode_call(wire), value["call"])
        for method, value in self.data["selectors"].items():
            self.assertEqual(method_selector(method).hex(), value["hex"])

    def test_local_canonicality_and_core_send_acceptance_are_distinct(self):
        for value in self.data["normalization_vectors"]:
            with self.subTest(value=value["id"]):
                wire = bytes.fromhex(value["data_hex"])
                if value["reference_decodes"]:
                    self.assertEqual(encode_call(decode_call(wire)), wire)
                    self.assertFalse(value["core_send_accepts"])
                else:
                    with self.assertRaises(CompatibilityError): decode_call(wire)
                if value["core_send_accepts"]:
                    canonical = bytes.fromhex(value["normalized_hex"])
                    self.assertNotEqual(wire, canonical)
                    self.assertEqual(encode_call(decode_call(canonical)), canonical)
                    self.assertNotEqual(account_block_hash(dict(self.block, data_hex=wire.hex())),
                                        account_block_hash(dict(self.block, data_hex=canonical.hex())))

    def test_every_hash_input_and_order_binds(self):
        baseline = self.data["hash_vectors"][0]["hash_hex"]
        seen = set()
        for value in self.data["hash_vectors"]:
            with self.subTest(value=value["id"]):
                preimage = account_block_preimage(value["block"])
                self.assertEqual(len(preimage), 306)
                self.assertEqual(preimage.hex(), value["preimage_hex"])
                self.assertEqual(account_block_hash(value["block"]), value["hash_hex"])
                self.assertNotIn(value["hash_hex"], seen)
                seen.add(value["hash_hex"])
                if value["id"] != "unlock-baseline": self.assertNotEqual(value["hash_hex"], baseline)

    def test_hash_digest_does_not_encode_the_rpc_or_signed_wire(self):
        value = account_block_hash(self.block)
        self.assertNotEqual(value, hashlib.sha3_256(json.dumps(self.block, sort_keys=True).encode()).hexdigest())
        self.assertNotEqual(account_block_preimage(self.block), bytes.fromhex(self.block["data_hex"]))
        for field in self.data["excluded_hash_fields"]:
            with self.subTest(field=field), self.assertRaises(CompatibilityError):
                account_block_hash(dict(self.block, **{field: "synthetic-untrusted-claim"}))

    def test_hash_widths_aliases_and_unknown_fields_are_refused(self):
        bad = [("amount", "-1"), ("amount", str(1 << 256)), ("amount", 0), ("height", True),
               ("height", "01"), ("height", str(1 << 64)), ("nonce_hex", "00" * 7),
               ("address_hex", "AA" * 20), ("token_standard_hex", "00" * 11),
               ("data_hex", "0"), ("descendant_hashes_hex", ("00" * 32,)),
               ("descendant_hashes_hex", ["00" * 31]), ("genesis_hash_hex", "00" * 32)]
        for name, value in bad:
            with self.subTest(name=name, value=value), self.assertRaises(CompatibilityError):
                account_block_hash(dict(self.block, **{name: value}))

    def test_public_resource_boundaries_refuse_before_unbounded_decoding(self):
        for name, value in (("data_hex", "00" * (MAX_BYTES + 1)),
                            ("descendant_hashes_hex", ["00" * 32] * (MAX_DESCENDANTS + 1))):
            with self.subTest(name=name), self.assertRaises(CompatibilityError):
                account_block_preimage(dict(self.block, **{name: value}))
        with self.assertRaises(CompatibilityError): decode_call(bytes(MAX_BYTES + 197))

    def test_signed_expiration_and_uint8_aliases_do_not_wrap(self):
        call = self.data["abi_vectors"][0]["call"]
        for key, value in (("expiration_time", "-0"), ("expiration_time", "01"),
                           ("expiration_time", str(1 << 63)), ("expiration_time", str(-(1 << 63) - 1)),
                           ("expiration_time", False), ("point_type", True), ("point_type", 256),
                           ("method", "Unknown"), ("extra", 0)):
            with self.subTest(key=key, value=value), self.assertRaises(CompatibilityError):
                encode_call(dict(call, **{key: value}))

    def test_nonzero_tail_padding_and_signed_extension_are_refused(self):
        point = bytearray(bytes.fromhex(self.data["abi_vectors"][8]["data_hex"])); point[-1] = 1
        negative = bytearray(bytes.fromhex(self.data["abi_vectors"][9]["data_hex"])); negative[4] = 0
        for wire in (bytes(point), bytes(negative)):
            with self.assertRaises(CompatibilityError): decode_call(wire)

    def test_each_canonical_wire_truncation_is_refused(self):
        for value in self.data["abi_vectors"]:
            wire = bytes.fromhex(value["data_hex"])
            for boundary in (0, 4, 35, len(wire) - 1):
                with self.subTest(value=value["id"], boundary=boundary), self.assertRaises(CompatibilityError):
                    decode_call(wire[:boundary])
            with self.assertRaises(CompatibilityError): decode_call(wire + b"\x00")

    def test_only_advertised_descendant_hashes_are_committed(self):
        child = copy.deepcopy(self.block); changed_child = dict(child, amount="100")
        parent = dict(self.block, descendant_hashes_hex=[account_block_hash(child)])
        expected = account_block_hash(parent)
        self.assertNotEqual(account_block_hash(child), account_block_hash(changed_child))
        self.assertEqual(account_block_hash(parent), expected)
        self.assertNotEqual(account_block_hash(dict(parent, descendant_hashes_hex=[account_block_hash(changed_child)])), expected)

    def test_synthetic_fixture_is_reproducible_without_account_keys(self):
        spec = importlib.util.spec_from_file_location("nom_wire_generator", ROOT / "scripts/generate_nom_wire.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertEqual(module.corpus(), self.data)

    def test_additive_manifest_pins_inputs_and_keeps_old_compatibility_subject(self):
        manifest = json.loads((ROOT / "compatibility/nom_wire_manifest.json").read_text("ascii"))
        self.assertEqual(manifest["core_commit"], CORE_COMMIT)
        self.assertEqual(manifest["expected_counts"], {"abi": 12, "normalization": 7, "hash": 22, "controls": 3})
        self.assertEqual((manifest["application"], manifest["core"], manifest["assessment"]), ("NO-GO", "NO-GO", "UNFILLED"))
        for name, expected in manifest["input_sha256"].items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected)
        for value in manifest["sources"]:
            self.assertTrue(value["url"].startswith("https://github.com/zenon-network/go-zenon/blob/" + CORE_COMMIT + "/"))
        old = json.loads((ROOT / "compatibility/manifest.json").read_text("ascii"))
        for group in ("fixture_sha256", "current_module_sha256", "legacy_file_sha256"):
            for name, expected in old[group].items():
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected)
