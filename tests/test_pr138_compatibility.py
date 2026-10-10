"""Version, replay and admission boundaries for the additive PR #138 corpus."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

from offline_session.pr138 import (
    CompatibilityError, CORE_COMMIT, PROFILE, CONTRACT_HEX, unlock_message,
    unlock_preimage, create_destination_allowed, payable, send_witness_size_allowed,
)

ROOT = Path(__file__).resolve().parents[1]


class PR138CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "compatibility/fixtures/pr138_messages_v1.json").read_text("ascii"))
        self.context = self.data["message_vectors"][16]["context"]

    def test_all_vectors_bind_every_domain_field_and_preserve_legacy_boundary(self):
        self.assertEqual(self.data["core_commit"], CORE_COMMIT)
        self.assertEqual(self.data["contract_hex"], CONTRACT_HEX)
        self.assertEqual(len(self.data["message_vectors"]), 48)
        for v in self.data["message_vectors"]:
            with self.subTest(v=v["id"]):
                raw = unlock_preimage(v["context"])
                self.assertEqual(len(raw), 101)
                self.assertEqual(raw.hex(), v["preimage_hex"])
                self.assertEqual(unlock_message(v["context"]), v["message_hex"])
                self.assertEqual(hashlib.sha3_256(raw[49:]).hexdigest(), v["legacy_message_hex"])
                self.assertNotEqual(v["legacy_message_hex"], v["message_hex"])
                for offset in (0, 20, 28, 48, 49, 81):
                    altered = bytearray(raw); altered[offset] ^= 1
                    self.assertNotEqual(hashlib.sha3_256(altered).hexdigest(), v["message_hex"])

    def test_unknown_profile_extra_fields_and_aliases_are_refused(self):
        for field, value in [("profile", "zenon-ptlc-unlock:v2"), ("profile", "legacy"),
                             ("chain_id", "01"), ("chain_id", 69), ("chain_id", True),
                             ("chain_id", "18446744073709551616"), ("chain_id", "-1"),
                             ("point_type", True), ("point_type", 3),
                             ("entry_id_hex", "AB" * 32), ("destination_hex", "00" * 19)]:
            changed = dict(self.context); changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(CompatibilityError):
                unlock_message(changed)
        changed = dict(self.context, contract_hex=CONTRACT_HEX)
        with self.assertRaises(CompatibilityError): unlock_message(changed)

    def test_destination_admission_is_distinct_from_message_encoding(self):
        for v in self.data["destination_vectors"]:
            self.assertEqual(payable(v["destination_hex"]), v["payable"])
            self.assertEqual(create_destination_allowed(v["point_type"], v["destination_hex"]), v["create_allowed"])
            context = dict(self.context, destination_hex=v["destination_hex"], point_type=v["point_type"])
            self.assertEqual(len(unlock_preimage(context)), 101)

    def test_send_size_union_does_not_assert_receive_validity(self):
        witnesses = json.loads((ROOT / "compatibility/fixtures/pr138_witnesses_v1.json").read_text("ascii"))
        self.assertTrue(any(v["send_size_allowed"] and not v["valid_witness"] for v in witnesses["vectors"]))
        for v in witnesses["vectors"]:
            self.assertEqual(send_witness_size_allowed(len(bytes.fromhex(v["witness_hex"]))), v["send_size_allowed"])
        self.assertFalse(send_witness_size_allowed(True))

    def test_message_fixture_is_reproducible_without_a_signer(self):
        spec = importlib.util.spec_from_file_location("pr138_generator", ROOT / "scripts/generate_pr138_messages.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertEqual(module.corpus(), self.data)

    def test_manifest_pins_fixture_bytes_and_preserves_all_legacy_module_inputs(self):
        manifest = json.loads((ROOT / "compatibility/manifest.json").read_text("ascii"))
        self.assertEqual(manifest["core_commit"], CORE_COMMIT)
        for group in ("fixture_sha256", "legacy_file_sha256", "current_module_sha256"):
            for name, expected in manifest[group].items():
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected, name)
        self.assertEqual(manifest["expected_counts"], {"message_vectors":48,"destination_vectors":15,"witness_vectors":26})
        self.assertEqual((manifest["application"],manifest["core"]), ("NO-GO","NO-GO"))
