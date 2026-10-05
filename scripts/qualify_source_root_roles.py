#!/usr/bin/env python3
"""Actual historical root mathematics, never source provisioning or admission."""

import argparse
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from qualification import source_root_roles as root, policy_effect_store as store
from qualification.source_root_verifier import PublicRootCheck
from test_source_root_roles import fixture, selection, fake_check


class RealSourceRootRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = fixture()
        cls.primary = cls.vectors["positive_vectors"]["primary"]
        cls.expected = selection()
        cls.wire = root._canonical(cls.primary["envelope"])

    def test_actual_all_ten_public_declarations_and_replay_return_no_role_capability(self):
        for name, vector in self.vectors["positive_vectors"].items():
            selected = selection(name)
            self.assertEqual(self.check(vector["request"]), vector["result"])
            for _ in range(2):
                self.assertIs(root.verify_selected_statement(selected, root._canonical(vector["envelope"]), verifier=self.check), selected)
        for name in ("authorized", "provisioned", "current", "enrolled", "permit", "root_signature_valid"):
            self.assertFalse(hasattr(self.expected, name))

    def test_actual_valid_peer_roots_roles_profiles_and_revisions_refuse_before_work(self):
        for name, vector in self.vectors["positive_vectors"].items():
            if name == "primary": continue
            self.assertEqual(self.check(vector["request"]), vector["result"])
            calls=[]
            def checked(request): calls.append(True); return self.check(request)
            with self.assertRaises(root.RootStatementError):
                root.verify_selected_statement(self.expected, root._canonical(vector["envelope"]), verifier=checked)
            self.assertEqual(calls, [])

    def test_actual_old_root_signature_cannot_follow_any_changed_complete_declaration(self):
        for name, vector in self.vectors["positive_vectors"].items():
            if name == "primary": continue
            packet = dict(vector["envelope"], root_signature_hex=self.primary["envelope"]["root_signature_hex"])
            with self.assertRaises(root.RootStatementError):
                root.verify_selected_statement(selection(name), root._canonical(packet), verifier=self.check)

    def test_actual_wrong_domain_key_signature_scalars_and_every_signature_byte_refuse(self):
        signatures = [self.vectors["wrong_domain_root_signature_hex"], self.vectors["wrong_signing_key_signature_hex"],
            "00"*64, "ff"*64, "ff"*32+"00"*32, "00"*32+"ff"*32]
        original = bytes.fromhex(self.primary["envelope"]["root_signature_hex"])
        for index in range(64):
            changed = bytearray(original); changed[index] ^= 1; signatures.append(bytes(changed).hex())
        for signature in signatures:
            wire = root._canonical(dict(self.primary["envelope"], root_signature_hex=signature))
            with self.assertRaises(root.RootStatementError): root.verify_selected_statement(self.expected, wire, verifier=self.check)

    def test_actual_curve_checks_cover_all_five_role_keys_and_role_collision(self):
        for obj, field in (("source_context", "provisioning_root_key_hex"), ("governor_profile", "owner_auth_key_hex"),
                *[("delegated_keys", field) for field in root._KEY_FIELDS]):
            for key in ("00"*32, "ff"*32):
                value = copy.deepcopy(self.primary["declaration"]); value[obj][field] = key
                selected = selection(declaration=value)
                with self.assertRaises(root.RootStatementError):
                    root.verify_selected_statement(selected, root.envelope(selected, root_signature=bytes(64)), verifier=self.check)
        with self.assertRaises(root.RootStatementError): self.check(self.vectors["role_collision"]["request"])

    def test_actual_alternate_signature_binds_a_distinct_complete_result(self):
        wire = root._canonical(dict(self.primary["envelope"], root_signature_hex=self.vectors["alternate_root_signature_hex"]))
        request = root.request(self.expected, wire)
        self.assertIs(root.verify_selected_statement(self.expected, wire, verifier=self.check), self.expected)
        self.assertNotEqual(self.check(request)["request_digest_hex"], self.primary["result"]["request_digest_hex"])
        with self.assertRaises(root.RootStatementError): root.verify_selected_statement(self.expected, wire, verifier=lambda r: self.primary["result"])

    def test_actual_old_selection_after_new_revision_or_root_still_verifies_as_history(self):
        for name in ("new_revision", "new_incarnation", "alternate_root", "alternate_admin", "alternate_response", "new_epoch"):
            selected = selection(name)
            self.assertIs(root.verify_selected_statement(selected, root._canonical(self.vectors["positive_vectors"][name]["envelope"]), verifier=self.check), selected)
            with self.assertRaises(root.RootStatementError): root.verify_selected_statement(selected, self.wire, verifier=self.check)
            restored = copy.deepcopy(self.expected)
            self.assertIs(root.verify_selected_statement(restored, self.wire, verifier=self.check), restored)

    def test_malicious_selected_callback_can_forge_the_zero_signature_actual_math_refuses(self):
        wire = root.envelope(self.expected, root_signature=bytes(64))
        with self.assertRaises(root.RootStatementError): root.verify_selected_statement(self.expected, wire, verifier=self.check)
        self.assertIs(root.verify_selected_statement(self.expected, wire, verifier=fake_check), self.expected)

    def test_actual_valid_root_history_does_not_change_revoked_sqlite_or_refund_charge(self):
        profile = root._canonical(self.primary["declaration"]["governor_profile"])
        labels = store.SourceLabels("ab"*32, "cd"*32, self.primary["declaration"]["source_context"]["authority_id_hex"],
            self.primary["declaration"]["source_context"]["resource_digest_hex"])
        with tempfile.TemporaryDirectory(prefix="synthetic-root-policy-") as directory:
            path = Path(directory)/"policy.sqlite3"
            with store.OfflinePolicyEffectStore(str(path), labels, initial_profile=profile) as source:
                original = store.OriginalRequest("01"*32, 0, profile, "02"*32)
                source.allocate_synthetic(original)
                source.replace_local_policy(0, profile, active=False)
                before = (source.local_view(), path.read_bytes())
                for _ in range(2): self.assertIs(root.verify_selected_statement(self.expected, self.wire, verifier=self.check), self.expected)
                with self.assertRaises(store.StoreRefused): source.apply_synthetic_effect(original)
                self.assertEqual((source.local_view(), path.read_bytes()), before)
                self.assertEqual((source.local_view().charged_operations, source.local_view().synthetic_effects), (1, 0))

    def test_actual_entry_pin_and_bounded_canonical_wire_refuse_without_private_output(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-root-entry-") as directory:
            entry = Path(directory)/"worker"; entry.write_bytes(self.entry.read_bytes()); entry.chmod(0o700)
            checked = PublicRootCheck(entry, expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
            with entry.open("ab") as stream: stream.write(b"\0")
            with patch("qualification.source_root_verifier.run_public_worker") as run:
                with self.assertRaises(root.RootStatementError): checked(self.primary["request"])
                run.assert_not_called()
        wire = root._canonical(self.primary["request"])
        for invalid in (b"", b"\xff", b"["*512+b"]"*512, b" "*8193, wire+b"\n\n",
                wire.replace(b'"declaration":', b'"\\u0064eclaration":'),
                wire.replace(b'"declaration_revision":1', b'"declaration_revision":1,"declaration_revision":1'),
                wire.replace(b'"declaration_revision":1', b'"declaration_revision":1e0')):
            result = subprocess.run([str(self.entry)], input=invalid, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b"", b""))


def main():
    parser = argparse.ArgumentParser(description="Offline selected root history qualification; no source service or admission")
    parser.add_argument("--root-verifier", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.root_verifier).resolve()
        RealSourceRootRoleTests.entry = entry
        RealSourceRootRoleTests.check = PublicRootCheck(entry, expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
    except (OSError, ValueError, TypeError):
        parser.exit(1, "selected public root check unavailable\n")
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealSourceRootRoleTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
