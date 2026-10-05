#!/usr/bin/env python3
"""Actual issuer/owner signature facts, never current authority or admission."""

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

from offline_session import completion, governor_authentication as auth
from offline_session.enrollment_authentication import _canonical as canonical
from offline_session.governor_verifier import SubprocessGovernorSignature
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import final_signatures, released_bob
from exchange_test_support import prepare
import test_governor_signature as support
import test_enrollment_signature as legacy


class RealGovernorSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.vectors = released_bob(), support.fixture()
        cls.bound = support.selected_bound(cls.state)
        cls.primary = cls.vectors["primary"]
        cls.wire = canonical(cls.primary["envelope"])

    def test_actual_two_signatures_and_replay_return_same_unsigned_intent(self):
        for name in ("primary", "alternate_issuer", "alternate_owner", "broader_caps", "new_epoch", "same_key_roles"):
            selected = support.selected_bound(self.state, name)
            for _ in range(2):
                self.assertIs(auth.verify_signatures(selected, canonical(self.vectors[name]["envelope"]), verifier=self.adapter), selected)
            self.assertEqual(self.adapter(self.vectors[name]["request"]), self.vectors[name]["result"])
        for name in ("authorized", "issuer_verified", "owner_verified", "enrolled", "quota_granted", "permit"):
            self.assertFalse(hasattr(self.bound, name))

    def test_valid_peer_issuer_owner_caps_or_epoch_refuse_before_actual_work(self):
        for name in ("alternate_issuer", "alternate_owner", "broader_caps", "new_epoch", "same_key_roles"):
            self.assertEqual(self.adapter(self.vectors[name]["request"]), self.vectors[name]["result"])
            calls = []
            def checked(request): calls.append(True); return self.adapter(request)
            with self.subTest(name=name), self.assertRaises(auth.GovernorSignatureError):
                auth.verify_signatures(self.bound, canonical(self.vectors[name]["envelope"]), verifier=checked)
            self.assertEqual(calls, [])

    def test_actual_old_signatures_cannot_follow_changed_complete_assignment(self):
        for name in ("alternate_issuer", "alternate_owner", "broader_caps", "new_epoch"):
            selected = support.selected_bound(self.state, name)
            for field in ("issuer_signature_hex", "owner_signature_hex"):
                packet = copy.deepcopy(self.vectors[name]["envelope"])
                packet[field] = self.primary["envelope"][field]
                with self.subTest(name=name, field=field), self.assertRaises(auth.GovernorSignatureError):
                    auth.verify_signatures(selected, canonical(packet), verifier=self.adapter)
        self.assertEqual(self.bound._intent.message_digest_hex,
            support.selected_bound(self.state, "broader_caps")._intent.message_digest_hex)

    def test_actual_wrong_role_domain_and_v1_signatures_refuse(self):
        for field, signature in (("issuer_signature_hex", self.vectors["wrong_domain_issuer_signature_hex"]),
            ("owner_signature_hex", self.vectors["wrong_domain_owner_signature_hex"]),
            ("issuer_signature_hex", self.primary["request"]["owner_signature_hex"]),
            ("owner_signature_hex", self.primary["request"]["issuer_signature_hex"]),
            ("owner_signature_hex", legacy.fixture()["request"]["signature_hex"])):
            packet = dict(self.primary["envelope"], **{field: signature})
            with self.assertRaises(auth.GovernorSignatureError):
                auth.verify_signatures(self.bound, canonical(packet), verifier=self.adapter)

    def test_actual_consistently_bound_noncurve_issuer_or_owner_keys_refuse(self):
        for key in ("00" * 32, "ff" * 32):
            for field in ("issuer", "owner"):
                selected = support.selected_bound(self.state, **{field: key})
                wire = auth.envelope(selected, issuer_signature=bytes(64), owner_signature=bytes(64))
                with self.assertRaises(auth.GovernorSignatureError):
                    auth.verify_signatures(selected, wire, verifier=self.adapter)

    def test_actual_both_signature_scalar_limits_and_each_byte_mutation_refuse(self):
        for field in ("issuer_signature_hex", "owner_signature_hex"):
            signature = bytes.fromhex(self.primary["request"][field])
            variants = [bytes(64), b"\xff" * 32 + bytes(32), bytes(32) + b"\xff" * 32]
            for index in range(64):
                changed = bytearray(signature); changed[index] ^= 1; variants.append(bytes(changed))
            for changed in variants:
                packet = dict(self.primary["envelope"], **{field: changed.hex()})
                with self.assertRaises(auth.GovernorSignatureError):
                    auth.verify_signatures(self.bound, canonical(packet), verifier=self.adapter)

    def test_actual_either_alternate_signature_has_a_distinct_bound_result(self):
        for field in ("issuer", "owner"):
            packet = dict(self.primary["envelope"], **{field + "_signature_hex": self.vectors["alternate_" + field + "_signature_hex"]})
            wire = canonical(packet); request = auth.request(self.bound, wire)
            self.assertIs(auth.verify_signatures(self.bound, wire, verifier=self.adapter), self.bound)
            self.assertNotEqual(self.adapter(request)["request_digest_hex"], self.primary["result"]["request_digest_hex"])
            with self.assertRaises(auth.GovernorSignatureError):
                auth.verify_signatures(self.bound, wire, verifier=lambda request: self.primary["result"])

    def test_actual_math_cannot_decode_scope_hash_or_override_local_caps(self):
        vector = self.vectors["opaque_scope_under_caps"]
        self.assertEqual(self.adapter(vector["request"]), vector["result"])
        calls = []
        def checked(request): calls.append(True); return self.adapter(request)
        with self.assertRaises(auth.GovernorSignatureError):
            auth.verify_signatures(self.bound, canonical(vector["envelope"]), verifier=checked)
        self.assertEqual(calls, [])
        with self.assertRaises(ValueError):
            support.selected_bound(self.state, profile_overrides=dict(max_attempt_limit=1, max_target_limit=1))

    def test_actual_old_expectation_still_verifies_after_epoch_or_source_copy_change(self):
        newer = support.selected_bound(self.state, "new_epoch")
        with self.assertRaises(auth.GovernorSignatureError): auth.verify_signatures(newer, self.wire, verifier=self.adapter)
        self.assertIs(auth.verify_signatures(self.bound, self.wire, verifier=self.adapter), self.bound)
        mutable = copy.deepcopy(self.state); selected = support.selected_bound(mutable)
        mutable["release_hex"] = "00"
        self.assertIs(auth.verify_signatures(selected, self.wire, verifier=self.adapter), selected)
        with self.assertRaises(ValueError): support.selected_bound(mutable)

    def test_malicious_selected_verifier_can_forge_what_actual_math_refuses(self):
        wire = auth.envelope(self.bound, issuer_signature=bytes(64), owner_signature=bytes(64))
        with self.assertRaises(auth.GovernorSignatureError): auth.verify_signatures(self.bound, wire, verifier=self.adapter)
        self.assertIs(auth.verify_signatures(self.bound, wire, verifier=support.fake_check), self.bound)

    def test_actual_signatures_after_exhausted_reopen_add_no_allowance_or_recovery(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-actual-governor-") as directory:
            root, head = Path(directory) / "state", Path(directory) / "head.json"
            with Journal.open(root, head) as journal:
                session = prepare(journal, verifier=self.verifier, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict): journal.complete_exchange_bitcoin(session, invalid, recoverer=self.completer)
            with Journal.open(root, head) as journal:
                state = journal.get_exchange(session); selected = support.selected_bound(state)
                self.assertEqual(selected, self.bound)
                before = (copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes())
                for _ in range(2): self.assertIs(auth.verify_signatures(selected, self.wire, verifier=self.adapter), selected)
                with self.assertRaises(auth.GovernorSignatureError):
                    auth.verify_signatures(selected, auth.envelope(selected, issuer_signature=bytes(64), owner_signature=bytes(64)), verifier=self.adapter)
                calls = []
                def recover(request): calls.append(True); return self.completer(request)
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, completion.bob_candidate_from_signature(state, final_signatures()[0]),
                        expected_observation_digest=completion.observation_digest(invalid), recoverer=recover)
                self.assertEqual((copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes()), before)
                self.assertEqual(calls, [])
                self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)

    def test_actual_entry_pin_and_bounded_sanitized_worker_wire_refusals(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-governor-entry-") as directory:
            copied = Path(directory) / "worker"
            copied.write_bytes(self.entry.read_bytes()); copied.chmod(0o700)
            adapter = SubprocessGovernorSignature(copied, expected_executable_sha256_hex=hashlib.sha256(copied.read_bytes()).hexdigest())
            with copied.open("ab") as source: source.write(b"\0")
            with patch("offline_session.governor_verifier.run_public_worker") as run:
                with self.assertRaises(auth.GovernorSignatureError): adapter(self.primary["request"])
                run.assert_not_called()
        wire = canonical(self.primary["request"])
        for invalid in (b"", b"\xff", b"[" * 512 + b"]" * 512, b" " * (8192 + 1), wire + b"\n\n",
            wire.replace(b'"assignment":', b'"\\u0061ssignment":'),
            wire.replace(b'"authority_epoch":1', b'"authority_epoch":1,"authority_epoch":1'),
            wire.replace(b'"authority_epoch":1', b'"authority_epoch":1e0')):
            result = subprocess.run([str(self.entry)], input=invalid, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b"", b""))


def main():
    parser = argparse.ArgumentParser(description="Offline public issuer/owner signature qualification; no provisioning or admission")
    parser.add_argument("--governor", required=True)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--completion", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.governor).resolve()
        RealGovernorSignatureTests.entry = entry
        RealGovernorSignatureTests.adapter = SubprocessGovernorSignature(entry, expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
        RealGovernorSignatureTests.verifier = SubprocessVerifier(Path(args.verifier).resolve())
        RealGovernorSignatureTests.completer = SubprocessCompletion(Path(args.completion).resolve())
    except (OSError, ValueError, TypeError):
        print("FAIL: selected public qualification inputs are unavailable", file=sys.stderr)
        return 1
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealGovernorSignatureTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
