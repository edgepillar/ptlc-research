#!/usr/bin/env python3
"""Actual public signature checks, separate from role, source trust and quota."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from offline_session import completion, enrollment_contract as contract
from offline_session import enrollment_authentication as auth
from offline_session.enrollment_verifier import SubprocessEnrollmentSignature
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import final_signatures, released_bob
from exchange_test_support import prepare
import test_enrollment_signature as support


class RealEnrollmentSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector, cls.state = support.fixture(), released_bob()
        cls.intent = support.local_intent(cls.state)
        cls.wire = support.canonical(cls.vector["envelope"])

    def test_actual_public_signature_and_replay_match_exact_local_intent(self):
        for _ in range(3):
            self.assertIs(auth.verify_signature(self.intent, self.wire, verifier=self.adapter), self.intent)
        self.assertEqual(self.adapter(self.vector["request"]), self.vector["result"])
        for name in ("authorized", "owner_verified", "enrolled", "quota_granted", "permit"):
            self.assertFalse(hasattr(self.intent, name))

    def test_actual_noncurve_keys_and_corrupted_signatures_refuse(self):
        zero_key = support.local_intent(self.state, owner="00" * 32)
        with self.assertRaises(auth.EnrollmentSignatureError):
            auth.verify_signature(zero_key, auth.envelope(zero_key, bytes(64)), verifier=self.adapter)
        signature = bytearray.fromhex(self.vector["request"]["signature_hex"]); signature[-1] ^= 1
        for changed in (bytes(64), bytes(signature)):
            with self.assertRaises(auth.EnrollmentSignatureError):
                auth.verify_signature(self.intent, auth.envelope(self.intent, changed), verifier=self.adapter)

    def test_actual_old_signature_cannot_authenticate_any_new_scope_selection(self):
        signature = bytes.fromhex(self.vector["request"]["signature_hex"])
        for field, old in support.selection().items():
            selected = dict(support.selection(), **{field: old + 1 if type(old) is int else "99" * 32})
            expected = support.local_intent(self.state, selected=selected)
            self.assertEqual(expected._resource, self.intent._resource)
            with self.subTest(field=field), self.assertRaises(auth.EnrollmentSignatureError):
                auth.verify_signature(expected, auth.envelope(expected, signature), verifier=self.adapter)

    def test_valid_alternate_owner_cannot_replace_the_local_pin_before_work(self):
        other = self.vector["alternate_owner"]
        self.assertEqual(self.adapter(other["request"]), other["result"])
        calls = []
        def checked(request): calls.append(True); return self.adapter(request)
        with self.assertRaises(auth.EnrollmentSignatureError):
            auth.verify_signature(self.intent, support.canonical(other["envelope"]), verifier=checked)
        self.assertEqual(calls, [])

    def test_valid_self_selected_source_is_not_local_source_evidence(self):
        other = self.vector["self_selected_source"]
        self.assertEqual(self.adapter(other["request"]), other["result"])
        calls = []
        def checked(request): calls.append(True); return self.adapter(request)
        with self.assertRaises(auth.EnrollmentSignatureError):
            auth.verify_signature(self.intent, support.canonical(other["envelope"]), verifier=checked)
        self.assertEqual(calls, [])

    def test_actual_signature_for_another_message_domain_refuses(self):
        signature = bytes.fromhex(self.vector["wrong_domain_signature_hex"])
        with self.assertRaises(auth.EnrollmentSignatureError):
            auth.verify_signature(self.intent, auth.envelope(self.intent, signature), verifier=self.adapter)

    def test_actual_alternate_signature_has_another_request_result_binding(self):
        wire = auth.envelope(self.intent, bytes.fromhex(self.vector["alternate_signature_hex"]))
        request = auth.request(self.intent, wire)
        self.assertIs(auth.verify_signature(self.intent, wire, verifier=self.adapter), self.intent)
        self.assertNotEqual(self.adapter(request)["request_digest_hex"], self.vector["result"]["request_digest_hex"])
        self.assertEqual(request["intent"], self.vector["intent"])

    def test_actual_old_expectation_verifies_after_live_copy_changes_without_freshness(self):
        mutable = copy.deepcopy(self.state); expected = support.local_intent(mutable)
        mutable["release_hex"] = "00"
        self.assertIs(auth.verify_signature(expected, self.wire, verifier=self.adapter), expected)
        with self.assertRaises(contract.EnrollmentContractError):
            contract.enrollment_intent(mutable, expected._scope, expected._resource,
                owner_auth_key_hex=self.vector["intent"]["owner_auth_key_hex"], request_id_hex="88" * 32)

    def test_actual_signature_checks_after_exhausted_reopen_preserve_source_journal(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-actual-enrollment-") as directory:
            root, head = Path(directory) / "state", Path(directory) / "head.json"
            with Journal.open(root, head) as journal:
                session = prepare(journal, verifier=self.verifier, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict): journal.complete_exchange_bitcoin(session, invalid, recoverer=self.completer)
            with Journal.open(root, head) as journal:
                state = journal.get_exchange(session); expected = support.local_intent(state)
                self.assertEqual(expected, self.intent)
                before = (copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes())
                for _ in range(2): self.assertIs(auth.verify_signature(expected, self.wire, verifier=self.adapter), expected)
                with self.assertRaises(auth.EnrollmentSignatureError):
                    auth.verify_signature(expected, auth.envelope(expected, bytes(64)), verifier=self.adapter)
                calls = []
                def recover(request): calls.append(True); return self.completer(request)
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, completion.bob_candidate_from_signature(state, final_signatures()[0]),
                        expected_observation_digest=completion.observation_digest(invalid), recoverer=recover)
                self.assertEqual((copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes()), before)
                self.assertEqual(calls, []); self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)
                self.assertEqual(journal.get_exchange(session)["zenon_completion_packet_hex"], invalid.hex())

    def test_changed_actual_entry_is_refused_before_work(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-actual-entry-") as directory:
            copied = Path(directory) / "worker"
            copied.write_bytes(self.entry.read_bytes()); copied.chmod(0o700)
            digest = hashlib.sha256(copied.read_bytes()).hexdigest()
            adapter = SubprocessEnrollmentSignature(copied, expected_executable_sha256_hex=digest)
            with copied.open("ab") as source: source.write(b"\0")
            with patch("offline_session.enrollment_verifier.run_public_worker") as run:
                with self.assertRaises(auth.EnrollmentSignatureError): adapter(self.vector["request"])
                run.assert_not_called()


def main():
    parser = argparse.ArgumentParser(description="Offline public enrollment signature qualification; no enrollment or signing")
    parser.add_argument("--enrollment", required=True)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--completion", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.enrollment).resolve()
        digest = hashlib.sha256(entry.read_bytes()).hexdigest()
        RealEnrollmentSignatureTests.entry = entry
        RealEnrollmentSignatureTests.adapter = SubprocessEnrollmentSignature(entry, expected_executable_sha256_hex=digest)
        RealEnrollmentSignatureTests.verifier = SubprocessVerifier(Path(args.verifier).resolve())
        RealEnrollmentSignatureTests.completer = SubprocessCompletion(Path(args.completion).resolve())
    except (OSError, ValueError, TypeError):
        print("FAIL: selected public qualification inputs are unavailable", file=sys.stderr)
        return 1
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealEnrollmentSignatureTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
