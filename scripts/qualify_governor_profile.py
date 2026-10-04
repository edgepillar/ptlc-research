#!/usr/bin/env python3
"""Actual public signatures and explicit local rules, never governor bootstrap."""

import argparse
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from offline_session import completion, enrollment_authentication as auth
from offline_session import governor_profile as governor
from offline_session.enrollment_verifier import SubprocessEnrollmentSignature
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import final_signatures, released_bob
from exchange_test_support import prepare
import test_enrollment_signature as support
from test_governor_profile import local_profile


class RealGovernorProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.vector = released_bob(), support.fixture()
        cls.intent = support.local_intent(cls.state)
        cls.profile = local_profile(cls.intent)
        cls.wire = support.canonical(cls.vector["envelope"])

    def test_actual_signature_and_local_rule_match_return_same_unsigned_intent(self):
        before = copy.deepcopy(self.state)
        for _ in range(3):
            self.assertIs(governor.match_governor_profile(self.profile, self.intent), self.intent)
            self.assertIs(auth.verify_signature(self.intent, self.wire, verifier=self.adapter), self.intent)
        self.assertEqual(self.state, before)
        for value in (self.intent, self.profile):
            for field in ("owner_verified", "authorized", "enrolled", "quota_granted", "can_start"):
                self.assertFalse(hasattr(value, field))

    def test_actual_valid_alternate_key_refuses_selected_role_before_work(self):
        alternate = support.local_intent(self.state, owner=self.vector["alternate_owner"]["intent"]["owner_auth_key_hex"])
        wire = support.canonical(self.vector["alternate_owner"]["envelope"])
        self.assertIs(auth.verify_signature(alternate, wire, verifier=self.adapter), alternate)
        calls = []
        def actual(request): calls.append(True); return self.adapter(request)
        with self.assertRaises(governor.GovernorProfileError):
            selected = governor.match_governor_profile(self.profile, alternate)
            auth.verify_signature(selected, wire, verifier=actual)
        self.assertEqual(calls, [])

    def test_valid_signature_cannot_override_six_scope_pins_or_two_caps(self):
        self.assertIs(auth.verify_signature(self.intent, self.wire, verifier=self.adapter), self.intent)
        changes = {key:(2 if key == "authority_epoch" else "99" * 32) for key in governor._SCOPE_PINS}
        changes.update(max_attempt_limit=1, max_target_limit=1)
        for key, value in changes.items():
            with self.subTest(field=key):
                with self.assertRaises(governor.GovernorProfileError):
                    governor.match_governor_profile(local_profile(self.intent, **{key:value}), self.intent)

    def test_choosing_a_peer_key_as_new_local_rules_does_not_establish_bootstrap(self):
        alternate = support.local_intent(self.state, owner=self.vector["alternate_owner"]["intent"]["owner_auth_key_hex"])
        peer_selected = local_profile(alternate)
        with self.assertRaises(governor.GovernorProfileError):
            governor.parse_governor_profile(self.profile, peer_selected.canonical_bytes)
        self.assertIs(governor.match_governor_profile(peer_selected, alternate), alternate)
        self.assertIs(auth.verify_signature(alternate, support.canonical(self.vector["alternate_owner"]["envelope"]), verifier=self.adapter), alternate)
        self.assertFalse(hasattr(peer_selected, "trusted"))

    def test_replay_stale_source_and_broader_rules_preserve_same_signed_message(self):
        state = copy.deepcopy(self.state); intent = support.local_intent(state)
        state["session_id"] = "99" * 32
        broader = local_profile(intent, max_attempt_limit=3, max_target_limit=3)
        self.assertNotEqual(broader.digest_hex, self.profile.digest_hex)
        for profile in (self.profile, broader, self.profile):
            self.assertIs(governor.match_governor_profile(profile, intent), intent)
            self.assertIs(auth.verify_signature(intent, self.wire, verifier=self.adapter), intent)
        self.assertEqual(intent.message_digest_hex, self.intent.message_digest_hex)

    def test_format_only_profile_match_does_not_replace_actual_curve_or_signature_checks(self):
        zero = support.local_intent(self.state, owner="00" * 32)
        self.assertIs(governor.match_governor_profile(local_profile(zero), zero), zero)
        with self.assertRaises(auth.EnrollmentSignatureError):
            auth.verify_signature(zero, auth.envelope(zero, bytes.fromhex(self.vector["request"]["signature_hex"])), verifier=self.adapter)
        with self.assertRaises(auth.EnrollmentSignatureError):
            auth.verify_signature(self.intent, auth.envelope(self.intent, bytes(64)), verifier=self.adapter)

    def test_role_and_actual_signature_checks_after_exhausted_reopen_add_no_quota(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-governor-journal-") as directory:
            root, head = Path(directory) / "state", Path(directory) / "head.json"
            with Journal.open(root, head) as journal:
                session = prepare(journal, verifier=self.verifier, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict): journal.complete_exchange_bitcoin(session, invalid, recoverer=self.completer)
            with Journal.open(root, head) as journal:
                state = journal.get_exchange(session); intent = support.local_intent(state)
                profile = local_profile(intent); before = (copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes())
                for _ in range(2):
                    self.assertIs(governor.match_governor_profile(profile, intent), intent)
                    self.assertIs(auth.verify_signature(intent, self.wire, verifier=self.adapter), intent)
                calls = []
                def recover(request): calls.append(True); return self.completer(request)
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, completion.bob_candidate_from_signature(state, final_signatures()[0]),
                        expected_observation_digest=completion.observation_digest(invalid), recoverer=recover)
                self.assertEqual((copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes()), before)
                self.assertEqual(calls, []); self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)


def main():
    parser = argparse.ArgumentParser(description="Offline local governor-profile qualification; no bootstrap, enrollment or signing")
    parser.add_argument("--enrollment", required=True)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--completion", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.enrollment).resolve()
        RealGovernorProfileTests.adapter = SubprocessEnrollmentSignature(entry,
            expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
        RealGovernorProfileTests.verifier = SubprocessVerifier(Path(args.verifier).resolve())
        RealGovernorProfileTests.completer = SubprocessCompletion(Path(args.completion).resolve())
    except (OSError, ValueError, TypeError):
        print("FAIL: selected public qualification inputs are unavailable", file=sys.stderr)
        return 1
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealGovernorProfileTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
