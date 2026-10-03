"""Offline envelope checks with actual public executables and synthetic pins.

The composition below is test-only. Existing journal APIs do not require it.
No signing, pin enrollment, peer transport, or chain access is performed.
"""

import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from offline_session import authentication as auth, completion
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.authentication_verifier import SubprocessAuthentication
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.exchange import canonical
from offline_session.journal import Conflict, Journal
from completion_test_support import alice_packet, final_signatures
from exchange_test_support import artifacts, prepare


class RealAuthenticationTests(unittest.TestCase):
    authenticator = None
    verifier = None
    completer = None

    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / "qualification/fixtures/authentication.json").read_text("ascii"))
        fields = cls.fixture["request"]["context"]
        cls.context = auth.context(artifacts()[0], alice_auth_key_hex=fields["alice_auth_key_hex"],
                                   bob_auth_key_hex=fields["bob_auth_key_hex"])
        cls.pins = {name: fields[name] for name in ("alice_auth_key_hex", "bob_auth_key_hex")}
        cls.wire = canonical(cls.fixture["envelope"])

    def storage(self, root):
        return (root / "state/journal.sqlite3").read_bytes(), (root / "head.json").read_bytes()

    def test_actual_authentication_returns_exact_existing_completion_and_allows_replay(self):
        self.assertEqual(self.context.as_dict(), self.fixture["request"]["context"])
        for _ in range(2):
            self.assertEqual(auth.authenticate(self.context, self.wire, verifier=self.authenticator), alice_packet())
        self.assertEqual(auth.message_digest(self.context, alice_packet()), self.fixture["message_digest_hex"])

    def test_changed_payload_and_signature_rejected_by_actual_worker(self):
        for field in ("payload_hex", "signature_hex"):
            changed = json.loads(self.wire)
            value = bytearray.fromhex(changed[field])
            value[-1] ^= 1
            changed[field] = value.hex()
            with self.assertRaises(auth.AuthenticationError):
                auth.authenticate(self.context, canonical(changed), verifier=self.authenticator)

    def test_remote_context_cannot_replace_local_pins_or_terms_before_worker(self):
        for field in ("session_id", "terms_digest_hex", "alice_auth_key_hex", "bob_auth_key_hex"):
            changed = json.loads(self.wire)
            changed["context"][field] = "ff" * 32
            calls = []
            def verify(request):
                calls.append(True)
                return self.authenticator(request)
            with self.assertRaises(auth.AuthenticationError):
                auth.authenticate(self.context, canonical(changed), verifier=verify)
            self.assertEqual(calls, [])

    def test_authentication_failure_prevents_test_composition_from_spending_allowance(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-auth-admission-") as directory:
            root = Path(directory)
            with Journal.open(root / "state", root / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier)
                bob.release_exchange_zenon(session)
                before = bob.get_session(session)
                db = root / "state/journal.sqlite3"
                saved = db.read_bytes(), (root / "head.json").read_bytes()
                changed = json.loads(self.wire)
                changed["signature_hex"] = "00" * 64
                with self.assertRaises(auth.AuthenticationError):
                    payload = auth.authenticate(self.context, canonical(changed), verifier=self.authenticator)
                    bob.complete_exchange_bitcoin(session, payload, recoverer=self.completer)
                self.assertEqual(bob.get_session(session), before)
                self.assertEqual((db.read_bytes(), (root / "head.json").read_bytes()), saved)
                payload = auth.authenticate(self.context, self.wire, verifier=self.authenticator)
                output = bob.complete_exchange_bitcoin(session, payload, recoverer=self.completer)
                self.assertEqual(json.loads(output)["signature_hex"], final_signatures()[1].hex())
                self.assertEqual(bob.get_session(session)["recovery_budget"]["consumed"], 1)
            with Journal.open(root / "state", root / "head.json") as bob:
                self.assertEqual(bob.replay_exchange_bitcoin(session), output)

    def test_authenticated_invalid_completion_still_fails_actual_recovery(self):
        vector = self.fixture["authenticated_invalid_completion"]
        payload = auth.authenticate(self.context, canonical(vector["envelope"]), verifier=self.authenticator)
        self.assertEqual(json.loads(payload)["signature_hex"], "00" * 64)
        with tempfile.TemporaryDirectory(prefix="ptlc-auth-invalid-completion-") as directory:
            root = Path(directory)
            with Journal.open(root / "state", root / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier)
                bob.release_exchange_zenon(session)
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, payload, recoverer=self.completer)
                self.assertEqual(bob.get_session(session)["recovery_budget"]["consumed"], 1)
                self.assertEqual(bob.get_exchange(session)["zenon_completion_packet_hex"], payload.hex())

    def test_existing_journal_remains_callable_without_any_authentication(self):
        # An explicit limitation: this stage does not enforce authenticated admission.
        with tempfile.TemporaryDirectory(prefix="ptlc-auth-bypass-boundary-") as directory:
            root = Path(directory)
            with Journal.open(root / "state", root / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier)
                bob.release_exchange_zenon(session)
                output = bob.complete_exchange_bitcoin(session, alice_packet(), recoverer=self.completer)
                self.assertEqual(json.loads(output)["signature_hex"], final_signatures()[1].hex())

    def test_persisted_pins_authenticate_after_reopen_without_mutating_storage(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-durable-authentication-") as directory:
            root = Path(directory)
            with Journal.open(root / "state", root / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier, authentication_pins=self.pins)
                bob.release_exchange_zenon(session)
            before = self.storage(root)
            with Journal.open(root / "state", root / "head.json") as bob:
                state = bob.get_session(session)
                self.assertEqual(state["authentication_pins"], self.pins)
                for _ in range(2):
                    self.assertEqual(bob.authenticate_exchange_envelope(
                        session, self.wire, verifier=self.authenticator), alice_packet())
                    self.assertEqual(bob.get_session(session), state)
                    self.assertEqual(self.storage(root), before)
                self.assertEqual(state["recovery_budget"]["consumed"], 0)
                self.assertFalse(state["possible_exposure"])
            self.assertEqual(self.storage(root), before)

    def test_stored_pins_reject_remote_substitution_and_actual_bad_signature(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-durable-auth-rejection-") as directory:
            root = Path(directory)
            with Journal.open(root / "state", root / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier, authentication_pins=self.pins)
            before = self.storage(root)
            with Journal.open(root / "state", root / "head.json") as bob:
                state = bob.get_session(session)
                changed = json.loads(self.wire)
                changed["context"]["bob_auth_key_hex"] = "ff" * 32
                calls = []
                def verify(request):
                    calls.append(True)
                    return self.authenticator(request)
                with self.assertRaises(Conflict):
                    bob.authenticate_exchange_envelope(session, canonical(changed), verifier=verify)
                self.assertEqual(calls, [])
                changed = json.loads(self.wire)
                changed["signature_hex"] = "00" * 64
                with self.assertRaises(Conflict):
                    bob.authenticate_exchange_envelope(session, canonical(changed), verifier=verify)
                self.assertEqual(calls, [True])
                self.assertEqual(bob.get_session(session), state)
                self.assertEqual(self.storage(root), before)

    def test_stored_pin_authentication_is_not_completion_or_exposure_tracking(self):
        vector = self.fixture["authenticated_invalid_completion"]
        with tempfile.TemporaryDirectory(prefix="ptlc-durable-auth-invalid-inner-") as directory:
            root = Path(directory)
            with Journal.open(root / "state", root / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier, authentication_pins=self.pins)
                bob.release_exchange_zenon(session)
                before = self.storage(root)
                payload = bob.authenticate_exchange_envelope(
                    session, canonical(vector["envelope"]), verifier=self.authenticator)
                self.assertEqual(self.storage(root), before)
                self.assertFalse(bob.get_session(session)["possible_exposure"])
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, payload, recoverer=self.completer)
                state = bob.get_session(session)
                self.assertTrue(state["possible_exposure"])
                self.assertEqual(state["recovery_budget"]["consumed"], 1)
                changed = json.loads(self.wire)
                changed["signature_hex"] = "00" * 64
                before = self.storage(root)
                with self.assertRaises(Conflict):
                    bob.authenticate_exchange_envelope(session, canonical(changed), verifier=self.authenticator)
                # Rejected outer authentication cannot clear possible witness exposure.
                self.assertEqual(bob.get_session(session), state)
                self.assertEqual(self.storage(root), before)

    def test_configured_session_preserves_raw_recovery_without_auxiliary_envelope(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-durable-pins-raw-recovery-") as directory:
            root = Path(directory)
            with Journal.open(root / "state", root / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier, authentication_pins=self.pins)
                bob.release_exchange_zenon(session)
            with Journal.open(root / "state", root / "head.json") as bob:
                # The raw API remains public-input qualification, not trusted chain observation.
                output = bob.complete_exchange_bitcoin(session, alice_packet(), recoverer=self.completer)
                self.assertEqual(json.loads(output)["signature_hex"], final_signatures()[1].hex())
                self.assertEqual(bob.get_session(session)["authentication_pins"], self.pins)
            with Journal.open(root / "state", root / "head.json") as bob:
                before = self.storage(root)
                self.assertEqual(bob.replay_exchange_bitcoin(session), output)
                self.assertEqual(bob.authenticate_exchange_envelope(
                    session, self.wire, verifier=self.authenticator), alice_packet())
                self.assertEqual(self.storage(root), before)

    def test_pins_survive_raw_reconciliation_and_authentication_remains_separate(self):
        invalid = bytes.fromhex(self.fixture["authenticated_invalid_completion"]["request"]["payload_hex"])
        with tempfile.TemporaryDirectory(prefix="ptlc-durable-pins-reconciliation-") as directory:
            root = Path(directory)
            with Journal.open(root / "state", root / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier, authentication_pins=self.pins)
                bob.release_exchange_zenon(session)
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, invalid, recoverer=self.completer)
            with Journal.open(root / "state", root / "head.json") as bob:
                before = self.storage(root)
                payload = bob.authenticate_exchange_envelope(session, self.wire, verifier=self.authenticator)
                self.assertEqual(self.storage(root), before)
                output = bob.reconcile_exchange_bitcoin(
                    session, payload, expected_observation_digest=completion.observation_digest(invalid),
                    recoverer=self.completer)
                self.assertEqual(json.loads(output)["signature_hex"], final_signatures()[1].hex())
                self.assertEqual(bob.get_session(session)["authentication_pins"], self.pins)
                self.assertEqual(bob.get_session(session)["recovery_budget"]["consumed"], 2)
                self.assertEqual(bob.get_exchange(session)["superseded_zenon_completion_packet_hex"], invalid.hex())


def main():
    parser = argparse.ArgumentParser(description="Offline public authentication qualification; no signer or network")
    parser.add_argument("--authentication", required=True)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--completion", required=True)
    args = parser.parse_args()
    RealAuthenticationTests.authenticator = SubprocessAuthentication(Path(args.authentication).resolve())
    RealAuthenticationTests.verifier = SubprocessVerifier(Path(args.verifier).resolve())
    RealAuthenticationTests.completer = SubprocessCompletion(Path(args.completion).resolve())
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealAuthenticationTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
