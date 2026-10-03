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

from offline_session import authentication as auth
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
        cls.wire = canonical(cls.fixture["envelope"])

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
