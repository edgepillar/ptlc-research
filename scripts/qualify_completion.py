"""Two local public journals with actual artifact/completion executables.

Alice's producer returns a checked-in synthetic signature. This deliberately
does not connect a secret signer or broadcast any transaction.
"""

import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.journal import Conflict, Journal, OutcomeUnknown
from completion_test_support import final_signatures, prepare_alice, alice_packet
from exchange_test_support import prepare


class RealCompletionTests(unittest.TestCase):
    verifier = None
    completer = None

    def test_two_journals_complete_with_actual_verifiers_and_replay(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-completion-integration-") as directory:
            base = Path(directory)
            bob_root, bob_anchor = base / "bob-state", base / "bob-head.json"
            alice_root, alice_anchor = base / "alice-state", base / "alice-head.json"
            with Journal.open(bob_root, bob_anchor) as bob:
                session = prepare(bob, verifier=self.verifier)
                release = bob.release_exchange_zenon(session)
            with Journal.open(alice_root, alice_anchor) as alice:
                self.assertEqual(prepare_alice(alice, verifier=self.verifier, release_packet=release), session)
            calls = []
            with Journal.open(alice_root, alice_anchor) as alice:
                def produce():
                    calls.append(True)
                    self.assertTrue(alice.get_session(session)["possible_exposure"])
                    self.assertEqual(alice.get_alice(session)["stage"], "COMPLETION_CONSUMED")
                    # Existing public fixture, not a signer invocation.
                    return final_signatures()[0]
                packet = alice.complete_alice(session, producer=produce, verifier=self.completer)
            with Journal.open(alice_root, alice_anchor) as alice:
                self.assertEqual(alice.replay_alice_completion(session), packet)
                with self.assertRaises(OutcomeUnknown):
                    alice.complete_alice(session, producer=produce, verifier=self.completer)
            self.assertEqual(calls, [True])
            # A failed public worker must leave the exact observation recoverable.
            with Journal.open(bob_root, bob_anchor) as bob:
                def unavailable(request):
                    raise RuntimeError("synthetic public worker unavailable")
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, packet, recoverer=unavailable)
                self.assertEqual(bob.get_exchange(session)["zenon_completion_packet_hex"], packet.hex())
                self.assertTrue(bob.get_session(session)["possible_exposure"])
            with Journal.open(bob_root, bob_anchor) as bob:
                output = bob.complete_exchange_bitcoin(session, recoverer=self.completer)
                completed = json.loads(output)
                self.assertEqual(completed["signature_hex"], final_signatures()[1].hex())
                self.assertEqual(completed["context"]["purpose"], "bitcoin-claim-complete")
                self.assertEqual(bob.replay_exchange_release(session), release)
            with Journal.open(bob_root, bob_anchor) as bob:
                self.assertEqual(bob.replay_exchange_bitcoin(session), output)
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, packet, recoverer=self.completer)

    def test_actual_final_verification_failure_never_reenables_alice_producer(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-completion-reject-") as directory:
            base = Path(directory)
            calls = []
            with Journal.open(base / "state", base / "head.json") as alice:
                session = prepare_alice(alice, verifier=self.verifier)
                with self.assertRaises(OutcomeUnknown):
                    alice.complete_alice(session, producer=lambda: calls.append(True) or bytes(64), verifier=self.completer)
                self.assertTrue(alice.get_session(session)["possible_exposure"])
            with Journal.open(base / "state", base / "head.json") as alice:
                self.assertEqual(alice.get_alice(session)["stage"], "OUTCOME_UNKNOWN")
                with self.assertRaises(OutcomeUnknown):
                    alice.complete_alice(session, producer=lambda: calls.append(True) or final_signatures()[0], verifier=self.completer)
                with self.assertRaises(OutcomeUnknown):
                    alice.replay_alice_completion(session)
            self.assertEqual(calls, [True])

    def test_invalid_observation_is_retained_but_never_claimed_as_verified(self):
        from offline_session.exchange import canonical
        with tempfile.TemporaryDirectory(prefix="ptlc-observation-reject-") as directory:
            base = Path(directory)
            packet = json.loads(alice_packet())
            packet["signature_hex"] = "00" * 64
            invalid = canonical(packet)
            with Journal.open(base / "state", base / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier)
                bob.release_exchange_zenon(session)
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, invalid, recoverer=self.completer)
                self.assertTrue(bob.get_session(session)["possible_exposure"])
                self.assertEqual(bob.get_exchange(session)["zenon_completion_packet_hex"], invalid.hex())
                self.assertIsNone(bob.get_exchange(session)["completion_receipt_hex"])
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, alice_packet(), recoverer=self.completer)
                with self.assertRaises(OutcomeUnknown):
                    bob.replay_exchange_bitcoin(session)


def main():
    parser = argparse.ArgumentParser(description="Offline public completion integration; no private signer or network")
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--completion", required=True)
    args = parser.parse_args()
    RealCompletionTests.verifier = SubprocessVerifier(Path(args.verifier).resolve())
    RealCompletionTests.completer = SubprocessCompletion(Path(args.completion).resolve())
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealCompletionTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
