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
from offline_session import completion, exchange
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.journal import Conflict, Journal, OutcomeUnknown, RecoveryExhausted
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
                self.assertEqual(bob.get_session(session)["recovery_budget"]["consumed"], 1)
                self.assertEqual(bob.get_exchange(session)["zenon_completion_packet_hex"], packet.hex())
                self.assertTrue(bob.get_session(session)["possible_exposure"])
            with Journal.open(bob_root, bob_anchor) as bob:
                output = bob.complete_exchange_bitcoin(session, recoverer=self.completer)
                self.assertEqual(bob.get_session(session)["recovery_budget"]["consumed"], 2)
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

    def test_positive_reconciliation_retains_original_and_seals_verified_output(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-reconciliation-integration-") as directory:
            base = Path(directory)
            packet = alice_packet()
            invalid = json.loads(packet)
            invalid["signature_hex"] = "00" * 64
            previous = exchange.canonical(invalid)
            expected = completion.observation_digest(previous)
            with Journal.open(base / "state", base / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier)
                release = bob.release_exchange_zenon(session)
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, previous, recoverer=self.completer)
            with Journal.open(base / "state", base / "head.json") as bob:
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, packet, recoverer=self.completer)
                output = bob.reconcile_exchange_bitcoin(
                    session, packet, expected_observation_digest=expected, recoverer=self.completer,
                )
                self.assertEqual(json.loads(output)["signature_hex"], final_signatures()[1].hex())
                state = bob.get_exchange(session)
                self.assertEqual(state["superseded_zenon_completion_packet_hex"], previous.hex())
                self.assertEqual(state["zenon_completion_packet_hex"], packet.hex())
                self.assertTrue(bob.get_session(session)["possible_exposure"])
            with Journal.open(base / "state", base / "head.json") as bob:
                self.assertEqual(bob.replay_exchange_bitcoin(session), output)
                self.assertEqual(bob.replay_exchange_release(session), release)
                with self.assertRaises(Conflict):
                    bob.reconcile_exchange_bitcoin(
                        session, packet, expected_observation_digest=expected, recoverer=self.completer,
                    )

    def test_failed_real_reconciliation_consumes_only_the_admission_allowance(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-reconciliation-reject-") as directory:
            base = Path(directory)
            value = json.loads(alice_packet())
            value["signature_hex"] = "00" * 64
            previous = exchange.canonical(value)
            value["signature_hex"] = "ff" * 64
            replacement = exchange.canonical(value)
            with Journal.open(base / "state", base / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier)
                bob.release_exchange_zenon(session)
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, previous, recoverer=self.completer)
                state = bob.get_session(session)
                db = base / "state" / "journal.sqlite3"
                saved = db.read_bytes(), (base / "head.json").read_bytes()
                with self.assertRaises(Conflict):
                    bob.reconcile_exchange_bitcoin(
                        session, replacement, expected_observation_digest=completion.observation_digest(previous),
                        recoverer=self.completer,
                    )
                state["recovery_budget"]["consumed"] += 1
                self.assertEqual(bob.get_session(session), state)
                self.assertNotEqual((db.read_bytes(), (base / "head.json").read_bytes()), saved)
                self.assertIsNone(bob.get_exchange(session)["superseded_zenon_completion_packet_hex"])
                with self.assertRaises(OutcomeUnknown):
                    bob.replay_exchange_bitcoin(session)

    def test_actual_rejection_exhausts_shared_recovery_allowance_across_reopen(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-recovery-admission-") as directory:
            base = Path(directory)
            value = json.loads(alice_packet())
            value["signature_hex"] = "00" * 64
            previous = exchange.canonical(value)
            with Journal.open(base / "state", base / "head.json") as bob:
                session = prepare(bob, verifier=self.verifier, recovery_limit=2)
                release = bob.release_exchange_zenon(session)
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, previous, recoverer=self.completer)
                self.assertEqual(bob.get_session(session)["recovery_budget"], {"limit": 2, "consumed": 1})
                value["signature_hex"] = "ff" * 64
                with self.assertRaises(Conflict):
                    bob.reconcile_exchange_bitcoin(
                        session, exchange.canonical(value),
                        expected_observation_digest=completion.observation_digest(previous),
                        recoverer=self.completer,
                    )
                retained = bob.get_exchange(session)
            with Journal.open(base / "state", base / "head.json") as bob:
                self.assertEqual(bob.get_session(session)["recovery_budget"], {"limit": 2, "consumed": 2})
                calls = []
                def unexpected(request):
                    calls.append(True)
                    return self.completer(request)
                with self.assertRaises(RecoveryExhausted):
                    bob.complete_exchange_bitcoin(session, recoverer=unexpected)
                with self.assertRaises(RecoveryExhausted):
                    bob.reconcile_exchange_bitcoin(
                        session, alice_packet(), expected_observation_digest=completion.observation_digest(previous),
                        recoverer=unexpected,
                    )
                self.assertEqual(calls, [])
                self.assertEqual(bob.get_exchange(session), retained)
                self.assertEqual(bob.replay_exchange_release(session), release)

    def test_reopened_bob_imports_raw_public_signature_without_an_envelope_or_construction_write(self):
        vector = json.loads((Path(__file__).resolve().parents[1]
                             / "qualification/fixtures/authentication.json").read_text("ascii"))
        pins = {key: vector["envelope"]["context"][key]
                for key in ("alice_auth_key_hex", "bob_auth_key_hex")}
        with tempfile.TemporaryDirectory(prefix="ptlc-raw-public-completion-") as directory:
            base = Path(directory)
            root, anchor = base / "state", base / "head.json"
            with Journal.open(root, anchor) as bob:
                session = prepare(bob, verifier=self.verifier, recovery_limit=1, authentication_pins=pins)
                bob.release_exchange_zenon(session)
            with Journal.open(root, anchor) as bob:
                before = bob.get_session(session), bob._sequence, (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()
                state = bob.get_exchange(session)
                candidate = completion.bob_candidate_from_signature(state, final_signatures()[0])
                self.assertEqual(candidate, bytes.fromhex(vector["envelope"]["payload_hex"]))
                self.assertEqual((bob.get_session(session), bob._sequence,
                                  (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()), before)
                self.assertEqual(bob.get_session(session)["authentication_pins"], pins)
                self.assertFalse(bob.get_session(session)["possible_exposure"])
                self.assertEqual(bob.get_session(session)["recovery_budget"]["consumed"], 0)
                output = bob.complete_exchange_bitcoin(session, candidate, recoverer=self.completer)
                bitcoin_context = dict(state["bitcoin_context"], role="bob", purpose="bitcoin-claim-complete")
                expected = exchange.canonical({"schema": "ptlc-bob-bitcoin-completion-v1",
                                               "context": bitcoin_context,
                                               "signature_hex": final_signatures()[1].hex()})
                self.assertEqual(output, expected)
                self.assertEqual(bob.get_session(session)["recovery_budget"]["consumed"], 1)
            with Journal.open(root, anchor) as bob:
                self.assertEqual(bob.replay_exchange_bitcoin(session), output)

    def test_imported_invalid_and_foreign_leg_signatures_require_real_math_and_consume_allowance(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-imported-signature-rejection-") as directory:
            base = Path(directory)
            root, anchor = base / "state", base / "head.json"
            with Journal.open(root, anchor) as bob:
                session = prepare(bob, verifier=self.verifier, recovery_limit=2)
                bob.release_exchange_zenon(session)
                previous = completion.bob_candidate_from_signature(bob.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, previous, recoverer=self.completer)
                # This fixture signature is valid for Bitcoin's different key and
                # message. A session label alone is not a chain-signature domain.
                wrong_leg = completion.bob_candidate_from_signature(bob.get_exchange(session), final_signatures()[1])
                self.assertNotEqual(wrong_leg, previous)
                with self.assertRaises(Conflict):
                    bob.reconcile_exchange_bitcoin(session, wrong_leg,
                        expected_observation_digest=completion.observation_digest(previous), recoverer=self.completer)
                state = bob.get_exchange(session)
                self.assertEqual(state["zenon_completion_packet_hex"], previous.hex())
                self.assertIsNone(state["superseded_zenon_completion_packet_hex"])
                self.assertIsNone(state["completion_receipt_hex"])
                self.assertEqual(bob.get_session(session)["recovery_budget"], {"limit": 2, "consumed": 2})
                before = bob.get_session(session), bob._sequence, (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()
                candidate = completion.bob_candidate_from_signature(state, final_signatures()[0])
                self.assertEqual(candidate, alice_packet())
                calls = []
                def unexpected(request):
                    calls.append(True)
                    return self.completer(request)
                with self.assertRaises(RecoveryExhausted):
                    bob.reconcile_exchange_bitcoin(session, candidate,
                        expected_observation_digest=completion.observation_digest(previous), recoverer=unexpected)
                self.assertEqual(calls, [])
                self.assertEqual((bob.get_session(session), bob._sequence,
                                  (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()), before)
                with self.assertRaises(OutcomeUnknown):
                    bob.replay_exchange_bitcoin(session)

    def test_imported_public_replacement_requires_exact_cas_then_archives_the_original(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-imported-public-reconciliation-") as directory:
            base = Path(directory)
            root, anchor = base / "state", base / "head.json"
            with Journal.open(root, anchor) as bob:
                session = prepare(bob, verifier=self.verifier, recovery_limit=2)
                release = bob.release_exchange_zenon(session)
                previous = completion.bob_candidate_from_signature(bob.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, previous, recoverer=self.completer)
            with Journal.open(root, anchor) as bob:
                before = bob.get_session(session), bob._sequence, (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()
                candidate = completion.bob_candidate_from_signature(bob.get_exchange(session), final_signatures()[0])
                self.assertEqual(candidate, alice_packet())
                calls = []
                def recover(request):
                    calls.append(True)
                    return self.completer(request)
                with self.assertRaises(Conflict):
                    bob.complete_exchange_bitcoin(session, candidate, recoverer=recover)
                with self.assertRaises(Conflict):
                    bob.reconcile_exchange_bitcoin(session, candidate,
                        expected_observation_digest=completion.observation_digest(candidate), recoverer=recover)
                self.assertEqual(calls, [])
                self.assertEqual((bob.get_session(session), bob._sequence,
                                  (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()), before)
                output = bob.reconcile_exchange_bitcoin(session, candidate,
                    expected_observation_digest=completion.observation_digest(previous), recoverer=recover)
                self.assertEqual(calls, [True])
                self.assertEqual(json.loads(output)["signature_hex"], final_signatures()[1].hex())
                state = bob.get_exchange(session)
                self.assertEqual(state["zenon_completion_packet_hex"], candidate.hex())
                self.assertEqual(state["superseded_zenon_completion_packet_hex"], previous.hex())
                self.assertEqual(bob.get_session(session)["recovery_budget"], {"limit": 2, "consumed": 2})
            with Journal.open(root, anchor) as bob:
                self.assertEqual(bob.replay_exchange_bitcoin(session), output)
                self.assertEqual(bob.replay_exchange_release(session), release)


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
