"""Real child termination for synthetic Alice output and public Bob recovery."""

import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest

from offline_session.journal import Conflict, Journal, OutcomeUnknown, Quarantined
from completion_test_support import alice_packet, completion_accepted, final_signatures, prepare_alice
from exchange_test_support import prepare


@unittest.skipUnless(os.name == "posix", "qualification requires POSIX process signals")
class CompletionCrashTests(unittest.TestCase):
    def kill(self, mode, root, anchor, session, checkpoint, marker):
        actor = Path(__file__).with_name("completion_crash_actor.py")
        child = subprocess.Popen([sys.executable, "-B", str(actor), mode, str(root), str(anchor), session,
                                  checkpoint, str(marker)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=20), "completion checkpoint timed out")
            self.assertEqual(child.stdout.readline().strip(), b"paused")
            child.kill()
            stdout, stderr = child.communicate(timeout=10)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            self.assertEqual((stdout, stderr), (b"", b""))
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def test_alice_completion_kill_matrix_never_repeats_a_consumed_producer(self):
        cases = (("before_db_commit", "PRESIGNATURE_RETAINED", False, 0),
                 ("after_db_commit", "QUARANTINED", None, 0),
                 ("after_anchor_replace", "OUTCOME_UNKNOWN", True, 0),
                 ("after_anchor_commit", "OUTCOME_UNKNOWN", True, 0),
                 ("after_alice_consume", "OUTCOME_UNKNOWN", True, 0),
                 ("after_alice_producer", "OUTCOME_UNKNOWN", True, 1),
                 ("after_alice_output_commit", "COMPLETION_RECORDED", True, 1))
        for checkpoint, stage, exposed, count in cases:
            with self.subTest(checkpoint=checkpoint), tempfile.TemporaryDirectory(prefix="ptlc-alice-crash-") as directory:
                base = Path(directory)
                root, anchor, marker = base / "state", base / "head.json", base / "calls"
                with Journal.open(root, anchor) as journal:
                    session = prepare_alice(journal)
                self.kill("alice", root, anchor, session, checkpoint, marker)
                self.assertEqual(len(marker.read_bytes()) if marker.exists() else 0, count)
                if stage == "QUARANTINED":
                    with self.assertRaises(Quarantined):
                        Journal.open(root, anchor)
                    continue
                with Journal.open(root, anchor) as journal:
                    self.assertEqual(journal.get_alice(session)["stage"], stage)
                    self.assertEqual(journal.get_session(session)["possible_exposure"], exposed)
                    if stage == "COMPLETION_RECORDED":
                        packet = journal.replay_alice_completion(session)
                        self.assertEqual(json.loads(packet)["signature_hex"], final_signatures()[0].hex())
                    elif stage == "PRESIGNATURE_RETAINED":
                        with self.assertRaises(OutcomeUnknown):
                            journal.replay_alice_completion(session)
                        # The producer was never entered and consumption never committed.
                        packet = journal.complete_alice(session, producer=lambda: final_signatures()[0], verifier=completion_accepted)
                        self.assertEqual(journal.replay_alice_completion(session), packet)
                    else:
                        calls = []
                        with self.assertRaises(OutcomeUnknown):
                            journal.complete_alice(session, producer=lambda: calls.append(True) or final_signatures()[0], verifier=completion_accepted)
                        with self.assertRaises(OutcomeUnknown):
                            journal.replay_alice_completion(session)
                        self.assertEqual(calls, [])
                self.assertEqual(len(marker.read_bytes()) if marker.exists() else 0, count)

    def test_bob_public_recovery_kill_matrix_retains_the_exact_observation(self):
        cases = (("before_db_commit", "RELEASE_RECORDED", False, 0),
                 ("after_db_commit", "QUARANTINED", None, 0),
                 ("after_bob_observation_commit", "RELEASE_RECORDED", True, 0),
                 ("after_bitcoin_recoverer", "RELEASE_RECORDED", True, 1),
                 ("after_bitcoin_completion_commit", "BTC_COMPLETION_RECORDED", True, 1))
        packet = alice_packet()
        for checkpoint, stage, observed, count in cases:
            with self.subTest(checkpoint=checkpoint), tempfile.TemporaryDirectory(prefix="ptlc-bob-crash-") as directory:
                base = Path(directory)
                root, anchor, marker = base / "state", base / "head.json", base / "calls"
                with Journal.open(root, anchor) as journal:
                    session = prepare(journal)
                    release = journal.release_exchange_zenon(session)
                self.kill("bob", root, anchor, session, checkpoint, marker)
                self.assertEqual(len(marker.read_bytes()) if marker.exists() else 0, count)
                if stage == "QUARANTINED":
                    with self.assertRaises(Quarantined):
                        Journal.open(root, anchor)
                    continue
                with Journal.open(root, anchor) as journal:
                    state = journal.get_exchange(session)
                    self.assertEqual(state["stage"], stage)
                    self.assertEqual(journal.get_session(session)["possible_exposure"], observed)
                    self.assertEqual(state["zenon_completion_packet_hex"], packet.hex() if observed else None)
                    self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], int(observed))
                    if stage == "BTC_COMPLETION_RECORDED":
                        output = journal.replay_exchange_bitcoin(session)
                        with self.assertRaises(Conflict):
                            journal.complete_exchange_bitcoin(session, packet, recoverer=completion_accepted)
                    else:
                        with self.assertRaises(OutcomeUnknown):
                            journal.replay_exchange_bitcoin(session)
                        if observed:
                            # This repeats only a public-input transformation, not a private nonce use.
                            output = journal.complete_exchange_bitcoin(session, recoverer=completion_accepted)
                        else:
                            output = journal.complete_exchange_bitcoin(session, packet, recoverer=completion_accepted)
                    self.assertEqual(json.loads(output)["signature_hex"], final_signatures()[1].hex())
                    self.assertEqual(journal.replay_exchange_bitcoin(session), output)
                    self.assertEqual(journal.replay_exchange_release(session), release)
                self.assertEqual(len(marker.read_bytes()) if marker.exists() else 0, count)


if __name__ == "__main__":
    unittest.main()
