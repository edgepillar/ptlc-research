"""Actual process death while reconciling public completion observations."""

import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest

from offline_session import completion, exchange
from offline_session.journal import Conflict, Journal, OutcomeUnknown, Quarantined
from completion_test_support import alice_packet, completion_accepted, final_signatures
from exchange_test_support import prepare


@unittest.skipUnless(os.name == "posix", "qualification requires POSIX process signals")
class ReconciliationCrashTests(unittest.TestCase):
    def kill(self, root, anchor, session, checkpoint, marker):
        actor = Path(__file__).with_name("completion_crash_actor.py")
        child = subprocess.Popen([sys.executable, "-B", str(actor), "reconcile", str(root), str(anchor),
                                  session, checkpoint, str(marker)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=20), "reconciliation checkpoint timed out")
            self.assertEqual(child.stdout.readline().strip(), b"paused")
            child.kill()
            stdout, stderr = child.communicate(timeout=10)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            self.assertEqual((stdout, stderr), (b"", b""))
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def test_kill_matrix_preserves_original_quarantines_or_replays_complete_reconciliation(self):
        cases = (("during_reconciliation_recoverer", "RELEASE_RECORDED"),
                 ("after_bitcoin_reconciliation_recoverer", "RELEASE_RECORDED"),
                 ("before_db_commit", "RELEASE_RECORDED"),
                 ("after_db_commit", "QUARANTINED"),
                 ("after_anchor_replace", "BTC_COMPLETION_RECORDED"),
                 ("after_anchor_commit", "BTC_COMPLETION_RECORDED"),
                 ("after_bitcoin_reconciliation_commit", "BTC_COMPLETION_RECORDED"))
        replacement = alice_packet()
        value = json.loads(replacement)
        value["signature_hex"] = "00" * 64
        previous = exchange.canonical(value)
        expected = completion.observation_digest(previous)

        def unavailable(request):
            raise RuntimeError("synthetic public recovery interruption")

        for checkpoint, stage in cases:
            with self.subTest(checkpoint=checkpoint), tempfile.TemporaryDirectory(prefix="ptlc-reconciliation-crash-") as directory:
                base = Path(directory)
                root, anchor, marker = base / "state", base / "head.json", base / "calls"
                with Journal.open(root, anchor) as journal:
                    session = prepare(journal)
                    release = journal.release_exchange_zenon(session)
                    with self.assertRaises(Conflict):
                        journal.complete_exchange_bitcoin(session, previous, recoverer=unavailable)
                    original = journal.get_session(session)
                self.kill(root, anchor, session, checkpoint, marker)
                self.assertEqual(marker.read_bytes(), b"1")
                if stage == "QUARANTINED":
                    with self.assertRaises(Quarantined):
                        Journal.open(root, anchor)
                    continue
                with Journal.open(root, anchor) as journal:
                    self.assertTrue(journal.get_session(session)["possible_exposure"])
                    self.assertEqual(journal.get_exchange(session)["stage"], stage)
                    if stage == "RELEASE_RECORDED":
                        self.assertEqual(journal.get_session(session), original)
                        with self.assertRaises(OutcomeUnknown):
                            journal.replay_exchange_bitcoin(session)
                        # The caller resupplies the uncommitted replacement. This
                        # repeats public computation without a signing nonce.
                        output = journal.reconcile_exchange_bitcoin(
                            session, replacement, expected_observation_digest=expected,
                            recoverer=completion_accepted,
                        )
                    else:
                        output = journal.replay_exchange_bitcoin(session)
                        with self.assertRaises(Conflict):
                            journal.reconcile_exchange_bitcoin(
                                session, replacement, expected_observation_digest=expected,
                                recoverer=completion_accepted,
                            )
                    state = journal.get_exchange(session)
                    self.assertEqual(state["superseded_zenon_completion_packet_hex"], previous.hex())
                    self.assertEqual(state["zenon_completion_packet_hex"], replacement.hex())
                    self.assertEqual(json.loads(output)["signature_hex"], final_signatures()[1].hex())
                    self.assertEqual(journal.replay_exchange_bitcoin(session), output)
                    self.assertEqual(journal.replay_exchange_release(session), release)
                self.assertEqual(marker.read_bytes(), b"1")


if __name__ == "__main__":
    unittest.main()
