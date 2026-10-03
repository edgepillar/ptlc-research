"""Real process death before and after durable public-recovery admission."""

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
from offline_session.journal import Conflict, Journal, Quarantined, RecoveryExhausted
from completion_test_support import alice_packet, completion_accepted
from exchange_test_support import prepare


@unittest.skipUnless(os.name == "posix", "qualification requires POSIX process signals")
class RecoveryBudgetCrashTests(unittest.TestCase):
    def kill(self, mode, root, anchor, session, checkpoint, marker):
        actor = Path(__file__).with_name("completion_crash_actor.py")
        child = subprocess.Popen([sys.executable, "-B", str(actor), mode, str(root), str(anchor),
                                  session, checkpoint, str(marker)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as selection:
                selection.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selection.select(timeout=20), "admission checkpoint timed out")
            self.assertEqual(child.stdout.readline().strip(), b"paused")
            child.kill()
            stdout, stderr = child.communicate(timeout=10)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            self.assertEqual((stdout, stderr), (b"", b""))
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def test_ordinary_and_reconciliation_admission_kill_matrix_never_refunds_committed_attempt(self):
        replacement = alice_packet()
        previous = json.loads(replacement)
        previous["signature_hex"] = "00" * 64
        previous = exchange.canonical(previous)
        digest = completion.observation_digest(previous)
        for mode in ("bob", "reconcile"):
            baseline = int(mode == "reconcile")
            for checkpoint in ("before_db_commit", "after_db_commit", "after_bob_recovery_admission_commit"):
                with self.subTest(mode=mode, checkpoint=checkpoint), \
                        tempfile.TemporaryDirectory(prefix="synthetic-admission-crash-") as directory:
                    base = Path(directory)
                    root, anchor, marker = base / "state", base / "head.json", base / "calls"
                    with Journal.open(root, anchor) as journal:
                        session = prepare(journal, recovery_limit=baseline + 1)
                        journal.release_exchange_zenon(session)
                        if baseline:
                            with self.assertRaises(Conflict):
                                journal.complete_exchange_bitcoin(session, previous, recoverer=lambda _: None)
                        before_exchange = journal.get_exchange(session)
                    self.kill(mode, root, anchor, session, checkpoint, marker)
                    self.assertFalse(marker.exists(), "worker ran before admission checkpoint")
                    if checkpoint == "after_db_commit":
                        with self.assertRaises(Quarantined):
                            Journal.open(root, anchor)
                        continue
                    with Journal.open(root, anchor) as journal:
                        admitted = checkpoint == "after_bob_recovery_admission_commit"
                        budget = journal.get_session(session)["recovery_budget"]
                        self.assertEqual(budget, {"limit": baseline + 1, "consumed": baseline + int(admitted)})
                        state = journal.get_exchange(session)
                        self.assertEqual(state["stage"], "RELEASE_RECORDED")
                        if baseline or not admitted:
                            self.assertEqual(state, before_exchange)
                        else:
                            self.assertEqual(state["zenon_completion_packet_hex"], replacement.hex())
                            self.assertTrue(journal.get_session(session)["possible_exposure"])
                        calls = []
                        def retry():
                            if baseline:
                                return journal.reconcile_exchange_bitcoin(
                                    session, replacement, expected_observation_digest=digest,
                                    recoverer=lambda request: calls.append(1) or completion_accepted(request),
                                )
                            return journal.complete_exchange_bitcoin(
                                session, replacement,
                                recoverer=lambda request: calls.append(1) or completion_accepted(request),
                            )
                        if admitted:
                            with self.assertRaises(RecoveryExhausted):
                                retry()
                            self.assertEqual(calls, [])
                        else:
                            self.assertIsInstance(retry(), bytes)
                            self.assertEqual(calls, [1])
                    self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
