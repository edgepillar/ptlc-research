"""Actual process-death qualification of retained public artifacts and release."""

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
from exchange_test_support import artifacts, prepare


@unittest.skipUnless(os.name == "posix", "qualification requires POSIX process signals")
class ExchangeCrashTests(unittest.TestCase):
    def test_retention_death_matrix_blocks_release_until_extraction_material_is_durable(self):
        from exchange_test_support import accepted
        cases = (("before_db_commit", "ALICE_PARTIAL_RETAINED"),
                 ("after_db_commit", "QUARANTINED"),
                 ("after_anchor_commit", "ZENON_RETAINED"),
                 ("after_exchange_retained", "ZENON_RETAINED"))
        for checkpoint, stage in cases:
            with self.subTest(checkpoint=checkpoint), tempfile.TemporaryDirectory(prefix="ptlc-retention-crash-") as directory:
                base = Path(directory)
                root, anchor = base / "state", base / "head.json"
                terms, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
                with Journal.open(root, anchor) as journal:
                    journal.create_session(terms.session_id, terms.digest_hex)
                    journal.start_exchange(terms.session_id, bitcoin)
                    journal.retain_exchange_bitcoin(terms.session_id, btc_bundle, verifier=accepted)
                    journal.bind_exchange_zenon(terms.session_id, zenon)
                    journal.retain_exchange_alice_partial(terms.session_id, znn_bundle["partial_signatures_hex"][0], verifier=accepted)
                actor = Path(__file__).with_name("exchange_crash_actor.py")
                child = subprocess.Popen([sys.executable, "-B", str(actor), str(root), str(anchor), terms.session_id,
                                          checkpoint, "--retain"], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(timeout=10), "retention checkpoint timed out")
                    self.assertEqual(child.stdout.readline().strip(), b"paused")
                    child.kill()
                    stdout, stderr = child.communicate(timeout=10)
                    self.assertEqual(child.returncode, -signal.SIGKILL)
                    self.assertEqual((stdout, stderr), (b"", b""))
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=10)
                if stage == "QUARANTINED":
                    with self.assertRaises(Quarantined):
                        Journal.open(root, anchor)
                    continue
                with Journal.open(root, anchor) as journal:
                    state = journal.get_exchange(terms.session_id)
                    self.assertEqual(state["stage"], stage)
                    with self.assertRaises(OutcomeUnknown):
                        journal.replay_exchange_release(terms.session_id)
                    if stage == "ALICE_PARTIAL_RETAINED":
                        self.assertIsNone(state["zenon_bundle"])
                        with self.assertRaises(Conflict):
                            journal.release_exchange_zenon(terms.session_id)
                    else:
                        self.assertEqual(state["zenon_bundle"], znn_bundle)
                        self.assertEqual(state["zenon_context"], zenon.as_dict())
                        self.assertIsInstance(journal.release_exchange_zenon(terms.session_id), bytes)

    def test_release_death_matrix_preserves_retained_extraction_material(self):
        cases = (
            ("before_db_commit", "ZENON_RETAINED"),
            ("after_db_commit", "QUARANTINED"),
            ("after_anchor_replace", "RELEASE_RECORDED"),
            ("after_anchor_commit", "RELEASE_RECORDED"),
            ("after_exchange_release_commit", "RELEASE_RECORDED"),
        )
        for checkpoint, stage in cases:
            with self.subTest(checkpoint=checkpoint), tempfile.TemporaryDirectory(prefix="ptlc-exchange-crash-") as directory:
                base = Path(directory)
                root, anchor = base / "state", base / "head.json"
                with Journal.open(root, anchor) as journal:
                    session = prepare(journal)
                    retained = journal.get_exchange(session)
                actor = Path(__file__).with_name("exchange_crash_actor.py")
                child = subprocess.Popen([sys.executable, "-B", str(actor), str(root), str(anchor), session, checkpoint],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(timeout=10), "release checkpoint timed out")
                    self.assertEqual(child.stdout.readline().strip(), b"paused")
                    child.kill()
                    stdout, stderr = child.communicate(timeout=10)
                    self.assertEqual(child.returncode, -signal.SIGKILL)
                    self.assertEqual((stdout, stderr), (b"", b""))
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=10)
                if stage == "QUARANTINED":
                    with self.assertRaises(Quarantined):
                        Journal.open(root, anchor)
                    continue
                with Journal.open(root, anchor) as journal:
                    state = journal.get_exchange(session)
                    self.assertEqual(state["stage"], stage)
                    for field in ("bitcoin_context", "zenon_context", "bitcoin_bundle", "zenon_bundle", "verification_receipts"):
                        self.assertEqual(state[field], retained[field])
                    self.assertFalse(journal.get_session(session)["possible_exposure"])
                    if stage == "ZENON_RETAINED":
                        self.assertFalse(state["release_may_have_escaped"])
                        with self.assertRaises(OutcomeUnknown):
                            journal.replay_exchange_release(session)
                        output = journal.release_exchange_zenon(session)
                    else:
                        self.assertTrue(state["release_may_have_escaped"])
                        with self.assertRaises(Conflict):
                            journal.release_exchange_zenon(session)
                        output = journal.replay_exchange_release(session)
                    packet = json.loads(output)
                    self.assertEqual(packet["context"], retained["zenon_context"])
                    self.assertEqual(packet["adaptor_presignature_hex"], retained["zenon_bundle"]["adaptor_presignature_hex"])
                    self.assertEqual(journal.replay_exchange_release(session), output)

    def test_incomplete_retention_never_permits_release_after_restart(self):
        from exchange_test_support import accepted
        terms, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
        with tempfile.TemporaryDirectory(prefix="ptlc-exchange-incomplete-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                journal.create_session(terms.session_id, terms.digest_hex)
                journal.start_exchange(terms.session_id, bitcoin)
                journal.retain_exchange_bitcoin(terms.session_id, btc_bundle, verifier=accepted)
                journal.bind_exchange_zenon(terms.session_id, zenon)
                journal.retain_exchange_alice_partial(terms.session_id, znn_bundle["partial_signatures_hex"][0], verifier=accepted)
            with Journal.open(base / "state", base / "head.json") as journal:
                with self.assertRaises(Conflict):
                    journal.release_exchange_zenon(terms.session_id)
                with self.assertRaises(OutcomeUnknown):
                    journal.replay_exchange_release(terms.session_id)
                self.assertEqual(journal.get_exchange(terms.session_id)["stage"], "ALICE_PARTIAL_RETAINED")


if __name__ == "__main__":
    unittest.main()
