"""Partial-output journal failure cuts and copy limits, using public fixtures only.

Callbacks return fixed bytes. They perform no nonce generation, private signing,
adaptor completion or key extraction. SIGKILL is not a storage power-cut test.
"""

import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest

from offline_session.journal import Conflict, Journal, OutcomeUnknown, Quarantined
from partial_journal_actor import PARTIAL_SCOPES, partial_context
from session_test_support import NONCE_TAG, OPERATION_ID, PUBLIC_OUTPUT


@unittest.skipUnless(os.name == "posix", "qualification requires POSIX locks and process signals")
class PartialJournalBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ptlc-partial-boundary-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def initialize(self, root, anchor, terms):
        with Journal.open(root, anchor) as journal:
            journal.create_session(terms.session_id, terms.digest_hex)

    def produce(self, journal, terms, context, calls):
        def synthetic_producer():
            self.assertEqual(journal.get_operation(terms.session_id, OPERATION_ID)["status"], "CONSUMED")
            self.assertFalse(journal.get_session(terms.session_id)["possible_exposure"])
            calls.append(1)
            return PUBLIC_OUTPUT

        return journal.produce_once(terms.session_id, OPERATION_ID, expected_context=context,
                                    callback=synthetic_producer)

    def assert_spent(self, journal, terms, context, *, recorded):
        attempted = []
        with self.assertRaises(OutcomeUnknown):
            journal.produce_once(terms.session_id, OPERATION_ID, expected_context=context,
                                 callback=lambda: attempted.append(1) or PUBLIC_OUTPUT)
        # Producer errors are wrapped; an assertion inside it could be swallowed.
        self.assertEqual(attempted, [], "spent producer was invoked")
        with self.assertRaises(Conflict):
            journal.reserve(terms.session_id, "32" * 32, context, "43" * 32)
        with self.assertRaises(Conflict):
            journal.reserve(terms.session_id, "32" * 32, context, NONCE_TAG)
        if recorded:
            # Replay is a read of retained bytes and changes no local history.
            before = journal.get_session(terms.session_id)
            self.assertEqual(journal.replay(terms.session_id, OPERATION_ID, expected_context=context), PUBLIC_OUTPUT)
            self.assertEqual(journal.replay(terms.session_id, OPERATION_ID, expected_context=context), PUBLIC_OUTPUT)
            self.assertEqual(journal.get_session(terms.session_id), before)
        else:
            with self.assertRaises(OutcomeUnknown):
                journal.replay(terms.session_id, OPERATION_ID, expected_context=context)

    def test_partial_sigkill_consumption_and_output_cut_matrix(self):
        # Explicit expected outcomes, not values derived from the implementation.
        cases = (
            ("before_db_commit", 1, "RETIRED", 0),
            ("after_db_commit", 1, "QUARANTINED", 0),
            ("after_anchor_replace", 1, "OUTCOME_UNKNOWN", 0),
            ("after_anchor_commit", 1, "OUTCOME_UNKNOWN", 0),
            ("after_consume", 1, "OUTCOME_UNKNOWN", 0),
            ("after_callback", 1, "OUTCOME_UNKNOWN", 1),
            ("before_db_commit", 2, "OUTCOME_UNKNOWN", 1),
            ("after_db_commit", 2, "QUARANTINED", 1),
            ("after_anchor_replace", 2, "OUTPUT_RECORDED", 1),
            ("after_anchor_commit", 2, "OUTPUT_RECORDED", 1),
            ("after_output_commit", 1, "OUTPUT_RECORDED", 1),
        )
        actor = Path(__file__).with_name("partial_journal_actor.py")
        for leg, role in PARTIAL_SCOPES:
            terms, context = partial_context(leg, role)
            for index, (cut, occurrence, expected_status, expected_calls) in enumerate(cases):
                with self.subTest(leg=leg, role=role, cut=cut, occurrence=occurrence):
                    case = self.base / (leg + "-" + role + "-" + str(index))
                    case.mkdir()
                    root, anchor, marker = case / "state", case / "anchor", case / "calls"
                    self.initialize(root, anchor, terms)
                    with subprocess.Popen(
                        [sys.executable, "-B", str(actor), str(root), str(anchor), "--leg", leg,
                         "--role", role, "--checkpoint", cut, "--occurrence", str(occurrence),
                         "--marker", str(marker)], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    ) as child:
                        try:
                            with selectors.DefaultSelector() as selector:
                                selector.register(child.stdout, selectors.EVENT_READ)
                                self.assertTrue(selector.select(timeout=10), "child did not reach the bounded cut")
                            self.assertEqual(child.stdout.readline().strip(), b"paused", "child cut mismatch")
                            child.kill()
                            _, stderr = child.communicate(timeout=10)
                            self.assertEqual(child.returncode, -signal.SIGKILL)
                            self.assertEqual(stderr, b"")
                        finally:
                            if child.poll() is None:
                                child.kill()
                            child.communicate(timeout=10)
                    self.assertEqual(marker.read_bytes() if marker.exists() else b"", b"1" * expected_calls)
                    if expected_status == "QUARANTINED":
                        with self.assertRaises(Quarantined):
                            with Journal.open(root, anchor):
                                pass
                        self.assertEqual(marker.read_bytes() if marker.exists() else b"", b"1" * expected_calls)
                        continue
                    with Journal.open(root, anchor) as journal:
                        operation = journal.get_operation(terms.session_id, OPERATION_ID)
                        self.assertEqual(operation["status"], expected_status)
                        self.assertEqual(operation["nonce_round_digest"], context.as_dict()["nonce_round_digest_hex"])
                        self.assertFalse(journal.get_session(terms.session_id)["possible_exposure"])
                        self.assert_spent(journal, terms, context, recorded=expected_status == "OUTPUT_RECORDED")
                    self.assertEqual(marker.read_bytes() if marker.exists() else b"", b"1" * expected_calls)

    def test_distinct_live_journal_copies_can_repeat_synthetic_partial_production(self):
        for leg, role in PARTIAL_SCOPES:
            with self.subTest(leg=leg, role=role):
                terms, context = partial_context(leg, role)
                case = self.base / (leg + "-" + role)
                case.mkdir()
                first, first_anchor = case / "first", case / "first-anchor"
                second, second_anchor = case / "second", case / "second-anchor"
                self.initialize(first, first_anchor, terms)
                second.mkdir(mode=0o700)
                second_db = second / "journal.sqlite3"
                second_db.write_bytes((first / "journal.sqlite3").read_bytes())
                second_db.chmod(0o600)
                second_anchor.write_bytes(first_anchor.read_bytes())
                second_anchor.chmod(0o600)
                calls = []
                # Both owners are live on distinct locks, with the same copied lineage.
                with Journal.open(first, first_anchor) as a, Journal.open(second, second_anchor) as b:
                    for journal in (a, b):
                        journal.reserve(terms.session_id, OPERATION_ID, context, NONCE_TAG)
                        self.assertEqual(self.produce(journal, terms, context, calls), PUBLIC_OUTPUT)
                        self.assert_spent(journal, terms, context, recorded=True)
                    self.assertEqual(calls, [1, 1])
                for root, anchor in ((first, first_anchor), (second, second_anchor)):
                    with Journal.open(root, anchor) as journal:
                        self.assert_spent(journal, terms, context, recorded=True)
                self.assertEqual(calls, [1, 1])

    def test_coherent_pre_reservation_restore_can_repeat_synthetic_partial_production(self):
        for leg, role in PARTIAL_SCOPES:
            with self.subTest(leg=leg, role=role):
                terms, context = partial_context(leg, role)
                case = self.base / (leg + "-" + role)
                case.mkdir()
                root, anchor = case / "state", case / "anchor"
                self.initialize(root, anchor, terms)
                database = root / "journal.sqlite3"
                before_database, before_anchor = database.read_bytes(), anchor.read_bytes()
                calls = []
                with Journal.open(root, anchor) as journal:
                    journal.reserve(terms.session_id, OPERATION_ID, context, NONCE_TAG)
                    self.assertEqual(self.produce(journal, terms, context, calls), PUBLIC_OUTPUT)
                    self.assert_spent(journal, terms, context, recorded=True)
                database.write_bytes(before_database)
                anchor.write_bytes(before_anchor)
                with Journal.open(root, anchor) as journal:
                    self.assertEqual(journal.get_session(terms.session_id)["operations"], {})
                    journal.reserve(terms.session_id, OPERATION_ID, context, NONCE_TAG)
                    self.assertEqual(self.produce(journal, terms, context, calls), PUBLIC_OUTPUT)
                    self.assert_spent(journal, terms, context, recorded=True)
                self.assertEqual(calls, [1, 1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
