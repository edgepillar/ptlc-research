"""Offline reconciliation durability with public fixtures and fake recovery."""

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from offline_session import completion, exchange
from offline_session.journal import (
    Busy, Conflict, InvalidInput, Journal, OutcomeUnknown, OwnershipError,
    Quarantined, VERSION,
)
from completion_test_support import alice_context, alice_packet, completion_accepted
from exchange_test_support import accepted, artifacts, prepare


class ReconciliationJournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.terms, cls.bitcoin, cls.zenon, cls.btc_bundle, cls.znn_bundle = artifacts()
        cls.session = cls.terms.session_id
        cls.valid_packet = alice_packet()
        candidate = json.loads(cls.valid_packet)
        candidate["signature_hex"] = "00" * 64
        cls.old_packet = exchange.canonical(candidate)
        cls.old_digest = hashlib.sha256(
            b"PTLC/completion-observation/v1\x00" + cls.old_packet,
        ).hexdigest()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ptlc-reconciliation-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "state"
        self.anchor = self.base / "head.json"

    def open(self, **kwargs):
        return Journal.open(self.root, self.anchor, **kwargs)

    def durable_bytes(self):
        return (self.root / "journal.sqlite3").read_bytes(), self.anchor.read_bytes()

    def ready(self, journal):
        self.assertEqual(prepare(journal), self.session)
        release = journal.release_exchange_zenon(self.session)
        with self.assertRaises(Conflict):
            journal.complete_exchange_bitcoin(
                self.session, self.old_packet,
                recoverer=lambda request: dict(completion_accepted(request), valid=False),
            )
        return release

    def reconcile(self, journal, *, packet=None, digest=None, recoverer=completion_accepted):
        return journal.reconcile_exchange_bitcoin(
            self.session, self.valid_packet if packet is None else packet,
            expected_observation_digest=self.old_digest if digest is None else digest,
            recoverer=recoverer,
        )

    def test_replacement_is_verified_before_single_commit_and_preserves_exact_audit(self):
        calls, events = [], []
        with self.open(hook=events.append) as journal:
            release = self.ready(journal)
            before = journal.get_session(self.session)
            stored_before = self.durable_bytes()
            sequence = json.loads(stored_before[1])["sequence"]
            events.clear()

            def recoverer(request):
                calls.append(1)
                self.assertEqual(journal.get_session(self.session), before)
                self.assertEqual(self.durable_bytes(), stored_before)
                self.assertEqual(request["zenon_signature_hex"], json.loads(self.valid_packet)["signature_hex"])
                self.assertEqual(events, [])
                return completion_accepted(request)

            output = self.reconcile(journal, recoverer=recoverer)
            result = journal.get_exchange(self.session)
            self.assertEqual(result["stage"], "BTC_COMPLETION_RECORDED")
            self.assertEqual(result["superseded_zenon_completion_packet_hex"], self.old_packet.hex())
            self.assertEqual(result["zenon_completion_packet_hex"], self.valid_packet.hex())
            self.assertEqual(result["bitcoin_completion_packet_hex"], output.hex())
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
            self.assertEqual(journal.replay_exchange_bitcoin(self.session), output)
            self.assertEqual(journal.replay_exchange_release(self.session), release)
            self.assertEqual(json.loads(self.anchor.read_bytes())["sequence"], sequence + 1)
            self.assertEqual(events, [
                "after_bitcoin_reconciliation_recoverer", "before_db_commit", "after_db_commit",
                "after_anchor_replace", "after_anchor_commit", "after_bitcoin_reconciliation_commit",
            ])
            with self.assertRaises(Conflict):
                self.reconcile(journal, recoverer=lambda request: self.fail("completed recovery repeated"))
            with self.assertRaises(Conflict):
                journal.complete_exchange_bitcoin(
                    self.session, recoverer=lambda request: self.fail("completed recovery repeated"),
                )
        with self.open() as journal:
            self.assertEqual(journal.get_exchange(self.session), result)
            self.assertEqual(journal.replay_exchange_bitcoin(self.session), output)
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
        self.assertEqual(calls, [1])

    def test_callback_failures_preserve_original_memory_storage_and_retry(self):
        def failure(request):
            raise KeyboardInterrupt("synthetic recovery detail")

        def runtime_failure(request):
            raise RuntimeError("synthetic recovery detail")

        cases = [failure, runtime_failure,
                 lambda request: dict(completion_accepted(request), valid=False),
                 lambda request: dict(completion_accepted(request), valid=1),
                 lambda request: dict(completion_accepted(request), request_digest_hex="99" * 32),
                 lambda request: dict(completion_accepted(request), bitcoin_signature_hex="00")]
        events = []
        with self.open(hook=events.append) as journal:
            self.ready(journal)
            before, stored = journal.get_session(self.session), self.durable_bytes()
            events.clear()
            for recoverer in cases:
                with self.subTest(callback=cases.index(recoverer)):
                    with self.assertRaisesRegex(Conflict, "^Bitcoin completion reconciliation rejected$"):
                        self.reconcile(journal, recoverer=recoverer)
                    self.assertEqual(journal.get_session(self.session), before)
                    self.assertEqual(self.durable_bytes(), stored)
                    self.assertEqual(events, [])
                    with self.assertRaises(OutcomeUnknown):
                        journal.replay_exchange_bitcoin(self.session)
        with self.open() as journal:
            self.assertEqual(journal.get_session(self.session), before)
            self.assertIsInstance(self.reconcile(journal), bytes)

    def test_stale_malformed_and_same_candidate_inputs_never_call_recoverer(self):
        wrong_context = json.loads(self.valid_packet)
        wrong_context["context"]["role"] = "bob"
        cases = [(self.valid_packet, "99" * 32), (self.valid_packet, True),
                 (self.valid_packet, "AB" * 32), (self.valid_packet, "00"),
                 (self.old_packet, self.old_digest), (self.valid_packet + b"\n", self.old_digest),
                 (b"{}", self.old_digest), (self.valid_packet.decode("ascii"), self.old_digest),
                 (exchange.canonical(wrong_context), self.old_digest)]
        with self.open() as journal:
            self.ready(journal)
            before, stored = journal.get_session(self.session), self.durable_bytes()
            for number, (packet, digest) in enumerate(cases):
                with self.subTest(number=number):
                    with self.assertRaises(Conflict):
                        self.reconcile(journal, packet=packet, digest=digest,
                                       recoverer=lambda request: self.fail("invalid request reached recovery"))
                    self.assertEqual(journal.get_session(self.session), before)
                    self.assertEqual(self.durable_bytes(), stored)
            with self.assertRaises(InvalidInput):
                self.reconcile(journal, recoverer=None)
            self.assertEqual(self.durable_bytes(), stored)

    def test_alice_generic_unreleased_and_unobserved_sessions_cannot_reconcile(self):
        for mode in ("empty", "generic", "alice", "unreleased", "unobserved"):
            with self.subTest(mode=mode):
                self.root, self.anchor = self.base / mode, self.base / (mode + ".head")
                with self.open() as journal:
                    if mode in {"unreleased", "unobserved"}:
                        prepare(journal)
                        if mode == "unobserved":
                            journal.release_exchange_zenon(self.session)
                    else:
                        journal.create_session(self.session, self.terms.digest_hex)
                        if mode == "generic":
                            journal.reserve(self.session, "31" * 32, self.bitcoin, "32" * 32)
                        elif mode == "alice":
                            journal.start_alice(self.session, alice_context(),
                                                self.znn_bundle["partial_signatures_hex"][0], verifier=accepted)
                    before, stored = journal.get_session(self.session), self.durable_bytes()
                    with self.assertRaises(Conflict):
                        self.reconcile(journal, recoverer=lambda request: self.fail("wrong mode reached recovery"))
                    self.assertEqual(journal.get_session(self.session), before)
                    self.assertEqual(self.durable_bytes(), stored)

    def test_recoverer_guard_blocks_mutation_close_and_foreign_thread_access(self):
        failures = []
        with self.open() as journal:
            self.ready(journal)
            before = journal.get_session(self.session)

            def recoverer(request):
                for action in (
                    journal.close,
                    lambda: journal.observe(self.session, "91" * 32),
                    lambda: self.reconcile(journal),
                    lambda: journal.complete_exchange_bitcoin(self.session, recoverer=completion_accepted),
                    lambda: journal.start_alice(self.session, alice_context(),
                                               self.znn_bundle["partial_signatures_hex"][0], verifier=accepted),
                ):
                    with self.assertRaises(Conflict):
                        action()
                snapshot = journal.get_exchange(self.session)
                snapshot["zenon_completion_packet_hex"] = "00"
                self.assertEqual(journal.get_session(self.session), before)
                with self.assertRaises(Busy):
                    self.open()

                def foreign():
                    for action in (journal.close, lambda: journal.get_exchange(self.session),
                                   lambda: self.reconcile(journal)):
                        try:
                            action()
                        except OwnershipError:
                            failures.append(1)

                thread = threading.Thread(target=foreign)
                thread.start()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                return completion_accepted(request)

            self.reconcile(journal, recoverer=recoverer)
            self.assertEqual(failures, [1, 1, 1])

    def test_closed_owner_cannot_begin_reconciliation(self):
        journal = self.open()
        self.ready(journal)
        journal.close()
        before = self.durable_bytes()
        with self.assertRaises(OwnershipError):
            self.reconcile(journal, recoverer=lambda request: self.fail("closed owner recovered"))
        self.assertEqual(self.durable_bytes(), before)

    def test_named_checkpoint_failures_preserve_prior_state_or_exact_completed_output(self):
        for checkpoint in ("after_bitcoin_reconciliation_recoverer", "after_bitcoin_reconciliation_commit"):
            with self.subTest(checkpoint=checkpoint):
                self.root, self.anchor = self.base / checkpoint, self.base / (checkpoint + ".head")
                enabled, calls = [], []

                def hook(name):
                    if enabled and name == checkpoint:
                        raise RuntimeError("synthetic checkpoint interruption")

                with self.open(hook=hook) as journal:
                    self.ready(journal)
                    prior = journal.get_exchange(self.session)
                    enabled.append(True)
                    with self.assertRaises(Quarantined):
                        self.reconcile(journal, recoverer=lambda request: calls.append(1) or completion_accepted(request))
                    with self.assertRaises(Quarantined):
                        journal.get_exchange(self.session)
                with self.open() as journal:
                    self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                    if checkpoint == "after_bitcoin_reconciliation_recoverer":
                        self.assertEqual(journal.get_exchange(self.session), prior)
                        with self.assertRaises(OutcomeUnknown):
                            journal.replay_exchange_bitcoin(self.session)
                        self.reconcile(journal)
                    else:
                        result = journal.get_exchange(self.session)
                        self.assertEqual(result["stage"], "BTC_COMPLETION_RECORDED")
                        self.assertEqual(result["superseded_zenon_completion_packet_hex"], self.old_packet.hex())
                        self.assertEqual(journal.replay_exchange_bitcoin(self.session).hex(), result["bitcoin_completion_packet_hex"])
                self.assertEqual(calls, [1])

    def test_database_checkpoint_failure_keeps_old_state_or_quarantines_gap(self):
        for checkpoint in ("before_db_commit", "after_db_commit", "after_anchor_replace"):
            with self.subTest(checkpoint=checkpoint):
                self.root, self.anchor = self.base / checkpoint, self.base / (checkpoint + ".head")
                enabled = []

                def hook(name):
                    if enabled and name == checkpoint:
                        raise RuntimeError("synthetic persistence interruption")

                with self.open(hook=hook) as journal:
                    self.ready(journal)
                    prior = journal.get_exchange(self.session)
                    enabled.append(True)
                    with self.assertRaises(Quarantined):
                        self.reconcile(journal)
                if checkpoint == "after_db_commit":
                    with self.assertRaises(Quarantined):
                        self.open()
                else:
                    with self.open() as journal:
                        self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                        if checkpoint == "before_db_commit":
                            self.assertEqual(journal.get_exchange(self.session), prior)
                        else:
                            self.assertEqual(journal.get_exchange(self.session)["stage"], "BTC_COMPLETION_RECORDED")
                            self.assertIsInstance(journal.replay_exchange_bitcoin(self.session), bytes)

    def test_version_four_checkpoint_is_quarantined_without_migration(self):
        with self.open() as journal:
            self.ready(journal)
        db = self.root / "journal.sqlite3"
        connection = sqlite3.connect(str(db))
        try:
            lineage, sequence, raw = connection.execute(
                "SELECT lineage, sequence, state_json FROM checkpoint",
            ).fetchone()
            state = json.loads(raw)
            state["sessions"][self.session]["exchange"].pop("superseded_zenon_completion_packet_hex")
            material = {"version": 4, "lineage": lineage, "sequence": sequence, "state": state}
            digest = hashlib.sha256(b"ptlc-offline-journal-v4\x00" + exchange.canonical(material)).hexdigest()
            connection.execute("UPDATE checkpoint SET version=4, state_json=?, digest=?",
                               (exchange.canonical(state).decode("ascii"), digest))
            connection.commit()
            self.anchor.write_bytes(exchange.canonical({
                "version": 4, "lineage": lineage, "sequence": sequence, "digest": digest,
            }))
        finally:
            connection.close()
        self.assertEqual(VERSION, 5)
        before = self.durable_bytes()
        with self.assertRaises(Quarantined):
            self.open()
        self.assertEqual(self.durable_bytes(), before)


if __name__ == "__main__":
    unittest.main()
