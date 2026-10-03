"""Durable local Bob recovery allowances, not authenticated peer admission."""

import copy
from contextlib import closing
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import unittest

from offline_session import completion, exchange
from offline_session.journal import (
    Busy, Conflict, InvalidInput, Journal, MAX_RECOVERY_ATTEMPTS, OwnershipError,
    Quarantined, RecoveryExhausted, VERSION,
)
from completion_test_support import alice_context, alice_packet, completion_accepted, final_signatures
from exchange_test_support import accepted, artifacts


class RecoveryBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.terms, cls.bitcoin, cls.zenon, cls.btc_bundle, cls.znn_bundle = artifacts()
        cls.session = cls.terms.session_id
        cls.packet = alice_packet()
        old = json.loads(cls.packet)
        old["signature_hex"] = "00" * 64
        cls.old_packet = exchange.canonical(old)
        cls.old_digest = completion.observation_digest(cls.old_packet)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-recovery-budget-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root, self.anchor = self.base / "state", self.base / "head.json"

    def open(self, **kwargs):
        return Journal.open(self.root, self.anchor, **kwargs)

    def ready(self, journal, limit=8, verifier=accepted):
        journal.create_session(self.session, self.terms.digest_hex)
        journal.start_exchange(self.session, self.bitcoin, recovery_limit=limit)
        journal.retain_exchange_bitcoin(self.session, self.btc_bundle, verifier=verifier)
        journal.bind_exchange_zenon(self.session, self.zenon)
        journal.retain_exchange_alice_partial(self.session, self.znn_bundle["partial_signatures_hex"][0], verifier=verifier)
        journal.retain_exchange_zenon(self.session, self.znn_bundle, verifier=verifier)
        return journal.release_exchange_zenon(self.session)

    def budget(self, journal):
        return journal.get_session(self.session)["recovery_budget"]

    def durable_bytes(self):
        return (self.root / "journal.sqlite3").read_bytes(), self.anchor.read_bytes()

    def disk_budget(self):
        with closing(sqlite3.connect(str(self.root / "journal.sqlite3"))) as connection:
            raw, sequence = connection.execute("SELECT state_json, sequence FROM checkpoint").fetchone()
        self.assertEqual(sequence, json.loads(self.anchor.read_bytes())["sequence"])
        return json.loads(raw)["sessions"][self.session]["recovery_budget"]

    def reject(self, journal, packet=None, recoverer=None):
        with self.assertRaises(Conflict):
            journal.complete_exchange_bitcoin(
                self.session, self.old_packet if packet is None else packet,
                recoverer=(lambda _: None) if recoverer is None else recoverer,
            )

    def reconcile(self, journal, recoverer=completion_accepted, **kwargs):
        return journal.reconcile_exchange_bitcoin(
            self.session, kwargs.get("packet", self.packet),
            expected_observation_digest=kwargs.get("digest", self.old_digest), recoverer=recoverer,
        )

    def rewrite(self, transform, version=VERSION):
        with closing(sqlite3.connect(str(self.root / "journal.sqlite3"))) as connection:
            lineage, sequence, raw = connection.execute("SELECT lineage, sequence, state_json FROM checkpoint").fetchone()
            state = json.loads(raw)
            transform(state["sessions"][self.session])
            material = {"version": version, "lineage": lineage, "sequence": sequence, "state": state}
            digest = hashlib.sha256(("ptlc-offline-journal-v" + str(version)).encode("ascii") + b"\x00"
                                    + exchange.canonical(material)).hexdigest()
            connection.execute("UPDATE checkpoint SET version=?, state_json=?, digest=?",
                               (version, exchange.canonical(state).decode("ascii"), digest))
            connection.commit()
        self.anchor.write_bytes(exchange.canonical({
            "version": version, "lineage": lineage, "sequence": sequence, "digest": digest,
        }))

    def test_explicit_limit_requires_exact_integer_with_closed_range(self):
        self.assertEqual(MAX_RECOVERY_ATTEMPTS, 64)
        with self.open() as journal:
            journal.create_session(self.session, self.terms.digest_hex)
            before = self.durable_bytes()
            with self.assertRaises(TypeError):
                journal.start_exchange(self.session, self.bitcoin)
            for limit in (None, True, False, 0, -1, 65, 1.0, "1", [], 2 ** 256):
                with self.subTest(limit=limit), self.assertRaises(InvalidInput):
                    journal.start_exchange(self.session, self.bitcoin, recovery_limit=limit)
                self.assertEqual(self.durable_bytes(), before)
                self.assertIsNone(self.budget(journal))
            journal.start_exchange(self.session, self.bitcoin, recovery_limit=64)
            self.assertEqual(self.budget(journal), {"limit": 64, "consumed": 0})

    def test_artifact_verifiers_do_not_consume_recovery_allowance(self):
        calls = []
        with self.open() as journal:
            self.ready(journal, limit=1, verifier=lambda request: calls.append(1) or accepted(request))
            self.assertEqual(calls, [1, 1, 1])
            self.assertEqual(self.budget(journal), {"limit": 1, "consumed": 0})

    def test_alice_and_generic_sessions_have_no_recovery_allowance(self):
        with self.open() as journal:
            journal.create_session(self.session, self.terms.digest_hex)
            self.assertIsNone(self.budget(journal))
            journal.start_alice(self.session, alice_context(), self.znn_bundle["partial_signatures_hex"][0], verifier=accepted)
            from completion_test_support import bob_release
            journal.accept_alice_release(self.session, bob_release(), verifier=accepted)
            calls = []
            output = journal.complete_alice(self.session, producer=lambda: calls.append(1) or final_signatures()[0],
                                            verifier=completion_accepted)
            self.assertIsNone(self.budget(journal))
            self.assertEqual(journal.replay_alice_completion(self.session), output)
            self.assertEqual(calls, [1])

    def test_ordinary_recovery_and_reconciliation_share_exhaustion_across_reopen(self):
        with self.open() as journal:
            self.ready(journal, limit=2)
            self.reject(journal)
            original = journal.get_exchange(self.session)
            with self.assertRaises(Conflict):
                self.reconcile(journal, recoverer=lambda _: None)
            self.assertEqual(self.budget(journal), {"limit": 2, "consumed": 2})
            self.assertEqual(journal.get_exchange(self.session), original)
        with self.open() as journal:
            before = self.durable_bytes()
            calls = []
            for action in (lambda: journal.complete_exchange_bitcoin(self.session, recoverer=lambda request: calls.append(1)),
                           lambda: self.reconcile(journal, recoverer=lambda request: calls.append(1))):
                with self.assertRaises(RecoveryExhausted):
                    action()
                self.assertEqual(self.durable_bytes(), before)
            self.assertEqual(calls, [])
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])

    def test_invalid_preflight_and_hostile_local_packet_never_consume_or_run(self):
        calls, equalities = [], []
        class HostilePacket:
            def __eq__(self, _):
                equalities.append(1)
                raise RuntimeError("synthetic equality detail")
        with self.open() as journal:
            self.ready(journal)
            for packet in (b"{}", self.packet + b"\n", HostilePacket()):
                before = self.durable_bytes()
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(self.session, packet, recoverer=lambda request: calls.append(1))
                self.assertEqual(self.durable_bytes(), before)
            self.reject(journal)
            before = self.durable_bytes()
            for packet, digest in ((self.packet, "99" * 32), (self.old_packet, self.old_digest),
                                   (b"{}", self.old_digest), (HostilePacket(), self.old_digest)):
                with self.assertRaises(Conflict):
                    self.reconcile(journal, packet=packet, digest=digest, recoverer=lambda request: calls.append(1))
                self.assertEqual(self.durable_bytes(), before)
            with self.assertRaises(Conflict):
                journal.complete_exchange_bitcoin(self.session, HostilePacket(), recoverer=lambda request: calls.append(1))
            with self.assertRaises(InvalidInput):
                journal.complete_exchange_bitcoin(self.session, self.old_packet, recoverer=None)
            self.assertEqual(self.durable_bytes(), before)
            self.assertEqual(self.budget(journal)["consumed"], 1)
        self.assertEqual((calls, equalities), ([], []))

    def test_failed_false_or_malformed_worker_results_each_consume_one_attempt(self):
        def fail(_):
            raise RuntimeError("synthetic failure")
        def interrupt(_):
            raise KeyboardInterrupt("synthetic interruption")
        def timeout(_):
            raise TimeoutError("synthetic timeout")
        callbacks = (fail, interrupt, timeout, lambda _: None,
                     lambda request: dict(completion_accepted(request), valid=False),
                     lambda request: dict(completion_accepted(request), request_digest_hex="99" * 32))
        with self.open() as journal:
            self.ready(journal, limit=len(callbacks))
            for count, callback in enumerate(callbacks, 1):
                self.reject(journal, recoverer=callback)
                self.assertEqual(self.budget(journal)["consumed"], count)
                self.assertEqual(self.disk_budget(), self.budget(journal))
            with self.assertRaises(RecoveryExhausted):
                journal.complete_exchange_bitcoin(self.session, recoverer=completion_accepted)

    def test_ordinary_worker_observes_candidate_exposure_and_durable_debit(self):
        events = []
        with self.open(hook=events.append) as journal:
            self.ready(journal, limit=1)
            events.clear()
            def worker(request):
                self.assertEqual(self.budget(journal), {"limit": 1, "consumed": 1})
                self.assertEqual(self.disk_budget(), self.budget(journal))
                self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                self.assertEqual(journal.get_exchange(self.session)["zenon_completion_packet_hex"], self.packet.hex())
                self.assertEqual(events[-2:], ["after_bob_recovery_admission_commit", "after_bob_observation_commit"])
                return completion_accepted(request)
            journal.complete_exchange_bitcoin(self.session, self.packet, recoverer=worker)
            self.assertEqual(self.budget(journal)["consumed"], 1)

    def test_reconciliation_worker_observes_durable_debit_with_old_artifacts_intact(self):
        events = []
        with self.open(hook=events.append) as journal:
            self.ready(journal, limit=2)
            self.reject(journal)
            original = journal.get_exchange(self.session)
            events.clear()
            def worker(request):
                self.assertEqual(self.budget(journal), {"limit": 2, "consumed": 2})
                self.assertEqual(self.disk_budget(), self.budget(journal))
                self.assertEqual(journal.get_exchange(self.session), original)
                self.assertEqual(events[-1], "after_bob_recovery_admission_commit")
                return completion_accepted(request)
            self.reconcile(journal, recoverer=worker)
            self.assertEqual(self.budget(journal)["consumed"], 2)

    def test_exact_recorded_replays_are_free_when_allowance_is_exhausted(self):
        with self.open() as journal:
            release = self.ready(journal, limit=1)
            output = journal.complete_exchange_bitcoin(self.session, self.packet, recoverer=completion_accepted)
            before = self.durable_bytes()
            for _ in range(3):
                self.assertEqual(journal.replay_exchange_bitcoin(self.session), output)
                self.assertEqual(journal.replay_exchange_release(self.session), release)
                self.assertEqual(self.budget(journal), {"limit": 1, "consumed": 1})
                self.assertEqual(self.durable_bytes(), before)

    def test_owner_reentrancy_and_foreign_thread_cannot_spend_extra_attempts(self):
        errors = []
        with self.open() as journal:
            self.ready(journal, limit=1)
            def worker(request):
                for action in (journal.close, lambda: journal.complete_exchange_bitcoin(self.session, recoverer=completion_accepted),
                               lambda: self.reconcile(journal), lambda: journal.observe(self.session, "91" * 32)):
                    with self.assertRaises(Conflict):
                        action()
                with self.assertRaises(Busy):
                    self.open()
                def foreign():
                    try:
                        journal.complete_exchange_bitcoin(self.session, recoverer=completion_accepted)
                    except OwnershipError:
                        errors.append(1)
                thread = threading.Thread(target=foreign)
                thread.start()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(self.budget(journal)["consumed"], 1)
                return completion_accepted(request)
            journal.complete_exchange_bitcoin(self.session, self.packet, recoverer=worker)
        self.assertEqual(errors, [1])

    def test_persistence_rejects_counter_rollback_limit_change_and_session_removal(self):
        with self.open() as journal:
            self.ready(journal, limit=5)
            self.reject(journal)
            self.reject(journal)
            before = self.durable_bytes()
            def remove_managed_mode(state):
                state["sessions"][self.session].update(
                    exchange=None, recovery_budget=None, possible_exposure=False,
                    bitcoin_binding_digest=None, zenon_binding_digest=None,
                    signing_rounds={}, signing_round_nonces={},
                )
            for change in (lambda state: state["sessions"][self.session]["recovery_budget"].update(consumed=1),
                           lambda state: state["sessions"][self.session]["recovery_budget"].update(consumed=4),
                           lambda state: state["sessions"][self.session]["recovery_budget"].update(limit=6),
                           lambda state: state["sessions"].pop(self.session), remove_managed_mode):
                changed = copy.deepcopy(journal._state)
                change(changed)
                with self.assertRaises(Conflict):
                    journal._persist(changed)
                self.assertEqual(self.durable_bytes(), before)
            with self.assertRaises(Conflict):
                journal.start_exchange(self.session, self.bitcoin, recovery_limit=6)
            copied = journal.get_session(self.session)
            copied["recovery_budget"]["consumed"] = 0
            self.assertEqual(self.budget(journal), {"limit": 5, "consumed": 2})

    def test_resealed_invalid_budget_shapes_types_and_causal_state_quarantine(self):
        with self.open() as journal:
            self.ready(journal, limit=2)
            self.reject(journal)
        saved_db, saved_anchor = self.base / "saved.sqlite3", self.base / "saved.head"
        shutil.copyfile(self.root / "journal.sqlite3", saved_db)
        shutil.copyfile(self.anchor, saved_anchor)
        bad = (None, {}, {"limit": True, "consumed": 1}, {"limit": 65, "consumed": 1},
               {"limit": 2, "consumed": False}, {"limit": 2, "consumed": -1},
               {"limit": 2, "consumed": 3}, {"limit": 2, "consumed": 0},
               {"limit": 2, "consumed": 1, "extra": 1})
        for budget in bad:
            with self.subTest(budget=budget):
                shutil.copyfile(saved_db, self.root / "journal.sqlite3")
                shutil.copyfile(saved_anchor, self.anchor)
                self.rewrite(lambda session: session.update(recovery_budget=budget))
                with self.assertRaises(Quarantined):
                    self.open()
        changes = (lambda session: session.pop("recovery_budget"),
                   lambda session: (session["exchange"].update(zenon_completion_packet_hex=None),
                                    session.update(possible_exposure=False)))
        for change in changes:
            shutil.copyfile(saved_db, self.root / "journal.sqlite3")
            shutil.copyfile(saved_anchor, self.anchor)
            self.rewrite(change)
            with self.assertRaises(Quarantined):
                self.open()
        # A retained candidate and its verified replacement require separate admissions.
        shutil.copyfile(saved_db, self.root / "journal.sqlite3")
        shutil.copyfile(saved_anchor, self.anchor)
        with self.open() as journal:
            self.reconcile(journal)
            self.assertEqual(self.budget(journal)["consumed"], 2)
        self.rewrite(lambda session: session["recovery_budget"].update(consumed=1))
        with self.assertRaises(Quarantined):
            with self.open():
                pass

    def test_resealed_version_five_checkpoint_quarantines_without_migration(self):
        with self.open() as journal:
            self.ready(journal)
        self.rewrite(lambda session: session.pop("recovery_budget"), version=5)
        self.assertEqual(VERSION, 6)
        before = self.durable_bytes()
        with self.assertRaises(Quarantined):
            self.open()
        self.assertEqual(self.durable_bytes(), before)

    def test_matching_snapshot_restore_can_replenish_allowance_and_is_not_detected(self):
        with self.open() as journal:
            self.ready(journal, limit=1)
        saved_db, saved_anchor = self.base / "saved.sqlite3", self.base / "saved.head"
        shutil.copyfile(self.root / "journal.sqlite3", saved_db)
        shutil.copyfile(self.anchor, saved_anchor)
        calls = []
        for attempt in range(2):
            with self.open() as journal:
                self.assertEqual(self.budget(journal)["consumed"], 0)
                self.reject(journal, recoverer=lambda request: calls.append(1))
                with self.assertRaises(RecoveryExhausted):
                    journal.complete_exchange_bitcoin(self.session, recoverer=completion_accepted)
            if attempt == 0:
                shutil.copyfile(saved_db, self.root / "journal.sqlite3")
                shutil.copyfile(saved_anchor, self.anchor)
        self.assertEqual(calls, [1, 1])

    def test_admission_checkpoint_failure_consumes_without_invoking_worker(self):
        def hook(name):
            if name == "after_bob_recovery_admission_commit":
                raise RuntimeError("synthetic admission interruption")
        calls = []
        with self.open(hook=hook) as journal:
            self.ready(journal, limit=1)
            with self.assertRaises(Quarantined):
                journal.complete_exchange_bitcoin(self.session, self.packet, recoverer=lambda request: calls.append(1))
        with self.open() as journal:
            self.assertEqual(self.budget(journal), {"limit": 1, "consumed": 1})
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
            with self.assertRaises(RecoveryExhausted):
                journal.complete_exchange_bitcoin(self.session, recoverer=completion_accepted)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
