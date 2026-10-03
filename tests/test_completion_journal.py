"""Durable completion ownership with fixed public fixtures and fake verifiers."""

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
    Busy, Conflict, InvalidInput, Journal, OutcomeUnknown, OwnershipError,
    Quarantined, VERSION,
)
from exchange_test_support import accepted, artifacts, prepare
from completion_test_support import alice_packet, bob_release, completion_accepted, final_signatures


class CompletionJournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ptlc-completion-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "state"
        self.anchor = self.base / "head.json"
        self.terms, self.bitcoin, self.zenon, self.btc_bundle, self.znn_bundle = artifacts()
        self.session = self.terms.session_id
        self.alice = completion.recontext(self.zenon, "alice", "zenon-claim-partial")
        self.partial = self.znn_bundle["partial_signatures_hex"][0]
        zenon, bitcoin = final_signatures()
        self.signatures = {"zenon": zenon, "bitcoin": bitcoin}
        self.release = bob_release()

    def finish(self, request):
        """Fake local acceptance; these tests establish no cryptographic validity."""
        return completion_accepted(request)

    def packet(self):
        return alice_packet()

    def open(self, **kwargs):
        return Journal.open(self.root, self.anchor, **kwargs)

    def start_alice(self, journal):
        journal.create_session(self.session, self.terms.digest_hex)
        journal.start_alice(self.session, self.alice, self.partial, verifier=accepted)

    def ready_alice(self, journal):
        self.start_alice(journal)
        journal.accept_alice_release(self.session, self.release, verifier=accepted)

    def ready_bob(self, journal):
        self.assertEqual(prepare(journal), self.session)
        self.assertEqual(journal.release_exchange_zenon(self.session), self.release)

    def test_alice_consumption_precedes_producer_and_verifier_and_output_replays(self):
        calls, events = [], []
        with self.open(hook=events.append) as journal:
            self.ready_alice(journal)
            self.assertFalse(journal.get_session(self.session)["possible_exposure"])

            def producer():
                calls.append("producer")
                self.assertEqual(journal.get_alice(self.session)["stage"], "COMPLETION_CONSUMED")
                self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                return self.signatures["zenon"]

            def verifier(request):
                calls.append("verifier")
                self.assertEqual(journal.get_alice(self.session)["stage"], "COMPLETION_CONSUMED")
                self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                return self.finish(request)

            packet = journal.complete_alice(self.session, producer=producer, verifier=verifier)
            self.assertEqual(packet, self.packet())
            self.assertEqual(events[-1], "after_alice_output_commit")
            self.assertLess(events.index("after_alice_consume"), events.index("after_alice_producer"))
            self.assertEqual(calls, ["producer", "verifier"])
            self.assertEqual(journal.replay_alice_completion(self.session), packet)
            with self.assertRaises(OutcomeUnknown):
                journal.complete_alice(self.session, producer=producer, verifier=verifier)
            journal.observe(self.session, "91" * 32, reorg=True)
        with self.open() as journal:
            self.assertEqual(journal.replay_alice_completion(self.session), packet)
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
            self.assertEqual(journal.get_alice(self.session)["stage"], "COMPLETION_RECORDED")
            self.assertEqual(calls, ["producer", "verifier"])

    def test_alice_producer_exception_is_sealed_and_reopens_unknown(self):
        calls = []

        def producer():
            calls.append(1)
            raise KeyboardInterrupt("synthetic private callback detail")

        with self.open() as journal:
            self.ready_alice(journal)
            with self.assertRaisesRegex(OutcomeUnknown, "^Alice producer outcome is unknown$"):
                journal.complete_alice(self.session, producer=producer, verifier=lambda request: self.fail("verifier ran"))
            self.assertEqual(journal.get_alice(self.session)["stage"], "COMPLETION_CONSUMED")
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
            with self.assertRaises(OutcomeUnknown):
                journal.complete_alice(self.session, producer=producer, verifier=self.finish)
        with self.open() as journal:
            self.assertEqual(journal.get_alice(self.session)["stage"], "OUTCOME_UNKNOWN")
            self.assertTrue(journal.get_alice(self.session)["possible_exposure"])
            with self.assertRaises(OutcomeUnknown):
                journal.complete_alice(self.session, producer=producer, verifier=self.finish)
            with self.assertRaises(OutcomeUnknown):
                journal.replay_alice_completion(self.session)
        self.assertEqual(calls, [1])

    def test_bad_output_or_final_verifier_failure_burns_completion_ownership(self):
        def failed(request):
            raise RuntimeError("synthetic verifier detail")

        cases = (
            (b"", self.finish), (b"x" * 65, self.finish), ("not bytes", self.finish),
            (self.signatures["zenon"], failed),
            (self.signatures["zenon"], lambda request: dict(self.finish(request), valid=False)),
            (self.signatures["zenon"], lambda request: dict(self.finish(request), request_digest_hex="99" * 32)),
        )
        for number, (output, verifier) in enumerate(cases):
            with self.subTest(number=number):
                self.root, self.anchor = self.base / str(number), self.base / (str(number) + ".head")
                with self.open() as journal:
                    self.ready_alice(journal)
                    with self.assertRaises(OutcomeUnknown):
                        journal.complete_alice(self.session, producer=lambda: output, verifier=verifier)
                    self.assertEqual(journal.get_alice(self.session)["stage"], "COMPLETION_CONSUMED")
                    self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                    with self.assertRaises(OutcomeUnknown):
                        journal.complete_alice(self.session, producer=lambda: self.fail("producer repeated"), verifier=self.finish)
                with self.open() as journal:
                    self.assertEqual(journal.get_alice(self.session)["stage"], "OUTCOME_UNKNOWN")

    def test_alice_callbacks_cannot_mutate_close_or_escape_owner_checks(self):
        failures = []
        with self.open() as journal:
            self.ready_alice(journal)

            def check_guards():
                for action in (
                    journal.close,
                    lambda: journal.observe(self.session, "91" * 32),
                    lambda: journal.complete_alice(self.session, producer=lambda: b"", verifier=self.finish),
                    lambda: journal.start_exchange(self.session, self.bitcoin, recovery_limit=8),
                    lambda: journal.accept_alice_release(self.session, self.release, verifier=accepted),
                ):
                    with self.assertRaises(Conflict):
                        action()
                snapshot = journal.get_alice(self.session)
                snapshot["stage"] = "COMPLETION_RECORDED"
                self.assertEqual(journal.get_alice(self.session)["stage"], "COMPLETION_CONSUMED")
                with self.assertRaises(Busy):
                    self.open()

                def foreign():
                    for action in (journal.close, lambda: journal.get_alice(self.session)):
                        try:
                            action()
                        except OwnershipError:
                            failures.append(1)

                thread = threading.Thread(target=foreign)
                thread.start()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

            def producer():
                check_guards()
                return self.signatures["zenon"]

            def verifier(request):
                check_guards()
                return self.finish(request)

            journal.complete_alice(self.session, producer=producer, verifier=verifier)
            self.assertEqual(failures, [1] * 4)

    def test_invalid_adapter_or_early_call_does_not_consume_alice(self):
        with self.open() as journal:
            self.start_alice(journal)
            with self.assertRaises(OutcomeUnknown):
                journal.complete_alice(self.session, producer=lambda: self.fail("early producer"), verifier=self.finish)
            self.assertFalse(journal.get_session(self.session)["possible_exposure"])
            journal.accept_alice_release(self.session, self.release, verifier=accepted)
            for producer, verifier in ((None, self.finish), (lambda: b"", None)):
                with self.assertRaises(InvalidInput):
                    journal.complete_alice(self.session, producer=producer, verifier=verifier)
                self.assertEqual(journal.get_alice(self.session)["stage"], "PRESIGNATURE_RETAINED")
                self.assertFalse(journal.get_session(self.session)["possible_exposure"])

    def test_rejected_alice_start_and_release_leave_prior_state_unchanged(self):
        reject = lambda request: dict(accepted(request), valid=False)
        with self.open() as journal:
            journal.create_session(self.session, self.terms.digest_hex)
            before = journal.get_session(self.session)
            with self.assertRaises(Conflict):
                journal.start_alice(self.session, self.alice, self.partial, verifier=reject)
            self.assertEqual(journal.get_session(self.session), before)
            journal.start_alice(self.session, self.alice, self.partial, verifier=accepted)
            before = journal.get_session(self.session)
            for packet, verifier in ((self.release + b"\n", accepted), (self.release, reject)):
                with self.assertRaises(Conflict):
                    journal.accept_alice_release(self.session, packet, verifier=verifier)
                self.assertEqual(journal.get_session(self.session), before)
            journal.accept_alice_release(self.session, self.release, verifier=accepted)
            self.assertFalse(journal.get_session(self.session)["possible_exposure"])

    def test_alice_bob_and_generic_flows_are_mutually_exclusive(self):
        for mode in ("alice", "bob", "generic"):
            with self.subTest(mode=mode):
                self.root, self.anchor = self.base / mode, self.base / (mode + ".head")
                with self.open() as journal:
                    journal.create_session(self.session, self.terms.digest_hex)
                    if mode == "alice":
                        journal.start_alice(self.session, self.alice, self.partial, verifier=accepted)
                    elif mode == "bob":
                        journal.start_exchange(self.session, self.bitcoin, recovery_limit=8)
                    else:
                        journal.reserve(self.session, "31" * 32, self.alice, "32" * 32)
                    for other in ({"alice", "bob", "generic"} - {mode}):
                        with self.assertRaises(Conflict):
                            if other == "alice":
                                journal.start_alice(self.session, self.alice, self.partial, verifier=accepted)
                            elif other == "bob":
                                journal.start_exchange(self.session, self.bitcoin, recovery_limit=8)
                            else:
                                journal.reserve(self.session, "33" * 32, self.alice, "34" * 32)
                    if mode == "alice":
                        with self.assertRaises(Conflict):
                            journal.produce_once(self.session, "31" * 32, expected_context=self.alice,
                                                 callback=lambda: self.fail("generic producer bypass"))
                        with self.assertRaises(Conflict):
                            journal.replay(self.session, "31" * 32, expected_context=self.alice)

    def test_alice_checkpoint_interruptions_preserve_unknown_or_exact_output(self):
        for checkpoint in ("after_alice_consume", "after_alice_producer", "after_alice_output_commit"):
            with self.subTest(checkpoint=checkpoint):
                self.root, self.anchor = self.base / checkpoint, self.base / (checkpoint + ".head")
                calls = []

                def hook(name):
                    if name == checkpoint:
                        raise RuntimeError("synthetic checkpoint interruption")

                with self.open(hook=hook) as journal:
                    self.ready_alice(journal)
                    with self.assertRaises(Quarantined):
                        journal.complete_alice(self.session, producer=lambda: calls.append(1) or self.signatures["zenon"],
                                               verifier=self.finish)
                    with self.assertRaises(Quarantined):
                        journal.get_alice(self.session)
                with self.open() as journal:
                    self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                    if checkpoint == "after_alice_output_commit":
                        self.assertEqual(journal.get_alice(self.session)["stage"], "COMPLETION_RECORDED")
                        self.assertEqual(journal.replay_alice_completion(self.session), self.packet())
                    else:
                        self.assertEqual(journal.get_alice(self.session)["stage"], "OUTCOME_UNKNOWN")
                        with self.assertRaises(OutcomeUnknown):
                            journal.replay_alice_completion(self.session)
                    with self.assertRaises(OutcomeUnknown):
                        journal.complete_alice(self.session, producer=lambda: self.fail("producer repeated"), verifier=self.finish)
                self.assertEqual(len(calls), 0 if checkpoint == "after_alice_consume" else 1)

    def test_bob_records_observation_before_recoverer_and_replays_exact_output(self):
        calls, events = [], []
        with self.open(hook=events.append) as journal:
            self.ready_bob(journal)

            def recoverer(request):
                calls.append(1)
                self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                self.assertEqual(journal.get_exchange(self.session)["stage"], "RELEASE_RECORDED")
                self.assertEqual(journal.get_exchange(self.session)["zenon_completion_packet_hex"], self.packet().hex())
                return self.finish(request)

            packet = journal.complete_exchange_bitcoin(self.session, self.packet(), recoverer=recoverer)
            self.assertEqual(events[-1], "after_bitcoin_completion_commit")
            self.assertEqual(journal.get_exchange(self.session)["zenon_completion_packet_hex"], self.packet().hex())
            self.assertEqual(journal.replay_exchange_bitcoin(self.session), packet)
            with self.assertRaises(Conflict):
                journal.complete_exchange_bitcoin(self.session, self.packet(), recoverer=recoverer)
            self.assertEqual(journal.replay_exchange_release(self.session), self.release)
        with self.open() as journal:
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
            self.assertEqual(journal.get_exchange(self.session)["stage"], "BTC_COMPLETION_RECORDED")
            self.assertEqual(journal.replay_exchange_bitcoin(self.session), packet)
        self.assertEqual(calls, [1])

    def test_bob_rejected_well_bound_observation_keeps_exposure_but_no_output(self):
        def failed(request):
            raise KeyboardInterrupt("synthetic recovery detail")

        with self.open() as journal:
            self.ready_bob(journal)
            with self.assertRaisesRegex(Conflict, "^Bitcoin completion verification rejected$"):
                journal.complete_exchange_bitcoin(self.session, self.packet(), recoverer=failed)
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
            self.assertEqual(journal.get_exchange(self.session)["stage"], "RELEASE_RECORDED")
            self.assertEqual(journal.get_exchange(self.session)["zenon_completion_packet_hex"], self.packet().hex())
            with self.assertRaises(OutcomeUnknown):
                journal.replay_exchange_bitcoin(self.session)
        with self.open() as journal:
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
            journal.observe(self.session, "91" * 32, reorg=True)
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
            changed = json.loads(self.packet())
            changed["signature_hex"] = "99" * 64
            with self.assertRaises(Conflict):
                journal.complete_exchange_bitcoin(self.session, exchange.canonical(changed),
                                                  recoverer=lambda request: self.fail("changed observation reached callback"))
            self.assertIsInstance(journal.complete_exchange_bitcoin(self.session, recoverer=self.finish), bytes)

    def test_bob_malformed_packet_and_noncallable_adapter_do_not_mark_exposure(self):
        with self.open() as journal:
            self.ready_bob(journal)
            before = journal.get_session(self.session)
            for packet in (None, b"{}", self.packet() + b"\n", self.packet().decode("ascii")):
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(self.session, packet, recoverer=lambda request: self.fail("bad packet callback"))
                self.assertEqual(journal.get_session(self.session), before)
            with self.assertRaises(InvalidInput):
                journal.complete_exchange_bitcoin(self.session, self.packet(), recoverer=None)
            self.assertEqual(journal.get_session(self.session), before)

    def test_bob_recoverer_guard_covers_reads_mutation_and_close(self):
        with self.open() as journal:
            self.ready_bob(journal)

            def recoverer(request):
                for action in (journal.close, lambda: journal.observe(self.session, "92" * 32),
                               lambda: journal.complete_exchange_bitcoin(self.session, self.packet(), recoverer=self.finish)):
                    with self.assertRaises(Conflict):
                        action()
                self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                with self.assertRaises(Busy):
                    self.open()
                return self.finish(request)

            journal.complete_exchange_bitcoin(self.session, self.packet(), recoverer=recoverer)

    def test_bob_checkpoint_interruptions_keep_observation_or_exact_output(self):
        for checkpoint in ("after_bob_observation_commit", "after_bitcoin_recoverer", "after_bitcoin_completion_commit"):
            with self.subTest(checkpoint=checkpoint):
                self.root, self.anchor = self.base / checkpoint, self.base / (checkpoint + ".head")
                calls = []

                def hook(name):
                    if name == checkpoint:
                        raise RuntimeError("synthetic completion interruption")

                with self.open(hook=hook) as journal:
                    self.ready_bob(journal)
                    with self.assertRaises(Quarantined):
                        journal.complete_exchange_bitcoin(self.session, self.packet(),
                                                          recoverer=lambda request: calls.append(1) or self.finish(request))
                with self.open() as journal:
                    self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                    if checkpoint == "after_bitcoin_completion_commit":
                        self.assertEqual(journal.get_exchange(self.session)["stage"], "BTC_COMPLETION_RECORDED")
                        self.assertIsInstance(journal.replay_exchange_bitcoin(self.session), bytes)
                    else:
                        self.assertEqual(journal.get_exchange(self.session)["stage"], "RELEASE_RECORDED")
                        self.assertEqual(journal.get_exchange(self.session)["zenon_completion_packet_hex"], self.packet().hex())
                        with self.assertRaises(OutcomeUnknown):
                            journal.replay_exchange_bitcoin(self.session)
                        journal.complete_exchange_bitcoin(self.session, recoverer=self.finish)
                self.assertEqual(len(calls), int(checkpoint != "after_bob_observation_commit"))

    def _rewrite(self, transform, version=VERSION):
        """Reseal synthetic state to test structural consistency, not host security."""
        connection = sqlite3.connect(str(self.root / "journal.sqlite3"))
        try:
            lineage, sequence, raw = connection.execute("SELECT lineage, sequence, state_json FROM checkpoint").fetchone()
            state = json.loads(raw)
            transform(state["sessions"][self.session])
            canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            material = {"version": version, "lineage": lineage, "sequence": sequence, "state": state}
            digest = hashlib.sha256(("ptlc-offline-journal-v" + str(version)).encode("ascii") + b"\x00" + canonical(material)).hexdigest()
            connection.execute("UPDATE checkpoint SET version=?, state_json=?, digest=?",
                               (version, canonical(state).decode("ascii"), digest))
            connection.commit()
            self.anchor.write_bytes(canonical({"version": version, "lineage": lineage, "sequence": sequence, "digest": digest}))
        finally:
            connection.close()

    def test_reload_rejects_alice_exposure_pin_and_output_contradictions(self):
        changes = {
            "exposure": lambda state: state.update(possible_exposure=False),
            "alice-exposure": lambda state: state["alice"].update(possible_exposure=False),
            "binding": lambda state: state.update(zenon_binding_digest="98" * 32),
            "round": lambda state: state["signing_rounds"].update(zenon="98" * 32),
            "nonce": lambda state: state["signing_round_nonces"].update(zenon=["98" * 32, "97" * 32]),
            "receipt": lambda state: state["alice"]["verification_receipts"].update(zenon_completion="98" * 32),
            "output": lambda state: state["alice"].update(completion_packet_hex="00"),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                self.root, self.anchor = self.base / name, self.base / (name + ".head")
                with self.open() as journal:
                    self.ready_alice(journal)
                    journal.complete_alice(self.session, producer=lambda: self.signatures["zenon"], verifier=self.finish)
                self._rewrite(change)
                with self.assertRaises(Quarantined):
                    self.open()

    def test_reload_requires_bob_completed_observation_and_bound_output(self):
        changes = {
            "exposure": lambda state: state.update(possible_exposure=False),
            "receipt": lambda state: state["exchange"].update(completion_receipt_hex="98" * 32),
            "output": lambda state: state["exchange"].update(bitcoin_completion_packet_hex="00"),
            "observation": lambda state: state["exchange"].update(zenon_completion_packet_hex="00"),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                self.root, self.anchor = self.base / name, self.base / (name + ".head")
                with self.open() as journal:
                    self.ready_bob(journal)
                    journal.complete_exchange_bitcoin(self.session, self.packet(), recoverer=self.finish)
                self._rewrite(change)
                with self.assertRaises(Quarantined):
                    self.open()

    def test_version_three_checkpoint_is_quarantined_without_migration(self):
        with self.open() as journal:
            journal.create_session(self.session, self.terms.digest_hex)
        self._rewrite(lambda state: state.pop("alice"), version=3)
        db = self.root / "journal.sqlite3"
        before = (db.read_bytes(), self.anchor.read_bytes())
        with self.assertRaises(Quarantined):
            self.open()
        self.assertEqual((db.read_bytes(), self.anchor.read_bytes()), before)

    def test_restoring_both_alice_copies_can_repeat_production_and_is_not_detected(self):
        """A matching snapshot restore remains outside this offline owner's proof."""
        with self.open() as journal:
            self.ready_alice(journal)
        db = self.root / "journal.sqlite3"
        saved_db, saved_anchor = self.base / "saved.sqlite3", self.base / "saved.head"
        shutil.copyfile(db, saved_db)
        shutil.copyfile(self.anchor, saved_anchor)
        calls = []
        for attempt in range(2):
            with self.open() as journal:
                self.assertFalse(journal.get_session(self.session)["possible_exposure"])
                journal.complete_alice(self.session, producer=lambda: calls.append(1) or self.signatures["zenon"],
                                       verifier=self.finish)
            if attempt == 0:
                shutil.copyfile(saved_db, db)
                shutil.copyfile(saved_anchor, self.anchor)
        self.assertEqual(calls, [1, 1])


if __name__ == "__main__":
    unittest.main()
