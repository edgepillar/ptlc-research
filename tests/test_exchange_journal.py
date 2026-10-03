"""Managed public-artifact exchange persistence, with a synthetic verifier only."""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from offline_session import exchange
from offline_session.journal import (
    Busy, Conflict, InvalidInput, Journal, OutcomeUnknown, OwnershipError,
    Quarantined, VERSION,
)
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round, nonce_commitment,
    reveal_nonce_round, signing_context,
)
from exchange_test_support import accepted as synthetic_verifier, artifacts


def exchange_fixture(*, session_id=None, bitcoin_change=False, repeated_nonces=False):
    """Load public corpus artifacts; no secret scalar or nonce is generated."""
    if session_id is None and not bitcoin_change and not repeated_nonces:
        terms, bitcoin, zenon, bitcoin_bundle, zenon_bundle = artifacts()
        return terms, {"bitcoin": bitcoin, "zenon": zenon}, {"bitcoin": bitcoin_bundle, "zenon": zenon_bundle}
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
    vectors = json.loads((root / "qualification/fixtures/nonce_rounds.json").read_text("ascii"))["vectors"]
    if session_id is not None:
        data["terms"]["session_id"] = session_id
    if bitcoin_change:
        data["bitcoin_binding"]["claim_sighash_hex"] = "99" * 32
    terms = agree_terms(data["terms"])
    bitcoin = bind_bitcoin(terms, data["bitcoin_binding"])
    bindings = {"bitcoin": bitcoin, "zenon": bind_zenon(bitcoin, data["zenon_binding"])}
    contexts, bundles = {}, {}
    for vector in vectors:
        leg, round_id = vector["leg"], vector["round_id_hex"]
        binding = bindings[leg]
        nonces = vectors[0]["public_nonces_hex"] if repeated_nonces else vector["public_nonces_hex"]
        commitments = commit_nonce_round(
            binding, round_id,
            *[nonce_commitment(binding, round_id, role, nonce)
              for role, nonce in zip(("alice", "bob"), nonces)],
        )
        nonce_round = reveal_nonce_round(commitments, *nonces)
        contexts[leg] = signing_context(binding, "bob", leg + "-claim-partial", nonce_round=nonce_round)
        bundles[leg] = {key: copy.deepcopy(vector[key]) for key in (
            "partial_signatures_hex", "adaptor_presignature_hex",
        )}
    return terms, contexts, bundles


class ExchangeJournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ptlc-exchange-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "journal"
        self.anchor = self.base / "head.json"
        self.terms, self.contexts, self.bundles = exchange_fixture()
        self.session = self.terms.session_id

    def open(self, **kwargs):
        return Journal.open(self.root, self.anchor, **kwargs)

    def initialize(self, journal):
        journal.create_session(self.session, self.terms.digest_hex)

    def start(self, journal):
        self.initialize(journal)
        journal.start_exchange(self.session, self.contexts["bitcoin"], recovery_limit=8)

    def bitcoin_retained(self, journal):
        self.start(journal)
        journal.retain_exchange_bitcoin(self.session, self.bundles["bitcoin"], verifier=synthetic_verifier)

    def zenon_bound(self, journal):
        self.bitcoin_retained(journal)
        journal.bind_exchange_zenon(self.session, self.contexts["zenon"])

    def alice_retained(self, journal):
        self.zenon_bound(journal)
        journal.retain_exchange_alice_partial(
            self.session, self.bundles["zenon"]["partial_signatures_hex"][0], verifier=synthetic_verifier,
        )

    def ready(self, journal):
        self.alice_retained(journal)
        journal.retain_exchange_zenon(self.session, self.bundles["zenon"], verifier=synthetic_verifier)

    def test_release_is_persisted_before_return_and_replays_without_verifier(self):
        events = []
        with self.open(hook=events.append) as journal:
            self.ready(journal)
            self.assertEqual(events[-1], "after_exchange_retained")
            self.assertEqual(journal.get_exchange(self.session)["stage"], "ZENON_RETAINED")
            self.assertFalse(journal.get_exchange(self.session)["release_may_have_escaped"])
            released = journal.release_exchange_zenon(self.session)
            self.assertEqual(events[-1], "after_exchange_release_commit")
            self.assertEqual(journal.get_exchange(self.session)["stage"], "RELEASE_RECORDED")
            self.assertTrue(journal.get_exchange(self.session)["release_may_have_escaped"])
            self.assertFalse(journal.get_session(self.session)["possible_exposure"])
            with self.assertRaises(Conflict):
                journal.release_exchange_zenon(self.session)
            self.assertEqual(journal.replay_exchange_release(self.session), released)
        with patch.object(exchange, "retain_zenon", side_effect=AssertionError("recomputed on reload")):
            with self.open() as journal:
                self.assertEqual(journal.replay_exchange_release(self.session), released)
                self.assertTrue(journal.get_exchange(self.session)["release_may_have_escaped"])
                journal.observe(self.session, "41" * 32, reorg=True)
                self.assertTrue(journal.get_exchange(self.session)["release_may_have_escaped"])

    def test_each_intermediate_stage_survives_reopen_with_full_context_and_receipts(self):
        with self.open() as journal:
            self.start(journal)
        stages = [
            ("BITCOIN_BOUND", lambda journal: journal.retain_exchange_bitcoin(
                self.session, self.bundles["bitcoin"], verifier=synthetic_verifier)),
            ("BITCOIN_RETAINED", lambda journal: journal.bind_exchange_zenon(self.session, self.contexts["zenon"])),
            ("ZENON_BOUND", lambda journal: journal.retain_exchange_alice_partial(
                self.session, self.bundles["zenon"]["partial_signatures_hex"][0], verifier=synthetic_verifier)),
            ("ALICE_PARTIAL_RETAINED", lambda journal: journal.retain_exchange_zenon(
                self.session, self.bundles["zenon"], verifier=synthetic_verifier)),
        ]
        for stage, action in stages:
            with self.open() as journal:
                self.assertEqual(journal.get_exchange(self.session)["stage"], stage)
                with self.assertRaises(OutcomeUnknown):
                    journal.replay_exchange_release(self.session)
                action(journal)
        with self.open() as journal:
            state = journal.get_exchange(self.session)
            self.assertEqual(state["stage"], "ZENON_RETAINED")
            self.assertEqual(state["bitcoin_context"], self.contexts["bitcoin"].as_dict())
            self.assertEqual(state["zenon_context"], self.contexts["zenon"].as_dict())
            self.assertEqual(set(state["verification_receipts"]), {
                "bitcoin_bundle", "zenon_alice_partial", "zenon_bundle",
            })

    def test_early_release_and_out_of_order_artifacts_leave_state_unchanged(self):
        with self.open() as journal:
            self.start(journal)
            before = journal.get_session(self.session)
            reject = lambda request: self.fail("verifier must not run out of order")
            actions = [
                lambda: journal.release_exchange_zenon(self.session),
                lambda: journal.bind_exchange_zenon(self.session, self.contexts["zenon"]),
                lambda: journal.retain_exchange_alice_partial(self.session, "01" * 32, verifier=reject),
                lambda: journal.retain_exchange_zenon(self.session, self.bundles["zenon"], verifier=reject),
                lambda: journal.start_exchange(self.session, self.contexts["bitcoin"], recovery_limit=8),
            ]
            for action in actions:
                with self.assertRaises(Conflict):
                    action()
                self.assertEqual(journal.get_session(self.session), before)

    def test_rejected_or_failed_verifier_never_commits_a_retention(self):
        with self.open() as journal:
            self.start(journal)
            before = journal.get_session(self.session)

            def rejected(request):
                result = synthetic_verifier(request)
                result["valid"] = False
                return result

            def failed(request):
                raise RuntimeError("untrusted supplied detail")

            def interrupted(request):
                raise KeyboardInterrupt("synthetic verifier interruption")

            for verifier in (rejected, failed, interrupted, lambda request: True,
                             lambda request: dict(synthetic_verifier(request), request_digest_hex="99" * 32)):
                with self.assertRaisesRegex(Conflict, "^managed exchange transition rejected$"):
                    journal.retain_exchange_bitcoin(self.session, self.bundles["bitcoin"], verifier=verifier)
                self.assertEqual(journal.get_session(self.session), before)
            journal.retain_exchange_bitcoin(self.session, self.bundles["bitcoin"], verifier=synthetic_verifier)
            self.assertEqual(journal.get_exchange(self.session)["stage"], "BITCOIN_RETAINED")

    def test_verifier_guard_blocks_mutation_close_and_release_but_allows_copied_reads(self):
        with self.open() as journal:
            self.start(journal)

            def verifier(request):
                for action in (
                    journal.close,
                    lambda: journal.observe(self.session, "42" * 32),
                    lambda: journal.create_session("91" * 32, "92" * 32),
                    lambda: journal.release_exchange_zenon(self.session),
                    lambda: journal.retain_exchange_bitcoin(self.session, self.bundles["bitcoin"], verifier=synthetic_verifier),
                ):
                    with self.assertRaises(Conflict):
                        action()
                snapshot = journal.get_exchange(self.session)
                snapshot["stage"] = "RELEASE_RECORDED"
                self.assertEqual(journal.get_exchange(self.session)["stage"], "BITCOIN_BOUND")
                with self.assertRaises(Busy):
                    self.open()
                return synthetic_verifier(request)

            journal.retain_exchange_bitcoin(self.session, self.bundles["bitcoin"], verifier=verifier)

    def test_foreign_thread_cannot_close_or_read_during_verification(self):
        failures = []
        with self.open() as journal:
            self.start(journal)

            def verifier(request):
                def foreign():
                    for action in (journal.close, lambda: journal.get_exchange(self.session),
                                   lambda: journal.release_exchange_zenon(self.session)):
                        try:
                            action()
                        except OwnershipError:
                            failures.append("owner")

                thread = threading.Thread(target=foreign)
                thread.start()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                with self.assertRaises(Busy):
                    self.open()
                return synthetic_verifier(request)

            journal.retain_exchange_bitcoin(self.session, self.bundles["bitcoin"], verifier=verifier)
            self.assertEqual(failures, ["owner"] * 3)

    def test_managed_session_blocks_all_generic_operation_routes(self):
        with self.open() as journal:
            self.start(journal)
            actions = [
                lambda: journal.reserve(self.session, "31" * 32, self.contexts["bitcoin"], "32" * 32),
                lambda: journal.produce_once(self.session, "31" * 32, expected_context=self.contexts["bitcoin"],
                                            callback=lambda: self.fail("generic callback bypass")),
                lambda: journal.replay(self.session, "31" * 32, expected_context=self.contexts["bitcoin"]),
            ]
            for action in actions:
                with self.assertRaisesRegex(Conflict, "managed exchange excludes generic operations"):
                    action()
            self.assertEqual(journal.get_session(self.session)["operations"], {})

    def test_existing_generic_ownership_cannot_convert_to_managed_exchange(self):
        with self.open() as journal:
            self.initialize(journal)
            journal.reserve(self.session, "31" * 32, self.contexts["bitcoin"], "32" * 32)
            with self.assertRaises(Conflict):
                journal.start_exchange(self.session, self.contexts["bitcoin"], recovery_limit=8)
        with self.open() as journal:
            with self.assertRaises(Conflict):
                journal.start_exchange(self.session, self.contexts["bitcoin"], recovery_limit=8)
            self.assertIsNone(journal.get_session(self.session)["exchange"])

    def test_managed_start_requires_dynamic_bob_bitcoin_context(self):
        from offline_session.transcript import _restore

        dynamic = self.contexts["bitcoin"].as_dict()
        binding = _restore(dynamic["binding"])
        nonce_round = _restore(dynamic["nonce_round"])
        bad = [
            self.contexts["zenon"],
            signing_context(binding, "bob", "bitcoin-claim-partial"),
            signing_context(binding, "alice", "bitcoin-claim-partial", nonce_round=nonce_round),
            signing_context(binding, "bob", "bitcoin-claim-complete", nonce_round=nonce_round),
        ]
        with self.open() as journal:
            self.initialize(journal)
            for context in bad:
                with self.assertRaises((Conflict, InvalidInput)):
                    journal.start_exchange(self.session, context, recovery_limit=8)
                self.assertIsNone(journal.get_session(self.session)["exchange"])
                self.assertEqual(journal.get_session(self.session)["signing_rounds"], {})

    def test_changed_bitcoin_predecessor_cannot_enter_zenon_stage(self):
        _, changed, _ = exchange_fixture(bitcoin_change=True)
        with self.open() as journal:
            self.bitcoin_retained(journal)
            before = journal.get_session(self.session)
            with self.assertRaisesRegex(Conflict, "Bitcoin stage mismatch"):
                journal.bind_exchange_zenon(self.session, changed["zenon"])
            self.assertEqual(journal.get_session(self.session), before)

    def test_public_nonce_history_is_shared_across_managed_and_generic_sessions(self):
        other_terms, other, _ = exchange_fixture(session_id="81" * 32)
        for first_managed in (False, True):
            with self.subTest(first_managed=first_managed):
                root = self.base / str(first_managed)
                anchor = self.base / (str(first_managed) + ".head")
                with Journal.open(root, anchor) as journal:
                    self.initialize(journal)
                    if first_managed:
                        journal.start_exchange(self.session, self.contexts["bitcoin"], recovery_limit=8)
                    else:
                        journal.reserve(self.session, "31" * 32, self.contexts["bitcoin"], "32" * 32)
                    journal.create_session(other_terms.session_id, other_terms.digest_hex)
                with Journal.open(root, anchor) as journal:
                    with self.assertRaisesRegex(Conflict, "public nonce encoding is already pinned"):
                        if first_managed:
                            journal.reserve(other_terms.session_id, "33" * 32, other["bitcoin"], "34" * 32)
                        else:
                            journal.start_exchange(other_terms.session_id, other["bitcoin"], recovery_limit=8)

    def test_repeated_nonce_between_managed_legs_is_rejected(self):
        _, repeated, _ = exchange_fixture(repeated_nonces=True)
        with self.open() as journal:
            self.bitcoin_retained(journal)
            with self.assertRaisesRegex(Conflict, "public nonce encoding is already pinned"):
                journal.bind_exchange_zenon(self.session, repeated["zenon"])
            self.assertIsNone(journal.get_session(self.session)["zenon_binding_digest"])

    def test_post_retention_checkpoint_failure_reopens_retained_without_release(self):
        def hook(name):
            if name == "after_exchange_retained":
                raise RuntimeError("synthetic interruption")

        with self.open(hook=hook) as journal:
            self.alice_retained(journal)
            with self.assertRaises(Quarantined):
                journal.retain_exchange_zenon(self.session, self.bundles["zenon"], verifier=synthetic_verifier)
            with self.assertRaises(Quarantined):
                journal.release_exchange_zenon(self.session)
        with self.open() as journal:
            self.assertEqual(journal.get_exchange(self.session)["stage"], "ZENON_RETAINED")
            self.assertFalse(journal.get_exchange(self.session)["release_may_have_escaped"])
            with self.assertRaises(OutcomeUnknown):
                journal.replay_exchange_release(self.session)
            self.assertIsInstance(journal.release_exchange_zenon(self.session), bytes)

    def test_post_release_checkpoint_failure_preserves_possible_release_and_exact_bytes(self):
        expected = []

        def hook(name):
            if name == "after_exchange_release_commit":
                expected.append(journal.replay_exchange_release(self.session))
                raise RuntimeError("synthetic interruption")

        with self.open(hook=hook) as journal:
            self.ready(journal)
            with self.assertRaises(Quarantined):
                journal.release_exchange_zenon(self.session)
            with self.assertRaises(Quarantined):
                journal.replay_exchange_release(self.session)
        with self.open() as journal:
            self.assertTrue(journal.get_exchange(self.session)["release_may_have_escaped"])
            self.assertEqual(journal.replay_exchange_release(self.session), expected[0])
            with self.assertRaises(Conflict):
                journal.release_exchange_zenon(self.session)

    def _rewrite(self, transform, version=VERSION):
        """Checksummed local mutations test semantic checks, not host resistance."""
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
            self.anchor.write_bytes(canonical({"version": version, "lineage": lineage,
                                               "sequence": sequence, "digest": digest}))
        finally:
            connection.close()

    def test_reload_checks_managed_context_pins_and_historical_receipts(self):
        alterations = {
            "bitcoin-pin": lambda session: session.update(bitcoin_binding_digest="98" * 32),
            "zenon-pin": lambda session: session.update(zenon_binding_digest="98" * 32),
            "round-pin": lambda session: session["signing_rounds"].update(zenon="98" * 32),
            "nonce-pin": lambda session: session["signing_round_nonces"].update(zenon=["98" * 32, "97" * 32]),
            "terms": lambda session: session.update(terms_digest="98" * 32),
            "orphan": lambda session: session["signing_rounds"].pop("zenon"),
            "receipt": lambda session: session["exchange"]["verification_receipts"].update(zenon_bundle="98" * 32),
            "stage": lambda session: session["exchange"].update(stage="RELEASE_RECORDED"),
        }
        for name, alteration in alterations.items():
            with self.subTest(alteration=name):
                self.root = self.base / name
                self.anchor = self.base / (name + ".head")
                with self.open() as journal:
                    self.ready(journal)
                self._rewrite(alteration)
                with self.assertRaises(Quarantined):
                    self.open()

    def test_version_two_checkpoint_is_quarantined_without_migration(self):
        with self.open() as journal:
            self.initialize(journal)
        self._rewrite(lambda session: session.pop("exchange"), version=2)
        db = self.root / "journal.sqlite3"
        before = (db.read_bytes(), self.anchor.read_bytes())
        with self.assertRaises(Quarantined):
            self.open()
        self.assertEqual((db.read_bytes(), self.anchor.read_bytes()), before)

    def test_one_sided_release_rollback_quarantines(self):
        with self.open() as journal:
            self.ready(journal)
        old_db = self.base / "old.sqlite3"
        shutil.copyfile(self.root / "journal.sqlite3", old_db)
        with self.open() as journal:
            journal.release_exchange_zenon(self.session)
        shutil.copyfile(old_db, self.root / "journal.sqlite3")
        with self.assertRaises(Quarantined):
            self.open()


if __name__ == "__main__":
    unittest.main()
