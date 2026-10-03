"""Offline journal state and binding tests using only public synthetic bytes."""

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from offline_session.journal import (
    Busy, Conflict, InvalidInput, Journal, MAX_OUTPUT_BYTES, OutcomeUnknown,
    OwnershipError, Quarantined,
    VERSION,
)
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round, nonce_commitment,
    reveal_nonce_round, signing_context,
)
from session_test_support import NONCE_TAG, OPERATION_ID, PUBLIC_OUTPUT, session_context


def altered_context(*, session_id=None, purpose="zenon-claim-complete", role=None, fee_change=False):
    data = json.loads((Path(__file__).parent / "fixtures" / "session_terms.json").read_text("ascii"))
    if session_id is not None:
        data["terms"]["session_id"] = session_id
    if fee_change:
        data["terms"]["bitcoin"]["claim_output_value_sats"] -= 1
        data["bitcoin_binding"]["claim_output_value_sats"] -= 1
    terms = agree_terms(data["terms"])
    bitcoin = bind_bitcoin(terms, data["bitcoin_binding"])
    binding = bind_zenon(bitcoin, data["zenon_binding"]) if purpose.startswith("zenon-") else bitcoin
    return terms, signing_context(binding, role=role or ("bob" if purpose == "bitcoin-claim-complete" else "alice"), purpose=purpose)


def dynamic_context(*, session_id=None, purpose="zenon-claim-complete", role=None,
                    round_id=None, public_nonces=None):
    """Build public shape-only nonce examples; this helper generates no secrets."""
    data = json.loads((Path(__file__).parent / "fixtures" / "session_terms.json").read_text("ascii"))
    if session_id is not None:
        data["terms"]["session_id"] = session_id
    terms = agree_terms(data["terms"])
    bitcoin = bind_bitcoin(terms, data["bitcoin_binding"])
    zenon = purpose.startswith("zenon-")
    binding = bind_zenon(bitcoin, data["zenon_binding"]) if zenon else bitcoin
    round_id = round_id or ("62" if zenon else "61") * 32
    if public_nonces is None:
        # Existing public signer points are only synthetic encoding inputs here.
        ordered = tuple(data["terms"][leg]["signer_keys_sec1_hex"] for leg in ("bitcoin", "zenon"))
        public_nonces = tuple("".join(reversed(pair) if zenon else pair) for pair in ordered)
    commitments = commit_nonce_round(
        binding, round_id,
        nonce_commitment(binding, round_id, "alice", public_nonces[0]),
        nonce_commitment(binding, round_id, "bob", public_nonces[1]),
    )
    nonce_round = reveal_nonce_round(commitments, *public_nonces)
    role = role or ("bob" if purpose == "bitcoin-claim-complete" else "alice")
    return terms, signing_context(binding, role, purpose, nonce_round=nonce_round)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "mutable"
        self.anchor = self.base / "checkpoint.json"
        self.terms, self.context = session_context()
        self.session = self.terms.session_id

    def open(self, **kwargs):
        return Journal.open(self.root, self.anchor, **kwargs)

    def initialize(self, journal):
        journal.create_session(self.session, self.terms.digest_hex)

    def reserve(self, journal, context=None):
        journal.reserve(self.session, OPERATION_ID, context or self.context, NONCE_TAG)

    def produce(self, journal, callback=lambda: PUBLIC_OUTPUT):
        return journal.produce_once(self.session, OPERATION_ID, expected_context=self.context, callback=callback)

    def test_output_recorded_before_return_and_replayed_after_reopen(self):
        events = []
        with self.open(hook=events.append) as journal:
            self.initialize(journal)
            self.reserve(journal)
            events.clear()
            self.assertEqual(self.produce(journal), PUBLIC_OUTPUT)
            self.assertLess(events.index("after_consume"), events.index("after_callback"))
            self.assertEqual(events[-1], "after_output_commit")
            with self.assertRaises(OutcomeUnknown):
                self.produce(journal, lambda: self.fail("producer invoked twice"))
        with self.open() as journal:
            self.assertEqual(journal.get_operation(self.session, OPERATION_ID)["status"], "OUTPUT_RECORDED")
            self.assertEqual(journal.replay(self.session, OPERATION_ID, expected_context=self.context), PUBLIC_OUTPUT)

    def test_consumption_and_possible_exposure_precede_callback(self):
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal)

            def callback():
                self.assertEqual(journal.get_operation(self.session, OPERATION_ID)["status"], "CONSUMED")
                self.assertTrue(journal.get_session(self.session)["possible_exposure"])
                return PUBLIC_OUTPUT

            self.produce(journal, callback)
            journal.observe(self.session, "51" * 32, reorg=True)
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
        with self.open() as journal:
            self.assertTrue(journal.get_session(self.session)["possible_exposure"])
            self.assertTrue(journal.get_session(self.session)["observations"][0]["reorg"])

    def test_partial_producer_does_not_mark_completion_exposure(self):
        _, partial = session_context("zenon-claim-partial")
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal, partial)
            journal.produce_once(self.session, OPERATION_ID, expected_context=partial, callback=lambda: b"public partial")
            self.assertFalse(journal.get_session(self.session)["possible_exposure"])

    def test_callback_failure_is_not_retryable_and_reopens_unknown(self):
        calls = []

        def failure():
            calls.append(1)
            raise RuntimeError("synthetic callback detail must not be exposed")

        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal)
            with self.assertRaisesRegex(OutcomeUnknown, "^synthetic producer outcome is unknown$"):
                self.produce(journal, failure)
            with self.assertRaises(OutcomeUnknown):
                self.produce(journal, failure)
            with self.assertRaises(Conflict):
                journal.reserve(self.session, "32" * 32, self.context, "43" * 32)
            self.assertEqual(calls, [1])
        with self.open() as journal:
            self.assertEqual(journal.get_operation(self.session, OPERATION_ID)["status"], "OUTCOME_UNKNOWN")
            with self.assertRaises(OutcomeUnknown):
                journal.replay(self.session, OPERATION_ID, expected_context=self.context)

    def test_reserved_operations_retire_on_restart_without_reusing_tag(self):
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal)
        with self.open() as journal:
            self.assertEqual(journal.get_operation(self.session, OPERATION_ID)["status"], "RETIRED")
            with self.assertRaises(OutcomeUnknown):
                self.produce(journal)
            with self.assertRaises(Conflict):
                journal.reserve(self.session, "32" * 32, self.context, "43" * 32)

    def test_global_nonce_tag_is_unique_across_sessions(self):
        other_terms, other_context = altered_context(session_id="12" * 32)
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal)
            journal.create_session(other_terms.session_id, other_terms.digest_hex)
            with self.assertRaises(Conflict):
                journal.reserve(other_terms.session_id, "32" * 32, other_context, NONCE_TAG)

    def test_context_must_match_session_terms_role_and_purpose(self):
        _, changed_terms_context = altered_context(fee_change=True)
        _, partial = session_context("zenon-claim-partial")
        _, other_session = altered_context(session_id="12" * 32)
        with self.open() as journal:
            self.initialize(journal)
            with self.assertRaises(Conflict):
                self.reserve(journal, changed_terms_context)
            with self.assertRaises(Conflict):
                self.reserve(journal, other_session)
            with self.assertRaises(InvalidInput):
                self.reserve(journal, self.terms)
            self.reserve(journal)
            with self.assertRaises(Conflict):
                journal.produce_once(self.session, OPERATION_ID, expected_context=partial, callback=lambda: self.fail("wrong context"))
            self.assertEqual(journal.get_operation(self.session, OPERATION_ID)["status"], "RESERVED")

    def test_same_signing_scope_cannot_change_context_to_retry(self):
        data = json.loads((Path(__file__).parent / "fixtures" / "session_terms.json").read_text("ascii"))
        data["bitcoin_binding"]["claim_sighash_hex"] = "99" * 32
        changed_binding = bind_bitcoin(self.terms, data["bitcoin_binding"])
        changed = signing_context(bind_zenon(changed_binding, data["zenon_binding"]), "alice", "zenon-claim-complete")
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal)
            with self.assertRaises(Conflict):
                journal.reserve(self.session, "32" * 32, changed, "43" * 32)

    def test_distinct_participant_roles_and_purposes_have_distinct_scopes(self):
        _, alice = altered_context(purpose="zenon-claim-partial", role="alice")
        _, bob = altered_context(purpose="zenon-claim-partial", role="bob")
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal, alice)
            journal.reserve(self.session, "32" * 32, bob, "43" * 32)
            self.assertEqual(len(journal.get_session(self.session)["operations"]), 2)

    def test_bitcoin_stage_is_pinned_across_roles_purposes_and_restart(self):
        _, partial = session_context("bitcoin-claim-partial")
        data = json.loads((Path(__file__).parent / "fixtures" / "session_terms.json").read_text("ascii"))
        data["bitcoin_binding"]["funding_txid_hex"] = "77" * 32
        changed_bitcoin = bind_bitcoin(self.terms, data["bitcoin_binding"])
        changed_claim = signing_context(changed_bitcoin, "bob", "bitcoin-claim-complete")
        changed_zenon = signing_context(bind_zenon(changed_bitcoin, data["zenon_binding"]), "alice", "zenon-claim-complete")
        with self.open() as journal:
            self.initialize(journal)
            self.assertIsNone(journal.get_session(self.session)["bitcoin_binding_digest"])
            self.reserve(journal, partial)
            self.assertEqual(journal.get_session(self.session)["bitcoin_binding_digest"], partial.as_dict()["binding_digest_hex"])
            self.assertIsNone(journal.get_session(self.session)["zenon_binding_digest"])
            for context in (changed_claim, changed_zenon):
                with self.assertRaisesRegex(Conflict, "Bitcoin stage mismatch"):
                    journal.reserve(self.session, "32" * 32, context, "43" * 32)
        with self.open() as journal:
            with self.assertRaisesRegex(Conflict, "Bitcoin stage mismatch"):
                journal.reserve(self.session, "32" * 32, changed_claim, "43" * 32)
            journal.reserve(self.session, "32" * 32, self.context, "43" * 32)
            self.assertEqual(journal.get_session(self.session)["zenon_binding_digest"], self.context.as_dict()["binding_digest_hex"])

    def test_zenon_stage_cannot_change_entry_between_partial_and_complete(self):
        _, partial = session_context("zenon-claim-partial")
        data = json.loads((Path(__file__).parent / "fixtures" / "session_terms.json").read_text("ascii"))
        data["zenon_binding"]["entry_id_hex"] = "77" * 32
        data["zenon_binding"]["message_hex"] = hashlib.sha3_256(
            bytes.fromhex(data["zenon_binding"]["entry_id_hex"])
            + bytes.fromhex(data["zenon_binding"]["destination_hex"])
        ).hexdigest()
        bitcoin = bind_bitcoin(self.terms, data["bitcoin_binding"])
        changed = signing_context(bind_zenon(bitcoin, data["zenon_binding"]), "alice", "zenon-claim-complete")
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal, partial)
            with self.assertRaisesRegex(Conflict, "Zenon stage mismatch"):
                journal.reserve(self.session, "32" * 32, changed, "43" * 32)
            journal.reserve(self.session, "32" * 32, self.context, "43" * 32)

    def test_invalid_or_oversized_output_burns_operation(self):
        for output in ("not bytes", bytearray(b"mutable"), b"x" * (MAX_OUTPUT_BYTES + 1)):
            with self.subTest(output_type=type(output).__name__):
                root = self.base / ("mutable-" + type(output).__name__)
                anchor = self.base / ("checkpoint-" + type(output).__name__)
                with Journal.open(root, anchor) as journal:
                    self.initialize(journal)
                    self.reserve(journal)
                    with self.assertRaises(OutcomeUnknown):
                        self.produce(journal, lambda: output)
                    with self.assertRaises(OutcomeUnknown):
                        self.produce(journal)
                    self.assertTrue(journal.get_session(self.session)["possible_exposure"])

    def test_public_output_bound_includes_empty_and_maximum_bytes(self):
        for output in (b"", b"x" * MAX_OUTPUT_BYTES):
            with self.subTest(length=len(output)):
                with Journal.open(self.base / ("mutable-" + str(len(output))), self.base / ("anchor-" + str(len(output)))) as journal:
                    self.initialize(journal)
                    self.reserve(journal)
                    self.assertEqual(self.produce(journal, lambda: output), output)

    def test_ambiguous_commit_poisons_instance_and_divergence_is_not_healed(self):
        armed = False

        def hook(name):
            if armed and name == "after_db_commit":
                raise OSError("synthetic durability failure")

        with self.open(hook=hook) as journal:
            self.initialize(journal)
            self.reserve(journal)
            armed = True
            with self.assertRaises(Quarantined):
                self.produce(journal, lambda: self.fail("callback after uncertain commit"))
            with self.assertRaises(Quarantined):
                journal.get_session(self.session)
        with self.assertRaises(Quarantined):
            self.open()

    def test_precommit_failure_poisoned_instance_recovers_only_retirement(self):
        armed = False

        def hook(name):
            if armed and name == "before_db_commit":
                raise OSError("synthetic precommit failure")

        with self.open(hook=hook) as journal:
            self.initialize(journal)
            self.reserve(journal)
            armed = True
            with self.assertRaises(Quarantined):
                self.produce(journal, lambda: self.fail("callback before commit"))
            with self.assertRaises(Quarantined):
                journal.observe(self.session, "51" * 32)
        with self.open() as journal:
            self.assertEqual(journal.get_operation(self.session, OPERATION_ID)["status"], "RETIRED")
            self.assertFalse(journal.get_session(self.session)["possible_exposure"])

    def test_database_only_and_anchor_only_rollback_fail_closed(self):
        for restored_copy in ("database", "anchor"):
            with self.subTest(restored_copy=restored_copy):
                root = self.base / restored_copy
                anchor = self.base / (restored_copy + ".anchor")
                with Journal.open(root, anchor) as journal:
                    self.initialize(journal)
                db = root / "journal.sqlite3"
                old_db, old_anchor = db.read_bytes(), anchor.read_bytes()
                with Journal.open(root, anchor) as journal:
                    journal.observe(self.session, "51" * 32)
                if restored_copy == "database":
                    db.write_bytes(old_db)
                else:
                    anchor.write_bytes(old_anchor)
                with self.assertRaises(Quarantined):
                    Journal.open(root, anchor)

    def test_restoring_both_copies_is_explicitly_undetectable(self):
        with self.open() as journal:
            self.initialize(journal)
        db = self.root / "journal.sqlite3"
        old_db, old_anchor = db.read_bytes(), self.anchor.read_bytes()
        with self.open() as journal:
            journal.observe(self.session, "51" * 32)
        db.write_bytes(old_db)
        self.anchor.write_bytes(old_anchor)
        with self.open() as journal:
            self.assertEqual(journal.get_session(self.session)["observations"], [])

    def test_valid_sql_mutation_of_recorded_output_is_detected(self):
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal)
            self.produce(journal)
        connection = sqlite3.connect(str(self.root / "journal.sqlite3"))
        try:
            raw = connection.execute("SELECT state_json FROM checkpoint").fetchone()[0]
            state = json.loads(raw)
            state["sessions"][self.session]["operations"][OPERATION_ID]["output_b64"] = "eA=="
            connection.execute("UPDATE checkpoint SET state_json=?", (json.dumps(state, sort_keys=True, separators=(",", ":")),))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(Quarantined):
            self.open()

    def test_missing_database_or_anchor_is_not_reinitialized(self):
        with self.open() as journal:
            self.initialize(journal)
        db = self.root / "journal.sqlite3"
        saved = db.read_bytes()
        db.unlink()
        with self.assertRaises(Quarantined):
            self.open()
        db.write_bytes(saved)
        db.chmod(0o600)
        self.anchor.unlink()
        with self.assertRaises(Quarantined):
            self.open()

    def test_same_directory_and_shared_anchor_are_exclusive_before_connect(self):
        with self.open() as journal:
            self.initialize(journal)
            clone = self.base / "clone"
            clone.mkdir(mode=0o700)
            shutil.copy2(self.root / "journal.sqlite3", clone / "journal.sqlite3")
            with patch("sqlite3.connect", side_effect=AssertionError("unexpected connection")):
                with self.assertRaises(Busy):
                    self.open()
                with self.assertRaises(Busy):
                    Journal.open(clone, self.anchor)

    def test_companion_lock_inode_persists_and_snapshots_are_copies(self):
        with self.open() as journal:
            self.initialize(journal)
            inode = (self.root / "journal.lock").stat().st_ino
            snapshot = journal.get_session(self.session)
            snapshot["possible_exposure"] = True
            self.assertFalse(journal.get_session(self.session)["possible_exposure"])
        with self.open():
            self.assertEqual((self.root / "journal.lock").stat().st_ino, inode)

    def test_bad_input_external_anchor_and_symlink_fail_closed(self):
        with self.assertRaises(InvalidInput):
            Journal.open(self.root, self.root / "anchor")
        with self.open() as journal:
            with self.assertRaises(InvalidInput):
                journal.create_session("AA" * 32, self.terms.digest_hex)
            self.initialize(journal)
            with self.assertRaises(InvalidInput):
                journal.observe(self.session, "51" * 32, reorg=1)
        alias = self.base / "alias"
        alias.symlink_to(self.anchor)
        with self.assertRaises(Quarantined):
            Journal.open(self.root, alias)

    def test_pid_guard_covers_methods_and_close(self):
        with self.open() as journal:
            self.initialize(journal)
            with patch("offline_session.journal.os.getpid", return_value=journal._pid + 1):
                with self.assertRaises(OwnershipError):
                    journal.get_session(self.session)
                with self.assertRaises(OwnershipError):
                    journal.close()
            self.assertFalse(journal.get_session(self.session)["possible_exposure"])

    def test_closed_instance_and_producer_mutation_are_refused(self):
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal)

            def callback():
                with self.assertRaises(Conflict):
                    journal.observe(self.session, "51" * 32)
                with self.assertRaises(Conflict):
                    journal.close()
                return PUBLIC_OUTPUT

            self.produce(journal, callback)
        with self.assertRaises(OwnershipError):
            journal.get_session(self.session)

    def test_hook_cannot_close_journal_during_commit(self):
        armed = False
        blocked = []

        def hook(name):
            if armed and name == "after_anchor_commit":
                with self.assertRaises(Conflict):
                    journal.close()
                blocked.append(name)

        with self.open(hook=hook) as journal:
            self.initialize(journal)
            self.reserve(journal)
            armed = True
            self.assertEqual(self.produce(journal), PUBLIC_OUTPUT)
            self.assertEqual(len(blocked), 2)

    def test_corrupt_database_and_unsupported_version_are_quarantined(self):
        for corruption in ("bytes", "version"):
            with self.subTest(corruption=corruption):
                root = self.base / corruption
                anchor = self.base / (corruption + ".anchor")
                with Journal.open(root, anchor) as journal:
                    self.initialize(journal)
                db = root / "journal.sqlite3"
                if corruption == "bytes":
                    db.write_bytes(b"synthetic invalid database")
                else:
                    connection = sqlite3.connect(str(db))
                    connection.execute("UPDATE checkpoint SET version=99")
                    connection.commit()
                    connection.close()
                with self.assertRaises(Quarantined):
                    Journal.open(root, anchor)

    def test_anchor_fsync_error_stops_before_callback_and_poison_is_persistent(self):
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal)
            with patch("offline_session.journal.os.fsync", side_effect=OSError("synthetic sync error")):
                with self.assertRaises(Quarantined):
                    self.produce(journal, lambda: self.fail("producer after fsync failure"))
            with self.assertRaises(Quarantined):
                journal.get_session(self.session)
        with self.assertRaises(Quarantined):
            self.open()

    def test_dynamic_round_is_shared_across_roles_partial_completion_and_replay(self):
        _, alice = dynamic_context(purpose="zenon-claim-partial", role="alice")
        _, bob = dynamic_context(purpose="zenon-claim-partial", role="bob")
        _, complete = dynamic_context()
        round_digest = complete.as_dict()["nonce_round_digest_hex"]
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal, alice)
            journal.reserve(self.session, "32" * 32, bob, "43" * 32)
            journal.reserve(self.session, "33" * 32, complete, "44" * 32)
            result = journal.produce_once(self.session, "33" * 32, expected_context=complete, callback=lambda: PUBLIC_OUTPUT)
            self.assertEqual(result, PUBLIC_OUTPUT)
            snapshot = journal.get_session(self.session)
            self.assertEqual(snapshot["signing_rounds"], {"zenon": round_digest})
            self.assertEqual(len(set(snapshot["signing_round_nonces"]["zenon"])), 2)
        with self.open() as journal:
            self.assertEqual(journal.get_session(self.session)["signing_rounds"], {"zenon": round_digest})
            self.assertEqual(journal.get_operation(self.session, "33" * 32)["nonce_round_digest"], round_digest)
            self.assertEqual(journal.replay(self.session, "33" * 32, expected_context=complete), PUBLIC_OUTPUT)

    def test_distinct_rounds_cannot_cross_roles_or_partial_completion(self):
        cases = (
            ("zenon-claim-partial", "alice", "zenon-claim-complete", "alice"),
            ("zenon-claim-partial", "alice", "zenon-claim-partial", "bob"),
            ("bitcoin-claim-partial", "alice", "bitcoin-claim-complete", "bob"),
        )
        for index, (first_purpose, first_role, second_purpose, second_role) in enumerate(cases):
            with self.subTest(case=index):
                _, first = dynamic_context(purpose=first_purpose, role=first_role)
                _, second = dynamic_context(purpose=second_purpose, role=second_role, round_id="63" * 32)
                with Journal.open(self.base / ("rounds-" + str(index)), self.base / ("rounds-anchor-" + str(index))) as journal:
                    self.initialize(journal)
                    self.reserve(journal, first)
                    with self.assertRaisesRegex(Conflict, "nonce round mismatch"):
                        journal.reserve(self.session, "32" * 32, second, "43" * 32)

    def test_static_dynamic_mixing_is_rejected_in_both_orders_for_each_leg(self):
        for leg in ("bitcoin", "zenon"):
            for dynamic_first in (False, True):
                with self.subTest(leg=leg, dynamic_first=dynamic_first):
                    first_builder = dynamic_context if dynamic_first else altered_context
                    second_builder = altered_context if dynamic_first else dynamic_context
                    _, first = first_builder(purpose=leg + "-claim-partial", role="alice")
                    _, second = second_builder(purpose=leg + "-claim-complete")
                    _, wrong_mode = second_builder(purpose=leg + "-claim-partial", role="alice")
                    name = leg + str(dynamic_first)
                    with Journal.open(self.base / name, self.base / (name + ".anchor")) as journal:
                        self.initialize(journal)
                        self.reserve(journal, first)
                        with self.assertRaisesRegex(Conflict, "nonce round mismatch"):
                            journal.reserve(self.session, "32" * 32, second, "43" * 32)
                        with self.assertRaisesRegex(Conflict, "nonce round mismatch"):
                            journal.produce_once(self.session, OPERATION_ID, expected_context=wrong_mode, callback=lambda: self.fail("mixed mode callback"))
                        with self.assertRaisesRegex(Conflict, "nonce round mismatch"):
                            journal.replay(self.session, OPERATION_ID, expected_context=wrong_mode)

    def test_round_mode_is_independent_between_legs(self):
        for dynamic_bitcoin in (False, True):
            with self.subTest(dynamic_bitcoin=dynamic_bitcoin):
                btc_builder = dynamic_context if dynamic_bitcoin else altered_context
                zenon_builder = altered_context if dynamic_bitcoin else dynamic_context
                _, bitcoin = btc_builder(purpose="bitcoin-claim-partial")
                _, zenon = zenon_builder(purpose="zenon-claim-partial")
                name = "mode-" + str(dynamic_bitcoin)
                with Journal.open(self.base / name, self.base / (name + ".anchor")) as journal:
                    self.initialize(journal)
                    self.reserve(journal, bitcoin)
                    journal.reserve(self.session, "32" * 32, zenon, "43" * 32)
                    rounds = journal.get_session(self.session)["signing_rounds"]
                    self.assertEqual(rounds["bitcoin"] is not None, dynamic_bitcoin)
                    self.assertEqual(rounds["zenon"] is not None, not dynamic_bitcoin)

    def test_alternate_round_cannot_retry_consumed_retired_or_recorded_scope(self):
        _, context = dynamic_context()
        _, alternative = dynamic_context(round_id="63" * 32)
        for result in ("retired", "unknown", "recorded"):
            with self.subTest(result=result):
                root, anchor = self.base / result, self.base / (result + ".anchor")
                with Journal.open(root, anchor) as journal:
                    self.initialize(journal)
                    self.reserve(journal, context)
                    if result == "unknown":
                        with self.assertRaises(OutcomeUnknown):
                            journal.produce_once(self.session, OPERATION_ID, expected_context=context, callback=lambda: 0)
                    elif result == "recorded":
                        journal.produce_once(self.session, OPERATION_ID, expected_context=context, callback=lambda: PUBLIC_OUTPUT)
                with Journal.open(root, anchor) as journal:
                    with self.assertRaisesRegex(Conflict, "nonce round mismatch"):
                        journal.reserve(self.session, "32" * 32, alternative, "43" * 32)
                    with self.assertRaisesRegex(Conflict, "nonce round mismatch"):
                        journal.produce_once(self.session, OPERATION_ID, expected_context=alternative, callback=lambda: self.fail("alternate round callback"))
                    with self.assertRaisesRegex(Conflict, "nonce round mismatch"):
                        journal.replay(self.session, OPERATION_ID, expected_context=alternative)
                    with self.assertRaises(Conflict):
                        journal.reserve(self.session, "32" * 32, context, "43" * 32)

    def test_public_nonce_encoding_cannot_be_reused_across_legs(self):
        _, bitcoin = dynamic_context(purpose="bitcoin-claim-partial")
        openings = bitcoin.as_dict()["nonce_round"]["public_nonces"]
        # Recalculate valid Zenon commitments; reject reuse despite valid hashes.
        _, zenon = dynamic_context(public_nonces=(openings["bob"], openings["alice"]))
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal, bitcoin)
            with self.assertRaisesRegex(Conflict, "public nonce encoding is already pinned"):
                journal.reserve(self.session, "32" * 32, zenon, "43" * 32)

    def test_public_nonce_encoding_cannot_be_reused_across_sessions_after_reopen(self):
        _, first = dynamic_context()
        openings = first.as_dict()["nonce_round"]["public_nonces"]
        other_terms, second = dynamic_context(
            session_id="12" * 32, round_id="63" * 32,
            public_nonces=(openings["bob"], openings["alice"]),
        )
        with self.open() as journal:
            self.initialize(journal)
            self.reserve(journal, first)
            journal.create_session(other_terms.session_id, other_terms.digest_hex)
        with self.open() as journal:
            with self.assertRaisesRegex(Conflict, "public nonce encoding is already pinned"):
                journal.reserve(other_terms.session_id, "32" * 32, second, "43" * 32)

    def _rewrite_checkpoint(self, root, anchor, transform, *, version=VERSION):
        """Create a checksummed synthetic state to exercise semantic validation."""
        connection = sqlite3.connect(str(root / "journal.sqlite3"))
        try:
            lineage, sequence, raw = connection.execute("SELECT lineage, sequence, state_json FROM checkpoint").fetchone()
            state = json.loads(raw)
            transform(state)
            material = {"version": version, "lineage": lineage, "sequence": sequence, "state": state}
            canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            digest = hashlib.sha256(("ptlc-offline-journal-v" + str(version)).encode("ascii") + b"\x00" + canonical(material)).hexdigest()
            connection.execute("UPDATE checkpoint SET version=?, state_json=?, digest=?", (version, canonical(state).decode("ascii"), digest))
            connection.commit()
            anchor.write_bytes(canonical({"version": version, "lineage": lineage, "sequence": sequence, "digest": digest}))
        finally:
            connection.close()

    def test_reload_requires_operation_round_pin_and_unique_public_nonce_pins(self):
        _, bitcoin = dynamic_context(purpose="bitcoin-claim-partial")
        _, zenon = dynamic_context()
        for alteration in ("missing-pin", "wrong-round", "missing-nonces", "duplicate-nonce"):
            with self.subTest(alteration=alteration):
                root, anchor = self.base / alteration, self.base / (alteration + ".anchor")
                with Journal.open(root, anchor) as journal:
                    self.initialize(journal)
                    self.reserve(journal, bitcoin)
                    journal.reserve(self.session, "32" * 32, zenon, "43" * 32)

                def transform(state):
                    session = state["sessions"][self.session]
                    if alteration == "missing-pin":
                        del session["signing_rounds"]["zenon"]
                        del session["signing_round_nonces"]["zenon"]
                    elif alteration == "wrong-round":
                        session["operations"]["32" * 32]["nonce_round_digest"] = "99" * 32
                    elif alteration == "missing-nonces":
                        del session["signing_round_nonces"]["zenon"]
                    else:
                        session["signing_round_nonces"]["zenon"][0] = session["signing_round_nonces"]["bitcoin"][0]

                self._rewrite_checkpoint(root, anchor, transform)
                with self.assertRaises(Quarantined):
                    Journal.open(root, anchor)

    def test_version_one_checkpoint_is_quarantined_without_migration(self):
        with self.open() as journal:
            self.initialize(journal)

        def old_schema(state):
            session = state["sessions"][self.session]
            del session["signing_rounds"]
            del session["signing_round_nonces"]

        self._rewrite_checkpoint(self.root, self.anchor, old_schema, version=1)
        db = self.root / "journal.sqlite3"
        before = (db.read_bytes(), self.anchor.read_bytes())
        with self.assertRaises(Quarantined):
            self.open()
        self.assertEqual((db.read_bytes(), self.anchor.read_bytes()), before)


if __name__ == "__main__":
    unittest.main()
