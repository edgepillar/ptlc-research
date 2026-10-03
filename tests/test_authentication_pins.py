"""Durable local pin choices; fake verifiers provide no cryptographic evidence."""

import copy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import tempfile
import threading
import unittest

from offline_session import authentication, completion, exchange
from offline_session.journal import Busy, Conflict, InvalidInput, Journal, OwnershipError, Quarantined, VERSION
from offline_session.transcript import agree_terms, bind_bitcoin, commit_nonce_round, nonce_commitment, reveal_nonce_round, signing_context
from completion_test_support import alice_context, completion_accepted
from exchange_test_support import accepted, artifacts


def authenticated(request):
    """A fake digest-bound result for sequencing, never signature verification."""
    return {"schema": "ptlc-completion-auth-result-v1",
            "request_digest_hex": authentication.request_digest(request), "valid": True}


class AuthenticationPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.terms, cls.bitcoin, cls.zenon, cls.btc_bundle, cls.znn_bundle = artifacts()
        cls.session = cls.terms.session_id
        root = Path(__file__).resolve().parents[1]
        cls.vector = json.loads((root / "qualification/fixtures/authentication.json").read_text("ascii"))
        cls.pins = {key: cls.vector["envelope"]["context"][key]
                    for key in ("alice_auth_key_hex", "bob_auth_key_hex")}
        cls.alternate_pins = dict(zip(cls.pins, reversed(list(cls.pins.values()))))
        cls.wire = exchange.canonical(cls.vector["envelope"])
        cls.payload = bytes.fromhex(cls.vector["envelope"]["payload_hex"])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-authentication-pins-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root, self.anchor = self.base / "state", self.base / "head.json"

    def open(self, **kwargs):
        return Journal.open(self.root, self.anchor, **kwargs)

    def start(self, journal, *, pins=True):
        journal.create_session(self.session, self.terms.digest_hex)
        journal.start_exchange(self.session, self.bitcoin, recovery_limit=8,
                               authentication_pins=self.pins.copy() if pins is True else pins)

    def durable_bytes(self):
        return (self.root / "journal.sqlite3").read_bytes(), self.anchor.read_bytes()

    def snapshot(self, journal):
        return copy.deepcopy(journal._state), journal._sequence, self.durable_bytes()

    def authenticate(self, journal, wire=None, verifier=authenticated):
        return journal.authenticate_exchange_envelope(
            self.session, self.wire if wire is None else wire, verifier=verifier,
        )

    def release(self, journal):
        journal.retain_exchange_bitcoin(self.session, self.btc_bundle, verifier=accepted)
        journal.bind_exchange_zenon(self.session, self.zenon)
        journal.retain_exchange_alice_partial(self.session, self.znn_bundle["partial_signatures_hex"][0], verifier=accepted)
        journal.retain_exchange_zenon(self.session, self.znn_bundle, verifier=accepted)
        journal.release_exchange_zenon(self.session)

    def rewrite(self, change, *, version=VERSION):
        with closing(sqlite3.connect(str(self.root / "journal.sqlite3"))) as connection:
            lineage, sequence, raw = connection.execute("SELECT lineage, sequence, state_json FROM checkpoint").fetchone()
            state = json.loads(raw)
            change(state["sessions"][self.session])
            material = {"version": version, "lineage": lineage, "sequence": sequence, "state": state}
            digest = hashlib.sha256(("ptlc-offline-journal-v" + str(version)).encode("ascii") + b"\x00"
                                    + exchange.canonical(material)).hexdigest()
            connection.execute("UPDATE checkpoint SET version=?, state_json=?, digest=?",
                               (version, exchange.canonical(state).decode("ascii"), digest))
            connection.commit()
        self.anchor.write_bytes(exchange.canonical({
            "version": version, "lineage": lineage, "sequence": sequence, "digest": digest,
        }))

    def test_configured_choice_is_copied_and_survives_reopen(self):
        pins = self.pins.copy()
        with self.open() as journal:
            self.start(journal, pins=pins)
            pins.update(self.alternate_pins)
            copied = journal.get_session(self.session)
            copied["authentication_pins"].clear()
            self.assertEqual(journal.get_session(self.session)["authentication_pins"], self.pins)
            before = self.snapshot(journal)
        with self.open() as journal:
            self.assertEqual(self.snapshot(journal), before)
            self.assertEqual(self.authenticate(journal), self.payload)
            self.assertEqual(self.snapshot(journal), before)

    def test_strict_pin_validation_precedes_untrusted_equality_without_persistence(self):
        equalities = []
        class HostileString(str):
            __hash__ = str.__hash__
            def __eq__(self, other):
                equalities.append(1)
                raise RuntimeError("synthetic equality detail")
        class HostileDict(dict):
            def copy(self):
                equalities.append(1)
                raise RuntimeError("synthetic copy detail")
        reserved = self.terms.as_dict()["terms"]["bitcoin"]["signer_keys_sec1_hex"][0][2:]
        bad = [True, False, [], {}, HostileDict(self.pins),
               dict(self.pins, extra="synthetic"), dict(self.pins, alice_auth_key_hex=True),
               dict(self.pins, alice_auth_key_hex=HostileString(self.pins["alice_auth_key_hex"])),
               dict(self.pins, alice_auth_key_hex=self.pins["bob_auth_key_hex"]),
               dict(self.pins, alice_auth_key_hex=reserved), dict(self.pins, alice_auth_key_hex="AA" * 32),
               {HostileString("alice_auth_key_hex"): self.pins["alice_auth_key_hex"],
                "bob_auth_key_hex": self.pins["bob_auth_key_hex"]}]
        with self.open() as journal:
            journal.create_session(self.session, self.terms.digest_hex)
            before = self.snapshot(journal)
            for pins in bad:
                with self.subTest(kind=type(pins).__name__), self.assertRaises(InvalidInput):
                    journal.start_exchange(self.session, self.bitcoin, recovery_limit=8, authentication_pins=pins)
                self.assertEqual(self.snapshot(journal), before)
            self.assertEqual(equalities, [])
            journal.start_exchange(self.session, self.bitcoin, recovery_limit=8, authentication_pins=self.pins)

    def test_missing_pins_nonbob_and_noncallable_fail_without_callback_or_changes(self):
        calls = []
        with self.open() as journal:
            journal.create_session(self.session, self.terms.digest_hex)
            before = self.snapshot(journal)
            with self.assertRaises(Conflict):
                self.authenticate(journal, verifier=lambda request: calls.append(1))
            self.assertEqual(self.snapshot(journal), before)
            journal.start_alice(self.session, alice_context(), self.znn_bundle["partial_signatures_hex"][0], verifier=accepted)
            before = self.snapshot(journal)
            with self.assertRaises(Conflict):
                self.authenticate(journal, verifier=lambda request: calls.append(1))
            self.assertEqual(self.snapshot(journal), before)
        with tempfile.TemporaryDirectory(prefix="synthetic-pinless-") as directory:
            with Journal.open(Path(directory) / "state", Path(directory) / "head.json") as journal:
                self.start(journal, pins=None)
                before = copy.deepcopy(journal._state), journal._sequence
                with self.assertRaises(Conflict):
                    self.authenticate(journal, verifier=lambda request: calls.append(1))
                self.assertEqual((journal._state, journal._sequence), before)
        self.assertEqual(calls, [])

    def test_noncallable_verifier_is_invalid_input_and_does_not_write(self):
        with self.open() as journal:
            self.start(journal)
            before = self.snapshot(journal)
            with self.assertRaises(InvalidInput):
                self.authenticate(journal, verifier=None)
            self.assertEqual(self.snapshot(journal), before)

    def test_authentication_and_replays_work_at_every_bob_stage_without_any_writes(self):
        with self.open() as journal:
            self.start(journal)
            transitions = [
                lambda: None,
                lambda: journal.retain_exchange_bitcoin(self.session, self.btc_bundle, verifier=accepted),
                lambda: journal.bind_exchange_zenon(self.session, self.zenon),
                lambda: journal.retain_exchange_alice_partial(self.session, self.znn_bundle["partial_signatures_hex"][0], verifier=accepted),
                lambda: journal.retain_exchange_zenon(self.session, self.znn_bundle, verifier=accepted),
                lambda: journal.release_exchange_zenon(self.session),
                lambda: journal.complete_exchange_bitcoin(self.session, self.payload, recoverer=completion_accepted),
            ]
            for transition in transitions:
                transition()
                before = self.snapshot(journal)
                for _ in range(2):
                    self.assertEqual(self.authenticate(journal), self.payload)
                    self.assertEqual(self.snapshot(journal), before)
            self.assertEqual(journal.get_session(self.session)["recovery_budget"]["consumed"], 1)

    def test_rejected_envelopes_and_worker_failures_preserve_all_durable_bytes(self):
        calls, equalities = [], []
        class HostileBytes(bytes):
            def __eq__(self, other):
                equalities.append(1)
                raise RuntimeError("synthetic equality detail")
        changed = copy.deepcopy(self.vector["envelope"])
        changed["context"].update(self.alternate_pins)
        with self.open() as journal:
            self.start(journal)
            before = self.snapshot(journal)
            for wire in (b"{}", self.wire + b"\n", exchange.canonical(changed), HostileBytes(self.wire)):
                with self.assertRaises(Conflict):
                    self.authenticate(journal, wire, verifier=lambda request: calls.append(1))
                self.assertEqual(self.snapshot(journal), before)
            self.assertEqual((calls, equalities), ([], []))
            def fail(request):
                raise RuntimeError("synthetic private diagnostic")
            for verifier in (fail, lambda _: None, lambda request: dict(authenticated(request), valid=False),
                             lambda request: dict(authenticated(request), valid=1),
                             lambda request: dict(authenticated(request), request_digest_hex="99" * 32)):
                with self.assertRaises(Conflict) as caught:
                    self.authenticate(journal, verifier=verifier)
                self.assertNotIn("synthetic private diagnostic", str(caught.exception))
                self.assertEqual(self.snapshot(journal), before)
            self.assertEqual(self.authenticate(journal), self.payload)

    def test_callback_mutation_cannot_change_returned_payload_or_local_pins(self):
        with self.open() as journal:
            self.start(journal)
            before = self.snapshot(journal)
            def worker(request):
                self.assertEqual({key: request["context"][key] for key in self.pins}, self.pins)
                result = authenticated(request)
                request["context"].update(self.alternate_pins)
                request["payload_hex"] = "00"
                return result
            self.assertEqual(self.authenticate(journal, verifier=worker), self.payload)
            self.assertEqual(self.snapshot(journal), before)

    def test_cancellation_propagates_and_releases_the_owner_guard_without_writes(self):
        with self.open() as journal:
            self.start(journal)
            before = self.snapshot(journal)
            for error in (KeyboardInterrupt, SystemExit):
                def cancel(request):
                    raise error("synthetic cancellation")
                with self.assertRaises(error):
                    self.authenticate(journal, verifier=cancel)
                self.assertEqual(self.snapshot(journal), before)
                self.assertEqual(self.authenticate(journal), self.payload)
                self.assertEqual(self.snapshot(journal), before)

    def test_opaque_payload_authentication_does_not_validate_inner_completion(self):
        vector = self.vector["authenticated_invalid_completion"]
        with self.open() as journal:
            self.start(journal)
            before = self.snapshot(journal)
            payload = self.authenticate(journal, exchange.canonical(vector["envelope"]))
            self.assertEqual(payload, bytes.fromhex(vector["envelope"]["payload_hex"]))
            self.assertEqual(json.loads(payload)["signature_hex"], "00" * 64)
            self.assertEqual(self.snapshot(journal), before)

    def test_configured_pins_do_not_gate_raw_recovery_or_reconciliation(self):
        old = bytes.fromhex(self.vector["authenticated_invalid_completion"]["envelope"]["payload_hex"])
        with self.open() as journal:
            self.start(journal)
            self.release(journal)
            with self.assertRaises(Conflict):
                journal.complete_exchange_bitcoin(self.session, old, recoverer=lambda _: None)
            output = journal.reconcile_exchange_bitcoin(
                self.session, self.payload, expected_observation_digest=completion.observation_digest(old),
                recoverer=completion_accepted,
            )
            self.assertIsInstance(output, bytes)
            self.assertEqual(journal.get_session(self.session)["authentication_pins"], self.pins)
            self.assertEqual(journal.get_session(self.session)["recovery_budget"]["consumed"], 2)

    def test_persistence_freezes_configured_pins_and_the_absent_choice(self):
        with self.open() as journal:
            self.start(journal)
            before = self.snapshot(journal)
            for replacement in (None, self.alternate_pins):
                changed = copy.deepcopy(journal._state)
                changed["sessions"][self.session]["authentication_pins"] = replacement
                with self.assertRaises(Conflict):
                    journal._persist(changed)
                self.assertEqual(self.snapshot(journal), before)
            changed = copy.deepcopy(journal._state)
            changed["sessions"].pop(self.session)
            with self.assertRaises(Conflict):
                journal._persist(changed)
            self.assertEqual(self.snapshot(journal), before)
        with tempfile.TemporaryDirectory(prefix="synthetic-absent-pins-") as directory:
            with Journal.open(Path(directory) / "state", Path(directory) / "head.json") as journal:
                self.start(journal, pins=None)
                changed = copy.deepcopy(journal._state)
                changed["sessions"][self.session]["authentication_pins"] = self.pins.copy()
                with self.assertRaises(Conflict):
                    journal._persist(changed)
                self.assertIsNone(journal.get_session(self.session)["authentication_pins"])

    def test_persistence_freezes_the_complete_valid_bitcoin_context(self):
        original = self.bitcoin.as_dict()
        raw = copy.deepcopy(original["binding"]["binding"])
        raw["claim_txid_hex"] = "77" * 32
        round_id = original["nonce_round"]["round_id"]
        nonces = original["nonce_round"]["public_nonces"]
        changed_terms = self.terms.as_dict()["terms"]
        changed_terms["policy"]["minimum_claim_margin_seconds"] += 1
        alternatives = ((self.terms, raw, round_id),
                        (self.terms, original["binding"]["binding"], "77" * 32),
                        (agree_terms(changed_terms), original["binding"]["binding"], round_id))
        with self.open() as journal:
            self.start(journal)
            before = self.snapshot(journal)
            for terms, raw_binding, changed_round_id in alternatives:
                binding = bind_bitcoin(terms, raw_binding)
                committed = commit_nonce_round(binding, changed_round_id, *[
                    nonce_commitment(binding, changed_round_id, role, nonces[role]) for role in ("alice", "bob")
                ])
                round_context = reveal_nonce_round(committed, nonces["alice"], nonces["bob"])
                alternate = signing_context(binding, "bob", "bitcoin-claim-partial", nonce_round=round_context)
                changed = copy.deepcopy(journal._state)
                session = changed["sessions"][self.session]
                session["exchange"] = exchange.start(alternate)
                session["terms_digest"] = terms.digest_hex
                session["bitcoin_binding_digest"] = binding.digest_hex
                session["signing_rounds"]["bitcoin"] = round_context.digest_hex
                with self.assertRaises(Conflict):
                    journal._persist(changed)
                self.assertEqual(self.snapshot(journal), before)

    def test_resealed_malformed_pin_metadata_quarantines(self):
        with self.open() as journal:
            self.start(journal)
        saved = self.durable_bytes()
        bad = ({}, True, [], dict(self.pins, extra="synthetic"), dict(self.pins, alice_auth_key_hex=False),
               dict(self.pins, alice_auth_key_hex=self.pins["bob_auth_key_hex"]),
               dict(self.pins, alice_auth_key_hex=self.terms.as_dict()["terms"]["adaptor_point_sec1_hex"][2:]))
        changes = [lambda session, pins=pins: session.update(authentication_pins=pins) for pins in bad]
        changes += [lambda session: session.pop("authentication_pins"),
                    lambda session: session.update(exchange=None, recovery_budget=None)]
        for change in changes:
            (self.root / "journal.sqlite3").write_bytes(saved[0])
            self.anchor.write_bytes(saved[1])
            self.rewrite(change)
            before = self.durable_bytes()
            with self.assertRaises(Quarantined):
                self.open()
            self.assertEqual(self.durable_bytes(), before)

    def test_resealed_version_six_checkpoint_quarantines_without_migration(self):
        with self.open() as journal:
            self.start(journal, pins=None)
        self.rewrite(lambda session: session.pop("authentication_pins"), version=6)
        before = self.durable_bytes()
        self.assertEqual(VERSION, 7)
        with self.assertRaises(Quarantined):
            self.open()
        self.assertEqual(self.durable_bytes(), before)

    def test_callback_owner_guard_blocks_reentry_other_sessions_close_and_competing_owner(self):
        with self.open() as journal:
            self.start(journal)
            other = "99" * 32
            journal.create_session(other, self.terms.digest_hex)
            before = self.snapshot(journal)
            def worker(request):
                self.assertEqual(journal.get_session(self.session)["authentication_pins"], self.pins)
                for action in (lambda: self.authenticate(journal),
                               lambda: journal.authenticate_exchange_envelope(other, self.wire, verifier=authenticated),
                               lambda: journal.create_session("88" * 32, self.terms.digest_hex),
                               lambda: journal.complete_exchange_bitcoin(self.session, self.payload, recoverer=completion_accepted),
                               journal.close):
                    with self.assertRaises(Conflict):
                        action()
                with self.assertRaises(Busy):
                    self.open()
                return authenticated(request)
            self.assertEqual(self.authenticate(journal, verifier=worker), self.payload)
            self.assertEqual(self.snapshot(journal), before)
        with self.assertRaises(OwnershipError):
            self.authenticate(journal)

    def test_foreign_thread_cannot_authenticate_read_or_close_owned_journal(self):
        with self.open() as journal:
            self.start(journal)
            before = self.snapshot(journal)
            errors = []
            def foreign():
                for action in (lambda: self.authenticate(journal), lambda: journal.get_session(self.session), journal.close):
                    try:
                        action()
                    except BaseException as error:
                        errors.append(type(error))
            def worker(request):
                thread = threading.Thread(target=foreign)
                thread.start()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                return authenticated(request)
            self.assertEqual(self.authenticate(journal, verifier=worker), self.payload)
            self.assertEqual(errors, [OwnershipError] * 3)
            self.assertEqual(self.snapshot(journal), before)

    @unittest.skipUnless(hasattr(os, "fork"), "qualification requires POSIX fork")
    def test_forked_callback_process_cannot_use_inherited_owner(self):
        with self.open() as journal:
            self.start(journal)
            before = self.snapshot(journal)
            def worker(request):
                reader, writer = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(reader)
                    result = bytearray()
                    for action in (lambda: self.authenticate(journal), lambda: journal.get_session(self.session), journal.close):
                        try:
                            action()
                        except OwnershipError:
                            result.extend(b"1")
                        except BaseException:
                            result.extend(b"0")
                    os.write(writer, result)
                    os.close(writer)
                    os._exit(0)
                os.close(writer)
                waited = False
                try:
                    with selectors.DefaultSelector() as selection:
                        selection.register(reader, selectors.EVENT_READ)
                        self.assertTrue(selection.select(timeout=5), "forked owner check timed out")
                    self.assertEqual(os.read(reader, 10), b"111")
                    _, status = os.waitpid(pid, 0)
                    waited = True
                    self.assertEqual(status, 0)
                finally:
                    os.close(reader)
                    if not waited:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                return authenticated(request)
            self.assertEqual(self.authenticate(journal, verifier=worker), self.payload)
            self.assertEqual(self.snapshot(journal), before)

    def test_matching_prestart_snapshot_restore_can_replace_the_local_choice(self):
        with self.open() as journal:
            journal.create_session(self.session, self.terms.digest_hex)
        saved = self.durable_bytes()
        with self.open() as journal:
            journal.start_exchange(self.session, self.bitcoin, recovery_limit=8, authentication_pins=self.pins)
            self.assertEqual(journal.get_session(self.session)["authentication_pins"], self.pins)
        (self.root / "journal.sqlite3").write_bytes(saved[0])
        self.anchor.write_bytes(saved[1])
        with self.open() as journal:
            journal.start_exchange(self.session, self.bitcoin, recovery_limit=8, authentication_pins=self.alternate_pins)
            self.assertEqual(journal.get_session(self.session)["authentication_pins"], self.alternate_pins)
            with self.assertRaises(Conflict):
                self.authenticate(journal)


if __name__ == "__main__":
    unittest.main()
