"""Public candidate packaging; fake callbacks do not verify signature math."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from offline_session import completion, exchange
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round, nonce_commitment,
    reveal_nonce_round, signing_context,
)
from completion_test_support import completion_accepted, final_signatures, released_bob
from exchange_test_support import accepted, artifacts, prepare


class PublicSignatureCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.fixture = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
        cls.rounds = json.loads((root / "qualification/fixtures/nonce_rounds.json").read_text("ascii"))["vectors"]
        authentication = json.loads((root / "qualification/fixtures/authentication.json").read_text("ascii"))
        cls.expected_packet = bytes.fromhex(authentication["envelope"]["payload_hex"])
        cls.pins = {key: authentication["envelope"]["context"][key]
                    for key in ("alice_auth_key_hex", "bob_auth_key_hex")}
        cls.signature, cls.bitcoin_signature = final_signatures()
        cls.released = released_bob()

    def assert_unchanged(self, state, signature):
        before = copy.deepcopy(state)
        packet = completion.bob_candidate_from_signature(state, signature)
        self.assertEqual(state, before)
        return packet

    def snapshot(self, journal, root, anchor):
        return copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()

    def test_known_signature_reconstructs_exact_checked_in_packet_without_an_envelope(self):
        packet = self.assert_unchanged(self.released, self.signature)
        self.assertIs(type(packet), bytes)
        self.assertEqual(packet, self.expected_packet)
        value = json.loads(packet)
        self.assertEqual(value["schema"], "ptlc-alice-zenon-completion-v1")
        self.assertEqual((value["sender_role"], value["recipient_role"]), ("alice", "bob"))
        self.assertEqual(value["signature_hex"], self.signature.hex())
        self.assertEqual(packet, exchange.canonical(value))
        self.assertNotIn("authentication", value)

    def test_signature_requires_plain_exact_64_bytes_before_local_object_methods(self):
        calls = []
        class HostileBytes(bytes):
            def hex(self):
                calls.append("hex")
                raise RuntimeError("synthetic conversion detail")
            def __len__(self):
                calls.append("length")
                raise RuntimeError("synthetic length detail")
        class HostileSignature:
            def __len__(self):
                calls.append("length")
                raise RuntimeError("synthetic length detail")
            def __eq__(self, other):
                calls.append("equality")
                raise RuntimeError("synthetic equality detail")
        before = copy.deepcopy(self.released)
        for signature in (None, True, 64, self.signature.hex(), bytearray(self.signature),
                          memoryview(self.signature), b"", b"x" * 63, b"x" * 65,
                          HostileBytes(self.signature), HostileSignature()):
            with self.subTest(kind=type(signature).__name__), self.assertRaises(completion.CompletionError):
                completion.bob_candidate_from_signature(self.released, signature)
            self.assertEqual(self.released, before)
        self.assertEqual(calls, [])

    def test_packaging_accepts_invalid_math_and_wrong_leg_bytes_without_validating_them(self):
        for signature in (bytes(64), b"\xff" * 64, self.bitcoin_signature):
            packet = self.assert_unchanged(self.released, signature)
            self.assertEqual(json.loads(packet)["signature_hex"], signature.hex())
            self.assertEqual(json.loads(packet)["context"], json.loads(self.expected_packet)["context"])
        # Actual rejection belongs to the separate executable integration tests.

    def test_only_a_valid_released_bob_snapshot_can_construct_a_candidate(self):
        _, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
        early = [exchange.start(bitcoin)]
        early.append(exchange.retain_bitcoin(early[-1], btc_bundle, accepted))
        early.append(exchange.bind_zenon(early[-1], zenon))
        early.append(exchange.retain_alice_partial(early[-1], znn_bundle["partial_signatures_hex"][0], accepted))
        early.append(exchange.retain_zenon(early[-1], znn_bundle, accepted))
        completed, _ = completion.complete_bob(self.released, self.expected_packet, completion_accepted)
        for state in [None, True, [], {}, *early, completed]:
            before = copy.deepcopy(state)
            with self.subTest(kind=type(state).__name__), self.assertRaises(completion.CompletionError):
                completion.bob_candidate_from_signature(state, self.signature)
            self.assertEqual(state, before)

    def test_malformed_deep_context_receipts_and_state_subclasses_fail_without_mutation(self):
        calls = []
        class HostileState(dict):
            def __deepcopy__(self, memo):
                calls.append("copy")
                raise RuntimeError("synthetic copy detail")
        with self.assertRaises(completion.CompletionError):
            completion.bob_candidate_from_signature(HostileState(self.released), self.signature)
        self.assertEqual(calls, [])
        changes = (
            lambda state: state.update(extra=True),
            lambda state: state.update(schema="future"),
            lambda state: state["verification_receipts"].clear(),
            lambda state: state.update(release_hex="00"),
            lambda state: state["zenon_context"].update(session_id="99" * 32),
            lambda state: state["zenon_context"].update(nonce_round_digest_hex="99" * 32),
            lambda state: state["zenon_context"]["nonce_round"]["public_nonces"].update(alice="00" * 66),
            lambda state: state["zenon_context"]["binding"]["binding"].update(point_type=True),
            lambda state: state["bitcoin_context"]["binding"]["terms"]["policy"].update(minimum_claim_margin_seconds=31),
        )
        for change in changes:
            state = copy.deepcopy(self.released)
            change(state)
            before = copy.deepcopy(state)
            with self.assertRaises(completion.CompletionError):
                completion.bob_candidate_from_signature(state, self.signature)
            self.assertEqual(state, before)

    def reconstructed_release(self, *, changed_session=False, changed_terms=False, changed_round=False):
        """Rebind public fixture bytes with fake checks, not new valid signatures."""
        raw = copy.deepcopy(self.fixture["terms"])
        if changed_session:
            raw["session_id"] = "99" * 32
        if changed_terms:
            raw["policy"]["minimum_claim_margin_seconds"] += 1
        terms = agree_terms(raw)
        bitcoin = bind_bitcoin(terms, self.fixture["bitcoin_binding"])
        zenon = bind_zenon(bitcoin, self.fixture["zenon_binding"])
        contexts = []
        for binding, vector in zip((bitcoin, zenon), self.rounds):
            round_id = "77" * 32 if changed_round else vector["round_id_hex"]
            alice, bob = vector["public_nonces_hex"]
            commitments = commit_nonce_round(binding, round_id,
                nonce_commitment(binding, round_id, "alice", alice),
                nonce_commitment(binding, round_id, "bob", bob))
            nonce_round = reveal_nonce_round(commitments, alice, bob)
            contexts.append(signing_context(binding, "bob", binding.stage + "-claim-partial", nonce_round=nonce_round))
        state = exchange.start(contexts[0])
        state = exchange.retain_bitcoin(state, self.released["bitcoin_bundle"], accepted)
        state = exchange.bind_zenon(state, contexts[1])
        state = exchange.retain_alice_partial(state, self.released["alice_partial_hex"], accepted)
        state = exchange.retain_zenon(state, self.released["zenon_bundle"], accepted)
        return exchange.release(state)[0], terms

    def test_packet_reconstructs_locally_bound_terms_and_nonce_round(self):
        for change in ({"changed_terms": True}, {"changed_round": True}):
            state, terms = self.reconstructed_release(**change)
            packet = self.assert_unchanged(state, self.signature)
            self.assertNotEqual(packet, self.expected_packet)
            value = json.loads(packet)
            expected = copy.deepcopy(state["zenon_context"])
            expected.update(role="alice", purpose="zenon-claim-complete")
            self.assertEqual(value["context"], expected)
            self.assertEqual(value["context"]["binding"]["bitcoin"]["terms_digest_hex"], terms.digest_hex)
            self.assertEqual(value["signature_hex"], self.signature.hex())
            completion.bob_request(state, packet)

    def test_raw_signature_has_no_session_label_to_import_or_authenticate(self):
        state, terms = self.reconstructed_release(changed_session=True)
        packet = self.assert_unchanged(state, self.signature)
        self.assertEqual(json.loads(packet)["context"]["session_id"], terms.session_id)
        self.assertEqual(json.loads(packet)["signature_hex"], self.signature.hex())
        self.assertNotEqual(packet, self.expected_packet)
        # Packaging neither proves session provenance nor changes the chain signature.

    def test_helper_accepts_no_source_inclusion_authentication_or_context_overrides(self):
        for field, value in (("source", "public"), ("included", True), ("authenticated", True),
                             ("context", self.released["zenon_context"]), ("session_id", "99" * 32),
                             ("verifier", accepted), ("recoverer", completion_accepted)):
            with self.subTest(field=field), self.assertRaises(TypeError):
                completion.bob_candidate_from_signature(self.released, self.signature, **{field: value})

    def test_retained_invalid_candidate_does_not_block_construction_or_allow_implicit_replacement(self):
        previous = completion.bob_candidate_from_signature(self.released, bytes(64))
        state = completion.observe_bob(self.released, previous)
        candidate = self.assert_unchanged(state, self.signature)
        self.assertEqual(candidate, self.expected_packet)
        self.assertNotEqual(candidate, previous)
        self.assertEqual(state["zenon_completion_packet_hex"], previous.hex())
        self.assertIsNone(state["superseded_zenon_completion_packet_hex"])
        with self.assertRaises(exchange.ExchangeError):
            completion.bob_request(state, candidate)
        with self.assertRaises(exchange.ExchangeError):
            completion.bob_reconciliation_request(state, candidate,
                expected_observation_digest=completion.observation_digest(candidate))
        completion.bob_reconciliation_request(state, candidate,
            expected_observation_digest=completion.observation_digest(previous))

    def test_construction_after_reopen_preserves_all_journal_bytes_sequence_budget_exposure_and_pins(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-public-candidate-") as directory:
            base = Path(directory)
            root, anchor = base / "state", base / "head.json"
            with Journal.open(root, anchor) as journal:
                session = prepare(journal, authentication_pins=self.pins)
                journal.release_exchange_zenon(session)
            with Journal.open(root, anchor) as journal:
                before = self.snapshot(journal, root, anchor)
                candidate = completion.bob_candidate_from_signature(journal.get_exchange(session), self.signature)
                self.assertEqual(candidate, self.expected_packet)
                self.assertEqual(self.snapshot(journal, root, anchor), before)
                with self.assertRaises(completion.CompletionError):
                    completion.bob_candidate_from_signature(journal.get_exchange(session), self.signature[:-1])
                self.assertEqual(self.snapshot(journal, root, anchor), before)
                self.assertEqual(journal.get_session(session)["authentication_pins"], self.pins)
                self.assertFalse(journal.get_session(session)["possible_exposure"])
                self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 0)

    def test_pure_construction_cannot_replenish_or_bypass_exhausted_recovery_allowance(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-exhausted-candidate-") as directory:
            base = Path(directory)
            root, anchor = base / "state", base / "head.json"
            with Journal.open(root, anchor) as journal:
                session = prepare(journal, recovery_limit=1, authentication_pins=self.pins)
                journal.release_exchange_zenon(session)
                previous = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, previous, recoverer=lambda _: None)
            with Journal.open(root, anchor) as journal:
                before = self.snapshot(journal, root, anchor)
                candidate = completion.bob_candidate_from_signature(journal.get_exchange(session), self.signature)
                self.assertEqual(candidate, self.expected_packet)
                self.assertEqual(self.snapshot(journal, root, anchor), before)
                calls = []
                with self.assertRaises(Conflict):
                    journal.reconcile_exchange_bitcoin(session, candidate,
                        expected_observation_digest=completion.observation_digest(candidate),
                        recoverer=lambda request: calls.append(request))
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, candidate,
                        expected_observation_digest=completion.observation_digest(previous),
                        recoverer=lambda request: calls.append(request))
                self.assertEqual(calls, [])
                self.assertEqual(self.snapshot(journal, root, anchor), before)


if __name__ == "__main__":
    unittest.main()
