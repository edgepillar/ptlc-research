"""Explicit Bob reconciliation with fake callbacks, not cryptographic evidence."""

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from offline_session import completion, exchange
from completion_test_support import alice_packet, completion_accepted, released_bob


class CompletionReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.released_fixture = released_bob()
        cls.replacement_fixture = alice_packet()
        old = json.loads(cls.replacement_fixture)
        old["signature_hex"] = "00" * 64
        cls.old_fixture = exchange.canonical(old)

    def setUp(self):
        self.released = copy.deepcopy(self.released_fixture)
        self.replacement = self.replacement_fixture
        self.old = self.old_fixture
        self.observed = completion.observe_bob(self.released, self.old)
        self.digest = completion.observation_digest(self.old)

    def reconcile(self, *, state=None, packet=None, digest=None, recoverer=completion_accepted):
        return completion.reconcile_bob(
            self.observed if state is None else state,
            self.replacement if packet is None else packet,
            expected_observation_digest=self.digest if digest is None else digest,
            recoverer=recoverer,
        )

    def test_observation_digest_binds_exact_nonempty_bounded_bytes_with_its_domain(self):
        expected = hashlib.sha256(b"PTLC/completion-observation/v1\x00" + self.old).hexdigest()
        self.assertEqual(self.digest, expected)
        self.assertNotEqual(self.digest, hashlib.sha256(self.old).hexdigest())
        self.assertNotEqual(self.digest, completion.observation_digest(self.old + b"\n"))
        self.assertEqual(len(completion.observation_digest(b"x" * completion.MAX_PACKET_BYTES)), 64)
        for packet in (None, True, "x", bytearray(b"x"), b"", b"x" * (completion.MAX_PACKET_BYTES + 1)):
            with self.subTest(kind=type(packet).__name__), self.assertRaises(exchange.ExchangeError):
                completion.observation_digest(packet)

    def test_reconciliation_archives_exact_old_packet_and_seals_replacement_output(self):
        before = exchange.canonical(self.observed)
        requests = []
        def recover(request):
            requests.append(copy.deepcopy(request))
            return completion_accepted(request)
        recorded, output = self.reconcile(recoverer=recover)
        self.assertEqual(exchange.canonical(self.observed), before)
        self.assertEqual(recorded["stage"], "BTC_COMPLETION_RECORDED")
        self.assertEqual(recorded["superseded_zenon_completion_packet_hex"], self.old.hex())
        self.assertEqual(recorded["zenon_completion_packet_hex"], self.replacement.hex())
        self.assertTrue(recorded["release_may_have_escaped"])
        self.assertEqual(recorded["release_hex"], self.observed["release_hex"])
        self.assertEqual(recorded["verification_receipts"], self.observed["verification_receipts"])
        request = completion.bob_request(self.released, self.replacement)
        self.assertEqual(requests, [request])
        self.assertEqual(recorded["completion_receipt_hex"], completion.request_digest(request))
        self.assertEqual(completion.replay_bob(recorded), output)
        self.assertEqual(exchange.replay(recorded), exchange.replay(self.observed))
        exchange.validate_state(recorded)

    def test_only_released_state_with_a_retained_candidate_can_reconcile(self):
        completed, _ = self.reconcile()
        early = exchange.start(exchange.contexts(self.released)[0])
        calls = []
        for state in (early, self.released, completed, {}, [], None):
            with self.subTest(stage=state.get("stage") if type(state) is dict else type(state).__name__), \
                    self.assertRaises(exchange.ExchangeError):
                completion.reconcile_bob(state, self.replacement,
                    expected_observation_digest=self.digest, recoverer=lambda request: calls.append(request))
        self.assertEqual(calls, [])

    def test_stale_or_malformed_compare_and_swap_digest_never_invokes_recovery(self):
        before = exchange.canonical(self.observed)
        calls = []
        for digest in (None, True, 1, b"00" * 32, "", "00", "00" * 32,
                       self.digest.upper(), self.digest + "0", completion.observation_digest(self.replacement)):
            with self.subTest(kind=type(digest).__name__), self.assertRaises(exchange.ExchangeError):
                completion.reconcile_bob(self.observed, self.replacement,
                    expected_observation_digest=digest, recoverer=lambda request: calls.append(request))
            self.assertEqual(exchange.canonical(self.observed), before)
        self.assertEqual(calls, [])

    def test_same_candidate_and_ordinary_implicit_replacement_are_rejected(self):
        calls = []
        with self.assertRaises(exchange.ExchangeError):
            self.reconcile(packet=self.old, recoverer=lambda request: calls.append(request))
        with self.assertRaises(exchange.ExchangeError):
            completion.observe_bob(self.observed, self.replacement)
        with self.assertRaises(exchange.ExchangeError):
            completion.complete_bob(self.observed, self.replacement, lambda request: calls.append(request))
        self.assertEqual(calls, [])
        self.assertEqual(self.observed["zenon_completion_packet_hex"], self.old.hex())
        self.assertIsNone(self.observed["superseded_zenon_completion_packet_hex"])

    def test_replacement_requires_canonical_packet_and_strict_input_bounds(self):
        value = json.loads(self.replacement)
        malformed = (None, True, bytearray(self.replacement), self.replacement.decode("ascii"), b"",
                     b"\xff", b"{}", b" " + self.replacement, self.replacement + b"\n",
                     self.replacement + b"{}", json.dumps(value, indent=2).encode("ascii"),
                     b"x" * (completion.MAX_PACKET_BYTES + 1),
                     b"[" * 1500 + b"0" + b"]" * 1500,
                     self.replacement[:-1] + b',"sender_role":"alice"}')
        calls = []
        for packet in malformed:
            with self.subTest(kind=type(packet).__name__), self.assertRaises(exchange.ExchangeError):
                completion.reconcile_bob(self.observed, packet,
                    expected_observation_digest=self.digest, recoverer=lambda request: calls.append(request))
        self.assertEqual(calls, [])

    def test_nonbytes_replacement_is_rejected_before_custom_equality_can_run(self):
        before = exchange.canonical(self.observed)
        equality_calls, recovery_calls = [], []
        class HostilePacket:
            def __eq__(self, _):
                equality_calls.append(True)
                raise RuntimeError("synthetic equality side effect")
        with self.assertRaises(exchange.ExchangeError):
            self.reconcile(packet=HostilePacket(), recoverer=lambda request: recovery_calls.append(request))
        self.assertEqual(equality_calls, [])
        self.assertEqual(recovery_calls, [])
        self.assertEqual(exchange.canonical(self.observed), before)

    def test_replacement_cannot_change_roles_binding_round_or_integer_types(self):
        value = json.loads(self.replacement)
        mutations = [{**value, "schema": "future"}, {**value, "sender_role": "bob"},
                     {**value, "recipient_role": "alice"}, {**value, "extra": "field"},
                     {**value, "signature_hex": "00"}, {**value, "signature_hex": "AA" * 64}]
        for field in ("session_id", "nonce_round_digest_hex", "binding_digest_hex"):
            changed = copy.deepcopy(value)
            changed["context"][field] = "99" * 32
            mutations.append(changed)
        changed = copy.deepcopy(value)
        changed["context"]["binding"]["binding"]["point_type"] = True
        mutations.append(changed)
        calls = []
        for value in mutations:
            with self.assertRaises(exchange.ExchangeError):
                self.reconcile(packet=exchange.canonical(value), recoverer=lambda request: calls.append(request))
        self.assertEqual(calls, [])

    def test_recovery_failures_leave_exact_original_candidate_and_history_untouched(self):
        before = exchange.canonical(self.observed)
        for error in (RuntimeError("synthetic"), TimeoutError("synthetic"),
                      KeyboardInterrupt("synthetic"), SystemExit("synthetic")):
            def failed(_, exception=error):
                raise exception
            with self.subTest(error=type(error).__name__), self.assertRaises(exchange.ExchangeError):
                self.reconcile(recoverer=failed)
            self.assertEqual(exchange.canonical(self.observed), before)
        with self.assertRaises(exchange.ExchangeError):
            self.reconcile(recoverer=None)
        self.assertEqual(exchange.canonical(self.observed), before)

    def test_only_exact_success_result_bound_to_replacement_can_finalize(self):
        before = exchange.canonical(self.observed)
        request = completion.bob_request(self.released, self.replacement)
        good = completion_accepted(request)
        old_receipt = completion.request_digest(completion.bob_request(self.observed, self.old))
        bad = (None, True, {}, {**good, "valid": 1}, {**good, "valid": False},
               {**good, "schema": None}, {**good, "unknown": "field"},
               {**good, "request_digest_hex": old_receipt}, {**good, "request_digest_hex": "00" * 32},
               {**good, "bitcoin_signature_hex": ""}, {**good, "bitcoin_signature_hex": "AA" * 64})
        for result in bad:
            with self.assertRaises(exchange.ExchangeError):
                self.reconcile(recoverer=lambda _: result)
            self.assertEqual(exchange.canonical(self.observed), before)

    def test_callback_request_mutation_cannot_rebind_retained_inputs(self):
        before = exchange.canonical(self.observed)
        def accepted_then_mutated(request):
            result = completion_accepted(request)
            request["zenon"]["partial_signatures_hex"].clear()
            request["bitcoin"]["message_hex"] = "00" * 32
            request["zenon_signature_hex"] = "00" * 64
            return result
        recorded, _ = self.reconcile(recoverer=accepted_then_mutated)
        exchange.validate_state(recorded)
        self.assertEqual(recorded["zenon_completion_packet_hex"], self.replacement.hex())
        self.assertEqual(exchange.canonical(self.observed), before)
        def mutated_then_accepted(request):
            request["zenon_signature_hex"] = "00" * 64
            return completion_accepted(request)
        with self.assertRaises(exchange.ExchangeError):
            self.reconcile(recoverer=mutated_then_accepted)
        self.assertEqual(exchange.canonical(self.observed), before)

    def test_callback_cannot_change_the_private_reconciliation_snapshot(self):
        before = copy.deepcopy(self.observed)
        def mutate_callers_state(request):
            self.observed.clear()
            return completion_accepted(request)
        recorded, _ = self.reconcile(recoverer=mutate_callers_state)
        self.assertEqual(self.observed, {})
        self.assertEqual(recorded["release_hex"], before["release_hex"])
        self.assertEqual(recorded["verification_receipts"], before["verification_receipts"])
        self.assertEqual(recorded["superseded_zenon_completion_packet_hex"], self.old.hex())
        exchange.validate_state(recorded)

    def test_normal_completion_has_no_superseded_candidate(self):
        recorded, _ = completion.complete_bob(self.observed, self.old, completion_accepted)
        self.assertIsNone(recorded["superseded_zenon_completion_packet_hex"])
        exchange.validate_state(recorded)

    def test_history_is_required_in_schema_and_forbidden_before_finalization(self):
        for state in (self.released, self.observed, exchange.start(exchange.contexts(self.released)[0])):
            changed = copy.deepcopy(state)
            del changed["superseded_zenon_completion_packet_hex"]
            with self.assertRaises(exchange.ExchangeError):
                exchange.validate_state(changed)
            changed = copy.deepcopy(state)
            changed["superseded_zenon_completion_packet_hex"] = self.old.hex()
            with self.assertRaises(exchange.ExchangeError):
                exchange.validate_state(changed)

    def test_historical_packet_requires_canonical_exact_context_and_distinct_bytes(self):
        recorded, _ = self.reconcile()
        bad = [True, [], {}, "", "AA", "0", "00", self.replacement.hex(),
               (self.old + b"\n").hex(), "00" * (completion.MAX_PACKET_BYTES + 1)]
        for field in ("session_id", "nonce_round_digest_hex", "binding_digest_hex"):
            value = json.loads(self.old)
            value["context"][field] = "99" * 32
            bad.append(exchange.canonical(value).hex())
        value = json.loads(self.old)
        value["context"]["binding"]["binding"]["point_type"] = True
        bad.append(exchange.canonical(value).hex())
        value = json.loads(self.old)
        value["sender_role"] = "bob"
        bad.append(exchange.canonical(value).hex())
        for historical in bad:
            changed = copy.deepcopy(recorded)
            changed["superseded_zenon_completion_packet_hex"] = historical
            with self.subTest(kind=type(historical).__name__), self.assertRaises(exchange.ExchangeError):
                exchange.validate_state(changed)

    def test_archived_packet_counts_toward_overall_state_size_bound(self):
        recorded, _ = self.reconcile()
        without_history = copy.deepcopy(recorded)
        without_history["superseded_zenon_completion_packet_hex"] = None
        bound = len(exchange.canonical(without_history)) + 1
        self.assertGreater(len(exchange.canonical(recorded)), bound)
        with patch.object(exchange, "MAX_EXCHANGE_BYTES", bound):
            exchange.validate_state(without_history)
            with self.assertRaises(exchange.ExchangeError):
                exchange.validate_state(recorded)

    def test_final_state_cannot_replace_or_reconcile_again(self):
        recorded, output = self.reconcile()
        before = exchange.canonical(recorded)
        calls = []
        with self.assertRaises(exchange.ExchangeError):
            self.reconcile(state=recorded, packet=self.old,
                           digest=completion.observation_digest(self.replacement),
                           recoverer=lambda request: calls.append(request))
        with self.assertRaises(exchange.ExchangeError):
            completion.complete_bob(recorded, self.replacement, lambda request: calls.append(request))
        with self.assertRaises(exchange.ExchangeError):
            completion.observe_bob(recorded, self.old)
        self.assertEqual(calls, [])
        self.assertEqual(exchange.canonical(recorded), before)
        self.assertEqual(completion.replay_bob(recorded), output)

    def test_fake_callback_acceptance_is_not_signature_validity_or_audit_attestation(self):
        value = json.loads(self.replacement)
        value["signature_hex"] = "11" * 64
        packet = exchange.canonical(value)
        recorded, _ = self.reconcile(packet=packet)
        self.assertEqual(recorded["zenon_completion_packet_hex"], packet.hex())
        self.assertEqual(recorded["superseded_zenon_completion_packet_hex"], self.old.hex())
        # Shape/hash reload checks do not rerun cryptography or certify the old packet.
        exchange.validate_state(recorded)


if __name__ == "__main__":
    unittest.main()
