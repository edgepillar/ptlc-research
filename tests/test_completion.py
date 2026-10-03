"""Pure completion sequencing with explicit fake cryptographic callbacks."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from offline_session import completion, exchange
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.public_worker import WorkerError
from offline_session.transcript import _restore, signing_context
from exchange_test_support import accepted, artifacts
from completion_test_support import (
    alice_context, alice_packet, alice_ready, bob_release, completion_accepted,
    final_signatures, released_bob,
)


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.terms, self.btc, self.znn, self.btc_bundle, self.znn_bundle = artifacts()
        self.context = alice_context()
        self.signature, self.bitcoin_signature = final_signatures()
        self.own_partial = self.znn_bundle["partial_signatures_hex"][0]
        self.initial = completion.start(self.context, self.own_partial, accepted)
        self.released = released_bob()
        self.release = exchange.replay(self.released)
        self.ready = completion.accept_release(self.initial, self.release, accepted)
        self.consumed = completion.consume(self.ready)

    def test_alice_exact_sequence_context_and_replay(self):
        self.assertEqual(self.initial["stage"], "ALICE_PARTIAL_RETAINED")
        self.assertFalse(self.initial["possible_exposure"])
        self.assertEqual(self.ready["stage"], "PRESIGNATURE_RETAINED")
        self.assertFalse(self.ready["possible_exposure"])
        self.assertEqual(self.consumed["stage"], "COMPLETION_CONSUMED")
        self.assertTrue(self.consumed["possible_exposure"])
        recorded, packet = completion.record(self.consumed, self.signature, completion_accepted)
        completion.validate_state(recorded)
        expected_context = completion.recontext(self.context, "alice", "zenon-claim-complete")
        self.assertEqual(json.loads(packet), {
            "schema": "ptlc-alice-zenon-completion-v1", "sender_role": "alice", "recipient_role": "bob",
            "context": expected_context.as_dict(), "signature_hex": self.signature.hex(),
        })
        self.assertEqual(completion.replay(recorded), packet)
        self.assertTrue(recorded["possible_exposure"])
        self.assertEqual(self.consumed["stage"], "COMPLETION_CONSUMED")

    def test_consumption_recovery_is_monotonic_and_cannot_restart_or_record(self):
        unknown = completion.recover(self.consumed)
        self.assertEqual(unknown["stage"], "OUTCOME_UNKNOWN")
        self.assertTrue(unknown["possible_exposure"])
        self.assertEqual(completion.recover(unknown), unknown)
        self.assertEqual(completion.recover(self.ready), self.ready)
        for state in (self.initial, self.ready, self.consumed, unknown):
            with self.assertRaises(exchange.ExchangeError):
                completion.replay(state)
        for state in (self.initial, self.consumed, unknown):
            with self.assertRaises(exchange.ExchangeError):
                completion.consume(state)
        for state in (self.initial, self.ready, unknown):
            with self.assertRaises(exchange.ExchangeError):
                completion.record(state, self.signature, completion_accepted)
        with self.assertRaises(exchange.ExchangeError):
            completion.accept_release(unknown, self.release, accepted)
        self.assertEqual(self.consumed["stage"], "COMPLETION_CONSUMED")

    def test_start_requires_alice_dynamic_zenon_partial_and_verified_own_bytes(self):
        binding = _restore(self.context.as_dict()["binding"])
        nonce_round = _restore(self.context.as_dict()["nonce_round"])
        invalid = (None, self.znn, self.btc, self.context.as_dict(),
                   signing_context(binding, "alice", "zenon-claim-partial"),
                   signing_context(binding, "alice", "zenon-claim-complete", nonce_round=nonce_round))
        for context in invalid:
            with self.subTest(kind=type(context).__name__), self.assertRaises(exchange.ExchangeError):
                completion.start(context, self.own_partial, accepted)
        for partial in (None, True, b"bytes", "00", "AA" * 32):
            with self.assertRaises(exchange.ExchangeError):
                completion.start(self.context, partial, accepted)
        with self.assertRaises(exchange.ExchangeError):
            completion.start(self.context, self.own_partial, lambda _: None)
        self.assertEqual(self.initial["own_partial_hex"], self.own_partial)

    def test_release_requires_canonical_version_two_packet_and_strict_boundaries(self):
        value = json.loads(self.release)
        malformed = [None, bytearray(self.release), self.release.decode("ascii"), b"", b"\xff", b"{}",
                     b" " + self.release, self.release + b"\n", self.release + b"{}",
                     json.dumps(value, indent=2).encode("ascii"), b"x" * (completion.MAX_PACKET_BYTES + 1),
                     b"[" * 1500 + b"0" + b"]" * 1500,
                     self.release[:-1] + b',"sender_role":"bob"}']
        for change in ({"schema": "ptlc-bob-zenon-release-v1"}, {"sender_role": "alice"},
                       {"recipient_role": "bob"}, {"unknown": "field"}, {"partial_signatures_hex": []},
                       {"context": self.context.as_dict()}, {"adaptor_presignature_hex": "00"}):
            malformed.append(exchange.canonical({**value, **change}))
        removed = copy.deepcopy(value)
        del removed["partial_signatures_hex"]
        malformed.append(exchange.canonical(removed))
        called = []
        for packet in malformed:
            with self.subTest(kind=type(packet).__name__), self.assertRaises(exchange.ExchangeError):
                completion.accept_release(self.initial, packet, lambda request: called.append(request))
        self.assertEqual(called, [])
        self.assertEqual(self.initial["stage"], "ALICE_PARTIAL_RETAINED")

    def test_release_cannot_replace_own_partial_or_change_binding_round_or_roles(self):
        value = json.loads(self.release)
        mutations = []
        replaced = copy.deepcopy(value)
        replaced["partial_signatures_hex"][0] = "00" * 32
        mutations.append(replaced)
        for field in ("session_id", "nonce_round_digest_hex", "binding_digest_hex"):
            changed = copy.deepcopy(value)
            changed["context"][field] = "99" * 32
            mutations.append(changed)
        swapped = copy.deepcopy(value)
        swapped["partial_signatures_hex"].reverse()
        mutations.append(swapped)
        for packet in mutations:
            with self.assertRaises(exchange.ExchangeError):
                completion.accept_release(self.initial, exchange.canonical(packet), accepted)
        with self.assertRaises(exchange.ExchangeError):
            completion.accept_release(self.initial, self.release, lambda _: None)

    def test_packet_context_equality_does_not_accept_boolean_for_integer_fields(self):
        release = json.loads(self.release)
        release["context"]["binding"]["binding"]["point_type"] = True
        with self.subTest(recipient="alice"), self.assertRaises(exchange.ExchangeError):
            completion.accept_release(self.initial, exchange.canonical(release), accepted)
        packet = json.loads(alice_packet())
        packet["context"]["binding"]["binding"]["point_type"] = True
        with self.subTest(recipient="bob"), self.assertRaises(exchange.ExchangeError):
            completion.observe_bob(self.released, exchange.canonical(packet))

    def test_failed_completion_result_does_not_erase_consumption_or_exposure(self):
        request = completion._request(self.znn, self.znn_bundle, self.signature.hex())
        good = completion_accepted(request)
        bad_results = (None, True, {}, {**good, "valid": 1}, {**good, "valid": False},
                       {**good, "request_digest_hex": "00" * 32}, {**good, "unknown": "field"},
                       {**good, "schema": None}, {**good, "bitcoin_signature_hex": self.bitcoin_signature.hex()})
        for result in bad_results:
            with self.subTest(result=result), self.assertRaises(exchange.ExchangeError):
                completion.record(self.consumed, self.signature, lambda _: result)
            self.assertTrue(self.consumed["possible_exposure"])
            self.assertEqual(self.consumed["stage"], "COMPLETION_CONSUMED")
        for error in (RuntimeError("synthetic"), KeyboardInterrupt("synthetic")):
            def failed(_, exception=error):
                raise exception
            with self.assertRaises(exchange.ExchangeError):
                completion.record(self.consumed, self.signature, failed)
        for signature in (None, self.signature.hex(), bytearray(self.signature), self.signature[:-1], self.signature + b"x"):
            with self.assertRaises(exchange.ExchangeError):
                completion.record(self.consumed, signature, completion_accepted)

    def test_verifier_mutation_cannot_change_retained_inputs_or_bind_a_stale_result(self):
        def accepted_then_mutated(request):
            result = completion_accepted(request)
            request["zenon"]["message_hex"] = "00" * 32
            request["zenon_signature_hex"] = "00" * 64
            return result
        recorded, _ = completion.record(self.consumed, self.signature, accepted_then_mutated)
        self.assertEqual(recorded["signature_hex"], self.signature.hex())
        completion.validate_state(recorded)
        def mutated_then_accepted(request):
            request["zenon_signature_hex"] = "00" * 64
            return completion_accepted(request)
        with self.assertRaises(exchange.ExchangeError):
            completion.record(self.consumed, self.signature, mutated_then_accepted)

    def test_alice_state_checks_required_artifacts_receipts_exposure_and_bounds(self):
        recorded, _ = completion.record(self.consumed, self.signature, completion_accepted)
        mutations = []
        for state, field, value in ((self.initial, "release_packet_hex", self.release.hex()),
                                    (self.ready, "release_packet_hex", None),
                                    (self.consumed, "possible_exposure", False),
                                    (self.ready, "possible_exposure", True),
                                    (recorded, "signature_hex", None),
                                    (recorded, "completion_packet_hex", "00"),
                                    (recorded, "release_packet_hex", "AA"),
                                    (recorded, "own_partial_hex", "00" * 32),
                                    (recorded, "verification_receipts", {}),
                                    (recorded, "stage", "FUTURE")):
            changed = copy.deepcopy(state)
            changed[field] = value
            mutations.append(changed)
        mutations.extend((None, [], {"extra": "x" * 64001}, {"extra": 2 ** 256}, {"extra": object()}))
        for state in mutations:
            with self.subTest(kind=type(state).__name__), self.assertRaises(exchange.ExchangeError):
                completion.validate_state(state)

    def test_bob_observation_retains_exact_candidate_before_public_completion(self):
        _, packet = completion.record(self.consumed, self.signature, completion_accepted)
        observed = completion.observe_bob(self.released, packet)
        self.assertEqual(observed["stage"], "RELEASE_RECORDED")
        self.assertEqual(observed["zenon_completion_packet_hex"], packet.hex())
        self.assertIsNone(observed["bitcoin_completion_packet_hex"])
        exchange.validate_state(observed)
        self.assertEqual(completion.observe_bob(observed, packet), observed)
        request = completion.bob_request(observed, packet)
        self.assertEqual(request["kind"], "recover-bitcoin")
        self.assertEqual(request["bitcoin"], exchange.verification_request(self.btc, bundle=self.btc_bundle))
        self.assertEqual(request["zenon"], exchange.verification_request(self.znn, bundle=self.znn_bundle))
        self.assertEqual(request["zenon_signature_hex"], self.signature.hex())
        recorded, bitcoin_packet = completion.complete_bob(observed, packet, completion_accepted)
        self.assertEqual(recorded["stage"], "BTC_COMPLETION_RECORDED")
        self.assertEqual(completion.replay_bob(recorded), bitcoin_packet)
        expected = completion.recontext(self.btc, "bob", "bitcoin-claim-complete")
        self.assertEqual(json.loads(bitcoin_packet), {
            "schema": "ptlc-bob-bitcoin-completion-v1", "context": expected.as_dict(),
            "signature_hex": self.bitcoin_signature.hex(),
        })
        self.assertEqual(exchange.replay(recorded), self.release)
        with self.assertRaises(exchange.ExchangeError):
            completion.complete_bob(recorded, packet, completion_accepted)

    def test_bob_pinned_observation_cannot_be_replaced_even_after_rejection(self):
        packet = alice_packet()
        bad = json.loads(packet)
        bad["signature_hex"] = "00" * 64
        bad = exchange.canonical(bad)
        observed = completion.observe_bob(self.released, bad)
        # Structural retention deliberately precedes cryptographic acceptance.
        self.assertEqual(observed["zenon_completion_packet_hex"], bad.hex())
        with self.assertRaises(exchange.ExchangeError):
            completion.complete_bob(observed, bad, lambda _: None)
        with self.assertRaises(exchange.ExchangeError):
            completion.observe_bob(observed, packet)
        with self.assertRaises(exchange.ExchangeError):
            completion.complete_bob(observed, packet, completion_accepted)
        self.assertIsNone(observed["bitcoin_completion_packet_hex"])

    def test_bob_rejects_wrong_packet_roles_context_and_syntax_before_recovery(self):
        packet = json.loads(alice_packet())
        mutations = [{**packet, "schema": "future"}, {**packet, "sender_role": "bob"},
                     {**packet, "recipient_role": "alice"}, {**packet, "signature_hex": "00"},
                     {**packet, "context": self.znn.as_dict()}, {**packet, "extra": "field"}]
        for field in ("session_id", "nonce_round_digest_hex", "binding_digest_hex"):
            changed = copy.deepcopy(packet)
            changed["context"][field] = "00" * 32
            mutations.append(changed)
        for value in mutations:
            with self.assertRaises(exchange.ExchangeError):
                completion.observe_bob(self.released, exchange.canonical(value))
        with self.assertRaises(exchange.ExchangeError):
            completion.bob_request(self.released, exchange.canonical(packet) + b"\n")
        early = exchange.start(self.btc)
        with self.assertRaises(exchange.ExchangeError):
            completion.observe_bob(early, exchange.canonical(packet))

    def test_bob_result_requires_bound_exact_shape_and_public_signature_encoding(self):
        packet = alice_packet()
        request = completion.bob_request(self.released, packet)
        good = completion_accepted(request)
        for result in (None, True, {}, {**good, "valid": 1}, {**good, "schema": "future"},
                       {**good, "request_digest_hex": "00" * 32}, {**good, "bitcoin_signature_hex": ""},
                       {**good, "bitcoin_signature_hex": "AA" * 64}, {**good, "extra": "field"}):
            with self.assertRaises(exchange.ExchangeError):
                completion.complete_bob(self.released, packet, lambda _: result)
        def changed(request):
            request["bitcoin"]["message_hex"] = "00" * 32
            return completion_accepted(request)
        with self.assertRaises(exchange.ExchangeError):
            completion.complete_bob(self.released, packet, changed)
        self.assertEqual(self.released["stage"], "RELEASE_RECORDED")

    def test_bob_stored_result_requires_matching_observation_output_and_receipt(self):
        recorded, _ = completion.complete_bob(self.released, alice_packet(), completion_accepted)
        for field, value in (("completion_receipt_hex", "00" * 32),
                             ("bitcoin_completion_packet_hex", "00"),
                             ("zenon_completion_packet_hex", None),
                             ("release_may_have_escaped", False),
                             ("stage", "RELEASE_RECORDED")):
            changed = copy.deepcopy(recorded)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(exchange.ExchangeError):
                exchange.validate_state(changed)
        changed = copy.deepcopy(recorded)
        packet = json.loads(bytes.fromhex(changed["bitcoin_completion_packet_hex"]))
        packet["context"]["binding_digest_hex"] = "00" * 32
        changed["bitcoin_completion_packet_hex"] = exchange.canonical(packet).hex()
        with self.assertRaises(exchange.ExchangeError):
            exchange.validate_state(changed)

    def test_fake_callbacks_are_not_final_signature_or_extraction_proof(self):
        # Actual curve/signature/extraction checks are in the separate Rust path.
        fake_recorded, packet = completion.record(self.consumed, b"\x00" * 64, completion_accepted)
        completion.validate_state(fake_recorded)
        result, _ = completion.complete_bob(self.released, packet, completion_accepted)
        exchange.validate_state(result)
        self.assertEqual(fake_recorded["signature_hex"], "00" * 64)


class CompletionAdapterTests(unittest.TestCase):
    def setUp(self):
        self.request = completion.bob_request(released_bob(), alice_packet())
        self.result = completion_accepted(self.request)
        with patch("offline_session.artifact_verifier.Path.is_file", return_value=True), \
                patch("offline_session.artifact_verifier.os.access", return_value=True):
            self.verifier = SubprocessCompletion(Path.cwd() / "synthetic-completion", timeout=1)

    def run_with(self, response, returncode=0):
        def process(executable, request, **kwargs):
            self.assertEqual(executable, self.verifier._executable)
            self.assertEqual(request, exchange.canonical(self.request))
            self.assertEqual(kwargs["timeout"], 1)
            self.assertEqual(kwargs["max_input_bytes"], 65536)
            self.assertEqual(kwargs.get("max_output_bytes", 4096), 4096)
            if returncode:
                raise WorkerError("synthetic worker rejection")
            return response
        with patch("offline_session.completion_verifier.run_public_worker", side_effect=process):
            return self.verifier(self.request)

    def test_canonical_success_binds_complete_public_request(self):
        for suffix in (b"", b"\n"):
            self.assertEqual(self.run_with(exchange.canonical(self.result) + suffix), self.result)
        self.assertNotIn("witness", self.result)

    def test_malformed_noncanonical_deep_or_unbound_responses_fail(self):
        raw = exchange.canonical(self.result)
        bad = [b"", b"\xff", b"{}", raw + b"\n\n", b" " + raw, b"x" * 4097,
               b"[" * 1500 + b"0" + b"]" * 1500, raw[:-1] + b',"valid":true}',
               exchange.canonical({**self.result, "valid": 1}),
               exchange.canonical({**self.result, "request_digest_hex": "00" * 32}),
               exchange.canonical({**self.result, "bitcoin_signature_hex": "AA" * 64}),
               exchange.canonical({**self.result, "extra": "field"})]
        for response in bad:
            with self.subTest(size=len(response)), self.assertRaises(exchange.ExchangeError):
                self.run_with(response)
        with self.assertRaises(exchange.ExchangeError):
            self.run_with(raw, returncode=1)

    def test_timeout_and_oversized_request_reject_without_unsanitized_details(self):
        for error in (WorkerError("synthetic worker detail"), OSError("synthetic worker detail")):
            with patch("offline_session.completion_verifier.run_public_worker", side_effect=error), \
                    self.assertRaisesRegex(completion.CompletionError, "public completion executable failed"):
                self.verifier(self.request)
        with patch("offline_session.completion_verifier.run_public_worker") as run:
            with self.assertRaises(exchange.ExchangeError):
                self.verifier({"value": "x" * 65537})
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
