"""Pure artifact ordering tests use an explicit mock, not cryptographic evidence."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from offline_session import exchange
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.public_worker import WorkerError
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round,
    nonce_commitment, reveal_nonce_round, signing_context,
)
from exchange_test_support import accepted, artifacts


class ArtifactExchangeTests(unittest.TestCase):
    def setUp(self):
        self.terms, self.btc, self.znn, self.btc_bundle, self.znn_bundle = artifacts()
        self.start = exchange.start(self.btc)

    def stages(self):
        states = [self.start]
        states.append(exchange.retain_bitcoin(states[-1], self.btc_bundle, accepted))
        states.append(exchange.bind_zenon(states[-1], self.znn))
        states.append(exchange.retain_alice_partial(
            states[-1], self.znn_bundle["partial_signatures_hex"][0], accepted))
        states.append(exchange.retain_zenon(states[-1], self.znn_bundle, accepted))
        states.append(exchange.release(states[-1])[0])
        return states

    def test_exact_happy_sequence_retains_complete_public_context_before_release(self):
        states = self.stages()
        self.assertEqual([state["stage"] for state in states], [
            "BITCOIN_BOUND", "BITCOIN_RETAINED", "ZENON_BOUND", "ALICE_PARTIAL_RETAINED",
            "ZENON_RETAINED", "RELEASE_RECORDED",
        ])
        for state in states:
            exchange.validate_state(state)
        before = states[-2]
        self.assertEqual(before["zenon_bundle"], self.znn_bundle)
        self.assertEqual(before["zenon_context"], self.znn.as_dict())
        self.assertEqual(before["bitcoin_bundle"], self.btc_bundle)
        self.assertFalse(before["release_may_have_escaped"])
        final, output = exchange.release(before)
        self.assertEqual(final, states[-1])
        self.assertEqual(exchange.replay(final), output)
        payload = json.loads(output)
        self.assertEqual(payload, {
            "schema": "ptlc-bob-zenon-release-v2", "sender_role": "bob", "recipient_role": "alice",
            "context": self.znn.as_dict(),
            "adaptor_presignature_hex": self.znn_bundle["adaptor_presignature_hex"],
            "partial_signatures_hex": self.znn_bundle["partial_signatures_hex"],
        })
        self.assertEqual(output, exchange.canonical(payload))
        self.assertTrue(final["release_may_have_escaped"])
        self.assertEqual(before["stage"], "ZENON_RETAINED")

    def test_every_transition_rejects_wrong_predecessor_without_verifier_calls(self):
        states = self.stages()
        called = []
        def verifier(request):
            called.append(request)
            return accepted(request)
        actions = (
            lambda state: exchange.retain_bitcoin(state, self.btc_bundle, verifier),
            lambda state: exchange.bind_zenon(state, self.znn),
            lambda state: exchange.retain_alice_partial(state, self.znn_bundle["partial_signatures_hex"][0], verifier),
            lambda state: exchange.retain_zenon(state, self.znn_bundle, verifier),
            exchange.release,
            exchange.replay,
        )
        for expected, action in enumerate(actions):
            for actual, state in enumerate(states):
                if expected == actual:
                    continue
                snapshot = copy.deepcopy(state)
                with self.subTest(action=expected, stage=actual), self.assertRaises(exchange.ExchangeError):
                    action(state)
                self.assertEqual(state, snapshot)
        self.assertEqual(called, [])

    def test_request_inputs_are_derived_from_the_reconstructed_context(self):
        for context, bundle, leg in ((self.btc, self.btc_bundle, "bitcoin"),
                                     (self.znn, self.znn_bundle, "zenon")):
            request = exchange.verification_request(context, bundle=bundle)
            terms = self.terms.as_dict()["terms"]
            self.assertEqual(request["context_digest_hex"], context.digest_hex)
            self.assertEqual(request["leg"], leg)
            self.assertEqual(request["signer_keys_sec1_hex"], terms[leg]["signer_keys_sec1_hex"])
            self.assertEqual(request["adaptor_point_sec1_hex"], terms["adaptor_point_sec1_hex"])
            self.assertEqual(request["partial_signatures_hex"], bundle["partial_signatures_hex"])
            self.assertEqual(request["public_nonces_hex"], list(context.as_dict()["nonce_round"]["public_nonces"].values()))
            if leg == "bitcoin":
                self.assertEqual(request["taproot_merkle_root_hex"], terms[leg]["tapleaf_hash_hex"])
            else:
                self.assertEqual(request["taproot_merkle_root_hex"], "")
            request["partial_signatures_hex"][0] = "00" * 32
            request["signer_keys_sec1_hex"][0] = "00" * 33
            self.assertNotEqual(request["partial_signatures_hex"], bundle["partial_signatures_hex"])
            exchange.validate_state(exchange.start(self.btc))
        partial = self.znn_bundle["partial_signatures_hex"][0]
        request = exchange.verification_request(self.znn, alice_partial=partial)
        self.assertEqual(request["kind"], "alice-partial")
        self.assertEqual(request["partial_signatures_hex"], [partial])
        self.assertEqual(request["adaptor_presignature_hex"], "")
        for kwargs in ({}, {"bundle": self.btc_bundle, "alice_partial": partial}):
            with self.assertRaises(exchange.ExchangeError):
                exchange.verification_request(self.btc, **kwargs)

    def test_failed_and_malformed_verifier_results_never_advance_state(self):
        good = accepted(exchange.verification_request(self.btc, bundle=self.btc_bundle))
        invalid = [None, True, 1, [], {}, {**good, "valid": False}, {**good, "valid": 1},
                   {**good, "request_digest_hex": "00" * 32}, {**good, "schema": "future"},
                   {**good, "extra": "field"}]
        for result in invalid:
            state = copy.deepcopy(self.start)
            with self.subTest(result=result), self.assertRaises(exchange.VerificationError):
                exchange.retain_bitcoin(state, self.btc_bundle, lambda _: result)
            self.assertEqual(state, self.start)
        for verifier in (None, "verifier", 1):
            with self.assertRaises(exchange.VerificationError):
                exchange.retain_bitcoin(self.start, self.btc_bundle, verifier)
        def failed(_):
            raise RuntimeError("synthetic verifier failure")
        with self.assertRaises(exchange.VerificationError):
            exchange.retain_bitcoin(self.start, self.btc_bundle, failed)
        self.assertEqual(self.start["stage"], "BITCOIN_BOUND")

    def test_verifier_receives_defensive_copy_and_mutated_receipt_is_rejected(self):
        def mutate_after_accept(request):
            result = accepted(request)
            request["partial_signatures_hex"][0] = "00" * 32
            request["signer_keys_sec1_hex"].clear()
            return result
        retained = exchange.retain_bitcoin(self.start, self.btc_bundle, mutate_after_accept)
        self.assertEqual(retained["bitcoin_bundle"], self.btc_bundle)
        exchange.validate_state(retained)
        def mutate_before_accept(request):
            request["message_hex"] = "00" * 32
            return accepted(request)
        with self.assertRaises(exchange.VerificationError):
            exchange.retain_bitcoin(self.start, self.btc_bundle, mutate_before_accept)
        self.assertEqual(self.start["stage"], "BITCOIN_BOUND")

    def test_alice_partial_cannot_be_replaced_by_later_bundle(self):
        state = self.stages()[3]
        changed = copy.deepcopy(self.znn_bundle)
        changed["partial_signatures_hex"][0] = "00" * 32
        called = []
        with self.assertRaises(exchange.ExchangeError):
            exchange.retain_zenon(state, changed, lambda request: called.append(request))
        self.assertEqual(called, [])
        self.assertEqual(state["alice_partial_hex"], self.znn_bundle["partial_signatures_hex"][0])

    def test_malformed_bundles_and_partials_are_rejected_before_verification(self):
        malformed = [None, [], {}, {**self.btc_bundle, "unknown": 1}]
        for partials in ([], ["00" * 32], ["00" * 32] * 3, ("00" * 32, "00" * 32),
                         [True, "00" * 32], ["AA" * 32, "00" * 32]):
            malformed.append({**self.btc_bundle, "partial_signatures_hex": partials})
        for pre in ("00", "00" * 66, "AA" * 65, True, b"bytes"):
            malformed.append({**self.btc_bundle, "adaptor_presignature_hex": pre})
        called = []
        for bundle in malformed:
            with self.subTest(bundle=bundle), self.assertRaises(exchange.ExchangeError):
                exchange.retain_bitcoin(self.start, bundle, lambda request: called.append(request))
        self.assertEqual(called, [])
        state = self.stages()[2]
        for partial in (None, True, b"bytes", "00", "AA" * 32, "gg" * 32):
            with self.assertRaises(exchange.ExchangeError):
                exchange.retain_alice_partial(state, partial, accepted)

    def test_static_wrong_role_and_completion_contexts_are_rejected(self):
        data = self.btc.as_dict()
        from offline_session.transcript import _restore
        binding = _restore(data["binding"])
        nonce_round = _restore(data["nonce_round"])
        invalid = [self.znn, None, data,
                   signing_context(binding, "bob", "bitcoin-claim-partial"),
                   signing_context(binding, "alice", "bitcoin-claim-partial", nonce_round=nonce_round),
                   signing_context(binding, "bob", "bitcoin-claim-complete", nonce_round=nonce_round)]
        for context in invalid:
            with self.subTest(kind=type(context).__name__), self.assertRaises(exchange.ExchangeError):
                exchange.start(context)

    def test_zenon_context_cannot_change_bitcoin_binding_or_reuse_btc_nonces(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/session_terms.json").read_text(encoding="ascii"))
        fixture["bitcoin_binding"]["funding_vout"] += 1
        changed_btc = bind_bitcoin(agree_terms(fixture["terms"]), fixture["bitcoin_binding"])
        changed_znn = bind_zenon(changed_btc, fixture["zenon_binding"])
        from offline_session.transcript import _restore
        original_znn = _restore(self.znn.as_dict()["binding"])
        for binding, nonces in ((changed_znn, list(self.znn.as_dict()["nonce_round"]["public_nonces"].values())),
                                (original_znn, list(self.btc.as_dict()["nonce_round"]["public_nonces"].values()))):
            round_id = "ab" * 32
            hashes = [nonce_commitment(binding, round_id, role, nonce)
                      for role, nonce in zip(("alice", "bob"), nonces)]
            revealed = reveal_nonce_round(commit_nonce_round(binding, round_id, *hashes), *nonces)
            context = signing_context(binding, "bob", "zenon-claim-partial", nonce_round=revealed)
            with self.assertRaises(exchange.ExchangeError):
                exchange.bind_zenon(self.stages()[1], context)

    def test_stored_state_checks_order_receipts_release_and_required_context(self):
        states = self.stages()
        mutations = []
        for index, field in ((1, "bitcoin_bundle"), (2, "zenon_context"),
                             (3, "alice_partial_hex"), (4, "zenon_bundle"), (5, "release_hex")):
            changed = copy.deepcopy(states[index])
            changed[field] = None
            mutations.append(changed)
        changed = copy.deepcopy(states[-1]); changed["release_hex"] = "00"; mutations.append(changed)
        changed = copy.deepcopy(states[-1]); changed["release_may_have_escaped"] = False; mutations.append(changed)
        changed = copy.deepcopy(states[0]); changed["release_may_have_escaped"] = True; mutations.append(changed)
        changed = copy.deepcopy(states[1]); changed["verification_receipts"] = {}; mutations.append(changed)
        changed = copy.deepcopy(states[1]); changed["verification_receipts"]["bitcoin_bundle"] = "00" * 32; mutations.append(changed)
        changed = copy.deepcopy(states[4]); changed["alice_partial_hex"] = "00" * 32; mutations.append(changed)
        changed = copy.deepcopy(states[0]); changed["extra"] = "field"; mutations.append(changed)
        changed = copy.deepcopy(states[0]); changed["stage"] = "FUTURE"; mutations.append(changed)
        changed = copy.deepcopy(states[0]); changed["bitcoin_context"]["nonce_round_digest_hex"] = "00" * 32; mutations.append(changed)
        for state in mutations:
            with self.subTest(stage=state["stage"]), self.assertRaises(exchange.ExchangeError):
                exchange.validate_state(state)

    def test_public_state_bounds_reject_deep_large_and_nonplain_values(self):
        malformed = [None, True, [], {"unknown": "a" * 64001}, {"unknown": "\u00e9"},
                     {"unknown": 2 ** 256}, {"unknown": object()}, {"unknown": [0] * 129}]
        nested = 0
        for _ in range(22):
            nested = {"child": nested}
        malformed.append(nested)
        for state in malformed:
            with self.subTest(kind=type(state).__name__), self.assertRaises(exchange.ExchangeError):
                exchange.validate_state(state)

    def test_retained_snapshots_are_independent_of_caller_bundle_and_state_mutation(self):
        bundle = copy.deepcopy(self.btc_bundle)
        retained = exchange.retain_bitcoin(self.start, bundle, accepted)
        bundle["partial_signatures_hex"][0] = "00" * 32
        self.start["bitcoin_context"]["nonce_round"]["public_nonces"]["alice"] = "00" * 66
        self.assertEqual(retained["bitcoin_bundle"], self.btc_bundle)
        exchange.validate_state(retained)

    def test_mock_acceptance_receipts_are_not_cryptographic_certificates(self):
        # The pure layer deliberately trusts the callback; parsing alone cannot
        # distinguish this invalid scalar from a valid public partial signature.
        changed = copy.deepcopy(self.btc_bundle)
        changed["partial_signatures_hex"][0] = "ff" * 32
        retained = exchange.retain_bitcoin(self.start, changed, accepted)
        exchange.validate_state(retained)
        self.assertEqual(retained["bitcoin_bundle"], changed)


class SubprocessVerifierAdapterTests(unittest.TestCase):
    def setUp(self):
        _, context, _, bundle, _ = artifacts()
        self.request = exchange.verification_request(context, bundle=bundle)
        self.result = accepted(self.request)
        with patch("offline_session.artifact_verifier.Path.is_file", return_value=True), \
                patch("offline_session.artifact_verifier.os.access", return_value=True):
            self.verifier = SubprocessVerifier(Path.cwd() / "synthetic-verifier", timeout=1)

    def run_with(self, response, returncode=0):
        def process(executable, request, **kwargs):
            self.assertEqual(executable, self.verifier._executable)
            self.assertEqual(request, exchange.canonical(self.request))
            self.assertEqual(kwargs["timeout"], 1)
            self.assertEqual(kwargs["max_input_bytes"], 32768)
            self.assertEqual(kwargs.get("max_output_bytes", 4096), 4096)
            if returncode:
                raise WorkerError("synthetic worker rejection")
            return response
        with patch("offline_session.artifact_verifier.run_public_worker", side_effect=process):
            return self.verifier(self.request)

    def test_exact_success_with_optional_lf_and_no_payload_reflection(self):
        for suffix in (b"", b"\n"):
            self.assertEqual(self.run_with(exchange.canonical(self.result) + suffix), self.result)

    def test_bad_output_status_duplicate_keys_and_oversized_response_reject(self):
        raw = exchange.canonical(self.result)
        invalid = [b"", b"not-json", b"\xff", raw + b"\n\n", b" " + raw,
                   json.dumps(self.result, indent=2).encode("ascii"),
                   raw[:-1] + b',"valid":true}', b"x" * 4097,
                   b"[" * 1500 + b"0" + b"]" * 1500,
                   exchange.canonical({**self.result, "valid": 1}),
                   exchange.canonical({**self.result, "request_digest_hex": "00" * 32}),
                   exchange.canonical({**self.result, "extra": "field"})]
        for response in invalid:
            with self.subTest(response_size=len(response)), self.assertRaises(exchange.VerificationError):
                self.run_with(response)
        with self.assertRaises(exchange.VerificationError):
            self.run_with(raw, returncode=1)

    def test_deadline_and_os_errors_are_sanitized(self):
        for error in (WorkerError("synthetic worker detail"), OSError("synthetic worker detail")):
            with patch("offline_session.artifact_verifier.run_public_worker", side_effect=error), \
                    self.assertRaisesRegex(exchange.VerificationError, "public verifier failed"):
                self.verifier(self.request)
        with patch("offline_session.artifact_verifier.run_public_worker") as run:
            with self.assertRaises(exchange.VerificationError):
                self.verifier({"value": "a" * 32769})
            run.assert_not_called()

    def test_constructor_rejects_relative_missing_and_invalid_deadlines(self):
        with self.assertRaises(exchange.VerificationError):
            SubprocessVerifier("relative-verifier")
        with patch("offline_session.artifact_verifier.Path.is_file", return_value=False):
            with self.assertRaises(exchange.VerificationError):
                SubprocessVerifier(Path.cwd() / "synthetic-verifier")
        for timeout in (True, None, 0, -1, 31, float("nan"), float("inf")):
            with patch("offline_session.artifact_verifier.Path.is_file", return_value=True), \
                    patch("offline_session.artifact_verifier.os.access", return_value=True):
                with self.subTest(timeout=timeout), self.assertRaises(exchange.VerificationError):
                    SubprocessVerifier(Path.cwd() / "synthetic-verifier", timeout=timeout)


if __name__ == "__main__":
    unittest.main()
