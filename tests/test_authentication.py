"""Offline authentication bindings; fake callbacks do not verify signatures."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from offline_session import authentication, exchange
from offline_session.authentication_verifier import SubprocessAuthentication
from offline_session.public_worker import WorkerError
from offline_session.transcript import Commitment, agree_terms, bind_bitcoin


RESULT_SCHEMA = "ptlc-completion-auth-result-v1"


def accepted(request):
    """Fake local sequencing result, with no BIP340 or curve verification."""
    return {"schema": RESULT_SCHEMA, "request_digest_hex": authentication.request_digest(request), "valid": True}


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.session_fixture = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
        cls.vector = json.loads((root / "qualification/fixtures/authentication.json").read_text("ascii"))
        cls.terms = agree_terms(cls.session_fixture["terms"])
        cls.alice_key = cls.vector["envelope"]["context"]["alice_auth_key_hex"]
        cls.bob_key = cls.vector["envelope"]["context"]["bob_auth_key_hex"]

    def setUp(self):
        self.context = self.make_context()
        self.payload = bytes.fromhex(self.vector["envelope"]["payload_hex"])
        self.signature = bytes.fromhex(self.vector["envelope"]["signature_hex"])
        self.wire = exchange.canonical(self.vector["envelope"])

    def make_context(self, terms=None, **keys):
        return authentication.context(
            self.terms if terms is None else terms,
            alice_auth_key_hex=keys.get("alice", self.alice_key),
            bob_auth_key_hex=keys.get("bob", self.bob_key),
        )

    def test_python_reproduces_rust_fixture_context_envelope_requests_and_digests(self):
        for vector in (self.vector, self.vector["authenticated_invalid_completion"]):
            payload = bytes.fromhex(vector["envelope"]["payload_hex"])
            signature = bytes.fromhex(vector["envelope"]["signature_hex"])
            wire = exchange.canonical(vector["envelope"])
            self.assertEqual(self.context.as_dict(), vector["envelope"]["context"])
            self.assertEqual(self.context.canonical_bytes, exchange.canonical(self.context.as_dict()))
            self.assertEqual(authentication.envelope(self.context, payload, signature), wire)
            request = authentication.request(self.context, wire)
            self.assertEqual(request, vector["request"])
            self.assertEqual(authentication.message_digest(self.context, payload), vector["message_digest_hex"])
            self.assertEqual(authentication.request_digest(request), vector["result"]["request_digest_hex"])
            self.assertEqual(accepted(request), vector["result"])

    def test_context_factory_closes_constructor_and_returns_immutable_copies(self):
        with self.assertRaises(TypeError):
            authentication.AuthenticationContext()
        original = self.context.canonical_bytes
        copy_of_context = self.context.as_dict()
        copy_of_context["alice_auth_key_hex"] = "00" * 32
        self.assertEqual(self.context.canonical_bytes, original)
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            self.context._encoded = b"{}"
        request = authentication.request(self.context, self.wire)
        request["context"]["bob_auth_key_hex"] = "00" * 32
        self.assertEqual(authentication.request(self.context, self.wire), self.vector["request"])

    def test_terms_are_revalidated_and_require_exact_canonical_terms_commitment(self):
        wrong_stage = bind_bitcoin(self.terms, self.session_fixture["bitcoin_binding"])
        malformed = [None, True, self.terms.as_dict(), wrong_stage, object.__new__(Commitment)]
        class TermsSubclass(Commitment):
            pass
        subclass = object.__new__(TermsSubclass)
        object.__setattr__(subclass, "_encoded", self.terms.canonical_bytes)
        malformed.append(subclass)
        changed = self.terms.as_dict()
        changed["terms"]["zenon"]["point_type"] = True
        wrong_session = self.terms.as_dict()
        wrong_session["session_id"] = "99" * 32
        for encoded in (b"{}", exchange.canonical(changed), exchange.canonical(wrong_session),
                        json.dumps(self.terms.as_dict(), indent=2).encode("ascii")):
            forged = object.__new__(Commitment)
            object.__setattr__(forged, "_encoded", encoded)
            malformed.append(forged)
        for terms in malformed:
            with self.subTest(kind=type(terms).__name__), self.assertRaises(authentication.AuthenticationError):
                authentication.context(terms, alice_auth_key_hex=self.alice_key, bob_auth_key_hex=self.bob_key)

    def test_authentication_keys_have_strict_encoding_and_are_distinct(self):
        equalities = []
        class StringSubclass(str):
            def __eq__(self, _):
                equalities.append(1)
                raise RuntimeError("synthetic equality detail")
        invalid = (None, True, 1, b"x" * 32, "", "00", "AA" * 32, "gg" * 32,
                   "02" + self.alice_key, StringSubclass(self.alice_key))
        for key in invalid:
            with self.subTest(kind=type(key).__name__), self.assertRaises(authentication.AuthenticationError):
                self.make_context(alice=key)
        with self.assertRaises(authentication.AuthenticationError):
            self.make_context(alice=self.bob_key)
        self.assertEqual(equalities, [])

    def test_authentication_keys_cannot_reuse_named_swap_keys_or_opposite_sec1_parity(self):
        terms = self.session_fixture["terms"]
        compressed = [terms["adaptor_point_sec1_hex"]]
        compressed += terms["bitcoin"]["signer_keys_sec1_hex"] + terms["zenon"]["signer_keys_sec1_hex"]
        xonly = [key[2:] for key in compressed]
        xonly += [terms["bitcoin"][field] for field in
                  ("internal_key_xonly_hex", "output_key_xonly_hex", "refund_key_xonly_hex")]
        xonly.append(terms["zenon"]["aggregate_key_xonly_hex"])
        for key in xonly:
            for role in ("alice", "bob"):
                with self.subTest(role=role, key=key), self.assertRaises(authentication.AuthenticationError):
                    self.make_context(**{role: key})
        changed = copy.deepcopy(terms)
        original = changed["bitcoin"]["signer_keys_sec1_hex"][0]
        changed["bitcoin"]["signer_keys_sec1_hex"][0] = ("02" if original[:2] == "03" else "03") + original[2:]
        with self.assertRaises(authentication.AuthenticationError):
            self.make_context(terms=agree_terms(changed), alice=original[2:])

    def test_same_payload_is_bound_to_terms_participants_session_and_both_authentication_keys(self):
        contexts = [self.make_context(alice=self.bob_key, bob=self.alice_key), self.make_context(bob="70" * 32)]
        for field in ("session_id", "alice_id_hex", "bob_id_hex"):
            terms = copy.deepcopy(self.session_fixture["terms"])
            terms[field] = "99" * 32
            contexts.append(self.make_context(terms=agree_terms(terms)))
        terms = copy.deepcopy(self.session_fixture["terms"])
        terms["policy"]["minimum_claim_margin_seconds"] += 1
        contexts.append(self.make_context(terms=agree_terms(terms)))
        original = authentication.message_digest(self.context, self.payload)
        for context in contexts:
            with self.assertRaises(authentication.AuthenticationError):
                authentication.request(context, self.wire)
            self.assertNotEqual(authentication.message_digest(context, self.payload), original)

    def test_signature_message_has_separate_domain_context_separator_and_byte_length(self):
        payload = b"\x00synthetic\xff"
        expected = hashlib.sha256(b"PTLC/completion-auth/signature/v1\x00" + self.context.canonical_bytes
                                  + b"\x00" + len(payload).to_bytes(4, "big") + payload).hexdigest()
        self.assertEqual(authentication.message_digest(self.context, payload), expected)
        self.assertNotEqual(expected, authentication.message_digest(self.context, payload + b"\x00"))
        self.assertNotEqual(expected, hashlib.sha256(payload).hexdigest())

    def test_payload_and_signature_require_plain_bytes_and_fixed_boundaries(self):
        class BytesSubclass(bytes):
            pass
        for payload in (None, True, "synthetic", bytearray(b"x"), BytesSubclass(b"x"), b"", b"x" * 32001):
            with self.subTest(kind=type(payload).__name__), self.assertRaises(authentication.AuthenticationError):
                authentication.envelope(self.context, payload, self.signature)
            with self.assertRaises(authentication.AuthenticationError):
                authentication.message_digest(self.context, payload)
        for signature in (None, True, "00" * 64, bytearray(self.signature), BytesSubclass(self.signature),
                          b"", self.signature[:-1], self.signature + b"x"):
            with self.assertRaises(authentication.AuthenticationError):
                authentication.envelope(self.context, b"x", signature)
        for payload in (b"x", b"x" * 32000):
            wire = authentication.envelope(self.context, payload, self.signature)
            self.assertLessEqual(len(wire), 65536)
            self.assertEqual(authentication.request(self.context, wire)["payload_hex"], payload.hex())

    def test_envelope_rejects_noncanonical_duplicate_unknown_or_deep_wire_before_callback(self):
        value = json.loads(self.wire)
        class BytesSubclass(bytes):
            pass
        malformed = [None, True, self.wire.decode("ascii"), bytearray(self.wire), BytesSubclass(self.wire),
                     b"", b"\xff", b"{}", b" " + self.wire, self.wire + b"\n", self.wire + b"{}",
                     json.dumps(value, indent=2).encode("ascii"), b"x" * 65537,
                     b"[" * 1500 + b"0" + b"]" * 1500,
                     self.wire[:-1] + b',"schema":"ptlc-completion-auth-envelope-v1"}']
        for change in ({"schema": "future"}, {"unknown": 1}, {"payload_hex": ""}, {"payload_hex": "0"},
                       {"payload_hex": "AA"}, {"payload_hex": "00" * 32001}, {"signature_hex": "00"},
                       {"signature_hex": "AA" * 64}, {"signature_hex": True}):
            malformed.append(exchange.canonical({**value, **change}))
        calls = []
        for wire in malformed:
            with self.subTest(kind=type(wire).__name__), self.assertRaises(authentication.AuthenticationError):
                authentication.authenticate(self.context, wire, verifier=lambda request: calls.append(request))
        self.assertEqual(calls, [])

    def test_incoming_context_requires_every_exact_field_before_callback(self):
        calls = []
        for field in self.context.as_dict():
            value = json.loads(self.wire)
            value["context"][field] = "unexpected"
            with self.subTest(field=field), self.assertRaises(authentication.AuthenticationError):
                authentication.authenticate(self.context, exchange.canonical(value), verifier=lambda request: calls.append(request))
        for context in (None, True, {}, {**self.context.as_dict(), "unknown": 1}):
            value = json.loads(self.wire)
            value["context"] = context
            with self.assertRaises(authentication.AuthenticationError):
                authentication.authenticate(self.context, exchange.canonical(value), verifier=lambda request: calls.append(request))
        self.assertEqual(calls, [])

    def test_request_digest_validates_plain_schema_and_binds_signature_bytes(self):
        request = authentication.request(self.context, self.wire)
        expected = hashlib.sha256(b"PTLC/completion-auth/request/v1\x00" + exchange.canonical(request)).hexdigest()
        self.assertEqual(authentication.request_digest(request), expected)
        self.assertEqual(authentication.request_digest(dict(reversed(list(request.items())))), expected)
        changed = copy.deepcopy(request)
        changed["signature_hex"] = "00" * 64
        self.assertNotEqual(authentication.request_digest(changed), expected)
        class DictSubclass(dict):
            pass
        bad = (None, True, [], DictSubclass(request), {**request, "schema": "future"},
               {**request, "extra": 1}, {**request, "payload_hex": ""}, {**request, "signature_hex": False})
        for value in bad:
            with self.assertRaises(authentication.AuthenticationError):
                authentication.request_digest(value)

    def test_authenticated_payload_is_plain_immutable_bytes_and_request_is_not_aliased(self):
        captured = []
        def verifier(request):
            captured.append(request)
            return accepted(request)
        payload = authentication.authenticate(self.context, self.wire, verifier=verifier)
        self.assertIs(type(payload), bytes)
        self.assertEqual(payload, self.payload)
        captured[0]["payload_hex"] = "00"
        captured[0]["context"]["bob_auth_key_hex"] = "00" * 32
        self.assertEqual(payload, self.payload)
        self.assertEqual(self.context.as_dict(), self.vector["envelope"]["context"])

    def test_callback_mutation_cannot_rebind_original_payload_or_accepted_receipt(self):
        def accepted_then_mutated(request):
            result = accepted(request)
            request["payload_hex"] = "00"
            request["context"]["bob_auth_key_hex"] = "70" * 32
            return result
        self.assertEqual(authentication.authenticate(self.context, self.wire, verifier=accepted_then_mutated), self.payload)
        def mutated_then_accepted(request):
            request["payload_hex"] = "00"
            return accepted(request)
        with self.assertRaises(authentication.AuthenticationError):
            authentication.authenticate(self.context, self.wire, verifier=mutated_then_accepted)

    def test_only_exact_bound_result_and_literal_true_are_accepted_without_custom_equality(self):
        request = authentication.request(self.context, self.wire)
        good = accepted(request)
        equalities = []
        class StringSubclass(str):
            def __eq__(self, _):
                equalities.append(1)
                raise RuntimeError("synthetic equality detail")
        class DictSubclass(dict):
            pass
        class LooksTrue:
            def __eq__(self, _):
                equalities.append(1)
                raise RuntimeError("synthetic equality detail")
        bad = (None, True, [], DictSubclass(good), {}, {**good, "valid": 1}, {**good, "valid": False},
               {**good, "valid": LooksTrue()}, {**good, "extra": 1}, {**good, "schema": "future"},
               {**good, "schema": StringSubclass(good["schema"])},
               {**good, "request_digest_hex": "00" * 32},
               {**good, "request_digest_hex": StringSubclass(good["request_digest_hex"])})
        for result in bad:
            with self.assertRaises(authentication.AuthenticationError):
                authentication.authenticate(self.context, self.wire, verifier=lambda _: result)
        self.assertEqual(equalities, [])

    def test_callback_errors_are_sanitized_while_explicit_cancellation_propagates(self):
        for error in (RuntimeError("synthetic hidden detail"), RecursionError("synthetic hidden detail")):
            def fail(_, failure=error):
                raise failure
            with self.assertRaises(authentication.AuthenticationError) as caught:
                authentication.authenticate(self.context, self.wire, verifier=fail)
            self.assertNotIn("synthetic hidden detail", str(caught.exception))
        for error in (KeyboardInterrupt("synthetic cancellation"), SystemExit("synthetic cancellation")):
            def cancelled(_, failure=error):
                raise failure
            with self.assertRaises(type(error)) as caught:
                authentication.authenticate(self.context, self.wire, verifier=cancelled)
            self.assertIs(caught.exception, error)
        for verifier in (None, True, "worker"):
            with self.assertRaises(authentication.AuthenticationError):
                authentication.authenticate(self.context, self.wire, verifier=verifier)

    def test_repeated_authenticated_envelope_has_no_freshness_or_one_use_claim(self):
        calls = []
        for _ in range(3):
            payload = authentication.authenticate(self.context, self.wire,
                verifier=lambda request: calls.append(authentication.request_digest(request)) or accepted(request))
            self.assertEqual(payload, self.payload)
        self.assertEqual(calls, [self.vector["result"]["request_digest_hex"]] * 3)

    def test_fake_acceptance_does_not_prove_a_signature_or_validate_completion_payload(self):
        payload = b"opaque synthetic payload"
        wire = authentication.envelope(self.context, payload, b"\x00" * 64)
        self.assertEqual(authentication.authenticate(self.context, wire, verifier=accepted), payload)

    def test_untrusted_context_types_are_rejected_before_custom_equality(self):
        equalities = []
        class HostileContext:
            def __eq__(self, _):
                equalities.append(1)
                raise RuntimeError("synthetic equality detail")
        class ContextSubclass(authentication.AuthenticationContext):
            pass
        subclass = object.__new__(ContextSubclass)
        for context in (None, True, self.context.as_dict(), HostileContext(), subclass):
            with self.assertRaises(authentication.AuthenticationError):
                authentication.request(context, self.wire)
            with self.assertRaises(authentication.AuthenticationError):
                authentication.envelope(context, self.payload, self.signature)
        self.assertEqual(equalities, [])


class AuthenticationAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.vector = json.loads((root / "qualification/fixtures/authentication.json").read_text("ascii"))

    def setUp(self):
        self.request = copy.deepcopy(self.vector["request"])
        self.result = copy.deepcopy(self.vector["result"])
        with patch("offline_session.authentication_verifier.Path.is_file", return_value=True), \
                patch("offline_session.authentication_verifier.os.access", return_value=True):
            self.verifier = SubprocessAuthentication(Path.cwd() / "synthetic-authentication", timeout=1)

    def run_with(self, response):
        def worker(executable, request, **kwargs):
            self.assertEqual(executable, self.verifier._executable)
            self.assertEqual(request, exchange.canonical(self.request))
            self.assertEqual(kwargs["timeout"], 1)
            self.assertEqual(kwargs["max_input_bytes"], 65536)
            self.assertEqual(kwargs.get("max_output_bytes", 4096), 4096)
            return response
        with patch("offline_session.authentication_verifier.run_public_worker", side_effect=worker):
            return self.verifier(self.request)

    def test_canonical_success_with_optional_lf_uses_bounded_shared_runner(self):
        for suffix in (b"", b"\n"):
            self.assertEqual(self.run_with(exchange.canonical(self.result) + suffix), self.result)

    def test_malformed_noncanonical_duplicate_deep_or_unbound_results_fail(self):
        raw = exchange.canonical(self.result)
        bad = (b"", b"\xff", b"{}", b" " + raw, raw + b"\n\n", b"x" * 4097,
               b"[" * 1100 + b"0" + b"]" * 1100, json.dumps(self.result, indent=2).encode("ascii"),
               raw[:-1] + b',"valid":true}', exchange.canonical({**self.result, "valid": 1}),
               exchange.canonical({**self.result, "schema": "future"}),
               exchange.canonical({**self.result, "request_digest_hex": "00" * 32}),
               exchange.canonical({**self.result, "extra": 1}))
        for response in bad:
            with self.subTest(size=len(response)), self.assertRaises(authentication.AuthenticationError):
                self.run_with(response)

    def test_worker_errors_are_sanitized_and_oversized_request_never_spawns(self):
        for error in (WorkerError("synthetic hidden detail"), OSError("synthetic hidden detail")):
            with patch("offline_session.authentication_verifier.run_public_worker", side_effect=error), \
                    self.assertRaises(authentication.AuthenticationError) as caught:
                self.verifier(self.request)
            self.assertNotIn("synthetic hidden detail", str(caught.exception))
        with patch("offline_session.authentication_verifier.run_public_worker") as run:
            with self.assertRaises(authentication.AuthenticationError):
                self.verifier({"value": "x" * 65537})
            run.assert_not_called()
        with patch("offline_session.authentication_verifier.Path.is_file", return_value=True), \
                patch("offline_session.authentication_verifier.os.access", return_value=True):
            for timeout in (True, None, 0, -1, 31, float("nan"), float("inf"), 10 ** 1000):
                with self.subTest(kind=type(timeout).__name__), self.assertRaises(authentication.AuthenticationError):
                    SubprocessAuthentication(Path.cwd() / "synthetic-authentication", timeout=timeout)


if __name__ == "__main__":
    unittest.main()
