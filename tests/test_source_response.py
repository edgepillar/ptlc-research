"""Independent response selections; fake callbacks do no signature mathematics."""

import copy
from dataclasses import FrozenInstanceError
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import current_authority_contract as current
from offline_session.public_worker import WorkerError
from qualification import source_response as response, source_root_roles as root
from qualification.source_response_verifier import PublicResponseCheck
from completion_test_support import released_bob
import test_governor_signature as public


def fixture():
    return json.loads(Path("qualification/fixtures/source_response.json").read_text("ascii"))


@lru_cache(maxsize=5)
def _bound(name):
    return public.selected_bound(released_bob(), name)


def selection(name="primary"):
    """Synthetic local fixture choices, never an incoming peer bootstrap."""
    v = fixture()["positive_vectors"][name]
    d, q = v["envelope"]["root_envelope"]["declaration"], v["response"]["query"]
    govname = {"alternate_owner": "alternate_owner", "alternate_issuer": "alternate_issuer",
        "broader_profile": "broader_caps", "new_epoch": "new_epoch"}.get(name, "primary")
    bound = copy.deepcopy(_bound(govname))
    source = current.source_context(bound, **{f: d["source_context"][f] for f in
        ("source_id_hex", "source_profile_digest_hex", "source_incarnation_hex", "provisioning_root_key_hex")})
    checkpoint = current.PolicyCheckpoint(**q["expected_checkpoint"])
    query = current.policy_read_query(bound, response._canonical(public.fixture()[govname]["envelope"]),
        source=source, checkpoint=checkpoint, challenge_hex=q["challenge_hex"])
    declaration = root.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"],
        delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])
    return response.source_response(declaration, query, observation=v["response"]["claim"]["observation"])


def fake_check(request):
    """Deliberately forge all four positives without any signature mathematics."""
    return response.expected_result(response.request_digest(request))


def objects(packet):
    """Visit all nested exact objects in a synthetic public packet."""
    yield (), packet
    for field, value in packet.items():
        if type(value) is dict:
            for path, item in objects(value):
                yield (field, *path), item


def target(packet, path):
    for field in path:
        packet = packet[field]
    return packet


class SourceResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = fixture()
        cls.primary = cls.vectors["positive_vectors"]["primary"]
        cls.expected = selection()
        cls.wire = response._canonical(cls.primary["envelope"])

    def refuse(self, packet):
        calls = []
        with self.assertRaises(response.SourceResponseError):
            response.verify_selected_response(self.expected, response._canonical(packet), verifier=lambda r: calls.append(r))
        self.assertEqual(calls, [])

    def test_public_fixture_complete_selection_and_separate_domains_match(self):
        p = self.primary["envelope"]
        self.assertEqual(response.envelope(self.expected, root_signature=bytes.fromhex(p["root_envelope"]["root_signature_hex"]),
            response_signature=bytes.fromhex(p["response_signature_hex"])), self.wire)
        self.assertEqual(self.expected.as_dict(), self.primary["response"])
        self.assertEqual(response.request(self.expected, self.wire), self.primary["request"])
        self.assertEqual(self.expected.message_digest_hex, self.primary["message_digest_hex"])
        self.assertEqual(self.expected.message_digest_hex, hashlib.sha256(response.RESPONSE_DOMAIN+self.expected.canonical_bytes).hexdigest())
        self.assertEqual(response.request_digest(self.primary["request"]), self.primary["result"]["request_digest_hex"])
        self.assertEqual(self.expected.as_dict()["claim_digest_hex"], hashlib.sha256(response.CLAIM_DOMAIN+response._canonical(self.expected.as_dict()["claim"])).hexdigest())

    def test_all_seventeen_independent_selections_match_without_truth_or_permission(self):
        self.assertEqual(len(self.vectors["positive_vectors"]), 17)
        for name, v in self.vectors["positive_vectors"].items():
            expected = selection(name)
            self.assertEqual(expected.as_dict(), v["response"])
            self.assertIs(response.verify_selected_response(expected, response._canonical(v["envelope"]), verifier=fake_check), expected)
            for field in ("current", "authenticated", "authorized", "permit", "can_start", "committed", "quota_granted"):
                self.assertFalse(hasattr(expected, field))

    def test_valid_peer_root_role_profile_checkpoint_challenge_and_observation_refuse_before_work(self):
        for name, v in self.vectors["positive_vectors"].items():
            if name != "primary": self.refuse(v["envelope"])

    def test_all_twenty_five_signed_inconsistent_reads_refuse_before_work(self):
        self.assertEqual(len(self.vectors["signed_refusal_vectors"]), 25)
        for v in self.vectors["signed_refusal_vectors"].values(): self.refuse(v["envelope"])

    def test_every_nested_field_is_bound_before_any_mathematical_work(self):
        for path, fields in objects(self.primary["envelope"]):
            for field, old in fields.items():
                packet = copy.deepcopy(self.primary["envelope"])
                target(packet, path)[field] = old+1 if type(old) is int else "ee"*32
                self.refuse(packet)

    def test_every_nested_object_refuses_missing_null_and_extra_privilege_fields(self):
        for path, fields in objects(self.primary["envelope"]):
            for field in fields:
                for mode in ("missing", "null"):
                    packet = copy.deepcopy(self.primary["envelope"])
                    if mode == "missing": target(packet, path).pop(field)
                    else: target(packet, path)[field] = None
                    self.refuse(packet)
            packet = copy.deepcopy(self.primary["envelope"]); target(packet, path)["authorized"] = True
            self.refuse(packet)

    def test_canonical_aliases_duplicate_keys_nonascii_and_oversized_wire_refuse(self):
        for wire in (b"", b"\xff", b" "*16385, self.wire+b"\n", b" "+self.wire,
                self.wire.replace(b'"response":', b'"\\u0072esponse":'),
                self.wire.replace(b'"revision":0', b'"revision":0,"revision":0'),
                self.wire.replace(b'"revision":0', b'"revision":0.0'),
                self.wire.replace(b'"revision":0', b'"revision":0e0'), b"["*512+b"]"*512):
            calls = []
            with self.assertRaises(response.SourceResponseError):
                response.verify_selected_response(self.expected, wire, verifier=lambda r: calls.append(r))
            self.assertEqual(calls, [])

    def test_exact_signature_bytes_required_while_zero_signatures_are_only_shape_valid(self):
        for wrong in (None, bytearray(64), bytes(63), bytes(65), "00"*64):
            for field in ("root_signature", "response_signature"):
                args = dict(root_signature=bytes(64), response_signature=bytes(64)); args[field] = wrong
                with self.assertRaises(response.SourceResponseError): response.envelope(self.expected, **args)
        for path in (("response_signature_hex",), ("root_envelope", "root_signature_hex")):
            for wrong in (True, "00"*63, "00"*65, "AB"*64, "ZZ"*64):
                packet = copy.deepcopy(self.primary["envelope"]); target(packet, path[:-1])[path[-1]] = wrong
                self.refuse(packet)
        wire = response.envelope(self.expected, root_signature=bytes(64), response_signature=bytes(64))
        self.assertIs(response.verify_selected_response(self.expected, wire, verifier=fake_check), self.expected)

    def test_all_four_exact_true_flags_complete_digest_and_no_extra_result_are_required(self):
        for field in response._FLAGS:
            for wrong in (False, 1, "true", None):
                result = dict(self.primary["result"], **{field: wrong})
                with self.assertRaises(response.SourceResponseError): response.verify_selected_response(self.expected, self.wire, verifier=lambda r:result)
        for result in (None, [], dict(self.primary["result"], authorized=True),
                dict(self.primary["result"], schema="unsupported"), dict(self.primary["result"], request_digest_hex="ee"*32),
                {k:v for k,v in self.primary["result"].items() if k != "root_signature_valid"}):
            with self.assertRaises(response.SourceResponseError): response.verify_selected_response(self.expected, self.wire, verifier=lambda r:result)

    def test_alternate_root_and_response_signatures_require_new_complete_request_results(self):
        for field in ("alternate_root_signature_hex", "alternate_response_signature_hex"):
            packet = copy.deepcopy(self.primary["envelope"])
            if field == "alternate_root_signature_hex": packet["root_envelope"]["root_signature_hex"] = self.vectors[field]
            else: packet["response_signature_hex"] = self.vectors[field]
            wire = response._canonical(packet)
            self.assertIs(response.verify_selected_response(self.expected, wire, verifier=fake_check), self.expected)
            self.assertNotEqual(response.request_digest(response.request(self.expected, wire)), self.primary["result"]["request_digest_hex"])
            with self.assertRaises(response.SourceResponseError): response.verify_selected_response(self.expected, wire, verifier=lambda r:self.primary["result"])

    def test_exact_query_and_response_replay_does_not_advance_or_consume_any_selection(self):
        before = copy.deepcopy(self.expected)
        for _ in range(3): self.assertIs(response.verify_selected_response(self.expected, self.wire, verifier=fake_check), self.expected)
        self.assertEqual(self.expected, before)

    def test_coherently_restored_old_root_query_checkpoint_and_response_match_again(self):
        for name in ("new_checkpoint", "new_root_revision", "new_incarnation", "alternate_root", "alternate_response", "revoked"):
            expected = selection(name)
            with self.assertRaises(response.SourceResponseError): response.verify_selected_response(expected, self.wire, verifier=fake_check)
            restored = copy.deepcopy(self.expected)
            self.assertIs(response.verify_selected_response(restored, self.wire, verifier=fake_check), restored)

    def test_new_challenge_can_bind_same_old_checkpoint_and_active_claim(self):
        new = selection("new_challenge")
        a, b = self.expected.as_dict(), new.as_dict()
        self.assertNotEqual(a["query"]["challenge_hex"], b["query"]["challenge_hex"])
        self.assertEqual(a["query"]["expected_checkpoint"], b["query"]["expected_checkpoint"])
        self.assertEqual(a["claim"]["assignment_digest_hex"], b["claim"]["assignment_digest_hex"])
        self.assertEqual(b["claim"]["observation"], "active")
        self.assertIs(response.verify_selected_response(new, response._canonical(self.vectors["positive_vectors"]["new_challenge"]["envelope"]), verifier=fake_check), new)

    def test_callback_receives_defensive_copy_and_cannot_rebind_result(self):
        def changed(value):
            value["response"]["query"]["challenge_hex"] = "ee"*32
            return self.primary["result"]
        before = copy.deepcopy(self.expected)
        self.assertIs(response.verify_selected_response(self.expected, self.wire, verifier=changed), self.expected)
        self.assertEqual(self.expected, before)

    def test_during_callback_selection_root_or_prepared_query_mutation_refuses(self):
        for field in ("_wire", "_root_wire", "_query"):
            selected = copy.deepcopy(self.expected)
            def change(value):
                object.__setattr__(selected, field, b"{}" if field != "_query" else object())
                return self.primary["result"]
            with self.assertRaises(response.SourceResponseError): response.verify_selected_response(selected, self.wire, verifier=change)

    def test_factory_rejects_inexact_root_query_and_observation_before_conversion_hooks(self):
        calls = []
        class Foreign:
            def as_dict(self): calls.append("conversion"); raise AssertionError
        class Text(str):
            def __eq__(self, other): calls.append("comparison"); raise AssertionError
        d = self.primary["envelope"]["root_envelope"]["declaration"]
        selected_root = root.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"], delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])
        for r, q, o in ((Foreign(),self.expected._query,"active"), (selected_root,Foreign(),"active"), (selected_root,self.expected._query,Text("active"))):
            with self.assertRaises(response.SourceResponseError): response.source_response(r,q,observation=o)
        self.assertEqual(calls, [])

    def test_direct_conversion_refuses_foreign_descriptors_and_subclass_overrides_before_access(self):
        calls = []
        class Foreign:
            @property
            def _wire(self): calls.append("wire"); raise AssertionError
            @property
            def _root_wire(self): calls.append("root"); raise AssertionError
        class Child(response.SourceResponse):
            def root_dict(self): calls.append("override"); raise AssertionError
        for method in (response.SourceResponse.root_dict, response.SourceResponse.as_dict,
                response.SourceResponse.canonical_bytes.fget, response.SourceResponse.message_digest_hex.fget):
            for value in (Foreign(), object.__new__(Child)):
                with self.assertRaises(response.SourceResponseError): method(value)
        self.assertEqual(calls, [])

    def test_incomplete_damaged_or_subclass_expected_selection_refuses_before_work(self):
        class Child(response.SourceResponse): pass
        values = [None, object(), object.__new__(response.SourceResponse), object.__new__(Child)]
        for field in ("_wire", "_root_wire", "_query"):
            item = copy.deepcopy(self.expected); object.__setattr__(item, field, b"{}" if field != "_query" else object()); values.append(item)
        for value in values:
            calls = []
            with self.assertRaises(response.SourceResponseError): response.verify_selected_response(value, self.wire, verifier=lambda r:calls.append(r))
            self.assertEqual(calls, [])
        with self.assertRaises(FrozenInstanceError): self.expected._wire = b"{}"

    def test_checkpoint_numbers_refuse_bool_float_string_negative_and_overflow(self):
        for wrong in (True, 0.0, "0", -1, 1<<53):
            packet = copy.deepcopy(self.primary["envelope"]); packet["response"]["query"]["expected_checkpoint"]["revision"] = wrong
            self.refuse(packet)

    def test_callback_failures_are_sanitized_and_cancellation_propagates(self):
        def failure(value): raise RuntimeError("synthetic private detail")
        with self.assertRaises(response.SourceResponseError) as caught: response.verify_selected_response(self.expected, self.wire, verifier=failure)
        self.assertNotIn("synthetic private detail", str(caught.exception))
        def cancel(value): raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt): response.verify_selected_response(self.expected, self.wire, verifier=cancel)
        with self.assertRaises(response.SourceResponseError): response.verify_selected_response(self.expected, self.wire, verifier=None)


class SourceResponsePublicCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-root-check-")
        self.addCleanup(temporary.cleanup)
        self.entry = Path(temporary.name)/"worker"
        self.entry.write_bytes(b"synthetic executable measurement only"); self.entry.chmod(0o700)
        self.digest = hashlib.sha256(self.entry.read_bytes()).hexdigest()
        self.check = PublicResponseCheck(self.entry, expected_executable_sha256_hex=self.digest)
        self.request = fixture()["positive_vectors"]["primary"]["request"]
        self.result = fake_check(self.request)

    def test_exact_result_with_optional_one_lf_uses_bounded_public_runner(self):
        for suffix in (b"", b"\n"):
            with patch("qualification.source_response_verifier.run_public_worker", return_value=response._canonical(self.result)+suffix) as run:
                self.assertEqual(self.check(self.request), self.result)
                run.assert_called_once_with(str(self.entry), response._canonical(self.request), timeout=5, max_input_bytes=16384, max_output_bytes=512)

    def test_wrong_binding_flags_extra_fields_and_output_refuse(self):
        for output in (b"", b"{}", response._canonical(dict(self.result, permit=True)),
                response._canonical(dict(self.result, response_signature_valid=1)),
                response._canonical(dict(self.result, root_signature_valid=1)),
                response._canonical(dict(self.result, request_digest_hex="00"*32)), response._canonical(self.result)+b"\n\n"):
            with patch("qualification.source_response_verifier.run_public_worker", return_value=output), self.assertRaises(response.SourceResponseError): self.check(self.request)

    def test_changed_or_missing_entry_refuses_before_any_launch(self):
        self.entry.write_bytes(b"changed synthetic entry")
        with patch("qualification.source_response_verifier.run_public_worker") as run:
            with self.assertRaises(response.SourceResponseError): self.check(self.request)
            self.entry.unlink()
            with self.assertRaises(response.SourceResponseError): self.check(self.request)
            run.assert_not_called()

    def test_path_pin_timeout_and_executable_mode_must_be_selected_exactly(self):
        for entry, digest, timeout in (("relative-worker", self.digest, 5), (self.entry, "00"*32, 5),
                (self.entry, self.digest, True), (self.entry, self.digest, 0), (self.entry, self.digest, 31)):
            with self.assertRaises(response.SourceResponseError): PublicResponseCheck(entry, expected_executable_sha256_hex=digest, timeout=timeout)
        self.entry.chmod(0o600)
        with self.assertRaises(response.SourceResponseError): PublicResponseCheck(self.entry, expected_executable_sha256_hex=self.digest)

    def test_malformed_request_refuses_before_any_launch(self):
        with patch("qualification.source_response_verifier.run_public_worker") as run:
            with self.assertRaises(response.SourceResponseError): self.check(dict(self.request, permit=True))
            run.assert_not_called()

    def test_runner_failures_sanitize_and_cancellation_propagates(self):
        with patch("qualification.source_response_verifier.run_public_worker", side_effect=WorkerError("synthetic private detail")):
            with self.assertRaises(response.SourceResponseError) as caught: self.check(self.request)
            self.assertNotIn("synthetic private detail", str(caught.exception))
        with patch("qualification.source_response_verifier.run_public_worker", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt): self.check(self.request)
