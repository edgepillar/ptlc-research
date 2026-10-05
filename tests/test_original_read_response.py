"""Selected historical expectations; fake callbacks do no signature math."""

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
from qualification import original_read_contract as read, original_read_response as response
from qualification import source_root_roles as roots
from qualification.original_read_response_verifier import PublicOriginalResponseCheck


@lru_cache(maxsize=1)
def fixture():
    return json.loads(Path("qualification/fixtures/original_read_response.json").read_text("ascii"))


def selection(name="primary"):
    """Known synthetic local expectations, never an incoming peer bootstrap."""
    v = fixture()["positive_vectors"][name]
    d, q = v["envelope"]["root_envelope"]["declaration"], v["response"]["query"]
    root = roots.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"],
        delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])
    o = q["original_operation"]
    original = read.original_operation(operation_id_hex=o["operation_id_hex"], expected_revision=o["expected_revision"],
        profile_wire=read._canonical(o["governor_profile"]), proposal_digest_hex=o["proposal_digest_hex"])
    h = q["expected_record_checkpoint"]
    query = read.original_read_query(root, original, checkpoint=current.PolicyCheckpoint(**q["expected_checkpoint"]),
        record_checkpoint=read.RecordCheckpoint(h["event_sequence"], h["record_lineage_digest_hex"]), challenge_hex=q["challenge_hex"])
    claim = read.parse_claim(query, read._canonical(v["response"]["claim"]))
    return response.original_read_response(root, query, claim)


def fake_check(request):
    """Deliberately forge two positive flags without signature mathematics."""
    return response.expected_result(response.request_digest(request))


def objects(value):
    yield (), value
    for field, item in value.items():
        if type(item) is dict:
            for path, child in objects(item):
                yield (field, *path), child


def target(value, path):
    for field in path:
        value = value[field]
    return value


class OriginalReadResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = fixture()
        cls.primary = cls.vectors["positive_vectors"]["primary"]
        cls.expected = selection()
        cls.wire = response._canonical(cls.primary["envelope"])

    def refuse(self, packet):
        calls = []
        with self.assertRaises(response.OriginalResponseError):
            response.verify_selected_response(self.expected, response._canonical(packet), verifier=lambda r: calls.append(r))
        self.assertEqual(calls, [])

    def test_complete_public_vectors_independently_select_root_original_and_both_checkpoints(self):
        self.assertEqual(len(self.vectors["positive_vectors"]), 22)
        for name, v in self.vectors["positive_vectors"].items():
            e = selection(name)
            self.assertEqual(e.as_dict(), v["response"])
            self.assertEqual(e.message_digest_hex, v["message_digest_hex"])
            p = v["envelope"]
            self.assertEqual(response.envelope(e, root_signature=bytes.fromhex(p["root_envelope"]["root_signature_hex"]),
                response_signature=bytes.fromhex(p["response_signature_hex"])), response._canonical(p))
            self.assertIs(response.verify_selected_response(e, response._canonical(p), verifier=fake_check), e)

    def test_response_uses_explicit_tagged_prehash_while_original_query_and_claim_digests_stay_fixed(self):
        tag = hashlib.sha256(b"PTLC/observation-original-read-response/v1").digest()
        self.assertEqual(self.expected.message_digest_hex, hashlib.sha256(tag+tag+self.expected.canonical_bytes).hexdigest())
        self.assertNotEqual(self.expected.message_digest_hex,
            hashlib.sha256(b"PTLC/observation-original-read-response/v1\0"+self.expected.canonical_bytes).hexdigest())
        unsigned = json.loads(Path("qualification/fixtures/original_read_contract.json").read_text("ascii"))
        self.assertEqual(self.expected._query.digest_hex, unsigned["query_digest_hex"])
        self.assertEqual(self.expected._claim.digest_hex, unsigned["observations"]["pending"]["claim_digest_hex"])

    def test_every_nested_binding_and_signature_shape_mutation_refuses_before_callback(self):
        for path, fields in objects(self.primary["envelope"]):
            for field, old in fields.items():
                packet = copy.deepcopy(self.primary["envelope"])
                target(packet, path)[field] = (not old if type(old) is bool else
                    old+1 if type(old) is int else "ee"*32)
                self.refuse(packet)

    def test_every_nested_object_refuses_missing_null_or_extra_permission_fields(self):
        for path, fields in objects(self.primary["envelope"]):
            for field, old in fields.items():
                for mode in ("missing", "null"):
                    if mode == "null" and old is None:
                        continue
                    packet = copy.deepcopy(self.primary["envelope"])
                    if mode == "missing": target(packet, path).pop(field)
                    else: target(packet, path)[field] = None
                    self.refuse(packet)
            packet = copy.deepcopy(self.primary["envelope"])
            target(packet, path)["authorized"] = True
            self.refuse(packet)

    def test_wire_aliases_duplicate_keys_nonascii_depth_and_byte_bounds_refuse(self):
        for wire in (b"", b"\xff", b" "*16385, self.wire+b"\n", b" "+self.wire,
                self.wire.replace(b'"response":', b'"\\u0072esponse":'),
                self.wire.replace(b'"revision":7', b'"revision":7,"revision":7'),
                self.wire.replace(b'"revision":7', b'"revision":7.0'),
                self.wire.replace(b'"revision":7', b'"revision":7e0'), b"["*512+b"]"*512):
            calls = []
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(self.expected, wire, verifier=lambda r: calls.append(r))
            self.assertEqual(calls, [])

    def test_all_revision_sequence_cap_and_active_numbers_refuse_type_and_range_aliases(self):
        for path, fields in objects(self.primary["envelope"]):
            for field, old in fields.items():
                if type(old) is not int:
                    continue
                for wrong in (True, float(old), str(old), -1, 1<<53):
                    packet = copy.deepcopy(self.primary["envelope"])
                    target(packet, path)[field] = wrong
                    self.refuse(packet)
        for wrong in (0, 1, "true", None):
            p = copy.deepcopy(self.primary["envelope"]); p["response"]["claim"]["head_policy"]["active"] = wrong
            self.refuse(p)

    def test_exact_signature_bytes_required_but_zero_signatures_are_only_format_valid(self):
        for wrong in (None, bytearray(64), bytes(63), bytes(65), "00"*64):
            for field in ("root_signature", "response_signature"):
                args = dict(root_signature=bytes(64), response_signature=bytes(64)); args[field] = wrong
                with self.assertRaises(response.OriginalResponseError): response.envelope(self.expected, **args)
        for path in (("response_signature_hex",), ("root_envelope", "root_signature_hex")):
            for wrong in (True, "00"*63, "00"*65, "AB"*64, "ZZ"*64):
                p = copy.deepcopy(self.primary["envelope"]); target(p, path[:-1])[path[-1]] = wrong
                self.refuse(p)
        zero = response.envelope(self.expected, root_signature=bytes(64), response_signature=bytes(64))
        self.assertIs(response.verify_selected_response(self.expected, zero, verifier=fake_check), self.expected)

    def test_result_has_only_two_exact_true_flags_and_complete_request_digest(self):
        self.assertEqual(set(response._FLAGS), {"root_signature_valid", "response_signature_valid"})
        for field in response._FLAGS:
            for wrong in (False, 1, "true", None):
                result = dict(self.primary["result"], **{field: wrong})
                with self.assertRaises(response.OriginalResponseError):
                    response.verify_selected_response(self.expected, self.wire, verifier=lambda r: result)
        for result in (None, [], dict(self.primary["result"], authorized=True),
                dict(self.primary["result"], issuer_signature_valid=True), dict(self.primary["result"], owner_signature_valid=True),
                dict(self.primary["result"], schema="unsupported"), dict(self.primary["result"], request_digest_hex="ee"*32),
                {k:v for k,v in self.primary["result"].items() if k != "root_signature_valid"}):
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(self.expected, self.wire, verifier=lambda r: result)

    def test_alternate_root_or_response_signature_requires_new_complete_request_result(self):
        for field in ("alternate_root_signature_hex", "alternate_response_signature_hex"):
            p = copy.deepcopy(self.primary["envelope"])
            if field == "alternate_root_signature_hex": p["root_envelope"]["root_signature_hex"] = self.vectors[field]
            else: p["response_signature_hex"] = self.vectors[field]
            wire = response._canonical(p)
            self.assertIs(response.verify_selected_response(self.expected, wire, verifier=fake_check), self.expected)
            self.assertNotEqual(response.request_digest(response.request(self.expected, wire)), self.primary["result"]["request_digest_hex"])
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(self.expected, wire, verifier=lambda r: self.primary["result"])

    def test_exact_replay_and_coherently_restored_expectations_consume_no_record_or_challenge(self):
        before = copy.deepcopy(self.expected)
        for _ in range(3):
            self.assertIs(response.verify_selected_response(self.expected, self.wire, verifier=fake_check), self.expected)
        self.assertEqual(self.expected, before)
        for name in ("new_policy_checkpoint", "new_record_checkpoint", "new_root_revision", "new_incarnation", "alternate_root", "new_head_profile"):
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(selection(name), self.wire, verifier=fake_check)
            old = copy.deepcopy(self.expected)
            self.assertIs(response.verify_selected_response(old, self.wire, verifier=fake_check), old)

    def test_fresh_challenge_can_bind_same_old_active_policy_and_pending_original(self):
        new = selection("new_challenge")
        a, b = self.expected.as_dict(), new.as_dict()
        self.assertNotEqual(a["query"]["challenge_hex"], b["query"]["challenge_hex"])
        for field in ("expected_checkpoint", "expected_record_checkpoint", "original_operation"):
            self.assertEqual(a["query"][field], b["query"][field])
        self.assertTrue(b["claim"]["head_policy"]["active"])

    def test_same_id_changed_original_and_different_id_same_proposal_are_distinct_self_selections(self):
        old = self.expected.as_dict()["query"]["original_operation"]
        for name in ("same_id_changed_proposal", "same_id_changed_revision", "historical_different_profile"):
            new = selection(name)
            o = new.as_dict()["query"]["original_operation"]
            self.assertEqual(old["operation_id_hex"], o["operation_id_hex"])
            self.assertNotEqual(old, o)
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(new, self.wire, verifier=fake_check)
        other = selection("different_id_same_proposal").as_dict()["query"]["original_operation"]
        self.assertEqual(old["proposal_digest_hex"], other["proposal_digest_hex"])
        self.assertNotEqual(old["operation_id_hex"], other["operation_id_hex"])

    def test_selected_old_profile_can_differ_from_head_without_owner_or_issuer_proof(self):
        e = selection("historical_different_profile")
        self.assertNotEqual(e.as_dict()["query"]["original_operation"]["governor_profile"], e.root_dict()["governor_profile"])
        for field in ("owner_signature", "issuer_signature", "authenticated", "current", "receipt", "retry", "refund", "can_start"):
            self.assertFalse(hasattr(e, field))
        self.assertEqual(len(e.as_dict()["query"]["original_operation"]), 5)

    def test_noncurve_historical_owner_is_only_shape_valid_until_selected_mathematical_check(self):
        v = self.vectors["signed_refusal_vectors"]["original_noncurve_owner"]
        q = response._prepared(v["envelope"]["root_envelope"]["declaration"], v["response"]["query"])
        c = read.parse_claim(q, read._canonical(v["response"]["claim"]))
        e = response.original_read_response(q._root, q, c)
        self.assertIs(response.verify_selected_response(e, response._canonical(v["envelope"]), verifier=fake_check), e)
        self.assertNotIn("owner_signature_valid", response.expected_result(response.request_digest(v["request"])))

    def test_no_lookup_signing_clock_network_or_store_is_called_by_selection(self):
        with patch("qualification.policy_effect_store.OfflinePolicyEffectStore", side_effect=AssertionError), \
                patch("subprocess.Popen", side_effect=AssertionError), patch("socket.socket", side_effect=AssertionError), \
                patch("time.time", side_effect=AssertionError):
            e = selection()
            self.assertIs(response.verify_selected_response(e, self.wire, verifier=fake_check), e)

    def test_callback_gets_defensive_copy_and_cannot_rebind_selected_original(self):
        before = copy.deepcopy(self.expected)
        def changed(r):
            r["response"]["query"]["original_operation"]["proposal_digest_hex"] = "ee"*32
            return self.primary["result"]
        self.assertIs(response.verify_selected_response(self.expected, self.wire, verifier=changed), self.expected)
        self.assertEqual(self.expected, before)

    def test_changed_root_query_claim_or_statement_during_callback_refuses(self):
        for field in ("_wire", "_root_wire", "_query", "_claim"):
            e = copy.deepcopy(self.expected)
            def changed(r):
                object.__setattr__(e, field, b"{}" if field in ("_wire", "_root_wire") else object())
                return self.primary["result"]
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(e, self.wire, verifier=changed)

    def test_factory_rejects_foreign_or_subclass_objects_before_conversion_hooks(self):
        calls = []
        class Foreign:
            def as_dict(self): calls.append("hook"); raise AssertionError
        class Child(read.OriginalReadClaim):
            def as_dict(self): calls.append("child"); raise AssertionError
        q, c = self.expected._query, self.expected._claim
        for r, query, claim in ((Foreign(),q,c), (q._root,Foreign(),c), (q._root,q,Foreign()), (q._root,q,object.__new__(Child))):
            with self.assertRaises(response.OriginalResponseError): response.original_read_response(r, query, claim)
        self.assertEqual(calls, [])

    def test_direct_methods_refuse_foreign_descriptors_and_subclass_overrides(self):
        calls = []
        class Foreign:
            @property
            def _wire(self): calls.append("wire"); raise AssertionError
        class Child(response.OriginalReadResponse):
            def root_dict(self): calls.append("override"); raise AssertionError
        for method in (response.OriginalReadResponse.root_dict, response.OriginalReadResponse.as_dict,
                response.OriginalReadResponse.canonical_bytes.fget, response.OriginalReadResponse.message_digest_hex.fget):
            for value in (Foreign(), object.__new__(Child)):
                with self.assertRaises(response.OriginalResponseError): method(value)
        self.assertEqual(calls, [])

    def test_incomplete_damaged_and_nonexact_expected_selection_refuses_before_work(self):
        class Child(response.OriginalReadResponse): pass
        values = [None, object(), object.__new__(response.OriginalReadResponse), object.__new__(Child)]
        for field in ("_wire", "_root_wire", "_query", "_claim"):
            e = copy.deepcopy(self.expected)
            object.__setattr__(e, field, b"{}" if field in ("_wire", "_root_wire") else object())
            values.append(e)
        for e in values:
            calls = []
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(e, self.wire, verifier=lambda r: calls.append(r))
            self.assertEqual(calls, [])
        with self.assertRaises(FrozenInstanceError): self.expected._wire = b"{}"

    def test_callback_failures_sanitize_and_cancellation_propagates(self):
        def failure(r): raise RuntimeError("synthetic private detail")
        with self.assertRaises(response.OriginalResponseError) as caught:
            response.verify_selected_response(self.expected, self.wire, verifier=failure)
        self.assertNotIn("synthetic private detail", str(caught.exception))
        def cancel(r): raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt): response.verify_selected_response(self.expected, self.wire, verifier=cancel)
        with self.assertRaises(response.OriginalResponseError): response.verify_selected_response(self.expected, self.wire, verifier=None)

    def test_old_assignment_governor_and_root_packets_are_not_original_receipts(self):
        legacy = json.loads(Path("qualification/fixtures/source_response.json").read_text("ascii"))["positive_vectors"]["primary"]
        for packet in (legacy["envelope"], legacy["request"], self.primary["envelope"]["root_envelope"],
                legacy["response"]["query"]["governor_signature_request"], self.expected._claim.as_dict()):
            self.refuse(packet)

    def test_signed_malformed_rules_refuse_before_callback_except_curve_math_is_external(self):
        self.assertEqual(len(self.vectors["signed_refusal_vectors"]), 43)
        for name, v in self.vectors["signed_refusal_vectors"].items():
            if name == "original_noncurve_owner":
                continue
            self.refuse(v["envelope"])

    def test_factory_refuses_root_query_or_claim_from_different_independent_selection(self):
        e = selection("new_challenge")
        with self.assertRaises(response.OriginalResponseError):
            response.original_read_response(self.expected._query._root, self.expected._query, e._claim)
        e = selection("new_incarnation")
        with self.assertRaises(response.OriginalResponseError):
            response.original_read_response(e._query._root, self.expected._query, self.expected._claim)

    def test_request_and_envelope_have_distinct_exact_schemas_and_request_only_digest(self):
        p = response.request(self.expected, self.wire)
        self.assertEqual(p["schema"], response.REQUEST_SCHEMA)
        self.assertEqual(response.request_digest(p), self.primary["result"]["request_digest_hex"])
        with self.assertRaises(response.OriginalResponseError): response.request_digest(self.primary["envelope"])
        self.refuse(p)

    def test_hostile_manual_request_subclasses_refuse_before_foreign_hooks(self):
        calls = []
        class Text(str):
            def __eq__(self, other): calls.append("text"); raise AssertionError
        class Number(int):
            def __lt__(self, other): calls.append("number"); raise AssertionError
        class Mapping(dict):
            def __eq__(self, other): calls.append("mapping"); raise AssertionError
        primary = self.primary["request"]
        with self.assertRaises(response.OriginalResponseError): response.request_digest(Mapping(primary))
        for path, fields in objects(primary):
            for field, old in fields.items():
                if type(old) not in (str, int, dict): continue
                p = copy.deepcopy(primary)
                target(p, path)[field] = (Text(old) if type(old) is str else
                    Number(old) if type(old) is int else Mapping(old))
                with self.assertRaises(response.OriginalResponseError): response.request_digest(p)
        self.assertEqual(calls, [])


class OriginalResponsePublicCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-original-check-")
        self.addCleanup(temporary.cleanup)
        self.entry = Path(temporary.name)/"worker"
        self.entry.write_bytes(b"synthetic executable measurement only"); self.entry.chmod(0o700)
        self.digest = hashlib.sha256(self.entry.read_bytes()).hexdigest()
        self.check = PublicOriginalResponseCheck(self.entry, expected_executable_sha256_hex=self.digest)
        self.request = fixture()["positive_vectors"]["primary"]["request"]
        self.result = fake_check(self.request)

    def test_exact_two_flag_result_and_optional_one_lf_use_existing_bounded_runner(self):
        for suffix in (b"", b"\n"):
            with patch("qualification.original_read_response_verifier.run_public_worker", return_value=response._canonical(self.result)+suffix) as run:
                self.assertEqual(self.check(self.request), self.result)
                run.assert_called_once_with(str(self.entry), response._canonical(self.request), timeout=5, max_input_bytes=16384, max_output_bytes=512)

    def test_bad_pins_path_timeout_and_unexecutable_entry_refuse(self):
        for entry, digest, timeout in (("relative", self.digest,5), (self.entry,"ee"*32,5), (self.entry,"AB"*32,5),
                (self.entry,self.digest,True), (self.entry,self.digest,0), (self.entry,self.digest,31),
                (self.entry,self.digest,float("nan")), (self.entry,self.digest,float("inf"))):
            with self.assertRaises(response.OriginalResponseError):
                PublicOriginalResponseCheck(entry, expected_executable_sha256_hex=digest, timeout=timeout)
        self.entry.chmod(0o600)
        with self.assertRaises(response.OriginalResponseError): PublicOriginalResponseCheck(self.entry, expected_executable_sha256_hex=self.digest)

    def test_mismatched_extra_or_partial_result_and_noisy_output_refuse(self):
        for wire in (b"", b"{}", response._canonical(dict(self.result, owner_signature_valid=True)),
                response._canonical(dict(self.result, request_digest_hex="ee"*32)),
                response._canonical(dict(self.result, response_signature_valid=False)),
                response._canonical(self.result)+b"\n\n", b" "+response._canonical(self.result)):
            with patch("qualification.original_read_response_verifier.run_public_worker", return_value=wire), self.assertRaises(response.OriginalResponseError): self.check(self.request)

    def test_changed_entry_refuses_before_any_launch(self):
        self.entry.write_bytes(b"changed synthetic entry")
        with patch("qualification.original_read_response_verifier.run_public_worker") as run:
            with self.assertRaises(response.OriginalResponseError): self.check(self.request)
            run.assert_not_called()

    def test_missing_entry_refuses_before_any_launch(self):
        self.entry.unlink()
        with patch("qualification.original_read_response_verifier.run_public_worker") as run:
            with self.assertRaises(response.OriginalResponseError): self.check(self.request)
            run.assert_not_called()

    def test_malformed_request_refuses_before_any_launch(self):
        with patch("qualification.original_read_response_verifier.run_public_worker") as run:
            with self.assertRaises(response.OriginalResponseError): self.check(dict(self.request, permit=True))
            run.assert_not_called()

    def test_worker_failure_sanitizes_and_cancellation_propagates(self):
        with patch("qualification.original_read_response_verifier.run_public_worker", side_effect=WorkerError("synthetic private detail")):
            with self.assertRaises(response.OriginalResponseError) as caught: self.check(self.request)
            self.assertNotIn("synthetic private detail", str(caught.exception))
        with patch("qualification.original_read_response_verifier.run_public_worker", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt): self.check(self.request)
