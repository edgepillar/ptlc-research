"""Independent selection and transport checks; fake callbacks do no BIP340 math."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import governor_authentication as auth, governor_contract as contract
from offline_session.enrollment_authentication import _canonical as canonical
from offline_session.governor_verifier import SubprocessGovernorSignature
from offline_session.public_worker import WorkerError
from completion_test_support import released_bob
from test_governor_profile import local_profile
import test_enrollment_signature as legacy

_DEFAULT = object()


def fixture():
    return json.loads((Path(__file__).resolve().parents[1] / "qualification/fixtures/governor_signature.json").read_text("ascii"))


def selected_bound(state, name="primary", *, issuer=None, owner=None, profile_overrides=None):
    """Synthetic independent local selections, never incoming packet bootstrap."""
    vectors = fixture()
    owner = owner or vectors["alternate_owner" if name == "alternate_owner" else "primary"]["bound_intent"]["owner_auth_key_hex"]
    issuer = issuer or vectors["alternate_issuer" if name == "alternate_issuer" else "primary"]["assignment"]["issuer_auth_key_hex"]
    selected = legacy.selection()
    if name == "new_epoch": selected["authority_epoch"] = 2
    intent = legacy.local_intent(state, selected=selected, owner=owner)
    overrides = dict(profile_overrides or {})
    if name == "broader_caps": overrides.update(max_attempt_limit=3, max_target_limit=3)
    if name == "same_key_roles": issuer = owner
    assignment = contract.governor_assignment(local_profile(intent, **overrides), issuer_auth_key_hex=issuer)
    return contract.bound_enrollment_intent(assignment, intent)


def fake_check(request):
    """Forge matching public result bytes, without any signature math."""
    return auth.result_for_digest(auth.request_digest(request))


class GovernorSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.vectors = released_bob(), fixture()
        cls.bound = selected_bound(cls.state)
        cls.vector = cls.vectors["primary"]
        cls.wire = canonical(cls.vector["envelope"])

    def refuse_before_work(self, packet, expected=_DEFAULT):
        calls = []
        with self.assertRaises(auth.GovernorSignatureError):
            auth.verify_signatures(self.bound if expected is _DEFAULT else expected,
                canonical(packet), verifier=lambda request: calls.append(request))
        self.assertEqual(calls, [])

    def test_exact_fixture_framing_reproduces_both_independent_messages(self):
        signatures = {field: bytes.fromhex(self.vector["request"][field + "_hex"])
                      for field in ("issuer_signature", "owner_signature")}
        self.assertEqual(auth.envelope(self.bound, **signatures), self.wire)
        self.assertEqual(auth.request(self.bound, self.wire), self.vector["request"])
        self.assertEqual(self.bound._assignment.digest_hex, self.vector["assignment_digest_hex"])
        self.assertEqual(self.bound.message_digest_hex, self.vector["bound_message_digest_hex"])
        self.assertEqual(auth.request_digest(self.vector["request"]), self.vector["result"]["request_digest_hex"])
        self.assertEqual(self.vector["result"], auth.result_for_digest(hashlib.sha256(
            b"PTLC/observation-governor-signature-request/v1\0" + canonical(self.vector["request"])).hexdigest()))

    def test_success_returns_same_unsigned_object_and_replay_changes_no_source(self):
        before = copy.deepcopy(self.state)
        for _ in range(3):
            self.assertIs(auth.verify_signatures(self.bound, self.wire, verifier=fake_check), self.bound)
        self.assertEqual(self.state, before)
        for name in ("authorized", "issuer_verified", "owner_verified", "enrolled", "quota_granted", "permit"):
            self.assertFalse(hasattr(self.bound, name))

    def test_each_valid_alternative_local_choice_cannot_replace_complete_expectations(self):
        for name in ("alternate_issuer", "alternate_owner", "broader_caps", "new_epoch", "same_key_roles"):
            with self.subTest(name=name):
                self.refuse_before_work(self.vectors[name]["envelope"])
                expected = selected_bound(self.state, name)
                self.assertIs(auth.verify_signatures(expected, canonical(self.vectors[name]["envelope"]), verifier=fake_check), expected)

    def test_every_assignment_profile_and_v2_intent_mutation_refuses_before_work(self):
        for path in (("assignment",), ("assignment", "governor_profile"), ("bound_intent",)):
            fields = self.vector["envelope"]
            for field in path: fields = fields[field]
            for field, old in fields.items():
                packet = copy.deepcopy(self.vector["envelope"]); target = packet
                for part in path: target = target[part]
                target[field] = old + 1 if type(old) is int else "99" * 32
                with self.subTest(path=path, field=field): self.refuse_before_work(packet)

    def test_missing_extra_and_wrong_types_refuse_at_every_packet_level(self):
        for path in ((), ("assignment",), ("assignment", "governor_profile"), ("bound_intent",)):
            fields = self.vector["envelope"]
            for field in path: fields = fields[field]
            for field in fields:
                packet = copy.deepcopy(self.vector["envelope"]); target = packet
                for part in path: target = target[part]
                target.pop(field)
                self.refuse_before_work(packet)
                for wrong in (None, True, [], {}):
                    packet = copy.deepcopy(self.vector["envelope"]); target = packet
                    for part in path: target = target[part]
                    target[field] = wrong
                    self.refuse_before_work(packet)
            packet = copy.deepcopy(self.vector["envelope"]); target = packet
            for part in path: target = target[part]
            target["authorized"] = True
            self.refuse_before_work(packet)

    def test_profile_numbers_reject_aliases_and_out_of_range_values(self):
        for field, maximum in (("authority_epoch", (1 << 53) - 1), ("max_attempt_limit", 64), ("max_target_limit", 64)):
            for wrong in (0, -1, maximum + 1, 1.0, "1", True):
                packet = copy.deepcopy(self.vector["envelope"])
                packet["assignment"]["governor_profile"][field] = wrong
                self.refuse_before_work(packet)

    def test_noncanonical_duplicates_aliases_deep_and_oversized_wire_refuse(self):
        for wire in (b"", self.wire + b"\n", b" " + self.wire, self.wire + b" ", b"\xff",
            self.wire.replace(b'"assignment":', b'"\\u0061ssignment":'),
            b'{"schema":"' + auth.ENVELOPE_SCHEMA.encode("ascii") + b'",' + self.wire[1:],
            self.wire.replace(b'"authority_epoch":1', b'"authority_epoch":1,"authority_epoch":1'),
            self.wire.replace(b'"authority_epoch":1', b'"authority_epoch":1e0'),
            b"[" * 512 + b"]" * 512, b" " * (auth.MAX_WIRE_BYTES + 1)):
            calls = []
            with self.assertRaises(auth.GovernorSignatureError):
                auth.verify_signatures(self.bound, wire, verifier=lambda request: calls.append(request))
            self.assertEqual(calls, [])

    def test_two_exact_public_signature_encodings_required_without_math(self):
        for field in ("issuer_signature_hex", "owner_signature_hex"):
            for value in ("00" * 63, "00" * 65, "ZZ" * 64, self.vector["request"][field].upper(), True):
                changed = copy.deepcopy(self.vector["envelope"]); changed[field] = value
                self.refuse_before_work(changed)
        wire = auth.envelope(self.bound, issuer_signature=bytes(64), owner_signature=bytes(64))
        self.assertIs(auth.verify_signatures(self.bound, wire, verifier=fake_check), self.bound)
        # This deliberately forged positive proves the selected-callback boundary.

    def test_envelope_refuses_nonbytes_and_inexact_signatures(self):
        for wrong in (bytearray(64), "00" * 64, bytes(63), bytes(65), None):
            for field in ("issuer_signature", "owner_signature"):
                args = dict(issuer_signature=bytes(64), owner_signature=bytes(64)); args[field] = wrong
                with self.assertRaises(auth.GovernorSignatureError): auth.envelope(self.bound, **args)

    def test_malicious_selected_verifier_can_forge_exact_positive_and_no_role(self):
        wire = auth.envelope(self.bound, issuer_signature=bytes(64), owner_signature=bytes(64))
        self.assertIs(auth.verify_signatures(self.bound, wire, verifier=fake_check), self.bound)
        self.assertEqual(set(fake_check(auth.request(self.bound, wire))),
                         {"schema", "request_digest_hex", "issuer_signature_valid", "owner_signature_valid"})

    def test_result_requires_both_exact_true_flags_and_complete_digest(self):
        for field, wrong in (("schema", "unsupported"), ("request_digest_hex", "99" * 32),
            ("issuer_signature_valid", False), ("owner_signature_valid", False),
            ("issuer_signature_valid", 1), ("owner_signature_valid", "true")):
            result = dict(self.vector["result"], **{field: wrong})
            with self.assertRaises(auth.GovernorSignatureError):
                auth.verify_signatures(self.bound, self.wire, verifier=lambda request: result)
        for result in (None, [], dict(self.vector["result"], authorized=True),
            {key: value for key, value in self.vector["result"].items() if key != "issuer_signature_valid"}):
            with self.assertRaises(auth.GovernorSignatureError):
                auth.verify_signatures(self.bound, self.wire, verifier=lambda request: result)

    def test_either_alternate_signature_changes_full_request_result_binding(self):
        for field in ("issuer", "owner"):
            packet = copy.deepcopy(self.vector["envelope"])
            packet[field + "_signature_hex"] = self.vectors["alternate_" + field + "_signature_hex"]
            request = auth.request(self.bound, canonical(packet))
            self.assertNotEqual(auth.request_digest(request), self.vector["result"]["request_digest_hex"])
            self.assertIs(auth.verify_signatures(self.bound, canonical(packet), verifier=fake_check), self.bound)
            with self.assertRaises(auth.GovernorSignatureError):
                auth.verify_signatures(self.bound, canonical(packet), verifier=lambda request: self.vector["result"])

    def test_legacy_packets_and_signatures_are_not_reinterpreted_as_v2_math(self):
        for packet in (legacy.fixture()["envelope"], self.vector["request"]): self.refuse_before_work(packet)
        # Framing permits a shape-valid old signature; only actual math can refuse it.
        packet = copy.deepcopy(self.vector["envelope"])
        packet["owner_signature_hex"] = legacy.fixture()["request"]["signature_hex"]
        self.assertIs(auth.verify_signatures(self.bound, canonical(packet), verifier=fake_check), self.bound)

    def test_opaque_scope_hash_cannot_bypass_independently_prepared_caps(self):
        packet = self.vectors["opaque_scope_under_caps"]["envelope"]
        self.refuse_before_work(packet)
        self.assertEqual(packet["bound_intent"]["scope_digest_hex"], self.vector["bound_intent"]["scope_digest_hex"])
        with self.assertRaises(contract.GovernorContractError):
            selected_bound(self.state, profile_overrides=dict(max_attempt_limit=1, max_target_limit=1))

    def test_stale_local_expectation_still_matches_without_current_authority(self):
        newer = selected_bound(self.state, "new_epoch")
        self.refuse_before_work(self.vector["envelope"], newer)
        self.assertIs(auth.verify_signatures(self.bound, self.wire, verifier=fake_check), self.bound)

    def test_changed_live_source_copy_does_not_refresh_retained_selection(self):
        state = copy.deepcopy(self.state); expected = selected_bound(state)
        state["release_hex"] = "00"
        self.assertIs(auth.verify_signatures(expected, self.wire, verifier=fake_check), expected)
        with self.assertRaises(ValueError): selected_bound(state)

    def test_same_key_for_two_roles_is_format_allowed_and_not_role_separation(self):
        expected = selected_bound(self.state, "same_key_roles")
        self.assertEqual(expected.as_dict()["owner_auth_key_hex"], expected._assignment.as_dict()["issuer_auth_key_hex"])
        self.assertIs(auth.verify_signatures(expected, canonical(self.vectors["same_key_roles"]["envelope"]), verifier=fake_check), expected)

    def test_worker_receives_defensive_request_copy_and_cannot_rebind_result(self):
        def changed(request):
            request["owner_signature_hex"] = self.vectors["alternate_owner_signature_hex"]
            return fake_check(request)
        with self.assertRaises(auth.GovernorSignatureError):
            auth.verify_signatures(self.bound, self.wire, verifier=changed)
        self.assertEqual(canonical(self.vector["envelope"]), self.wire)

    def test_changed_independent_selection_during_callback_refuses(self):
        expected = selected_bound(self.state)
        def changed(request):
            object.__setattr__(expected, "_wire", canonical(dict(expected.as_dict(), request_id_hex="99" * 32)))
            return fake_check(request)
        with self.assertRaises(auth.GovernorSignatureError):
            auth.verify_signatures(expected, self.wire, verifier=changed)

    def test_incomplete_damaged_and_nonexact_expected_objects_refuse_before_work(self):
        for expected in (None, self.bound.as_dict(), self.bound._intent, object.__new__(contract.BoundEnrollmentIntent)):
            self.refuse_before_work(self.vector["envelope"], expected)
        damaged = selected_bound(self.state); object.__setattr__(damaged._assignment, "_wire", b"{}")
        self.refuse_before_work(self.vector["envelope"], damaged)

    def test_hostile_mapping_and_string_subclasses_refuse_without_hooks(self):
        calls = []
        class Hostile(dict):
            def __iter__(self): calls.append("iterate"); raise AssertionError("foreign hook")
            def __len__(self): calls.append("length"); raise AssertionError("foreign hook")
        class Text(str):
            def __eq__(self, other): calls.append("equal"); raise AssertionError("foreign hook")
        for request in (Hostile(self.vector["request"]),
            dict(self.vector["request"], schema=Text(auth.REQUEST_SCHEMA))):
            with self.assertRaises(auth.GovernorSignatureError): auth.request_digest(request)
        self.assertEqual(calls, [])

    def test_callback_failures_are_sanitized_and_cancellation_propagates(self):
        def failed(request): raise RuntimeError("synthetic private diagnostic")
        with self.assertRaisesRegex(auth.GovernorSignatureError, "^public governor signature verification failed$"):
            auth.verify_signatures(self.bound, self.wire, verifier=failed)
        def cancelled(request): raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): auth.verify_signatures(self.bound, self.wire, verifier=cancelled)
        with self.assertRaises(auth.GovernorSignatureError): auth.verify_signatures(self.bound, self.wire, verifier=None)


class GovernorSignatureAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.request = fixture()["primary"]["request"]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-governor-entry-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "worker"
        self.path.write_bytes(b"synthetic executable entry"); self.path.chmod(0o700)
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.adapter = SubprocessGovernorSignature(self.path, expected_executable_sha256_hex=self.digest)

    def test_exact_result_and_one_lf_use_existing_bounded_runner(self):
        expected = fake_check(self.request)
        for wire in (canonical(expected), canonical(expected) + b"\n"):
            with patch("offline_session.governor_verifier.run_public_worker", return_value=wire) as run:
                self.assertEqual(self.adapter(self.request), expected)
                run.assert_called_once_with(str(self.path), canonical(self.request), timeout=5,
                    max_input_bytes=8192, max_output_bytes=512)

    def test_mismatched_digest_incomplete_results_or_extra_output_refuse(self):
        expected = fake_check(self.request)
        for wire in (b"{}", canonical(expected) + b"\n\n", b" " + canonical(expected),
            canonical(dict(expected, request_digest_hex="99" * 32)),
            canonical(dict(expected, owner_signature_valid=False)), canonical(dict(expected, authorized=True))):
            with patch("offline_session.governor_verifier.run_public_worker", return_value=wire):
                with self.assertRaises(auth.GovernorSignatureError): self.adapter(self.request)

    def test_changed_entry_refuses_before_runner(self):
        self.path.write_bytes(b"changed synthetic entry")
        with patch("offline_session.governor_verifier.run_public_worker") as run:
            with self.assertRaises(auth.GovernorSignatureError): self.adapter(self.request)
            run.assert_not_called()

    def test_bad_pin_path_timeout_or_unexecutable_entry_refuse(self):
        for path, digest, timeout in ((Path("worker"), self.digest, 5), (self.path, "99" * 32, 5),
            (self.path, self.digest, True), (self.path, self.digest, 0), (self.path, self.digest, 31)):
            with self.assertRaises(auth.GovernorSignatureError):
                SubprocessGovernorSignature(path, expected_executable_sha256_hex=digest, timeout=timeout)
        self.path.chmod(0o600)
        with self.assertRaises(auth.GovernorSignatureError):
            SubprocessGovernorSignature(self.path, expected_executable_sha256_hex=self.digest)

    def test_missing_or_oversized_entry_refuses_before_launch(self):
        with patch("offline_session.governor_verifier._file_digest", side_effect=ValueError("synthetic oversized entry")):
            with self.assertRaises(auth.GovernorSignatureError): self.adapter(self.request)
        self.path.unlink()
        with self.assertRaises(auth.GovernorSignatureError): self.adapter(self.request)

    def test_worker_failure_is_sanitized_and_cancellation_propagates(self):
        for error in (WorkerError("synthetic timeout"), OSError("synthetic diagnostic")):
            with patch("offline_session.governor_verifier.run_public_worker", side_effect=error):
                with self.assertRaisesRegex(auth.GovernorSignatureError, "^public governor signature verifier failed$"):
                    self.adapter(self.request)
        with patch("offline_session.governor_verifier.run_public_worker", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt): self.adapter(self.request)

    def test_malformed_request_refuses_before_runner(self):
        with patch("offline_session.governor_verifier.run_public_worker") as run:
            with self.assertRaises(auth.GovernorSignatureError): self.adapter({})
            run.assert_not_called()
