"""Local binding/transport guards; fake callbacks supply no signature evidence."""

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import authority_contract as authority, completion
from offline_session import enrollment_contract as contract, enrollment_authentication as auth
from offline_session.enrollment_verifier import SubprocessEnrollmentSignature
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from offline_session.observation_verifier import MAX_EXECUTABLE_BYTES
from offline_session.public_worker import WorkerError
from completion_test_support import final_signatures, released_bob
from exchange_test_support import prepare


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def fixture():
    return json.loads((Path(__file__).resolve().parents[1] / "qualification/fixtures/enrollment_signature.json").read_text("ascii"))


def selection():
    return dict(authority_id_hex="11" * 32, enrollment_id_hex="22" * 32, authority_epoch=1,
        authority_profile_digest_hex="33" * 32, verifier_profile_digest_hex="44" * 32,
        pool_profile_digest_hex="55" * 32, resource_profile_digest_hex="66" * 32, attempt_limit=2, target_limit=2)


def local_intent(state, *, selected=None, owner=None, request_id="88" * 32):
    scope = authority.authority_scope(state, **(selection() if selected is None else selected))
    resource = contract.retained_resource(scope)
    owner = fixture()["intent"]["owner_auth_key_hex"] if owner is None else owner
    return contract.enrollment_intent(state, scope, resource, owner_auth_key_hex=owner, request_id_hex=request_id)


def fake_check(request):
    """Forge a matching public result; no curve or BIP340 verification occurs."""
    return dict(schema=auth.RESULT_SCHEMA, request_digest_hex=auth.request_digest(request), signature_valid=True)


class EnrollmentSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector, cls.state = fixture(), released_bob()
        cls.intent = local_intent(cls.state)
        cls.wire = canonical(cls.vector["envelope"])
        cls.signature = bytes.fromhex(cls.vector["request"]["signature_hex"])

    def test_cross_language_fixture_matches_retained_source_and_exact_message(self):
        self.assertEqual(self.intent._scope.as_dict(), self.vector["scope"])
        self.assertEqual(self.intent._resource.as_dict(), self.vector["resource"])
        self.assertEqual(self.intent.as_dict(), self.vector["intent"])
        self.assertEqual(self.intent.message_digest_hex, self.vector["message_digest_hex"])
        self.assertEqual(auth.envelope(self.intent, self.signature), self.wire)
        self.assertEqual(auth.request(self.intent, self.wire), self.vector["request"])
        self.assertEqual(auth.request_digest(self.vector["request"]), self.vector["result"]["request_digest_hex"])
        self.assertEqual(self.intent.message_digest_hex, hashlib.sha256(
            b"PTLC/observation-enrollment-owner-intent/v1\0" + canonical(self.vector["intent"])).hexdigest())

    def test_success_returns_same_unsigned_intent_without_authority_properties(self):
        before = copy.deepcopy(self.state)
        for _ in range(2):
            self.assertIs(auth.verify_signature(self.intent, self.wire, verifier=fake_check), self.intent)
        self.assertEqual(self.state, before)
        for name in ("authorized", "owner_verified", "enrolled", "quota_granted", "permit", "can_start"):
            self.assertFalse(hasattr(self.intent, name))

    def test_valid_alternate_owner_and_self_selected_source_refuse_before_work(self):
        for name in ("alternate_owner", "self_selected_source"):
            calls = []
            with self.subTest(vector=name), self.assertRaises(auth.EnrollmentSignatureError):
                auth.verify_signature(self.intent, canonical(self.vector[name]["envelope"]), verifier=lambda v: calls.append(v))
            self.assertEqual(calls, [])

    def test_all_eight_intent_mutations_refuse_before_work(self):
        for field, old in self.vector["intent"].items():
            changed = copy.deepcopy(self.vector["envelope"])
            changed["intent"][field] = "99" * 32 if field.endswith("_hex") else "unsupported"
            self.assertNotEqual(changed["intent"][field], old)
            calls = []
            with self.subTest(field=field), self.assertRaises(auth.EnrollmentSignatureError):
                auth.verify_signature(self.intent, canonical(changed), verifier=lambda v: calls.append(v))
            self.assertEqual(calls, [])

    def test_all_nine_external_scope_changes_refuse_old_envelope(self):
        for field, old in selection().items():
            selected = dict(selection(), **{field: old + 1 if type(old) is int else "99" * 32})
            intent = local_intent(self.state, selected=selected)
            self.assertEqual(intent._resource, self.intent._resource)
            self.assertNotEqual(intent.message_digest_hex, self.intent.message_digest_hex)
            calls = []
            with self.subTest(field=field), self.assertRaises(auth.EnrollmentSignatureError):
                auth.verify_signature(intent, self.wire, verifier=lambda v: calls.append(v))
            self.assertEqual(calls, [])

    def test_candidate_and_copy_changes_keep_selected_message_and_envelope(self):
        for signature in (final_signatures()[0], bytes(64), b"\xff" * 64):
            state = completion.observe_bob(self.state, completion.bob_candidate_from_signature(self.state, signature))
            intent = local_intent(state)
            self.assertEqual(intent, self.intent)
            self.assertEqual(auth.envelope(intent, self.signature), self.wire)
        self.assertEqual(local_intent(copy.deepcopy(self.state)), self.intent)

    def test_unsigned_intent_request_and_legacy_schemas_are_not_envelopes(self):
        values = [self.intent.canonical_bytes, canonical(self.vector["request"])]
        for schema in ("ptlc-completion-auth-envelope-v1", "ptlc-observation-enrollment-signature-envelope-v2"):
            values.append(canonical(dict(self.vector["envelope"], schema=schema)))
        for wire in values:
            with self.assertRaises(auth.EnrollmentSignatureError): auth.request(self.intent, wire)

    def test_packaging_requires_exact_signature_bytes_and_does_no_crypto(self):
        self.assertEqual(auth.request(self.intent, auth.envelope(self.intent, bytes(64)))["signature_hex"], "00" * 64)
        for signature in (None, "00" * 64, bytes(63), bytes(65), bytearray(64), memoryview(bytes(64))):
            with self.assertRaises(auth.EnrollmentSignatureError): auth.envelope(self.intent, signature)

    def test_wire_bounds_canonical_alias_duplicates_and_depth_refuse(self):
        values = [b"", b"x" * (auth.MAX_WIRE_BYTES + 1), self.wire + b"\n", b" " + self.wire,
            json.dumps(self.vector["envelope"], indent=2).encode(), self.wire.replace(b'"intent":', b'"\\u0069ntent":'),
            b'{"schema":"ptlc-observation-enrollment-signature-envelope-v1",' + self.wire[1:],
            self.wire.replace(b'"role":', b'"role":"enrollment-governor","role":'), b"[" * 1000 + b"]" * 1000,
            b"\xff", None, {}, bytearray(self.wire), memoryview(self.wire)]
        for wire in values:
            with self.assertRaises(auth.EnrollmentSignatureError): auth.request(self.intent, wire)

    def test_shape_guards_reject_missing_extra_nonstring_fields_at_each_level(self):
        for nested in (False, True):
            source = self.vector["request"]["intent"] if nested else self.vector["request"]
            for field in source:
                for wrong in (None, True, 1, [], {}):
                    changed = copy.deepcopy(self.vector["request"])
                    target = changed["intent"] if nested else changed
                    target[field] = wrong
                    with self.assertRaises(auth.EnrollmentSignatureError): auth.request_digest(changed)
                changed = copy.deepcopy(self.vector["request"])
                del (changed["intent"] if nested else changed)[field]
                with self.assertRaises(auth.EnrollmentSignatureError): auth.request_digest(changed)
            changed = copy.deepcopy(self.vector["request"])
            (changed["intent"] if nested else changed)["authorized"] = True
            with self.assertRaises(auth.EnrollmentSignatureError): auth.request_digest(changed)

    def test_hostile_objects_and_subclasses_supply_no_hooks(self):
        calls = []
        class HostileDict(dict):
            def __iter__(self): calls.append(True); raise RuntimeError("untrusted-diagnostic-marker")
        class HostileBytes(bytes):
            def __len__(self): calls.append(True); raise RuntimeError("untrusted-diagnostic-marker")
        class HostileIntent(contract.EnrollmentIntent):
            def as_dict(self): calls.append(True); raise RuntimeError("untrusted-diagnostic-marker")
        for request in (HostileDict(self.vector["request"]), dict(self.vector["request"], intent=HostileDict(self.vector["intent"]))):
            with self.assertRaises(auth.EnrollmentSignatureError): auth.request_digest(request)
        with self.assertRaises(auth.EnrollmentSignatureError): auth.request(self.intent, HostileBytes(self.wire))
        with self.assertRaises(auth.EnrollmentSignatureError): auth.envelope(self.intent, HostileBytes(bytes(64)))
        with self.assertRaises(auth.EnrollmentSignatureError): auth.envelope(object.__new__(HostileIntent), self.signature)
        self.assertEqual(calls, [])

    def test_closed_and_tampered_expected_intents_refuse_before_work(self):
        with self.assertRaises(TypeError): contract.EnrollmentIntent()
        for intent in (None, self.vector["intent"], object.__new__(contract.EnrollmentIntent)):
            with self.assertRaises(auth.EnrollmentSignatureError): auth.request(intent, self.wire)
        changed = copy.copy(self.intent); object.__setattr__(changed, "_wire", b"untrusted-diagnostic-marker")
        calls = []
        with self.assertRaises(auth.EnrollmentSignatureError) as error:
            auth.verify_signature(changed, self.wire, verifier=lambda v: calls.append(v))
        self.assertEqual(calls, []); self.assertNotIn("untrusted-diagnostic-marker", str(error.exception))

    def test_wrong_stale_extra_or_bool_aliased_result_supplies_no_fact(self):
        for value in (None, [], canonical(self.vector["result"]),
            dict(self.vector["result"], signature_valid=1), dict(self.vector["result"], signature_valid=False),
            dict(self.vector["result"], authorized=True), dict(self.vector["result"], request_digest_hex="00" * 32),
            dict(self.vector["result"], schema="ptlc-completion-auth-result-v1")):
            with self.assertRaises(auth.EnrollmentSignatureError):
                auth.verify_signature(self.intent, self.wire, verifier=lambda _, value=value: value)
        with self.assertRaises(auth.EnrollmentSignatureError): auth.verify_signature(self.intent, self.wire, verifier=None)

    def test_callback_errors_and_mutations_are_sanitized_and_defensive(self):
        def failure(_): raise RuntimeError("untrusted-diagnostic-marker")
        with self.assertRaises(auth.EnrollmentSignatureError) as error:
            auth.verify_signature(self.intent, self.wire, verifier=failure)
        self.assertNotIn("untrusted-diagnostic-marker", str(error.exception))
        def mutate(request):
            request["intent"]["scope_digest_hex"] = "ff" * 32
            return fake_check(request)
        with self.assertRaises(auth.EnrollmentSignatureError): auth.verify_signature(self.intent, self.wire, verifier=mutate)
        self.assertEqual(self.intent.as_dict(), self.vector["intent"])
        changed = copy.copy(self.intent)
        def mutate_expected(request):
            object.__setattr__(changed, "_wire", b"broken")
            return fake_check(request)
        with self.assertRaises(auth.EnrollmentSignatureError): auth.verify_signature(changed, self.wire, verifier=mutate_expected)

    def test_cancellation_propagates_without_success_or_state_change(self):
        for kind in (KeyboardInterrupt, SystemExit):
            def cancel(_): raise kind()
            with self.assertRaises(kind): auth.verify_signature(self.intent, self.wire, verifier=cancel)
        self.assertEqual(self.intent.as_dict(), self.vector["intent"])

    def test_replay_stale_expectation_and_reused_id_supply_no_freshness(self):
        mutable_source = copy.deepcopy(self.state)
        expected = local_intent(mutable_source)
        mutable_source["release_hex"] = "00"
        for _ in range(3): self.assertIs(auth.verify_signature(expected, self.wire, verifier=fake_check), expected)
        other = local_intent(self.state, selected=dict(selection(), authority_epoch=2))
        self.assertEqual(other.as_dict()["request_id_hex"], expected.as_dict()["request_id_hex"])
        self.assertNotEqual(other.message_digest_hex, expected.message_digest_hex)

    def test_alternate_signature_changes_the_full_result_binding(self):
        wire = auth.envelope(self.intent, bytes.fromhex(self.vector["alternate_signature_hex"]))
        request = auth.request(self.intent, wire)
        self.assertEqual(request["intent"], self.vector["intent"])
        self.assertNotEqual(auth.request_digest(request), self.vector["result"]["request_digest_hex"])
        with self.assertRaises(auth.EnrollmentSignatureError):
            auth.verify_signature(self.intent, wire, verifier=lambda _: self.vector["result"])

    def test_malicious_selected_verifier_can_forge_a_matching_positive(self):
        wire = auth.envelope(self.intent, bytes(64))
        self.assertIs(auth.verify_signature(self.intent, wire, verifier=fake_check), self.intent)
        zero_key = local_intent(self.state, owner="00" * 32)
        self.assertIs(auth.verify_signature(zero_key, auth.envelope(zero_key, bytes(64)), verifier=fake_check), zero_key)

    def test_verification_after_exhausted_journal_reopen_changes_no_storage(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-enrollment-signature-") as directory:
            root, head = Path(directory) / "state", Path(directory) / "head.json"
            with Journal.open(root, head) as journal:
                session = prepare(journal, recovery_limit=1); journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict): journal.complete_exchange_bitcoin(session, invalid, recoverer=lambda _: None)
            with Journal.open(root, head) as journal:
                state = journal.get_exchange(session); intent = local_intent(state)
                self.assertEqual(intent, self.intent)
                before = (copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes())
                for _ in range(2): self.assertIs(auth.verify_signature(intent, self.wire, verifier=fake_check), intent)
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, completion.bob_candidate_from_signature(state, final_signatures()[0]),
                        expected_observation_digest=completion.observation_digest(invalid), recoverer=lambda v: calls.append(v))
                self.assertEqual((copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes()), before)
                self.assertEqual(calls, []); self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)


class EnrollmentSignatureAdapterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="synthetic-enrollment-worker-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "worker"
        self.path.write_bytes(b"synthetic executable fixture"); self.path.chmod(0o700)
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.vector = fixture()
        self.adapter = SubprocessEnrollmentSignature(self.path, expected_executable_sha256_hex=self.digest)

    def test_constructor_requires_explicit_valid_pin_path_and_deadline(self):
        for digest in (None, True, "ff" * 32, "AA" * 32, "0" * 63):
            with self.assertRaises(auth.EnrollmentSignatureError): SubprocessEnrollmentSignature(self.path, expected_executable_sha256_hex=digest)
        for timeout in (True, None, 0, -1, 31, float("nan"), float("inf"), 10 ** 1000):
            with self.assertRaises(auth.EnrollmentSignatureError): SubprocessEnrollmentSignature(self.path, expected_executable_sha256_hex=self.digest, timeout=timeout)
        with self.assertRaises(auth.EnrollmentSignatureError): SubprocessEnrollmentSignature("relative-worker", expected_executable_sha256_hex=self.digest)
        with self.assertRaises(TypeError): SubprocessEnrollmentSignature(self.path)

    def test_exact_result_with_at_most_one_lf_uses_bounded_runner(self):
        for output in (canonical(self.vector["result"]), canonical(self.vector["result"]) + b"\n"):
            with patch("offline_session.enrollment_verifier.run_public_worker", return_value=output) as run:
                self.assertEqual(self.adapter(self.vector["request"]), self.vector["result"])
                run.assert_called_once_with(str(self.path), canonical(self.vector["request"]), timeout=5, max_input_bytes=8192, max_output_bytes=512)

    def test_malformed_stale_alias_and_overlong_output_refuse(self):
        outputs = [b"", b"x" * 513, canonical(self.vector["result"]) + b"\n\n", b" " + canonical(self.vector["result"])]
        for field, value in (("schema", "ptlc-completion-auth-result-v1"), ("request_digest_hex", "ff" * 32), ("signature_valid", 1)):
            outputs.append(canonical(dict(self.vector["result"], **{field: value})))
        outputs.append(canonical(dict(self.vector["result"], authorized=True)))
        for output in outputs:
            with patch("offline_session.enrollment_verifier.run_public_worker", return_value=output), self.assertRaises(auth.EnrollmentSignatureError):
                self.adapter(self.vector["request"])

    def test_malformed_request_refuses_before_measurement_or_launch(self):
        with patch("offline_session.enrollment_verifier._file_digest") as measure, patch("offline_session.enrollment_verifier.run_public_worker") as run:
            for request in (None, {}, {"value": "x" * 8193}, dict(self.vector["request"], authorized=True)):
                with self.assertRaises(auth.EnrollmentSignatureError): self.adapter(request)
            measure.assert_not_called(); run.assert_not_called()

    def test_changed_missing_or_nonregular_entry_refuses_before_launch(self):
        with patch("offline_session.enrollment_verifier.run_public_worker") as run:
            self.path.write_bytes(b"changed executable")
            with self.assertRaises(auth.EnrollmentSignatureError): self.adapter(self.vector["request"])
            self.path.unlink()
            with self.assertRaises(auth.EnrollmentSignatureError): self.adapter(self.vector["request"])
            os.mkfifo(self.path)
            with self.assertRaises(auth.EnrollmentSignatureError): self.adapter(self.vector["request"])
            run.assert_not_called()

    def test_worker_errors_are_sanitized_and_cancellation_propagates(self):
        for error in (WorkerError("untrusted-diagnostic-marker"), OSError("untrusted-diagnostic-marker")):
            with patch("offline_session.enrollment_verifier.run_public_worker", side_effect=error), self.assertRaises(auth.EnrollmentSignatureError) as caught:
                self.adapter(self.vector["request"])
            self.assertNotIn("untrusted-diagnostic-marker", str(caught.exception))
        for error in (KeyboardInterrupt(), SystemExit()):
            with patch("offline_session.enrollment_verifier.run_public_worker", side_effect=error), self.assertRaises(type(error)):
                self.adapter(self.vector["request"])

    def test_entry_measurement_rejects_empty_or_oversized_file(self):
        for size in (0, MAX_EXECUTABLE_BYTES + 1):
            with self.path.open("wb") as source: source.truncate(size)
            with self.assertRaises(auth.EnrollmentSignatureError): SubprocessEnrollmentSignature(self.path, expected_executable_sha256_hex=self.digest)


if __name__ == "__main__":
    unittest.main()
