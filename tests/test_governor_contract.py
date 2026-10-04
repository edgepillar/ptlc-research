"""Unsigned complete bindings are not issuer trust, signatures or currentness."""

import ast
import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from offline_session import completion, enrollment_authentication as auth
from offline_session import enrollment_contract as enrollment
from offline_session import governor_contract as contract, governor_profile as governor
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import final_signatures, released_bob
from exchange_test_support import prepare
from test_enrollment_contract import changed_source
from test_governor_profile import local_profile
import test_enrollment_signature as support


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


class GovernorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.intent = support.local_intent(cls.state)
        cls.profile = local_profile(cls.intent)
        cls.issuer = support.fixture()["alternate_owner"]["intent"]["owner_auth_key_hex"]
        cls.assignment = contract.governor_assignment(cls.profile, issuer_auth_key_hex=cls.issuer)
        cls.bound = contract.bound_enrollment_intent(cls.assignment, cls.intent)
        cls.vector = json.loads((Path(__file__).resolve().parents[1] / "qualification/fixtures/governor_contract.json").read_text("ascii"))

    def refuse_assignment(self, wire):
        with self.assertRaises(contract.GovernorContractError):
            contract.parse_governor_assignment(self.assignment, wire)

    def refuse_bound(self, wire):
        with self.assertRaises(contract.GovernorContractError):
            contract.parse_bound_enrollment_intent(self.bound, wire)

    def test_exact_five_field_unsigned_assignment_and_separate_domain(self):
        value = dict(schema=contract.ASSIGNMENT_SCHEMA, purpose=contract.ASSIGNMENT_PURPOSE,
            algorithm=enrollment.ALGORITHM, issuer_auth_key_hex=self.issuer, governor_profile=self.profile.as_dict())
        self.assertEqual(len(value), 5)
        self.assertEqual(len(value["governor_profile"]), 14)
        self.assertEqual(self.assignment.canonical_bytes, canonical(value))
        self.assertEqual(self.assignment.digest_hex, hashlib.sha256(
            b"PTLC/observation-governor-assignment/v1\0" + canonical(value)).hexdigest())
        self.assertNotEqual(self.assignment.digest_hex, self.profile.digest_hex)
        self.assertNotEqual(self.assignment.digest_hex, self.profile.as_dict()["authority_profile_digest_hex"])

    def test_exact_nine_field_profile_bound_intent_and_distinct_v2_domain(self):
        value = dict(self.intent.as_dict(), schema=contract.BOUND_INTENT_SCHEMA,
                     governor_assignment_digest_hex=self.assignment.digest_hex)
        self.assertEqual(len(value), 9)
        self.assertEqual(self.bound.canonical_bytes, canonical(value))
        self.assertEqual(self.bound.message_digest_hex, hashlib.sha256(
            b"PTLC/observation-enrollment-owner-intent/v2\0" + canonical(value)).hexdigest())
        self.assertNotEqual(self.bound.message_digest_hex, self.intent.message_digest_hex)
        self.assertNotEqual(self.bound.message_digest_hex, hashlib.sha256(
            b"PTLC/observation-enrollment-owner-intent/v1\0" + canonical(value)).hexdigest())

    def test_unsigned_public_vector_pins_exact_bytes_and_all_digests(self):
        self.assertEqual(self.vector["schema"], "ptlc-governor-contract-unsigned-vector-v1")
        self.assertEqual(self.vector["assignment"], self.assignment.as_dict())
        self.assertEqual(self.vector["bound_intent"], self.bound.as_dict())
        for field, actual in (("assignment_digest_hex", self.assignment.digest_hex),
            ("governor_profile_digest_hex", self.profile.digest_hex),
            ("bound_message_digest_hex", self.bound.message_digest_hex),
            ("legacy_message_digest_hex", self.intent.message_digest_hex)):
            self.assertEqual(self.vector[field], actual)
        self.assertEqual(self.intent.message_digest_hex, support.fixture()["message_digest_hex"])

    def test_broader_caps_change_bound_message_with_identical_legacy_intent(self):
        broader = local_profile(self.intent, max_attempt_limit=3, max_target_limit=3)
        assignment = contract.governor_assignment(broader, issuer_auth_key_hex=self.issuer)
        bound = contract.bound_enrollment_intent(assignment, self.intent)
        self.assertIs(governor.match_governor_profile(broader, self.intent), self.intent)
        self.assertEqual(broader.as_dict()["authority_profile_digest_hex"], self.profile.as_dict()["authority_profile_digest_hex"])
        self.assertEqual(bound._intent.message_digest_hex, self.intent.message_digest_hex)
        self.assertNotEqual(assignment.digest_hex, self.assignment.digest_hex)
        self.assertNotEqual(bound.message_digest_hex, self.bound.message_digest_hex)
        self.refuse_assignment(assignment.canonical_bytes)
        self.refuse_bound(bound.canonical_bytes)

    def test_independent_issuer_selection_is_bound_without_establishing_trust(self):
        peer = contract.governor_assignment(self.profile, issuer_auth_key_hex="99" * 32)
        bound = contract.bound_enrollment_intent(peer, self.intent)
        self.assertEqual(peer._profile.digest_hex, self.profile.digest_hex)
        self.assertNotEqual(peer.digest_hex, self.assignment.digest_hex)
        self.assertNotEqual(bound.message_digest_hex, self.bound.message_digest_hex)
        self.refuse_assignment(peer.canonical_bytes)
        self.refuse_bound(bound.canonical_bytes)
        self.assertIs(contract.parse_governor_assignment(peer, peer.canonical_bytes), peer)
        self.assertFalse(hasattr(peer, "issuer_trusted"))

    def test_peer_selected_owner_and_matching_profile_cannot_replace_expectations(self):
        intent = support.local_intent(self.state, owner=self.issuer)
        profile = local_profile(intent)
        peer = contract.governor_assignment(profile, issuer_auth_key_hex=self.issuer)
        self.refuse_assignment(peer.canonical_bytes)
        self.refuse_bound(contract.bound_enrollment_intent(peer, intent).canonical_bytes)

    def test_assignment_requires_every_top_level_field_and_refuses_extras(self):
        for field in self.assignment.as_dict():
            value = self.assignment.as_dict(); del value[field]
            with self.subTest(field=field): self.refuse_assignment(canonical(value))
        for field in ("signature_hex", "signature_valid", "current", "authorized", "quota", "permit"):
            self.refuse_assignment(canonical(dict(self.assignment.as_dict(), **{field:True})))

    def test_every_embedded_profile_field_is_bound_to_independent_selection(self):
        for field, old in self.profile.as_dict().items():
            value = self.assignment.as_dict()
            value["governor_profile"][field] = old + 1 if type(old) is int else ("99" * 32 if field.endswith("_hex") else "unsupported")
            with self.subTest(field=field): self.refuse_assignment(canonical(value))
        value = self.assignment.as_dict(); value["governor_profile"]["extra"] = "synthetic"
        self.refuse_assignment(canonical(value))

    def test_bound_intent_requires_all_nine_fields_and_refuses_authority_claims(self):
        for field in self.bound.as_dict():
            value = self.bound.as_dict(); del value[field]
            with self.subTest(field=field): self.refuse_bound(canonical(value))
        for field in ("signature_hex", "signature_valid", "issuer_trusted", "current", "enrolled", "permit"):
            self.refuse_bound(canonical(dict(self.bound.as_dict(), **{field:True})))

    def test_every_bound_intent_field_and_fixed_purpose_is_required(self):
        for field in self.bound.as_dict():
            value = self.bound.as_dict(); value[field] = "99" * 32 if field.endswith("_hex") else "unsupported"
            with self.subTest(field=field): self.refuse_bound(canonical(value))
        for field in ("schema", "purpose", "algorithm", "issuer_auth_key_hex"):
            value = self.assignment.as_dict(); value[field] = "99" * 32 if field.endswith("_hex") else "unsupported"
            self.refuse_assignment(canonical(value))

    def test_duplicate_alias_whitespace_nonascii_and_trailing_bytes_refuse(self):
        for obj, refuse in ((self.assignment, self.refuse_assignment), (self.bound, self.refuse_bound)):
            wire = obj.canonical_bytes
            for changed in (wire + b"\n", b" " + wire, wire.replace(b'"schema"', b'"schema":"duplicate","schema"'),
                wire.replace(b'"schema"', b'"\\u0073chema"'), wire.replace(b"ptlc", b"\\u0070tlc", 1),
                wire.replace(b"ptlc", b"\xfftlc", 1), b"{}{}"):
                with self.subTest(wire=changed[:24]): refuse(changed)

    def test_wire_bounds_depth_and_hostile_byte_subclasses_run_no_hooks(self):
        class HostileBytes(bytes):
            def __len__(self): raise AssertionError("untrusted hook ran")
            def decode(self, *args): raise AssertionError("untrusted hook ran")
        for refuse, maximum in ((self.refuse_assignment, contract.MAX_ASSIGNMENT_BYTES),
                               (self.refuse_bound, contract.MAX_BOUND_INTENT_BYTES)):
            for wire in (None, "{}", bytearray(b"{}"), HostileBytes(b"{}"), b"", b" " * (maximum + 1),
                         b"[" * 1500 + b"]" * 1500, b"null", b"[]", b"NaN", b"Infinity"):
                refuse(wire)

    def test_embedded_numeric_aliases_and_invalid_epoch_caps_refuse(self):
        for field in ("authority_epoch", "max_attempt_limit", "max_target_limit"):
            for number in (True, False, 1.0, 0, -1, "1", 2 ** 53):
                value = self.assignment.as_dict(); value["governor_profile"][field] = number
                self.refuse_assignment(canonical(value))
        for field in self.bound.as_dict():
            value = self.bound.as_dict(); value[field] = 1
            self.refuse_bound(canonical(value))

    def test_issuer_encodings_are_exact_without_calling_foreign_string_hooks(self):
        class HostileText(str):
            def __eq__(self, other): raise AssertionError("untrusted hook ran")
            def __str__(self): raise AssertionError("untrusted hook ran")
        for value in (None, 1, b"11" * 32, "", "11" * 31, "11" * 33, "AA" * 32, "zz" * 32, HostileText("11" * 32)):
            with self.assertRaises(contract.GovernorContractError):
                contract.governor_assignment(self.profile, issuer_auth_key_hex=value)

    def test_assignment_factory_and_parser_require_exact_complete_types(self):
        class Hostile:
            def __getattribute__(self, field): raise AssertionError("untrusted hook ran")
        class ProfileSubclass(governor.GovernorProfile): pass
        class AssignmentSubclass(contract.GovernorAssignment): pass
        for value in (None, {}, Hostile(), object.__new__(ProfileSubclass), object.__new__(governor.GovernorProfile)):
            with self.assertRaises(contract.GovernorContractError): contract.governor_assignment(value, issuer_auth_key_hex=self.issuer)
        for value in (None, {}, Hostile(), object.__new__(AssignmentSubclass), object.__new__(contract.GovernorAssignment)):
            with self.assertRaises(contract.GovernorContractError): contract.parse_governor_assignment(value, self.assignment.canonical_bytes)

    def test_bound_factory_parser_constructors_and_frozen_objects(self):
        class Hostile:
            def __getattribute__(self, field): raise AssertionError("untrusted hook ran")
        class IntentSubclass(enrollment.EnrollmentIntent): pass
        class BoundSubclass(contract.BoundEnrollmentIntent): pass
        for cls in (contract.GovernorAssignment, contract.BoundEnrollmentIntent):
            with self.assertRaises(TypeError): cls()
        for obj in (self.assignment, self.bound):
            with self.assertRaises(FrozenInstanceError): obj._wire = b"{}"
        for value in (None, {}, Hostile(), object.__new__(IntentSubclass), object.__new__(enrollment.EnrollmentIntent)):
            with self.assertRaises(contract.GovernorContractError): contract.bound_enrollment_intent(self.assignment, value)
        for value in (None, {}, Hostile(), object.__new__(BoundSubclass), object.__new__(contract.BoundEnrollmentIntent)):
            with self.assertRaises(contract.GovernorContractError): contract.parse_bound_enrollment_intent(value, self.bound.canonical_bytes)

    def test_defensive_nested_dictionaries_do_not_replace_selected_objects(self):
        value = self.assignment.as_dict(); value["governor_profile"]["max_attempt_limit"] = 3
        value["issuer_auth_key_hex"] = "99" * 32
        bound = self.bound.as_dict(); bound["governor_assignment_digest_hex"] = "99" * 32
        self.assertEqual(self.assignment.canonical_bytes, canonical(self.vector["assignment"]))
        self.assertEqual(self.bound.canonical_bytes, canonical(self.vector["bound_intent"]))

    def test_damaged_assignment_references_revalidate_with_sanitized_errors(self):
        for field, value in (("_wire", b'{"synthetic-detail":true}'), ("_profile", local_profile(self.intent, max_attempt_limit=3))):
            damaged = object.__new__(contract.GovernorAssignment)
            object.__setattr__(damaged, "_wire", self.assignment.canonical_bytes)
            object.__setattr__(damaged, "_profile", self.profile)
            object.__setattr__(damaged, field, value)
            with self.assertRaises(contract.GovernorContractError) as error: damaged.as_dict()
            self.assertNotIn("synthetic-detail", str(error.exception))
            self.assertTrue(error.exception.__suppress_context__)

    def test_damaged_bound_references_and_foreign_objects_refuse_without_hooks(self):
        class Hostile:
            def __getattribute__(self, field): raise AssertionError("untrusted hook ran")
        for field, value in (("_wire", b'{"synthetic-detail":true}'), ("_assignment", Hostile()), ("_intent", Hostile())):
            damaged = object.__new__(contract.BoundEnrollmentIntent)
            for name in ("_wire", "_assignment", "_intent"): object.__setattr__(damaged, name, getattr(self.bound, name))
            object.__setattr__(damaged, field, value)
            with self.assertRaises(contract.GovernorContractError) as error: damaged.as_dict()
            self.assertNotIn("synthetic-detail", str(error.exception))
            self.assertTrue(error.exception.__suppress_context__)

    def test_owner_and_retained_resource_mismatches_refuse_before_binding(self):
        for intent in (support.local_intent(self.state, owner=self.issuer), support.local_intent(changed_source("terms"))):
            with self.assertRaises(contract.GovernorContractError): contract.bound_enrollment_intent(self.assignment, intent)

    def test_every_namespace_epoch_and_profile_pin_must_match(self):
        for field in governor._SCOPE_PINS:
            changed = 2 if field == "authority_epoch" else "99" * 32
            intent = support.local_intent(self.state, selected=dict(support.selection(), **{field:changed}))
            with self.subTest(field=field), self.assertRaises(contract.GovernorContractError):
                contract.bound_enrollment_intent(self.assignment, intent)

    def test_requested_attempt_and_target_caps_are_independent_limits(self):
        for field in ("attempt_limit", "target_limit"):
            intent = support.local_intent(self.state, selected=dict(support.selection(), **{field:3}))
            with self.assertRaises(contract.GovernorContractError): contract.bound_enrollment_intent(self.assignment, intent)

    def test_request_and_enrollment_ids_bind_requests_without_registry_uniqueness(self):
        for intent in (support.local_intent(self.state, request_id="99" * 32),
                       support.local_intent(self.state, selected=dict(support.selection(), enrollment_id_hex="99" * 32))):
            bound = contract.bound_enrollment_intent(self.assignment, intent)
            self.assertEqual(bound.as_dict()["governor_assignment_digest_hex"], self.assignment.digest_hex)
            self.assertNotEqual(bound.message_digest_hex, self.bound.message_digest_hex)
        for _ in range(2): self.assertIs(contract.parse_bound_enrollment_intent(self.bound, self.bound.canonical_bytes), self.bound)

    def test_retained_old_source_still_parses_without_freshness_or_reread(self):
        changed = changed_source("terms")
        intent = support.local_intent(changed)
        self.assertNotEqual(intent._resource.digest_hex, self.intent._resource.digest_hex)
        self.assertIs(contract.parse_governor_assignment(self.assignment, self.assignment.canonical_bytes), self.assignment)
        self.assertIs(contract.parse_bound_enrollment_intent(self.bound, self.bound.canonical_bytes), self.bound)

    def test_new_epoch_selection_refuses_old_bytes_but_old_selection_still_matches(self):
        intent = support.local_intent(self.state, selected=dict(support.selection(), authority_epoch=2))
        assignment = contract.governor_assignment(local_profile(intent), issuer_auth_key_hex=self.issuer)
        bound = contract.bound_enrollment_intent(assignment, intent)
        with self.assertRaises(contract.GovernorContractError): contract.parse_governor_assignment(assignment, self.assignment.canonical_bytes)
        with self.assertRaises(contract.GovernorContractError): contract.parse_bound_enrollment_intent(bound, self.bound.canonical_bytes)
        self.assertIs(contract.parse_governor_assignment(self.assignment, self.assignment.canonical_bytes), self.assignment)
        self.assertIs(contract.parse_bound_enrollment_intent(self.bound, self.bound.canonical_bytes), self.bound)

    def test_zero_owner_and_issuer_encodings_do_not_establish_curve_or_role_facts(self):
        intent = support.local_intent(self.state, owner="00" * 32)
        assignment = contract.governor_assignment(local_profile(intent), issuer_auth_key_hex="00" * 32)
        bound = contract.bound_enrollment_intent(assignment, intent)
        self.assertIs(contract.parse_governor_assignment(assignment, assignment.canonical_bytes), assignment)
        self.assertIs(contract.parse_bound_enrollment_intent(bound, bound.canonical_bytes), bound)
        self.assertFalse(hasattr(assignment, "signature_valid"))
        self.assertFalse(hasattr(bound, "owner_verified"))

    def test_structurally_retained_invalid_source_math_remains_unverified(self):
        state = changed_source("zenon_bundle")
        self.assertEqual(state["zenon_bundle"]["adaptor_presignature_hex"], "00" * 65)
        intent = support.local_intent(state)
        assignment = contract.governor_assignment(local_profile(intent), issuer_auth_key_hex=self.issuer)
        bound = contract.bound_enrollment_intent(assignment, intent)
        self.assertIs(contract.parse_bound_enrollment_intent(bound, bound.canonical_bytes), bound)
        self.assertFalse(hasattr(bound, "source_verified"))

    def test_no_io_signer_verifier_clock_or_backend_interface_exists(self):
        for name in ("signer", "verifier", "path", "store", "worker", "clock", "current", "authorized"):
            with self.assertRaises(TypeError): contract.governor_assignment(self.profile, issuer_auth_key_hex=self.issuer, **{name:None})
            with self.assertRaises(TypeError): contract.bound_enrollment_intent(self.assignment, self.intent, **{name:None})
        tree = ast.parse((Path(__file__).resolve().parents[1] / "offline_session/governor_contract.py").read_text("ascii"))
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual({node.module for node in imports}, {"dataclasses", None})
        self.assertFalse(any(isinstance(node, ast.Import) for node in imports))

    def test_legacy_signatures_and_parsers_do_not_reinterpret_v2_bytes(self):
        self.refuse_bound(self.intent.canonical_bytes)
        with self.assertRaises(enrollment.EnrollmentContractError): enrollment.parse_enrollment_intent(self.intent, self.bound.canonical_bytes)
        with self.assertRaises(auth.EnrollmentSignatureError): auth.envelope(self.bound, bytes(64))
        value = copy.deepcopy(support.fixture()["envelope"]); value["intent"] = self.bound.as_dict()
        calls = []
        with self.assertRaises(auth.EnrollmentSignatureError): auth.verify_signature(self.intent, canonical(value), verifier=lambda v:calls.append(v))
        self.assertEqual(calls, [])
        for obj in (self.assignment, self.bound):
            for name in ("authorized", "issuer_trusted", "owner_verified", "current", "enrolled", "quota_granted", "permit", "can_start", "sign", "verify"):
                self.assertFalse(hasattr(obj, name))

    def test_repeated_unsigned_binding_after_exhausted_reopen_changes_no_allowance(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-governor-contract-") as directory:
            root, head = Path(directory) / "state", Path(directory) / "head.json"
            with Journal.open(root, head) as journal:
                session = prepare(journal, recovery_limit=1); journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict): journal.complete_exchange_bitcoin(session, invalid, recoverer=lambda _:None)
            with Journal.open(root, head) as journal:
                state = journal.get_exchange(session); intent = support.local_intent(state)
                before = (copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes())
                assignment = contract.governor_assignment(local_profile(intent), issuer_auth_key_hex=self.issuer)
                bound = contract.bound_enrollment_intent(assignment, intent)
                for _ in range(2):
                    self.assertIs(contract.parse_governor_assignment(assignment, assignment.canonical_bytes), assignment)
                    self.assertIs(contract.parse_bound_enrollment_intent(bound, bound.canonical_bytes), bound)
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, completion.bob_candidate_from_signature(state, final_signatures()[0]),
                        expected_observation_digest=completion.observation_digest(invalid), recoverer=lambda v:calls.append(v))
                after = (copy.deepcopy(journal._state), journal._sequence, (root / "journal.sqlite3").read_bytes(), head.read_bytes())
                self.assertEqual(after, before)
                self.assertEqual(calls, [])
                self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)


if __name__ == "__main__":
    unittest.main()
