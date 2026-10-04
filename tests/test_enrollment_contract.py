"""Selected content equality and unsigned intent are not enrollment authority."""

import copy
from dataclasses import FrozenInstanceError
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from offline_session import authority_contract as authority, completion, exchange
from offline_session import enrollment_contract as contract
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import completion_accepted, final_signatures, released_bob
from exchange_test_support import artifacts, prepare
import test_authority_contract as authority_test_support


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


@lru_cache(maxsize=5)
def changed_source(kind):
    """Reuse MIT fixture sequencing; no cryptographic or source-truth oracle."""
    return authority_test_support.AuthorityContractTests().rebound(kind)


class EnrollmentContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.signature = final_signatures()[0]
        cls.selection = dict(authority_id_hex="11" * 32, enrollment_id_hex="22" * 32,
            authority_epoch=1, authority_profile_digest_hex="33" * 32,
            verifier_profile_digest_hex="44" * 32, pool_profile_digest_hex="55" * 32,
            resource_profile_digest_hex="66" * 32, attempt_limit=2, target_limit=2)
        cls.scope = authority.authority_scope(cls.state, **cls.selection)
        cls.resource = contract.retained_resource(cls.scope)
        cls.intent = contract.enrollment_intent(cls.state, cls.scope, cls.resource,
            owner_auth_key_hex="77" * 32, request_id_hex="88" * 32)

    def proposal(self, *, state=None, scope=None, resource=None, owner="77" * 32, request="88" * 32):
        return contract.enrollment_intent(self.state if state is None else state,
            self.scope if scope is None else scope, self.resource if resource is None else resource,
            owner_auth_key_hex=owner, request_id_hex=request)

    def test_resource_contains_exact_seven_source_bindings_and_selected_unit(self):
        expected = dict(schema=contract.RESOURCE_SCHEMA, predicate="zenon-completion-v1",
            resource_kind="exact-paired-release-v1")
        fields = ("session_id", "terms_digest_hex", "bitcoin_context_digest_hex",
            "zenon_context_digest_hex", "bitcoin_bundle_digest_hex", "zenon_bundle_digest_hex",
            "release_digest_hex")
        expected.update({key:self.scope.as_dict()[key] for key in fields})
        self.assertEqual(self.resource.as_dict(), expected)
        self.assertEqual(self.resource.canonical_bytes, canonical(expected))
        self.assertEqual(self.resource.digest_hex, hashlib.sha256(
            b"PTLC/observation-retained-resource/v1\0" + canonical(expected)).hexdigest())
        self.assertLessEqual(len(self.resource.canonical_bytes), contract.MAX_RESOURCE_BYTES)

    def test_all_nine_external_scope_selections_leave_resource_key_unchanged(self):
        for field, old in self.selection.items():
            new = old + 1 if type(old) is int else "99" * 32
            scope = authority.authority_scope(self.state, **dict(self.selection, **{field:new}))
            with self.subTest(field=field):
                self.assertNotEqual(scope.digest_hex, self.scope.digest_hex)
                self.assertEqual(contract.retained_resource(scope), self.resource)
                changed = self.proposal(scope=scope)
                self.assertNotEqual(changed.message_digest_hex, self.intent.message_digest_hex)

    def test_candidate_changes_and_copied_retained_state_do_not_change_resource(self):
        for signature in (self.signature, bytes(64), b"\xff" * 64):
            packet = completion.bob_candidate_from_signature(self.state, signature)
            state = completion.observe_bob(self.state, packet)
            before = copy.deepcopy(state)
            scope = authority.authority_scope(state, **self.selection)
            self.assertEqual(contract.retained_resource(scope), self.resource)
            self.assertEqual(self.proposal(state=state, scope=scope), self.intent)
            self.assertEqual(state, before)
        self.assertEqual(self.proposal(state=copy.deepcopy(self.state)), self.intent)

    def test_changed_retained_sources_refuse_old_resource_and_old_live_scope(self):
        for change in ("session", "terms", "nonce", "bitcoin_bundle", "zenon_bundle"):
            state = changed_source(change)
            scope = authority.authority_scope(state, **self.selection)
            with self.subTest(change=change):
                self.assertNotEqual(contract.retained_resource(scope), self.resource)
                with self.assertRaises(contract.EnrollmentContractError):
                    self.proposal(state=state, scope=scope)
                with self.assertRaises(contract.EnrollmentContractError):
                    self.proposal(state=state)

    def test_new_source_selection_is_representable_but_does_not_prove_equivalence_or_quota(self):
        state = changed_source("terms")
        scope = authority.authority_scope(state, **self.selection)
        resource = contract.retained_resource(scope)
        intent = self.proposal(state=state, scope=scope, resource=resource)
        self.assertNotEqual(resource.digest_hex, self.resource.digest_hex)
        self.assertNotEqual(intent.message_digest_hex, self.intent.message_digest_hex)
        for field in ("canonical", "economic_resource", "enrolled", "quota_granted"):
            self.assertFalse(hasattr(resource, field))
            self.assertFalse(hasattr(intent, field))

    def test_structural_fixture_acceptance_does_not_make_source_math_or_owner_true(self):
        state = changed_source("zenon_bundle")
        scope = authority.authority_scope(state, **self.selection)
        self.assertEqual(state["zenon_bundle"]["adaptor_presignature_hex"], "00" * 65)
        resource = contract.retained_resource(scope)
        intent = self.proposal(state=state, scope=scope, resource=resource)
        self.assertIs(contract.parse_enrollment_intent(intent, intent.canonical_bytes), intent)
        self.assertFalse(hasattr(intent, "valid"))
        self.assertFalse(hasattr(intent, "owner_verified"))

    def test_intent_binds_resource_full_scope_owner_request_role_purpose_and_domain(self):
        expected = dict(schema=contract.INTENT_SCHEMA, purpose="observation-enrollment",
            role="enrollment-governor", algorithm="BIP340-SHA256",
            resource_digest_hex=self.resource.digest_hex, scope_digest_hex=self.scope.digest_hex,
            owner_auth_key_hex="77" * 32, request_id_hex="88" * 32)
        self.assertEqual(self.intent.as_dict(), expected)
        self.assertEqual(self.intent.canonical_bytes, canonical(expected))
        self.assertEqual(self.intent.message_digest_hex, hashlib.sha256(
            b"PTLC/observation-enrollment-owner-intent/v1\0" + canonical(expected)).hexdigest())
        self.assertNotEqual(self.intent.message_digest_hex, self.scope.digest_hex)
        self.assertNotEqual(self.intent.message_digest_hex, self.resource.digest_hex)
        self.assertLessEqual(len(self.intent.canonical_bytes), contract.MAX_INTENT_BYTES)

    def test_independent_owner_pin_changes_intent_without_changing_resource(self):
        changed = self.proposal(owner="99" * 32)
        self.assertNotEqual(changed.message_digest_hex, self.intent.message_digest_hex)
        self.assertEqual(changed.as_dict()["resource_digest_hex"], self.resource.digest_hex)
        with self.assertRaises(contract.EnrollmentContractError):
            contract.parse_enrollment_intent(self.intent, changed.canonical_bytes)

    def test_request_id_changes_binding_and_reuse_has_no_idempotency_owner(self):
        other_id = self.proposal(request="99" * 32)
        same_id_other_owner = self.proposal(owner="99" * 32)
        for changed in (other_id, same_id_other_owner):
            self.assertNotEqual(changed.message_digest_hex, self.intent.message_digest_hex)
            self.assertEqual(changed.as_dict()["resource_digest_hex"], self.resource.digest_hex)
        self.assertEqual(same_id_other_owner.as_dict()["request_id_hex"], self.intent.as_dict()["request_id_hex"])
        self.assertFalse(hasattr(self.intent, "idempotent"))

    def test_peer_owner_pin_and_matching_source_cannot_replace_independent_expectation(self):
        value = self.intent.as_dict()
        for field in ("owner_auth_key_hex", "request_id_hex", "resource_digest_hex", "scope_digest_hex"):
            with self.subTest(field=field), self.assertRaises(contract.EnrollmentContractError):
                contract.parse_enrollment_intent(self.intent, canonical(dict(value, **{field:"aa" * 32})))

    def test_all_scope_selection_changes_reject_old_intent_while_sharing_resource_key(self):
        for field, old in self.selection.items():
            new = old + 1 if type(old) is int else "99" * 32
            scope = authority.authority_scope(self.state, **dict(self.selection, **{field:new}))
            intent = self.proposal(scope=scope)
            with self.subTest(field=field), self.assertRaises(contract.EnrollmentContractError):
                contract.parse_enrollment_intent(intent, self.intent.canonical_bytes)

    def test_zero_key_encoding_is_not_a_curve_or_key_control_check(self):
        intent = self.proposal(owner="00" * 32)
        self.assertEqual(intent.as_dict()["owner_auth_key_hex"], "00" * 32)
        self.assertIs(contract.parse_enrollment_intent(intent, intent.canonical_bytes), intent)
        for field in ("owner_verified", "curve_valid", "authenticated", "authorized"):
            self.assertFalse(hasattr(intent, field))

    def test_public_pin_and_request_id_exact_encodings_reject_aliases(self):
        for field in ("owner", "request"):
            for value in (None, True, 0, 1.0, bytes(32), "", "aa" * 31, "aa" * 33,
                          "AA" * 32, "gg" * 32, "aa" * 32 + "\n"):
                with self.subTest(field=field, kind=type(value).__name__), self.assertRaises(contract.EnrollmentContractError):
                    self.proposal(**{field:value})

    def test_resource_and_intent_are_frozen_and_return_defensive_public_values(self):
        for value in (self.resource, self.intent):
            with self.assertRaises(FrozenInstanceError):
                value._wire = b"{}"
            fields = value.as_dict()
            fields["schema"] = "synthetic-replacement"
            self.assertNotEqual(value.as_dict()["schema"], fields["schema"])
        before = copy.deepcopy(self.state)
        self.proposal()
        self.assertEqual(self.state, before)

    def test_constructors_incomplete_objects_and_exact_class_requirements(self):
        for cls in (contract.RetainedResource, contract.EnrollmentIntent):
            with self.assertRaises(TypeError):
                cls()
            value = object.__new__(cls)
            with self.assertRaises(contract.EnrollmentContractError):
                value.as_dict()
            class Subclass(cls):
                pass
            subclass = object.__new__(Subclass)
            with self.assertRaises(contract.EnrollmentContractError):
                subclass.as_dict()
        for scope in (None, True, {}, self.scope.as_dict(), self.resource):
            with self.assertRaises(contract.EnrollmentContractError):
                contract.retained_resource(scope)
        for parser, expected in ((contract.parse_retained_resource, self.resource),
                                 (contract.parse_enrollment_intent, self.intent)):
            for invalid in (None, True, {}, expected.as_dict(), expected.canonical_bytes):
                with self.assertRaises(contract.EnrollmentContractError):
                    parser(invalid, expected.canonical_bytes)

    def test_expected_resource_must_match_every_selected_source_binding(self):
        for field in contract.SOURCE_FIELDS:
            value = self.resource.as_dict()
            value[field] = "aa" * 32
            resource = object.__new__(contract.RetainedResource)
            object.__setattr__(resource, "_wire", canonical(value))
            with self.subTest(field=field), self.assertRaises(contract.EnrollmentContractError):
                self.proposal(resource=resource)

    def test_wire_fields_cannot_omit_bindings_add_authority_or_change_fixed_domains(self):
        for parser, expected in ((contract.parse_retained_resource, self.resource),
                                 (contract.parse_enrollment_intent, self.intent)):
            value = expected.as_dict()
            for field in value:
                missing = dict(value)
                del missing[field]
                changed = dict(value, **{field:True})
                for raw in (canonical(missing), canonical(changed)):
                    with self.subTest(parser=parser.__name__, field=field), self.assertRaises(contract.EnrollmentContractError):
                        parser(expected, raw)
            for field in ("authorized", "signature_hex", "permit", "source", "quota", "owner_verified"):
                with self.assertRaises(contract.EnrollmentContractError):
                    parser(expected, canonical(dict(value, **{field:True})))

    def test_noncanonical_duplicate_non_ascii_deep_and_cross_schema_bytes_reject(self):
        for parser, expected, other in ((contract.parse_retained_resource, self.resource, self.intent),
                                       (contract.parse_enrollment_intent, self.intent, self.resource)):
            wire = expected.canonical_bytes
            variants = (wire + b"\n", b" " + wire, wire + b"\r\n",
                json.dumps(expected.as_dict(), indent=2).encode("ascii"),
                wire[:-1] + b',"schema":"duplicate"}', wire.replace(b'"ptlc-', b'"ptl\\u0063-'),
                b"\xff", b"{}", b"[]", b"null", b"NaN", b"Infinity",
                b"[" * 1500 + b"0" + b"]" * 1500, other.canonical_bytes)
            for raw in variants:
                with self.subTest(parser=parser.__name__, size=len(raw)), self.assertRaises(contract.EnrollmentContractError):
                    parser(expected, raw)

    def test_wire_bounds_types_and_hostile_bytes_execute_no_methods(self):
        calls = []
        class HostileBytes(bytes):
            def __len__(self):
                calls.append("length")
                raise RuntimeError("synthetic-private-detail")
            def decode(self, *args):
                calls.append("decode")
                raise RuntimeError("synthetic-private-detail")
        for parser, expected, maximum in ((contract.parse_retained_resource, self.resource, contract.MAX_RESOURCE_BYTES),
                                          (contract.parse_enrollment_intent, self.intent, contract.MAX_INTENT_BYTES)):
            for raw in (None, True, "{}", bytearray(b"{}"), memoryview(b"{}"), b"", b"x" * (maximum + 1), HostileBytes(b"{}")):
                with self.assertRaises(contract.EnrollmentContractError) as error:
                    parser(expected, raw)
                self.assertNotIn("synthetic-private-detail", str(error.exception))
        self.assertEqual(calls, [])

    def test_hostile_local_strings_states_and_scopes_execute_no_hooks(self):
        calls = []
        class HostileText(str):
            def __eq__(self, other):
                calls.append("equality")
                raise RuntimeError("synthetic-private-detail")
        class HostileState(dict):
            def __deepcopy__(self, memo):
                calls.append("copy")
                raise RuntimeError("synthetic-private-detail")
        class HostileScope(authority.AuthorityScope):
            def as_dict(self):
                calls.append("scope")
                raise RuntimeError("synthetic-private-detail")
        for changes in (dict(owner=HostileText("77" * 32)), dict(request=HostileText("88" * 32)),
                        dict(state=HostileState(self.state)), dict(scope=object.__new__(HostileScope))):
            with self.assertRaises(contract.EnrollmentContractError) as error:
                self.proposal(**changes)
            self.assertNotIn("synthetic-private-detail", str(error.exception))
        self.assertEqual(calls, [])

    def test_tampered_expected_objects_numeric_scope_aliases_and_malformed_values_reject(self):
        resource = object.__new__(contract.RetainedResource)
        object.__setattr__(resource, "_wire", b"{}")
        with self.assertRaises(contract.EnrollmentContractError):
            self.proposal(resource=resource)
        for field in ("authority_epoch", "attempt_limit", "target_limit"):
            scope = object.__new__(authority.AuthorityScope)
            object.__setattr__(scope, "_wire", canonical(dict(self.scope.as_dict(), **{field:True})))
            with self.assertRaises(contract.EnrollmentContractError):
                contract.retained_resource(scope)
        intent = object.__new__(contract.EnrollmentIntent)
        object.__setattr__(intent, "_scope", self.scope)
        object.__setattr__(intent, "_resource", self.resource)
        object.__setattr__(intent, "_wire", canonical(dict(self.intent.as_dict(), owner_auth_key_hex=True)))
        with self.assertRaises(contract.EnrollmentContractError):
            contract.parse_enrollment_intent(intent, intent._wire)

    def test_live_source_requires_release_and_refuses_broken_or_finished_snapshots(self):
        packet = completion.bob_candidate_from_signature(self.state, self.signature)
        finished, _ = completion.complete_bob(self.state, packet, completion_accepted)
        broken = copy.deepcopy(self.state)
        broken["zenon_context"]["nonce_round_digest_hex"] = "99" * 32
        for state in (None, True, [], {}, exchange.start(artifacts()[1]), finished, broken):
            before = copy.deepcopy(state)
            with self.assertRaises(contract.EnrollmentContractError):
                contract.enrollment_intent(state, self.scope, self.resource,
                    owner_auth_key_hex="77" * 32, request_id_hex="88" * 32)
            self.assertEqual(state, before)

    def test_unsigned_matching_bytes_replay_without_signature_or_owner_permission(self):
        for parser, expected in ((contract.parse_retained_resource, self.resource),
                                 (contract.parse_enrollment_intent, self.intent)):
            self.assertIs(parser(expected, expected.canonical_bytes), expected)
            self.assertIs(parser(expected, expected.canonical_bytes), expected)
            self.assertFalse(callable(expected))
            for field in ("authorized", "authenticated", "owner_verified", "enrolled", "quota_granted",
                          "permit", "can_start", "signature_hex", "sign", "verify", "worker"):
                self.assertFalse(hasattr(expected, field))

    def test_retained_expected_intent_does_not_supply_current_source_or_freshness(self):
        changed = changed_source("terms")
        self.assertNotEqual(authority.authority_scope(changed, **self.selection), self.scope)
        self.assertIs(contract.parse_enrollment_intent(self.intent, self.intent.canonical_bytes), self.intent)
        self.assertFalse(hasattr(self.intent, "fresh"))

    def test_unknown_io_signer_callback_candidate_and_path_inputs_are_not_accepted(self):
        for field in ("signer", "verifier", "signature", "path", "store_id", "worker", "enroll", "authorized"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                contract.enrollment_intent(self.state, self.scope, self.resource,
                    owner_auth_key_hex="77" * 32, request_id_hex="88" * 32, **{field:None})
            with self.assertRaises(TypeError):
                contract.retained_resource(self.scope, **{field:None})
        maximal = authority.authority_scope(self.state, **dict(self.selection,
            authority_epoch=authority.MAX_NUMBER, attempt_limit=authority.MAX_LIMIT, target_limit=authority.MAX_LIMIT))
        self.assertEqual(contract.retained_resource(maximal), self.resource)
        self.assertNotEqual(self.proposal(scope=maximal).message_digest_hex, self.intent.message_digest_hex)

    def test_unsigned_intent_after_exhausted_journal_reopen_changes_no_history_or_allowance(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-enrollment-contract-") as directory:
            root, anchor = Path(directory) / "state", Path(directory) / "head.json"
            with Journal.open(root, anchor) as journal:
                session = prepare(journal, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, invalid, recoverer=lambda _: None)
            with Journal.open(root, anchor) as journal:
                state = journal.get_exchange(session)
                before = (copy.deepcopy(journal._state), journal._sequence,
                    (root / "journal.sqlite3").read_bytes(), anchor.read_bytes())
                scope = authority.authority_scope(state, **self.selection)
                resource = contract.retained_resource(scope)
                intent = self.proposal(state=state, scope=scope, resource=resource)
                contract.parse_retained_resource(resource, resource.canonical_bytes)
                contract.parse_enrollment_intent(intent, intent.canonical_bytes)
                contract.parse_enrollment_intent(intent, intent.canonical_bytes)
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session,
                        completion.bob_candidate_from_signature(state, self.signature),
                        expected_observation_digest=completion.observation_digest(invalid),
                        recoverer=lambda value: calls.append(value))
                after = (copy.deepcopy(journal._state), journal._sequence,
                    (root / "journal.sqlite3").read_bytes(), anchor.read_bytes())
                self.assertEqual(after, before)
                self.assertEqual(calls, [])
                self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)
                self.assertEqual(journal.get_exchange(session)["zenon_completion_packet_hex"], invalid.hex())


if __name__ == "__main__":
    unittest.main()
