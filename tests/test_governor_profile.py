"""Explicit local rules are not governor provenance or enrollment authority."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest

from offline_session import authority_contract as authority
from offline_session import enrollment_contract as contract, enrollment_authentication as auth
from offline_session import governor_profile as governor
from completion_test_support import released_bob
from test_enrollment_contract import changed_source
import test_enrollment_signature as support

_DEFAULT = object()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def local_profile(intent, **overrides):
    """Synthetic locally prepared context only; never peer bootstrap code."""
    scope = intent._scope.as_dict()
    fields = {name: scope[name] for name in governor._SCOPE_PINS}
    fields.update(owner_auth_key_hex=intent.as_dict()["owner_auth_key_hex"],
        max_attempt_limit=2, max_target_limit=2)
    fields.update(overrides)
    return governor.governor_profile(intent._resource, **fields)


class GovernorProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.vector = released_bob(), support.fixture()
        cls.intent = support.local_intent(cls.state)
        cls.profile = local_profile(cls.intent)

    def refuse(self, wire, profile=_DEFAULT):
        with self.assertRaises(governor.GovernorProfileError):
            governor.parse_governor_profile(self.profile if profile is _DEFAULT else profile, wire)

    def test_exact_fourteen_field_profile_and_separate_digest(self):
        value = dict(schema=governor.SCHEMA, purpose=contract.PURPOSE, role=contract.ROLE,
            algorithm=contract.ALGORITHM, resource_digest_hex=self.intent._resource.digest_hex,
            owner_auth_key_hex=self.intent.as_dict()["owner_auth_key_hex"],
            max_attempt_limit=2, max_target_limit=2)
        value.update({key:self.intent._scope.as_dict()[key] for key in governor._SCOPE_PINS})
        self.assertEqual(len(value), 14)
        self.assertEqual(self.profile.as_dict(), value)
        self.assertEqual(self.profile.canonical_bytes, canonical(value))
        self.assertEqual(self.profile.digest_hex, hashlib.sha256(
            b"PTLC/observation-governor-profile/v1\0" + canonical(value)).hexdigest())
        self.assertNotEqual(self.profile.digest_hex, self.intent.message_digest_hex)
        self.assertNotEqual(self.profile.digest_hex, self.intent._scope.digest_hex)

    def test_profile_is_frozen_and_factory_only(self):
        with self.assertRaises(TypeError): governor.GovernorProfile()
        with self.assertRaises(FrozenInstanceError): self.profile._wire = b"{}"

    def test_profile_dictionary_copies_do_not_replace_local_rules(self):
        value = self.profile.as_dict(); value["owner_auth_key_hex"] = "99" * 32
        self.assertNotEqual(value, self.profile.as_dict())
        self.assertIs(governor.match_governor_profile(self.profile, self.intent), self.intent)

    def test_exact_profile_replay_returns_same_selected_object(self):
        for _ in range(3):
            self.assertIs(governor.parse_governor_profile(self.profile, self.profile.canonical_bytes), self.profile)
        copied = local_profile(self.intent)
        self.assertIs(governor.parse_governor_profile(copied, self.profile.canonical_bytes), copied)

    def test_peer_profile_cannot_bootstrap_or_replace_selected_owner(self):
        alternate = local_profile(self.intent, owner_auth_key_hex=self.vector["alternate_owner"]["intent"]["owner_auth_key_hex"])
        self.refuse(alternate.canonical_bytes)
        for expected in (None, {}, alternate.as_dict(), alternate.canonical_bytes):
            self.refuse(alternate.canonical_bytes, profile=expected)

    def test_each_profile_field_changes_exact_profile_selection(self):
        for key, old in self.profile.as_dict().items():
            value = self.profile.as_dict()
            value[key] = old + 1 if type(old) is int else ("99" * 32 if key.endswith("_hex") else old + "_other")
            with self.subTest(field=key): self.refuse(canonical(value))

    def test_missing_extra_and_nonstring_fields_refuse(self):
        for key in self.profile.as_dict():
            value = self.profile.as_dict(); del value[key]
            self.refuse(canonical(value))
            for wrong in (None, {}, [], True, 1.5):
                value = self.profile.as_dict(); value[key] = wrong
                self.refuse(canonical(value))
        value = self.profile.as_dict(); value["authorized"] = True
        self.refuse(canonical(value))

    def test_duplicate_alias_whitespace_and_trailing_lf_refuse(self):
        wire = self.profile.canonical_bytes
        for altered in (b" " + wire, wire + b"\n", wire.replace(b'"schema":', b'"schema":"other","schema":'),
            wire.replace(b'"role"', b'"r\\u006fle"'), json.dumps(self.profile.as_dict(), indent=2).encode("ascii")):
            self.refuse(altered)

    def test_wire_type_size_depth_nonascii_and_json_numbers_refuse(self):
        for value in (None, "{}", {}, bytearray(self.profile.canonical_bytes), b"", b"{}", b"\xff", b" " * 4097,
            b"[" * 1500 + b"0" + b"]" * 1500, b"NaN", b"Infinity"):
            self.refuse(value)

    def test_exact_epoch_and_limit_integer_bounds(self):
        for key, maximum in (("authority_epoch", authority.MAX_NUMBER),
                             ("max_attempt_limit", authority.MAX_LIMIT), ("max_target_limit", authority.MAX_LIMIT)):
            for wrong in (False, True, 0, -1, 1.0, "1", maximum + 1):
                with self.subTest(field=key, value=wrong):
                    with self.assertRaises(governor.GovernorProfileError): local_profile(self.intent, **{key:wrong})
            for valid in (1, maximum):
                self.assertEqual(local_profile(self.intent, **{key:valid}).as_dict()[key], valid)

    def test_hex_format_checks_do_not_establish_curve_membership(self):
        for key in governor._DIGESTS:
            if key == "resource_digest_hex": continue
            for wrong in (None, bytes(32), "aa" * 31, "aa" * 33, "AA" * 32, "gg" * 32):
                with self.subTest(field=key):
                    with self.assertRaises(governor.GovernorProfileError): local_profile(self.intent, **{key:wrong})
        zero = support.local_intent(self.state, owner="00" * 32)
        self.assertIs(governor.match_governor_profile(local_profile(zero), zero), zero)
        self.assertFalse(hasattr(zero, "signature_valid"))

    def test_matching_returns_same_unsigned_intent_without_permissions(self):
        before = copy.deepcopy(self.state)
        self.assertIs(governor.match_governor_profile(self.profile, self.intent), self.intent)
        self.assertEqual(before, self.state)
        for object_value in (self.profile, self.intent):
            for field in ("authorized", "owner_verified", "enrolled", "quota_granted", "permit", "can_start"):
                self.assertFalse(hasattr(object_value, field))

    def test_alternate_locally_selected_key_refuses_original_profile(self):
        alternate = support.local_intent(self.state, owner=self.vector["alternate_owner"]["intent"]["owner_auth_key_hex"])
        with self.assertRaises(governor.GovernorProfileError): governor.match_governor_profile(self.profile, alternate)

    def test_changed_resource_refuses_original_profile(self):
        changed = support.local_intent(changed_source("terms"))
        with self.assertRaises(governor.GovernorProfileError): governor.match_governor_profile(self.profile, changed)
        self.assertIs(governor.match_governor_profile(local_profile(changed), changed), changed)

    def test_all_six_scope_pins_are_required(self):
        for key in governor._SCOPE_PINS:
            old = support.selection()[key]
            changed = old + 1 if type(old) is int else "99" * 32
            intent = support.local_intent(self.state, selected=dict(support.selection(), **{key:changed}))
            with self.subTest(field=key):
                with self.assertRaises(governor.GovernorProfileError): governor.match_governor_profile(self.profile, intent)

    def test_attempt_and_target_proposal_caps_are_separate(self):
        for field in ("attempt_limit", "target_limit"):
            for limit in (1, 2, 3, authority.MAX_LIMIT):
                intent = support.local_intent(self.state, selected=dict(support.selection(), **{field:limit}))
                if limit <= 2:
                    self.assertIs(governor.match_governor_profile(self.profile, intent), intent)
                else:
                    with self.assertRaises(governor.GovernorProfileError): governor.match_governor_profile(self.profile, intent)

    def test_changed_request_and_enrollment_ids_still_match_without_uniqueness(self):
        cases = (support.local_intent(self.state, request_id="99" * 32),
            support.local_intent(self.state, selected=dict(support.selection(), enrollment_id_hex="99" * 32)))
        for intent in cases:
            self.assertNotEqual(intent.message_digest_hex, self.intent.message_digest_hex)
            self.assertIs(governor.match_governor_profile(self.profile, intent), intent)

    def test_broader_local_profile_changes_digest_without_changing_signed_intent(self):
        broader = local_profile(self.intent, max_attempt_limit=3, max_target_limit=3)
        self.assertNotEqual(broader.digest_hex, self.profile.digest_hex)
        self.assertEqual(broader.as_dict()["authority_profile_digest_hex"], self.profile.as_dict()["authority_profile_digest_hex"])
        self.assertIs(governor.match_governor_profile(broader, self.intent), self.intent)
        self.assertIs(governor.match_governor_profile(self.profile, self.intent), self.intent)
        self.refuse(broader.canonical_bytes)

    def test_old_saved_profile_matches_without_revocation_or_freshness(self):
        replacement = local_profile(self.intent, owner_auth_key_hex=self.vector["alternate_owner"]["intent"]["owner_auth_key_hex"])
        with self.assertRaises(governor.GovernorProfileError): governor.match_governor_profile(replacement, self.intent)
        self.assertIs(governor.match_governor_profile(self.profile, self.intent), self.intent)

    def test_old_intent_still_matches_after_mutable_source_copy_changes(self):
        state = copy.deepcopy(self.state); intent = support.local_intent(state)
        state["session_id"] = "99" * 32
        self.assertIs(governor.match_governor_profile(self.profile, intent), intent)

    def test_structurally_selected_invalid_source_and_arbitrary_key_can_match(self):
        state = changed_source("zenon_bundle")
        self.assertEqual(state["zenon_bundle"]["adaptor_presignature_hex"], "00" * 65)
        intent = support.local_intent(state, owner="00" * 32)
        self.assertIs(governor.match_governor_profile(local_profile(intent), intent), intent)

    def test_hostile_subclasses_incomplete_objects_and_inputs_refuse_without_hooks(self):
        class Hostile:
            def __getattribute__(self, name): raise AssertionError("untrusted hook ran")
            def __str__(self): raise AssertionError("untrusted hook ran")
        class ProfileSubclass(governor.GovernorProfile): pass
        for value in (None, {}, Hostile(), object.__new__(ProfileSubclass), object.__new__(governor.GovernorProfile)):
            with self.assertRaises(governor.GovernorProfileError): governor.match_governor_profile(value, self.intent)
        for value in (None, {}, Hostile(), self.intent.canonical_bytes, object.__new__(contract.EnrollmentIntent)):
            with self.assertRaises(governor.GovernorProfileError): governor.match_governor_profile(self.profile, value)
        fields = self.profile.as_dict()
        selected = {key:fields[key] for key in (*governor._SCOPE_PINS, "owner_auth_key_hex", "max_attempt_limit", "max_target_limit")}
        with self.assertRaises(governor.GovernorProfileError): governor.governor_profile(Hostile(), **selected)

    def test_damaged_selected_profile_is_revalidated_with_sanitized_error(self):
        damaged = object.__new__(governor.GovernorProfile)
        object.__setattr__(damaged, "_wire", b'{"synthetic-detail":true}')
        with self.assertRaises(governor.GovernorProfileError) as error: governor.match_governor_profile(damaged, self.intent)
        self.assertNotIn("synthetic-detail", str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)

    def test_role_match_does_not_repair_a_forged_selected_verifier_positive(self):
        zero_signature = auth.envelope(self.intent, bytes(64))
        unsigned = auth.verify_signature(self.intent, zero_signature, verifier=support.fake_check)
        self.assertIs(governor.match_governor_profile(self.profile, unsigned), self.intent)
        self.assertFalse(hasattr(unsigned, "owner_verified"))
