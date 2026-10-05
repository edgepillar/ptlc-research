"""Forgeable read framing and stale/restore/outage boundaries, not authority."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from offline_session import authority_contract as authority, completion, current_authority_contract as contract
from offline_session import governor_authentication as signatures
from offline_session.enrollment_contract import _canonical as canonical
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import final_signatures, released_bob
from exchange_test_support import prepare
import test_governor_signature as public


def selected_source(bound, **changes):
    selected = dict(source_id_hex="a1" * 32, source_profile_digest_hex="a2" * 32,
        source_incarnation_hex="a3" * 32,
        provisioning_root_key_hex=public.fixture()["alternate_owner"]["bound_intent"]["owner_auth_key_hex"])
    selected.update(changes)
    return contract.source_context(bound, **selected)


def read_query(bound, envelope, *, source=None, checkpoint=None, challenge="a5" * 32):
    return contract.policy_read_query(bound, envelope,
        source=selected_source(bound) if source is None else source,
        checkpoint=contract.PolicyCheckpoint(0, "a4" * 32) if checkpoint is None else checkpoint,
        challenge_hex=challenge)


def forged_claim(query, observation="active"):
    """Synthetic unauthenticated response; anybody can generate these bytes."""
    selected = query.as_dict()
    return dict(schema=contract.CLAIM_SCHEMA, query_digest_hex=query.digest_hex,
        source_context_digest_hex=query._source.digest_hex, challenge_hex=selected["challenge_hex"],
        observation=observation,
        claimed_checkpoint=None if observation == "unavailable" else selected["expected_checkpoint"],
        assignment_digest_hex=None if observation in ("absent", "unavailable") else
            selected["governor_signature_request"]["bound_intent"]["governor_assignment_digest_hex"])


class CurrentAuthorityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.bound = public.selected_bound(cls.state)
        cls.envelope = canonical(public.fixture()["primary"]["envelope"])
        cls.query = read_query(cls.bound, cls.envelope)

    def refuse_claim(self, value, *, expected=None):
        with self.assertRaises(contract.CurrentAuthorityContractError):
            contract.parse_claim(self.query if expected is None else expected, canonical(value))

    def test_public_fixture_reproduces_exact_source_checkpoint_query_and_all_claims(self):
        fixture = json.loads(Path("qualification/fixtures/current_authority_contract.json").read_text("ascii"))
        self.assertEqual(fixture["source_context"], self.query._source.as_dict())
        self.assertEqual(fixture["source_context_digest_hex"], self.query._source.digest_hex)
        self.assertEqual(fixture["query"], self.query.as_dict())
        self.assertEqual(fixture["query_digest_hex"], self.query.digest_hex)
        self.assertEqual(len(fixture["query"]), 8)
        self.assertEqual(len(fixture["source_context"]), 8)
        self.assertEqual(len(fixture["query"]["expected_checkpoint"]), 2)
        for observation in contract.OBSERVATIONS:
            value = forged_claim(self.query, observation)
            self.assertEqual(fixture["claims"][observation], value)
            self.assertEqual(len(value), 7)
            self.assertEqual(contract.parse_claim(self.query, canonical(value)).as_dict(), value)

    def test_source_and_query_have_separate_domains_and_include_both_public_signatures(self):
        source, query = self.query._source.as_dict(), self.query.as_dict()
        self.assertEqual(self.query._source.digest_hex, hashlib.sha256(
            b"PTLC/observation-policy-source-context/v1\0" + canonical(source)).hexdigest())
        self.assertEqual(self.query.digest_hex, hashlib.sha256(
            b"PTLC/observation-policy-read-query/v1\0" + canonical(query)).hexdigest())
        self.assertNotEqual(self.query.digest_hex, signatures.request_digest(query["governor_signature_request"]))
        for field in ("issuer_signature_hex", "owner_signature_hex"):
            packet = copy.deepcopy(public.fixture()["primary"]["envelope"])
            packet[field] = "00" * 64
            changed = read_query(self.bound, canonical(packet))
            self.assertNotEqual(changed.digest_hex, self.query.digest_hex)
            self.refuse_claim(forged_claim(self.query), expected=changed)

    def test_decoded_scope_and_retained_resource_are_complete_independent_expectations(self):
        query = self.query.as_dict()
        self.assertEqual(query["decoded_scope"], self.bound._intent._scope.as_dict())
        self.assertEqual(query["retained_resource"], self.bound._intent._resource.as_dict())
        self.assertEqual(hashlib.sha256(b"PTLC/observation-authority-scope/v1\0" +
            canonical(query["decoded_scope"])).hexdigest(), query["governor_signature_request"]["bound_intent"]["scope_digest_hex"])
        self.assertEqual(query["decoded_scope"]["attempt_limit"], 2)
        self.assertEqual(query["decoded_scope"]["target_limit"], 2)
        self.assertEqual(query["retained_resource"]["resource_kind"], "exact-paired-release-v1")

    def test_exact_query_replay_and_claim_replay_change_no_retained_source(self):
        before = copy.deepcopy(self.state)
        for _ in range(3):
            self.assertIs(contract.parse_query(self.query, self.query.canonical_bytes), self.query)
            self.assertEqual(contract.parse_claim(self.query, canonical(forged_claim(self.query))).as_dict(), forged_claim(self.query))
        self.assertEqual(self.state, before)

    def test_every_object_has_no_authority_currentness_registration_or_use_attributes(self):
        claim = contract.parse_claim(self.query, canonical(forged_claim(self.query)))
        for value in (self.bound, self.query._source, self.query._checkpoint, self.query, claim):
            for field in ("current", "authenticated", "issuer_verified", "authorized", "enrolled", "permit", "can_start", "quota_granted"):
                self.assertFalse(hasattr(value, field))

    def test_active_revoked_absent_and_unavailable_are_only_matched_public_labels(self):
        for observation in contract.OBSERVATIONS:
            claim = contract.parse_claim(self.query, canonical(forged_claim(self.query, observation)))
            self.assertEqual(claim.as_dict()["observation"], observation)
            self.assertIs(type(claim), contract.PolicyReadClaim)

    def test_zero_signatures_and_a_forged_active_reply_match_without_mathematical_facts(self):
        packet = copy.deepcopy(public.fixture()["primary"]["envelope"])
        packet.update(issuer_signature_hex="00" * 64, owner_signature_hex="00" * 64)
        query = read_query(self.bound, canonical(packet))
        claim = contract.parse_claim(query, canonical(forged_claim(query)))
        self.assertEqual(claim.as_dict()["observation"], "active")
        self.assertNotEqual(query.digest_hex, self.query.digest_hex)

    def test_all_query_fields_and_nested_fields_reject_incoming_replacements(self):
        original = self.query.as_dict()
        paths = ((), ("source_context",), ("expected_checkpoint",), ("decoded_scope",),
            ("retained_resource",), ("governor_signature_request",),
            ("governor_signature_request", "assignment"),
            ("governor_signature_request", "assignment", "governor_profile"),
            ("governor_signature_request", "bound_intent"))
        for path in paths:
            fields = original
            for part in path: fields = fields[part]
            for field, old in fields.items():
                changed = copy.deepcopy(original); target = changed
                for part in path: target = target[part]
                target[field] = old + 1 if type(old) is int else "99" * 32
                with self.subTest(path=path, field=field), self.assertRaises(contract.CurrentAuthorityContractError):
                    contract.parse_query(self.query, canonical(changed))

    def test_query_and_claim_missing_extra_fields_reject(self):
        for original, parser in ((self.query.as_dict(), contract.parse_query), (forged_claim(self.query), contract.parse_claim)):
            for field in original:
                changed = copy.deepcopy(original); changed.pop(field)
                with self.assertRaises(contract.CurrentAuthorityContractError): parser(self.query, canonical(changed))
            changed = dict(original, current=True)
            with self.assertRaises(contract.CurrentAuthorityContractError): parser(self.query, canonical(changed))

    def test_each_claim_binding_observation_or_assignment_replacement_rejects(self):
        for field in forged_claim(self.query):
            value = forged_claim(self.query)
            value[field] = "99" * 32
            self.refuse_claim(value)
            for invalid in (True, None, [], {}):
                value = forged_claim(self.query); value[field] = invalid
                self.refuse_claim(value)

    def test_valid_alternate_issuer_owner_caps_and_epoch_cannot_replace_selected_packet(self):
        for name in ("alternate_issuer", "alternate_owner", "broader_caps", "new_epoch", "same_key_roles"):
            vector = public.fixture()[name]
            with self.subTest(name=name), self.assertRaises(contract.CurrentAuthorityContractError):
                read_query(self.bound, canonical(vector["envelope"]))
            bound = public.selected_bound(self.state, name)
            changed = read_query(bound, canonical(vector["envelope"]))
            self.assertNotEqual(changed.digest_hex, self.query.digest_hex)
            self.refuse_claim(forged_claim(self.query), expected=changed)

    def test_opaque_scope_under_caps_cannot_bypass_independent_preparation(self):
        packet = public.fixture()["opaque_scope_under_caps"]["envelope"]
        with self.assertRaises(contract.CurrentAuthorityContractError):
            read_query(self.bound, canonical(packet))
        with self.assertRaises(ValueError):
            public.selected_bound(self.state, profile_overrides=dict(max_attempt_limit=1, max_target_limit=1))

    def test_source_context_cannot_replace_the_independent_resource_namespace_or_role(self):
        for field in ("resource_digest_hex", "authority_id_hex", "role"):
            source = copy.copy(self.query._source)
            value = source.as_dict(); value[field] = "99" * 32
            object.__setattr__(source, "_wire", canonical(value))
            with self.assertRaises(contract.CurrentAuthorityContractError):
                read_query(self.bound, self.envelope, source=source)

    def test_provisioning_root_and_assignment_issuer_have_separate_unverified_meanings(self):
        root = self.query._source.as_dict()["provisioning_root_key_hex"]
        issuer = self.query.as_dict()["governor_signature_request"]["assignment"]["issuer_auth_key_hex"]
        self.assertNotEqual(root, issuer)
        for key in (issuer, "00" * 32):
            source = selected_source(self.bound, provisioning_root_key_hex=key)
            query = read_query(self.bound, self.envelope, source=source)
            self.assertEqual(query.as_dict()["governor_signature_request"], self.query.as_dict()["governor_signature_request"])
            self.assertNotEqual(query.digest_hex, self.query.digest_hex)
            self.assertEqual(contract.parse_claim(query, canonical(forged_claim(query))).as_dict()["observation"], "active")

    def test_each_independently_changed_source_pin_changes_query_and_refuses_old_claim(self):
        for field in ("source_id_hex", "source_profile_digest_hex", "source_incarnation_hex", "provisioning_root_key_hex"):
            query = read_query(self.bound, self.envelope, source=selected_source(self.bound, **{field: "99" * 32}))
            self.assertNotEqual(query.digest_hex, self.query.digest_hex)
            self.refuse_claim(forged_claim(self.query), expected=query)

    def test_new_incarnation_with_reused_revision_is_distinct_without_proving_antirollback(self):
        query = read_query(self.bound, self.envelope, source=selected_source(self.bound, source_incarnation_hex="b3" * 32))
        self.assertEqual(query.as_dict()["expected_checkpoint"], self.query.as_dict()["expected_checkpoint"])
        self.refuse_claim(forged_claim(self.query), expected=query)
        self.assertEqual(contract.parse_claim(self.query, canonical(forged_claim(self.query))).as_dict()["observation"], "active")

    def test_policy_revision_and_digest_both_require_exact_selected_checkpoint(self):
        for checkpoint in (contract.PolicyCheckpoint(1, "a4" * 32), contract.PolicyCheckpoint(0, "b4" * 32)):
            query = read_query(self.bound, self.envelope, checkpoint=checkpoint)
            self.refuse_claim(forged_claim(self.query), expected=query)
            self.assertNotEqual(query.digest_hex, self.query.digest_hex)
        for head in (dict(revision=1, policy_state_digest_hex="a4" * 32), dict(revision=0, policy_state_digest_hex="b4" * 32)):
            value = forged_claim(self.query); value["claimed_checkpoint"] = head
            self.refuse_claim(value)

    def test_revision_has_exact_integer_bounds_without_alias_or_wraparound(self):
        for revision in (0, authority.MAX_NUMBER):
            checkpoint = contract.PolicyCheckpoint(revision, "a4" * 32)
            query = read_query(self.bound, self.envelope, checkpoint=checkpoint)
            self.assertEqual(contract.parse_claim(query, canonical(forged_claim(query))).as_dict()["claimed_checkpoint"]["revision"], revision)
        for revision in (None, False, True, -1, authority.MAX_NUMBER + 1, 0.0, 1.0, "0"):
            with self.assertRaises(contract.CurrentAuthorityContractError): contract.PolicyCheckpoint(revision, "a4" * 32)

    def test_checkpoint_refuses_quota_heads_and_malformed_or_additional_state(self):
        with self.assertRaises(contract.CurrentAuthorityContractError):
            read_query(self.bound, self.envelope, checkpoint=authority.AuthorityHead(0, "a4" * 32, 0))
        for field in ("revision", "policy_state_digest_hex"):
            value = forged_claim(self.query); value["claimed_checkpoint"].pop(field)
            self.refuse_claim(value)
        value = forged_claim(self.query); value["claimed_checkpoint"]["consumed"] = 0
        self.refuse_claim(value)

    def test_new_challenge_refuses_retained_old_reply_but_reused_challenge_replays(self):
        query = read_query(self.bound, self.envelope, challenge="b5" * 32)
        self.refuse_claim(forged_claim(self.query), expected=query)
        for _ in range(2):
            self.assertEqual(contract.parse_claim(self.query, canonical(forged_claim(self.query))).as_dict(), forged_claim(self.query))

    def test_new_challenge_and_forged_bound_reply_supply_no_authentication_or_recency(self):
        query = read_query(self.bound, self.envelope, challenge="b5" * 32)
        value = forged_claim(query)
        self.assertEqual(contract.parse_claim(query, canonical(value)).as_dict(), value)
        self.assertEqual(value["claimed_checkpoint"], self.query.as_dict()["expected_checkpoint"])

    def test_live_policy_change_does_not_refresh_retained_old_query(self):
        external_policy = dict(checkpoint=self.query._checkpoint, revoked=False)
        claim = forged_claim(self.query)
        external_policy.update(checkpoint=contract.PolicyCheckpoint(1, "b4" * 32), revoked=True)
        self.assertEqual(contract.parse_claim(self.query, canonical(claim)).as_dict()["observation"], "active")
        updated = read_query(self.bound, self.envelope, checkpoint=external_policy["checkpoint"])
        self.refuse_claim(claim, expected=updated)

    def test_coherent_old_source_query_and_reply_restore_still_matches_after_rotation(self):
        saved = (copy.copy(self.query._source), self.query.canonical_bytes, canonical(forged_claim(self.query)))
        rotated = read_query(self.bound, self.envelope, source=selected_source(self.bound, source_incarnation_hex="b3" * 32))
        self.refuse_claim(json.loads(saved[2]), expected=rotated)
        restored = read_query(self.bound, self.envelope, source=saved[0])
        self.assertIs(contract.parse_query(restored, saved[1]), restored)
        self.assertEqual(contract.parse_claim(restored, saved[2]).as_dict()["observation"], "active")

    def test_unavailable_and_absent_claims_cannot_carry_a_checkpoint_or_assignment_positive(self):
        unavailable = forged_claim(self.query, "unavailable")
        self.assertIsNone(contract.parse_claim(self.query, canonical(unavailable)).as_dict()["claimed_checkpoint"])
        for field, item in (("claimed_checkpoint", self.query._checkpoint.as_dict()), ("assignment_digest_hex", self.bound._assignment.digest_hex)):
            value = dict(unavailable); value[field] = item
            self.refuse_claim(value)
        value = forged_claim(self.query, "absent"); value["assignment_digest_hex"] = self.bound._assignment.digest_hex
        self.refuse_claim(value)
        value = forged_claim(self.query); value["claimed_checkpoint"] = None
        self.refuse_claim(value)

    def test_all_claims_after_exhausted_reopen_add_no_allowance_refund_or_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root, head = Path(directory) / "state", Path(directory) / "head.json"
            with Journal.open(root, head) as journal:
                session = prepare(journal, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, invalid, recoverer=lambda _: None)
            with Journal.open(root, head) as journal:
                state = journal.get_exchange(session)
                bound = public.selected_bound(state)
                query = read_query(bound, self.envelope)
                before = (copy.deepcopy(journal._state), journal._sequence,
                    (root / "journal.sqlite3").read_bytes(), head.read_bytes())
                for observation in contract.OBSERVATIONS:
                    contract.parse_claim(query, canonical(forged_claim(query, observation)))
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session,
                        completion.bob_candidate_from_signature(state, final_signatures()[0]),
                        expected_observation_digest=completion.observation_digest(invalid),
                        recoverer=lambda value: calls.append(value))
                self.assertEqual((copy.deepcopy(journal._state), journal._sequence,
                    (root / "journal.sqlite3").read_bytes(), head.read_bytes()), before)
                self.assertEqual(calls, [])
                self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)

    def test_noncanonical_duplicates_aliases_deep_oversized_and_nonascii_wire_refuse(self):
        for wire, parser in ((self.query.canonical_bytes, contract.parse_query), (canonical(forged_claim(self.query)), contract.parse_claim)):
            schema = json.loads(wire)["schema"]
            invalid = (b"", wire + b"\n", b" " + wire, wire + b"x",
                b'{"schema":"' + schema.encode("ascii") + b'",' + wire[1:],
                wire.replace(b'"schema"', b'"\\u0073chema"', 1),
                b"[" * 1100 + b"0" + b"]" * 1100, b"x" * (contract.MAX_WIRE_BYTES + 1),
                b"\xff", wire.decode("ascii"), bytearray(wire), memoryview(wire))
            for value in invalid:
                with self.assertRaises(contract.CurrentAuthorityContractError): parser(self.query, value)

    def test_hostile_foreign_types_and_key_encodings_run_no_foreign_hooks(self):
        class Hostile:
            def __getattribute__(self, name): raise AssertionError("untrusted hook ran")
            def __eq__(self, other): raise AssertionError("untrusted hook ran")
        class HostileString(str):
            def __eq__(self, other): raise AssertionError("untrusted hook ran")
        for item in (Hostile(), HostileString("a1" * 32), None, True, [], {}, "A1" * 32, "a1" * 31):
            with self.assertRaises(contract.CurrentAuthorityContractError): selected_source(self.bound, source_id_hex=item)
            with self.assertRaises(contract.CurrentAuthorityContractError): contract.PolicyCheckpoint(0, item)
            with self.assertRaises(contract.CurrentAuthorityContractError): read_query(self.bound, self.envelope, challenge=item)
        for expected in (None, {}, Hostile(), object.__new__(contract.PolicyReadQuery)):
            with self.assertRaises(contract.CurrentAuthorityContractError): contract.parse_query(expected, self.query.canonical_bytes)
            with self.assertRaises(contract.CurrentAuthorityContractError): contract.parse_claim(expected, canonical(forged_claim(self.query)))

    def test_factory_only_frozen_objects_and_nonexact_expected_types_refuse(self):
        for cls in (contract.SourceContext, contract.PolicyReadQuery, contract.PolicyReadClaim):
            with self.assertRaises(TypeError): cls()
        for value, field in ((self.query, "_wire"), (self.query._source, "_wire"), (self.query._checkpoint, "revision")):
            with self.assertRaises(FrozenInstanceError): setattr(value, field, None)
        for bound in (None, {}, object.__new__(type(self.bound))):
            with self.assertRaises(contract.CurrentAuthorityContractError): selected_source(bound)
            with self.assertRaises(contract.CurrentAuthorityContractError): read_query(bound, self.envelope, source=self.query._source)

    def test_defensive_nested_copies_do_not_replace_source_checkpoint_or_expected_bytes(self):
        original = self.query.canonical_bytes
        value = self.query.as_dict()
        value["source_context"]["source_id_hex"] = "99" * 32
        value["expected_checkpoint"]["revision"] = 2
        value["decoded_scope"]["attempt_limit"] = 64
        value["governor_signature_request"]["owner_signature_hex"] = "00" * 64
        self.assertEqual(self.query.canonical_bytes, original)
        claim = contract.parse_claim(self.query, canonical(forged_claim(self.query)))
        claim.as_dict()["claimed_checkpoint"]["revision"] = 2
        self.assertEqual(claim.as_dict()["claimed_checkpoint"]["revision"], 0)

    def test_damaged_selected_source_checkpoint_or_bound_revalidates_before_parsing(self):
        for field, original, damaged_field, item in (
            ("_source", self.query._source, "_wire", b"{}"),
            ("_checkpoint", self.query._checkpoint, "revision", True),
            ("_expected", self.bound, "_wire", b"{}")):
            changed = copy.copy(self.query); damaged = copy.copy(original)
            object.__setattr__(damaged, damaged_field, item)
            object.__setattr__(changed, field, damaged)
            with self.assertRaises(contract.CurrentAuthorityContractError): contract.parse_query(changed, self.query.canonical_bytes)
            self.refuse_claim(forged_claim(self.query), expected=changed)

    def test_errors_are_sanitized_without_echoing_rejected_public_labels(self):
        value = forged_claim(self.query); value["observation"] = "invalid-selected-observation"
        with self.assertRaises(contract.CurrentAuthorityContractError) as caught:
            contract.parse_claim(self.query, canonical(value))
        self.assertEqual(str(caught.exception), "policy read claim selection rejected")
        self.assertNotIn("invalid-selected-observation", str(caught.exception))

    def test_numeric_wire_aliases_in_checkpoint_and_scope_cannot_replace_exact_query(self):
        wire = self.query.canonical_bytes
        for token, alternate in ((b'"revision":0', b'"revision":0.0'),
            (b'"authority_epoch":1', b'"authority_epoch":1e0'),
            (b'"attempt_limit":2', b'"attempt_limit":2.0')):
            self.assertIn(token, wire)
            alternate_wire = wire.replace(token, alternate, 1)
            with self.assertRaises(contract.CurrentAuthorityContractError):
                contract.parse_query(self.query, alternate_wire)
            damaged = copy.copy(self.query)
            object.__setattr__(damaged, "_wire", alternate_wire)
            with self.assertRaises(contract.CurrentAuthorityContractError):
                damaged.as_dict()
