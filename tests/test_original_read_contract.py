"""Unsigned original lookup grammar and explicit false-authority controls."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from offline_session import current_authority_contract as current
from qualification import original_read_contract as read
from qualification import policy_effect_store as local, source_read_ordering as ordering
from qualification import source_response as legacy, source_root_roles as roots


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


class OriginalReadContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy_fixture = json.loads(Path("qualification/fixtures/source_response.json").read_text("ascii"))
        cls.declaration = cls.legacy_fixture["positive_vectors"]["primary"]["envelope"]["root_envelope"]["declaration"]
        cls.root = cls.root_from(cls.declaration)
        cls.profile_wire = read._canonical(cls.declaration["governor_profile"])

    @staticmethod
    def root_from(d):
        return roots.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"],
            delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])

    def original(self, **overrides):
        fields = dict(operation_id_hex="01"*32, expected_revision=4,
            profile_wire=self.profile_wire, proposal_digest_hex="02"*32)
        fields.update(overrides)
        return read.original_operation(**fields)

    def query(self, *, root=None, original=None, checkpoint=None, record_checkpoint=None, challenge="03"*32):
        return read.original_read_query(self.root if root is None else root,
            self.original() if original is None else original,
            checkpoint=current.PolicyCheckpoint(7, "04"*32) if checkpoint is None else checkpoint,
            record_checkpoint=read.RecordCheckpoint(9, "05"*32) if record_checkpoint is None else record_checkpoint,
            challenge_hex=challenge)

    def claim(self, query=None, observation="pending", *, active=True, charge=2, effect=6):
        query = self.query() if query is None else query
        q = query.as_dict()
        unknown = observation == "unavailable"
        record = None if observation in ("absent", "unavailable") else dict(
            original_operation=q["original_operation"], charge_sequence=charge,
            effect_sequence=effect if observation == "completed" else None)
        return dict(schema=read.CLAIM_SCHEMA, query_digest_hex=query.digest_hex,
            root_declaration_digest_hex=q["root_declaration_digest_hex"],
            source_context_digest_hex=read._digest(b"PTLC/observation-policy-source-context/v1\0", q["source_context"]),
            challenge_hex=q["challenge_hex"], observation=observation,
            claimed_checkpoint=None if unknown else q["expected_checkpoint"],
            claimed_record_checkpoint=None if unknown else q["expected_record_checkpoint"],
            head_policy=None if unknown else dict(governor_profile=query._root.as_dict()["governor_profile"], active=active),
            original_record=record)

    def parsed(self, query=None, **kwargs):
        query = self.query() if query is None else query
        return read.parse_claim(query, read._canonical(self.claim(query, **kwargs)))

    def refuse_claim(self, value, query=None):
        with self.assertRaises(read.OriginalReadError):
            read.parse_claim(self.query() if query is None else query, read._canonical(value))

    def test_complete_original_source_root_policy_and_record_positions_are_independently_selected(self):
        query = self.query()
        q = query.as_dict()
        self.assertEqual(len(q), 9)
        self.assertEqual(len(q["original_operation"]["governor_profile"]), 14)
        self.assertEqual(q["source_context"], self.declaration["source_context"])
        self.assertEqual(q["root_declaration_digest_hex"], self.root.message_digest_hex)
        self.assertIs(read.parse_query(query, query.canonical_bytes), query)
        self.assertEqual(q["expected_record_checkpoint"]["retention_rule"], read.RETENTION_RULE)

    def test_fixed_unsigned_framing_fixture_reproduces_complete_bytes_and_all_four_claim_digests(self):
        fixture = json.loads(Path("qualification/fixtures/original_read_contract.json").read_text("ascii"))
        query = self.query()
        self.assertEqual(fixture["root_declaration"], self.root.as_dict())
        self.assertEqual(query.canonical_bytes, read._canonical(fixture["query"]))
        self.assertEqual(query.digest_hex, fixture["query_digest_hex"])
        self.assertEqual(set(fixture["observations"]), set(read.OBSERVATIONS))
        for observation, vector in fixture["observations"].items():
            parsed = self.parsed(query, observation=observation)
            self.assertEqual(parsed.canonical_bytes, read._canonical(vector["claim"]))
            self.assertEqual(parsed.digest_hex, vector["claim_digest_hex"])

    def test_all_four_record_states_match_without_permission_or_source_truth(self):
        for observation in read.OBSERVATIONS:
            for active in (False, True):
                query = self.query()
                parsed = self.parsed(query, observation=observation, active=active)
                self.assertEqual(parsed.as_dict(), self.claim(query, observation, active=active))
                for field in ("authenticated", "current", "authorized", "receipt", "can_start",
                              "refund", "retry", "committed", "nonrollbackable"):
                    self.assertFalse(hasattr(parsed, field))

    def test_query_and_claim_domains_are_distinct_from_each_other_and_legacy_reads(self):
        query, claim = self.query(), self.parsed()
        self.assertEqual(query.digest_hex, hashlib.sha256(read.QUERY_DOMAIN+query.canonical_bytes).hexdigest())
        self.assertEqual(claim.digest_hex, hashlib.sha256(read.CLAIM_DOMAIN+claim.canonical_bytes).hexdigest())
        self.assertEqual(len({read.QUERY_DOMAIN, read.CLAIM_DOMAIN, legacy.RESPONSE_DOMAIN,
            legacy.CLAIM_DOMAIN, roots.DECLARATION_DOMAIN}), 5)
        self.assertNotEqual(query.digest_hex, claim.digest_hex)

    def test_same_id_changed_proposal_revision_or_each_profile_field_cannot_rebind_old_claim(self):
        query = self.query()
        old = read._canonical(self.claim(query))
        alternatives = [self.original(proposal_digest_hex="06"*32), self.original(expected_revision=3)]
        profile = json.loads(self.profile_wire)
        # Namespace fields remain fixed; every other selectable profile field is bound.
        for field, value in profile.items():
            if field in ("schema", "purpose", "role", "algorithm", "authority_id_hex", "resource_digest_hex"):
                continue
            changed = dict(profile)
            changed[field] = value-1 if type(value) is int and value > 1 else (value+1 if type(value) is int else "07"*32)
            alternatives.append(self.original(profile_wire=read._canonical(changed)))
        for original in alternatives:
            alternate = self.query(original=original)
            self.assertEqual(alternate.as_dict()["original_operation"]["operation_id_hex"], "01"*32)
            self.assertNotEqual(alternate.digest_hex, query.digest_hex)
            with self.assertRaises(read.OriginalReadError):
                read.parse_claim(alternate, old)

    def test_different_ids_with_same_proposal_remain_distinct_original_operations(self):
        first = self.query()
        second = self.query(original=self.original(operation_id_hex="08"*32))
        self.assertEqual(first.as_dict()["original_operation"]["proposal_digest_hex"], second.as_dict()["original_operation"]["proposal_digest_hex"])
        self.assertNotEqual(first.digest_hex, second.digest_hex)
        self.refuse_claim(self.claim(first), second)

    def test_self_selected_colliding_original_claims_still_match_without_source_deduplication(self):
        first = self.query()
        second = self.query(original=self.original(proposal_digest_hex="17"*32))
        one, two = self.parsed(first), self.parsed(second)
        self.assertEqual(one.as_dict()["original_record"]["original_operation"]["operation_id_hex"],
            two.as_dict()["original_record"]["original_operation"]["operation_id_hex"])
        self.assertNotEqual(one.canonical_bytes, two.canonical_bytes)
        # Matching separately changed premises cannot discover a source collision.
        self.assertNotEqual(first.digest_hex, second.digest_hex)

    def test_historical_original_profile_is_not_rebound_to_new_policy_or_caps(self):
        d = copy.deepcopy(self.declaration)
        d["governor_profile"]["authority_epoch"] += 1
        d["governor_profile"]["max_attempt_limit"] = 1
        root = self.root_from(d)
        query = self.query(root=root)
        parsed = self.parsed(query, active=False)
        self.assertEqual(parsed.as_dict()["original_record"]["original_operation"]["governor_profile"], self.declaration["governor_profile"])
        self.assertEqual(parsed.as_dict()["head_policy"]["governor_profile"], d["governor_profile"])
        self.assertNotEqual(d["governor_profile"], self.declaration["governor_profile"])

    def test_future_revision_and_same_revision_changed_profile_refuse(self):
        with self.assertRaises(read.OriginalReadError):
            self.query(original=self.original(expected_revision=8))
        d = copy.deepcopy(self.declaration)
        d["governor_profile"]["max_attempt_limit"] = 1
        with self.assertRaises(read.OriginalReadError):
            self.query(root=self.root_from(d), original=self.original(expected_revision=7))
        self.query(original=self.original(expected_revision=7))

    def test_original_namespace_cannot_change_resource_authority_or_role(self):
        for field in ("authority_id_hex", "resource_digest_hex"):
            profile = json.loads(self.profile_wire)
            profile[field] = "09"*32
            with self.assertRaises(read.OriginalReadError):
                self.query(original=self.original(profile_wire=read._canonical(profile)))
        profile = json.loads(self.profile_wire)
        profile["role"] = "source-response"
        with self.assertRaises(read.OriginalReadError):
            self.original(profile_wire=read._canonical(profile))

    def test_every_query_field_and_nested_original_source_checkpoint_field_is_bound(self):
        query = self.query()
        for path, obj in objects(query.as_dict()):
            for field, value in obj.items():
                if type(value) is dict:
                    continue
                changed = query.as_dict()
                target(changed, path)[field] = value+1 if type(value) is int else "different"
                with self.assertRaises(read.OriginalReadError):
                    read.parse_query(query, read._canonical(changed))

    def test_each_claim_binding_refuses_individually(self):
        for field in ("schema", "query_digest_hex", "root_declaration_digest_hex",
                      "source_context_digest_hex", "challenge_hex"):
            value = self.claim()
            value[field] = "0a"*32
            self.refuse_claim(value)
        for field in ("claimed_checkpoint", "claimed_record_checkpoint"):
            value = self.claim()
            key = "policy_state_digest_hex" if field == "claimed_checkpoint" else "record_lineage_digest_hex"
            value[field][key] = "0b"*32
            self.refuse_claim(value)

    def test_missing_extra_and_privilege_fields_refuse_at_every_nested_level(self):
        for observation in read.OBSERVATIONS:
            for path, obj in objects(self.claim(observation=observation)):
                for field in obj:
                    value = self.claim(observation=observation)
                    del target(value, path)[field]
                    self.refuse_claim(value)
                for field in ("permit", "refund", "retry", "signature_hex", "physical_entry"):
                    value = self.claim(observation=observation)
                    target(value, path)[field] = True
                    self.refuse_claim(value)
        query = self.query()
        for path, obj in objects(query.as_dict()):
            for field in obj:
                value = query.as_dict()
                del target(value, path)[field]
                with self.assertRaises(read.OriginalReadError):
                    read.parse_query(query, read._canonical(value))

    def test_numeric_aliases_limits_and_boolean_policy_are_exact(self):
        for bad in (True, False, -1, 1.0, "1", None, read.MAX_NUMBER+1):
            with self.assertRaises(read.OriginalReadError):
                self.original(expected_revision=bad)
            with self.assertRaises(read.OriginalReadError):
                read.RecordCheckpoint(bad, "05"*32)
            value = self.claim()
            value["original_record"]["charge_sequence"] = bad
            self.refuse_claim(value)
        for bad in (0, 1, "true", None):
            value = self.claim()
            value["head_policy"]["active"] = bad
            self.refuse_claim(value)
        read.RecordCheckpoint(read.MAX_NUMBER, "05"*32)

    def test_zero_boundary_absence_does_not_assert_charge_or_effect(self):
        query = self.query(record_checkpoint=read.RecordCheckpoint(0, "05"*32))
        self.parsed(query, observation="absent")
        self.refuse_claim(self.claim(query), query)
        for charge in (0, -1, True, 10):
            self.refuse_claim(self.claim(charge=charge))

    def test_completed_effect_must_follow_original_charge_and_not_exceed_record_cutoff(self):
        self.parsed(observation="completed")
        for effect in (None, False, 0, 1, 2, 10, 6.0, "6", read.MAX_NUMBER+1):
            self.refuse_claim(self.claim(observation="completed", effect=effect))

    def test_pending_absent_and_unavailable_cannot_smuggle_completed_record_or_head(self):
        value = self.claim()
        value["original_record"]["effect_sequence"] = 6
        self.refuse_claim(value)
        value = self.claim(observation="absent")
        value["original_record"] = self.claim()["original_record"]
        self.refuse_claim(value)
        for field in ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record"):
            value = self.claim(observation="unavailable")
            value[field] = self.claim()[field]
            self.refuse_claim(value)

    def test_each_original_record_field_refuses_even_when_outer_bindings_match(self):
        for field, replacement in (("operation_id_hex", "0c"*32), ("expected_revision", 3),
                                  ("proposal_digest_hex", "0d"*32)):
            value = self.claim()
            value["original_record"]["original_operation"][field] = replacement
            self.refuse_claim(value)
        value = self.claim()
        value["original_record"]["original_operation"]["governor_profile"]["authority_epoch"] += 1
        self.refuse_claim(value)

    def test_all_head_profile_fields_are_complete_and_active_is_only_a_claim(self):
        for field, selected in self.declaration["governor_profile"].items():
            value = self.claim()
            value["head_policy"]["governor_profile"][field] = selected+1 if type(selected) is int else "0e"*32
            self.refuse_claim(value)
        self.assertNotEqual(self.parsed(active=False).digest_hex, self.parsed(active=True).digest_hex)

    def test_noncanonical_duplicate_alias_deep_nonascii_and_oversized_wire_refuse(self):
        query = self.query()
        wire = read._canonical(self.claim(query))
        malformed = [b"", b" " + wire, wire+b"\n", wire.replace(b'"observation":', b'"observation":"pending","observation":', 1),
            wire.replace(b'"charge_sequence":2', b'"charge_sequence":2.0'),
            wire.replace(b'"charge_sequence":2', b'"charge_sequence":2e0'),
            b"["*2000+b"0"+b"]"*2000, b"\xff", b"x"*(read.MAX_WIRE_BYTES+1)]
        for item in malformed:
            with self.assertRaises(read.OriginalReadError):
                read.parse_claim(query, item)
            with self.assertRaises(read.OriginalReadError):
                read.parse_query(query, item)

    def test_nonbytes_hex_case_and_profile_digest_instead_of_complete_profile_refuse(self):
        query = self.query()
        wire = read._canonical(self.claim())
        for bad in (wire.decode("ascii"), bytearray(wire), memoryview(wire), None):
            with self.assertRaises(read.OriginalReadError):
                read.parse_claim(query, bad)
        for bad in ("AA"*32, "00"*31, "00"*33, "gg"*32, 0, None):
            with self.assertRaises(read.OriginalReadError):
                self.original(operation_id_hex=bad)
            with self.assertRaises(read.OriginalReadError):
                self.query(challenge=bad)
            with self.assertRaises(read.OriginalReadError):
                read.RecordCheckpoint(9, bad)
        for bad in (b"00"*32, self.profile_wire.decode("ascii"), bytearray(self.profile_wire)):
            with self.assertRaises(read.OriginalReadError):
                self.original(profile_wire=bad)

    def test_legacy_assignment_reads_and_signed_responses_are_not_original_receipts(self):
        v = self.legacy_fixture["positive_vectors"]["primary"]
        for value in (v["response"]["query"], v["response"]["claim"], v["response"], v["envelope"], v["request"]):
            self.refuse_claim(value)
            with self.assertRaises(read.OriginalReadError):
                read.parse_query(self.query(), read._canonical(value))

    def test_source_incarnation_and_root_rotation_require_new_complete_selections(self):
        old = self.claim()
        for field in ("source_id_hex", "source_incarnation_hex", "source_profile_digest_hex", "provisioning_root_key_hex"):
            d = copy.deepcopy(self.declaration)
            d["source_context"][field] = "0f"*32
            alternate = self.query(root=self.root_from(d))
            self.refuse_claim(old, alternate)
            self.parsed(alternate)
        d = copy.deepcopy(self.declaration)
        d["declaration_revision"] += 1
        self.refuse_claim(old, self.query(root=self.root_from(d)))

    def test_record_cutoff_retention_and_lineage_cannot_be_changed_by_peer(self):
        value = self.claim()
        value["claimed_record_checkpoint"]["event_sequence"] += 1
        self.refuse_claim(value)
        value = self.claim()
        value["claimed_record_checkpoint"]["retention_rule"] = "evict-old-originals"
        self.refuse_claim(value)
        alternate = self.query(record_checkpoint=read.RecordCheckpoint(10, "10"*32))
        self.refuse_claim(self.claim(), alternate)

    def test_lost_return_and_unavailable_retain_original_identity_without_inferred_absence(self):
        query = self.query()
        first = self.parsed(query)
        unknown = self.parsed(query, observation="unavailable")
        second = self.parsed(query)
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)
        self.assertIsNone(unknown.as_dict()["original_record"])
        self.assertEqual(query.as_dict()["original_operation"], self.original().as_dict())
        self.assertNotEqual(unknown.digest_hex, self.parsed(query, observation="absent").digest_hex)

    def test_absence_at_selected_retention_position_does_not_prove_no_earlier_or_later_effect(self):
        # These mutually inconsistent truth claims are all forgeable public bytes.
        query = self.query()
        absent = self.parsed(query, observation="absent")
        completed = self.parsed(query, observation="completed")
        self.assertEqual(absent._query.canonical_bytes, completed._query.canonical_bytes)
        self.assertNotEqual(absent.digest_hex, completed.digest_hex)
        self.assertIsNone(absent.as_dict()["original_record"])

    def test_fresh_challenge_over_old_policy_and_record_state_still_matches_unsigned_history(self):
        first = self.query()
        fresh = self.query(challenge="11"*32)
        old = self.parsed(first, observation="completed")
        fresh_claim = self.parsed(fresh, observation="completed")
        self.refuse_claim(old.as_dict(), fresh)
        self.assertEqual(old.as_dict()["claimed_checkpoint"], fresh_claim.as_dict()["claimed_checkpoint"])
        self.assertEqual(old.as_dict()["original_record"], fresh_claim.as_dict()["original_record"])
        self.assertNotEqual(old.digest_hex, fresh_claim.digest_hex)

    def test_arbitrary_noncurve_root_and_opaque_lineage_match_without_authentication(self):
        d = copy.deepcopy(self.declaration)
        d["source_context"]["provisioning_root_key_hex"] = "ff"*32
        d["source_context"]["source_profile_digest_hex"] = "12"*32
        query = self.query(root=self.root_from(d), record_checkpoint=read.RecordCheckpoint(9, "ff"*32))
        parsed = self.parsed(query)
        self.assertEqual(parsed.as_dict()["claimed_record_checkpoint"]["record_lineage_digest_hex"], "ff"*32)
        self.assertEqual(len(set([d["source_context"]["provisioning_root_key_hex"],
            d["governor_profile"]["owner_auth_key_hex"], *d["delegated_keys"].values()])), 5)

    def test_factories_objects_and_defensive_copies_supply_no_mutable_admission_token(self):
        for cls in (read.OriginalOperation, read.OriginalReadQuery, read.OriginalReadClaim):
            with self.assertRaises(TypeError):
                cls()
        query, parsed = self.query(), self.parsed()
        for obj in (query, parsed, self.original()):
            with self.assertRaises(FrozenInstanceError):
                obj._wire = b"changed"
        q = query.as_dict()
        q["original_operation"]["operation_id_hex"] = "13"*32
        claim = parsed.as_dict()
        claim["original_record"]["original_operation"]["operation_id_hex"] = "13"*32
        self.assertEqual(query.as_dict()["original_operation"]["operation_id_hex"], "01"*32)
        self.assertEqual(parsed.as_dict()["original_record"]["original_operation"]["operation_id_hex"], "01"*32)

    def test_damaged_selected_challenge_wire_or_original_object_refuses(self):
        for field, replacement in (("_root", object()), ("_original", object()), ("_checkpoint", object()),
                ("_record_checkpoint", object()), ("_challenge", "14"*32), ("_wire", b"{}")):
            query = copy.deepcopy(self.query())
            object.__setattr__(query, field, replacement)
            with self.assertRaises(read.OriginalReadError):
                query.as_dict()
        query = copy.deepcopy(self.query())
        value = query.as_dict()
        value["challenge_hex"] = "14"*32
        object.__setattr__(query, "_wire", read._canonical(value))
        with self.assertRaises(read.OriginalReadError):
            query.as_dict()
        parsed = copy.deepcopy(self.parsed())
        object.__setattr__(parsed, "_wire", b"{}")
        with self.assertRaises(read.OriginalReadError):
            parsed.as_dict()

    def test_inexact_selected_objects_and_hostile_subclasses_refuse_before_hooks(self):
        calls = []
        class HostileRoot(roots.RootDeclaration):
            def as_dict(self):
                calls.append("root")
                raise RuntimeError("synthetic private diagnostic")
        class HostileQuery(read.OriginalReadQuery):
            def as_dict(self):
                calls.append("query")
                raise RuntimeError("synthetic private diagnostic")
        class HostileBytes(bytes):
            def decode(self, *args, **kwargs):
                calls.append("wire")
                raise RuntimeError("synthetic private diagnostic")
        with self.assertRaises(read.OriginalReadError):
            self.query(root=object.__new__(HostileRoot))
        with self.assertRaises(read.OriginalReadError):
            read.parse_claim(object.__new__(HostileQuery), read._canonical(self.claim()))
        with self.assertRaises(read.OriginalReadError):
            read.parse_claim(self.query(), HostileBytes(read._canonical(self.claim())))
        self.assertEqual(calls, [])

    def test_framing_does_not_launch_verifier_read_store_or_use_legacy_response_worker(self):
        with patch.object(local.OfflinePolicyEffectStore, "_transaction", side_effect=AssertionError("no store")), \
             patch.object(legacy, "verify_selected_response", side_effect=AssertionError("no legacy verifier")):
            self.parsed(observation="completed")


class OriginalReadStoreControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OriginalReadContractTests.setUpClass()
        cls.root = OriginalReadContractTests.root
        cls.profile = OriginalReadContractTests.profile_wire
        source = cls.root.as_dict()["source_context"]
        cls.labels = local.SourceLabels(source["source_id_hex"], source["source_incarnation_hex"],
            source["authority_id_hex"], source["resource_digest_hex"])

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-original-read-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)/"policy.sqlite3"
        self.store = local.OfflinePolicyEffectStore(str(self.path), self.labels, initial_profile=self.profile)
        self.addCleanup(self.dispose)
        self.original = local.OriginalRequest("01"*32, 0, self.profile, "02"*32)

    def dispose(self):
        if not self.store._closed:
            self.store.close()

    def selected_query(self):
        original = read.original_operation(operation_id_hex=self.original.operation_id_hex,
            expected_revision=self.original.expected_revision, profile_wire=self.original.profile_wire,
            proposal_digest_hex=self.original.proposal_digest_hex)
        return read.original_read_query(self.root, original,
            checkpoint=ordering.local_checkpoint(self.store, self.root),
            record_checkpoint=read.RecordCheckpoint(2, "15"*32), challenge_hex="16"*32)

    def completed_wire(self, query):
        # Arbitrary retention digest/position are test selections, not a source adapter.
        helper = OriginalReadContractTests()
        return read._canonical(helper.claim(query, "completed", charge=1, effect=2))

    def test_parsed_old_active_completed_statement_does_not_reenable_revoked_pending_effect_or_refund(self):
        self.store.allocate_synthetic(self.original)
        query = self.selected_query()
        forged = self.completed_wire(query)
        self.store.replace_local_policy(0, self.profile, active=False)
        before = self.path.read_bytes(), self.store.local_view()
        read.parse_claim(query, forged)
        with self.assertRaises(local.StoreRefused):
            self.store.apply_synthetic_effect(self.original)
        self.assertEqual((self.path.read_bytes(), self.store.local_view()), before)
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_coherent_restore_repeats_original_effect_while_same_selected_history_still_matches(self):
        checkpoint_copy = self.path.with_name("old.sqlite3")
        shutil.copyfile(self.path, checkpoint_copy)
        query = self.selected_query()
        forged = self.completed_wire(query)
        self.store.allocate_synthetic(self.original)
        self.store.apply_synthetic_effect(self.original)
        self.store.close()
        shutil.copyfile(checkpoint_copy, self.path)
        with local.OfflinePolicyEffectStore(str(self.path), self.labels) as restored:
            read.parse_claim(query, forged)
            self.assertEqual(restored.local_view().charged_operations, 0)
            restored.allocate_synthetic(self.original)
            restored.apply_synthetic_effect(self.original)
            self.assertEqual((restored.local_view().charged_operations, restored.local_view().synthetic_effects), (1, 1))

    def test_cloned_source_repeats_same_original_under_identical_root_and_opaque_lineage(self):
        clone = self.path.with_name("clone.sqlite3")
        shutil.copyfile(self.path, clone)
        query = self.selected_query()
        forged = self.completed_wire(query)
        with local.OfflinePolicyEffectStore(str(clone), self.labels) as copied:
            read.parse_claim(query, forged)
            self.store.allocate_synthetic(self.original)
            self.store.apply_synthetic_effect(self.original)
            copied.allocate_synthetic(self.original)
            copied.apply_synthetic_effect(self.original)
            self.assertEqual(self.store.local_view().synthetic_effects+copied.local_view().synthetic_effects, 2)

    def test_read_statement_can_age_before_delivery_and_cannot_fence_blind_external_entry(self):
        self.store.allocate_synthetic(self.original)
        self.store.apply_synthetic_effect(self.original)
        query = self.selected_query()
        queued_response = self.completed_wire(query)
        self.store.replace_local_policy(0, self.profile, active=False)
        delivered = read.parse_claim(query, queued_response)
        # An ideal blind list actuator deliberately ignores current policy.
        ideal_entry = [delivered.as_dict()["original_record"]["original_operation"]["operation_id_hex"]]
        self.assertEqual(ideal_entry, [self.original.operation_id_hex])
        self.assertFalse(self.store.local_view().active)


if __name__ == "__main__":
    unittest.main()
