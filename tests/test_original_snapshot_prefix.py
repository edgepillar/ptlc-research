"""Retained synthetic prefixes detect forks only relative to retained witnesses."""

import ast
import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import current_authority_contract as current
from qualification import original_read_contract as reads, original_read_response as responses
from qualification import policy_effect_store as local
from original_snapshot_vectors import INPUT, OUTPUT, canonical, root_from, scenario
import original_snapshot_opening as opening
import original_snapshot_prefix as prefix


def wire(material):
    return canonical(dict(schema=opening.SCHEMA, purpose=opening.PURPOSE, record_material=material))


def capture(actual, **selection):
    return actual.query(**selection), wire(actual.material())


def describe(earlier, later):
    return prefix.compare_openings(*earlier, *later)


def select_material(query, material):
    """Adversarial self-selection control, never an authoritative head provider."""
    source = material["source"]
    policy = dict(root_declaration=material["root_declaration"], revision=source["revision"],
        profile_hex=source["profile_hex"], active=source["active"], mode=source["mode"])
    return reads.original_read_query(query._root, query._original,
        checkpoint=current.PolicyCheckpoint(source["revision"],
            hashlib.sha256(opening.POLICY_DOMAIN+canonical(policy)).hexdigest()),
        record_checkpoint=reads.RecordCheckpoint(len(material["events"]),
            hashlib.sha256(opening.RECORD_DOMAIN+canonical(material)).hexdigest()),
        challenge_hex=query.as_dict()["challenge_hex"])


def opened(pair):
    return opening.derive_claim(*pair).as_dict()


class OriginalSnapshotPrefixTests(unittest.TestCase):
    def test_nine_live_identical_openings_match_existing_claims_without_store_mutation(self):
        fixtures = json.loads(INPUT.read_text("ascii"))["positive_vectors"]
        for name, vector in fixtures.items():
            if name == "unavailable_pending":
                continue
            with self.subTest(name=name), scenario(name) as actual:
                pair = capture(actual)
                before = actual.path.read_bytes(), actual.store.local_view()
                result = describe(pair, pair)
                self.assertEqual(result.relation, "same-history")
                self.assertEqual(result.earlier_observation, vector["response"]["claim"]["observation"])
                self.assertEqual(result.later_observation, result.earlier_observation)
                self.assertEqual((result.appended_originals, result.appended_effects), (0, 0))
                self.assertEqual((actual.path.read_bytes(), actual.store.local_view()), before)

    def test_actual_absent_pending_completed_chain_retains_charges_without_refunds(self):
        with scenario("initial_absent") as actual:
            absent = capture(actual)
            actual.store.allocate_synthetic(actual.original)
            pending = capture(actual)
            actual.store.apply_synthetic_effect(actual.original)
            completed = capture(actual)
            charged = describe(absent, pending)
            effected = describe(pending, completed)
            complete = describe(absent, completed)
            self.assertEqual((charged.earlier_observation, charged.later_observation), ("absent", "pending"))
            self.assertEqual((charged.appended_originals, charged.appended_effects), (1, 0))
            self.assertEqual((effected.retained_originals, effected.appended_originals, effected.appended_effects), (1, 0, 1))
            self.assertEqual((complete.appended_originals, complete.appended_effects), (1, 1))
            self.assertEqual(actual.store.local_view().charged_operations, 1)
            for earlier, later in ((pending, absent), (completed, pending), (completed, absent)):
                with self.subTest(direction=(opened(earlier)["observation"], opened(later)["observation"])):
                    with self.assertRaises(prefix.PrefixRefused):
                        describe(earlier, later)

    def test_appended_original_may_sort_before_old_row_but_charges_only_after_old_head(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            other = replace(actual.original, operation_id_hex="00"*32, proposal_digest_hex="10"*32)
            actual.store.allocate_synthetic(other)
            actual.store.apply_synthetic_effect(other)
            actual.store.apply_synthetic_effect(actual.original)
            later = capture(actual)
            result = describe(earlier, later)
            self.assertEqual(actual.material()["operations"][0]["original_operation"]["operation_id_hex"], "00"*32)
            self.assertEqual((result.retained_originals, result.appended_originals, result.appended_effects), (1, 1, 2))
            self.assertEqual(result.later_observation, "completed")
            self.assertEqual(actual.store.local_view().charged_operations, 2)

    def test_actual_revocation_preserves_pending_original_without_admission_or_effect(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            actual.store.replace_local_policy(0, actual.profile, active=False)
            later = capture(actual)
            result = describe(earlier, later)
            self.assertEqual((result.earlier_revision, result.later_revision), (0, 1))
            self.assertEqual((result.earlier_observation, result.later_observation), ("pending", "pending"))
            self.assertFalse(opened(later)["head_policy"]["active"])
            before = actual.path.read_bytes(), actual.store.local_view()
            with self.assertRaises(local.StoreRefused):
                actual.store.apply_synthetic_effect(actual.original)
            self.assertEqual((actual.path.read_bytes(), actual.store.local_view()), before)

    def test_actual_identical_profile_policy_round_trip_keeps_all_revision_rows(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            actual.store.replace_local_policy(0, actual.profile, active=False)
            revoked = capture(actual)
            actual.store.replace_local_policy(1, actual.profile, active=True)
            restored_active = capture(actual)
            self.assertEqual(describe(earlier, restored_active).later_revision, 2)
            self.assertEqual(describe(revoked, restored_active).retained_originals, 1)
            self.assertEqual(len(actual.material()["policies"]), 3)
            self.assertEqual(actual.store.local_view().charged_operations, 1)
            with self.assertRaises(local.StoreRefused):
                actual.store.apply_synthetic_effect(actual.original)

    def test_mode_round_trip_repeats_policy_digest_but_retains_record_extension(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            actual.store.set_local_source_mode("unavailable")
            actual.store.set_local_source_mode("live")
            later = capture(actual)
            self.assertEqual(earlier[0].as_dict()["expected_checkpoint"], later[0].as_dict()["expected_checkpoint"])
            self.assertNotEqual(earlier[0].as_dict()["expected_record_checkpoint"], later[0].as_dict()["expected_record_checkpoint"])
            result = describe(earlier, later)
            self.assertEqual((result.earlier_event_sequence, result.later_event_sequence), (1, 3))
            self.assertEqual(result.relation, "retained-extension")
            self.assertEqual((result.appended_originals, result.appended_effects), (0, 0))

    def test_nonlive_openings_refuse_on_either_side_and_unavailable_keeps_null_facts(self):
        for mode in ("unavailable", "ambiguous", "compromise-detected"):
            with self.subTest(mode=mode), scenario("pending") as actual:
                live = capture(actual)
                actual.store.set_local_source_mode(mode)
                nonlive = capture(actual)
                if mode == "unavailable":
                    claim = actual.response(nonlive[0]).as_dict()["claim"]
                    self.assertEqual(claim["observation"], "unavailable")
                    self.assertTrue(all(claim[key] is None for key in
                        ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record")))
                for earlier, later in ((live, nonlive), (nonlive, live), (nonlive, nonlive)):
                    with self.assertRaises(prefix.PrefixRefused):
                        describe(earlier, later)
                self.assertEqual(actual.store.local_view().charged_operations, 1)

    def test_fresh_challenge_over_identical_old_absence_is_still_replayable_history(self):
        with scenario("initial_absent") as actual:
            earlier, fresh = capture(actual), capture(actual, challenge="07")
            result = describe(earlier, fresh)
            self.assertNotEqual(result.earlier_query_digest_hex, result.later_query_digest_hex)
            self.assertEqual(result.relation, "same-history")
            actual.store.allocate_synthetic(actual.original)
            self.assertEqual(describe(earlier, fresh), result)
            with self.assertRaises(opening.OpeningRefused):
                opened((actual.query(challenge="07"), fresh[1]))
            self.assertEqual(actual.store.local_view().charged_operations, 1)

    def test_correct_extension_remains_openable_after_actual_later_revocation(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            actual.store.apply_synthetic_effect(actual.original)
            later = capture(actual)
            result = describe(earlier, later)
            actual.store.replace_local_policy(0, actual.profile, active=False)
            self.assertEqual(describe(earlier, later), result)
            self.assertTrue(opened(later)["head_policy"]["active"])
            self.assertFalse(actual.store.local_view().active)
            with self.assertRaises(opening.OpeningRefused):
                opened((actual.query(), later[1]))

    def test_coherent_truncated_absence_opens_own_heads_but_refuses_retained_pending_witness(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            material = actual.material()
            material.update(operations=[], effects=[], events=[])
            later = select_material(earlier[0], material), wire(material)
            self.assertEqual(opened(later)["observation"], "absent")
            with self.assertRaises(prefix.PrefixRefused):
                describe(earlier, later)
            self.assertEqual(actual.store.local_view().charged_operations, 1)

    def test_lost_completed_effect_opens_as_pending_but_refuses_retained_completion(self):
        with scenario("completed") as actual:
            earlier = capture(actual)
            material = actual.material()
            material["operations"][0]["effect_sequence"] = None
            material["effects"] = []
            material["events"] = material["events"][:1]
            later = select_material(earlier[0], material), wire(material)
            self.assertEqual(opened(later)["observation"], "pending")
            with self.assertRaises(prefix.PrefixRefused):
                describe(earlier, later)
            self.assertEqual(actual.store.local_view().synthetic_effects, 1)

    def test_same_length_divergent_mode_histories_each_open_but_are_not_prefixes(self):
        with scenario("mode_round_trip_pending") as actual:
            earlier = capture(actual)
            material = actual.material()
            material["events"][1]["detail"] = "ambiguous"
            later = select_material(earlier[0], material), wire(material)
            self.assertEqual(opened(earlier)["observation"], opened(later)["observation"])
            self.assertEqual(len(actual.material()["events"]), len(material["events"]))
            for first, second in ((earlier, later), (later, earlier)):
                with self.assertRaises(prefix.PrefixRefused):
                    describe(first, second)

    def test_two_actual_source_forks_both_extend_one_prior_witness_without_canonicality(self):
        with scenario("pending") as actual, tempfile.TemporaryDirectory(prefix="synthetic-prefix-forks-") as directory:
            earlier = capture(actual)
            actual.store.close()
            retained = actual.path.read_bytes()
            forks = []
            try:
                for index in range(2):
                    fork = copy.copy(actual)
                    fork.path = Path(directory)/("branch-"+str(index)+".sqlite3")
                    fork.path.write_bytes(retained)
                    fork.store = local.OfflinePolicyEffectStore(str(fork.path), fork.labels)
                    forks.append(fork)
                forks[0].store.apply_synthetic_effect(forks[0].original)
                forks[1].store.replace_local_policy(0, forks[1].profile, active=False)
                completed, revoked = (capture(fork) for fork in forks)
                self.assertEqual(describe(earlier, completed).later_observation, "completed")
                self.assertEqual(describe(earlier, revoked).later_observation, "pending")
                self.assertFalse(opened(revoked)["head_policy"]["active"])
                for first, second in ((completed, revoked), (revoked, completed)):
                    with self.assertRaises(prefix.PrefixRefused):
                        describe(first, second)
            finally:
                for fork in forks:
                    fork.store.close()

    def test_same_events_can_hide_different_other_original_proposals_on_two_futures(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            other = replace(actual.original, operation_id_hex="10"*32, proposal_digest_hex="11"*32)
            actual.store.allocate_synthetic(other)
            first = capture(actual)
            material = actual.material()
            material["operations"][1]["original_operation"]["proposal_digest_hex"] = "12"*32
            second = select_material(first[0], material), wire(material)
            self.assertEqual(json.loads(first[1])["record_material"]["events"], material["events"])
            self.assertEqual(describe(earlier, first).appended_originals, 1)
            self.assertEqual(describe(earlier, second).appended_originals, 1)
            self.assertEqual(opened(first)["original_record"], opened(second)["original_record"])
            with self.assertRaises(prefix.PrefixRefused):
                describe(first, second)

    def test_rewriting_nonqueried_retained_proposal_refuses_even_with_identical_event_prefix(self):
        with scenario("pending") as actual:
            other = replace(actual.original, operation_id_hex="10"*32, proposal_digest_hex="11"*32)
            actual.store.allocate_synthetic(other)
            earlier = capture(actual)
            actual.store.apply_synthetic_effect(actual.original)
            material = actual.material()
            material["operations"][1]["original_operation"]["proposal_digest_hex"] = "12"*32
            later = select_material(actual.query(), material), wire(material)
            self.assertEqual(opened(later)["observation"], "completed")
            self.assertEqual(json.loads(earlier[1])["record_material"]["events"], material["events"][:2])
            with self.assertRaises(prefix.PrefixRefused):
                describe(earlier, later)

    def test_rewriting_old_policy_row_refuses_even_when_events_and_current_root_match(self):
        with scenario("initial_absent") as actual:
            actual.store.replace_local_policy(0, actual.profile, active=True)
            selected = replace(actual.original, expected_revision=1)
            earlier = capture(actual, original=selected)
            material = actual.material()
            historical = json.loads(actual.profile)
            historical["authority_epoch"] += 1
            material["policies"][0]["profile_hex"] = canonical(historical).hex()
            later = select_material(earlier[0], material), wire(material)
            self.assertEqual(opened(later)["observation"], "absent")
            self.assertEqual(json.loads(earlier[1])["record_material"]["events"], material["events"])
            with self.assertRaises(prefix.PrefixRefused):
                describe(earlier, later)

    def test_distinct_complete_original_queries_refuse_even_when_both_are_absent(self):
        with scenario("initial_absent") as actual:
            actual.store.replace_local_policy(0, actual.profile, active=True)
            earlier = capture(actual)
            alternatives = (replace(actual.original, operation_id_hex="10"*32),
                replace(actual.original, proposal_digest_hex="11"*32),
                replace(actual.original, expected_revision=1))
            for original in alternatives:
                with self.subTest(original=original.operation_id_hex, revision=original.expected_revision):
                    later = capture(actual, original=original)
                    self.assertEqual(opened(later)["observation"], "absent")
                    with self.assertRaises(prefix.PrefixRefused):
                        describe(earlier, later)
            material = actual.material()
            historical = json.loads(actual.profile)
            historical["authority_epoch"] += 1
            material["policies"][0]["profile_hex"] = canonical(historical).hex()
            changed_original = reads.original_operation(operation_id_hex=actual.original.operation_id_hex,
                expected_revision=0, profile_wire=canonical(historical), proposal_digest_hex=actual.original.proposal_digest_hex)
            query = reads.original_read_query(actual.root, changed_original,
                checkpoint=earlier[0]._checkpoint, record_checkpoint=earlier[0]._record_checkpoint,
                challenge_hex=earlier[0]._challenge)
            later = select_material(query, material), wire(material)
            self.assertEqual(opened(later)["observation"], "absent")
            with self.assertRaises(prefix.PrefixRefused):
                describe(earlier, later)

    def test_complete_root_source_and_incarnation_changes_refuse_despite_matching_key_labels(self):
        with scenario("initial_absent") as actual:
            earlier = capture(actual)
            original = actual.root.as_dict()
            variants = []
            changed = copy.deepcopy(original)
            changed["declaration_revision"] += 1
            variants.append(changed)
            for field in ("source_id_hex", "source_incarnation_hex", "source_profile_digest_hex"):
                changed = copy.deepcopy(original)
                changed["source_context"][field] = "ff"*32
                variants.append(changed)
            changed = copy.deepcopy(original)
            keys = changed["delegated_keys"]
            keys["policy_admin_key_hex"], keys["governor_issuer_key_hex"] = keys["governor_issuer_key_hex"], keys["policy_admin_key_hex"]
            variants.append(changed)
            changed = copy.deepcopy(original)
            keys, context = changed["delegated_keys"], changed["source_context"]
            keys["source_response_key_hex"], context["provisioning_root_key_hex"] = context["provisioning_root_key_hex"], keys["source_response_key_hex"]
            variants.append(changed)
            for index, declaration in enumerate(variants):
                with self.subTest(index=index):
                    root = root_from(declaration)
                    material = actual.material()
                    material["root_declaration"] = declaration
                    query = reads.original_read_query(root, earlier[0]._original,
                        checkpoint=earlier[0]._checkpoint, record_checkpoint=earlier[0]._record_checkpoint,
                        challenge_hex=earlier[0]._challenge)
                    later = select_material(query, material), wire(material)
                    self.assertEqual(opened(later)["observation"], "absent")
                    with self.assertRaises(prefix.PrefixRefused):
                        describe(earlier, later)

    def test_actual_current_profile_replacement_is_explicitly_outside_prefix_scope(self):
        with scenario("completed") as actual:
            earlier = capture(actual)
            fixture = json.loads(INPUT.read_text("ascii"))["positive_vectors"]["replaced_completed"]
            declaration = fixture["root_declaration"]
            actual.root = root_from(declaration)
            actual.store.replace_local_policy(0, canonical(declaration["governor_profile"]), active=False)
            later = capture(actual)
            self.assertEqual(opened(later)["original_record"], opened(earlier)["original_record"])
            with self.assertRaises(prefix.PrefixRefused):
                describe(earlier, later)

    def test_incoming_claims_permission_flags_and_signature_envelopes_cannot_supply_expectations(self):
        with scenario("pending") as actual:
            pair = capture(actual)
            packet = json.loads(pair[1])
            for key, value in (("claim", opened(pair)), ("root_signature_valid", True),
                               ("response_signature_valid", True), ("current", True), ("authorized", True)):
                altered = copy.deepcopy(packet)
                altered[key] = value
                for earlier, later in (((pair[0], canonical(altered)), pair), (pair, (pair[0], canonical(altered)))):
                    with self.assertRaises(prefix.PrefixRefused):
                        describe(earlier, later)
            public = json.loads(OUTPUT.read_text("ascii"))["positive_vectors"]["pending"]["envelope"]
            with self.assertRaises(prefix.PrefixRefused):
                describe(pair, (pair[0], canonical(public)))

    def test_both_openings_require_their_complete_independent_heads(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            actual.store.apply_synthetic_effect(actual.original)
            later = capture(actual)
            for first, second in (((later[0], earlier[1]), later), (earlier, (earlier[0], later[1]))):
                with self.assertRaises(prefix.PrefixRefused):
                    describe(first, second)
            for pair in (earlier, later):
                query = pair[0]
                bad_policy = reads.original_read_query(query._root, query._original,
                    checkpoint=current.PolicyCheckpoint(query._checkpoint.revision, "00"*32),
                    record_checkpoint=query._record_checkpoint, challenge_hex=query._challenge)
                bad_record = reads.original_read_query(query._root, query._original,
                    checkpoint=query._checkpoint,
                    record_checkpoint=reads.RecordCheckpoint(query._record_checkpoint.event_sequence, "00"*32),
                    challenge_hex=query._challenge)
                for changed in (bad_policy, bad_record):
                    for first, second in (((changed, pair[1]), pair), (pair, (changed, pair[1]))):
                        with self.assertRaises(prefix.PrefixRefused):
                            describe(first, second)

    def test_inconsistent_retained_rows_cannot_bypass_complete_opening_on_either_side(self):
        with scenario("completed") as actual:
            pair = capture(actual)
            for table in ("operations", "effects", "events", "policies"):
                changed = actual.material()
                changed[table] = []
                malformed = select_material(pair[0], changed), wire(changed)
                for first, second in ((malformed, pair), (pair, malformed)):
                    with self.subTest(table=table), self.assertRaises(prefix.PrefixRefused):
                        describe(first, second)

    def test_noncanonical_depth_number_and_wire_bounds_remain_stage51_requirements(self):
        with scenario("pending") as actual:
            pair = capture(actual)
            variants = (pair[1]+b"\n", b" "+pair[1], b"", b" "*(opening.MAX_WIRE_BYTES+1),
                pair[1].replace(b'"revision":0', b'"revision":0.0', 1),
                pair[1].replace(b'"revision":0', b'"revision":'+b"9"*5000, 1),
                pair[1].replace(b'"purpose":', b'"purpose":"x","purpose":', 1),
                b"["*1000+b"0"+b"]"*1000, b'{"schema":NaN}')
            for index, value in enumerate(variants):
                for first, second in (((pair[0], value), pair), (pair, (pair[0], value))):
                    with self.subTest(index=index), self.assertRaises(prefix.PrefixRefused):
                        describe(first, second)

    def test_exact_query_and_wire_guards_refuse_subclass_hooks_before_any_opening(self):
        class QueryHook(reads.OriginalReadQuery):
            @property
            def canonical_bytes(self):
                raise AssertionError("query hook reached")
            def as_dict(self):
                raise AssertionError("query hook reached")
        class WireHook(bytes):
            def decode(self, *args, **kwargs):
                raise AssertionError("wire hook reached")
        with scenario("pending") as actual:
            pair = capture(actual)
            with patch.object(opening, "derive_claim", side_effect=AssertionError("opening reached")):
                for value in (None, {}, object.__new__(QueryHook)):
                    for args in ((value, pair[1], *pair), (*pair, value, pair[1])):
                        with self.assertRaises(prefix.PrefixRefused):
                            prefix.compare_openings(*args)
                for value in (bytearray(pair[1]), pair[1].decode("ascii"), WireHook(pair[1])):
                    for args in ((pair[0], value, *pair), (*pair, pair[0], value)):
                        with self.assertRaises(prefix.PrefixRefused):
                            prefix.compare_openings(*args)

    def test_damaged_exact_queries_refuse_without_leaking_synthetic_tuple_or_material(self):
        with scenario("pending") as actual:
            pair = capture(actual)
            changed = copy.copy(pair[0])
            object.__setattr__(changed, "_wire", b'{"private_test_marker":true}')
            for args in ((changed, pair[1], *pair), (*pair, changed, pair[1])):
                with self.assertRaises(prefix.PrefixRefused) as caught:
                    prefix.compare_openings(*args)
                self.assertEqual(str(caught.exception), "synthetic retained-prefix comparison refused")
                self.assertIsNone(caught.exception.__cause__)

    def test_frozen_description_and_defensive_dictionary_contain_no_permission_or_signature_fact(self):
        with scenario("pending") as actual:
            result = describe(capture(actual), capture(actual))
            self.assertIs(type(result), prefix.PrefixDescription)
            with self.assertRaises(FrozenInstanceError):
                result.relation = "current"
            retained = result.as_dict()
            retained["earlier"]["event_sequence"] = 0
            retained["retained_originals"] = 0
            self.assertEqual(result.as_dict()["earlier"]["event_sequence"], 1)
            self.assertEqual(result.retained_originals, 1)
            self.assertEqual(result.as_dict()["purpose"], prefix.PURPOSE)
            self.assertFalse(any(key in result.as_dict() for key in
                ("authorized", "current", "recovered", "root_signature_valid", "response_signature_valid")))

    def test_actual_coherent_consumer_and_source_restore_can_repeat_same_completed_history(self):
        with scenario("pending") as actual:
            prior = capture(actual)
            actual.store.close()
            retained = actual.path.read_bytes()
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            first_effect = actual.store.apply_synthetic_effect(actual.original).effect_sequence
            completed = capture(actual)
            self.assertEqual(describe(prior, completed).appended_effects, 1)
            actual.store.close()
            actual.path.write_bytes(retained)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            restored = capture(actual)
            with self.assertRaises(prefix.PrefixRefused):
                describe(completed, restored)
            self.assertEqual(describe(prior, restored).relation, "same-history")
            second_effect = actual.store.apply_synthetic_effect(actual.original).effect_sequence
            repeated = capture(actual)
            self.assertEqual(describe(restored, repeated).appended_effects, 1)
            self.assertEqual(describe(completed, repeated).relation, "same-history")
            self.assertEqual((first_effect, second_effect), (2, 2))
            self.assertEqual(actual.store.local_view().charged_operations, 1)

    def test_actual_revision32_extension_keeps_every_policy_row_and_original_charge(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            for revision in range(32):
                actual.store.replace_local_policy(revision, actual.profile, active=True)
            later = capture(actual)
            result = describe(earlier, later)
            self.assertEqual((result.later_revision, result.later_event_sequence), (32, 33))
            self.assertEqual((len(actual.material()["policies"]), result.retained_originals), (33, 1))
            self.assertEqual(opened(later)["original_record"]["charge_sequence"], 1)

    def test_actual_maximum_complete_extension_fits_unchanged_opening_bounds(self):
        with scenario("initial_absent") as actual:
            actual.store.close()
            actual.path.unlink()
            declaration = actual.root.as_dict()
            declaration["governor_profile"].update(max_attempt_limit=64, max_target_limit=64)
            actual.root = root_from(declaration)
            actual.profile = canonical(declaration["governor_profile"])
            actual.original = replace(actual.original, operation_id_hex=format(1, "064x"), profile_wire=actual.profile)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels, initial_profile=actual.profile)
            earlier = capture(actual)
            for index in range(1, 65):
                original = replace(actual.original, operation_id_hex=format(index, "064x"))
                actual.store.allocate_synthetic(original)
                actual.store.apply_synthetic_effect(original)
            for _ in range(64):
                actual.store.set_local_source_mode("unavailable")
                actual.store.set_local_source_mode("live")
            later = capture(actual)
            self.assertLessEqual(len(later[1]), opening.MAX_WIRE_BYTES)
            result = describe(earlier, later)
            self.assertEqual((result.later_event_sequence, result.appended_originals, result.appended_effects), (256, 64, 64))
            self.assertEqual(result.later_observation, "completed")
            self.assertEqual(actual.store.local_view().charged_operations, 64)

    def test_all_six_unchanged_signed_counterclaims_keep_their_separate_truth_boundary(self):
        public = json.loads(OUTPUT.read_text("ascii"))["counterclaim_vectors"]
        refused = {"same_id_other_proposal", "same_id_other_historical_profile"}
        false_state = {"false_absence_at_pending_head", "false_completion_at_two_charge_head", "false_active_at_revoked_head"}
        self.assertEqual(len(public), 6)
        for name, vector in public.items():
            with self.subTest(name=name), scenario(vector["actual_scenario"]) as actual:
                query = responses._prepared(actual.root.as_dict(), vector["response"]["query"])
                pair = query, wire(actual.material())
                self.assertTrue(vector["result"]["root_signature_valid"])
                self.assertTrue(vector["result"]["response_signature_valid"])
                if name in refused:
                    with self.assertRaises(prefix.PrefixRefused):
                        describe(pair, pair)
                else:
                    result = describe(pair, pair)
                    self.assertEqual(result.relation, "same-history")
                    if name in false_state:
                        self.assertNotEqual(opened(pair), vector["response"]["claim"])
                    else:
                        self.assertEqual(result.later_observation, "absent")
                        actual.store.allocate_synthetic(actual.original)
                        self.assertEqual(describe(pair, pair), result)

    def test_helper_has_no_io_source_provider_crypto_signer_or_application_adapter(self):
        path = Path("tests/original_snapshot_prefix.py")
        tree = ast.parse(path.read_text("ascii"))
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imports.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertEqual(imports, {"dataclasses", "qualification", "original_snapshot_opening"})
        calls = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertFalse(calls & {"open", "eval", "exec", "compile", "__import__", "input"})
        attributes = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(attributes & {"read_bytes", "write_bytes", "read_text", "write_text", "execute", "sign", "verify", "allocate_synthetic", "apply_synthetic_effect"})
        self.assertEqual(hashlib.sha256(INPUT.read_bytes()).hexdigest(), "0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01")
        self.assertEqual(hashlib.sha256(OUTPUT.read_bytes()).hexdigest(), "2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb")


if __name__ == "__main__":
    unittest.main()
