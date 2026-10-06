#!/usr/bin/env python3
"""Test-only signed retained histories, forks and copied-witness limits."""

import argparse
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[1]/"tests")]
from qualification import original_read_response as response
from qualification import policy_effect_store as local
from qualification.original_read_response_verifier import PublicOriginalResponseCheck
from original_snapshot_vectors import OUTPUT, canonical, scenario, selected
import original_snapshot_opening as opening
import original_snapshot_prefix as prefix
import original_snapshot_prefix_response as composition


def capture(actual, **selection):
    return actual.query(**selection), canonical(dict(schema=opening.SCHEMA,
        purpose=opening.PURPOSE, record_material=actual.material()))


def compare(earlier, later, earlier_vector, later_vector, *, verifier):
    return composition.compare_public_responses(*earlier, canonical(earlier_vector["envelope"]),
        *later, canonical(later_vector["envelope"]), verifier=verifier)


def counter_query(actual, name):
    """Independent synthetic query controls, not packet-selected expectations."""
    original, challenge = actual.original, "03"
    if name == "same_id_other_proposal":
        original = replace(original, proposal_digest_hex="06"*32)
    elif name == "same_id_other_historical_profile":
        profile = json.loads(original.profile_wire.decode("ascii"))
        profile["authority_epoch"] += 1
        original = replace(original, profile_wire=canonical(profile))
    elif name == "fresh_challenge_over_initial_absence":
        challenge = "07"
    return capture(actual, challenge=challenge, original=original)


class RealOriginalSnapshotPrefixResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(OUTPUT.read_text("ascii"))

    def positive(self, name):
        return self.fixture["positive_vectors"][name]

    def refuse_before_check(self, earlier, later, earlier_vector, later_vector):
        calls = []
        def check(packet):
            calls.append(packet)
            return self.check(packet)
        with self.assertRaises(composition.PrefixResponseRefused):
            compare(earlier, later, earlier_vector, later_vector, verifier=check)
        self.assertEqual(calls, [])

    def test_actual_nine_live_signed_openings_derive_expectations_without_store_mutation(self):
        for name, vector in self.fixture["positive_vectors"].items():
            if name == "unavailable_pending":
                continue
            with self.subTest(name=name), scenario(name) as actual:
                pair = capture(actual)
                before = actual.path.read_bytes(), actual.store.local_view()
                claim = opening.derive_claim(*pair)
                expected = response.original_read_response(actual.root, pair[0], claim)
                self.assertEqual(expected.as_dict(), vector["response"])
                result = compare(pair, pair, vector, vector, verifier=self.check)
                self.assertEqual(result, prefix.compare_openings(*pair, *pair))
                self.assertEqual(result.relation, "same-history")
                self.assertEqual((actual.path.read_bytes(), actual.store.local_view()), before)

    def test_actual_signed_absent_pending_completed_chain_and_reverse_refusals(self):
        with scenario("initial_absent") as actual:
            absent = capture(actual)
            actual.store.allocate_synthetic(actual.original)
            pending = capture(actual)
            actual.store.apply_synthetic_effect(actual.original)
            completed = capture(actual)
            pairs = ((absent, pending, "initial_absent", "pending"),
                (pending, completed, "pending", "completed"),
                (absent, completed, "initial_absent", "completed"))
            for earlier, later, old_name, new_name in pairs:
                with self.subTest(transition=(old_name, new_name)):
                    result = compare(earlier, later, self.positive(old_name), self.positive(new_name), verifier=self.check)
                    self.assertEqual(result.relation, "retained-extension")
                    self.refuse_before_check(later, earlier, self.positive(new_name), self.positive(old_name))
            self.assertEqual((actual.store.local_view().charged_operations,
                actual.store.local_view().synthetic_effects), (1, 1))

    def test_actual_two_signed_fork_futures_extend_same_pending_but_not_each_other(self):
        with scenario("pending") as actual:
            pending = capture(actual)
            actual.store.close()
            cloned = actual.path.with_name("fork.sqlite3")
            shutil.copyfile(actual.path, cloned)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            actual.store.apply_synthetic_effect(actual.original)
            completed = capture(actual)
            with local.OfflinePolicyEffectStore(str(cloned), actual.labels) as fork:
                fork.replace_local_policy(0, actual.profile, active=False)
                original_store = actual.store
                try:
                    actual.store = fork
                    revoked = capture(actual)
                finally:
                    actual.store = original_store
                with self.assertRaises(local.StoreRefused):
                    fork.apply_synthetic_effect(actual.original)
                self.assertEqual((fork.local_view().charged_operations, fork.local_view().synthetic_effects), (1, 0))
            for later, name in ((completed, "completed"), (revoked, "revoked_pending")):
                result = compare(pending, later, self.positive("pending"), self.positive(name), verifier=self.check)
                self.assertEqual((result.relation, result.retained_originals), ("retained-extension", 1))
            self.refuse_before_check(completed, revoked, self.positive("completed"), self.positive("revoked_pending"))
            self.refuse_before_check(revoked, completed, self.positive("revoked_pending"), self.positive("completed"))
            self.assertEqual(actual.store.local_view().synthetic_effects, 1)

    def test_actual_three_validly_signed_false_states_refuse_independently_derived_claims(self):
        for name, vector in self.fixture["counterclaim_vectors"].items():
            if not name.startswith("false_"):
                continue
            with self.subTest(name=name), scenario(vector["actual_scenario"]) as actual:
                unsafe = selected(vector)  # Explicit packet-selected mathematics control only.
                self.assertIs(response.verify_selected_response(unsafe, canonical(vector["envelope"]), verifier=self.check), unsafe)
                pair = counter_query(actual, name)
                self.assertNotEqual(opening.derive_claim(*pair).as_dict(), vector["response"]["claim"])
                self.refuse_before_check(pair, pair, self.positive(vector["actual_scenario"]), vector)

    def test_actual_two_signed_tuple_collisions_cannot_open_complete_retained_original(self):
        for name in ("same_id_other_proposal", "same_id_other_historical_profile"):
            vector = self.fixture["counterclaim_vectors"][name]
            with self.subTest(name=name), scenario(vector["actual_scenario"]) as actual:
                unsafe = selected(vector)  # Explicit packet-selected mathematics control only.
                self.assertIs(response.verify_selected_response(unsafe, canonical(vector["envelope"]), verifier=self.check), unsafe)
                collision = counter_query(actual, name)
                self.assertEqual(collision[0].as_dict(), vector["response"]["query"])
                with self.assertRaises(opening.OpeningRefused):
                    opening.derive_claim(*collision)
                self.refuse_before_check(collision, collision, vector, vector)

    def test_actual_fresh_challenge_signed_old_absence_remains_history_after_charge(self):
        with scenario("initial_absent") as actual:
            old = capture(actual)
            fresh = capture(actual, challenge="07")
            old_vector = self.positive("initial_absent")
            fresh_vector = self.fixture["counterclaim_vectors"]["fresh_challenge_over_initial_absence"]
            before = compare(old, fresh, old_vector, fresh_vector, verifier=self.check)
            actual.store.allocate_synthetic(actual.original)
            pending = capture(actual)
            self.assertEqual(compare(old, fresh, old_vector, fresh_vector, verifier=self.check), before)
            self.assertEqual((before.relation, before.later_observation), ("same-history", "absent"))
            self.assertNotEqual(before.earlier_query_digest_hex, before.later_query_digest_hex)
            self.refuse_before_check(pending, fresh, self.positive("pending"), fresh_vector)
            self.assertEqual(actual.store.local_view().charged_operations, 1)

    def test_actual_signed_unavailable_nulls_are_not_complete_live_openings(self):
        with scenario("pending") as actual:
            live = capture(actual)
            actual.store.set_local_source_mode("unavailable")
            unavailable = capture(actual)
            vector = self.positive("unavailable_pending")
            expected = actual.response(unavailable[0])
            self.assertIs(response.verify_selected_response(expected, canonical(vector["envelope"]), verifier=self.check), expected)
            claim = expected.as_dict()["claim"]
            self.assertTrue(all(claim[k] is None for k in
                ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record")))
            self.refuse_before_check(live, unavailable, self.positive("pending"), vector)
            self.refuse_before_check(unavailable, live, vector, self.positive("pending"))
            self.assertEqual((actual.store.local_view().charged_operations, actual.store.local_view().synthetic_effects), (1, 0))

    def test_actual_valid_signed_extension_can_age_before_delivery_without_permission(self):
        with scenario("initial_absent") as actual:
            earlier = capture(actual)
            actual.store.allocate_synthetic(actual.original)
            later = capture(actual)
            def cut(name):
                if name == "original-read-sample-after-commit":
                    with local.OfflinePolicyEffectStore(str(actual.path), actual.labels) as writer:
                        writer.replace_local_policy(0, actual.profile, active=False)
            with patch.object(actual.store, "_cut", side_effect=cut):
                historical = actual.response(later[0])
            self.assertEqual(historical.as_dict(), self.positive("pending")["response"])
            result = compare(earlier, later, self.positive("initial_absent"), self.positive("pending"), verifier=self.check)
            self.assertEqual(result.later_observation, "pending")
            self.assertFalse(actual.store.local_view().active)
            with self.assertRaises(local.StoreRefused):
                actual.response(later[0])
            with self.assertRaises(local.StoreRefused):
                actual.store.apply_synthetic_effect(actual.original)

    def test_actual_source_and_consumer_restore_repeat_valid_signed_synthetic_effect(self):
        with scenario("pending") as actual:
            consumer_pending = capture(actual)
            actual.store.close()
            saved = actual.path.with_name("saved.sqlite3")
            shutil.copyfile(actual.path, saved)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            effects = [actual.store.apply_synthetic_effect(actual.original).effect_sequence]
            consumer_completed = capture(actual)
            before = compare(consumer_pending, consumer_completed, self.positive("pending"), self.positive("completed"), verifier=self.check)
            actual.store.close()
            shutil.copyfile(saved, actual.path)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            restored = capture(actual)
            self.refuse_before_check(consumer_completed, restored, self.positive("completed"), self.positive("pending"))
            # Restoring the old consumer witness loses knowledge of the effect.
            consumer_completed = consumer_pending
            replay = compare(consumer_completed, restored, self.positive("pending"), self.positive("pending"), verifier=self.check)
            self.assertEqual(replay.relation, "same-history")
            effects.append(actual.store.apply_synthetic_effect(actual.original).effect_sequence)
            repeated = capture(actual)
            after = compare(consumer_completed, repeated, self.positive("pending"), self.positive("completed"), verifier=self.check)
            self.assertEqual(after, before)
            self.assertEqual(effects, [2, 2])
            self.assertEqual((actual.store.local_view().charged_operations, actual.store.local_view().synthetic_effects), (1, 1))

    def test_actual_zero_signatures_on_either_side_refuse_but_forged_callback_can_pass(self):
        with scenario("pending") as actual:
            pair = capture(actual)
            valid = self.positive("pending")
            forged = copy.deepcopy(valid)
            forged["envelope"]["root_envelope"]["root_signature_hex"] = "00"*64
            forged["envelope"]["response_signature_hex"] = "00"*64
            def dishonest(packet):
                return response.expected_result(response.request_digest(packet))
            self.assertEqual(compare(pair, pair, forged, forged, verifier=dishonest).relation, "same-history")
            for earlier, later in ((forged, valid), (valid, forged)):
                with self.assertRaises(composition.PrefixResponseRefused):
                    compare(pair, pair, earlier, later, verifier=self.check)

    def test_actual_same_policy_mode_round_trip_requires_record_extension_and_bound_results(self):
        with scenario("pending") as actual:
            earlier = capture(actual)
            actual.store.set_local_source_mode("unavailable")
            actual.store.set_local_source_mode("live")
            later = capture(actual)
            self.assertEqual(earlier[0].as_dict()["expected_checkpoint"], later[0].as_dict()["expected_checkpoint"])
            self.assertNotEqual(earlier[0].as_dict()["expected_record_checkpoint"], later[0].as_dict()["expected_record_checkpoint"])
            result = compare(earlier, later, self.positive("pending"), self.positive("mode_round_trip_pending"), verifier=self.check)
            self.assertEqual((result.relation, result.later_event_sequence, result.appended_effects), ("retained-extension", 3, 0))
            cached = self.positive("pending")["result"]
            with self.assertRaises(composition.PrefixResponseRefused):
                compare(earlier, later, self.positive("pending"), self.positive("mode_round_trip_pending"), verifier=lambda _: cached)

    def test_actual_changed_worker_measurement_refuses_composed_response(self):
        with scenario("pending") as actual:
            pair = capture(actual)
            worker = actual.path.with_name("worker")
            shutil.copyfile(self.entry, worker)
            worker.chmod(0o700)
            check = PublicOriginalResponseCheck(worker.resolve(),
                expected_executable_sha256_hex=hashlib.sha256(worker.read_bytes()).hexdigest())
            worker.write_bytes(worker.read_bytes()+b"\n")
            with self.assertRaises(composition.PrefixResponseRefused):
                compare(pair, pair, self.positive("pending"), self.positive("pending"), verifier=check)


def main():
    parser = argparse.ArgumentParser(description="Offline test-only signed retained-prefix qualification")
    parser.add_argument("--original-response-verifier", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.original_response_verifier).resolve()
        RealOriginalSnapshotPrefixResponseTests.entry = entry
        RealOriginalSnapshotPrefixResponseTests.check = PublicOriginalResponseCheck(entry,
            expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
    except (OSError, ValueError, TypeError):
        parser.exit(1, "selected public original response check unavailable\n")
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RealOriginalSnapshotPrefixResponseTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
