"""Selected finite source, freshness, clone and restore counterexamples."""

import subprocess
import sys
import unittest

from scripts import model_nom_authority as model


class NoMAuthorityModelTests(unittest.TestCase):
    def test_selected_domain_is_exact_and_complete_for_each_policy(self):
        for policy in model.POLICIES:
            result = model.compare(policy)
            self.assertTrue(result["complete"])
            self.assertEqual((result["selected_schedules"], result["executed_schedules"], result["transitions"]), (72, 72, 334))
            self.assertEqual((result["recovery_action"], result["application"], result["core"]), ("NONE", "NO-GO", "NO-GO"))

    def test_ideal_atomic_entry_is_conditional_and_has_no_selected_counterexample(self):
        result = model.compare("ideal-atomic-entry")
        self.assertEqual((result["unsafe_entries"], result["repeated_effect_schedules"], result["counterexamples"]), (0, 0, []))
        # Twelve entries precede updates; a benign update before the read also
        # permits one current entry, twenty copy shuffles deduplicate, and two
        # unknown-result schedules retain their first entry.
        self.assertEqual(result["abstract_effects"], 35)
        self.assertEqual(result["external_facts"], "IDEAL_PREMISE")
        self.assertEqual(result["nonrollback_ledger_and_fence"], "IDEAL_PREMISE")
        self.assertEqual(result["signature_mathematics"], "NOT_PERFORMED")

    def test_cached_and_split_checks_have_stale_entry_counterexamples(self):
        for policy in ("cached-claim", "check-before-entry"):
            result = model.compare(policy)
            self.assertGreater(result["unsafe_entries"], 0)
            names = {row["scenario"] for row in result["counterexamples"]}
            self.assertIn("update-live_funding_entry", names)
            self.assertIn("update-network_profile", names)
            self.assertIn("update-recipient_receipt", names)

    def test_every_required_fact_is_rechecked_at_abstract_entry(self):
        for fact in model.OBLIGATIONS:
            events = ((0, "read", None), (0, "check", None), (0, "advance", fact), (0, "enter", None))
            ideal, trace = model.run_schedule("ideal-atomic-entry", events)
            split, unused = model.run_schedule("check-before-entry", events)
            self.assertEqual((ideal.effects, trace[-1]), (0, "REFUSED"))
            self.assertEqual((split.effects, split.unsafe_entries), (1, 1))

    def test_even_benign_extension_requires_current_position_recheck(self):
        events = ((0, "read", None), (0, "check", None), (0, "advance", "benign_extension"), (0, "enter", None))
        world, trace = model.run_schedule("ideal-atomic-entry", events)
        self.assertTrue(all(world.facts))
        self.assertEqual((world.effects, trace[-1]), (0, "REFUSED"))

    def test_update_after_entry_does_not_rewrite_the_prior_entry_verdict(self):
        events = ((0, "read", None), (0, "check", None), (0, "enter", None), (0, "advance", "live_funding_entry"))
        world, unused = model.run_schedule("ideal-atomic-entry", events)
        self.assertEqual((world.effects, world.unsafe_entries), (1, 0))

    def test_current_reread_after_extension_is_a_separate_abstract_premise(self):
        events = ((0, "advance", "benign_extension"), (0, "read", None), (0, "check", None), (0, "enter", None))
        world, trace = model.run_schedule("ideal-atomic-entry", events)
        self.assertEqual((world.effects, trace[-1]), (1, "ABSTRACT_ENTRY_COMPLETE"))

    def test_source_restore_fools_rollbackable_atomic_check(self):
        label, events = next(row for row in model.schedules() if row[0] == "source-restore")
        ideal, unused = model.run_schedule("ideal-atomic-entry", events)
        rollback, unused = model.run_schedule("rollbackable-atomic-entry", events)
        self.assertEqual((ideal.effects, rollback.effects, rollback.unsafe_entries), (0, 1, 1))

    def test_consumer_restore_after_read_defeats_split_use(self):
        label, events = next(row for row in model.schedules() if row[0] == "consumer-restore-before-entry")
        ideal, unused = model.run_schedule("ideal-atomic-entry", events)
        split, unused = model.run_schedule("check-before-entry", events)
        self.assertEqual((ideal.effects, split.effects, split.unsafe_entries), (0, 1, 1))

    def test_restore_cannot_erase_ideal_unknown_but_rollbackable_copy_repeats_effect(self):
        label, events = next(row for row in model.schedules() if row[0] == "consumer-restore-after-unknown")
        ideal, trace = model.run_schedule("ideal-atomic-entry", events)
        rollback, unused = model.run_schedule("rollbackable-atomic-entry", events)
        self.assertEqual((ideal.effects, ideal.unknown_replays, trace[-1]), (1, 1, "RETAINED_UNKNOWN"))
        self.assertEqual(rollback.effects, 2)

    def test_all_twenty_copy_shuffles_share_only_the_ideal_external_ledger(self):
        rows = [events for label, events in model.schedules() if label == "independent-copies"]
        self.assertEqual(len(rows), 20)
        for events in rows:
            ideal, unused = model.run_schedule("ideal-atomic-entry", events)
            local, unused = model.run_schedule("rollbackable-atomic-entry", events)
            self.assertEqual((ideal.effects, local.effects), (1, 2))

    def test_unknown_result_replay_has_no_new_entry_for_each_policy(self):
        label, events = next(row for row in model.schedules() if row[0] == "lost-result-exact-replay")
        for policy in model.POLICIES:
            world, trace = model.run_schedule(policy, events)
            self.assertEqual((world.effects, world.unknown_replays, trace[-1]), (1, 1, "RETAINED_UNKNOWN"))

    def test_schedule_cap_zero_and_partial_never_report_completion(self):
        for cap in (0, 1, 71):
            result = model.compare("ideal-atomic-entry", schedule_limit=cap)
            self.assertFalse(result["complete"])
            self.assertEqual(result["executed_schedules"], cap)
        self.assertTrue(model.compare("ideal-atomic-entry", schedule_limit=72)["complete"])

    def test_invalid_selections_are_refused(self):
        for bad in (-1, True, "2", 2.0):
            with self.assertRaises(ValueError):
                model.compare("ideal-atomic-entry", schedule_limit=bad)
        with self.assertRaises(ValueError):
            model.compare("unsupported")

    def test_incomplete_cli_returns_exit_two(self):
        result = subprocess.run([sys.executable, "-B", "-m", "scripts.model_nom_authority", "--schedule-limit", "0"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn('"complete":false', result.stdout)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
