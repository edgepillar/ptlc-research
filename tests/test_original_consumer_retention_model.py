"""Finite consumer traces pinned to unchanged synthetic openings and fixtures."""

import ast
from dataclasses import FrozenInstanceError, replace
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from scripts import model_original_consumer_retention as model
from scripts import model_original_read_provenance as statements
from qualification import policy_effect_store as local
import original_snapshot_opening as opening
import original_snapshot_prefix as prefix
from original_snapshot_vectors import INPUT, OUTPUT, SCENARIOS, canonical, scenario


def capture(actual, **selection):
    return actual.query(**selection), canonical(dict(schema=opening.SCHEMA,
        purpose=opening.PURPOSE, record_material=actual.material()))


@lru_cache(None)
def comparison(policy):
    return model.comparison(policy=policy)


def deliver(actor, selected, incoming=None):
    return model.Action("deliver", actor, selected, selected if incoming is None else incoming)


class OriginalConsumerRetentionModelTests(unittest.TestCase):
    def trace(self, actions, *, state=None, **options):
        state = state or model.State()
        for action in actions:
            state = model.step(state, action, **options)
        return state

    def test_all_eighty_one_live_relations_match_complete_owned_openings(self):
        captured = {}
        self.assertEqual(set(model.HISTORIES), set(SCENARIOS)-{"unavailable_pending"})
        for name in model.HISTORIES:
            with scenario(name) as actual:
                captured[name] = capture(actual)
                before = actual.path.read_bytes(), actual.store.local_view()
                opening.derive_claim(*captured[name])
                self.assertEqual((actual.path.read_bytes(), actual.store.local_view()), before)
        for earlier in captured:
            for later in captured:
                with self.subTest(earlier=earlier, later=later):
                    try:
                        prefix.compare_openings(*captured[earlier], *captured[later])
                        opened = True
                    except prefix.PrefixRefused:
                        opened = False
                    self.assertEqual(model.extends(earlier, later), opened)

    def test_ten_independent_selected_samples_preserve_statement_binding_and_null_refusal(self):
        fixtures = json.loads(OUTPUT.read_text("ascii"))["positive_vectors"]
        self.assertEqual(set(fixtures), set(statements.SAMPLES))
        for name, vector in fixtures.items():
            with self.subTest(name=name), scenario(name) as actual:
                self.assertEqual(actual.response().as_dict(), vector["response"])
                self.assertEqual(model.bound_read(name, name),
                    "no-live-opening" if name == "unavailable_pending" else "bound-live-read")
                if name == "unavailable_pending":
                    claim = vector["response"]["claim"]
                    self.assertTrue(all(claim[k] is None for k in
                        ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record")))

    def test_six_existing_signed_counterclaims_remain_distinct_from_independent_expectation(self):
        fixtures = json.loads(OUTPUT.read_text("ascii"))["counterclaim_vectors"]
        self.assertEqual(set(fixtures), set(statements.COUNTERS))
        for name, vector in fixtures.items():
            with self.subTest(name=name):
                self.assertTrue(vector["result"]["root_signature_valid"])
                self.assertTrue(vector["result"]["response_signature_valid"])
                base = vector["actual_scenario"]
                if name == "fresh_challenge_over_initial_absence":
                    base = "fresh:" + base
                expected = "bound-live-read" if name.startswith("fresh_challenge") else "statement-refused"
                self.assertEqual(model.bound_read(base, name), expected)
                for policy in model.POLICIES:
                    state = model.step(model.State(), deliver(0, base, name), policy=policy)
                    # The fresh old absence is bound, but cannot extend pending
                    # knowledge under either prefix policy.
                    self.assertEqual(state.deliveries[-1].accepted,
                        name.startswith("fresh_challenge") and policy == "replace-witness")

    def test_new_model_preserves_fixture_helper_and_public_worker_source_pins(self):
        for path, digest in (
            (INPUT, "0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01"),
            (OUTPUT, "2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb"),
            (Path("tests/original_snapshot_opening.py"), "e1e8cdd3f868bce2117c56f1eb2eab90bef8626b7687793b62214f0884805ff6"),
            (Path("tests/original_snapshot_prefix.py"), "20b7e00c5aef3ec28184d385d7e10098f289a6e476373ab93527deaa7664a622"),
            (Path("qualification/examples/verify_original_read_response.rs"),
                "e96a8219e500cd0f79716796c146f64ce22e5f95bd3af26ccd2ad8a208c4834e")):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_signature_premise_and_arbitrary_callback_flags_remain_different_controls(self):
        for policy in model.POLICIES:
            refused = model.step(model.State(), deliver(0, "pending", "zero-signatures"), policy=policy)
            self.assertFalse(refused.deliveries[-1].accepted)
            forged = model.step(model.State(), deliver(0, "pending", "zero-signatures"),
                                policy=policy, check="callback-flags")
            self.assertTrue(forged.deliveries[-1].accepted)
            self.assertIn("callback_flags_without_signature_mathematics",
                          model.findings(forged, policy=policy, check="callback-flags")[0])

    def test_each_consumer_retains_its_first_valid_fork_without_selecting_global_canonicality(self):
        actions = (deliver(0, "completed"), deliver(1, "revoked_pending"),
                   deliver(0, "revoked_pending"), deliver(1, "completed"))
        for policy in ("retained-prefix", "ideal-nonrollback-prefix"):
            state = self.trace(actions, policy=policy)
            self.assertEqual([d.accepted for d in state.deliveries], [True, True, False, False])
            self.assertEqual(tuple(c.witness for c in state.consumers), ("completed", "revoked_pending"))
            violations, boundaries = model.findings(state, policy=policy)
            self.assertEqual(violations, ())
            self.assertIn("separate_consumers_keep_incomparable_futures", boundaries)

    def test_real_owned_fork_futures_match_the_two_consumer_refusals(self):
        with scenario("pending") as actual:
            pending = capture(actual)
            actual.store.close()
            fork_path = actual.path.with_name("fork.sqlite3")
            shutil.copyfile(actual.path, fork_path)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            with local.OfflinePolicyEffectStore(str(fork_path), actual.labels) as fork:
                actual.store.apply_synthetic_effect(actual.original)
                completed = capture(actual)
                fork.replace_local_policy(0, actual.profile, active=False)
                old_store = actual.store
                try:
                    actual.store = fork
                    revoked = capture(actual)
                finally:
                    actual.store = old_store
                for future in (completed, revoked):
                    self.assertEqual(prefix.compare_openings(*pending, *future).relation, "retained-extension")
                for first, second in ((completed, revoked), (revoked, completed)):
                    with self.assertRaises(prefix.PrefixRefused):
                        prefix.compare_openings(*first, *second)
                with self.assertRaises(local.StoreRefused):
                    fork.apply_synthetic_effect(actual.original)
                self.assertEqual((fork.local_view().charged_operations, fork.local_view().synthetic_effects), (1, 0))
        state = self.trace((deliver(0, "completed"), deliver(1, "revoked_pending")))
        self.assertIn("separate_consumers_keep_incomparable_futures", model.findings(state)[1])

    def test_replace_witness_control_accepts_incomparable_futures_at_the_same_consumer(self):
        state = self.trace((deliver(0, "completed"), deliver(0, "revoked_pending")), policy="replace-witness")
        self.assertTrue(all(d.accepted for d in state.deliveries))
        self.assertIn("accepted_incomparable_history_after_prior_knowledge",
                      model.findings(state, policy="replace-witness")[0])

    def test_delayed_absence_and_pending_refuse_retained_completed_knowledge(self):
        for old in ("initial_absent", "fresh:initial_absent", "pending"):
            for policy in model.POLICIES:
                state = self.trace((deliver(0, "completed"), deliver(0, old)), policy=policy)
                self.assertEqual(state.deliveries[-1].accepted, policy == "replace-witness")
                self.assertEqual(state.consumers[0].witness, old if policy == "replace-witness" else "completed")

    def test_same_history_with_new_challenge_changes_query_without_implying_latest_history(self):
        state = self.trace((model.Action("revoke"), deliver(0, "fresh:pending")))
        self.assertTrue(state.deliveries[-1].accepted)
        self.assertTrue(model.extends("pending", "fresh:pending"))
        self.assertNotEqual(statements.PACKETS["pending"].query, statements.PACKETS["fresh:pending"].query)
        boundaries = model.findings(state)[1]
        self.assertIn("fresh_challenge_does_not_select_latest_history", boundaries)
        self.assertIn("historical_selection_does_not_identify_source_view", boundaries)

    def test_fresh_signed_absence_can_be_opened_after_charge_but_cannot_extend_retained_pending(self):
        with scenario("initial_absent") as actual:
            old = capture(actual, challenge="07")
            claim = opening.derive_claim(*old)
            actual.store.allocate_synthetic(actual.original)
            current = capture(actual)
            self.assertEqual(opening.derive_claim(*old), claim)
            with self.assertRaises(prefix.PrefixRefused):
                prefix.compare_openings(*current, *old)
            with self.assertRaises(local.StoreRefused):
                actual.response(old[0])
        self.assertEqual(model.bound_read("fresh:initial_absent", "fresh_challenge_over_initial_absence"), "bound-live-read")
        self.assertFalse(model.extends("pending", "fresh:initial_absent"))

    def test_consumer_restore_erases_local_completion_and_allows_old_pending_without_nonrollback_premise(self):
        actions = (deliver(0, "completed"), model.Action("restore-consumer", 0), deliver(0, "pending"))
        for policy in ("replace-witness", "retained-prefix"):
            state = self.trace(actions, policy=policy)
            self.assertTrue(state.deliveries[-1].accepted)
            self.assertEqual(state.consumers[0].witness, "pending")
            violations, boundaries = model.findings(state, policy=policy)
            self.assertIn("accepted_older_history_after_prior_knowledge", violations)
            self.assertIn("coherent_consumer_restore_can_erase_local_knowledge", boundaries)

    def test_ideal_nonrollback_witness_survives_consumer_restore_but_is_an_external_premise(self):
        state = self.trace((deliver(0, "completed"), model.Action("restore-consumer", 0), deliver(0, "pending")),
                           policy="ideal-nonrollback-prefix")
        self.assertFalse(state.deliveries[-1].accepted)
        self.assertEqual(state.consumers[0].witness, "pending")
        self.assertEqual(state.consumers[0].nonrollback_witness, "completed")
        self.assertEqual(model.findings(state, policy="ideal-nonrollback-prefix")[0], ())

    def test_restoring_one_consumer_does_not_erase_the_other_consumers_witness(self):
        state = self.trace((deliver(0, "completed"), deliver(1, "completed"),
                            model.Action("restore-consumer", 0), deliver(1, "pending")))
        self.assertEqual(tuple(c.witness for c in state.consumers), ("pending", "completed"))
        self.assertFalse(state.deliveries[-1].accepted)
        self.assertFalse(state.consumers[1].restored)

    def test_source_restore_preserves_external_effect_audit_and_does_not_roll_back_consumer_knowledge(self):
        actions = (model.Action("complete"), deliver(0, "completed"), model.Action("restore-source"), deliver(0, "pending"))
        state = self.trace(actions)
        self.assertEqual((state.source_view, state.external_synthetic_effects), ("pending", 1))
        self.assertEqual(state.consumers[0].witness, "completed")
        self.assertFalse(state.deliveries[-1].accepted)
        self.assertIn("coherent_source_restore_does_not_rewind_external_outcome", model.findings(state)[1])

    def test_real_source_restore_repeats_synthetic_effect_even_when_retained_consumer_detects_old_head(self):
        with scenario("pending") as actual:
            pending = capture(actual)
            actual.store.close()
            saved = actual.path.with_name("saved.sqlite3")
            shutil.copyfile(actual.path, saved)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            effects = [actual.store.apply_synthetic_effect(actual.original).effect_sequence]
            completed = capture(actual)
            actual.store.close()
            shutil.copyfile(saved, actual.path)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            restored = capture(actual)
            with self.assertRaises(prefix.PrefixRefused):
                prefix.compare_openings(*completed, *restored)
            self.assertEqual(prefix.compare_openings(*pending, *restored).relation, "same-history")
            effects.append(actual.store.apply_synthetic_effect(actual.original).effect_sequence)
            self.assertEqual(effects, [2, 2])
            self.assertEqual((actual.store.local_view().charged_operations, actual.store.local_view().synthetic_effects), (1, 1))
        state = self.trace((model.Action("complete"), deliver(0, "completed"), model.Action("restore-source"),
            deliver(0, "pending"), model.Action("repeat-effect")))
        self.assertFalse(state.deliveries[-1].accepted)
        self.assertEqual(state.external_synthetic_effects, 2)
        self.assertIn("same_restored_history_can_repeat_external_synthetic_effect", model.findings(state)[1])

    def test_unavailable_refuses_without_erasing_retained_witness_or_reconciling_unknown_outcome(self):
        state = self.trace((deliver(0, "completed"), model.Action("outage"), deliver(0, "unavailable_pending")))
        self.assertEqual(state.deliveries[-1].reason, "no-live-opening")
        self.assertEqual(state.consumers[0].witness, "completed")
        self.assertTrue(all(c.outcome_unknown for c in state.consumers))
        self.assertIn("signed_unavailable_has_no_live_retention_evidence", model.findings(state)[1])

    def test_mode_round_trip_same_policy_is_a_distinct_record_future_and_not_completed_extension(self):
        before, after = statements.SAMPLES["pending"], statements.SAMPLES["mode_round_trip_pending"]
        self.assertEqual(before.query.policy_head, after.query.policy_head)
        self.assertNotEqual(before.query.record_head, after.query.record_head)
        self.assertTrue(model.extends("pending", "mode_round_trip_pending"))
        self.assertFalse(model.extends("completed", "mode_round_trip_pending"))
        self.assertFalse(model.extends("mode_round_trip_pending", "completed"))

    def test_root_and_historical_profile_changes_are_not_implicit_consumer_migrations(self):
        for selected in ("replaced_completed", "reduced_pending_two_charges"):
            self.assertTrue(model.extends(selected, selected))
            self.assertFalse(model.extends("pending", selected))
            state = model.step(model.State(), deliver(0, selected))
            self.assertFalse(state.deliveries[-1].accepted)
        changed = statements.SAMPLES["replaced_completed"]
        self.assertNotEqual(changed.query.original[2], changed.claim.head_profile)
        self.assertEqual(model.bound_read("replaced_completed", "same_id_other_historical_profile"), "statement-refused")

    def test_cold_consumer_has_no_prior_witness_to_detect_a_valid_historical_first_choice(self):
        cold = model.Consumer(witness="", saved_witness="", nonrollback_witness="")
        state = model.State(source_view="completed", consumers=(cold, cold))
        after = model.step(state, deliver(0, "initial_absent"))
        self.assertTrue(after.deliveries[-1].accepted)
        self.assertEqual(after.consumers[0].witness, "initial_absent")
        self.assertIn("historical_selection_does_not_identify_source_view", model.findings(after)[1])

    def test_all_selected_schedules_have_explicit_counts_and_conditional_retention_findings(self):
        expected = {
            "replace-witness": {"accepted_older_history_after_prior_knowledge", "accepted_incomparable_history_after_prior_knowledge"},
            "retained-prefix": {"accepted_older_history_after_prior_knowledge"},
            "ideal-nonrollback-prefix": set(),
        }
        for policy in model.POLICIES:
            result = comparison(policy)
            self.assertTrue(result.complete)
            self.assertEqual((result.schedules, result.transitions), (710, 5320))
            self.assertEqual(tuple(n for _, n in result.cases), (30, 30, 560, 90))
            self.assertEqual({w.name for w in result.violations}, expected[policy])
            self.assertIn("separate_consumers_keep_incomparable_futures", {w.name for w in result.boundaries})
            self.assertIn("same_restored_history_can_repeat_external_synthetic_effect", {w.name for w in result.boundaries})

    def test_reported_counterexample_prefixes_replay_under_their_exact_policy(self):
        for policy in model.POLICIES:
            result = comparison(policy)
            for witness in result.violations + result.boundaries:
                replay = self.trace(witness.trace, policy=policy)
                self.assertEqual(replay, witness.state)
                found = model.findings(replay, policy=policy)
                self.assertIn(witness.name, found[0]+found[1])

    def test_schedule_cap_is_incomplete_including_zero_and_one_before_complete_domain(self):
        for cap in (0, 1, 30, 709):
            result = model.comparison(max_schedules=cap)
            self.assertFalse(result.complete)
            self.assertEqual((result.reason, result.schedules), ("schedule-cap", cap))
        self.assertTrue(model.comparison(max_schedules=710).complete)

    def test_cli_complete_cap_and_invalid_parameters_report_their_actual_boundary(self):
        command = [sys.executable, "-B", "-m", "scripts.model_original_consumer_retention"]
        for args, code in (([], 0), (["--max-schedules", "1"], 2), (["--max-schedules", "0"], 2)):
            run = subprocess.run(command+args, capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, code)
            data = json.loads(run.stdout)
            self.assertEqual(data["complete"], code == 0)
            self.assertFalse(data["domain"]["full_action_graph"])
            for field in ("current_authority", "global_canonical_choice", "application_permission", "recovery"):
                self.assertIs(data[field], False)
            self.assertIn("no signature mathematics", data["signature_verification"])
        bad = subprocess.run(command+["--max-schedules", "-1"], capture_output=True, text=True, check=False)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(bad.stdout, "")

    def test_invalid_exact_types_shapes_and_action_budgets_refuse_without_mutation(self):
        state = model.State()
        for bad in (replace(state, events=True), replace(state, external_synthetic_effects=True),
            replace(state, events=9), replace(state, consumers=[model.Consumer(), model.Consumer()]),
            replace(state, consumers=(model.Consumer(outcome_unknown=False), model.Consumer())),
            replace(state, consumers=(model.Consumer(witness="unavailable_pending"), model.Consumer())),
            replace(state, deliveries=(None,))):
            with self.assertRaises(ValueError):
                model.step(bad, deliver(0, "pending"))
        for action in (model.Action("deliver", True, "pending", "pending"), deliver(2, "pending"),
            deliver(0, "false_absence_at_pending_head"), model.Action("complete", 0),
            model.Action("restore-consumer", 0, "pending"), model.Action("unknown")):
            with self.assertRaises(ValueError):
                model.step(state, action)
        for cap in (True, -1, 10001, "1"):
            with self.assertRaises(ValueError):
                model.comparison(max_schedules=cap)
        exhausted = replace(state, events=8)
        with self.assertRaises(ValueError):
            model.step(exhausted, deliver(0, "pending"))
        four = self.trace(tuple(deliver(0, "pending") for _ in range(4)))
        with self.assertRaises(ValueError):
            model.step(four, deliver(0, "pending"))
        restored = model.step(state, model.Action("restore-consumer", 0))
        with self.assertRaises(ValueError):
            model.step(restored, model.Action("restore-consumer", 0))
        with self.assertRaises(ValueError):
            model.step(state, model.Action("repeat-effect"))
        self.assertEqual(state, model.State())

    def test_frozen_results_unknown_outcomes_and_pure_model_import_boundary(self):
        state = model.step(model.State(), deliver(0, "completed"))
        with self.assertRaises(FrozenInstanceError):
            state.consumers[0].witness = "pending"
        with self.assertRaises(FrozenInstanceError):
            comparison("retained-prefix").complete = False
        self.assertTrue(all(c.outcome_unknown for c in state.consumers))
        tree = ast.parse(Path("scripts/model_original_consumer_retention.py").read_text("ascii"))
        imports = {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imports.update(alias.name.split(".")[0] for node in ast.walk(tree)
                       if isinstance(node, ast.Import) for alias in node.names)
        self.assertEqual(imports, {"__future__", "argparse", "dataclasses", "json", "scripts"})
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in ("open", "eval", "exec", "__import__") for node in ast.walk(tree)))


if __name__ == "__main__":
    unittest.main()
