"""Replayable symbolic nonce counterexamples, without signer or nonce bytes."""

import ast
from dataclasses import FrozenInstanceError, replace
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_nonce_invocation as model


@lru_cache(maxsize=None)
def comparison(policy):
    return model.compare(policy=policy)


class NonceInvocationModelTests(unittest.TestCase):
    def trace(self, actions, *, policy="entry-consume", state=None):
        state = model.State() if state is None else state
        for action in actions:
            state = model.step(state, action, policy=policy)
        return state

    def prefix(self, *, policy="entry-consume", binding=0):
        return self.trace((model.Action("request", 0, binding), model.Action("claim", 0)), policy=policy)

    def refuse(self, state, action, **options):
        with self.assertRaises(ValueError):
            model.step(state, action, **options)

    def test_complete_binding_symbols_change_each_required_coordinate_separately(self):
        self.assertEqual(model.BINDING_FIELDS, ("session", "leg", "role", "key_aggregation", "tweak", "message", "nonce_round", "adaptor"))
        self.assertEqual(len(model.BINDINGS), 9)
        for index, binding in enumerate(model.BINDINGS[1:]):
            self.assertEqual(tuple(i for i, value in enumerate(binding) if value), (index,))
        self.assertEqual(model.DEFAULT_BINDINGS, (0, 6))

    def test_each_wrong_binding_refuses_before_consumption_and_nonce_work(self):
        for binding in range(1, 9):
            state = self.prefix(binding=binding)
            self.assertFalse(state.consumed)
            self.assertEqual(state.actors[0].phase, "refused")
            self.assertEqual(state.work, ())
            self.refuse(state, model.Action("work", 0))

    def test_atomic_shared_consume_allows_only_one_copied_owner(self):
        state = self.trace((model.Action("restore-copy"), model.Action("request", 0, 0),
            model.Action("request", 1, 0), model.Action("claim", 0), model.Action("claim", 1), model.Action("work", 0)))
        self.assertEqual(state.actors[1].phase, "refused")
        self.assertTrue(state.consumed)
        self.assertEqual(len(state.work), 1)
        self.assertEqual(model.findings(state), ())
        self.refuse(state, model.Action("work", 1))

    def test_restoration_before_or_after_claim_cannot_reset_shared_consume_word(self):
        for before in (True, False):
            actions = (model.Action("request", 0, 0), model.Action("claim", 0))
            actions = ((model.Action("restore-copy"),) + actions) if before else (actions + (model.Action("restore-copy"),))
            state = self.trace(actions + (model.Action("request", 1, 0), model.Action("claim", 1)))
            self.assertTrue(state.consumed)
            self.assertEqual(state.actors[1].phase, "refused")
            self.assertEqual(state.work, ())

    def test_lost_consume_reply_discards_authority_without_work_or_refund(self):
        state = self.trace((model.Action("lose", 0), model.Action("restore-copy"),
            model.Action("request", 1, 0), model.Action("claim", 1)), state=self.prefix())
        self.assertEqual(state.work, ())
        self.assertTrue(state.consumed)
        self.assertEqual(tuple(actor.phase for actor in state.actors), ("lost", "refused"))
        self.refuse(state, model.Action("claim", 0))
        self.refuse(state, model.Action("work", 0))

    def test_lost_result_preserves_irreversible_work_and_refuses_copy_recomputation(self):
        state = self.trace((model.Action("work", 0), model.Action("lose", 0),
            model.Action("restore-copy"), model.Action("request", 1, 0), model.Action("claim", 1)), state=self.prefix())
        self.assertEqual(len(state.work), 1)
        self.assertEqual(state.deliveries, ())
        self.assertEqual(state.actors[1].phase, "refused")
        self.refuse(state, model.Action("lookup", 0))
        self.refuse(state, model.Action("work", 1))

    def test_result_epoch_rejects_old_work_without_reassigning_consumed_nonce(self):
        state = self.trace((model.Action("work", 0), model.Action("restore-copy"),
            model.Action("result", 0), model.Action("request", 1, 0), model.Action("claim", 1)), state=self.prefix())
        self.assertEqual(tuple(actor.phase for actor in state.actors), ("refused", "refused"))
        self.assertEqual(len(state.work), 1)
        self.assertEqual(model.findings(state), ())

    def test_result_fence_rejects_stale_output_after_both_nonce_computations(self):
        policy = "result-fence"
        state = self.trace((model.Action("work", 0), model.Action("restore-copy"),
            model.Action("request", 1, 0), model.Action("claim", 1), model.Action("work", 1),
            model.Action("result", 0), model.Action("result", 1), model.Action("retain", 1), model.Action("release", 1)),
            state=self.prefix(policy=policy), policy=policy)
        self.assertEqual(state.actors[0].phase, "refused")
        self.assertTrue(state.consumed)
        self.assertEqual(len(state.work), 2)
        self.assertEqual(tuple(event.actor for event in state.deliveries), (1,))
        self.assertEqual(set(model.findings(state)), {"same_nonce_work_repeated", "work_before_durable_consumption"})

    def test_two_local_durable_journals_repeat_same_nonce_after_ambiguous_loss(self):
        policy = "journal-only"
        state = self.trace((model.Action("work", 0), model.Action("lose", 0),
            model.Action("restore-copy"), model.Action("request", 1, 0), model.Action("claim", 1), model.Action("work", 1)),
            state=self.prefix(policy=policy), policy=policy)
        self.assertTrue(all(event.durable_consumption_before_work for event in state.work))
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
        self.assertEqual(state.deliveries, ())

    def test_split_check_then_durable_burn_race_grants_both_callers(self):
        state = self.trace((model.Action("restore-copy"), model.Action("request", 0, 0),
            model.Action("request", 1, 0), model.Action("check", 0), model.Action("check", 1),
            model.Action("burn", 0), model.Action("burn", 1), model.Action("work", 0), model.Action("work", 1)), policy="split-entry")
        self.assertTrue(state.consumed)
        self.assertTrue(all(event.durable_consumption_before_work for event in state.work))
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))

    def test_split_check_after_other_burn_refuses_but_does_not_cover_prior_check(self):
        state = self.trace((model.Action("restore-copy"), model.Action("request", 0, 0),
            model.Action("request", 1, 0), model.Action("check", 0), model.Action("burn", 0),
            model.Action("check", 1), model.Action("work", 0)), policy="split-entry")
        self.assertEqual(state.actors[1].phase, "refused")
        self.assertEqual(model.findings(state), ())

    def test_restoring_consume_authority_keeps_audit_and_allows_second_effect(self):
        policy = "rollbackable-entry"
        first = self.trace((model.Action("work", 0),), state=self.prefix(policy=policy), policy=policy)
        restored = self.trace((model.Action("restore-copy"),), state=first, policy=policy)
        self.assertFalse(restored.consumed)
        self.assertEqual(restored.work, first.work)
        state = self.trace((model.Action("request", 1, 0), model.Action("claim", 1),
            model.Action("work", 1), model.Action("result", 0)), state=restored, policy=policy)
        self.assertEqual(state.actors[0].phase, "refused")
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))

    def test_missing_exact_binding_check_allows_each_wrong_context_before_output(self):
        for binding in range(1, 9):
            state = self.trace((model.Action("work", 0),), state=self.prefix(policy="context-unchecked", binding=binding), policy="context-unchecked")
            self.assertEqual(model.findings(state), ("work_outside_selected_binding",))
            self.assertEqual(state.deliveries, ())

    def test_delivery_before_retention_remains_violation_after_later_retention(self):
        policy = "release-before-retain"
        state = self.trace((model.Action("work", 0), model.Action("result", 0),
            model.Action("release", 0), model.Action("retain", 0), model.Action("lose", 0)), state=self.prefix(policy=policy), policy=policy)
        self.assertTrue(state.actors[0].retained)
        self.assertEqual(model.findings(state), ("output_delivered_before_retention",))
        self.assertFalse(state.deliveries[0].retained_before_delivery)

    def test_reference_policy_refuses_delivery_before_exact_output_retention(self):
        state = self.trace((model.Action("work", 0), model.Action("result", 0)), state=self.prefix())
        self.refuse(state, model.Action("release", 0))
        self.assertEqual(state.deliveries, ())
        self.assertTrue(state.consumed)

    def test_retained_output_survives_loss_and_replays_same_symbol_without_new_work(self):
        state = self.trace((model.Action("work", 0), model.Action("result", 0), model.Action("retain", 0),
            model.Action("release", 0), model.Action("lose", 0), model.Action("lookup", 0), model.Action("replay", 0)), state=self.prefix())
        self.assertEqual(len(state.work), 1)
        self.assertEqual(len(state.deliveries), 2)
        first, replay = state.deliveries
        self.assertEqual(replace(first, replay=True), replay)
        self.assertEqual(model.findings(state), ())

    def test_loss_at_each_pre_retention_cut_offers_no_lookup_or_signing_retry(self):
        actions = (model.Action("work", 0), model.Action("result", 0))
        for cut in range(3):
            state = self.trace(actions[:cut] + (model.Action("lose", 0),), state=self.prefix())
            for kind in ("lookup", "claim", "work", "result", "request"):
                action = model.Action(kind, 0, 0) if kind == "request" else model.Action(kind, 0)
                self.refuse(state, action)
            self.assertTrue(state.consumed)
            self.assertEqual(len(state.work), int(cut > 0))

    def test_return_retention_and_lookup_do_not_grant_new_nonce_work(self):
        state = self.trace((model.Action("work", 0), model.Action("result", 0),
            model.Action("retain", 0), model.Action("lose", 0), model.Action("lookup", 0)), state=self.prefix())
        for kind in ("claim", "work", "result", "retain"):
            self.refuse(state, model.Action(kind, 0))
        self.assertEqual(len(state.work), 1)

    def test_replay_requires_prior_delivery_and_cannot_be_recomputed_or_looped(self):
        state = self.trace((model.Action("work", 0), model.Action("result", 0), model.Action("retain", 0)), state=self.prefix())
        self.refuse(state, model.Action("replay", 0))
        replayed = self.trace((model.Action("release", 0), model.Action("replay", 0)), state=state)
        self.refuse(replayed, model.Action("replay", 0))
        self.refuse(replayed, model.Action("release", 0))
        self.assertEqual(len(replayed.work), 1)

    def test_audit_invariants_do_not_depend_on_consume_flags_or_current_acceptance(self):
        work = (model.Work(0, 0, 0, 0, True), model.Work(1, 0, 0, 1, True))
        for consumed in (True, False):
            state = model.State(epoch=1, consumed=consumed, work=work)
            self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
        delivery = model.Delivery(0, 0, 1, 0, True, True)
        names = model.findings(model.State(work=(work[0],), deliveries=(delivery,)))
        self.assertEqual(set(names), {"delivery_without_same_work_output", "replay_without_same_retained_output"})

    def test_all_selected_finite_graphs_complete_and_controls_find_distinct_failures(self):
        expected = {
            "entry-consume": set(), "journal-only": {"same_nonce_work_repeated"},
            "result-fence": {"work_before_durable_consumption", "same_nonce_work_repeated"},
            "split-entry": {"same_nonce_work_repeated"}, "rollbackable-entry": {"same_nonce_work_repeated"},
            "context-unchecked": {"work_outside_selected_binding"},
            "release-before-retain": {"output_delivered_before_retention"},
        }
        for policy, names in expected.items():
            report = comparison(policy)
            self.assertTrue(report.complete)
            self.assertEqual(report.reason, "finite-graph-exhausted")
            self.assertEqual({w.name for w in report.witnesses}, names)
            self.assertEqual(report.status, "counterexample" if names else "conditional-no-counterexample")

    def test_every_shortest_counterexample_replays_to_exact_reported_audit(self):
        count = 0
        for policy in model.POLICIES:
            for witness in comparison(policy).witnesses:
                final = self.trace(witness.trace, policy=policy)
                self.assertEqual(final, witness.state)
                self.assertIn(witness.name, model.findings(final))
                prefix = self.trace(witness.trace[:-1], policy=policy)
                self.assertNotIn(witness.name, model.findings(prefix))
                count += 1
        self.assertEqual(count, 7)

    def test_all_nine_binding_symbols_are_exhausted_under_the_reference_premise(self):
        report = model.compare(bindings=tuple(range(9)))
        self.assertTrue(report.complete)
        self.assertEqual(report.witnesses, ())
        self.assertGreater(report.states, comparison("entry-consume").states)

    def test_search_cutoff_remains_incomplete_even_when_it_has_found_a_violation(self):
        report = model.compare(policy="result-fence", max_states=50)
        self.assertFalse(report.complete)
        self.assertEqual((report.reason, report.status, report.states), ("state-limit", "incomplete", 50))
        self.assertTrue(report.witnesses)
        for limit in (True, False, 0, -1, 1000001, 3.0, "3", None):
            with self.assertRaises(ValueError):
                model.compare(max_states=limit)

    def test_exact_policy_domain_and_action_fields_refuse_aliases_and_extensions(self):
        for policy in (None, True, "safe", [], 0):
            with self.assertRaises(ValueError):
                model.compare(policy=policy)
        for bindings in ([], (), (True,), (0, 0), (6, 0), (0, 9), (6,), (0, 1.0)):
            with self.assertRaises(ValueError):
                model.compare(bindings=bindings)
        for action in (None, {}, model.Action("unknown"), model.Action("restore-copy", 0),
                       model.Action("work", True), model.Action("work", 0, 0), model.Action("request", 0)):
            self.refuse(model.State(), action)

    def test_exact_state_and_audit_types_refuse_without_custom_conversion_hooks(self):
        class Foreign:
            def __eq__(self, other):
                raise AssertionError("foreign comparison hook")
            def __int__(self):
                raise AssertionError("foreign conversion hook")
        invalid = (None, {}, replace(model.State(), epoch=True), replace(model.State(), consumed=1),
                   replace(model.State(), actors=[]), replace(model.State(), work=[]),
                   replace(model.State(), actors=(Foreign(), model.Actor())),
                   replace(model.State(), work=(model.Work(0, True, 0, 0, True),)),
                   replace(model.State(), deliveries=(model.Delivery(0, 0, 0, 0, 1, False),)))
        for state in invalid:
            with self.assertRaises(ValueError):
                model.findings(state)

    def test_model_values_and_reports_are_immutable_and_import_no_worker_or_storage(self):
        state = self.prefix()
        with self.assertRaises(FrozenInstanceError):
            state.consumed = False
        with self.assertRaises(FrozenInstanceError):
            state.actors[0].binding = 6
        tree = ast.parse(Path(model.__file__).read_text("ascii"))
        modules = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertEqual(modules, {"__future__", "argparse", "collections", "dataclasses", "json"})
        forbidden = {"open", "eval", "exec", "compile", "__import__"}
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                             and node.func.id in forbidden for node in ast.walk(tree)))

    def test_real_cli_distinguishes_conditional_completion_counterexample_and_cutoff(self):
        for policy, limit, code, status in (("entry-consume", "100000", 0, "conditional-no-counterexample"),
            ("all", "100000", 1, "counterexample"), ("entry-consume", "1", 2, "incomplete")):
            result = subprocess.run([sys.executable, "-B", "scripts/model_nonce_invocation.py", "--policy", policy,
                                     "--max-states", limit], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, code)
            self.assertEqual(result.stderr, "")
            body = json.loads(result.stdout)
            self.assertEqual(body["schema"], "ptlc-nonce-invocation-model-v1")
            self.assertIn("NO-GO", body["claim"])
            self.assertIn(status, [row["status"] for row in body["results"]])
            self.assertTrue(result.stdout.isascii())

    def test_real_cli_unknown_private_option_and_invalid_values_are_not_echoed(self):
        for args in (("--synthetic-private-value=do-not-publish",), ("--max-states", "do-not-publish"),
                     ("--policy", "do-not-publish"), ("--max-states", "-1")):
            result = subprocess.run([sys.executable, "-B", "scripts/model_nonce_invocation.py", *args], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "FAIL: finite nonce model arguments rejected\n")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
