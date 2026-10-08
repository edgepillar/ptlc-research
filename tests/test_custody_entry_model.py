"""Current effect authority and separately authorized original-output recovery."""

import ast
from dataclasses import FrozenInstanceError, replace
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_custody_entry as model


@lru_cache(maxsize=None)
def comparison(policy):
    return model.compare(policy=policy)


class CustodyEntryModelTests(unittest.TestCase):
    def trace(self, actions, *, policy="continuous-authority", state=None):
        state = model.State() if state is None else state
        for action in actions:
            state = model.step(state, action, policy=policy)
        return state

    def ready(self, *, policy="continuous-authority", copied=False):
        actions = (model.Action("admit", 0), model.Action("burn", 0))
        if copied:
            actions += (model.Action("snapshot", 0), model.Action("restore"))
        return self.trace(actions, policy=policy)

    def retained(self, *, policy="continuous-authority", copied=False):
        return self.trace((model.Action("work", 0), model.Action("retain", 0)),
                          state=self.ready(policy=policy, copied=copied), policy=policy)

    def refuse(self, state, action, **options):
        with self.assertRaises(ValueError):
            model.step(state, action, **options)

    def test_equal_image_copy_keeps_one_admission_and_durable_burn_without_new_release(self):
        state = self.ready(copied=True)
        self.assertEqual(state.workers, (state.snapshot, state.snapshot))
        self.assertEqual(tuple(worker.image for worker in state.workers), (0, 0))
        self.assertTrue(state.burned)
        self.assertFalse(state.consumed)
        for action in (model.Action("admit", 1), model.Action("admit", 0), model.Action("burn", 0)):
            self.refuse(state, action)

    def test_recipient_admission_alone_can_burn_after_revoke_while_current_policies_refuse(self):
        actions = (model.Action("admit", 0), model.Action("revoke"), model.Action("burn", 0))
        for policy in model.POLICIES:
            state = self.trace(actions, policy=policy)
            self.assertEqual(state.burned, policy == "recipient-only")
            self.assertEqual(state.workers[0].phase, "ready" if state.burned else "refused")
            self.assertEqual(state.work, ())

    def test_revocation_after_burn_before_entry_refuses_both_copies_and_keeps_burn_spent(self):
        for policy in ("local-consumption", "work-only", "continuous-authority"):
            state = self.trace((model.Action("revoke"), model.Action("work", 0), model.Action("work", 1)),
                               state=self.ready(policy=policy, copied=True), policy=policy)
            self.assertTrue(state.burned)
            self.assertFalse(state.consumed)
            self.assertEqual(tuple(w.phase for w in state.workers), ("refused", "refused"))
            self.assertEqual(state.work, ())
            self.refuse(state, model.Action("burn", 0), policy=policy)

    def test_cached_current_burn_passes_then_revocation_precedes_the_actual_effect(self):
        policy = "cached-current"
        state = self.trace((model.Action("revoke"), model.Action("work", 0)),
                           state=self.ready(policy=policy), policy=policy)
        self.assertEqual(model.findings(state), ("work_after_revocation",))
        self.assertEqual((state.work[0].bound_epoch, state.work[0].actual_epoch), (0, 1))
        self.assertTrue(state.consumed)

    def test_continuity_loss_between_burn_and_effect_refuses_without_refunding(self):
        state = self.trace((model.Action("lose-continuity"), model.Action("work", 0), model.Action("work", 1)),
                           state=self.ready(copied=True))
        self.assertEqual((state.continuity, state.burned, state.consumed), (1, True, False))
        self.assertEqual(state.work, ())
        self.assertEqual(model.findings(state), ())

    def test_cached_current_permission_survives_loss_of_actual_continuity(self):
        policy = "cached-current"
        state = self.trace((model.Action("lose-continuity"), model.Action("work", 0)),
                           state=self.ready(policy=policy), policy=policy)
        self.assertEqual(model.findings(state), ("work_without_verified_continuity",))
        self.assertEqual(state.work[0].actual_continuity, 1)

    def test_copied_local_consumption_repeats_effect_despite_current_external_authority(self):
        policy = "local-consumption"
        for first, second in ((0, 1), (1, 0)):
            state = self.trace((model.Action("work", first), model.Action("work", second)),
                               state=self.ready(policy=policy, copied=True), policy=policy)
            self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
            self.assertTrue(all(worker.local_consumed for worker in state.workers))
            self.assertTrue(all(event.actual_epoch == 0 and event.actual_continuity == 0 for event in state.work))
            self.assertTrue(state.consumed)

    def test_single_original_retention_cannot_undo_a_second_actual_effect(self):
        policy = "local-consumption"
        state = self.trace((model.Action("work", 0), model.Action("retain", 0),
            model.Action("work", 1), model.Action("retain", 1), model.Action("deliver")),
            state=self.ready(policy=policy, copied=True), policy=policy)
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
        self.assertEqual(state.original, model.Output(0, 0))
        self.assertEqual(state.workers[1].phase, "refused")
        self.assertEqual(len(state.work), 2)
        self.assertEqual(state.deliveries[0].output, state.original)

    def test_indivisible_reference_consumption_admits_only_one_copy_in_either_order(self):
        for first, second in ((0, 1), (1, 0)):
            state = self.trace((model.Action("work", first), model.Action("work", second)),
                               state=self.ready(copied=True))
            self.assertEqual(tuple(event.worker for event in state.work), (first,))
            self.assertEqual(state.workers[second].phase, "refused")
            self.assertEqual(model.findings(state), ())

    def test_reference_exposes_no_separate_checked_state_or_exported_execution_permit(self):
        state = self.ready()
        for kind in ("check", "permit", "authorize", "reset", "retry", "fresh-nonce"):
            self.refuse(state, model.Action(kind, 0))
        done = self.trace((model.Action("work", 0),), state=state)
        self.refuse(done, model.Action("work", 0))
        self.refuse(done, model.Action("snapshot", 0))

    def test_ideal_reanchor_restores_current_authority_without_releasing_or_reburning(self):
        ready = self.ready()
        state = self.trace((model.Action("lose-continuity"), model.Action("reanchor")), state=ready)
        self.assertEqual(replace(state, continuity=0), ready)
        executed = self.trace((model.Action("work", 0),), state=state)
        self.assertEqual(executed.work[0].actual_continuity, 2)
        self.assertEqual(model.findings(executed), ())

    def test_ideal_reanchor_cannot_reverse_policy_revocation(self):
        state = self.trace((model.Action("revoke"), model.Action("lose-continuity"),
            model.Action("reanchor"), model.Action("work", 0)), state=self.ready())
        self.assertEqual((state.epoch, state.continuity, state.burned), (1, 2, True))
        self.assertEqual(state.work, ())
        self.assertEqual(state.workers[0].phase, "refused")

    def test_reanchor_after_effect_keeps_consumption_and_blocks_saved_ready_copy(self):
        state = self.trace((model.Action("work", 0), model.Action("lose-continuity"),
            model.Action("reanchor"), model.Action("work", 1)), state=self.ready(copied=True))
        self.assertTrue(state.consumed)
        self.assertEqual(len(state.work), 1)
        self.assertEqual(state.workers[1].phase, "refused")
        self.assertEqual(model.findings(state), ())

    def test_exact_original_survives_worker_loss_and_can_be_delivered_after_reanchor(self):
        original = self.retained()
        lost = self.trace((model.Action("lose", 0), model.Action("lose-continuity")), state=original)
        self.refuse(lost, model.Action("deliver"))
        state = self.trace((model.Action("reanchor"), model.Action("deliver")), state=lost)
        self.assertEqual((state.original, state.work), (original.original, original.work))
        self.assertEqual(state.deliveries[0].output, original.original)
        self.assertEqual(state.workers[0].phase, "lost")
        self.refuse(state, model.Action("work", 0))

    def test_original_delivery_is_separately_refused_after_revocation_without_erasing_output(self):
        original = self.retained()
        revoked = self.trace((model.Action("revoke"),), state=original)
        self.refuse(revoked, model.Action("deliver"))
        self.assertEqual((revoked.original, revoked.work), (original.original, original.work))
        self.assertEqual(revoked.deliveries, ())

    def test_original_delivery_requires_verified_continuity_on_every_replay(self):
        first = self.trace((model.Action("deliver"),), state=self.retained())
        lost = self.trace((model.Action("lose-continuity"),), state=first)
        self.refuse(lost, model.Action("deliver"))
        state = self.trace((model.Action("reanchor"), model.Action("deliver")), state=lost)
        self.assertEqual(tuple(d.output for d in state.deliveries), (state.original, state.original))
        self.assertEqual(tuple(d.actual_continuity for d in state.deliveries), (0, 2))
        self.assertEqual(state.work, first.work)

    def test_work_only_boundary_can_deliver_after_revoke_despite_one_authorized_effect(self):
        policy = "work-only"
        original = self.retained(policy=policy)
        state = self.trace((model.Action("revoke"), model.Action("deliver")), state=original, policy=policy)
        self.assertEqual(model.findings(state), ("delivery_after_revocation",))
        self.assertEqual(state.work, original.work)
        self.assertEqual(len(state.work), 1)

    def test_work_only_boundary_can_deliver_without_verified_continuity(self):
        policy = "work-only"
        state = self.trace((model.Action("lose-continuity"), model.Action("deliver")),
                           state=self.retained(policy=policy), policy=policy)
        self.assertEqual(model.findings(state), ("delivery_without_verified_continuity",))
        self.assertEqual(state.deliveries[0].output, state.original)

    def test_loss_after_burn_before_effect_stays_unknown_spent_and_refuses_restored_work(self):
        state = self.trace((model.Action("snapshot", 0), model.Action("lose", 0),
            model.Action("restore"), model.Action("work", 1)), state=self.ready())
        self.assertEqual((state.burned, state.consumed, state.unknown_spent), (True, False, True))
        self.assertEqual(state.work, ())
        self.assertIsNone(state.original)
        self.assertEqual(state.workers[1].phase, "refused")
        self.refuse(state, model.Action("burn", 0))
        self.refuse(state, model.Action("deliver"))

    def test_loss_after_effect_before_original_retention_cannot_recompute_or_deliver(self):
        state = self.trace((model.Action("snapshot", 0), model.Action("work", 0), model.Action("lose", 0),
            model.Action("restore"), model.Action("work", 1)), state=self.ready())
        self.assertTrue(state.unknown_spent and state.consumed and state.burned)
        self.assertEqual(len(state.work), 1)
        self.assertIsNone(state.original)
        self.assertEqual(model.findings(state), ())
        self.refuse(state, model.Action("retain", 0))
        self.refuse(state, model.Action("deliver"))

    def test_loss_after_retention_supports_exact_replay_without_new_nonce_work(self):
        retained = self.retained(copied=True)
        state = self.trace((model.Action("lose", 0), model.Action("work", 1),
            model.Action("deliver"), model.Action("deliver")), state=retained)
        self.assertEqual(state.work, retained.work)
        self.assertEqual(state.original, retained.original)
        self.assertEqual(tuple(d.output for d in state.deliveries), (retained.original, retained.original))
        self.assertEqual(model.findings(state), ())

    def test_unknown_spent_can_only_reconcile_an_exact_surviving_original(self):
        # The second worker is lost after the first effect but before retention.
        executed = self.trace((model.Action("work", 0),), state=self.ready(copied=True))
        state = self.trace((model.Action("lose", 1), model.Action("retain", 0), model.Action("deliver")),
                           state=executed)
        self.assertTrue(state.unknown_spent)
        self.assertEqual(state.work, executed.work)
        self.assertEqual(state.original, model.Output(0, 0))
        self.assertEqual(model.findings(state), ())
        self.refuse(state, model.Action("work", 1))

    def test_no_output_can_be_delivered_or_retained_before_its_effect_and_retention(self):
        for state in (model.State(), self.ready(), self.trace((model.Action("work", 0),), state=self.ready())):
            self.refuse(state, model.Action("deliver"))
        self.refuse(self.ready(), model.Action("retain", 0))
        retained = self.retained()
        self.refuse(retained, model.Action("retain", 0))

    def test_only_one_snapshot_restoration_and_two_original_deliveries_are_in_scope(self):
        state = self.ready(copied=True)
        for action in (model.Action("snapshot", 0), model.Action("snapshot", 1), model.Action("restore")):
            self.refuse(state, action)
        state = self.trace((model.Action("work", 0), model.Action("retain", 0),
            model.Action("deliver"), model.Action("deliver")), state=state)
        self.refuse(state, model.Action("deliver"))
        self.assertEqual(len(state.work), 1)

    def test_revocation_loss_and_ideal_reanchor_are_once_only_and_never_reset_external_audits(self):
        original = self.retained()
        state = self.trace((model.Action("revoke"), model.Action("lose-continuity"), model.Action("reanchor")), state=original)
        for action in (model.Action("revoke"), model.Action("lose-continuity"), model.Action("reanchor")):
            self.refuse(state, action)
        self.assertEqual((state.burned, state.consumed, state.original, state.work),
                         (original.burned, original.consumed, original.original, original.work))

    def test_work_findings_use_irreversible_event_facts_instead_of_current_flags(self):
        event = model.Work(0, 0, 0, 0, 1, 1, False, True)
        state = model.State(work=(event, replace(event, worker=1, output=1)))
        self.assertEqual(set(model.findings(state)), {"same_nonce_work_repeated", "work_before_durable_burn",
            "work_after_revocation", "work_without_verified_continuity", "work_after_unknown_spent"})
        self.assertEqual(model.findings(replace(state, epoch=1, continuity=2, burned=True, consumed=True)),
                         model.findings(state))

    def test_delivery_findings_distinguish_retention_exactness_effect_and_current_authority(self):
        output = model.Output(0, 0)
        event = model.Delivery(output, None, 1, 1)
        state = model.State(original=output, deliveries=(event,))
        self.assertEqual(set(model.findings(state)), {"delivery_without_exact_original_retention",
            "delivery_without_original_effect", "delivery_after_revocation", "delivery_without_verified_continuity"})
        work = model.Work(0, 0, 0, 0, 0, 0, True, False)
        exact = replace(event, retained_at_delivery=output, actual_epoch=0, actual_continuity=2)
        self.assertEqual(model.findings(model.State(work=(work,), deliveries=(exact,))), ())
        other = replace(exact, retained_at_delivery=model.Output(1, 1))
        self.assertEqual(model.findings(model.State(work=(work,), deliveries=(other,))),
                         ("delivery_without_exact_original_retention",))

    def test_exact_policies_actions_and_limits_refuse_boolean_aliases_and_extra_fields(self):
        for policy in (None, True, "secure", [], 0):
            with self.assertRaises(ValueError):
                model.compare(policy=policy)
        for limit in (True, False, 0, -1, 1000001, 3.0, "3", None):
            with self.assertRaises(ValueError):
                model.compare(max_states=limit)
        for action in (None, {}, model.Action("unknown"), model.Action("admit"), model.Action("burn", 1),
                       model.Action("work", True), model.Action("deliver", 0), model.Action("restore", 1)):
            self.refuse(model.State(), action)

    def test_exact_state_worker_output_and_audit_types_refuse_foreign_conversion_hooks(self):
        class Foreign:
            def __eq__(self, other):
                raise AssertionError("foreign comparison hook")
            def __int__(self):
                raise AssertionError("foreign conversion hook")
        invalid = (None, {}, replace(model.State(), epoch=True), replace(model.State(), continuity=True),
            replace(model.State(), burned=1), replace(model.State(), consumed=1),
            replace(model.State(), unknown_spent=1), replace(model.State(), workers=[]),
            replace(model.State(), snapshot=Foreign()), replace(model.State(), snapshot=model.Worker()),
            replace(model.State(), workers=(Foreign(), model.Worker())),
            replace(model.State(), workers=(model.Worker(image=True), model.Worker())),
            replace(model.State(), workers=(model.Worker(local_consumed=1), model.Worker())),
            replace(model.State(), workers=(model.Worker(output=True), model.Worker())),
            replace(model.State(), original=model.Output(0, 0, True)),
            replace(model.State(), original=Foreign()),
            replace(model.State(), work=(model.Work(0, 0, 0, 0, 0, True, True, False),)),
            replace(model.State(), work=(model.Work(0, 0, True, 0, 0, 0, True, False),)),
            replace(model.State(), work=(model.Work(0, 0, 0, 0, 0, 0, 1, False),)),
            replace(model.State(), deliveries=(model.Delivery(model.Output(0, 0), Foreign(), 0, 0),)))
        for state in invalid:
            with self.assertRaises(ValueError):
                model.findings(state)

    def test_frozen_symbols_import_no_worker_storage_network_or_cryptographic_backend(self):
        state = self.ready(copied=True)
        for value, field, replacement in ((state, "burned", False), (state.snapshot, "phase", "ready"),
                                          (model.Output(0, 0), "nonce", 1), (comparison("continuous-authority"), "complete", False)):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field, replacement)
        tree = ast.parse(Path(model.__file__).read_text("ascii"))
        modules = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertEqual(modules, {"__future__", "argparse", "collections", "dataclasses", "json"})
        forbidden = {"open", "eval", "exec", "compile", "__import__"}
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in forbidden for node in ast.walk(tree)))

    def test_all_five_graphs_complete_and_only_the_combined_explicit_premise_has_no_finding(self):
        expected = {
            "recipient-only": {"work_after_revocation", "work_without_verified_continuity", "same_nonce_work_repeated",
                               "work_after_unknown_spent", "delivery_after_revocation", "delivery_without_verified_continuity"},
            "cached-current": {"work_after_revocation", "work_without_verified_continuity",
                               "delivery_after_revocation", "delivery_without_verified_continuity"},
            "local-consumption": {"same_nonce_work_repeated", "work_after_unknown_spent"},
            "work-only": {"delivery_after_revocation", "delivery_without_verified_continuity"},
            "continuous-authority": set(),
        }
        for policy in model.POLICIES:
            report = comparison(policy)
            self.assertTrue(report.complete)
            self.assertEqual(report.reason, "finite-graph-exhausted")
            self.assertEqual({w.name for w in report.witnesses}, expected[policy])
            self.assertEqual(report.status, "conditional-no-counterexample" if not expected[policy] else "counterexample")

    def test_every_shortest_finding_replays_and_appears_only_at_its_last_action(self):
        count = 0
        for policy in model.POLICIES:
            for witness in comparison(policy).witnesses:
                self.assertEqual(self.trace(witness.trace, policy=policy), witness.state)
                self.assertIn(witness.name, model.findings(witness.state))
                prefix = self.trace(witness.trace[:-1], policy=policy)
                self.assertNotIn(witness.name, model.findings(prefix))
                self.assertEqual(witness.trace[0], model.Action("admit", 0))
                count += 1
        self.assertEqual(count, 14)

    def test_state_limit_reports_incomplete_even_after_a_counterexample_is_found(self):
        empty = model.compare(max_states=1)
        self.assertEqual((empty.complete, empty.status, empty.states, empty.witnesses), (False, "incomplete", 1, ()))
        full = comparison("recipient-only")
        partial = model.compare(policy="recipient-only", max_states=full.states - 1)
        self.assertFalse(partial.complete)
        self.assertEqual((partial.reason, partial.status), ("state-limit", "incomplete"))
        self.assertTrue(partial.witnesses)

    def test_real_cli_distinguishes_conditional_completion_counterexamples_and_cutoff(self):
        for policy, limit, code, status in (("continuous-authority", "200000", 0, "conditional-no-counterexample"),
            ("all", "200000", 1, "counterexample"), ("recipient-only", "1", 2, "incomplete")):
            result = subprocess.run([sys.executable, "-B", "scripts/model_custody_entry.py", "--policy", policy,
                                     "--max-states", limit], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, code)
            self.assertEqual(result.stderr, "")
            body = json.loads(result.stdout)
            self.assertEqual(body["schema"], "ptlc-custody-entry-model-v1")
            self.assertIn("unimplemented", body["claim"])
            self.assertIn("NO-GO", body["claim"])
            self.assertEqual(body["bounds"]["nonce_labels"], 1)
            self.assertEqual(body["bounds"]["deliveries"], 2)
            self.assertIn(status, [row["status"] for row in body["results"]])
            self.assertTrue(result.stdout.isascii())

    def test_real_cli_invalid_options_private_values_and_abbreviations_are_not_echoed(self):
        for args in (("--synthetic-private-value=do-not-publish",), ("--max-states", "do-not-publish"),
                     ("--policy", "do-not-publish"), ("--pol", "recipient-only"), ("--max-states", "-1")):
            result = subprocess.run([sys.executable, "-B", "scripts/model_custody_entry.py", *args],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "FAIL: finite custody model arguments rejected\n")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
