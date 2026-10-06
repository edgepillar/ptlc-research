"""Already issued symbolic grants, copied permissions and irreversible effects."""

import ast
from dataclasses import FrozenInstanceError, replace
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_nonce_grant_copy as model


@lru_cache(maxsize=None)
def comparison(policy):
    return model.compare(policy=policy)


class NonceGrantCopyModelTests(unittest.TestCase):
    def trace(self, actions, *, policy="effect-coupled", state=None):
        state = model.State() if state is None else state
        for action in actions:
            state = model.step(state, action, policy=policy)
        return state

    def issue(self, *, policy="effect-coupled"):
        return self.trace((model.Action("issue"),), policy=policy)

    def refuse(self, state, action, **options):
        with self.assertRaises(ValueError):
            model.step(state, action, **options)

    def copy(self, *, policy="effect-coupled", prepared=False):
        actions = [model.Action("issue")]
        if prepared:
            actions.append(model.Action("preflight" if policy == "preflight-epoch" else "permit", 0))
        return self.trace(tuple(actions) + (model.Action("snapshot", 0), model.Action("restore")), policy=policy)

    def test_unique_durable_issuance_survives_copy_and_epoch_without_a_second_grant(self):
        for policy in model.POLICIES:
            state = self.trace((model.Action("advance-epoch"),), state=self.copy(policy=policy), policy=policy)
            self.assertTrue(state.burned)
            self.assertEqual(state.workers[0].grant, state.workers[1].grant)
            self.refuse(state, model.Action("issue"), policy=policy)
            self.assertEqual(state.work, ())

    def test_snapshot_keeps_the_exact_issued_grant_epoch_and_cached_phase(self):
        for policy, prepared in (("copyable-grant", False), ("preflight-epoch", True), ("exported-permit", True)):
            state = self.copy(policy=policy, prepared=prepared)
            self.assertEqual(state.workers[0], state.snapshot)
            self.assertEqual(state.workers[1], state.snapshot)
            self.assertEqual(state.snapshot.grant, model.Grant())
            self.assertEqual(state.work, ())
            self.assertTrue(state.burned)

    def test_snapshot_is_unavailable_before_issuance_or_after_effect_without_prior_capture(self):
        self.refuse(model.State(), model.Action("snapshot", 0))
        state = self.trace((model.Action("work", 0),), state=self.issue())
        self.refuse(state, model.Action("snapshot", 0))
        self.refuse(state, model.Action("restore"))
        self.assertIsNone(state.snapshot)

    def test_only_one_saved_snapshot_and_one_restoration_are_available(self):
        state = self.copy(policy="copyable-grant")
        for action in (model.Action("snapshot", 0), model.Action("snapshot", 1), model.Action("restore")):
            self.refuse(state, action, policy="copyable-grant")
        lost = self.trace((model.Action("lose", 1),), policy="copyable-grant", state=state)
        self.refuse(lost, model.Action("restore"), policy="copyable-grant")

    def test_copyable_post_burn_grant_repeats_same_nonce_work_in_the_same_epoch(self):
        state = self.trace((model.Action("work", 0), model.Action("work", 1)),
                           policy="copyable-grant", state=self.copy(policy="copyable-grant"))
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
        self.assertTrue(all(event.durable_burn_before_work for event in state.work))
        self.assertEqual({(event.nonce, event.grant, event.binding, event.epoch) for event in state.work}, {(0, 0, 0, 0)})
        self.assertEqual(state.receipts, ())

    def test_saved_grant_can_be_restored_after_original_result_and_worker_loss(self):
        policy = "copyable-grant"
        state = self.trace((model.Action("snapshot", 0), model.Action("work", 0), model.Action("result", 0),
            model.Action("lose", 0), model.Action("restore"), model.Action("work", 1)), policy=policy, state=self.issue(policy=policy))
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
        self.assertTrue(state.receipts[0].accepted)
        self.assertTrue(state.burned)
        self.assertEqual(state.workers[0].phase, "lost")

    def test_loss_of_an_issued_grant_never_refunds_or_reissues_the_nonce(self):
        for policy in model.POLICIES:
            state = self.trace((model.Action("lose", 0),), state=self.issue(policy=policy), policy=policy)
            self.assertTrue(state.burned)
            self.assertEqual(state.work, ())
            for action in (model.Action("issue"), model.Action("work", 0), model.Action("restore")):
                self.refuse(state, action, policy=policy)

    def test_epoch_rejected_results_leave_both_prior_nonce_computations_in_audit(self):
        policy = "copyable-grant"
        state = self.trace((model.Action("work", 0), model.Action("advance-epoch"), model.Action("work", 1),
            model.Action("result", 0), model.Action("result", 1)), state=self.copy(policy=policy), policy=policy)
        self.assertEqual(len(state.work), 2)
        self.assertEqual(tuple(event.accepted for event in state.receipts), (False, False))
        self.assertEqual(tuple(event.result_epoch for event in state.receipts), (1, 1))
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))

    def test_grant_identity_receipt_deduplication_cannot_undo_a_second_computation(self):
        policy = "copyable-grant"
        for first, second in ((0, 1), (1, 0)):
            state = self.trace((model.Action("work", first), model.Action("result", first),
                model.Action("work", second), model.Action("result", second)), state=self.copy(policy=policy), policy=policy)
            self.assertEqual(tuple(event.accepted for event in state.receipts), (True, False))
            self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
            self.assertEqual(len(state.work), 2)

    def test_fresh_preflight_after_epoch_change_refuses_before_any_work(self):
        policy = "preflight-epoch"
        state = self.trace((model.Action("advance-epoch"), model.Action("preflight", 0), model.Action("preflight", 1)),
                           state=self.copy(policy=policy), policy=policy)
        self.assertEqual(tuple(worker.phase for worker in state.workers), ("refused", "refused"))
        self.assertEqual(state.work, ())
        for worker in (0, 1):
            self.refuse(state, model.Action("work", worker), policy=policy)

    def test_copied_passed_preflight_survives_epoch_change_before_both_effects(self):
        policy = "preflight-epoch"
        state = self.trace((model.Action("advance-epoch"), model.Action("work", 0), model.Action("work", 1),
            model.Action("result", 0), model.Action("result", 1)), state=self.copy(policy=policy, prepared=True), policy=policy)
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
        self.assertFalse(any(event.accepted for event in state.receipts))
        self.assertTrue(state.burned)

    def test_preflight_copies_before_or_after_the_check_have_distinct_stale_cut_behavior(self):
        policy = "preflight-epoch"
        before = self.trace((model.Action("preflight", 0), model.Action("advance-epoch"),
            model.Action("preflight", 1), model.Action("work", 0)), state=self.copy(policy=policy), policy=policy)
        after = self.trace((model.Action("advance-epoch"), model.Action("work", 0), model.Action("work", 1)),
                           state=self.copy(policy=policy, prepared=True), policy=policy)
        self.assertEqual(before.workers[1].phase, "refused")
        self.assertEqual((len(before.work), len(after.work)), (1, 2))
        self.assertEqual(model.findings(before), ())
        self.assertEqual(model.findings(after), ("same_nonce_work_repeated",))

    def test_atomic_durable_effect_mark_still_exports_a_copyable_execution_permit(self):
        policy = "exported-permit"
        copied = self.copy(policy=policy, prepared=True)
        self.assertTrue(copied.effect_consumed)
        self.assertEqual(copied.work, ())
        state = self.trace((model.Action("work", 0), model.Action("work", 1)), state=copied, policy=policy)
        self.assertTrue(state.effect_consumed)
        self.assertTrue(state.burned)
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))

    def test_ready_snapshot_before_effect_mark_cannot_acquire_a_second_permit(self):
        policy = "exported-permit"
        state = self.trace((model.Action("permit", 0), model.Action("permit", 1), model.Action("work", 0)),
                           state=self.copy(policy=policy), policy=policy)
        self.assertEqual(state.workers[1].phase, "refused")
        self.assertEqual(len(state.work), 1)
        self.assertEqual(model.findings(state), ())
        self.refuse(state, model.Action("work", 1), policy=policy)

    def test_saved_exported_permit_survives_original_completion_without_authority_rollback(self):
        policy = "exported-permit"
        state = self.trace((model.Action("permit", 0), model.Action("snapshot", 0), model.Action("work", 0),
            model.Action("result", 0), model.Action("lose", 0), model.Action("restore"), model.Action("work", 1),
            model.Action("result", 1)), state=self.issue(policy=policy), policy=policy)
        self.assertTrue(state.effect_consumed)
        self.assertTrue(state.burned)
        self.assertEqual(tuple(event.accepted for event in state.receipts), (True, False))
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))

    def test_epoch_change_cannot_revoke_an_already_exported_execution_permit(self):
        policy = "exported-permit"
        state = self.trace((model.Action("advance-epoch"), model.Action("work", 0), model.Action("work", 1)),
                           state=self.copy(policy=policy, prepared=True), policy=policy)
        self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
        self.assertTrue(state.effect_consumed)
        self.assertEqual(state.receipts, ())

    def test_effect_coupled_premise_allows_only_one_copied_worker_in_either_order(self):
        for first, second in ((0, 1), (1, 0)):
            state = self.trace((model.Action("work", first), model.Action("work", second)), state=self.copy())
            self.assertEqual(state.workers[second].phase, "refused")
            self.assertEqual(tuple(event.worker for event in state.work), (first,))
            self.assertTrue(state.effect_consumed)
            self.assertEqual(model.findings(state), ())

    def test_effect_coupled_premise_has_no_separate_preflight_or_exported_permit_state(self):
        state = self.issue()
        for kind in ("preflight", "permit"):
            self.refuse(state, model.Action(kind, 0))
        done = self.trace((model.Action("work", 0),), state=state)
        for kind in ("work", "permit", "preflight", "snapshot"):
            self.refuse(done, model.Action(kind, 0))

    def test_loss_after_effect_cannot_replay_saved_grant_under_the_effect_coupled_premise(self):
        state = self.trace((model.Action("snapshot", 0), model.Action("work", 0), model.Action("lose", 0),
            model.Action("restore"), model.Action("work", 1)), state=self.issue())
        self.assertEqual(len(state.work), 1)
        self.assertEqual(state.receipts, ())
        self.assertEqual(state.workers[1].phase, "refused")
        self.assertTrue(state.effect_consumed)

    def test_restoring_saved_ready_state_after_receipt_keeps_external_effect_and_result_audits(self):
        first = self.trace((model.Action("snapshot", 0), model.Action("work", 0), model.Action("result", 0)), state=self.issue())
        restored = self.trace((model.Action("restore"), model.Action("work", 1)), state=first)
        self.assertEqual(restored.work, first.work)
        self.assertEqual(restored.receipts, first.receipts)
        self.assertTrue(restored.receipts[0].accepted)
        self.assertTrue(restored.effect_consumed)
        self.assertEqual(model.findings(restored), ())

    def test_effect_coupled_premise_checks_epoch_at_the_effect_for_both_workers(self):
        state = self.trace((model.Action("advance-epoch"), model.Action("work", 0), model.Action("work", 1)), state=self.copy())
        self.assertEqual(state.work, ())
        self.assertFalse(state.effect_consumed)
        self.assertTrue(state.burned)
        self.assertEqual(tuple(worker.phase for worker in state.workers), ("refused", "refused"))

    def test_loss_before_and_after_effect_mark_never_refunds_external_issuance_or_consumption(self):
        for policy, action in (("copyable-grant", None), ("preflight-epoch", "preflight"),
                               ("exported-permit", "permit"), ("effect-coupled", "work")):
            issued = self.issue(policy=policy)
            actions = () if action is None else (model.Action(action, 0),)
            state = self.trace(actions + (model.Action("lose", 0),), state=issued, policy=policy)
            self.assertTrue(state.burned)
            self.assertEqual(state.effect_consumed, policy in ("exported-permit", "effect-coupled"))
            self.refuse(state, model.Action("issue"), policy=policy)
            self.refuse(state, model.Action("work", 0), policy=policy)

    def test_duplicate_work_finding_is_independent_of_current_flags_epoch_and_receipts(self):
        work = (model.Work(0, 0, 0, 0, 0, True), model.Work(1, 0, 0, 0, 0, True))
        for burned in (True, False):
            for effect_consumed in (True, False):
                state = model.State(epoch=1, burned=burned, effect_consumed=effect_consumed, work=work)
                self.assertEqual(model.findings(state), ("same_nonce_work_repeated",))
        unburned = replace(work[0], durable_burn_before_work=False)
        self.assertEqual(model.findings(model.State(burned=True, work=(unburned,))), ("work_before_durable_burn",))

    def test_receipt_findings_use_matching_work_and_actual_acceptance_history(self):
        work = model.Work(0, 0, 0, 0, 0, True)
        one = model.Receipt(0, 0, 0, 0, 0, 0, True)
        other = model.Receipt(1, 0, 0, 0, 0, 0, True)
        self.assertEqual(model.findings(model.State(work=(work,), receipts=(one,))), ())
        self.assertEqual(model.findings(model.State(receipts=(one,))), ("receipt_without_same_work",))
        self.assertEqual(set(model.findings(model.State(work=(work,), receipts=(one, other)))),
                         {"receipt_without_same_work", "multiple_accepted_receipts_for_grant"})

    def test_all_four_finite_graphs_complete_and_only_the_explicit_custody_premise_has_no_finding(self):
        for policy in model.POLICIES:
            report = comparison(policy)
            self.assertTrue(report.complete)
            self.assertEqual(report.reason, "finite-graph-exhausted")
            expected = set() if policy == "effect-coupled" else {"same_nonce_work_repeated"}
            self.assertEqual({w.name for w in report.witnesses}, expected)
            self.assertEqual(report.status, "conditional-no-counterexample" if not expected else "counterexample")

    def test_every_shortest_finding_replays_exactly_from_post_consumption_snapshots(self):
        count = 0
        for policy in model.POLICIES:
            for witness in comparison(policy).witnesses:
                final = self.trace(witness.trace, policy=policy)
                prefix = self.trace(witness.trace[:-1], policy=policy)
                self.assertEqual(final, witness.state)
                self.assertIn(witness.name, model.findings(final))
                self.assertNotIn(witness.name, model.findings(prefix))
                self.assertEqual(witness.trace[0], model.Action("issue"))
                self.assertTrue(final.burned)
                count += 1
        self.assertEqual(count, 3)

    def test_state_limit_reports_incomplete_with_or_without_an_already_found_counterexample(self):
        empty = model.compare(max_states=1)
        self.assertEqual((empty.complete, empty.status, empty.states, empty.witnesses), (False, "incomplete", 1, ()))
        full = comparison("copyable-grant")
        partial = model.compare(policy="copyable-grant", max_states=full.states - 1)
        self.assertFalse(partial.complete)
        self.assertEqual((partial.reason, partial.status), ("state-limit", "incomplete"))
        self.assertTrue(partial.witnesses)

    def test_exact_policies_actions_and_limits_refuse_boolean_aliases_and_extra_fields(self):
        for policy in (None, True, "secure", [], 0):
            with self.assertRaises(ValueError):
                model.compare(policy=policy)
        for limit in (True, False, 0, -1, 1000001, 3.0, "3", None):
            with self.assertRaises(ValueError):
                model.compare(max_states=limit)
        for action in (None, {}, model.Action("unknown"), model.Action("issue", 0),
                       model.Action("work", True), model.Action("work"), model.Action("snapshot", 1)):
            self.refuse(model.State(), action)

    def test_exact_state_grant_snapshot_and_audit_types_refuse_foreign_conversion_hooks(self):
        class Foreign:
            def __eq__(self, other):
                raise AssertionError("foreign comparison hook")
            def __int__(self):
                raise AssertionError("foreign conversion hook")
        invalid = (None, {}, replace(model.State(), epoch=True), replace(model.State(), burned=1),
            replace(model.State(), effect_consumed=1), replace(model.State(), workers=[]),
            replace(model.State(), snapshot=Foreign()), replace(model.State(), snapshot=model.Worker()),
            replace(model.State(), workers=(model.Worker("ready", replace(model.Grant(), nonce=True)), model.Worker("absent"))),
            replace(model.State(), workers=(Foreign(), model.Worker("absent"))),
            replace(model.State(), work=(model.Work(True, 0, 0, 0, 0, True),)),
            replace(model.State(), work=(model.Work(0, 0, 0, 0, 0, 1),)),
            replace(model.State(), receipts=(model.Receipt(0, 0, 0, 0, 0, True, True),)),
            replace(model.State(), receipts=(model.Receipt(0, 0, 0, 0, 0, 0, 1),)))
        for state in invalid:
            with self.assertRaises(ValueError):
                model.findings(state)

    def test_frozen_symbolic_values_import_no_worker_storage_or_cryptographic_backend(self):
        state = self.copy()
        for value, field, replacement in ((state, "burned", False), (state.snapshot, "phase", "ready"),
                                          (state.snapshot.grant, "nonce", 1), (comparison("effect-coupled"), "complete", False)):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field, replacement)
        tree = ast.parse(Path(model.__file__).read_text("ascii"))
        modules = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertEqual(modules, {"__future__", "argparse", "collections", "dataclasses", "json"})
        forbidden = {"open", "eval", "exec", "compile", "__import__"}
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in forbidden for node in ast.walk(tree)))

    def test_real_cli_distinguishes_conditional_completion_counterexamples_and_cutoff(self):
        for policy, limit, code, status in (("effect-coupled", "100000", 0, "conditional-no-counterexample"),
            ("all", "100000", 1, "counterexample"), ("copyable-grant", "1", 2, "incomplete")):
            result = subprocess.run([sys.executable, "-B", "scripts/model_nonce_grant_copy.py", "--policy", policy,
                                     "--max-states", limit], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, code)
            self.assertEqual(result.stderr, "")
            body = json.loads(result.stdout)
            self.assertEqual(body["schema"], "ptlc-nonce-grant-copy-model-v1")
            self.assertIn("NO-GO", body["claim"])
            self.assertEqual(body["bounds"]["grant_labels"], 1)
            self.assertIn(status, [row["status"] for row in body["results"]])
            self.assertTrue(result.stdout.isascii())

    def test_real_cli_private_arguments_unknown_options_and_abbreviations_are_not_echoed(self):
        for args in (("--synthetic-private-value=do-not-publish",), ("--max-states", "do-not-publish"),
                     ("--policy", "do-not-publish"), ("--pol", "copyable-grant"), ("--max-states", "-1")):
            result = subprocess.run([sys.executable, "-B", "scripts/model_nonce_grant_copy.py", *args],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "FAIL: finite grant-copy model arguments rejected\n")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
