"""Adversarial offline reserve traces and independent resource invariants."""

from collections import deque
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_recovery_admission as core
from scripts import model_recovery_reserve as model


class RecoveryReserveModelTests(unittest.TestCase):
    def choice(self, kind, lane="", **fields):
        return model.Choice(core.Action(kind, **fields), lane)

    def advance(self, state, choice, *, bounds=model.Bounds(), policy="reserved"):
        following = model.step(state, choice, bounds=bounds, policy=policy)
        self.assertEqual(model.safety_violations(following, bounds=bounds, policy=policy), ())
        self.assertEqual(model.transition_violations(state, choice, following, bounds=bounds, policy=policy), ())
        return following

    def trace(self, choices, *, state=None, bounds=model.Bounds(), policy="reserved"):
        state = model.State() if state is None else state
        for choice in choices:
            state = self.advance(state, choice, bounds=bounds, policy=policy)
        return state

    def public_witness(self, *, state=None, authenticated=False, authorize=True,
                       bounds=model.Bounds(), policy="reserved"):
        choices = [self.choice("observe_public", authenticated=authenticated)]
        if authorize:
            choices.append(self.choice("authorize_public"))
        return self.trace(choices, state=state, bounds=bounds, policy=policy)

    def public_recovery(self, state, lane):
        if not state.core.retained:
            return self.choice("begin", lane, candidate="valid", source="public",
                               authenticated=state.core.public_authenticated)
        if state.core.retained == "valid":
            return self.choice("retry", lane)
        return self.choice("reconcile", lane, candidate="valid", source="public",
                           authenticated=state.core.public_authenticated,
                           expected_candidate=state.core.retained)

    def poison(self, *, bounds=model.Bounds(), policy="reserved", state=None):
        lane = "shared" if policy == "shared" else "general"
        state = model.State() if state is None else state
        count = bounds.total if policy == "shared" else bounds.general_limit
        for attempt in range(count):
            admission = self.choice("retry", lane) if attempt else self.choice(
                "begin", lane, candidate="invalid", source="peer", authenticated=True)
            state = self.trace((admission, self.choice("worker_verify")), state=state,
                               bounds=bounds, policy=policy)
        return state

    def assert_unavailable(self, state, choice, *, bounds=model.Bounds(), policy="reserved"):
        before = state
        with self.assertRaises(ValueError):
            model.step(state, choice, bounds=bounds, policy=policy)
        self.assertEqual(state, before)

    def reachable(self, *, bounds=model.Bounds(), policy="reserved"):
        queue = deque([model.State()])
        seen = {queue[0]}
        edges = set()
        while queue:
            state = queue.popleft()
            for choice, following in model.successors(state, bounds=bounds, policy=policy):
                edges.add((state.core, choice.action, following.core))
                if following not in seen:
                    seen.add(following)
                    queue.append(following)
        return seen, edges

    def test_equal_total_shared_allowance_can_be_drained_without_any_public_worker(self):
        bounds = model.Bounds(2, 1, 0)
        state = self.poison(bounds=bounds, policy="shared")
        state = self.public_witness(state=state, bounds=bounds, policy="shared")
        self.assertEqual((state.general_consumed, state.reserve_consumed, state.public_failures), (3, 0, 0))
        self.assertEqual(model.availability_violations(state, bounds=bounds, policy="shared"),
                         ("public_recovery_allowance_exhausted",))
        self.assert_unavailable(state, self.public_recovery(state, "shared"), bounds=bounds, policy="shared")

    def test_reserved_public_replacement_survives_complete_general_poisoning(self):
        state = self.poison()
        state = self.public_witness(state=state)
        self.assertEqual((state.general_consumed, state.reserve_consumed), (2, 0))
        self.assertEqual(model.availability_violations(state), ())
        admitted = self.advance(state, self.public_recovery(state, "reserve"))
        self.assertEqual((admitted.general_consumed, admitted.reserve_consumed), (2, 1))
        self.assertEqual((admitted.core.retained, admitted.core.archive, admitted.core.completed),
                         ("invalid", "", ""))
        completed = self.advance(admitted, self.choice("worker_verify"))
        self.assertEqual((completed.core.original, completed.core.retained, completed.core.archive,
                          completed.core.completed), ("invalid", "valid", "invalid", "valid"))

    def test_finite_reserve_can_be_exhausted_by_each_public_worker_interruption(self):
        for outcome in model.INTERRUPTIONS:
            with self.subTest(outcome=outcome):
                state = self.public_witness(state=self.poison())
                admitted = self.advance(state, self.public_recovery(state, "reserve"))
                failed = self.advance(admitted, self.choice(outcome))
                self.assertEqual((failed.core.consumed, failed.reserve_consumed, failed.public_failures), (3, 1, 1))
                self.assertEqual((failed.core.retained, failed.core.archive, failed.core.completed), ("invalid", "", ""))
                self.assertEqual(model.availability_violations(failed), ("public_recovery_allowance_exhausted",))
                self.assert_unavailable(failed, self.public_recovery(failed, "reserve"))

    def test_reserved_retry_requires_separate_public_authorization_of_retained_valid_bytes(self):
        bounds = model.Bounds(1, 1)
        state = self.trace((self.choice("begin", "general", candidate="valid", source="peer", authenticated=True),
                            self.choice("worker_fail")), bounds=bounds)
        self.assert_unavailable(state, self.choice("retry", "reserve"), bounds=bounds)
        state = self.public_witness(state=state, authorize=False, bounds=bounds)
        self.assert_unavailable(state, self.choice("retry", "reserve"), bounds=bounds)
        state = self.advance(state, self.choice("authorize_public"), bounds=bounds)
        self.assertFalse(state.core.public_authenticated)
        self.assertTrue(state.core.retained_authenticated)
        self.assert_unavailable(state, self.choice("retry", "general"), bounds=bounds)
        admitted = self.advance(state, self.choice("retry", "reserve"), bounds=bounds)
        self.assertTrue(admitted.pending_public)
        self.assertFalse(admitted.core.pending.locally_authorized)
        self.assertEqual(admitted.core.pending.source, "retained")
        self.assertEqual(self.advance(admitted, self.choice("worker_verify"), bounds=bounds).core.completed, "valid")

    def test_peer_source_authentication_and_claimed_inclusion_cannot_spend_reserve(self):
        for authenticated in (False, True):
            state = self.public_witness(authenticated=authenticated, authorize=False)
            state = self.advance(state, self.choice("claim_inclusion"))
            public = self.choice("begin", "reserve", candidate="valid", source="public", authenticated=authenticated)
            self.assert_unavailable(state, public)
            state = self.advance(state, self.choice("authorize_public"))
            for candidate in ("valid", "invalid"):
                self.assert_unavailable(state, self.choice("begin", "reserve", candidate=candidate,
                                                          source="peer", authenticated=True))
            self.assert_unavailable(state, replace(public, action=replace(public.action, authenticated=not authenticated)))
            self.assertEqual(self.advance(state, public).reserve_consumed, 1)

    def test_invalid_retained_retry_cannot_be_reclassified_as_public_reserve_work(self):
        state = self.public_witness(state=self.poison())
        self.assert_unavailable(state, self.choice("retry", "reserve"))
        self.assert_unavailable(state, self.choice("reconcile", "reserve", candidate="invalid", source="public",
                                                  expected_candidate="invalid"))
        self.assertEqual((state.reserve_consumed, state.public_failures), (0, 0))

    def test_wrong_reconciliation_comparison_does_not_debit_any_lane(self):
        state = self.public_witness(state=self.poison())
        replacement = self.public_recovery(state, "reserve")
        wrong = replace(replacement, action=replace(replacement.action, expected_candidate="valid"))
        self.assert_unavailable(state, wrong)
        self.assertEqual((state.core.consumed, state.general_consumed, state.reserve_consumed), (2, 2, 0))

    def test_public_admission_may_use_general_lane_without_consuming_reserve(self):
        state = self.public_witness()
        admitted = self.advance(state, self.public_recovery(state, "general"))
        self.assertEqual((admitted.general_consumed, admitted.reserve_consumed), (1, 0))
        self.assertTrue(admitted.pending_public)
        failed = self.advance(admitted, self.choice("worker_cancel"))
        self.assertEqual(failed.public_failures, 1)
        retried = self.advance(failed, self.choice("retry", "general"))
        self.assertFalse(retried.pending_public)
        failed = self.advance(retried, self.choice("worker_fail"))
        self.assertEqual(failed.public_failures, 1)
        self.assertEqual(self.advance(self.advance(failed, self.choice("retry", "reserve")),
                                      self.choice("worker_verify")).core.completed, "valid")

    def test_pending_worker_blocks_overlapping_recovery_in_either_lane(self):
        state = self.public_witness()
        pending = self.advance(state, self.choice("begin", "general", candidate="invalid",
                                                  source="peer", authenticated=True))
        for lane in ("general", "reserve"):
            self.assert_unavailable(pending, self.public_recovery(pending, lane))
            self.assert_unavailable(pending, self.choice("retry", lane))
        self.assertEqual((pending.general_consumed, pending.reserve_consumed), (1, 0))
        settled = self.advance(pending, self.choice("worker_crash"))
        completed = self.trace((self.public_recovery(settled, "reserve"), self.choice("worker_verify")), state=settled)
        self.assertEqual(completed.core.completed, "valid")

    def test_public_failure_bound_is_explicit_and_does_not_restrict_peer_interruptions(self):
        bounds = model.Bounds(2, 1, 0)
        state = self.public_witness(bounds=bounds)
        state = self.trace((self.choice("begin", "general", candidate="valid", source="peer", authenticated=True),
                            self.choice("worker_cancel")), state=state, bounds=bounds)
        self.assertEqual(state.public_failures, 0)
        public = self.advance(state, self.choice("retry", "reserve"), bounds=bounds)
        for outcome in model.INTERRUPTIONS:
            self.assert_unavailable(public, self.choice(outcome), bounds=bounds)
        self.assertEqual((public.core.consumed, public.reserve_consumed), (2, 1))
        self.assertEqual(self.advance(public, self.choice("worker_verify"), bounds=bounds).core.completed, "valid")

    def test_two_reserved_attempts_cover_one_public_interruption_under_that_assumption(self):
        bounds = model.Bounds(2, 2, 1)
        for outcome in model.INTERRUPTIONS:
            state = self.public_witness(state=self.poison(bounds=bounds), bounds=bounds)
            state = self.trace((self.public_recovery(state, "reserve"), self.choice(outcome)), state=state, bounds=bounds)
            self.assertEqual((state.reserve_consumed, state.public_failures), (1, 1))
            admitted = self.advance(state, self.public_recovery(state, "reserve"), bounds=bounds)
            self.assert_unavailable(admitted, self.choice(outcome), bounds=bounds)
            completed = self.advance(admitted, self.choice("worker_verify"), bounds=bounds)
            self.assertEqual((completed.core.completed, completed.reserve_consumed, completed.public_failures), ("valid", 2, 1))

    def test_free_completed_replay_and_reorg_preserve_all_resource_and_candidate_facts(self):
        state = self.public_witness()
        state = self.trace((self.public_recovery(state, "reserve"), self.choice("worker_verify"),
                            self.choice("claim_inclusion")), state=state)
        self.assertEqual(self.advance(state, self.choice("replay")), state)
        reorged = self.advance(state, self.choice("reorg"))
        self.assertEqual((reorged.general_consumed, reorged.reserve_consumed, reorged.public_failures), (0, 1, 0))
        for field in ("retained", "original", "archive", "completed", "consumed", "possible_exposure",
                      "witness_known", "alice_consumed"):
            self.assertEqual(getattr(reorged.core, field), getattr(state.core, field))
        self.assertEqual(self.advance(reorged, self.choice("replay")), reorged)
        self.assert_unavailable(reorged, self.choice("retry", "reserve"))

    def test_independent_checkers_detect_refunds_and_worker_reclassification(self):
        bounds = model.Bounds(2, 1, 1)
        before = self.public_witness(bounds=bounds)
        choice = self.public_recovery(before, "reserve")
        admitted = self.advance(before, choice, bounds=bounds)
        refunded = replace(admitted, reserve_consumed=0)
        self.assertIn("lane_total_mismatch", model.safety_violations(refunded, bounds=bounds))
        self.assertIn("lane_debit_or_refund_error", model.transition_violations(before, choice, refunded, bounds=bounds))
        relabeled = replace(admitted, pending_public=False)
        self.assertIn("reserve_without_public_worker", model.safety_violations(relabeled, bounds=bounds))
        self.assertIn("admitted_worker_classification_mismatch",
                      model.transition_violations(before, choice, relabeled, bounds=bounds))
        failed = self.advance(admitted, self.choice("worker_fail"), bounds=bounds)
        hidden = replace(failed, public_failures=0)
        self.assertIn("public_failure_accounting_error",
                      model.transition_violations(admitted, self.choice("worker_fail"), hidden, bounds=bounds))

    def test_independent_checkers_detect_peer_reserve_theft_and_authorization_bypass(self):
        before = self.public_witness()
        peer = self.choice("begin", "general", candidate="invalid", source="peer", authenticated=True)
        admitted = self.advance(before, peer)
        stolen = replace(admitted, general_consumed=0, reserve_consumed=1, pending_lane="reserve", pending_public=True)
        self.assertIn("unauthorized_public_worker", model.safety_violations(stolen))
        self.assertIn("unauthorized_reserve_charge",
                      model.transition_violations(before, replace(peer, lane="reserve"), stolen))
        erased = replace(stolen, core=replace(stolen.core, public_authorized=False))
        self.assertIn("unauthorized_reserve_charge", model.safety_violations(erased))

    def test_independent_checkers_retain_core_completion_and_history_constraints(self):
        before = self.public_witness()
        choice = self.public_recovery(before, "reserve")
        admitted = self.advance(before, choice)
        forged = replace(admitted, core=replace(admitted.core, completed="valid", pending=None),
                         pending_lane="", pending_public=False)
        self.assertIn("completion_without_worker_verification", model.transition_violations(before, choice, forged))
        invalid = replace(forged, core=replace(forged.core, completed="invalid", retained="invalid"))
        self.assertIn("invalid_inner_completion", model.safety_violations(invalid))
        failure = self.advance(admitted, self.choice("worker_fail"))
        changed = replace(failure, core=replace(failure.core, original="invalid"))
        self.assertIn("original_candidate_replaced", model.transition_violations(admitted, self.choice("worker_fail"), changed))

    def test_independent_checker_detects_an_outcome_bypassing_the_environment_bound(self):
        bounds = model.Bounds(1, 1, 0)
        before = self.public_witness(bounds=bounds)
        admitted = self.advance(before, self.public_recovery(before, "reserve"), bounds=bounds)
        forged = model.step(admitted, self.choice("worker_cancel"), bounds=model.Bounds(1, 1))
        self.assertIn("public_failure_count_out_of_bounds", model.safety_violations(forged, bounds=bounds))
        self.assertIn("public_failure_environment_bypassed",
                      model.transition_violations(admitted, self.choice("worker_cancel"), forged, bounds=bounds))

    def test_complete_comparison_matrix_preserves_integrity_and_replays_exhaustion_findings(self):
        for general, reserve in ((1, 0), (1, 1), (2, 1), (2, 2)):
            for failures in (None, 0, 1, 2):
                bounds = model.Bounds(general, reserve, failures)
                for policy in model.POLICIES:
                    with self.subTest(bounds=bounds, policy=policy):
                        result = model.explore(bounds=bounds, policy=policy)
                        self.assertTrue(result.complete)
                        self.assertEqual(result.reason, "graph_exhausted")
                        self.assertEqual(result.safety_findings, ())
                        blocked = policy == "shared" or not reserve or failures is None or failures >= reserve
                        self.assertEqual(bool(result.availability_findings), blocked)
                        self.assertEqual(result.status, "counterexample" if blocked else "complete")
                        for finding in result.availability_findings:
                            self.assertEqual(finding.name, "public_recovery_allowance_exhausted")
                            self.assertEqual(self.trace(finding.trace, bounds=bounds, policy=policy), finding.state)
                            self.assertEqual(len(finding.trace), 2 * bounds.total + 2)
                            self.assertEqual(finding.state.core.completed, "")
                            self.assertTrue(finding.state.core.public_authorized)

    def test_every_reachable_authorized_idle_state_has_a_reserved_path_under_failure_bound(self):
        bounds = model.Bounds(2, 2, 1)
        states, _ = self.reachable(bounds=bounds)
        checked = 0
        for state in states:
            if (state.core.completed or state.core.pending is not None
                    or not state.core.public_observed or not state.core.public_authorized):
                continue
            checked += 1
            self.assertLess(state.reserve_consumed, bounds.public_reserve)
            # Explicitly schedule all remaining permitted public interruptions,
            # then one successful outcome. This is a finite path, not fairness.
            while state.public_failures < bounds.public_failure_limit:
                state = self.trace((self.public_recovery(state, "reserve"), self.choice("worker_cancel")),
                                   state=state, bounds=bounds)
            completed = self.trace((self.public_recovery(state, "reserve"), self.choice("worker_verify")),
                                   state=state, bounds=bounds)
            self.assertEqual(completed.core.completed, "valid")
        self.assertGreater(checked, 1)

    def test_unbounded_shared_projection_matches_the_unchanged_baseline_graph(self):
        bounds = model.Bounds(1, 1)
        wrapped, wrapped_edges = self.reachable(bounds=bounds, policy="shared")
        queue = deque([core.State()])
        seen = {queue[0]}
        edges = set()
        while queue:
            state = queue.popleft()
            for action, following in core.successors(state, bounds=core.Bounds(bounds.total)):
                edges.add((state, action, following))
                if following not in seen:
                    seen.add(following)
                    queue.append(following)
        self.assertEqual({state.core for state in wrapped}, seen)
        self.assertEqual(wrapped_edges, edges)

    def test_state_budget_is_incomplete_even_when_a_finding_is_known(self):
        result = model.explore(max_states=1)
        self.assertFalse(result.complete)
        self.assertEqual((result.reason, result.status), ("state_budget_exhausted", "incomplete"))
        full = model.explore(bounds=model.Bounds(1, 1))
        truncated = model.explore(bounds=model.Bounds(1, 1), max_states=full.states - 1)
        self.assertFalse(truncated.complete)
        self.assertTrue(truncated.availability_findings)
        self.assertEqual(truncated.status, "incomplete")

    def test_invalid_parameters_choices_and_state_types_are_rejected(self):
        for bounds in (model.Bounds(True, 1), model.Bounds(0, 1), model.Bounds(64, 1), model.Bounds(1, -1),
                       model.Bounds(1, True), model.Bounds(1, 1, True), model.Bounds(1, 1, -1), model.Bounds(1, 1, 65)):
            with self.assertRaises(ValueError):
                model.explore(bounds=bounds)
        for kwargs in ({"policy": "unknown"}, {"policy": 1}, {"bounds": object()}, {"max_states": True},
                       {"max_states": 0}, {"max_states": 1_000_001}):
            with self.assertRaises(ValueError):
                model.explore(**kwargs)
        for choice in (self.choice("observe_public", "reserve"), self.choice("retry"),
                       self.choice("begin", "shared", candidate="valid", source="peer", authenticated=True),
                       model.Choice(object()), self.choice("worker_verify", candidate="valid")):
            self.assert_unavailable(model.State(), choice)
        for state in (replace(model.State(), general_consumed=True), replace(model.State(), pending_public=1),
                      replace(model.State(), core=object()), object()):
            with self.assertRaises(ValueError):
                model.safety_violations(state)
        model.Bounds(64, 0, 64).validate()

    def test_cli_reports_assumptions_and_distinguishes_counterexample_complete_and_incomplete(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "model_recovery_reserve.py"
        cases = (([], 1, "counterexample"), (["--public-failure-limit", "0"], 0, "complete"),
                 (["--policy", "shared", "--public-failure-limit", "0"], 1, "counterexample"),
                 (["--max-states", "1"], 2, "incomplete"), (["--public-reserve", "-1"], 2, "incomplete"))
        for arguments, expected_code, status in cases:
            result = subprocess.run([sys.executable, "-B", str(script), *arguments],
                                    capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(result.returncode, expected_code)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], status)
            self.assertEqual(result.stderr, "")
            if report["reason"] != "invalid_parameters":
                self.assertIn("no journal implementation or liveness proof", report["scope"])
                self.assertIn("environment", report)


if __name__ == "__main__":
    unittest.main()
