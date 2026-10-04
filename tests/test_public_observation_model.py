"""Exact public authority, invalid rejection and bounded recovery experiments."""

from collections import deque
from dataclasses import replace
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_public_observation as model
from scripts import model_recovery_admission as core
from scripts import model_recovery_reserve as reserve


class PublicObservationModelTests(unittest.TestCase):
    def choice(self, kind, lane="", **fields):
        return model.Choice(core.Action(kind, **fields), lane)

    def advance(self, state, choice, *, bounds=model.Bounds(1, 1, 0), policy="reserved", public_policy="authorized-bytes"):
        following = model.step(state, choice, bounds=bounds, policy=policy, public_policy=public_policy)
        self.assertEqual(model.safety_violations(following, bounds=bounds, policy=policy, public_policy=public_policy), ())
        self.assertEqual(model.transition_violations(state, choice, following, bounds=bounds,
                                                     policy=policy, public_policy=public_policy), ())
        return following

    def trace(self, choices, *, state=None, **parameters):
        state = model.State() if state is None else state
        for choice in choices:
            state = self.advance(state, choice, **parameters)
        return state

    def witness(self, candidate, *, state=None, authenticated=False, authorize=True, **parameters):
        choices = [self.choice("observe_public", candidate=candidate, authenticated=authenticated)]
        if authorize:
            choices.append(self.choice("authorize_public", candidate=candidate))
        return self.trace(choices, state=state, **parameters)

    def public_recovery(self, state, candidate, lane):
        if state.core.retained == candidate:
            return self.choice("retry", lane)
        observed = model.observation(state, candidate)
        fields = dict(candidate=candidate, source="public", authenticated=observed.authenticated)
        if state.core.retained:
            fields["expected_candidate"] = state.core.retained
            return self.choice("reconcile", lane, **fields)
        return self.choice("begin", lane, **fields)

    def assert_unavailable(self, state, choice, *, bounds=model.Bounds(1, 1, 0), policy="reserved", public_policy="authorized-bytes"):
        before = state
        with self.assertRaises(ValueError):
            model.step(state, choice, bounds=bounds, policy=policy, public_policy=public_policy)
        self.assertEqual(state, before)

    @staticmethod
    @lru_cache(maxsize=None)
    def search(bounds, policy, public_policy):
        return model.explore(bounds=bounds, policy=policy, public_policy=public_policy)

    def reachable(self, *, bounds=model.Bounds(1, 1, 0), policy="reserved", public_policy="authorized-bytes", valid_subset=False):
        queue = deque([model.State()])
        seen = {queue[0]}
        edges = set()
        while queue:
            state = queue.popleft()
            for choice, following in model.successors(state, bounds=bounds, policy=policy, public_policy=public_policy):
                if valid_subset and choice.action.kind in model.EXTERNAL and choice.action.candidate == "invalid":
                    continue
                edges.add((state, choice, following))
                if following not in seen:
                    seen.add(following)
                    queue.append(following)
        return seen, edges

    def exhausted_without_interruption(self, *, bounds=model.Bounds(1, 1, 0)):
        state = self.witness("valid", bounds=bounds)
        state = self.witness("invalid", state=state, bounds=bounds)
        state = self.trace((self.choice("begin", "general", candidate="invalid", source="peer", authenticated=True),
                            self.choice("worker_verify")), state=state, bounds=bounds)
        for _ in range(bounds.public_reserve):
            state = self.trace((self.choice("retry", "reserve"), self.choice("worker_verify")), state=state, bounds=bounds)
        return state

    def test_invalid_public_candidate_is_not_relabelled_as_an_authenticated_peer(self):
        for authenticated in (False, True):
            state = self.witness("invalid", authenticated=authenticated)
            admitted = self.advance(state, self.public_recovery(state, "invalid", "reserve"))
            self.assertEqual(admitted.core.pending.source, "public")
            self.assertTrue(admitted.core.pending.locally_authorized)
            self.assertEqual(admitted.core.pending.authenticated, authenticated)
            rejected = self.advance(admitted, self.choice("worker_verify"))
            self.assertEqual((rejected.core.retained, rejected.core.original, rejected.core.completed), ("invalid", "invalid", ""))
            self.assertEqual((rejected.reserve_consumed, rejected.reserve_rejections, rejected.public_failures,
                              rejected.worker_interruptions), (1, 1, 0, 0))
            self.assertFalse(rejected.core.public_observed)
            self.assertFalse(rejected.core.witness_known)

    def test_zero_interruption_rejections_can_block_a_known_authorized_valid_witness(self):
        state = self.exhausted_without_interruption()
        self.assertEqual((state.general_consumed, state.reserve_consumed, state.reserve_rejections), (1, 1, 1))
        self.assertEqual((state.public_failures, state.worker_interruptions), (0, 0))
        self.assertTrue(state.core.witness_known)
        self.assertEqual(state.core.completed, "")
        self.assertIn("invalid_public_rejection_without_interruption", model.availability_violations(state, bounds=model.Bounds(1, 1, 0)))
        for lane in ("general", "reserve"):
            self.assert_unavailable(state, self.public_recovery(state, "valid", lane))

    def test_repeated_same_invalid_public_bytes_can_drain_a_larger_reserve(self):
        bounds = model.Bounds(1, 2, 0)
        state = self.exhausted_without_interruption(bounds=bounds)
        self.assertEqual((state.reserve_consumed, state.reserve_rejections, state.worker_interruptions), (2, 2, 0))
        self.assertEqual((state.core.original, state.core.retained, state.core.archive), ("invalid", "invalid", ""))
        self.assert_unavailable(state, self.public_recovery(state, "valid", "reserve"), bounds=bounds)

    def test_late_valid_observation_keeps_separate_authority_and_does_not_refill_allowance(self):
        state = self.witness("invalid")
        state = self.trace((self.public_recovery(state, "invalid", "reserve"), self.choice("worker_verify"),
                            self.choice("retry", "general"), self.choice("worker_verify")), state=state)
        self.assertEqual(model.availability_violations(state, bounds=model.Bounds(1, 1, 0)), ())
        before = state
        state = self.witness("valid", state=state, authorize=False)
        self.assertTrue(state.invalid.authorized)
        self.assertFalse(state.core.public_authorized)
        self.assertEqual((state.general_consumed, state.reserve_consumed, state.reserve_rejections),
                         (before.general_consumed, before.reserve_consumed, before.reserve_rejections))
        state = self.advance(state, self.choice("authorize_public", candidate="valid"))
        self.assertIn("invalid_public_rejection_without_interruption", model.availability_violations(state, bounds=model.Bounds(1, 1, 0)))

    def test_remaining_reserve_recovers_valid_replacement_and_archives_the_invalid_original(self):
        bounds = model.Bounds(1, 2, 0)
        state = self.witness("invalid", bounds=bounds)
        state = self.trace((self.public_recovery(state, "invalid", "reserve"), self.choice("worker_verify")), state=state, bounds=bounds)
        state = self.witness("valid", state=state, bounds=bounds)
        admitted = self.advance(state, self.public_recovery(state, "valid", "reserve"), bounds=bounds)
        self.assertEqual((admitted.core.retained, admitted.core.archive, admitted.core.completed), ("invalid", "", ""))
        completed = self.advance(admitted, self.choice("worker_verify"), bounds=bounds)
        self.assertEqual((completed.core.original, completed.core.retained, completed.core.archive, completed.core.completed),
                         ("invalid", "valid", "invalid", "valid"))
        self.assertEqual((completed.reserve_consumed, completed.reserve_rejections, completed.public_failures), (2, 1, 0))

    def test_authentication_and_claimed_inclusion_never_supply_missing_exact_authority(self):
        for candidate in core.VALIDITY:
            state = self.witness(candidate, authenticated=True, authorize=False)
            state = self.advance(state, self.choice("claim_inclusion", candidate=candidate))
            self.assert_unavailable(state, self.public_recovery(state, candidate, "reserve"))
            self.assertEqual(state.core.consumed, 0)
            state = self.advance(state, self.choice("authorize_public", candidate=candidate))
            self.assertEqual(self.advance(state, self.public_recovery(state, candidate, "reserve")).reserve_consumed, 1)

    def test_authority_for_one_identity_does_not_authorize_the_other_or_a_mismatched_envelope_flag(self):
        state = self.witness("invalid", authenticated=True)
        state = self.witness("valid", state=state, authorize=False)
        self.assert_unavailable(state, self.public_recovery(state, "valid", "reserve"))
        invalid = self.public_recovery(state, "invalid", "reserve")
        self.assert_unavailable(state, replace(invalid, action=replace(invalid.action, authenticated=False)))
        self.assert_unavailable(state, self.choice("begin", "reserve", candidate="invalid", source="peer", authenticated=True))
        self.assert_unavailable(state, self.choice("observe_public", candidate="invalid", authenticated=False))
        self.assertEqual(self.advance(state, invalid).core.pending.candidate, "invalid")

    def test_invalid_public_replacement_rejection_preserves_retained_valid_bytes(self):
        state = self.trace((self.choice("begin", "general", candidate="valid", source="peer", authenticated=True),
                            self.choice("worker_fail")))
        state = self.witness("invalid", state=state)
        state = self.trace((self.public_recovery(state, "invalid", "reserve"), self.choice("worker_verify")), state=state)
        self.assertEqual((state.core.original, state.core.retained, state.core.archive, state.core.completed), ("valid", "valid", "", ""))
        self.assertEqual((state.public_failures, state.worker_interruptions, state.reserve_rejections), (0, 1, 1))
        self.assertFalse(state.core.witness_known)

    def test_zero_public_interruption_bound_still_allows_a_normal_invalid_verdict(self):
        state = self.witness("invalid")
        admitted = self.advance(state, self.public_recovery(state, "invalid", "reserve"))
        for outcome in model.INTERRUPTIONS:
            self.assert_unavailable(admitted, self.choice(outcome))
        rejected = self.advance(admitted, self.choice("worker_verify"))
        self.assertEqual((rejected.reserve_rejections, rejected.public_failures, rejected.worker_interruptions), (1, 0, 0))

    def test_each_interruption_consumes_reserve_without_becoming_an_invalid_verdict(self):
        bounds = model.Bounds(1, 1, 1)
        for outcome in model.INTERRUPTIONS:
            state = self.witness("invalid", bounds=bounds)
            state = self.trace((self.public_recovery(state, "invalid", "reserve"), self.choice(outcome)), state=state, bounds=bounds)
            self.assertEqual((state.reserve_consumed, state.public_failures, state.worker_interruptions, state.reserve_rejections), (1, 1, 1, 0))
            self.assertEqual(state.core.retained, "invalid")

    def test_ideal_filter_is_a_stronger_explicit_premise_not_a_math_or_authority_result(self):
        state = self.witness("invalid")
        for lane in ("general", "reserve"):
            self.assert_unavailable(state, self.public_recovery(state, "invalid", lane), public_policy="ideal-valid")
        pending = self.advance(state, self.public_recovery(state, "invalid", "reserve"))
        self.assertIn("ideal_public_validity_premise_bypassed", model.safety_violations(pending, bounds=model.Bounds(1, 1, 0), public_policy="ideal-valid"))
        self.assertIn("ideal_public_validity_premise_bypassed", model.transition_violations(
            state, self.public_recovery(state, "invalid", "reserve"), pending, bounds=model.Bounds(1, 1, 0), public_policy="ideal-valid"))

    def test_pending_admission_and_wrong_comparison_block_replacement_without_an_extra_debit(self):
        bounds = model.Bounds(1, 2, 0)
        state = self.witness("invalid", bounds=bounds)
        pending = self.advance(state, self.public_recovery(state, "invalid", "reserve"), bounds=bounds)
        pending = self.witness("valid", state=pending, bounds=bounds)
        for lane in ("general", "reserve"):
            self.assert_unavailable(pending, self.public_recovery(pending, "valid", lane), bounds=bounds)
        rejected = self.advance(pending, self.choice("worker_verify"), bounds=bounds)
        replacement = self.public_recovery(rejected, "valid", "reserve")
        self.assert_unavailable(rejected, replace(replacement, action=replace(replacement.action, expected_candidate="valid")), bounds=bounds)
        self.assertEqual((rejected.core.consumed, rejected.reserve_consumed), (1, 1))
        self.assertEqual(self.trace((replacement, self.choice("worker_verify")), state=rejected, bounds=bounds).core.completed, "valid")

    def test_completed_replay_and_both_claimed_reorgs_preserve_candidate_and_resource_facts(self):
        bounds = model.Bounds(1, 2, 0)
        state = self.witness("invalid", bounds=bounds)
        state = self.trace((self.public_recovery(state, "invalid", "reserve"), self.choice("worker_verify")), state=state, bounds=bounds)
        state = self.witness("valid", state=state, bounds=bounds)
        state = self.trace((self.public_recovery(state, "valid", "reserve"), self.choice("worker_verify")), state=state, bounds=bounds)
        sealed = state.core
        for candidate in core.VALIDITY:
            state = self.trace((self.choice("claim_inclusion", candidate=candidate), self.choice("reorg", candidate=candidate)),
                               state=state, bounds=bounds)
            self.assertEqual((state.core.original, state.core.retained, state.core.archive, state.core.completed, state.core.consumed),
                             (sealed.original, sealed.retained, sealed.archive, sealed.completed, sealed.consumed))
            self.assertTrue(model.observation(state, candidate).authorized)
            self.assertEqual(self.advance(state, self.choice("replay"), bounds=bounds), state)
        self.assertEqual((state.reserve_consumed, state.reserve_rejections, state.worker_interruptions), (2, 1, 0))

    def test_independent_checkers_detect_automatic_authority_and_false_witness_knowledge(self):
        bounds = model.Bounds(1, 1, 0)
        before = model.State()
        for candidate in core.VALIDITY:
            choice = self.choice("observe_public", candidate=candidate)
            following = self.advance(before, choice)
            forged = (replace(following, core=replace(following.core, public_authorized=True)) if candidate == "valid"
                      else replace(following, invalid=replace(following.invalid, authorized=True)))
            self.assertIn("public_external_event_mismatch", model.transition_violations(before, choice, forged, bounds=bounds))
        choice = self.choice("observe_public", candidate="invalid")
        following = self.advance(before, choice)
        forged = replace(following, core=replace(following.core, witness_known=True))
        self.assertIn("witness_knowledge_evidence_mismatch", model.safety_violations(forged, bounds=bounds))
        self.assertIn("witness_knowledge_without_valid_evidence", model.transition_violations(before, choice, forged, bounds=bounds))
        unrelated = replace(following, core=replace(following.core, public_observed=True, witness_known=True))
        self.assertIn("unrelated_public_observation_changed", model.transition_violations(before, choice, unrelated, bounds=bounds))

    def test_independent_checkers_detect_refunds_hidden_rejections_and_interruption_bound_bypass(self):
        bounds = model.Bounds(1, 1, 0)
        before = self.witness("invalid")
        choice = self.public_recovery(before, "invalid", "reserve")
        admitted = self.advance(before, choice)
        refunded = replace(admitted, reserve_consumed=0)
        self.assertIn("lane_total_mismatch", model.safety_violations(refunded, bounds=bounds))
        self.assertIn("admission_debit_or_refund_error", model.transition_violations(before, choice, refunded, bounds=bounds))
        relabeled = replace(admitted, pending_public=False)
        self.assertIn("public_worker_classification_mismatch", model.safety_violations(relabeled, bounds=bounds))
        stolen = replace(admitted, core=replace(admitted.core, pending=replace(admitted.core.pending, source="peer", authenticated=True)))
        self.assertIn("unauthorized_public_worker", model.safety_violations(stolen, bounds=bounds))
        rejected = self.advance(admitted, self.choice("worker_verify"))
        hidden = replace(rejected, reserve_rejections=0)
        self.assertIn("worker_outcome_accounting_error", model.transition_violations(admitted, self.choice("worker_verify"), hidden, bounds=bounds))
        erased = replace(rejected, invalid=replace(rejected.invalid, authorized=False))
        self.assertIn("reserve_without_retained_public_authority", model.safety_violations(erased, bounds=bounds))
        interrupted = model.step(admitted, self.choice("worker_cancel"), bounds=model.Bounds(1, 1, 1))
        self.assertIn("worker_outcome_count_out_of_bounds", model.safety_violations(interrupted, bounds=bounds))
        self.assertIn("public_failure_environment_bypassed", model.transition_violations(admitted, self.choice("worker_cancel"), interrupted, bounds=bounds))

    def test_independent_checkers_reject_premature_invalid_completion_and_lost_original_history(self):
        bounds = model.Bounds(1, 1, 0)
        before = self.witness("valid")
        choice = self.public_recovery(before, "valid", "reserve")
        admitted = self.advance(before, choice)
        denied = replace(admitted, core=replace(admitted.core, pending=None), pending_lane="", pending_public=False)
        self.assertIn("completion_verdict_mismatch", model.transition_violations(admitted, self.choice("worker_verify"), denied, bounds=bounds))
        forged = replace(admitted, core=replace(admitted.core, completed="valid", pending=None), pending_lane="", pending_public=False)
        self.assertIn("completion_without_worker_verification", model.transition_violations(before, choice, forged, bounds=bounds))
        invalid = self.witness("invalid")
        invalid = self.advance(invalid, self.public_recovery(invalid, "invalid", "reserve"))
        forged = replace(invalid, core=replace(invalid.core, completed="invalid", pending=None), pending_lane="", pending_public=False)
        self.assertIn("invalid_inner_completion", model.safety_violations(forged, bounds=bounds))
        both = self.witness("invalid", state=before)
        selected = self.public_recovery(both, "invalid", "reserve")
        substituted = self.advance(both, self.public_recovery(both, "valid", "reserve"))
        self.assertEqual(model.safety_violations(substituted, bounds=bounds), ())
        self.assertIn("admitted_candidate_binding_mismatch", model.transition_violations(both, selected, substituted, bounds=bounds))
        self.assertIn("worker_outcome_without_admission", model.transition_violations(before, self.choice("worker_verify"), before, bounds=bounds))
        failed = model.step(invalid, self.choice("worker_fail"), bounds=model.Bounds(1, 1, 1))
        changed = replace(failed, core=replace(failed.core, original="valid"))
        self.assertIn("original_candidate_replaced", model.transition_violations(invalid, self.choice("worker_fail"), changed,
                                                                                 bounds=model.Bounds(1, 1, 1)))

    def test_complete_policy_comparisons_replay_findings_and_separate_ideal_filter_from_authority(self):
        cases = [(model.Bounds(1, 1, 0), policy, public_policy) for policy in reserve.POLICIES
                 for public_policy in model.PUBLIC_POLICIES]
        cases += [(model.Bounds(1, 2, 1), "reserved", public_policy) for public_policy in model.PUBLIC_POLICIES]
        for bounds, policy, public_policy in cases:
            with self.subTest(bounds=bounds, policy=policy, public_policy=public_policy):
                result = self.search(bounds, policy, public_policy)
                self.assertTrue(result.complete)
                self.assertEqual(result.reason, "graph_exhausted")
                self.assertEqual(result.safety_findings, ())
                blocked = policy == "shared" or public_policy == "authorized-bytes"
                self.assertEqual(bool(result.availability_findings), blocked)
                self.assertEqual(result.status, "counterexample" if blocked else "complete")
                names = {finding.name for finding in result.availability_findings}
                strict = policy == "reserved" and public_policy == "authorized-bytes"
                self.assertEqual("invalid_public_rejection_without_interruption" in names, strict)
                for finding in result.availability_findings:
                    self.assertEqual(self.trace(finding.trace, bounds=bounds, policy=policy, public_policy=public_policy), finding.state)
                    self.assertEqual(finding.state.core.consumed, bounds.total)
                    self.assertEqual(finding.state.core.completed, "")
                    self.assertTrue(finding.state.core.public_authorized)
                    if finding.name == "invalid_public_rejection_without_interruption":
                        self.assertEqual(len(finding.trace), 2 * bounds.total + 4)
                        self.assertTrue(all(choice.action.kind not in model.INTERRUPTIONS for choice in finding.trace))
                        self.assertEqual((finding.state.worker_interruptions, finding.state.public_failures), (0, 0))
                        self.assertGreater(finding.state.reserve_rejections, 0)

    def test_valid_observation_subset_projects_to_the_unchanged_reserve_state_and_edge_graph(self):
        bounds = model.Bounds(1, 1, 0)
        states, edges = self.reachable(bounds=bounds, public_policy="ideal-valid", valid_subset=True)

        def project(state):
            self.assertEqual(state.invalid, model.Observation())
            self.assertEqual(state.reserve_rejections, 0)
            return reserve.State(**{name: getattr(state, name) for name in reserve.State.__dataclass_fields__})

        def project_choice(choice):
            if choice.action.kind in model.EXTERNAL:
                self.assertEqual(choice.action.candidate, "valid")
                return replace(choice, action=replace(choice.action, candidate=""))
            return choice

        projected_states = {project(state) for state in states}
        projected_edges = {(project(before), project_choice(choice), project(after)) for before, choice, after in edges}
        queue = deque([reserve.State()])
        old_states = {queue[0]}
        old_edges = set()
        while queue:
            state = queue.popleft()
            for choice, following in reserve.successors(state, bounds=bounds):
                old_edges.add((state, choice, following))
                if following not in old_states:
                    old_states.add(following)
                    queue.append(following)
        self.assertEqual(projected_states, old_states)
        self.assertEqual(projected_edges, old_edges)

    def test_every_reachable_ideal_filtered_idle_authorized_state_has_a_valid_reserved_path(self):
        bounds = model.Bounds(1, 1, 0)
        states, _ = self.reachable(bounds=bounds, public_policy="ideal-valid")
        checked = 0
        for state in states:
            if (state.core.completed or state.core.pending is not None
                    or not state.core.public_observed or not state.core.public_authorized):
                continue
            checked += 1
            self.assertLess(state.reserve_consumed, bounds.public_reserve)
            completed = self.trace((self.public_recovery(state, "valid", "reserve"), self.choice("worker_verify")),
                                   state=state, bounds=bounds, public_policy="ideal-valid")
            self.assertEqual(completed.core.completed, "valid")
        self.assertGreater(checked, 1)

    def test_state_budget_remains_incomplete_when_it_retains_a_concrete_counterexample(self):
        bounds = model.Bounds(1, 1, 0)
        first = model.explore(bounds=bounds, max_states=1)
        self.assertEqual((first.complete, first.status, first.reason), (False, "incomplete", "state_budget_exhausted"))
        full = self.search(bounds, "reserved", "authorized-bytes")
        truncated = model.explore(bounds=bounds, max_states=full.states - 1)
        self.assertFalse(truncated.complete)
        self.assertEqual(truncated.status, "incomplete")
        self.assertTrue(truncated.availability_findings)
        self.assertTrue(any(finding.name == "invalid_public_rejection_without_interruption" for finding in truncated.availability_findings))

    def test_malformed_bounds_identity_fields_and_state_types_are_rejected(self):
        for kwargs in ({"bounds": model.Bounds(True, 1)}, {"bounds": model.Bounds(64, 1)}, {"public_policy": True},
                       {"public_policy": "unknown"}, {"max_states": True}, {"max_states": 0}, {"policy": "unknown"}):
            with self.assertRaises(ValueError):
                model.explore(**kwargs)
        for choice in (self.choice("observe_public"), self.choice("observe_public", candidate="other"),
                       self.choice("authorize_public", candidate="invalid", authenticated=True),
                       self.choice("claim_inclusion", candidate="valid", source="public"),
                       self.choice("retry"), self.choice("reorg", "reserve", candidate="invalid"), model.Choice(object())):
            self.assert_unavailable(model.State(), choice)
        for state in (replace(model.State(), reserve_rejections=True), replace(model.State(), invalid=object()),
                      replace(model.State(), invalid=model.Observation(observed=1)), replace(model.State(), core=object())):
            with self.assertRaises(ValueError):
                model.safety_violations(state)
        unauthorized = replace(model.State(), invalid=model.Observation(authorized=True))
        self.assertIn("public_metadata_without_observation", model.safety_violations(unauthorized))
        with self.assertRaises(ValueError):
            model.observation(model.State(), "unknown")

    def test_cli_names_the_validity_premise_and_reports_complete_counterexample_and_incomplete(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "model_public_observation.py"
        common = ["--general-limit", "1", "--public-reserve", "1", "--public-failure-limit", "0"]
        cases = (([], 1, "counterexample"), (["--public-policy", "ideal-valid"], 0, "complete"),
                 (["--max-states", "1"], 2, "incomplete"), (["--public-reserve", "64"], 2, "incomplete"))
        for flags, code, status in cases:
            result = subprocess.run([sys.executable, "-B", str(script), *common, *flags],
                                    capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(result.returncode, code)
            self.assertEqual(result.stderr, "")
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], status)
            if report["reason"] != "invalid_parameters":
                self.assertIn("excludes mathematical rejection", report["environment"])
                self.assertIn("no trust source or liveness proof", report["scope"])
                self.assertIn(report["public_policy"], model.PUBLIC_POLICIES)


if __name__ == "__main__":
    unittest.main()
