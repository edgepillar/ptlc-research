"""Independent finite traces, not cryptographic or availability guarantees."""

from collections import deque
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts.model_recovery_admission import (
    Action, Bounds, POLICIES, State, availability_violations, explore, safety_violations,
    step, successors, transition_violations,
)


class RecoveryAdmissionModelTests(unittest.TestCase):
    def advance(self, state, action, *, bounds=Bounds(), policy=POLICIES["baseline"]):
        following = step(state, action, bounds=bounds, policy=policy)
        self.assertGreaterEqual(following.consumed, state.consumed)
        self.assertLessEqual(following.consumed, bounds.attempt_limit)
        self.assertLessEqual(following.consumed - state.consumed, 1)
        self.assertTrue(following.alice_consumed)
        if state.possible_exposure:
            self.assertTrue(following.possible_exposure)
        if state.witness_known:
            self.assertTrue(following.witness_known)
        if state.original:
            self.assertEqual(following.original, state.original)
        return following

    def trace(self, actions, *, state=None, bounds=Bounds(), policy=POLICIES["baseline"]):
        result = State() if state is None else state
        for action in actions:
            result = self.advance(result, action, bounds=bounds, policy=policy)
        return result

    def public_witness(self, *, authenticated=False, authorize=True, policy=POLICIES["baseline"]):
        actions = [Action("observe_public", authenticated=authenticated)]
        if authorize:
            actions.append(Action("authorize_public"))
        return self.trace(actions, policy=policy)

    def assert_unavailable(self, state, action, *, bounds=Bounds(), policy=POLICIES["baseline"]):
        before = state
        with self.assertRaises(ValueError):
            step(state, action, bounds=bounds, policy=policy)
        self.assertEqual(state, before)

    def test_authorized_public_valid_witness_recovers_without_any_envelope(self):
        observed = self.public_witness()
        self.assertTrue(observed.public_authorized)
        self.assertFalse(observed.public_authenticated)
        admitted = self.advance(observed, Action("begin", candidate="valid", source="public"))
        self.assertEqual(admitted.consumed, 1)
        self.assertEqual(admitted.retained, "valid")
        self.assertIsNotNone(admitted.pending)
        recovered = self.advance(admitted, Action("worker_verify"))
        self.assertEqual(recovered.completed, "valid")
        self.assertFalse(recovered.retained_authenticated)
        self.assertEqual(recovered.original, "valid")
        self.assertEqual(recovered.archive, "")

    def test_source_authentication_and_inclusion_labels_do_not_authorize_public_recovery(self):
        self.assert_unavailable(State(), Action("begin", candidate="valid", source="public", authenticated=True))
        for authenticated in (False, True):
            state = self.public_witness(authenticated=authenticated, authorize=False)
            state = self.advance(state, Action("claim_inclusion"))
            self.assertTrue(state.claimed_included)
            self.assertFalse(state.public_authorized)
            self.assert_unavailable(state, Action("begin", candidate="valid", source="public",
                                                  authenticated=authenticated))
            self.assertEqual(state.consumed, 0)
            state = self.advance(state, Action("authorize_public"))
            state = self.advance(state, Action("begin", candidate="valid", source="public",
                                               authenticated=authenticated))
            self.assertEqual(self.advance(state, Action("worker_verify")).completed, "valid")

    def test_authenticated_invalid_inner_candidate_never_recovers_in_baseline(self):
        state = self.trace((Action("begin", candidate="invalid", source="peer", authenticated=True),
                            Action("worker_verify")))
        self.assertEqual(state.completed, "")
        self.assertEqual(state.retained, "invalid")
        self.assertTrue(state.retained_authenticated)
        self.assertEqual(state.consumed, 1)
        state = self.trace((Action("retry"), Action("worker_verify")), state=state)
        self.assertEqual(state.completed, "")
        self.assertEqual(state.consumed, 2)

    def test_valid_inner_candidate_does_not_supply_missing_peer_authentication(self):
        self.assert_unavailable(State(), Action("begin", candidate="valid", source="peer"))
        public = self.public_witness()
        self.assert_unavailable(public, Action("begin", candidate="valid", source="peer"))
        self.assert_unavailable(public, Action("begin", candidate="valid", source="public", authenticated=True))
        self.assertEqual(public.consumed, 0)
        completed = self.trace((Action("begin", candidate="valid", source="peer", authenticated=True),
                                Action("worker_verify")))
        self.assertEqual(completed.completed, "valid")

    def test_repeated_authenticated_invalid_candidate_can_exhaust_shared_allowance(self):
        state = self.public_witness()
        state = self.trace((Action("begin", candidate="invalid", source="peer", authenticated=True),
                            Action("worker_fail"), Action("retry"), Action("worker_verify")), state=state)
        self.assertEqual(state.consumed, 2)
        self.assertEqual(state.completed, "")
        self.assertTrue(state.public_authorized)
        self.assertTrue(state.witness_known)
        self.assert_unavailable(state, Action("retry"))
        self.assert_unavailable(state, Action("reconcile", candidate="valid", source="public",
                                              expected_candidate="invalid"))
        self.assertTrue(state.possible_exposure)

    def test_begin_debits_before_worker_and_interruptions_preserve_retained_bytes(self):
        for candidate in ("valid", "invalid"):
            for interruption in ("worker_fail", "worker_cancel", "worker_crash"):
                with self.subTest(candidate=candidate, interruption=interruption):
                    admitted = self.trace((Action("begin", candidate=candidate, source="peer", authenticated=True),))
                    self.assertEqual(admitted.consumed, 1)
                    self.assertEqual(admitted.completed, "")
                    self.assertIsNotNone(admitted.pending)
                    state = self.advance(admitted, Action(interruption))
                    self.assertEqual(state.consumed, 1)
                    self.assertEqual(state.retained, candidate)
                    self.assertEqual(state.original, candidate)
                    self.assertEqual(state.archive, "")
                    self.assertEqual(state.completed, "")
                    self.assertIsNone(state.pending)
                    retried = self.trace((Action("retry"), Action("worker_verify")), state=state)
                    self.assertEqual(retried.consumed, 2)
                    self.assertEqual(retried.completed, "valid" if candidate == "valid" else "")

    def test_pending_worker_owns_one_admitted_attempt_and_blocks_overlapping_recovery(self):
        self.assert_unavailable(State(), Action("worker_verify"))
        state = self.trace((Action("begin", candidate="invalid", source="peer", authenticated=True),))
        for action in (Action("begin", candidate="valid", source="peer", authenticated=True),
                       Action("retry"), Action("replay"),
                       Action("reconcile", candidate="valid", source="peer", authenticated=True,
                              expected_candidate="invalid")):
            self.assert_unavailable(state, action)
        self.assertEqual(state.consumed, 1)
        self.assertTrue(state.alice_consumed)
        state = self.advance(state, Action("worker_cancel"))
        state = self.advance(state, Action("retry"))
        self.assertEqual(state.consumed, 2)
        self.assertIsNotNone(state.pending)
        self.assertTrue(state.alice_consumed)

    def test_independent_checkers_reject_completion_forged_before_verification_and_invalid_inner_result(self):
        before = State()
        begin = Action("begin", candidate="valid", source="peer", authenticated=True)
        admitted = self.advance(before, begin)
        forged = replace(admitted, completed="valid", pending=None, witness_known=True)
        self.assertEqual(safety_violations(forged), ())
        self.assertIn("completion_without_worker_verification", transition_violations(before, begin, forged))
        verified = self.advance(admitted, Action("worker_verify"))
        self.assertEqual(transition_violations(admitted, Action("worker_verify"), verified), ())
        invalid = self.trace((Action("begin", candidate="invalid", source="peer", authenticated=True),))
        invalid = replace(invalid, completed="invalid", pending=None)
        self.assertIn("invalid_inner_completion", safety_violations(invalid))

    def test_independent_edge_checker_rejects_completed_result_changes_during_metadata_or_reorg(self):
        state = self.trace((Action("begin", candidate="invalid", source="peer", authenticated=True),
                            Action("worker_verify"),
                            Action("reconcile", candidate="valid", source="peer", authenticated=True,
                                   expected_candidate="invalid"), Action("worker_verify")))
        for action in (Action("observe_public"), Action("claim_inclusion"), Action("reorg")):
            following = self.advance(state, action)
            self.assertEqual(transition_violations(state, action, following), ())
            for fields in ({"completed": ""}, {"completed": "invalid", "retained": "invalid"},
                           {"retained": "invalid"}, {"retained_authenticated": False}, {"archive": ""}):
                forged = replace(following, **fields)
                self.assertIn("completed_result_changed", transition_violations(state, action, forged))
            state = following

    def test_reconciliation_requires_retained_original_exact_cas_and_different_candidate(self):
        replacement = Action("reconcile", candidate="valid", source="peer", authenticated=True,
                             expected_candidate="invalid")
        self.assert_unavailable(State(), replacement)
        state = self.trace((Action("begin", candidate="invalid", source="peer", authenticated=True),
                            Action("worker_fail")))
        self.assert_unavailable(state, Action("begin", candidate="valid", source="peer", authenticated=True))
        self.assert_unavailable(state, replace(replacement, expected_candidate="valid"))
        self.assert_unavailable(state, replace(replacement, candidate="invalid"))
        pending = self.advance(state, replacement)
        self.assertEqual(pending.consumed, 2)
        self.assertEqual(pending.retained, "invalid")
        self.assertEqual(pending.original, "invalid")
        self.assertEqual(pending.archive, "")
        self.assertEqual(pending.completed, "")
        completed = self.advance(pending, Action("worker_verify"))
        self.assertEqual(completed.completed, "valid")
        self.assertEqual(completed.retained, "valid")
        self.assertEqual(completed.original, "invalid")
        self.assertEqual(completed.archive, "invalid")
        self.assert_unavailable(completed, replacement)

    def test_reconciliation_failure_consumes_shared_budget_without_replacing_or_archiving(self):
        bounds = Bounds(attempt_limit=3)
        for failure in ("worker_fail", "worker_cancel", "worker_crash"):
            with self.subTest(failure=failure):
                state = self.trace((Action("begin", candidate="invalid", source="peer", authenticated=True),
                                    Action("worker_verify")), bounds=bounds)
                replacement = Action("reconcile", candidate="valid", source="peer", authenticated=True,
                                     expected_candidate="invalid")
                state = self.trace((replacement, Action(failure)), state=state, bounds=bounds)
                self.assertEqual(state.consumed, 2)
                self.assertEqual(state.retained, "invalid")
                self.assertEqual(state.original, "invalid")
                self.assertEqual(state.archive, "")
                self.assertEqual(state.completed, "")
                self.assertIsNone(state.pending)
                completed = self.trace((replacement, Action("worker_verify")), state=state, bounds=bounds)
                self.assertEqual(completed.completed, "valid")
                self.assertEqual(completed.consumed, 3)

    def test_completed_exact_replay_is_free_but_new_recovery_attempts_are_sealed(self):
        state = self.trace((Action("begin", candidate="valid", source="peer", authenticated=True),
                            Action("worker_verify")))
        for _ in range(3):
            self.assertEqual(self.advance(state, Action("replay")), state)
        self.assertEqual(state.consumed, 1)
        self.assert_unavailable(state, Action("retry"))
        self.assert_unavailable(state, Action("begin", candidate="valid", source="peer", authenticated=True))
        self.assert_unavailable(State(), Action("replay"))

    def test_reorg_preserves_exposure_witness_completion_and_signer_consumption(self):
        state = self.public_witness()
        state = self.trace((Action("claim_inclusion"), Action("begin", candidate="valid", source="public"),
                            Action("worker_verify")), state=state)
        original = state
        state = self.advance(state, Action("reorg"))
        self.assertFalse(state.claimed_included)
        self.assertTrue(state.reorged)
        for field in ("possible_exposure", "witness_known", "alice_consumed", "consumed",
                      "completed", "retained", "original", "archive"):
            self.assertEqual(getattr(state, field), getattr(original, field))
        self.assertEqual(self.advance(state, Action("replay")), state)

    def test_baseline_exhaustive_search_completes_without_safety_findings(self):
        result = explore()
        self.assertTrue(result.complete)
        self.assertEqual(result.safety_findings, ())
        self.assertGreater(result.states, 1)
        self.assertGreater(result.transitions, 1)
        # Finite local allowances explicitly do not guarantee recovery availability.
        self.assertTrue(result.availability_findings)
        for finding in result.availability_findings:
            state = self.trace(finding.trace)
            self.assertEqual(state, finding.state)
            self.assertEqual(state.completed, "")
            self.assertTrue(state.public_authorized)
            self.assertEqual(state.consumed, Bounds().attempt_limit)

    def shortest_bad_depth(self, policy, bad, maximum_depth):
        queue = deque([(State(), 0)])
        seen = {State()}
        while queue:
            state, depth = queue.popleft()
            if bad(state):
                return depth
            if depth == maximum_depth:
                continue
            for _, following in successors(state, policy=policy):
                if following not in seen:
                    seen.add(following)
                    queue.append((following, depth + 1))
        return None

    def test_authentication_as_inner_validity_mutant_has_replayable_shortest_counterexample(self):
        policy = POLICIES["auth-is-valid"]
        result = explore(policy=policy)
        self.assertTrue(result.complete)
        for finding in result.safety_findings + result.availability_findings:
            self.assertEqual(self.trace(finding.trace, policy=policy), finding.state)
        findings = [finding for finding in result.safety_findings
                    if self.trace(finding.trace, policy=policy).completed == "invalid"]
        self.assertTrue(findings)
        shortest = min(findings, key=lambda finding: len(finding.trace))
        self.assertEqual(len(shortest.trace), 2)
        self.assertEqual(self.shortest_bad_depth(policy, lambda state: state.completed == "invalid", 2), 2)
        state = self.trace(shortest.trace, policy=policy)
        self.assertTrue(state.retained_authenticated)
        self.assertEqual(self.trace(shortest.trace).completed, "")

    def test_universal_envelope_mutant_has_replayable_shortest_public_recovery_block(self):
        policy = POLICIES["universal-envelope"]
        result = explore(policy=policy)
        self.assertTrue(result.complete)
        for finding in result.safety_findings + result.availability_findings:
            self.assertEqual(self.trace(finding.trace, policy=policy), finding.state)
        def unbudgeted_public_block(state):
            return (state.public_observed and state.public_authorized and not state.public_authenticated
                    and state.consumed == 0 and state.retained == "" and state.completed == "")
        findings = [finding for finding in result.availability_findings
                    if unbudgeted_public_block(self.trace(finding.trace, policy=policy))]
        self.assertTrue(findings)
        shortest = min(findings, key=lambda finding: len(finding.trace))
        self.assertEqual(len(shortest.trace), 2)
        self.assertEqual(self.shortest_bad_depth(policy, unbudgeted_public_block, 2), 2)
        blocked = self.trace(shortest.trace, policy=policy)
        begin = Action("begin", candidate="valid", source="public")
        self.assert_unavailable(blocked, begin, policy=policy)
        baseline = self.trace(shortest.trace)
        self.assertEqual(self.trace((begin, Action("worker_verify")), state=baseline).completed, "valid")

    def test_envelope_gate_is_not_an_availability_finding_when_exact_valid_retry_remains(self):
        policy = POLICIES["universal-envelope"]
        state = self.trace((Action("begin", candidate="valid", source="peer", authenticated=True),
                            Action("worker_fail"), Action("observe_public"), Action("authorize_public")),
                           policy=policy)
        self.assertFalse(state.public_authenticated)
        self.assertEqual(state.retained, "valid")
        self.assertEqual(state.consumed, 1)
        self.assertEqual(availability_violations(state, policy=policy), ())
        self.assertEqual(self.trace((Action("retry"), Action("worker_verify")), state=state,
                                    policy=policy).completed, "valid")
        exhausted = self.trace((Action("retry"), Action("worker_fail")), state=state, policy=policy)
        self.assertEqual(exhausted.consumed, 2)
        self.assertEqual(availability_violations(exhausted, policy=policy), ("recovery_allowance_exhausted",))

    def test_capped_search_is_explicitly_incomplete_not_a_successful_empty_report(self):
        result = explore(max_states=1)
        self.assertFalse(result.complete)
        self.assertTrue(result.reason)
        self.assertEqual(result.states, 1)
        self.assertEqual(result.safety_findings, ())
        partial = explore(policy=POLICIES["auth-is-valid"], max_states=100)
        self.assertFalse(partial.complete)
        self.assertEqual(partial.status, "incomplete")
        self.assertEqual(partial.reason, "state_budget_exhausted")
        self.assertTrue(partial.safety_findings)
        self.assertEqual(self.trace(partial.safety_findings[0].trace,
                                    policy=POLICIES["auth-is-valid"]).completed, "invalid")

    def test_invalid_bounds_and_caps_reject_instead_of_reporting_success(self):
        class IntegerSubclass(int):
            pass
        for value in (True, False, 0, -1, 65, 1.0, "2", None, IntegerSubclass(2)):
            with self.subTest(attempt_limit=repr(value)), self.assertRaises((TypeError, ValueError)):
                explore(bounds=Bounds(attempt_limit=value))
        for value in (True, False, 0, -1, 1_000_001, 1.0, "100", None, IntegerSubclass(100)):
            with self.subTest(max_states=repr(value)), self.assertRaises((TypeError, ValueError)):
                explore(max_states=value)

    def test_cli_distinguishes_complete_counterexamples_invalid_bounds_and_truncation(self):
        script = Path(__file__).resolve().parents[1] / "scripts/model_recovery_admission.py"
        cases = (((), 1, "counterexample", True),
                 (("--attempt-limit", "0"), 2, "incomplete", False),
                 (("--max-states", "0"), 2, "incomplete", False),
                 (("--max-states", "1"), 2, "incomplete", False),
                 (("--policy", "auth-is-valid", "--max-states", "100"), 2, "incomplete", False))
        for arguments, exit_code, status, complete in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, "-B", str(script), *arguments],
                                        capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, exit_code)
                self.assertEqual(result.stderr, "")
                report = json.loads(result.stdout)
                self.assertEqual(report["status"], status)
                self.assertIs(report["complete"], complete)
                if complete:
                    self.assertEqual(report["safety_findings"], [])
                    self.assertTrue(report["availability_findings"])
                if "auth-is-valid" in arguments:
                    self.assertTrue(report["safety_findings"])
                    self.assertEqual(report["reason"], "state_budget_exhausted")


if __name__ == "__main__":
    unittest.main()
