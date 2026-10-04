"""Counterexamples and conditional safety of an ideal external authority model."""

from collections import deque
from dataclasses import replace
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_observation_authority as model


@lru_cache(maxsize=None)
def comparison(policy):
    return model.explore(policy=policy)


class ObservationAuthorityModelTests(unittest.TestCase):
    def action(self, kind, actor=-1, other=-1, **fields):
        return model.Action(kind, actor, other, **fields)

    def trace(self, actions, *, state=None, policy="ideal-dispatch", bounds=model.Bounds()):
        state = model.State() if state is None else state
        for action in actions:
            state = model.step(state, action, policy=policy, bounds=bounds)
        return state

    def unavailable(self, state, action, **parameters):
        with self.assertRaises(ValueError):
            model.step(state, action, **parameters)

    def test_local_closed_empty_history_restore_replenishes_quota(self):
        state = self.trace((self.action("reserve", 0), self.action("start", 0),
                            self.action("finish_normal", 0), self.action("restore_empty", 0),
                            self.action("reserve", 0), self.action("start", 0)), policy="local")
        self.assertEqual(len(state.entries), 2)
        self.assertEqual(state.actors[0].used, 1)
        self.assertIn("scope_worker_entry_quota_exceeded", model.safety_violations(state, policy="local"))

    def test_cached_head_check_can_expire_before_admission_and_entry(self):
        state = self.trace((self.action("check", 0), self.action("check", 1),
                            self.action("reserve", 0), self.action("start", 0),
                            self.action("finish_normal", 0), self.action("reserve", 1),
                            self.action("start", 1)), policy="read-check")
        self.assertEqual((state.authority.revision, len(state.entries)), (1, 2))
        self.assertTrue(state.entries[-1].stale)
        self.assertEqual(set(model.safety_violations(state, policy="read-check")),
                         {"scope_worker_entry_quota_exceeded", "stale_worker_entry"})

    def test_charged_receipt_copy_can_start_more_than_one_worker(self):
        state = self.trace((self.action("reserve", 0), self.action("copy", 1, 0),
                            self.action("start", 0), self.action("start", 1)), policy="authority-charge")
        self.assertEqual(state.authority.consumed, 1)
        self.assertEqual([entry.ticket for entry in state.entries], [1, 1])
        self.assertIn("receipt_reused_for_multiple_entries",
                      model.safety_violations(state, policy="authority-charge"))
        self.assertIn("scope_worker_entry_quota_exceeded",
                      model.safety_violations(state, policy="authority-charge"))

    def test_charged_local_receipt_can_start_after_authority_recovery(self):
        state = self.trace((self.action("reserve", 0), self.action("recover"),
                            self.action("start", 0)), policy="authority-charge")
        self.assertEqual((state.authority.consumed, state.authority.unknown), (1, (1,)))
        self.assertTrue(state.entries[0].stale)
        self.assertEqual(model.safety_violations(state, policy="authority-charge"), ("stale_worker_entry",))

    def test_ideal_dispatcher_spends_copied_receipt_once(self):
        state = self.trace((self.action("reserve", 0), self.action("copy", 1, 0), self.action("start", 0)))
        self.unavailable(state, self.action("start", 1))
        self.assertEqual((state.authority.consumed, state.authority.dispatched, len(state.entries)), (1, (1,), 1))
        self.assertEqual(model.safety_violations(state), ())

    def test_ideal_authority_rejects_old_history_and_sync_does_not_refund(self):
        state = self.trace((self.action("reserve", 0), self.action("start", 0),
                            self.action("finish_normal", 0), self.action("restore_empty", 0)))
        self.assertEqual((state.actors[0].view, state.authority.revision), (0, 2))
        self.unavailable(state, self.action("reserve", 0))
        state = self.trace((self.action("sync", 0),), state=state)
        self.assertEqual((state.actors[0].used, state.authority.consumed), (1, 1))
        self.unavailable(state, self.action("reserve", 0))
        self.assertEqual(state.authority.normal, (1,))

    def test_lost_receipt_can_exhaust_quota_without_any_worker_entry(self):
        state = self.trace((self.action("reserve", 0), self.action("lose_receipt", 0), self.action("recover")))
        self.assertEqual((state.authority.consumed, state.authority.unknown, state.entries), (1, (1,), ()))
        self.assertEqual(state.authority.normal, ())
        self.assertIn("exhausted_without_retained_normal", model.boundary_findings(state))
        self.unavailable(state, self.action("reserve", 0))

    def test_authority_loss_refuses_reservation_and_dispatch_without_fallback(self):
        state = self.trace((self.action("service_loss"),))
        self.unavailable(state, self.action("reserve", 0))
        self.assertEqual(state.entries, ())
        pending = self.trace((self.action("reserve", 0), self.action("service_loss")))
        self.unavailable(pending, self.action("start", 0))
        self.assertEqual((pending.authority.consumed, pending.entries), (1, ()))
        self.assertIn("authority_availability_is_an_external_premise", model.boundary_findings(pending))

    def test_authority_loss_after_normal_event_preserves_pending_for_unknown_recovery(self):
        state = self.trace((self.action("reserve", 0), self.action("start", 0),
                            self.action("service_loss"), self.action("finish_normal", 0)))
        self.assertEqual((state.lost_results, state.authority.active, state.authority.normal), (1, 1, ()))
        self.assertEqual(state.authority.unknown, ())
        self.unavailable(state, self.action("recover"))
        state = self.trace((self.action("service_return"), self.action("recover")), state=state)
        self.assertEqual((state.authority.consumed, state.authority.unknown, state.authority.normal), (1, (1,), ()))
        self.assertEqual(len(state.entries), 1)

    def test_history_recovery_fences_old_result_without_containing_running_work(self):
        bounds = model.Bounds(2, 3)
        state = self.trace((self.action("reserve", 0), self.action("start", 0), self.action("recover"),
                            self.action("sync", 1), self.action("reserve", 1), self.action("start", 1)), bounds=bounds)
        self.assertEqual(state.peak_running, 2)
        self.assertEqual(state.authority.active, 2)
        self.assertIn("history_fencing_is_not_worker_containment", model.boundary_findings(state, bounds=bounds))
        state = self.trace((self.action("finish_normal", 0),), state=state, bounds=bounds)
        self.assertEqual((state.stale_publications, state.authority.active, state.authority.normal), (1, 2, ()))
        self.assertEqual(state.authority.unknown, (1,))
        state = self.trace((self.action("finish_normal", 1),), state=state, bounds=bounds)
        self.assertEqual((state.authority.normal, state.authority.consumed, len(state.entries)), ((2,), 2, 2))
        self.assertEqual(model.safety_violations(state, bounds=bounds), ())

    def test_rollbackable_authority_replenishes_even_ideal_dispatch_quota(self):
        old_pending = self.trace((self.action("reserve", 0), self.action("rewind_authority")),
                                 policy="rollbackable-dispatch")
        self.unavailable(old_pending, self.action("start", 0), policy="rollbackable-dispatch")
        state = self.trace((self.action("reserve", 0), self.action("start", 0), self.action("finish_normal", 0),
                            self.action("rewind_authority"), self.action("restore_empty", 0),
                            self.action("reserve", 0), self.action("start", 0)), policy="rollbackable-dispatch")
        self.assertEqual((state.authority.consumed, len(state.entries)), (1, 2))
        self.assertEqual([entry.ticket for entry in state.entries], [1, 1])
        self.assertIn("scope_worker_entry_quota_exceeded", model.safety_violations(state, policy="rollbackable-dispatch"))
        self.unavailable(model.State(), self.action("rewind_authority"))

    def test_abstract_unknown_consumes_allowance_without_inventing_a_normal(self):
        state = self.trace((self.action("reserve", 0), self.action("start", 0), self.action("finish_unknown", 0)))
        self.assertEqual((state.authority.consumed, state.authority.unknown, state.authority.normal), (1, (1,), ()))
        self.assertEqual(len(state.entries), 1)
        self.assertIn("exhausted_without_retained_normal", model.boundary_findings(state))

    def test_snapshot_operations_refuse_running_source_or_destination(self):
        state = self.trace((self.action("reserve", 0), self.action("start", 0)))
        for action in (self.action("restore_empty", 0), self.action("copy", 1, 0), self.action("copy", 0, 1)):
            with self.subTest(action=action):
                self.unavailable(state, action)
        self.assertEqual(len(state.entries), 1)

    def test_exact_scope_and_profile_premise_excludes_request_selected_reenrollment(self):
        for fields in ({"scope": "new-scope"}, {"profile": "new-profile"}, {"scope": ""}, {"profile": None}):
            with self.subTest(fields=fields):
                self.unavailable(model.State(), self.action("reserve", 0, **fields))
        self.assertEqual(model.State().authority.consumed, 0)

    def test_invalid_bounds_policies_actions_and_states_are_not_explored(self):
        for bounds in (model.Bounds(True, 2), model.Bounds(0, 2), model.Bounds(1, 1), model.Bounds(4, 5)):
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                model.explore(bounds=bounds)
        for policy in (None, "unknown", True):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                model.explore(policy=policy)
        for state in (replace(model.State(), available=1), replace(model.State(), actors=(model.Actor(),)),
                      replace(model.State(), actors=(replace(model.Actor(), receipt=True), model.Actor())),
                      replace(model.State(), authority=model.Authority(active=1)),
                      replace(model.State(), authority=model.Authority(revision=2, consumed=1, normal=(1,), unknown=(1,)))):
            with self.subTest(state=state), self.assertRaises(ValueError):
                list(model.successors(state))
        for action in (self.action("reserve", True), self.action("copy", 0, 0), self.action("recover", 0)):
            with self.subTest(action=action):
                self.unavailable(model.State(), action)

    def test_complete_finite_comparison_exposes_weaker_policies(self):
        expected = {
            "local": {"scope_worker_entry_quota_exceeded"},
            "read-check": {"scope_worker_entry_quota_exceeded", "stale_worker_entry"},
            "authority-charge": {"scope_worker_entry_quota_exceeded", "receipt_reused_for_multiple_entries", "stale_worker_entry"},
            "ideal-dispatch": set(),
            "rollbackable-dispatch": {"scope_worker_entry_quota_exceeded", "receipt_reused_for_multiple_entries"},
        }
        for policy, names in expected.items():
            with self.subTest(policy=policy):
                result = comparison(policy)
                self.assertTrue(result.complete, result.reason)
                self.assertEqual(result.reason, "finite domain exhausted")
                self.assertEqual({finding.name for finding in result.safety_findings}, names)
                self.assertGreater(result.states, 1)
                self.assertGreater(result.transitions, result.states)

    def test_reported_finding_traces_replay_to_exact_states(self):
        for policy in model.POLICIES:
            result = comparison(policy)
            for finding in result.safety_findings + result.boundary_findings:
                with self.subTest(policy=policy, name=finding.name):
                    state = self.trace(finding.trace, policy=policy)
                    self.assertEqual(state, finding.state)
                    self.assertIn(finding.name, model.safety_violations(state, policy=policy)
                                  + model.boundary_findings(state, policy=policy))

    def test_every_ideal_scope_transition_preserves_nonrefundable_external_history(self):
        queue = deque((model.State(),))
        seen = set(queue)
        while queue:
            state = queue.popleft()
            self.assertEqual(model.safety_violations(state), ())
            for action, following in model.successors(state):
                self.assertGreaterEqual(following.authority.consumed, state.authority.consumed)
                self.assertGreaterEqual(following.authority.revision, state.authority.revision)
                self.assertEqual(following.authority.consumed - state.authority.consumed, int(action.kind == "reserve"))
                self.assertEqual(len(following.entries) - len(state.entries), int(action.kind == "start"))
                self.assertTrue(set(state.authority.normal).issubset(following.authority.normal))
                if following not in seen:
                    seen.add(following)
                    queue.append(following)
        self.assertEqual(len(seen), comparison("ideal-dispatch").states)

    def test_state_cap_is_incomplete_and_not_a_security_result(self):
        result = model.explore(max_states=1)
        self.assertFalse(result.complete)
        self.assertEqual((result.reason, result.states), ("state cap reached", 1))
        self.assertEqual(result.safety_findings, ())
        for cap in (True, 0, 1000001):
            with self.subTest(cap=cap), self.assertRaises(ValueError):
                model.explore(max_states=cap)

    def test_cli_separates_complete_bounded_search_from_incomplete_exit(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "model_observation_authority.py"
        for options, expected_code, expected_status in (([], 0, "bounded-complete"),
                                                       (["--max-states", "1"], 2, "incomplete")):
            result = subprocess.run([sys.executable, "-B", str(script), *options], capture_output=True,
                                    text=True, check=False, timeout=60)
            self.assertEqual(result.returncode, expected_code, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], expected_status)
            self.assertIn("ideal external state", payload["trust"])
            self.assertNotIn(str(script.parent), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
