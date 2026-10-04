"""Finite enrollment counterexamples; ideal owner facts are not authentication."""

from collections import deque
from dataclasses import FrozenInstanceError, replace
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_observation_enrollment as model


@lru_cache(maxsize=None)
def comparison(policy):
    return model.explore(policy=policy)


class ObservationEnrollmentModelTests(unittest.TestCase):
    base = model.Proposal()

    def action(self, kind, actor=-1, proposal=None, *, authorized=True):
        return model.Action(kind, actor, proposal, authorized)

    def trace(self, actions, *, state=None, policy="atomic-owner", bounds=model.Bounds()):
        state = model.State() if state is None else state
        for action in actions:
            state = model.step(state, action, policy=policy, bounds=bounds)
        return state

    def refused(self, state, action, **options):
        with self.assertRaises(ValueError):
            model.step(state, action, **options)

    def double_charge(self, changed, *, policy="scope-keyed"):
        return self.trace((self.action("enroll", 0, self.base), self.action("charge", 0, self.base),
            self.action("enroll", 1, changed), self.action("charge", 1, changed)), policy=policy)

    def test_new_label_opens_second_scope_budget_for_same_protected_resource(self):
        state = self.double_charge(replace(self.base, label=1))
        self.assertEqual([record.consumed for record in state.records], [1, 1])
        self.assertEqual([event.proposal.resource for event in state.charges], [0, 0])
        self.assertEqual(set(model.safety_violations(state, policy="scope-keyed")),
                         {"duplicate_canonical_enrollment", "protected_resource_charge_quota_exceeded"})

    def test_unreviewed_epoch_change_opens_budget_without_a_reset_authority(self):
        state = self.double_charge(replace(self.base, epoch=2))
        self.assertEqual([event.proposal.epoch for event in state.registrations], [1, 2])
        self.assertIn("unreviewed_epoch_or_profile_enrolled", model.safety_violations(state, policy="scope-keyed"))
        self.assertIn("protected_resource_charge_quota_exceeded", model.safety_violations(state, policy="scope-keyed"))

    def test_unreviewed_profile_change_opens_budget_without_rotation_policy(self):
        state = self.double_charge(replace(self.base, profile=1))
        self.assertEqual([event.proposal.profile for event in state.registrations], [0, 1])
        self.assertIn("unreviewed_epoch_or_profile_enrolled", model.safety_violations(state, policy="scope-keyed"))
        self.assertIn("protected_resource_charge_quota_exceeded", model.safety_violations(state, policy="scope-keyed"))

    def test_caller_claimed_resource_alias_can_open_second_bucket_for_same_resource(self):
        state = self.double_charge(replace(self.base, claimed_resource=1), policy="claimed-resource")
        self.assertEqual([record.proposal.claimed_resource for record in state.records], [0, 1])
        self.assertEqual([event.proposal.resource for event in state.charges], [0, 0])
        self.assertIn("protected_resource_charge_quota_exceeded", model.safety_violations(state, policy="claimed-resource"))

    def test_claimed_resource_lookup_can_charge_a_different_canonical_binding(self):
        alias = model.Proposal(resource=1, claimed_resource=0)
        state = self.trace((self.action("enroll", 0, self.base), self.action("enroll", 1, alias),
                            self.action("charge", 1, alias)), policy="claimed-resource")
        self.assertEqual((len(state.registrations), state.records[0].proposal.resource), (1, 0))
        self.assertEqual(state.charges[0].proposal.resource, 1)
        self.assertIn("charge_crossed_canonical_binding", model.safety_violations(state, policy="claimed-resource"))

    def test_known_canonical_source_alone_does_not_authorize_enrollment_or_charge(self):
        state = self.trace((self.action("enroll", 0, self.base, authorized=False),
                            self.action("charge", 0, self.base, authorized=False)), policy="canonical-source")
        self.assertEqual(set(model.safety_violations(state, policy="canonical-source")),
                         {"unauthorized_enrollment", "unauthorized_charge"})
        self.assertEqual(len(state.records), 1)

    def test_owned_policies_refuse_absent_independent_owner_fact_before_registration(self):
        for policy in model.OWNED:
            state = model.State()
            for kind in ("enroll", "check") if policy == "checked-owner" else ("enroll",):
                with self.subTest(policy=policy, kind=kind):
                    self.refused(state, self.action(kind, 0, self.base, authorized=False), policy=policy)
            self.assertEqual(state, model.State())

    def test_owner_authorization_is_required_again_at_each_charge(self):
        for policy in model.OWNED:
            actions = (self.action("enroll", 0, self.base),)
            if policy == "checked-owner":
                actions = (self.action("check", 0, self.base),) + actions
            state = self.trace(actions, policy=policy)
            self.refused(state, self.action("charge", 0, self.base, authorized=False), policy=policy)
            self.assertEqual((state.charges, state.records[0].consumed), ((), 0))

    def test_canonical_policies_freeze_profile_epoch_and_trusted_source_mapping(self):
        for policy in model.CANONICAL:
            for proposal in (replace(self.base, claimed_resource=1), replace(self.base, epoch=2),
                             replace(self.base, profile=1)):
                with self.subTest(policy=policy, proposal=proposal):
                    self.refused(model.State(), self.action("enroll", 0, proposal), policy=policy)
                    if policy == "checked-owner":
                        self.refused(model.State(), self.action("check", 0, proposal), policy=policy)

    def test_two_checked_absences_can_create_duplicate_canonical_enrollments(self):
        changed = replace(self.base, label=1)
        state = self.trace((self.action("check", 0, self.base), self.action("check", 1, changed),
            self.action("enroll", 0, self.base), self.action("enroll", 1, changed),
            self.action("charge", 0, self.base), self.action("charge", 1, changed)), policy="checked-owner")
        self.assertEqual([record.ticket for record in state.records], [1, 2])
        self.assertEqual(set(model.safety_violations(state, policy="checked-owner")),
                         {"duplicate_canonical_enrollment", "protected_resource_charge_quota_exceeded"})
        self.assertTrue(all(event.owner_authorized for event in state.registrations + state.charges))

    def test_exact_same_label_also_duplicates_under_nonatomic_missing_check(self):
        state = self.trace((self.action("check", 0, self.base), self.action("check", 1, self.base),
            self.action("enroll", 0, self.base), self.action("enroll", 1, self.base)), policy="checked-owner")
        self.assertEqual([record.proposal for record in state.records], [self.base, self.base])
        self.assertIn("duplicate_canonical_enrollment", model.safety_violations(state, policy="checked-owner"))

    def test_atomic_registration_refuses_new_label_without_replacing_existing_owner(self):
        state = self.trace((self.action("enroll", 0, self.base),))
        before = state
        self.refused(state, self.action("enroll", 1, replace(self.base, label=1)))
        self.assertEqual(state, before)
        self.assertEqual((len(state.records), state.records[0].consumed), (1, 0))
        self.assertEqual(model.safety_violations(state), ())

    def test_exact_duplicate_lookup_attaches_to_same_consumed_record_without_new_quota(self):
        state = self.trace((self.action("enroll", 0, self.base), self.action("charge", 0, self.base),
                            self.action("enroll", 1, self.base)))
        self.assertEqual([actor.ticket for actor in state.actors], [1, 1])
        self.assertEqual((len(state.registrations), state.records[0].consumed), (1, 1))
        self.refused(state, self.action("charge", 1, self.base))
        self.assertEqual(model.safety_violations(state), ())

    def test_lost_binding_and_exact_lookup_never_refund_previous_charge(self):
        state = self.trace((self.action("enroll", 0, self.base), self.action("charge", 0, self.base),
            self.action("lose_binding", 0), self.action("enroll", 0, self.base)))
        self.assertEqual((state.losses, len(state.registrations), len(state.charges)), (1, 1, 1))
        self.assertEqual(state.records[0].consumed, 1)
        self.refused(state, self.action("charge", 0, self.base))
        self.assertIn("lost_binding_does_not_refund_a_charge", model.boundary_findings(state))

    def test_registry_outage_refuses_registration_and_charge_without_fallback(self):
        for policy in model.POLICIES:
            state = self.trace((self.action("service_loss"),), policy=policy)
            self.refused(state, self.action("enroll", 0, self.base), policy=policy)
            actions = (self.action("enroll", 0, self.base),)
            if policy == "checked-owner":
                actions = (self.action("check", 0, self.base),) + actions
            pending = self.trace(actions + (self.action("service_loss"),), policy=policy)
            self.refused(pending, self.action("charge", 0, self.base), policy=policy)
            self.assertEqual(pending.records[0].consumed, 0)
            self.assertIn("registry_outage_refuses_admission", model.boundary_findings(pending, policy=policy))

    def test_registry_restore_reuses_identity_and_refills_even_atomic_owned_budget(self):
        state = self.trace((self.action("enroll", 0, self.base), self.action("charge", 0, self.base),
            self.action("rewind_registry"), self.action("enroll", 0, self.base),
            self.action("charge", 0, self.base)), policy="rollbackable-owner")
        self.assertEqual([(event.generation, event.ticket) for event in state.registrations], [(0, 1), (1, 1)])
        self.assertEqual((state.records[0].consumed, len(state.charges)), (1, 2))
        self.assertEqual(set(model.safety_violations(state, policy="rollbackable-owner")),
                         {"registration_identity_reused", "protected_resource_charge_quota_exceeded"})
        self.assertTrue(all(event.owner_authorized for event in state.registrations + state.charges))

    def test_empty_restored_registry_and_changed_current_label_refuse_old_binding(self):
        state = self.trace((self.action("enroll", 0, self.base), self.action("charge", 0, self.base),
            self.action("rewind_registry")), policy="rollbackable-owner")
        self.refused(state, self.action("charge", 0, self.base), policy="rollbackable-owner")
        changed = replace(self.base, label=1)
        state = self.trace((self.action("enroll", 1, changed),), state=state, policy="rollbackable-owner")
        self.refused(state, self.action("charge", 0, self.base), policy="rollbackable-owner")
        self.assertEqual((len(state.charges), state.records[0].consumed), (1, 0))
        self.refused(state, self.action("rewind_registry"), policy="rollbackable-owner")
        self.refused(model.State(), self.action("rewind_registry"))

    def test_distinct_canonical_resources_keep_distinct_allowances(self):
        other = model.Proposal(1, 1)
        state = self.trace((self.action("enroll", 0, self.base), self.action("charge", 0, self.base),
                            self.action("enroll", 1, other), self.action("charge", 1, other)))
        self.assertEqual([record.consumed for record in state.records], [1, 1])
        self.assertEqual(len(state.charges), 2)
        self.assertEqual(model.safety_violations(state), ())
        self.assertIn("distinct_resources_can_use_distinct_allowances", model.boundary_findings(state))

    def test_allowance_two_trace_is_separate_from_default_complete_domain(self):
        bounds = model.Bounds(attempt_limit=2, max_charges=3)
        changed = replace(self.base, label=1)
        state = self.trace((self.action("enroll", 0, self.base), self.action("charge", 0, self.base),
            self.action("charge", 0, self.base), self.action("enroll", 1, changed),
            self.action("charge", 1, changed)), bounds=bounds, policy="scope-keyed")
        self.assertEqual(len(state.charges), 3)
        self.assertIn("protected_resource_charge_quota_exceeded", model.safety_violations(state, bounds=bounds, policy="scope-keyed"))
        self.assertEqual(model.Bounds().attempt_limit, 1)

    def test_invalid_bounds_proposals_actions_and_numeric_aliases_are_refused(self):
        for bounds in (None, model.Bounds(attempt_limit=True), model.Bounds(attempt_limit=0),
                       model.Bounds(max_enrollments=1), model.Bounds(max_charges=1), model.Bounds(max_losses=2)):
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                model.step(model.State(), self.action("enroll", 0, self.base), bounds=bounds)
        for proposal in (None, model.Proposal(resource=True), model.Proposal(label=1.0), model.Proposal(epoch=0),
                         model.Proposal(profile=2), model.Proposal(label=1, epoch=2)):
            self.refused(model.State(), self.action("enroll", 0, proposal))
        for action in (None, model.Action("unknown"), model.Action("enroll", True, self.base),
                       model.Action("enroll", 0, self.base, 1), model.Action("service_loss", 0),
                       model.Action("lose_binding", 0, self.base), model.Action("charge", 0, self.base)):
            self.refused(model.State(), action)
        for policy in (None, True, "unknown"):
            with self.assertRaises(ValueError):
                model.explore(policy=policy)

    def test_state_partition_requires_registered_bindings_and_exact_nonrefundable_counts(self):
        valid = self.trace((self.action("enroll", 0, self.base),))
        broken = (None, model.State(available=1), model.State(actors=[]), model.State(generation=1),
                  model.State(charges=(None,)), model.State(registrations=(None,)),
                  model.State(actors=(model.Actor(1, self.base), model.Actor())),
                  replace(valid, records=(replace(valid.records[0], consumed=1),)),
                  replace(valid, registrations=valid.registrations * 2),
                  replace(valid, records=(replace(valid.records[0], ticket=2),)),
                  replace(valid, charges=(model.Event(0, 0, 2, self.base, True),)))
        for state in broken:
            with self.subTest(kind=type(state).__name__), self.assertRaises(ValueError):
                model.safety_violations(state)
        with self.assertRaises(FrozenInstanceError):
            valid.available = False

    def test_default_complete_comparisons_have_exact_states_edges_and_expected_findings(self):
        expected = {
            "scope-keyed":(202242, 427882, {"unauthorized_enrollment", "unreviewed_epoch_or_profile_enrolled", "unauthorized_charge", "duplicate_canonical_enrollment", "protected_resource_charge_quota_exceeded"}),
            "claimed-resource":(531522, 1075882, {"unauthorized_enrollment", "unreviewed_epoch_or_profile_enrolled", "unauthorized_charge", "duplicate_canonical_enrollment", "charge_crossed_canonical_binding", "protected_resource_charge_quota_exceeded"}),
            "canonical-source":(18626, 39666, {"unauthorized_enrollment", "unauthorized_charge"}),
            "checked-owner":(5156, 12316, {"duplicate_canonical_enrollment", "protected_resource_charge_quota_exceeded"}),
            "atomic-owner":(1954, 3714, set()),
            "rollbackable-owner":(9410, 19810, {"registration_identity_reused", "protected_resource_charge_quota_exceeded"}),
        }
        for policy, (states, transitions, findings) in expected.items():
            with self.subTest(policy=policy):
                result = comparison(policy)
                self.assertTrue(result.complete, result.reason)
                self.assertEqual(result.reason, "finite domain exhausted")
                self.assertEqual((result.states, result.transitions), (states, transitions))
                self.assertEqual({finding.name for finding in result.safety_findings}, findings)

    def test_every_reported_finding_trace_replays_to_its_exact_state(self):
        for policy in model.POLICIES:
            result = comparison(policy)
            for finding in result.safety_findings + result.boundary_findings:
                state = self.trace(finding.trace, policy=policy)
                self.assertEqual(state, finding.state)
                self.assertIn(finding.name, model.safety_violations(state, policy=policy)
                              + model.boundary_findings(state, policy=policy))

    def test_every_atomic_transition_preserves_single_owner_and_nonrefundable_audit(self):
        queue = deque((model.State(),))
        seen = set(queue)
        while queue:
            state = queue.popleft()
            self.assertEqual(model.safety_violations(state), ())
            self.assertEqual(len({record.proposal.resource for record in state.records}), len(state.records))
            for action, following in model.successors(state):
                self.assertEqual(following.registrations[:len(state.registrations)], state.registrations)
                self.assertEqual(following.charges[:len(state.charges)], state.charges)
                self.assertEqual(len(following.charges) - len(state.charges), int(action.kind == "charge"))
                self.assertGreaterEqual(sum(record.consumed for record in following.records),
                                        sum(record.consumed for record in state.records))
                self.assertEqual(following.generation, 0)
                if following not in seen:
                    seen.add(following)
                    queue.append(following)
        self.assertEqual(len(seen), comparison("atomic-owner").states)

    def test_state_caps_are_incomplete_even_when_no_finding_has_been_seen(self):
        for policy in model.POLICIES:
            result = model.explore(policy=policy, max_states=1)
            self.assertFalse(result.complete)
            self.assertEqual((result.reason, result.states), ("state cap reached", 1))
            self.assertEqual(result.safety_findings, ())
        for cap in (True, 0, 1000001):
            with self.assertRaises(ValueError):
                model.explore(max_states=cap)

    def test_cli_reports_finite_completion_and_incomplete_exit_without_private_paths(self):
        script = Path(__file__).resolve().parents[1] / "scripts/model_observation_enrollment.py"
        for options, code, status in (([], 0, "bounded-complete"), (["--max-states", "1"], 2, "incomplete")):
            result = subprocess.run([sys.executable, "-B", str(script), *options], capture_output=True,
                                    text=True, check=False, timeout=60)
            self.assertEqual((result.returncode, json.loads(result.stdout)["status"]), (code, status))
            self.assertIn("external owner facts", json.loads(result.stdout)["trust"])
            self.assertNotIn(str(script.parent), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
