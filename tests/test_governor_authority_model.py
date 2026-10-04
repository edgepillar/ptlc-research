"""Ideal governor facts and finite check/use witnesses are not credentials."""

from dataclasses import FrozenInstanceError, replace
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_governor_authority as model


@lru_cache(maxsize=None)
def comparison(policy):
    return model.explore(policy=policy)


class GovernorAuthorityModelTests(unittest.TestCase):
    def trace(self, actions, *, policy="atomic-current", state=None):
        state = model.State() if state is None else state
        for action in actions: state = model.step(state, action, policy=policy)
        return state

    def use(self, proposal=1, *, policy="atomic-current", before=(), between=()):
        return self.trace((*before, model.Action("check", 0, proposal), *between, model.Action("use", 0)), policy=policy)

    def safety(self, state, policy="atomic-current"):
        return model.findings(state, policy=policy)[0]

    def refuse(self, state, action, **options):
        with self.assertRaises(ValueError): model.step(state, action, **options)

    def test_domain_has_separate_keys_scope_roles_and_complete_profile_symbols(self):
        self.assertEqual((len(model.POLICIES), len(model.PROFILES), len(model.PROPOSALS)), (7, 7, 12))
        self.assertEqual([p.owner for p in model.PROFILES[:3]], [0, 0, 1])
        self.assertEqual([p.opaque_authority_label for p in model.PROFILES[:3]], [0, 0, 0])
        self.assertEqual([(p.attempt_cap, p.target_cap) for p in model.PROFILES[:2]], [(2, 2), (3, 3)])

    def test_valid_peer_root_and_owner_signature_do_not_establish_trusted_assignment(self):
        state = self.use(5, policy="self-selected")
        self.assertTrue(state.actors[0].admitted)
        self.assertIn("untrusted_role_assignment", self.safety(state, "self-selected"))
        self.assertFalse(self.use(5, policy="scoped-role").actors[0].admitted)

    def test_initial_key_pin_does_not_bind_resource_namespace_or_role(self):
        for proposal, name in ((6, "wrong_resource"), (7, "wrong_namespace"), (8, "wrong_role")):
            with self.subTest(proposal=proposal):
                state = self.use(proposal, policy="anchored-key")
                self.assertIn(name, self.safety(state, "anchored-key"))
                self.assertFalse(self.use(proposal, policy="scoped-role").actors[0].admitted)

    def test_valid_owner_math_does_not_replace_assignment_credential_fact(self):
        state = self.use(10, policy="anchored-key")
        self.assertTrue(state.actors[0].admitted)
        self.assertIn("untrusted_role_assignment", self.safety(state, "anchored-key"))
        self.assertFalse(self.use(10, policy="scoped-role").actors[0].admitted)

    def test_all_policies_refuse_independently_invalid_intent_signature_fact(self):
        for policy in model.POLICIES:
            self.assertFalse(self.use(9, policy=policy).actors[0].admitted)

    def test_scoped_assignment_does_not_bind_legacy_intent_to_local_profile(self):
        state = self.use(0, policy="scoped-role")
        self.assertEqual(self.safety(state, "scoped-role"), ("intent_not_bound_to_selected_profile",))
        self.assertFalse(self.use(0, policy="profile-bound").actors[0].admitted)

    def test_broader_caps_and_same_opaque_pin_require_separate_intent_profile_binding(self):
        advance = (model.Action("advance"),)
        state = self.use(2, policy="scoped-role", before=advance)
        self.assertTrue(state.actors[0].admitted)
        self.assertEqual(self.safety(state, "scoped-role"), ("intent_not_bound_to_selected_profile",))
        self.assertFalse(self.use(2, before=advance).actors[0].admitted)
        self.assertTrue(self.use(3, before=advance).actors[0].admitted)

    def test_old_bound_message_cannot_select_another_complete_profile(self):
        for policy in model.POLICIES[3:]:
            self.assertFalse(self.use(11, policy=policy, before=(model.Action("advance"),)).actors[0].admitted)

    def test_signature_and_complete_profile_binding_do_not_supply_current_policy(self):
        state = self.use(1, policy="profile-bound", between=(model.Action("advance"),))
        self.assertEqual(self.safety(state, "profile-bound"), ("not_current_profile",))
        self.assertFalse(self.use(1, between=(model.Action("advance"),)).actors[0].admitted)

    def test_cached_current_check_can_admit_after_policy_changes(self):
        state = self.use(1, policy="checked-current", between=(model.Action("advance"),))
        self.assertTrue(state.actors[0].cached and state.actors[0].admitted)
        self.assertEqual(self.safety(state, "checked-current"), ("not_current_profile",))

    def test_key_rotation_between_check_and_use_refuses_old_key_under_atomic_current(self):
        advance = (model.Action("advance"), model.Action("advance"))
        cached = self.use(1, policy="checked-current", between=advance)
        self.assertEqual(set(self.safety(cached, "checked-current")), {"not_current_profile", "not_current_owner"})
        self.assertFalse(self.use(1, between=advance).actors[0].admitted)
        self.assertTrue(self.use(4, before=advance).actors[0].admitted)

    def test_revocation_between_check_and_use_is_not_repaired_by_a_valid_old_signature(self):
        advance = (model.Action("advance"),) * 3
        cached = self.use(1, policy="checked-current", between=advance)
        self.assertEqual(self.safety(cached, "checked-current"), ("admitted_after_revocation",))
        self.assertFalse(self.use(1, between=advance).actors[0].admitted)

    def test_atomic_current_checks_again_at_use_and_can_accept_newly_current_packet(self):
        state = self.use(3, between=(model.Action("advance"),))
        self.assertTrue(state.actors[0].admitted)
        self.assertEqual(self.safety(state), ())
        cached = self.use(3, policy="checked-current", between=(model.Action("advance"),))
        self.assertFalse(cached.actors[0].admitted)
        self.assertIn("stale_check_or_view_can_refuse_current_valid_proposal", model.findings(cached, policy="checked-current")[1])

    def test_coherent_local_anchor_restore_does_not_restore_independent_current_authority(self):
        before = (model.Action("advance"), model.Action("restore"))
        state = self.use(1, policy="rollbackable-current", before=before)
        self.assertEqual((state.phase, state.local_view), (1, 0))
        self.assertEqual(self.safety(state, "rollbackable-current"), ("not_current_profile",))
        self.assertIn("local_restore_does_not_rewind_trusted_world", model.findings(state, policy="rollbackable-current")[1])

    def test_restored_old_anchor_can_admit_after_rotation_and_revocation(self):
        for count, expected in ((2, {"not_current_profile", "not_current_owner"}), (3, {"admitted_after_revocation"})):
            state = self.use(1, policy="rollbackable-current", before=(model.Action("advance"),) * count + (model.Action("restore"),))
            self.assertEqual(set(self.safety(state, "rollbackable-current")), expected)

    def test_refresh_is_a_separate_external_premise_and_restores_current_refusal(self):
        before = (model.Action("advance"), model.Action("restore"), model.Action("refresh"))
        state = self.use(1, policy="rollbackable-current", before=before)
        self.assertFalse(state.actors[0].admitted)
        self.assertEqual((state.phase, state.local_view), (1, 1))
        self.refuse(state, model.Action("restore"), policy="rollbackable-current")
        self.refuse(state, model.Action("refresh"), policy="rollbackable-current")

    def test_completed_decisions_are_audited_at_use_without_retroactive_revocation(self):
        state = self.trace((model.Action("check", 0, 1), model.Action("use", 0), *(model.Action("advance"),) * 3))
        self.assertTrue(state.actors[0].admitted)
        self.assertEqual((state.phase, state.actors[0].use_phase), (3, 0))
        self.assertEqual(self.safety(state), ())

    def test_two_callers_and_replayed_packet_have_no_registry_or_idempotency_guarantee(self):
        state = self.trace((model.Action("check", 0, 1), model.Action("check", 1, 1), model.Action("use", 0), model.Action("use", 1)))
        self.assertTrue(all(a.admitted for a in state.actors))
        self.assertEqual(self.safety(state), ())
        self.assertIn("same_proposal_can_be_admitted_twice_without_idempotency", model.findings(state)[1])

    def test_no_policy_provides_a_registry_quota_worker_or_real_certificate(self):
        for value in (model.State(), model.PROPOSALS[1], model.PROFILES[0]):
            for field in ("quota_granted", "enrolled", "can_start", "certificate_verified", "signature_hex"):
                self.assertFalse(hasattr(value, field))
        self.assertEqual(model.PROPOSALS[1].intent_signature_valid, True)

    def test_environment_events_cannot_be_peer_claims_or_repeated_after_bounds(self):
        state = self.trace((model.Action("advance"),) * 3)
        self.refuse(state, model.Action("advance"))
        for kind in ("advance", "restore", "refresh"):
            self.refuse(model.State(), model.Action(kind, 0, 0))
        self.refuse(model.State(), model.Action("restore"))
        self.refuse(model.State(), model.Action("refresh"))
        pending = self.trace((model.Action("check", 0, 1),))
        self.refuse(pending, model.Action("check", 0, 1))
        self.refuse(model.State(), model.Action("use", 0))
        self.refuse(self.use(), model.Action("use", 0))

    def test_bad_types_numeric_aliases_and_forged_actor_history_refuse(self):
        class Hostile:
            def __getattribute__(self, name): raise AssertionError("untrusted hook ran")
            def __eq__(self, other): raise AssertionError("untrusted hook ran")
        for state in (None, {}, Hostile(), model.State(phase=True), model.State(local_view=1),
            model.State(restored=1), model.State(actors=[]), model.State(actors=(model.Actor(),)),
            model.State(actors=(model.Actor(proposal=Hostile()), model.Actor())),
            model.State(actors=(model.Actor(proposal=1, cached=False), model.Actor())),
            model.State(actors=(model.Actor(proposal=1, cached=True, done=True, use_phase=0, use_view=0, admitted=False), model.Actor()))):
            self.refuse(state, model.Action("advance"))
        for action in (None, {}, Hostile(), model.Action("unknown"), model.Action("check", True, 1),
                       model.Action("check", 0, False), model.Action("use", 0, 1)):
            self.refuse(model.State(), action)
        for policy in (None, {}, Hostile(), "unknown"):
            self.refuse(model.State(), model.Action("advance"), policy=policy)
        with self.assertRaises(FrozenInstanceError): model.State().phase = 1

    def test_complete_comparison_preserves_conditional_atomic_safety_and_other_counterexamples(self):
        for policy in model.POLICIES:
            result = comparison(policy)
            self.assertTrue(result.complete, policy)
            self.assertEqual(result.reason, "bounded-complete")
            self.assertEqual(bool(result.safety_findings), policy != "atomic-current", policy)
            self.assertIn("same_proposal_can_be_admitted_twice_without_idempotency", {f.name for f in result.boundary_findings})
            for finding in result.safety_findings + result.boundary_findings:
                self.assertEqual(self.trace(finding.trace, policy=policy), finding.state)
                self.assertIn(finding.name, sum(model.findings(finding.state, policy=policy), ()))

    def test_search_cap_is_incomplete_and_invalid_caps_are_not_security_results(self):
        result = model.explore(max_states=1)
        self.assertEqual((result.complete, result.reason, result.states), (False, "state-cap", 1))
        for cap in (None, False, 0, 1.0, 1000001):
            with self.assertRaises(ValueError): model.explore(max_states=cap)

    def test_cli_reports_complete_and_incomplete_without_application_imports_or_live_access(self):
        script = Path("scripts/model_governor_authority.py")
        result = subprocess.run([sys.executable, "-B", str(script), "--max-states", "1"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(payload["domain"], dict(actors=2, profiles=7, proposals=12, trusted_phases=4, local_restores=0, local_refreshes=0))
        self.assertIn("hypothetical profile binding", payload["trust"])
        import ast
        tree = ast.parse(script.read_text())
        modules = {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules.update(alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertEqual(modules, {"argparse", "collections", "dataclasses", "json"})
