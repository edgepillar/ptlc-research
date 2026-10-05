"""Ideal source cutoffs and durable records are separate unimplemented premises."""

import ast
from dataclasses import FrozenInstanceError, replace
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_policy_source_use as model


@lru_cache(maxsize=None)
def comparison(policy, distinct=False):
    return model.comparison(policy=policy, distinct_operations=distinct)


class PolicySourceUseModelTests(unittest.TestCase):
    def trace(self, actions, *, policy="commit-cutoff", state=None):
        state = model.State() if state is None else state
        for action in actions: state = model.step(state, action, policy=policy)
        return state

    def initial_commit(self, *, policy="commit-cutoff", lost=False):
        return self.trace((model.Action("read", 0, 0, 0), model.Action("commit-lost" if lost else "commit", 0)), policy=policy)

    def refuse(self, state, action, **options):
        with self.assertRaises(ValueError): model.step(state, action, **options)

    def test_explicit_domain_keeps_complete_profile_symbols_and_source_modes_separate(self):
        self.assertEqual(model.PROFILE_FACTS, {0: (0, 0, 2), 1: (0, 0, 1), 2: (1, 0, 1), 4: (1, 1, 1)})
        self.assertEqual(model.MODES, ("live", "unavailable", "ambiguous", "compromise-detected"))
        self.assertEqual(len(model.POLICIES), 4)

    def test_current_read_commit_and_entry_are_three_distinct_events(self):
        read = self.trace((model.Action("read", 0, 0, 0),))
        self.assertEqual((read.charges, read.entries), ((), ()))
        committed = self.trace((model.Action("commit", 0),), state=read)
        self.assertEqual((len(committed.charges), len(committed.entries)), (1, 0))
        entered = self.trace((model.Action("enter", 0),), state=committed)
        self.assertEqual((len(entered.charges), len(entered.entries)), (1, 1))
        self.assertEqual(model.findings(entered), ((), ()))

    def test_cached_positive_can_charge_after_cap_update_owner_rotation_or_revocation(self):
        for count in (1, 2, 3, 4):
            actions = (model.Action("read", 0, 0, 0), *(model.Action("advance"),) * count,
                       model.Action("commit", 0), model.Action("enter", 0))
            bad = self.trace(actions, policy="cached-read")
            self.assertIn("charge_without_current_policy", model.findings(bad, policy="cached-read")[0])
            for policy in model.POLICIES[1:]:
                good = self.trace(actions, policy=policy)
                self.assertEqual((good.charges, good.entries), ((), ()))

    def test_stale_or_forged_active_read_does_not_replace_current_source_at_commit(self):
        for kind in ("read-stale", "read-forged"):
            actions = (*(model.Action("advance"),) * 3, model.Action(kind, 0, 0, 0), model.Action("commit", 0))
            self.assertEqual(len(self.trace(actions, policy="cached-read").charges), 1)
            self.assertEqual(self.trace(actions).charges, ())

    def test_valid_new_profile_can_commit_after_caps_owner_and_source_incarnation_change(self):
        for profile in (1, 2, 4):
            state = self.trace((*(model.Action("advance"),) * profile,
                model.Action("read", 0, profile, 0), model.Action("commit", 0), model.Action("enter", 0)))
            self.assertEqual((state.records[0].profile, len(state.charges), len(state.entries)), (profile, 1, 1))
            self.assertEqual(model.findings(state)[0], ())

    def test_commit_cutoff_honors_one_previously_committed_entry_after_revocation(self):
        state = self.trace((*(model.Action("advance"),) * 3, model.Action("enter", 0)), state=self.initial_commit())
        self.assertEqual(state.entries[0].phase, 3)
        self.assertEqual(state.entries[0].commit_phase, 0)
        self.assertEqual(model.findings(state)[0], ())
        self.assertIn("entry_after_revocation_under_commit_cutoff", model.findings(state)[1])

    def test_entry_cutoff_refuses_after_revocation_without_refunding_a_charge(self):
        state = self.trace((*(model.Action("advance"),) * 3, model.Action("enter", 0)),
            state=self.initial_commit(policy="entry-cutoff"), policy="entry-cutoff")
        self.assertEqual((len(state.charges), len(state.entries)), (1, 0))
        self.assertEqual(state.records[0].entry_phase, -1)
        self.assertIn("charge_does_not_prove_worker_entry", model.findings(state, policy="entry-cutoff")[1])

    def test_owner_and_root_rotation_between_commit_and_entry_follow_selected_cutoff(self):
        for count in (1, 2, 4):
            for policy, entered in (("commit-cutoff", 1), ("entry-cutoff", 0)):
                state = self.trace((*(model.Action("advance"),) * count, model.Action("enter", 0)),
                    state=self.initial_commit(policy=policy), policy=policy)
                self.assertEqual((len(state.charges), len(state.entries)), (1, entered))
                self.assertEqual(model.findings(state, policy=policy)[0], ())

    def test_later_revocation_does_not_retroactively_invalidate_an_earlier_entry(self):
        for policy in ("commit-cutoff", "entry-cutoff"):
            state = self.trace((model.Action("enter", 0), *(model.Action("advance"),) * 3),
                state=self.initial_commit(policy=policy), policy=policy)
            self.assertEqual(state.entries[0].phase, 0)
            self.assertEqual(model.findings(state, policy=policy)[0], ())

    def test_unavailable_ambiguous_or_known_compromised_source_refuses_new_commits(self):
        for mode in model.MODES[1:]:
            actions = (model.Action("read", 0, 0, 0), model.Action(mode), model.Action("commit", 0))
            self.assertEqual(self.trace(actions).charges, ())
            cached = self.trace(actions, policy="cached-read")
            self.assertIn("charge_without_available_trusted_source", model.findings(cached, policy="cached-read")[0])

    def test_cached_claim_cannot_safely_replace_entry_source_during_outage(self):
        for policy in ("cached-read", "commit-cutoff", "entry-cutoff"):
            state = self.trace((model.Action("unavailable"), model.Action("enter", 0)),
                state=self.initial_commit(policy=policy), policy=policy)
            self.assertEqual(len(state.entries), int(policy == "cached-read"))
            if policy == "cached-read":
                self.assertIn("entry_without_available_trusted_source", model.findings(state, policy=policy)[0])

    def test_service_return_resumes_original_commit_without_a_second_charge(self):
        state = self.trace((model.Action("unavailable"), model.Action("enter", 0),
            model.Action("live"), model.Action("commit", 0), model.Action("enter", 0)), state=self.initial_commit())
        self.assertEqual((len(state.charges), len(state.entries)), (1, 1))

    def test_lost_commit_reply_retains_charge_and_no_known_entry_authority(self):
        state = self.initial_commit(lost=True)
        self.assertTrue(state.actors[0].outcome_unknown)
        self.assertFalse(state.actors[0].receipt_known)
        self.assertEqual(self.trace((model.Action("enter", 0),), state=state).entries, ())
        self.assertIn("lost_reply_does_not_prove_absence_or_refund", model.findings(state)[1])

    def test_original_lookup_after_lost_reply_finds_the_committed_record_without_charge(self):
        state = self.trace((model.Action("lookup", 0), model.Action("enter", 0)), state=self.initial_commit(lost=True))
        self.assertFalse(state.actors[0].outcome_unknown)
        self.assertEqual((len(state.charges), len(state.entries)), (1, 1))

    def test_same_operation_retry_after_lost_reply_reconciles_without_charge_or_duplicate_entry(self):
        state = self.trace((model.Action("commit", 0), model.Action("enter", 0),
            model.Action("commit", 0), model.Action("enter", 0)), state=self.initial_commit(lost=True))
        self.assertEqual((len(state.charges), len(state.entries)), (1, 1))

    def test_unavailable_lookup_does_not_convert_unknown_into_absence(self):
        state = self.trace((model.Action("unavailable"), model.Action("lookup", 0)), state=self.initial_commit(lost=True))
        self.assertTrue(state.actors[0].outcome_unknown)
        self.assertEqual(len(state.charges), 1)

    def test_lost_request_can_have_no_record_and_lookup_is_not_a_refund(self):
        state = self.trace((model.Action("read", 0, 0, 0), model.Action("unavailable"),
            model.Action("commit-lost", 0)))
        self.assertTrue(state.actors[0].outcome_unknown)
        self.assertEqual(state.charges, ())
        state = self.trace((model.Action("live"), model.Action("lookup", 0), model.Action("commit", 0)), state=state)
        self.assertFalse(state.actors[0].outcome_unknown)
        self.assertEqual(len(state.charges), 1)

    def test_duplicate_record_lookup_survives_revocation_but_entry_cutoff_still_rechecks(self):
        for policy, entered in (("commit-cutoff", 1), ("entry-cutoff", 0)):
            state = self.trace((*(model.Action("advance"),) * 3, model.Action("commit", 0), model.Action("enter", 0)),
                state=self.initial_commit(lost=True, policy=policy), policy=policy)
            self.assertTrue(state.actors[0].receipt_known)
            self.assertEqual((len(state.charges), len(state.entries)), (1, entered))

    def test_two_cloned_callers_with_same_scoped_operation_have_one_charge_and_entry(self):
        for policy in ("commit-cutoff", "entry-cutoff"):
            actions = (model.Action("read", 0, 0, 0), model.Action("read", 1, 0, 0),
                model.Action("commit", 0), model.Action("commit", 1), model.Action("enter", 1), model.Action("enter", 0))
            state = self.trace(actions, policy=policy)
            self.assertEqual((len(state.charges), len(state.entries)), (1, 1))
            self.assertEqual(model.findings(state, policy=policy)[0], ())

    def test_same_operation_with_another_complete_profile_cannot_replace_original_record(self):
        state = self.trace((model.Action("advance"), model.Action("read", 1, 1, 0), model.Action("commit", 1)), state=self.initial_commit())
        self.assertFalse(state.actors[1].receipt_known)
        self.assertEqual((state.records[0].profile, len(state.charges)), (0, 1))

    def test_different_operation_ids_do_not_prove_business_intent_uniqueness(self):
        state = self.trace((model.Action("read", 1, 0, 1), model.Action("commit", 1),
            model.Action("enter", 0), model.Action("enter", 1)), state=self.initial_commit())
        self.assertEqual((len(state.charges), len(state.entries)), (2, 2))
        self.assertIn("different_operation_ids_can_charge_the_same_proposal", model.findings(state)[1])

    def test_cap_decrease_retains_old_charges_and_prevents_a_new_distinct_operation(self):
        state = self.trace((model.Action("advance"), model.Action("read", 1, 1, 1), model.Action("commit", 1)), state=self.initial_commit())
        self.assertEqual(len(state.charges), 1)
        self.assertIsNone(state.records[1])

    def test_coherent_client_restore_replays_original_record_without_rewinding_source(self):
        state = self.trace((model.Action("enter", 0), model.Action("restore-client", 0),
            model.Action("commit", 0), model.Action("enter", 0)), state=self.initial_commit())
        self.assertEqual((len(state.charges), len(state.entries)), (1, 1))
        self.assertIn("local_restore_does_not_rewind_trusted_source", model.findings(state)[1])

    def test_client_restore_does_not_make_an_old_read_current_after_revocation(self):
        actions = (model.Action("read", 0, 0, 0), *(model.Action("advance"),) * 3,
            model.Action("restore-client", 0), model.Action("commit", 0))
        self.assertEqual(self.trace(actions).charges, ())
        self.assertEqual(len(self.trace(actions, policy="cached-read").charges), 1)

    def test_atomic_current_policy_is_insufficient_when_source_charge_ledger_can_restore(self):
        policy = "rollbackable-ledger"
        actions = (model.Action("enter", 0), model.Action("restore-ledger"),
            model.Action("restore-client", 0), model.Action("commit", 0), model.Action("enter", 0))
        state = self.trace(actions, state=self.initial_commit(policy=policy), policy=policy)
        self.assertEqual((state.phase, len(state.charges), len(state.entries)), (0, 2, 2))
        names = model.findings(state, policy=policy)[0]
        self.assertIn("same_operation_charged_again_after_source_restore", names)
        self.assertIn("same_operation_entered_again_after_source_restore", names)
        self.assertIn("source_restore_erased_charge_lineage", names)

    def test_trusted_source_restore_and_repeated_environment_events_are_not_peer_actions(self):
        for policy in ("cached-read", "commit-cutoff", "entry-cutoff"):
            self.refuse(self.initial_commit(policy=policy), model.Action("restore-ledger"), policy=policy)
        self.refuse(model.State(), model.Action("restore-ledger"), policy="rollbackable-ledger")
        self.refuse(model.State(), model.Action("live"))
        self.refuse(self.trace((model.Action("advance"),) * 4), model.Action("advance"))
        state = self.trace((model.Action("restore-client", 0),), state=self.initial_commit())
        self.refuse(state, model.Action("restore-client", 0))

    def test_invalid_types_numeric_aliases_foreign_hooks_and_forged_audit_states_refuse(self):
        class Hostile:
            def __getattribute__(self, name): raise AssertionError("untrusted hook ran")
            def __eq__(self, other): raise AssertionError("untrusted hook ran")
        for state in (None, {}, Hostile(), model.State(phase=True), model.State(mode=Hostile()),
            model.State(actors=[]), model.State(actors=(Hostile(), model.Actor())),
            model.State(actors=(model.Actor(profile=True, operation=0), model.Actor())),
            model.State(records=(Hostile(), None)), model.State(charges=(Hostile(),)),
            model.State(entries=(Hostile(),)), model.State(records=(model.Record(0, 0, 0), None))):
            self.refuse(state, model.Action("advance"))
        for action in (None, {}, Hostile(), model.Action("unknown"), model.Action("advance", 0),
                       model.Action("read", True, 0, 0), model.Action("read", 0, False, 0), model.Action("enter", 0, 0)):
            self.refuse(model.State(), action)
        for policy in (None, {}, Hostile(), "unknown"):
            self.refuse(model.State(), model.Action("advance"), policy=policy)
        with self.assertRaises(FrozenInstanceError): model.State().phase = 1

    def test_model_objects_return_no_source_signature_credential_or_application_permission(self):
        for value in (model.State(), model.Actor(), self.initial_commit().records[0]):
            for field in ("signature_hex", "authenticated", "authorized", "permit", "can_start", "quota_granted"):
                self.assertFalse(hasattr(value, field))

    def test_operation_records_require_consistent_charge_and_entry_audit(self):
        committed = self.initial_commit()
        entered = self.trace((model.Action("enter", 0),), state=committed)
        for state in (replace(committed, records=(replace(committed.records[0], entry_phase=0), None)),
            replace(entered, entries=()), replace(entered, records=(committed.records[0], None)),
            replace(committed, records=(None, None)), replace(committed, charges=())):
            self.refuse(state, model.Action("advance"))

    def test_selected_shuffle_enumeration_preserves_stream_order_and_exact_counts(self):
        counts = []
        for changes in (1, 2, 3, 4):
            streams = (tuple(model.Action(k, 0, 0, 0) if k == "read" else model.Action(k, 0) for k in ("read", "commit", "enter")),
                tuple(model.Action(k, 1, 0, 0) if k == "read" else model.Action(k, 1) for k in ("read", "commit", "enter")),
                (model.Action("advance"),) * changes)
            traces = list(model.interleavings(*streams)); counts.append(len(traces))
            self.assertEqual(len(set(traces)), len(traces))
            for trace in traces:
                for actor in (0, 1): self.assertEqual(tuple(a.kind for a in trace if a.actor == actor), ("read", "commit", "enter"))
        self.assertEqual(counts, [140, 560, 1680, 4200])

    def test_all_selected_schedules_keep_conditional_cutoff_safety_and_replay_witnesses(self):
        for policy in model.POLICIES:
            result = comparison(policy)
            self.assertEqual((result.complete, result.reason, result.schedules, result.transitions),
                (True, "selected-schedules-complete", 6580, 62580))
            self.assertEqual(bool(result.violations), policy == "cached-read")
            for witness in result.violations + result.boundaries:
                self.assertEqual(self.trace(witness.trace, policy=policy), witness.state)
                self.assertIn(witness.name, sum(model.findings(witness.state, policy=policy), ()))

    def test_distinct_operation_schedules_preserve_scoped_idempotency_boundary(self):
        for policy in ("commit-cutoff", "entry-cutoff"):
            result = comparison(policy, True)
            self.assertTrue(result.complete)
            self.assertEqual(result.violations, ())
            self.assertIn("different_operation_ids_can_charge_the_same_proposal", {f.name for f in result.boundaries})

    def test_schedule_cap_is_incomplete_and_invalid_parameters_are_not_safety_results(self):
        result = model.comparison(max_schedules=1)
        self.assertEqual((result.complete, result.reason, result.schedules), (False, "schedule-cap", 1))
        for cap in (None, False, 0, 1.0, 100001):
            with self.assertRaises(ValueError): model.comparison(max_schedules=cap)
        with self.assertRaises(ValueError): model.comparison(distinct_operations=1)

    def test_cli_incomplete_status_and_import_boundary_claim_no_full_graph_or_live_service(self):
        path = Path("scripts/model_policy_source_use.py")
        result = subprocess.run([sys.executable, "-B", str(path), "--max-schedules", "1"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        value = json.loads(result.stdout)
        self.assertEqual((value["status"], value["policy_cutoff"]), ("incomplete", "commit"))
        self.assertFalse(value["domain"]["full_action_graph"])
        self.assertFalse(value["domain"]["distinct_operations"])
        self.assertIn("no actual source authentication or actuation", value["trust"])
        tree = ast.parse(path.read_text("ascii"))
        modules = {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules.update(alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertEqual(modules, {"__future__", "argparse", "dataclasses", "json"})
