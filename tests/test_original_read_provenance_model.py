"""Directed symbolic traces tied to unchanged public fixtures and owned stores."""

import ast
from dataclasses import FrozenInstanceError, replace
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import model_original_read_provenance as model
from original_snapshot_vectors import INPUT, OUTPUT, canonical, scenario


@lru_cache(None)
def comparison(use):
    return model.comparison(use=use)


def fixture():
    return json.loads(OUTPUT.read_text("ascii"))


def symbols():
    f = fixture()
    roots, profiles, policies, records = {}, {}, {}, {}
    for name, value in f["positive_vectors"].items():
        statement = model.SAMPLES[name]
        q, c = value["response"]["query"], value["response"]["claim"]
        for mapping, wire, symbol in (
            (roots, value["root_declaration"], statement.query.root),
            (profiles, q["original_operation"]["governor_profile"], statement.query.original[2]),
            (policies, q["expected_checkpoint"], statement.query.policy_head),
            (records, q["expected_record_checkpoint"], statement.query.record_head)):
            key = canonical(wire)
            if key in mapping and mapping[key] != symbol:
                raise AssertionError("same complete object mapped to conflicting symbols")
            mapping[key] = symbol
        if c["head_policy"] is not None:
            profiles[canonical(c["head_policy"]["governor_profile"])] = statement.claim.head_profile
    altered = f["counterclaim_vectors"]["same_id_other_historical_profile"]
    profiles[canonical(altered["response"]["query"]["original_operation"]["governor_profile"])] = 3
    for mapping in (roots, profiles, policies, records):
        if len(mapping) != len(set(mapping.values())):
            raise AssertionError("different complete objects collapsed to the same symbol")
    return roots, profiles, policies, records


def project(value):
    roots, profiles, policies, records = symbols()
    q, c = value["response"]["query"], value["response"]["claim"]
    original = q["original_operation"]
    query = model.Query(roots[canonical(value["root_declaration"])],
        (0 if original["operation_id_hex"] == "01"*32 else -1,
         original["expected_revision"], profiles[canonical(original["governor_profile"])],
         {"02"*32: 0, "06"*32: 1}[original["proposal_digest_hex"]]),
        policies[canonical(q["expected_checkpoint"])], records[canonical(q["expected_record_checkpoint"])],
        {"03"*32: 0, "07"*32: 1}[q["challenge_hex"]])
    record, head = c["original_record"], c["head_policy"]
    if record is not None and record["original_operation"] != original:
        raise AssertionError("the projected record must bind the complete queried original")
    if c["observation"] != "unavailable":
        if (c["claimed_checkpoint"] != q["expected_checkpoint"] or
                c["claimed_record_checkpoint"] != q["expected_record_checkpoint"]):
            raise AssertionError("the projected claim must bind both queried heads")
    elif any(c[field] is not None for field in
             ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record")):
        raise AssertionError("unavailable does not contain state facts")
    return model.Statement(query, model.Claim(c["observation"], None if head is None else head["active"],
        None if head is None else profiles[canonical(head["governor_profile"])],
        None if record is None else record["charge_sequence"],
        None if record is None else record["effect_sequence"]))


class OriginalReadProvenanceModelTests(unittest.TestCase):
    def trace(self, actions, *, state=None, **options):
        state = state or model.State()
        for action in actions:
            state = model.step(state, action, **options)
        return state

    def reader(self, actor=0, packet="sample", fresh=False):
        return (model.Action("sample", actor, "fresh" if fresh else ""),
            model.Action("deliver", actor, packet), model.Action("verify", actor))

    def test_ten_symbols_match_complete_public_objects_and_recreated_owned_samples(self):
        f = fixture()
        self.assertEqual(set(f["positive_vectors"]), set(model.SAMPLES))
        for name, value in f["positive_vectors"].items():
            with self.subTest(name=name), scenario(name) as actual:
                self.assertEqual(project(value), model.SAMPLES[name])
                before = actual.path.read_bytes(), actual.store.local_view()
                self.assertEqual(actual.response().as_dict(), value["response"])
                self.assertEqual((actual.path.read_bytes(), actual.store.local_view()), before)

    def test_six_signed_counterclaim_symbols_match_named_unchanged_public_fixtures(self):
        counters = fixture()["counterclaim_vectors"]
        self.assertEqual(set(counters), set(model.COUNTERS))
        for name, value in counters.items():
            with self.subTest(name=name):
                self.assertEqual(project(value), model.COUNTERS[name])
                self.assertEqual(value["actual_scenario"], model.COUNTER_BASES[name])
                self.assertTrue(model.COUNTERS[name].signature_valid)
                self.assertTrue(value["result"]["root_signature_valid"])
                self.assertTrue(value["result"]["response_signature_valid"])

    def test_both_fixed_fixture_pins_are_preserved_without_new_signature_or_key_material(self):
        for path, pin in ((INPUT, "0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01"),
                          (OUTPUT, "2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb")):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), pin)

    def test_query_binding_still_accepts_three_false_observations_at_exact_selected_heads(self):
        for name in tuple(model.COUNTERS)[:3]:
            base = model.COUNTER_BASES[name]
            self.assertTrue(model.accepts(base, name, binding="peer-selected"))
            self.assertTrue(model.accepts(base, name, binding="query-bound"))
            self.assertFalse(model.accepts(base, name, binding="snapshot-bound"))
            state = self.trace(self.reader(packet=name), state=model.State(view=base, truth=base),
                               binding="query-bound")
            self.assertIn("accepted_claim_differs_from_owned_sample", model.findings(state, binding="query-bound")[0])

    def test_peer_replacement_of_proposal_historical_profile_or_challenge_refuses_query_binding(self):
        for name in tuple(model.COUNTERS)[3:]:
            base = model.COUNTER_BASES[name]
            self.assertTrue(model.accepts(base, name, binding="peer-selected"))
            self.assertFalse(model.accepts(base, name, binding="query-bound"))
            self.assertFalse(model.accepts(base, name, binding="snapshot-bound"))
            state = self.trace(self.reader(packet=name), state=model.State(view=base, truth=base),
                               binding="peer-selected")
            self.assertIn("reply_replaced_independent_query", model.findings(state, binding="peer-selected")[0])

    def test_changed_root_policy_and_record_heads_are_distinct_query_pins(self):
        for name in ("completed", "revoked_pending", "replaced_completed", "mode_round_trip_pending"):
            self.assertTrue(model.accepts("pending", name, binding="peer-selected"))
            self.assertFalse(model.accepts("pending", name, binding="query-bound"))
        first, after = model.SAMPLES["pending"], model.SAMPLES["mode_round_trip_pending"]
        self.assertEqual(first.query.policy_head, after.query.policy_head)
        self.assertNotEqual(first.query.record_head, after.query.record_head)

    def test_callback_flags_cannot_replace_the_signature_validity_premise(self):
        for binding in model.BINDINGS:
            self.assertFalse(model.accepts("pending", "zero-signatures", binding=binding))
            self.assertTrue(model.accepts("pending", "zero-signatures", binding=binding, check="callback-flags"))
        state = self.trace(self.reader(packet="zero-signatures"), check="callback-flags")
        self.assertIn("callback_flags_without_signature_mathematics", model.findings(state, check="callback-flags")[0])

    def test_sampling_delivery_and_verification_are_three_distinct_events(self):
        state = model.State()
        for phase, action in enumerate(self.reader(), 1):
            state = model.step(state, action)
            self.assertEqual(state.actors[0].phase, phase)
            self.assertEqual(state.actors[0].accepted, phase == 3)
        self.assertEqual(state.entries, ())
        self.assertTrue(state.actors[0].outcome_unknown)

    def test_snapshot_bound_signature_can_remain_valid_after_postcommit_revocation(self):
        trace = (model.Action("sample", 0), model.Action("revoke"),
                 model.Action("deliver", 0, "sample"), model.Action("verify", 0), model.Action("enter", 0))
        state = self.trace(trace)
        self.assertTrue(state.actors[0].accepted)
        self.assertEqual(state.entries, ())
        violations, boundaries = model.findings(state)
        self.assertEqual(violations, ())
        self.assertIn("historical_read_not_current", boundaries)
        self.assertIn("accepted_read_not_application_permission", boundaries)

    def test_unsafe_receipt_entry_uses_old_pending_claim_after_revocation(self):
        trace = self.reader() + (model.Action("revoke"), model.Action("enter", 0))
        state = self.trace(trace, use="receipt-entry")
        self.assertEqual(len(state.entries), 1)
        self.assertIn("entry_after_revocation", model.findings(state, use="receipt-entry")[0])
        ideal = self.trace(trace, use="ideal-current-entry")
        self.assertTrue(ideal.actors[0].accepted)
        self.assertEqual(ideal.entries, ())

    def test_ideal_entry_rechecks_after_verification_and_preserves_current_pending_entry(self):
        trace = self.reader() + (model.Action("enter", 0),)
        ideal = self.trace(trace, use="ideal-current-entry")
        self.assertEqual(len(ideal.entries), 1)
        self.assertEqual(model.findings(ideal, use="ideal-current-entry")[0], ())
        later = model.step(ideal, model.Action("revoke"), use="ideal-current-entry")
        self.assertEqual(model.findings(later, use="ideal-current-entry")[0], ())

    def test_two_readers_of_identical_signed_pending_copy_have_no_entry_deduplication(self):
        trace = self.reader(0) + self.reader(1) + (model.Action("enter", 0), model.Action("enter", 1))
        unsafe = self.trace(trace, use="receipt-entry")
        self.assertEqual(len(unsafe.entries), 2)
        self.assertIn("same_original_entered_more_than_once", model.findings(unsafe, use="receipt-entry")[0])
        ideal = self.trace(trace, use="ideal-current-entry")
        self.assertEqual(len(ideal.entries), 1)

    def test_coherent_source_restore_repeats_selected_statement_without_rewinding_external_completion(self):
        before = model.SAMPLES["pending"]
        trace = (model.Action("complete"), model.Action("restore-source")) + self.reader() + (model.Action("enter", 0),)
        state = self.trace(trace, use="receipt-entry")
        self.assertEqual(model.PACKETS[state.actors[0].expected], before)
        self.assertEqual((state.view, state.truth), ("pending", "completed"))
        self.assertIn("entry_after_external_completion", model.findings(state, use="receipt-entry")[0])
        self.assertEqual(self.trace(trace, use="ideal-current-entry").entries, ())

    def test_source_and_reader_restore_never_erase_ideal_external_entry_audit(self):
        first = self.trace(self.reader() + (model.Action("enter", 0),), use="ideal-current-entry")
        after = self.trace((model.Action("complete"), model.Action("restore-source"),
            model.Action("restore-reader", 0)) + self.reader() + (model.Action("enter", 0),),
            state=first, use="ideal-current-entry")
        self.assertEqual(after.entries, first.entries)
        self.assertEqual(after.truth, "completed")
        self.assertTrue(after.actors[0].outcome_unknown)

    def test_fresh_challenge_over_restored_initial_absence_does_not_prove_latest_record_head(self):
        initial = model.State(view="initial_absent", truth="initial_absent", saved_view="initial_absent")
        trace = (model.Action("charge"), model.Action("restore-source")) + self.reader(
            packet="fresh_challenge_over_initial_absence", fresh=True)
        state = self.trace(trace, state=initial)
        self.assertTrue(state.actors[0].accepted)
        self.assertEqual(state.truth, "pending")
        self.assertIn("historical_read_not_current", model.findings(state)[1])
        counter = fixture()["counterclaim_vectors"]["fresh_challenge_over_initial_absence"]
        with scenario("initial_absent") as actual:
            query = actual.query(challenge="07")
            self.assertEqual(actual.response(query).as_dict(), counter["response"])
            actual.store.allocate_synthetic(actual.original)
            from qualification.policy_effect_store import StoreRefused
            with self.assertRaises(StoreRefused):
                actual.response(query)

    def test_historical_original_profile_and_replaced_current_owner_are_separate_symbols(self):
        statement = model.SAMPLES["replaced_completed"]
        self.assertEqual(statement.query.original[2], 0)
        self.assertEqual(statement.claim.head_profile, 1)
        state = self.trace(self.reader(), state=model.State(view="replaced_completed", truth="replaced_completed"))
        self.assertTrue(state.actors[0].accepted)
        self.assertEqual(state.entries, ())

    def test_unavailable_and_reduced_cap_observations_do_not_grant_ideal_entry_or_recovery(self):
        for name in ("unavailable_pending", "reduced_pending_two_charges", "revoked_pending"):
            state = self.trace(self.reader() + (model.Action("enter", 0),),
                state=model.State(view=name, truth=name), use="ideal-current-entry")
            self.assertTrue(state.actors[0].accepted)
            self.assertEqual(state.entries, ())
            self.assertTrue(state.actors[0].outcome_unknown)
        self.assertEqual(model.SAMPLES["unavailable_pending"].claim,
                         model.Claim("unavailable", None, None, None, None))

    def test_lost_sample_delivery_and_reader_restore_do_not_clear_unknown_or_mutate_source(self):
        trace = (model.Action("sample", 0), model.Action("lose-return", 0))
        lost = self.trace(trace)
        self.assertFalse(lost.actors[0].accepted)
        self.assertEqual(lost.entries, ())
        restored = model.step(lost, model.Action("restore-reader", 0))
        self.assertEqual((restored.view, restored.truth), ("pending", "pending"))
        self.assertTrue(restored.actors[0].outcome_unknown)
        self.assertEqual(restored.actors[0].phase, 0)
        self.assertIn("reader_restore_does_not_reconcile_original", model.findings(restored)[1])

    def test_read_only_actions_never_clear_unknown_outcome_or_emit_permission(self):
        state = self.trace(self.reader() + (model.Action("enter", 0),))
        self.assertTrue(all(actor.outcome_unknown for actor in state.actors))
        self.assertEqual(state.entries, ())
        with self.assertRaises(FrozenInstanceError):
            state.truth = "completed"
        with self.assertRaises(ValueError):
            model.findings(replace(state, actors=(replace(state.actors[0], outcome_unknown=False), state.actors[1])))

    def test_invalid_types_policy_aliases_peer_source_events_and_reader_order_refuse(self):
        for action in (model.Action("sample", True), model.Action("revoke", 0), model.Action("verify", 0),
                       model.Action("sample", 0, "pending"), model.Action("unknown", 0)):
            with self.subTest(action=action), self.assertRaises(ValueError):
                model.step(model.State(), action)
        for options in ({"binding": False}, {"use": "admit"}, {"check": "true"}):
            with self.assertRaises(ValueError):
                model.step(model.State(), model.Action("sample", 0), **options)

    def test_selected_schedule_counts_and_conditional_ideal_entry_guards(self):
        for use in model.USES:
            result = comparison(use)
            self.assertEqual((result.complete, result.reason, result.schedules, result.transitions),
                             (True, "selected-schedules-complete", 6930, 68670))
            if use == "receipt-entry":
                self.assertEqual({item.name for item in result.violations}, {
                    "entry_without_current_original_and_policy", "entry_after_revocation",
                    "entry_after_external_completion", "same_original_entered_more_than_once"})
            else:
                self.assertEqual(result.violations, ())
            self.assertIn("historical_read_not_current", {item.name for item in result.boundaries})

    def test_each_reported_prefix_witness_replays_to_exact_state(self):
        for use in model.USES:
            result = comparison(use)
            for witness in result.violations + result.boundaries:
                state = self.trace(witness.trace, use=use)
                self.assertEqual(state, witness.state)
                self.assertIn(witness.name, sum(model.findings(state, use=use), ()))

    def test_schedule_cap_marks_incomplete_and_invalid_caps_are_not_safety_results(self):
        result = model.comparison(max_schedules=1)
        self.assertEqual((result.complete, result.reason, result.schedules, result.transitions),
                         (False, "schedule-cap", 1, 9))
        for cap in (True, 0, -1, 100001, "1"):
            with self.assertRaises(ValueError):
                model.comparison(max_schedules=cap)

    def test_cli_incomplete_result_and_pure_model_imports_exclude_operational_adapters(self):
        script = Path("scripts/model_original_read_provenance.py")
        result = subprocess.run([sys.executable, "-B", str(script), "--max-schedules", "1"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        output = json.loads(result.stdout)
        self.assertEqual(output["status"], "incomplete")
        self.assertFalse(output["domain"]["full_action_graph"])
        for key in ("source_authentication", "application_permission", "recovery"):
            self.assertIs(output[key], False)
        tree = ast.parse(script.read_text("ascii"))
        modules = {node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
            for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))}
        self.assertEqual(modules, {"__future__", "argparse", "dataclasses", "json"})


if __name__ == "__main__":
    unittest.main()
