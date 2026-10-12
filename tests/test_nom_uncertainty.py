"""Original retention and refusal ordering controls, with no trusted observer."""

import copy
from dataclasses import FrozenInstanceError
import json
import subprocess
import sys
import unittest

from offline_session import nom_uncertainty as hold, nom_authority_contract as authority
from scripts import qualify_nom_uncertainty as qualify, model_nom_uncertainty as model


class NoMUncertaintyTests(unittest.TestCase):
    def setUp(self):
        self.query = qualify.query_selection()
        self.initial = qualify.selected_hold()
        self.fixture = json.loads((qualify.ROOT / qualify.FIXTURE).read_text("ascii"))

    def refusal(self, case=hold.CASES[1]):
        return bytes.fromhex(self.fixture["refusals_hex"][case])

    def source(self, name="complete"):
        return bytes.fromhex(self.fixture["source_claims_hex"][name])

    def retained(self):
        return hold.retain_claim(self.initial, self.refusal(), kind="refusal")

    def selected(self, value=None):
        value = value or self.initial.as_dict()
        return json.loads(bytes.fromhex(value["selection_hex"]))

    def compare_refused(self, value, expected=None):
        with self.assertRaises(hold.NoMUncertaintyRefused):
            hold.compare_hold(expected or self.initial, qualify.wire(value))

    def selection_refused(self, selection):
        value = self.initial.as_dict()
        value["selection_hex"] = qualify.wire(selection).hex()
        self.compare_refused(value)

    def test_full_qualification_binds_prior_records_without_new_native_claims(self):
        result = qualify.qualify()
        self.assertEqual(result["outcome"], "PASS")
        self.assertEqual((result["preserved_source_tests_including_parents"], result["new_native_outcomes"]), (342, 0))
        self.assertTrue(result["source_unchanged"])
        self.assertEqual(result["native_query_context_pairing"], "NOT_COMPOSED")

    def test_exact_long_and_short_originals_and_selected_prior_evidence_survive(self):
        retained = hold.retain_claim(self.retained(), self.source("unavailable"), kind="source")
        self.assertEqual(retained.as_dict()["selection_hex"], self.initial.as_dict()["selection_hex"])
        selected = self.selected(retained.as_dict())
        self.assertEqual(json.loads(bytes.fromhex(selected["query_hex"]))["originals_hex"], self.query.as_dict()["originals_hex"])
        self.assertEqual(len(selected["prior_evidence_hex"]), 2)

    def test_original_error_before_any_pop_still_gives_no_recovery_authority(self):
        result = hold.retain_claim(self.initial, self.refusal(hold.CASES[0]), kind="refusal").review()
        self.assertEqual((result["state"], result["recovery_action"], result["charged_work"]), ("HOLD", "NONE", 1))

    def test_typed_partial_rollback_still_gives_no_recovery_authority(self):
        result = self.retained().review()
        self.assertEqual((result["state"], result["recovery_action"], result["charged_work"]), ("HOLD", "NONE", 1))
        self.assertEqual((result["source_authentication"], result["restore_fence"]), ("NOT_PERFORMED", "UNFILLED"))

    def test_forged_failure_labels_are_opaque_and_cannot_release_a_hold(self):
        value = json.loads(self.refusal())
        value["failure"] = {"target_reached": True, "successful_pops": 999, "typed_uncertain": False}
        retained = hold.retain_claim(self.initial, qualify.wire(value), kind="refusal")
        self.assertEqual(retained.review()["recovery_action"], "NONE")
        self.assertEqual(retained.review()["native_query_context_pairing"], "NOT_COMPOSED")

    def test_forgeable_all_supported_zero_digest_claim_cannot_release_or_replenish(self):
        retained = hold.retain_claim(self.retained(), self.source(), kind="source")
        review = retained.review()
        self.assertEqual((review["recovery_action"], review["charged_work"], review["disclosure_possible"]), ("NONE", 1, True))
        for field in ("replacement_original_allowed", "replenish_work", "automatic_retry"):
            self.assertIs(review[field], False)
        self.assertFalse(callable(retained))
        self.assertEqual(review["journal_composition"], "NOT_PERFORMED")

    def test_unavailable_claim_after_supported_claim_preserves_unknown_charge(self):
        retained = hold.retain_claim(self.retained(), self.source(), kind="source")
        retained = hold.retain_claim(retained, self.source("unavailable"), kind="source")
        self.assertEqual(self.selected(retained.as_dict())["charged_work"], self.selected()["charged_work"])
        self.assertEqual(retained.review()["retained_source_claims"], 2)

    def test_exact_refusal_replay_is_the_same_object_and_adds_no_work(self):
        retained = self.retained()
        self.assertIs(hold.retain_claim(retained, self.refusal(), kind="refusal"), retained)
        self.assertEqual(retained.review()["retained_refusal_claims"], 1)

    def test_exact_source_replay_is_the_same_object_and_supplies_no_freshness(self):
        retained = hold.retain_claim(self.initial, self.source(), kind="source")
        self.assertIs(hold.retain_claim(retained, self.source(), kind="source"), retained)
        self.assertEqual(retained.review()["source_currentness"], "UNFILLED")

    def test_claim_order_keeps_all_exact_bytes_and_cannot_delete_the_prefix(self):
        retained = self.retained()
        for name in ("complete", "unavailable", "unknown", "contradicted"):
            retained = hold.retain_claim(retained, self.source(name), kind="source")
        self.assertEqual(retained.as_dict()["source_claim_wires_hex"],
                         [self.source(name).hex() for name in ("complete", "unavailable", "unknown", "contradicted")])
        self.assertEqual(retained.as_dict()["refusal_wires_hex"], [self.refusal().hex()])

    def test_complete_failed_and_unknown_charges_all_remain_charged(self):
        selected = self.selected()
        for outcome in ("UNKNOWN", "COMPLETE", "FAILED"):
            work = copy.deepcopy(selected["charged_work"])
            work[0]["outcome"] = outcome
            initial = hold.select_hold(self.query, charged_work=work, prior_evidence=[b"synthetic retained evidence"])
            retained = hold.retain_claim(initial, self.source("unavailable"), kind="source")
            self.assertEqual(retained.review()["charged_work"], 1)
            self.assertEqual(self.selected(retained.as_dict())["charged_work"], work)

    def test_exhausted_selected_work_is_not_replenished_by_complete_or_unavailable(self):
        retained = qualify.selected_hold(charged=16)
        for name in ("complete", "unavailable"):
            retained = hold.retain_claim(retained, self.source(name), kind="source")
        self.assertEqual(retained.review()["charged_work"], 16)
        self.assertIs(retained.review()["replenish_work"], False)

    def test_changed_original_bytes_cannot_replace_the_exact_selected_operation(self):
        selection = self.selected()
        query = json.loads(bytes.fromhex(selection["query_hex"]))
        original = json.loads(bytes.fromhex(query["originals_hex"]["short"]))
        original["signature_hex"] = "11" * 64
        query["originals_hex"]["short"] = qualify.wire(original).hex()
        selection["query_hex"] = qualify.wire(query).hex()
        self.selection_refused(selection)

    def test_same_bytes_are_bound_with_a_distinct_non_account_hash_domain(self):
        from offline_session.nom_recovery import synthetic_transaction_hash
        original = bytes.fromhex(self.query.as_dict()["originals_hex"]["short"])
        self.assertNotEqual(hold.original_digest(original), synthetic_transaction_hash(original))
        self.assertEqual(self.selected()["charged_work"][0]["original_digest_hex"], hold.original_digest(original))

    def test_new_query_challenge_cannot_replay_old_claim_or_erase_old_hold(self):
        query = self.query.as_dict()
        query["challenge_hex"] = "99" * 32
        newer = hold._query(qualify.wire(query))
        initial = hold.select_hold(newer, charged_work=self.selected()["charged_work"], prior_evidence=[])
        with self.assertRaises(hold.NoMUncertaintyRefused):
            hold.retain_claim(initial, self.source(), kind="source")
        self.assertEqual(initial.review()["charged_work"], 1)
        self.assertEqual(self.initial.review()["retained_prior_evidence"], 2)

    def test_omitted_charged_work_is_refused_against_independent_retained_selection(self):
        selection = self.selected(); selection["charged_work"] = []
        self.selection_refused(selection)

    def test_unknown_work_cannot_be_rewritten_as_a_completed_outcome(self):
        selection = self.selected(); selection["charged_work"][0]["outcome"] = "COMPLETE"
        self.selection_refused(selection)

    def test_possible_disclosure_cannot_be_erased_by_false_claimed_knowledge(self):
        selection = self.selected(); selection["disclosure_possible"] = False
        self.selection_refused(selection)

    def test_prior_evidence_cannot_be_dropped_or_reordered_against_retained_selection(self):
        for evidence in (self.selected()["prior_evidence_hex"][:1], list(reversed(self.selected()["prior_evidence_hex"]))):
            selection = self.selected(); selection["prior_evidence_hex"] = evidence
            self.selection_refused(selection)

    def test_omitted_refusal_prefix_cannot_match_the_retained_hold(self):
        retained = self.retained(); value = retained.as_dict(); value["refusal_wires_hex"] = []
        self.compare_refused(value, retained)

    def test_omitted_source_evidence_cannot_match_the_retained_hold(self):
        retained = hold.retain_claim(self.retained(), self.source(), kind="source")
        value = retained.as_dict(); value["source_claim_wires_hex"] = []
        self.compare_refused(value, retained)

    def test_mutable_inputs_and_returned_copies_cannot_alter_immutable_selection(self):
        before = self.initial.canonical_bytes
        value = self.initial.as_dict(); value["selection_hex"] = "00"
        self.assertEqual(self.initial.canonical_bytes, before)
        with self.assertRaises(FrozenInstanceError):
            self.initial._wire = b"{}"
        with self.assertRaises(TypeError):
            hold.NoMUncertaintyHold()

    def test_unknown_and_missing_fields_in_selection_state_and_refusal_are_refused(self):
        value = self.initial.as_dict(); value["permission"] = True
        self.compare_refused(value)
        selection = self.selected(); del selection["disclosure_possible"]
        self.selection_refused(selection)
        value = json.loads(self.refusal()); value["recovery_permission"] = True
        with self.assertRaises(hold.NoMUncertaintyRefused):
            hold.retain_claim(self.initial, qualify.wire(value), kind="refusal")

    def test_noncanonical_duplicate_nonfinite_and_non_ascii_bytes_are_refused(self):
        for wire in (b'{"selection_hex":"00","selection_hex":"00"}', b'{"x":NaN}',
                     b'{"x":"\xff"}', b' ' + self.initial.canonical_bytes):
            with self.assertRaises(hold.NoMUncertaintyRefused):
                hold.compare_hold(self.initial, wire)

    def test_depth_and_total_byte_bounds_refuse_before_any_retention_change(self):
        before = self.initial.canonical_bytes
        for wire in (b'[' * 13 + b'0' + b']' * 13, b' ' * (hold.MAX_WIRE_BYTES + 1)):
            with self.assertRaises(hold.NoMUncertaintyRefused):
                hold.compare_hold(self.initial, wire)
        self.assertEqual(self.initial.canonical_bytes, before)

    def test_refusal_count_allowance_exhaustion_preserves_exact_previous_image(self):
        retained = self.initial
        for number in range(8):
            value = json.loads(self.refusal()); value["record_digest_hex"] = bytes([number]).hex() * 32
            retained = hold.retain_claim(retained, qualify.wire(value), kind="refusal")
        before = retained.canonical_bytes
        value["record_digest_hex"] = "99" * 32
        with self.assertRaises(hold.NoMUncertaintyRefused):
            hold.retain_claim(retained, qualify.wire(value), kind="refusal")
        self.assertEqual(retained.canonical_bytes, before)
        self.assertEqual(retained.review()["charged_work"], 1)

    def test_source_claim_allowance_exhaustion_preserves_exact_previous_image(self):
        retained = self.initial
        for number in range(8):
            value = json.loads(self.source())
            value["facts"]["network_profile"]["evidence_digest_hex"] = bytes([number]).hex() * 32
            retained = hold.retain_claim(retained, qualify.wire(value), kind="source")
        before = retained.canonical_bytes
        value["facts"]["network_profile"]["evidence_digest_hex"] = "99" * 32
        with self.assertRaises(hold.NoMUncertaintyRefused):
            hold.retain_claim(retained, qualify.wire(value), kind="source")
        self.assertEqual(retained.canonical_bytes, before)

    def test_prior_evidence_bytes_and_count_are_bounded_and_unique(self):
        for evidence in ([b"x"] * 2, [b"x" * 513], [bytes([i]) for i in range(9)], [b""]):
            with self.assertRaises(hold.NoMUncertaintyRefused):
                hold.select_hold(self.query, charged_work=[], prior_evidence=evidence)

    def test_duplicate_wrong_original_and_oversized_work_selections_are_refused(self):
        work = self.selected()["charged_work"]
        wrong = copy.deepcopy(work); wrong[0]["original_digest_hex"] = "00" * 32
        for selected in (work * 2, wrong, work * 17):
            with self.assertRaises(hold.NoMUncertaintyRefused):
                hold.select_hold(self.query, charged_work=selected, prior_evidence=[])

    def test_wire_kind_and_boolean_or_mutable_work_types_are_refused(self):
        for selected in (True, {}, (), "UNKNOWN"):
            with self.assertRaises(hold.NoMUncertaintyRefused):
                hold.select_hold(self.query, charged_work=selected, prior_evidence=[])
        for wire, kind in ((bytearray(self.refusal()), "refusal"), (self.refusal(), True), (self.source(), "observer")):
            with self.assertRaises(hold.NoMUncertaintyRefused):
                hold.retain_claim(self.initial, wire, kind=kind)

    def test_exact_local_replay_and_coherent_older_copy_supply_no_restore_fence(self):
        newer = self.retained()
        self.assertIs(hold.compare_hold(newer, newer.canonical_bytes), newer)
        with self.assertRaises(hold.NoMUncertaintyRefused):
            hold.compare_hold(newer, self.initial.canonical_bytes)
        self.assertIs(hold.compare_hold(self.initial, self.initial.canonical_bytes), self.initial)
        self.assertEqual((self.initial.review()["restore_fence"], self.initial.review()["recovery_action"]), ("UNFILLED", "NONE"))

    def test_complete_selected_finite_domain_runs_twenty_eight_schedules_per_policy(self):
        for policy in model.POLICIES:
            result = model.compare(policy, self.fixture)
            self.assertTrue(result["complete"])
            self.assertEqual((result["executed_schedules"], result["selected_schedules"], result["transitions"]), (28, 28, 136))

    def test_forgetting_unavailable_evidence_erases_charges_and_reopens_exhausted_work(self):
        result = model.compare("forget-on-unavailable", self.fixture)
        self.assertGreater(result["erased_charges"], 0)
        self.assertGreater(result["unsafe_entries"], 0)
        self.assertTrue(any(row["initial_charged_work"] == 16 and row["abstract_effects"] > 0 for row in result["counterexamples"]))

    def test_releasing_on_supported_claim_has_untrusted_entry_counterexamples(self):
        result = model.compare("release-on-supported", self.fixture)
        self.assertGreater(result["unsafe_entries"], 0)
        self.assertEqual(result["erased_charges"], 0)
        self.assertEqual(result["source_authentication"], "NOT_PERFORMED")

    def test_every_selected_hold_ordering_keeps_zero_new_effects_and_zero_reset_charges(self):
        result = model.compare("retain-hold", self.fixture)
        self.assertEqual((result["abstract_effects"], result["erased_charges"], result["unsafe_entries"], result["counterexamples"]), (0, 0, 0, []))
        self.assertEqual(result["coherent_restore_losses"], 2)
        self.assertEqual((result["application"], result["core"], result["recovery_action"]), ("NO-GO", "NO-GO", "NONE"))

    def test_partial_finite_caps_cannot_report_complete_or_external_verification(self):
        for cap in (0, 1, 27):
            result = model.compare("retain-hold", self.fixture, schedule_limit=cap)
            self.assertFalse(result["complete"])
            self.assertEqual(result["executed_schedules"], cap)
        for cap in (-1, True, "1"):
            with self.assertRaises(ValueError):
                model.compare("retain-hold", self.fixture, schedule_limit=cap)

    def test_partial_cli_exits_two_and_reports_no_recovery_action(self):
        result = subprocess.run([sys.executable, "-B", "-m", "scripts.model_nom_uncertainty", "--schedule-limit", "0"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        self.assertFalse(json.loads(result.stdout)["complete"])
        self.assertEqual(json.loads(result.stdout)["recovery_action"], "NONE")


if __name__ == "__main__":
    unittest.main()
