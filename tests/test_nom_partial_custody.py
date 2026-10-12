"""Disclosed synthetic partial selections; no actual journal interruption tests."""

import copy
import dataclasses
import hashlib
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from offline_session import nom_partial_custody as hold, nom_recovery as recovery
from scripts import qualify_nom_partial_custody as qualify, model_nom_partial_custody as model


class PartialCustodyTests(unittest.TestCase):
    def setUp(self):
        self.initial = qualify.selected_hold()
        self.fixture = json.loads((qualify.ROOT / qualify.FIXTURE).read_text("ascii"))

    def claim(self, name="supported", selected=None):
        return qualify.source_claim(selected or self.initial, name)

    def selected(self, **updates):
        selected = self.initial.selection(); selected.update(updates)
        return hold.select_partial_hold(selected["terms"], selected["pair"], bytes.fromhex(selected["remote_short_hex"]),
            charged_work=selected["charged_work"], prior_evidence=[bytes.fromhex(w) for w in selected["prior_evidence_hex"]],
            recovered_long_signature=selected["recovered_long_signature_hex"],
            original_long=None if selected["original_long_hex"] is None else bytes.fromhex(selected["original_long_hex"]),
            challenge_hex=selected["challenge_hex"])

    def refuse_state(self, selected):
        state = self.initial.as_dict(); state["selection_hex"] = qualify.wire(selected).hex()
        with self.assertRaises(hold.PartialCustodyRefused):
            hold.compare_hold(self.initial, qualify.wire(state))

    def refuse_claim(self, value):
        with self.assertRaises(hold.PartialCustodyRefused):
            hold.retain_claim(self.initial, qualify.wire(value), kind="source")

    def test_admitted_unknown_charge_does_not_require_an_uncreated_long_original(self):
        selected = self.initial.selection()
        self.assertIsNone(selected["recovered_long_signature_hex"])
        self.assertIsNone(selected["original_long_hex"])
        self.assertEqual(self.initial.review()["long_original_custody"], hold.MISSING)
        self.assertEqual(self.initial.review()["long_result_custody"], hold.MISSING)
        self.assertEqual(self.initial.review()["charged_work"], 1)

    def test_known_public_result_does_not_imply_retained_original_custody(self):
        selected = qualify.selected_hold(qualify.CUTS[1])
        self.assertIsNotNone(selected.selection()["recovered_long_signature_hex"])
        self.assertIsNone(selected.selection()["original_long_hex"])
        self.assertEqual(selected.review()["long_result_custody"], "PUBLIC_RESULT_RETAINED")
        self.assertEqual(selected.review()["long_original_custody"], hold.MISSING)

    def test_exact_retained_original_is_separate_from_a_retained_public_result(self):
        selected = qualify.selected_hold(qualify.CUTS[2])
        original = bytes.fromhex(selected.selection()["original_long_hex"])
        signature = recovery.claim_signature(selected.selection()["terms"], "long", original)
        self.assertEqual(signature, selected.selection()["recovered_long_signature_hex"])
        self.assertEqual(selected.review()["long_original_custody"], "EXACT_SELECTED_BYTES")
        self.assertEqual(selected.review()["recovery_action"], "NONE")

    def test_present_long_fixture_cannot_fill_the_absent_cut(self):
        completions = json.loads((qualify.ROOT / qualify.SELECTION_INPUTS[1]).read_text("ascii"))
        self.assertTrue(completions["long_signature_hex"])
        self.assertNotIn(completions["long_signature_hex"], self.initial.canonical_bytes.decode("ascii"))
        self.assertIsNone(self.initial.selection()["original_long_hex"])

    def test_forgeable_supported_zero_digest_preserves_both_absences(self):
        retained = hold.retain_claim(self.initial, self.claim(), kind="source")
        self.assertEqual(retained.selection(), self.initial.selection())
        self.assertEqual((retained.review()["long_result_custody"], retained.review()["long_original_custody"]),
            (hold.MISSING, hold.MISSING))
        self.assertEqual(retained.review()["recovery_action"], "NONE")

    def test_supported_claim_cannot_construct_an_original_from_retained_result(self):
        initial = qualify.selected_hold(qualify.CUTS[1])
        retained = hold.retain_claim(initial, self.claim(selected=initial), kind="source")
        self.assertIsNone(retained.selection()["original_long_hex"])
        self.assertEqual(retained.selection()["recovered_long_signature_hex"], initial.selection()["recovered_long_signature_hex"])

    def test_unavailable_after_supported_preserves_work_and_possible_disclosure(self):
        retained = hold.retain_claim(self.initial, self.claim(), kind="source")
        retained = hold.retain_claim(retained, self.claim("unavailable"), kind="source")
        self.assertEqual(retained.selection(), self.initial.selection())
        self.assertIs(retained.review()["disclosure_possible"], True)
        self.assertIs(retained.review()["automatic_retry"], False)

    def test_both_selected_refusal_labels_preserve_exact_short_and_prior_evidence(self):
        retained = self.initial
        for wire in self.fixture["refusals_hex"].values():
            retained = hold.retain_claim(retained, bytes.fromhex(wire), kind="refusal")
        self.assertEqual(retained.selection(), self.initial.selection())
        self.assertEqual(retained.review()["retained_refusal_claims"], 2)
        self.assertEqual(retained.review()["native_query_context_pairing"], "NOT_COMPOSED")

    def test_false_failure_labels_are_opaque_and_cannot_provide_missing_custody(self):
        value = json.loads(bytes.fromhex(self.fixture["refusals_hex"]["after-one-actual-pop"]))
        value["failure"] = {"target_reached": True, "long_original_exists": True}
        retained = hold.retain_claim(self.initial, qualify.wire(value), kind="refusal")
        self.assertEqual(retained.selection(), self.initial.selection())
        self.assertEqual(retained.review()["recovery_action"], "NONE")

    def test_unknown_complete_and_failed_work_labels_all_remain_charged(self):
        for outcome in ("UNKNOWN", "COMPLETE", "FAILED"):
            initial = qualify.selected_hold(outcome=outcome)
            retained = hold.retain_claim(initial, self.claim("unavailable", initial), kind="source")
            self.assertEqual(retained.review()["charged_work"], 1)
            self.assertEqual(retained.review()["long_result_custody"], hold.MISSING)
            self.assertEqual(retained.review()["worker_execution_from_absence"], "NOT_ESTABLISHED")

    def test_exhausted_sixteen_charges_stay_exhausted_with_missing_result(self):
        initial = qualify.selected_hold(charged=16)
        for name in ("supported", "unavailable"):
            initial = hold.retain_claim(initial, self.claim(name, initial), kind="source")
        self.assertEqual(initial.review()["charged_work"], 16)
        self.assertIs(initial.review()["replenish_work"], False)

    def test_zero_boolean_or_seventeen_charges_are_refused(self):
        for count in (0, True, 17):
            with self.assertRaises(ValueError):
                qualify.selected_hold(charged=count)
        with self.assertRaises(hold.PartialCustodyRefused):
            self.selected(charged_work=[])

    def test_duplicate_attempt_identifier_is_refused(self):
        work = self.initial.selection()["charged_work"]
        with self.assertRaises(hold.PartialCustodyRefused):
            self.selected(charged_work=work + copy.deepcopy(work))

    def test_work_must_bind_the_exact_short_original_in_its_own_domain(self):
        work = self.initial.selection()["charged_work"]
        work[0]["short_original_digest_hex"] = "00" * 32
        with self.assertRaises(hold.PartialCustodyRefused):
            self.selected(charged_work=work)
        short = bytes.fromhex(self.initial.selection()["remote_short_hex"])
        self.assertNotEqual(hold.short_digest(short), recovery.synthetic_transaction_hash(short))

    def test_absent_result_cannot_acquire_fixture_original_against_retained_selection(self):
        selected = self.initial.selection()
        full = qualify.selected_hold(qualify.CUTS[2]).selection()
        selected["recovered_long_signature_hex"] = full["recovered_long_signature_hex"]
        selected["original_long_hex"] = full["original_long_hex"]
        self.refuse_state(selected)

    def test_original_without_selected_result_is_refused(self):
        full = qualify.selected_hold(qualify.CUTS[2]).selection()
        with self.assertRaises(hold.PartialCustodyRefused):
            self.selected(original_long_hex=full["original_long_hex"])

    def test_retained_original_must_match_exact_selected_public_result(self):
        full = qualify.selected_hold(qualify.CUTS[2]).selection()
        with self.assertRaises(hold.PartialCustodyRefused):
            self.selected(original_long_hex=full["original_long_hex"], recovered_long_signature_hex="11" * 64)

    def test_mismatched_fixed_terms_refuse_retained_short_bytes(self):
        terms = self.initial.selection()["terms"]
        terms["long"]["entry_id_hex"] = "71" * 32
        with self.assertRaises(hold.PartialCustodyRefused):
            self.selected(terms=terms)

    def test_public_pair_changes_are_bound_but_not_cryptographically_authenticated(self):
        selected = self.initial.selection(); selected["pair"]["long_presignature_hex"] = "02" + "11" * 64
        selected["verification_context_digest_hex"] = recovery.verification_context_digest(selected["terms"], selected["pair"])
        self.refuse_state(selected)
        changed = self.selected(pair=selected["pair"])
        self.assertNotEqual(changed.selection_digest_hex, self.initial.selection_digest_hex)
        self.assertEqual(changed.review()["signature_mathematics"], "NOT_PERFORMED")

    def test_original_short_alteration_cannot_match_the_retained_operation(self):
        selected = self.initial.selection()
        wire = json.loads(bytes.fromhex(selected["remote_short_hex"]))
        wire["signature_hex"] = "11" * 64
        selected["remote_short_hex"] = qualify.wire(wire).hex()
        self.refuse_state(selected)

    def test_charge_erasure_and_outcome_rewrite_cannot_match_retained_bytes(self):
        for mode in ("erase", "outcome"):
            selected = self.initial.selection()
            if mode == "erase": selected["charged_work"] = []
            else: selected["charged_work"][0]["outcome"] = "COMPLETE"
            self.refuse_state(selected)

    def test_possible_disclosure_cannot_be_reset(self):
        selected = self.initial.selection(); selected["disclosure_possible"] = False
        self.refuse_state(selected)

    def test_prior_evidence_prefix_cannot_be_dropped_or_reordered(self):
        for evidence in ([], list(reversed(self.initial.selection()["prior_evidence_hex"]))):
            selected = self.initial.selection(); selected["prior_evidence_hex"] = evidence
            self.refuse_state(selected)

    def test_changing_challenge_or_partial_cut_rejects_old_source_claim(self):
        for selected in (self.selected(challenge_hex="52" * 32), qualify.selected_hold(qualify.CUTS[1])):
            with self.assertRaises(hold.PartialCustodyRefused):
                hold.retain_claim(selected, self.claim(), kind="source")

    def test_exact_source_replay_returns_the_same_object_without_freshness(self):
        retained = hold.retain_claim(self.initial, self.claim(), kind="source")
        self.assertIs(hold.retain_claim(retained, self.claim(), kind="source"), retained)
        self.assertEqual(retained.review()["source_currentness"], "UNFILLED")

    def test_exact_refusal_replay_returns_same_object_without_work(self):
        wire = bytes.fromhex(self.fixture["refusals_hex"]["before-first-pop"])
        retained = hold.retain_claim(self.initial, wire, kind="refusal")
        self.assertIs(hold.retain_claim(retained, wire, kind="refusal"), retained)
        self.assertEqual(retained.review()["charged_work"], 1)

    def test_source_claim_cap_refuses_ninth_claim_and_preserves_eight(self):
        retained = self.initial
        for number in range(8):
            value = json.loads(self.claim()); value["evidence_digest_hex"] = bytes([number]).hex() * 32
            retained = hold.retain_claim(retained, qualify.wire(value), kind="source")
        before = retained.canonical_bytes
        value["evidence_digest_hex"] = "09" * 32
        with self.assertRaises(hold.PartialCustodyRefused):
            hold.retain_claim(retained, qualify.wire(value), kind="source")
        self.assertEqual(retained.canonical_bytes, before)

    def test_refusal_cap_refuses_ninth_claim_without_erasing_prefix(self):
        retained = self.initial
        value = json.loads(bytes.fromhex(self.fixture["refusals_hex"]["before-first-pop"]))
        for number in range(8):
            value["record_digest_hex"] = bytes([number]).hex() * 32
            retained = hold.retain_claim(retained, qualify.wire(value), kind="refusal")
        before = retained.canonical_bytes
        value["record_digest_hex"] = "09" * 32
        with self.assertRaises(hold.PartialCustodyRefused):
            hold.retain_claim(retained, qualify.wire(value), kind="refusal")
        self.assertEqual(retained.canonical_bytes, before)

    def test_prior_evidence_caps_and_duplicate_bytes_are_refused(self):
        selected = self.initial.selection()
        for values in ([b"x"] * 2, [bytes([n]) for n in range(9)], [b"x" * 513]):
            with self.assertRaises(hold.PartialCustodyRefused):
                hold.select_partial_hold(selected["terms"], selected["pair"], bytes.fromhex(selected["remote_short_hex"]),
                    charged_work=selected["charged_work"], prior_evidence=values, challenge_hex="51" * 32)

    def test_malformed_or_extra_source_fields_refuse_without_input_leakage(self):
        value = json.loads(self.claim()); value["status"] = "public synthetic invalid label"
        self.refuse_claim(value)
        value = json.loads(self.claim()); value["original_long_hex"] = "11" * 64
        self.refuse_claim(value)
        with self.assertRaisesRegex(hold.PartialCustodyRefused, "^partial NoM custody claim refused$"):
            hold.retain_claim(self.initial, b"public synthetic invalid bytes", kind="source")

    def test_unavailable_with_supported_status_is_refused(self):
        value = json.loads(self.claim()); value["availability"] = "unavailable"
        self.refuse_claim(value)

    def test_unhashable_claim_hex_is_sanitized(self):
        value = self.initial.as_dict(); value["source_claim_wires_hex"] = [{}]
        with self.assertRaises(hold.PartialCustodyRefused):
            hold.compare_hold(self.initial, qualify.wire(value))

    def test_duplicate_json_key_is_refused(self):
        with self.assertRaises(hold.PartialCustodyRefused):
            hold.retain_claim(self.initial, b'{"schema":"x","schema":"y"}', kind="source")

    def test_wire_and_nesting_budgets_refuse_before_comparison(self):
        for wire in (b"x" * (hold.MAX_WIRE_BYTES + 1), b"[" * 13 + b"0" + b"]" * 13):
            with self.assertRaises(hold.PartialCustodyRefused):
                hold.compare_hold(self.initial, wire)

    def test_noncanonical_hex_and_wrong_result_lengths_are_refused(self):
        for result in ("11" * 63, True, "AB" * 64):
            with self.assertRaises(hold.PartialCustodyRefused):
                self.selected(recovered_long_signature_hex=result)
        selected = self.initial.selection(); selected["remote_short_hex"] = selected["remote_short_hex"].upper()
        self.refuse_state(selected)

    def test_caller_and_returned_dictionary_mutation_cannot_change_frozen_hold(self):
        original = self.initial.canonical_bytes
        selected = self.initial.selection(); selected["charged_work"][0]["outcome"] = "FAILED"
        value = self.initial.as_dict(); value["source_claim_wires_hex"].append("00")
        self.assertEqual(self.initial.canonical_bytes, original)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.initial._wire = b"{}"

    def test_coherent_old_copy_passes_only_its_own_comparison_without_restore_authority(self):
        retained = hold.retain_claim(self.initial, self.claim(), kind="source")
        with self.assertRaises(hold.PartialCustodyRefused):
            hold.compare_hold(retained, self.initial.canonical_bytes)
        self.assertIs(hold.compare_hold(self.initial, self.initial.canonical_bytes), self.initial)
        self.assertEqual(self.initial.review()["restore_fence"], "UNFILLED")

    def test_partial_hold_is_not_the_frozen_complete_query_or_observation_callback(self):
        from offline_session.nom_authority_contract import NoMReadQuery
        self.assertNotIsInstance(self.initial, NoMReadQuery)
        self.assertFalse(callable(self.initial))
        self.assertEqual(self.initial.review()["complete_query_conversion"], "NOT_PROVIDED")
        self.assertEqual(self.initial.review()["journal_composition"], "NOT_PERFORMED")

    def test_pure_selection_and_claims_never_call_a_journal_or_public_worker(self):
        with patch("offline_session.nom_recovery.NomRecovery.open", side_effect=AssertionError("journal execution forbidden")), \
             patch("offline_session.nom_verifier.NomPublicVerifier._verify", side_effect=AssertionError("worker execution forbidden")):
            selected = qualify.selected_hold()
            retained = hold.retain_claim(selected, self.claim(), kind="source")
            self.assertIs(hold.compare_hold(retained, retained.canonical_bytes), retained)

    def test_separate_fixture_manifest_and_preserved_input_pairing(self):
        manifest, fixture, measured = qualify.inputs()
        self.assertEqual(fixture, self.fixture)
        self.assertEqual(len(manifest["preserved_file_sha256"]), 135)
        self.assertGreaterEqual(len(measured), 141)
        for cut in qualify.CUTS:
            self.assertEqual(fixture["holds_hex"][cut], qualify.selected_hold(cut).canonical_bytes.hex())

    def test_selected_policies_have_counterexamples_and_pure_hold_has_no_effects(self):
        rows = [model.compare(policy, self.fixture) for policy in model.POLICIES]
        self.assertEqual([r["selected_schedules"] for r in rows], [36] * 3)
        self.assertEqual([r["transitions"] for r in rows], [180] * 3)
        self.assertEqual([r["invented_originals"] for r in rows], [24, 12, 0])
        self.assertEqual([r["new_worker_entries"] for r in rows], [12, 6, 0])
        self.assertEqual([r["coherent_old_copy_losses"] for r in rows], [36] * 3)

    def test_truncated_finite_enumeration_is_incomplete_and_cli_returns_two(self):
        row = model.compare(model.POLICIES[-1], self.fixture, schedule_limit=1)
        self.assertFalse(row["complete"])
        result = subprocess.run([sys.executable, "-B", str(qualify.ROOT / "scripts/model_nom_partial_custody.py"),
            "--schedule-limit", "1"], capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(all(not r["complete"] for r in json.loads(result.stdout)))

    def test_complete_pure_qualification_retains_missing_custody_and_separate_gates(self):
        result = qualify.qualify()
        self.assertEqual((result["outcome"], result["new_native_outcomes"]), ("PASS", 0))
        self.assertEqual(len(result["cases"]), 6)
        self.assertEqual(result["preserved_source_tests_including_parents"], 342)
        self.assertEqual(result["reference_journal_cut_execution"], "NOT_PERFORMED; CALLER-SELECTED STATES ONLY")
        self.assertTrue(all(row["review"]["recovery_action"] == "NONE" for row in result["cases"]))


if __name__ == "__main__":
    unittest.main()
