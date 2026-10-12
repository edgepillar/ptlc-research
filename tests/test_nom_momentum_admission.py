"""Adversarial controls for local actual-source momentum execution."""

import copy
import json
from pathlib import Path
import unittest

from scripts import qualify_nom_momentum_admission as admission
from scripts.generate_nom_momentum_admission import CASE, FIXTURE, corpus

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))


class NoMMomentumAdmissionTests(unittest.TestCase):
    def setUp(self): self.records = copy.deepcopy(FIX["records"]); self.r = self.records[CASE]
    def refused(self):
        with self.assertRaises(ValueError): admission.validate_records(self.records)
    def stage(self): return self.r["stages"]["after-sends"]
    def control(self): return self.r["refusals"]["producer-rejected"]
    def stream(self):
        return (json.dumps({"Action": "output", "Package": admission.PACKAGE, "Test": admission.TEST + "/" + CASE,
            "Output": "    zz_research_nom_momentum_admission_test.go:900: " + admission.PREFIX + json.dumps(self.r) + "\n"}) + "\n").encode("ascii")

    def test_complete_profile_preserves_old_originals_and_source_qualification(self):
        manifest, fixture, measured = admission.inputs(ROOT)
        self.assertEqual(fixture, corpus(admission.validate_records(self.records)))
        self.assertEqual(len(manifest["preserved_file_sha256"]), 97)
        self.assertIn(admission.prior.MANIFEST, measured)
        self.assertEqual(len(admission.expected_tests()[admission.PACKAGE]), 15)

    def test_independent_hash_and_protobuf_require_content_in_exact_order(self):
        self.stage()["momentum"]["momentum"]["content"].reverse(); self.refused()

    def test_independent_vm_delta_cannot_include_unselected_writes(self):
        self.stage()["delta_patch_hex"] += "0101780179"; self.refused()

    def test_exact_apply_must_reproduce_the_generated_delta(self):
        self.stage()["exact_apply_patch_hex"] = ""; self.refused()

    def test_manager_patch_requires_original_delta_and_ordered_frontier_augmentation(self):
        self.stage()["manager_patch_hex"] = self.stage()["delta_patch_hex"]; self.refused()

    def test_manager_changes_must_be_stolen_only_on_selected_add(self):
        self.stage()["manager_stole_changes"] = False; self.refused()

    def test_normal_pool_patches_cannot_be_replaced_with_vm_deltas(self):
        self.r["pool_patches"]["send-first"] = self.r["candidates"]["send-first"]["delta_patch_hex"]; self.refused()

    def test_generated_momentum_signs_exactly_once(self):
        self.stage()["generation_signatures"] = 0; self.refused()

    def test_exact_momentum_apply_never_signs(self):
        self.stage()["apply_signatures"] = 1; self.refused()

    def test_each_valid_transaction_reaches_separate_producer_verification(self):
        self.stage()["apply_producer_calls"] = 0; self.refused()

    def test_self_signature_cannot_bypass_false_selected_producer_response(self):
        self.control()["result"] = "PASS"; self.refused()

    def test_producer_error_cannot_be_converted_into_acceptance(self):
        self.r["refusals"]["producer-error"]["transaction_present"] = True; self.refused()

    def test_static_hash_refusal_does_not_consult_producer(self):
        self.r["refusals"]["outer-hash"]["producer_calls"] = 1; self.refused()

    def test_structural_refusal_requires_an_isolated_previous_snapshot(self):
        self.r["refusals"]["reversed-content"]["snapshot_calls"] = 0; self.refused()

    def test_every_refusal_preserves_complete_original_stable_db(self):
        self.control()["stable_dump_hex"] = self.r["checkpoints"]["after-sends"]["global_dump_hex"]; self.refused()

    def test_refusals_cannot_return_partial_transactions(self):
        self.control()["transaction_present"] = True; self.refused()

    def test_all_thirteen_refusals_are_required(self):
        del self.r["refusals"]["nil-prefetch"]; self.refused()

    def test_refusal_candidates_require_exact_selected_mutations(self):
        self.r["refusals"]["changes-hash"]["candidate"] = copy.deepcopy(self.stage()["momentum"]); self.refused()

    def test_nil_prefetch_refusal_requires_exact_nil_input(self):
        self.r["refusals"]["nil-prefetch"]["prefetched_wires"] = self.stage()["prefetched_wires"]; self.refused()

    def test_refusal_error_cannot_be_replaced_with_an_unselected_failure(self):
        self.control()["error"] = "unselected error"; self.refused()

    def test_boolean_counts_cannot_replace_measured_integer_counts(self):
        self.stage()["generation_producer_calls"] = True; self.refused()

    def test_complete_account_state_includes_both_original_sends(self):
        self.r["checkpoints"]["after-sends"]["sender"]["account_dump_hex"] = ""; self.refused()

    def test_global_block_lookup_must_return_exact_original_wire(self):
        self.r["checkpoints"]["after-sends"]["send-first"]["wire_hex"] = self.r["candidates"]["send-second"]["block"]["wire_hex"]; self.refused()

    def test_confirmation_height_is_set_by_actual_momentum_store(self):
        self.r["checkpoints"]["after-sends"]["send-first"]["confirmation_height"] = "10109300"; self.refused()

    def test_mailbox_pending_entry_is_removed_only_for_exact_received_send(self):
        self.r["checkpoints"]["after-receive"]["recipient"]["pending_hashes"] = []; self.refused()

    def test_sender_mailbox_retains_exact_receive_ownership_header(self):
        self.r["checkpoints"]["after-receive"]["sender"]["mailbox_dump_hex"] = ""; self.refused()

    def test_complete_global_state_cannot_omit_zero_balance_index(self):
        self.r["checkpoints"]["after-sends"]["global_dump_hex"] = self.r["checkpoints"]["initial"]["global_dump_hex"]; self.refused()

    def test_actual_prefetch_must_keep_original_content_order(self):
        self.stage()["prefetched_wires"].reverse(); self.refused()

    def test_source_record_requires_complete_correct_package_framing(self):
        self.assertEqual(admission.collect_records(self.stream()), self.records)
        with self.assertRaises(ValueError): admission.collect_records(self.stream().replace(admission.PACKAGE.encode(), b"unselected/package"))

    def test_duplicate_truncated_and_extended_records_are_refused(self):
        wire = self.stream()
        with self.assertRaises(ValueError): admission.collect_records(wire + wire)
        with self.assertRaises((ValueError, json.JSONDecodeError)): admission.collect_records(wire[:-20])
        self.r["unselected"] = "true"; self.refused()
