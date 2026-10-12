"""Adversarial controls for both actual pops, intermediate retention and complete listeners."""

import copy
import json
from pathlib import Path
import unittest

from scripts import qualify_nom_multi_rollback as batch
from scripts.generate_nom_multi_rollback import CASE, FIXTURE, corpus

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text('ascii'))


class NoMMultiRollbackTests(unittest.TestCase):
    def setUp(self): self.records = copy.deepcopy(FIX['records']); self.r = self.records[CASE]
    def refused(self):
        with self.assertRaises(ValueError): batch.validate_records(self.records)
    def control(self): return self.r['controls']['old-receipt-before-confirmation']
    def stream(self):
        return (json.dumps({'Action': 'output', 'Package': batch.PACKAGE, 'Test': batch.TEST + '/' + CASE,
            'Output': '    zz_research_nom_multi_rollback_test.go:900: ' + batch.PREFIX + json.dumps(self.r) + '\n'}) + '\n').encode('ascii')

    def test_complete_profile_preserves_all_prior_originals_and_source_controls(self):
        manifest, fixture, measured = batch.inputs(ROOT)
        self.assertEqual(fixture, corpus(batch.validate_records(self.records)))
        self.assertEqual(len(manifest['preserved_file_sha256']), 115)
        self.assertIn(batch.prior.MANIFEST, measured)
        self.assertEqual(len(batch.expected_tests()[batch.PACKAGE]), 8)

    def test_actual_selector_cannot_reverse_child_and_parent(self):
        self.r['selection_wires'].reverse(); self.refused()

    def test_actual_selector_cannot_omit_child_header(self):
        self.r['selection_wires'] = self.r['selection_wires'][1:]; self.refused()

    def test_original_parent_and_inner_witness_bytes_cannot_be_replaced(self):
        self.r['input']['parent_wire_hex'] = ''; self.refused()

    def test_independent_initial_global_state_cannot_omit_mailbox_sequencer(self):
        self.r['input']['root_hex'] = ''; self.refused()

    def test_exact_parent_apply_never_signs(self):
        self.r['parent_apply_signatures'] = 1; self.refused()

    def test_empty_child_patch_is_not_an_independent_transaction_patch(self):
        self.r['pool_patches']['child'] = self.r['pool_patches']['parent']; self.refused()

    def test_augmented_parent_patch_requires_both_original_frontiers(self):
        self.r['pool_patches']['parent'] = self.r['input']['parent_delta_hex']; self.refused()

    def test_vm_delta_requires_complete_global_header_and_confirmation_writes(self):
        self.r['delta_patch_hex'] = ''; self.refused()

    def test_exact_momentum_apply_must_reproduce_generated_delta(self):
        self.r['exact_apply_patch_hex'] = ''; self.refused()

    def test_memory_manager_patch_requires_ordered_momentum_frontier_augmentation(self):
        self.r['manager_patch_hex'] = self.r['delta_patch_hex']; self.refused()

    def test_momentum_hash_and_protobuf_require_actual_ordered_content(self):
        self.r['momentum']['momentum']['content'].reverse(); self.refused()

    def test_each_actual_previous_snapshot_requires_exact_anchor_identifier(self):
        self.r['snapshot_identifiers'][0]['hash_hex'] = '00' * 32; self.refused()

    def test_boolean_counts_cannot_replace_measured_integer_counts(self):
        self.r['momentum_signatures'] = True; self.refused()

    def test_selected_self_signature_does_not_authenticate_elected_producer(self):
        self.r['producer_calls'] = 0; self.refused()

    def test_old_receipt_refusal_preserves_exact_original_wire(self):
        self.control()['original_wire_hex'] = self.r['candidates']['fresh-dependent-receive']['block']['wire_hex']; self.refused()

    def test_old_receipt_refusal_cannot_return_transaction_or_sign(self):
        self.control()['transaction_present'] = True; self.refused()
        self.setUp(); self.control()['signatures'] = 1; self.refused()

    def test_each_refusal_binds_complete_original_stable_and_pool_checkpoint(self):
        self.control()['checkpoint_after_sha256'] = '00' * 32; self.refused()

    def test_refused_rollback_requires_exact_target_and_locker(self):
        self.r['controls']['wrong-target-hash']['target']['height'] = '10109302'; self.refused()

    def test_refused_caller_cannot_emit_partial_callback(self):
        self.r['controls']['missing-add-locker']['callbacks'] = 1; self.refused()

    def test_fresh_receipt_cannot_acknowledge_before_actual_child_confirmation(self):
        self.r['candidates']['fresh-dependent-receive']['block']['block']['momentum_height'] = '10109301'; self.refused()

    def test_fresh_receive_delta_requires_actual_child_token_and_amount(self):
        self.r['candidates']['fresh-dependent-receive']['delta_patch_hex'] = ''; self.refused()

    def test_actual_delete_prefetch_requires_child_and_parent_as_top_level_entries(self):
        self.r['events'][6]['included_wires'] = self.r['selection_wires'][1:]; self.refused()

    def test_listener_order_cannot_claim_post_pool_state_before_callback(self):
        self.r['events'][6]['phase'] = 'delete-after-account-pool'; self.refused()

    def test_actual_pop_restores_stable_state_before_delete_listener(self):
        self.r['events'][6]['checkpoint']['global_dump_hex'] = self.r['checkpoints']['after-insertion']['global_dump_hex']; self.refused()

    def test_complete_dependent_manager_eviction_removes_receive_and_later_suffix(self):
        self.r['checkpoints']['after-rollback']['alice']['pending_wires'] = self.r['checkpoints']['before-rollback']['alice']['pending_wires']; self.refused()

    def test_unrelated_old_ack_original_retains_exact_patch_and_pending_wire(self):
        self.r['post_rollback_aliases']['unrelated-old-ack']['patch_hex'] = ''; self.refused()

    def test_removed_contract_child_alias_cannot_remain_eligible(self):
        self.r['post_rollback_aliases']['child']['present'] = True; self.refused()

    def test_source_record_requires_complete_correct_package_and_test_framing(self):
        self.assertEqual(batch.collect_records(self.stream()), self.records)
        with self.assertRaises(ValueError): batch.collect_records(self.stream().replace(batch.PACKAGE.encode(), b'unselected/package'))

    def test_duplicate_truncated_and_extended_source_records_are_refused(self):
        wire = self.stream()
        with self.assertRaises(ValueError): batch.collect_records(wire + wire)
        with self.assertRaises((ValueError, json.JSONDecodeError)): batch.collect_records(wire[:-20])
        self.r['unselected'] = 'true'; self.refused()

    def test_empty_successor_requires_no_account_content_and_no_vm_writes(self):
        self.r['second_momentum']['delta_patch_hex'] = self.r['delta_patch_hex']; self.refused()
        self.setUp(); self.r['second_momentum']['momentum']['momentum']['content'] = self.r['momentum']['momentum']['content']; self.refused()

    def test_empty_successor_binds_exact_previous_hash_height_and_timestamp(self):
        self.r['second_momentum']['momentum']['momentum']['previous_hash_hex'] = '00' * 32; self.refused()
        self.setUp(); self.r['second_momentum']['momentum']['momentum']['timestamp'] = '701'; self.refused()

    def test_first_pop_retains_original_receipt_and_suffix_with_complete_state(self):
        self.r['checkpoints']['after-first-pop']['alice']['pending_wires'] = []; self.refused()
        self.setUp(); self.r['events'][5]['checkpoint']['alice']['pool_hex'] = ''; self.refused()

    def test_first_pop_preserves_all_original_pending_aliases_and_exact_patches(self):
        self.r['intermediate_pending_aliases']['fresh-dependent-receive']['patch_hex'] = ''; self.refused()
        self.setUp(); self.r['intermediate_pending_aliases']['fresh-dependent-suffix']['present'] = False; self.refused()

    def test_each_delete_uses_its_actual_prefetch_and_complete_intermediate_root(self):
        self.r['events'][4]['included_wires'] = self.r['selection_wires']; self.refused()
        self.setUp(); self.r['events'][4]['checkpoint']['global_dump_hex'] = self.r['checkpoints']['after-rollback']['global_dump_hex']; self.refused()

    def test_frontier_no_op_requires_exact_target_zero_callbacks_and_complete_state(self):
        self.r['controls']['already-at-frontier']['callbacks'] = True; self.refused()
        self.setUp(); self.r['controls']['already-at-frontier']['target']['height'] = '10109302'; self.refused()
        self.setUp(); self.r['controls']['already-at-frontier']['checkpoint_after_sha256'] = '00' * 32; self.refused()
