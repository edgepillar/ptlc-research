"""Independent and adversarial controls for actual public content-cap properties."""

import copy
import json
from pathlib import Path
import unittest

from scripts import qualify_nom_content_cap as cap
from scripts.generate_nom_content_cap import CASE, FIXTURE, corpus

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text('ascii'))


class NoMContentCapTests(unittest.TestCase):
    def setUp(self): self.records = copy.deepcopy(FIX['records']); self.r = self.records[CASE]
    def refused(self):
        with self.assertRaises(ValueError): cap.validate_records(self.records)
    def prop(self, n=99): return self.r['observation_properties']['unrelated-' + str(n)]
    def candidate(self): return self.r['candidates'][98]
    def raw_record(self, mixed=True):
        # Hypothesized parser inputs only; never substituted for an original stream.
        r = copy.deepcopy(self.r); properties = r.pop('observation_properties'); r['observations'] = {}
        for label, p in properties.items():
            rows = []
            for i in range(cap.READS):
                a = 'contract-first' if mixed and i % 2 else 'user-first'
                b = 'user-first' if mixed and i % 2 else 'contract-first'
                rows.append({'all_indices': p['all_admissible_orders'][a], 'selection_indices': p['selection_admissible_orders'][b],
                             'checkpoint_before_sha256': p['checkpoint_sha256'], 'checkpoint_after_sha256': p['checkpoint_sha256'], 'signatures': 0})
            r['observations'][label] = rows
        return r
    def source_stream(self, r):
        return (json.dumps({'Action': 'output', 'Package': cap.PACKAGE, 'Test': cap.TEST + '/' + CASE,
                           'Output': '    zz_research_nom_content_cap_test.go:900: ' + cap.PREFIX + json.dumps(r) + '\n'}) + '\n').encode('ascii')

    def test_complete_property_profile_preserves_all_prior_source_inputs(self):
        manifest, fixture, measured = cap.inputs(ROOT)
        self.assertEqual(len(manifest['preserved_file_sha256']), 109)
        self.assertEqual(fixture, corpus(cap.validate_records(self.records)))
        self.assertEqual(len(cap.expected_tests()[cap.PACKAGE]), 6)
        self.assertIn(cap.prior.MANIFEST, measured)

    def test_separate_getters_can_observe_different_admissible_account_orders(self):
        raw = self.raw_record()
        self.assertEqual(cap.validate_record(raw, raw=True), self.r)
        self.assertEqual(cap.collect_records(self.source_stream(raw)), self.records)

    def test_both_random_order_variants_are_not_required_to_appear(self):
        self.assertEqual(cap.validate_record(self.raw_record(False), raw=True), self.r)

    def test_98_user_headers_fit_with_the_complete_preserved_batch(self):
        p = self.prop(98)
        self.assertEqual([len(v) for v in p['selection_admissible_orders'].values()], [100, 100])
        for order in p['selection_admissible_orders'].values(): self.assertIn([0, 1], [order[i:i + 2] for i in range(len(order) - 1)])

    def test_99_users_first_leave_one_unused_slot_without_splitting_batch(self):
        p = self.prop(99)
        self.assertEqual(p['selection_admissible_orders']['user-first'], list(range(2, 101)))
        self.assertEqual(p['selection_admissible_orders']['contract-first'], [0, 1] + list(range(2, 100)))

    def test_101_users_first_truncate_at_100_without_selecting_a_later_batch(self):
        self.assertEqual(self.prop(101)['selection_admissible_orders']['user-first'], list(range(2, 102)))

    def test_actual_content_cap_cannot_be_changed_to_a_private_test_value(self):
        self.r['actual_cap'] = 2; self.refused()

    def test_unchanged_pending_account_cap_and_typed_signature_counts_required(self):
        self.r['actual_pending_cap'] = 101; self.refused()
        self.setUp(); self.r['parent_apply_signatures'] = False; self.refused()

    def test_exact_parent_apply_never_replaces_funding_or_inner_witness_bytes(self):
        self.r['input']['parent_wire_hex'] = ''; self.refused()

    def test_complete_synthetic_global_seed_cannot_be_reclassified_or_omitted(self):
        self.r['input']['root_hex'] = ''; self.refused()

    def test_separate_public_candidates_cannot_omit_a_prefix_member(self):
        self.r['candidates'].pop(49); self.refused()

    def test_separate_public_prefix_requires_exact_predecessor_and_wire(self):
        self.candidate()['block']['block']['previous_hash_hex'] = '00' * 32; self.refused()

    def test_synthetic_fusion_budget_requires_exact_used_plasma_debit(self):
        self.candidate()['available_before'] = '10500000'; self.refused()

    def test_exact_apply_must_match_generated_delta_and_sign_zero_times(self):
        self.candidate()['applied_delta_hex'] = ''; self.refused()
        self.setUp(); self.candidate()['apply_signatures'] = 1; self.refused()

    def test_each_generated_control_requires_disclosed_public_key(self):
        self.candidate()['block']['public_key_hex'] = '00' * 32; self.refused()

    def test_preserved_child_alias_is_empty_and_parent_patch_has_both_frontiers(self):
        self.r['pool_patches']['child'] = self.r['pool_patches']['parent']; self.refused()
        self.setUp(); self.r['pool_patches']['parent'] = self.r['input']['parent_delta_hex']; self.refused()

    def test_each_normal_pool_patch_requires_complete_original_frontier_writes(self):
        self.r['pool_patches']['99'] = self.candidate()['delta_patch_hex']; self.refused()

    def test_every_getter_checkpoint_preserves_complete_stable_state(self):
        self.r['checkpoints']['unrelated-99']['global_hex'] = ''; self.refused()

    def test_complete_pool_state_and_pending_wire_digest_cannot_be_inferred_from_count(self):
        self.r['checkpoints']['unrelated-99']['unrelated']['pending_wire_sha256'] = '00' * 32; self.refused()

    def test_boolean_aliases_cannot_replace_pending_counts_or_catalog_indices(self):
        self.r['checkpoints']['initial']['unrelated']['pending_count'] = False; self.refused()
        self.setUp(); self.prop()['all_admissible_orders']['contract-first'][0] = False; self.refused()

    def test_all_contract_snapshot_queries_require_exact_selected_anchor(self):
        self.r['snapshot_identifiers'][0]['hash_hex'] = '00' * 32; self.refused()

    def test_property_catalog_cannot_promote_map_order_to_a_required_sequence(self):
        self.prop()['observed_both_orders_required'] = True; self.refused()

    def test_property_projection_cannot_select_one_half_of_preserved_batch(self):
        self.prop()['selection_admissible_orders']['user-first'].append(0); self.refused()

    def test_all_original_reads_required_before_deterministic_projection(self):
        raw = self.raw_record(); raw['observations']['unrelated-99'].pop()
        with self.assertRaises(ValueError): cap.validate_record(raw, raw=True)

    def test_one_bad_native_selection_is_not_hidden_by_other_successful_reads(self):
        raw = self.raw_record(); raw['observations']['unrelated-99'][7]['selection_indices'] = [0] + list(range(2, 101))
        with self.assertRaises(ValueError): cap.collect_records(self.source_stream(raw))

    def test_raw_all_pending_order_cannot_interleave_accounts_or_reverse_children(self):
        for order in ([1, 0] + list(range(2, 101)), [0, 2, 1] + list(range(3, 101))):
            raw = self.raw_record(); raw['observations']['unrelated-99'][0]['all_indices'] = order
            with self.assertRaises(ValueError): cap.validate_record(raw, raw=True)

    def test_raw_duplicate_missing_or_boolean_catalog_references_refused(self):
        for order in ([0, 1, 2, 2], [False, 1] + list(range(2, 100)), list(range(2, 100))):
            raw = self.raw_record(); raw['observations']['unrelated-99'][0]['selection_indices'] = order
            with self.assertRaises(ValueError): cap.validate_record(raw, raw=True)

    def test_each_raw_read_requires_full_unchanged_checkpoint_and_no_signing(self):
        for field, value in (('checkpoint_after_sha256', '00' * 32), ('signatures', 1), ('signatures', False)):
            raw = self.raw_record(); raw['observations']['unrelated-99'][0][field] = value
            with self.assertRaises(ValueError): cap.validate_record(raw, raw=True)

    def test_source_stream_requires_correct_package_test_and_original_raw_fields(self):
        stream = self.source_stream(self.raw_record())
        with self.assertRaises(ValueError): cap.collect_records(stream.replace(cap.PACKAGE.encode(), b'unselected/package'))
        with self.assertRaises(ValueError): cap.collect_records(self.source_stream(self.r))

    def test_duplicate_truncated_and_extended_source_records_are_refused(self):
        wire = self.source_stream(self.raw_record())
        with self.assertRaises(ValueError): cap.collect_records(wire + wire)
        with self.assertRaises((ValueError, json.JSONDecodeError)): cap.collect_records(wire[:-20])
        self.r['unselected'] = True; self.refused()
