"""Check the exact tracked delta and its source-only boundary."""
import unittest
from unittest.mock import patch

from qualification import nom_dev_008bdcd_source as selected


class TrackedDeltaTests(unittest.TestCase):
    def test_delta_reconstructs_the_complete_observed_tree(self):
        result, index = selected.inputs()
        self.assertEqual(len(index), 562)
        self.assertEqual(selected.common.git_tree(index), selected.TREE)
        self.assertEqual(result['source_bytes'], 8971060)
        self.assertEqual((len(result['added']), len(result['changed']), result['unchanged']), (37, 89, 436))
        self.assertEqual(result['removed'], [])
        self.assertEqual(len(result['unchanged_ptlc_paths']), 18)
        self.assertIn('vm/vm_context/lifecycle.go', result['changed'])
        self.assertIn('rpc/api/ledger.go', result['changed'])
        self.assertEqual(result['last_qualified_behavior_core'], selected.inventory.CORE)
        self.assertEqual(result['native_compatibility'], 'UNFILLED')
        self.assertEqual(result['journal_source_upgrade'], 'NOT_SELECTED')
        self.assertEqual(result['independent_assessment'], 'UNFILLED')
        self.assertEqual((result['application'], result['core']), ('NO-GO', 'NO-GO'))

    def test_base_and_delta_bytes_are_both_required(self):
        read = selected.common.regular
        for name in (selected.DELTA, selected.prior.SOURCE):
            with self.subTest(name=name):
                def changed(path, limit):
                    raw = read(path, limit)
                    return raw + b'\n' if path == selected.ROOT/name else raw

                with patch.object(selected.common, 'regular', side_effect=changed):
                    with self.assertRaises(ValueError):
                        selected.inputs()

    def test_index_inspection_does_not_open_an_archive_or_process(self):
        refusal = AssertionError('source index inspection must stay offline')
        with (
            patch('zipfile.ZipFile', side_effect=refusal),
            patch('subprocess.run', side_effect=refusal),
            patch('subprocess.Popen', side_effect=refusal),
        ):
            result, _ = selected.inputs()
        self.assertEqual(result['archive_verification'], 'NOT_PERFORMED_BY_INDEX_READER')
        self.assertEqual(result['native_execution'], 'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['producer_authentication'], 'NOT_ESTABLISHED_BY_INDEX_READER')
