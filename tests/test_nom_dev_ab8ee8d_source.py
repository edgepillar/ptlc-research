"""Check source impact and retain the boundary around the unexecuted revision."""
import unittest
from unittest.mock import patch

from qualification import nom_dev_ab8ee8d_source as selected


class TrackedDeltaTests(unittest.TestCase):
    def test_delta_preserves_ptlc_and_exposes_shared_admission_changes(self):
        result, index = selected.inputs()
        self.assertEqual(len(index), 574)
        self.assertEqual(selected.common.git_tree(index), selected.TREE)
        self.assertEqual(result['source_bytes'], 9161440)
        self.assertEqual((len(result['added']), len(result['changed']), result['unchanged']), (12, 27, 535))
        self.assertEqual(result['removed'], [])
        self.assertEqual(len(result['unchanged_ptlc_paths']), 18)
        self.assertTrue({'chain/acknowledgement_recency.go', 'rpc/server/admission.go',
                         'verifier/embedded_refund.go'} <= set(result['added']))
        self.assertTrue({'chain/account_pool.go', 'pillar/content_selector.go', 'verifier/account_block.go',
                         'verifier/momentum.go', 'vm/vm.go'} <= set(result['changed']))
        self.assertIs(result['dependency_files_unchanged'], False)
        self.assertEqual(result['dependency_files_changed'], ['go.mod'])
        self.assertEqual(result['unchanged_dependency_paths'], ['go.sum'])
        self.assertEqual(result['go_mod_change'], 'X_NET_V0_25_0_PROMOTED_TO_DIRECT_ONLY')
        _, baseline = selected.prior.inputs()
        for name in (*result['unchanged_ptlc_paths'], 'LICENSE', 'go.sum'):
            with self.subTest(protected=name):
                self.assertEqual(index[name], baseline[name])
        self.assertNotEqual(index['go.mod'], baseline['go.mod'])
        self.assertEqual(result['last_qualified_behavior_core'], selected.inventory.CORE)
        self.assertEqual(result['native_compatibility'], 'UNFILLED')
        self.assertEqual(result['journal_source_upgrade'], 'NOT_SELECTED')
        self.assertEqual(result['independent_assessment'], 'UNFILLED')
        self.assertEqual((result['application'], result['core']), ('NO-GO', 'NO-GO'))

    def test_base_and_delta_bytes_are_both_required(self):
        read = selected.common.regular
        for name in (selected.DELTA, selected.prior.DELTA):
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
