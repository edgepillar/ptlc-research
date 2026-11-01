"""Complete source bindings and nonexecution controls for the tracked delta."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_dev_18c048a_source as selected


class TrackedSourceTests(unittest.TestCase):
    def test_complete_shared_delta_keeps_native_and_journal_selection_separate(self):
        result, index = selected.inputs()
        self.assertEqual(len(index), 525)
        self.assertEqual(selected.prior.baseline.common.git_tree(index), selected.TREE)
        self.assertEqual(result['source_bytes'], 8552692)
        self.assertEqual((len(result['added']), len(result['changed']), result['unchanged']), (2, 6, 517))
        self.assertEqual(result['removed'], [])
        self.assertEqual(len(result['unchanged_ptlc_paths']), 18)
        self.assertIn('common/db/enable_delete.go', result['changed'])
        self.assertIn('protocol/sync.go', result['changed'])
        self.assertNotIn('vm/embedded/implementation/ptlc.go', result['changed'])
        self.assertEqual(result['tracked_core_commit'], selected.CORE)
        self.assertEqual(result['prior_tracked_core'], selected.prior.CORE)
        self.assertEqual(result['delta_baseline_core'], selected.prior.CORE)
        self.assertEqual(result['last_qualified_behavior_core'], selected.prior.baseline.CORE)
        self.assertEqual(result['native_compatibility'], 'UNFILLED')
        self.assertEqual(result['journal_source_upgrade'], 'NOT_SELECTED')
        self.assertEqual(result['independent_assessment'], 'UNFILLED')
        self.assertEqual((result['application'], result['core']), ('NO-GO', 'NO-GO'))

    def test_each_retained_inventory_requires_its_own_complete_bytes(self):
        latest, tracked, behavior = selected.SOURCE, selected.prior.SOURCE, selected.prior.baseline.SOURCE
        sources = {name:(selected.ROOT/name).read_bytes() for name in (latest, tracked, behavior)}
        cases = (
            (latest, None), (latest, tracked), (tracked, None), (tracked, latest),
            (behavior, None), (behavior, latest), (latest, 'extra-byte'))
        for name, replacement in cases:
            with self.subTest(name=name, replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                for relative, raw in sources.items():
                    path = root/relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                path = root/name
                if replacement is None:
                    path.unlink()
                elif replacement == 'extra-byte':
                    path.write_bytes(sources[name]+b'\n')
                else:
                    path.write_bytes(sources[replacement])
                with self.assertRaises((ValueError, AssertionError, KeyError, TypeError, OSError)):
                    selected.inputs(root)

    def test_inventory_inspection_opens_no_archive_and_starts_no_process(self):
        refusal = AssertionError('index inspection must not open an archive or start a process')
        with patch('zipfile.ZipFile', side_effect=refusal), \
                patch('subprocess.run', side_effect=refusal), \
                patch('subprocess.Popen', side_effect=refusal):
            result, index = selected.inputs()
        self.assertEqual(len(index), 525)
        self.assertEqual(result['archive_verification'], 'NOT_PERFORMED_BY_INDEX_READER')
        self.assertEqual(result['native_execution'], 'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['producer_authentication'], 'NOT_ESTABLISHED_BY_INDEX_READER')


if __name__ == '__main__':
    unittest.main()
