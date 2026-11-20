"""Cover explicit removals in the tracked source inventory."""
import unittest
from unittest.mock import patch

from qualification import nom_dev_54f6bad_source as selected


class TrackedDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous, cls.baseline = selected.prior.inputs()
        cls.delta = selected.common.decoded(
            (selected.ROOT / selected.DELTA).read_bytes(), selected.common.MIB)

    def test_inventory_accounts_for_removed_paths_without_executing_upstream(self):
        refusal = AssertionError('source index inspection must stay offline')
        with (
            patch('zipfile.ZipFile', side_effect=refusal),
            patch('subprocess.Popen', side_effect=refusal),
        ):
            result, index = selected.inputs()
        self.assertEqual(len(index), 621)
        self.assertEqual(selected.common.git_tree(index), selected.TREE)
        self.assertEqual(result['source_bytes'], 9776906)
        self.assertEqual((len(result['added']), len(result['changed']), result['unchanged']), (52, 60, 509))
        self.assertEqual(len(result['removed']), 5)
        self.assertEqual(set(self.baseline) - set(index), set(result['removed']))
        self.assertEqual(len(result['unchanged_ptlc_paths']), 18)
        for name in (*result['unchanged_ptlc_paths'], 'LICENSE'):
            with self.subTest(protected=name):
                self.assertEqual(index[name], self.baseline[name])
        self.assertEqual(result['dependency_files_changed'], ['go.mod', 'go.sum'])
        self.assertEqual(result['last_qualified_behavior_core'], self.previous['last_qualified_behavior_core'])
        self.assertEqual(result['journal_source_upgrade'], 'NOT_SELECTED')
        self.assertEqual(result['native_compatibility'], 'UNFILLED')
        self.assertEqual(result['independent_assessment'], 'UNFILLED')
        self.assertEqual((result['application'], result['core']), ('NO-GO', 'NO-GO'))

    def test_removed_and_modified_sets_must_describe_distinct_base_records(self):
        removed = self.delta['removed']
        modified = self.delta['modified']
        name = next(iter(modified))
        overlap = modified.copy()
        overlap[removed[0]] = overlap.pop(name)
        added_existing = self.delta['added'].copy()
        added_existing[name] = added_existing.pop(next(iter(added_existing)))
        no_change = modified.copy()
        no_change[name] = self.baseline[name]
        for label, change, reason in (
            ('missing removal', {'removed': removed[:-1]}, 'entry count'),
            ('duplicate removal', {'removed': removed[:-1] + [removed[-2]]}, 'entry count'),
            ('unknown removal', {'removed': sorted(removed[:-1] + ['synthetic/unknown.go'])}, 'range'),
            ('overlap', {'modified': overlap}, 'range'),
            ('added existing path', {'added': added_existing}, 'range'),
            ('no-op modification', {'modified': no_change}, 'range'),
            ('unknown field', {'renamed': []}, 'fields'),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, f'source delta {reason}'):
                    selected.reconstruct(self.baseline, self.delta | change)

    def test_reconstructed_index_must_match_the_pinned_bytes(self):
        added = self.delta['added'].copy()
        name = next(iter(added))
        added[name] = dict(added[name], bytes=added[name]['bytes'] + 1)
        with self.assertRaisesRegex(ValueError, 'source input refused'):
            selected.reconstruct(self.baseline, self.delta | {'added': added})

    def test_inputs_requires_the_exact_delta_bytes(self):
        read = selected.common.regular

        def changed(path, limit):
            raw = read(path, limit)
            return raw + b'\n' if path == selected.ROOT / selected.DELTA else raw

        with patch.object(selected.common, 'regular', side_effect=changed):
            with self.assertRaisesRegex(ValueError, '54f6bad source delta digest mismatch'):
                selected.inputs()
