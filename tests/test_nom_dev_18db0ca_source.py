"""Check the boundary of the workflow-only source inventory."""

import unittest
from unittest.mock import patch

from qualification import nom_dev_18db0ca_source as subject


class WorkflowOnlySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous, cls.baseline = subject.prior.inputs()
        raw = (subject.ROOT / subject.DELTA).read_bytes()
        cls.delta = subject.common.decoded(raw, subject.MAX_DELTA)

    def test_two_workflows_reconstruct_the_exact_index_offline(self):
        refusal = AssertionError('source inventory inspection must stay offline')
        with (patch('zipfile.ZipFile', side_effect=refusal), patch('subprocess.Popen', side_effect=refusal)):
            result, index = subject.inputs()
        self.assertEqual(set(index), set(self.baseline))
        self.assertEqual({name for name in index if index[name] != self.baseline[name]}, subject.WORKFLOWS)
        self.assertEqual(subject.common.git_tree(index), subject.TREE)
        self.assertEqual((result['source_files'], result['source_bytes'], result['unchanged']), (621, 9777883, 619))
        self.assertTrue(result['dependency_files_unchanged'])
        self.assertEqual(result['unchanged_ptlc_paths'], self.previous['unchanged_ptlc_paths'])
        self.assertEqual(result['last_qualified_behavior_core'], self.previous['last_qualified_behavior_core'])
        self.assertEqual((result['native_compatibility'], result['journal_source_upgrade'], result['independent_assessment']),
                         ('UNFILLED', 'NOT_SELECTED', 'UNFILLED'))
        self.assertEqual((result['application'], result['core']), ('NO-GO', 'NO-GO'))

    def test_changed_paths_and_bytes_are_bounded(self):
        name = min(subject.WORKFLOWS)
        changed = self.delta['modified']
        for mutation in (
            {'added': {'new.go': self.baseline[name]}},
            {'removed': ['go.sum']},
            {'modified': {name: changed[name]}},
            {'modified': changed | {'go.mod': self.baseline['go.mod']}},
            {'modified': changed | {name: self.baseline[name]}},
        ):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'two changed workflow records'):
                subject.reconstruct(self.baseline, self.delta | mutation)
        altered = changed | {name: dict(changed[name], bytes=changed[name]['bytes'] + 1)}
        with self.assertRaisesRegex(ValueError, 'source input refused'):
            subject.reconstruct(self.baseline, self.delta | {'modified': altered})

    def test_inputs_require_the_exact_retained_delta(self):
        read = subject.common.regular

        def changed(path, limit):
            raw = read(path, limit)
            return raw + b'\n' if path == subject.ROOT / subject.DELTA else raw

        with patch.object(subject.common, 'regular', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'source delta digest mismatch'):
                subject.inputs()
