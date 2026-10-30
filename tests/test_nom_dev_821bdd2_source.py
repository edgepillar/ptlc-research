"""Tracked-source substitution checks; no native compatibility or authority."""
from pathlib import Path
import tempfile
import unittest

from qualification import nom_dev_821bdd2_source as selected


class TrackedSourceTests(unittest.TestCase):
    def test_complete_delta_keeps_tracked_and_qualified_subjects_separate(self):
        result,index=selected.inputs()
        self.assertEqual(len(index),523)
        self.assertEqual(selected.baseline.common.git_tree(index),selected.TREE)
        self.assertEqual(result['source_bytes'],8538502)
        self.assertEqual((len(result['added']),len(result['changed']),result['unchanged']),(2,5,516))
        self.assertEqual(result['removed'],[])
        self.assertEqual(len(result['unchanged_ptlc_paths']),18)
        self.assertIn('vm/embedded/definition/common.go',result['changed'])
        self.assertIn('vm/embedded/implementation/common.go',result['changed'])
        self.assertNotIn('vm/vm.go',result['changed'])
        self.assertEqual(result['tracked_core_commit'],selected.CORE)
        self.assertEqual(result['last_qualified_behavior_core'],selected.baseline.CORE)
        self.assertNotEqual(result['tracked_core_commit'],result['last_qualified_behavior_core'])
        self.assertEqual(result['native_compatibility'],'UNFILLED')
        self.assertEqual(result['native_execution'],'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['journal_source_upgrade'],'NOT_SELECTED')
        self.assertEqual(result['archive_verification'],'NOT_PERFORMED_BY_INDEX_READER')
        self.assertEqual((result['application'],result['core']),('NO-GO','NO-GO'))

    def test_each_complete_inventory_has_its_own_immutable_binding(self):
        sources={name:(selected.ROOT/name).read_bytes()
            for name in (selected.SOURCE,selected.baseline.SOURCE)}
        cases=('missing-candidate','changed-candidate','candidate-replaced-by-baseline',
               'missing-baseline','baseline-replaced-by-candidate')
        for case in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve()
                for name,raw in sources.items():
                    path=root/name
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(raw)
                candidate=root/selected.SOURCE
                prior=root/selected.baseline.SOURCE
                if case=='missing-candidate':candidate.unlink()
                elif case=='changed-candidate':candidate.write_bytes(sources[selected.SOURCE]+b'\n')
                elif case=='candidate-replaced-by-baseline':candidate.write_bytes(sources[selected.baseline.SOURCE])
                elif case=='missing-baseline':prior.unlink()
                else:prior.write_bytes(sources[selected.SOURCE])
                with self.assertRaises((ValueError,AssertionError,KeyError,TypeError,OSError)):
                    selected.inputs(root)


if __name__=='__main__':unittest.main()
