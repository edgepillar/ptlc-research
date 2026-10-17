"""Synthetic source-frame controls, not fresh Go execution or chain evidence."""
import json
from pathlib import Path
import unittest

from scripts.qualify_nom_signed_originals import inspect, git_tree, CORE_TREE
from nom_signed_source_frames import fixture_stream, variants

ROOT=Path(__file__).resolve().parents[1]


class SignedOriginalSourceFrames(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records=json.loads((ROOT/'compatibility/fixtures/nom_signed_originals_v1.json').read_bytes())
        cls.fixture=json.loads((ROOT/'compatibility/fixtures/nom_supervisor_plasma_v1.json').read_bytes())
        cls.inputs=json.loads((ROOT/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())
        cls.completions=json.loads((ROOT/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())
        cls.stream=fixture_stream(cls.records)
        cls.bad=variants(cls.stream)

    def refuse(self,name):
        with self.assertRaises((AssertionError,ValueError,KeyError)):
            inspect(self.bad[name],self.fixture,self.inputs,self.completions)

    def test_fragmented_public_fixture_comparison(self):
        report,records=inspect(self.stream,self.fixture,self.inputs,self.completions)
        self.assertEqual(records,self.records)
        self.assertEqual(report['records'],24)
        self.assertEqual(report['transaction_only_accepted'],12)
        self.assertEqual(report['selected_refusals'],12)

    def test_missing_native_outcome_refuses(self):self.refuse('missing actual Go outcome')
    def test_duplicate_complete_record_refuses(self):self.refuse('duplicate complete record')
    def test_missing_record_with_complete_outcomes_refuses(self):self.refuse('missing record with complete Go outcomes')
    def test_normalized_alias_substitution_refuses(self):self.refuse('normalized original substitution')
    def test_relabelled_node_identifier_refuses(self):self.refuse('changed node identifier')
    def test_relabelled_leg_refuses(self):self.refuse('changed leg label')
    def test_integer_decoded_flag_refuses(self):self.refuse('integer decoded flag')
    def test_positive_missing_signature_claim_refuses(self):self.refuse('positive missing signature claim')
    def test_fragment_crossing_test_identity_refuses(self):self.refuse('fragment assigned to another test')
    def test_reordered_same_test_fragments_refuse(self):self.refuse('reordered same-test fragments')
    def test_unterminated_record_line_refuses(self):self.refuse('unterminated record line')

    def test_complete_selected_git_tree_reconstructs(self):
        index=json.loads((ROOT/'compatibility/nom_signed_originals_source_v1.json').read_bytes())
        self.assertEqual(len(index),443)
        self.assertEqual(git_tree(index),CORE_TREE)
        index['verifier/account_block.go']['git_blob_sha1']='00'*20
        self.assertNotEqual(git_tree(index),CORE_TREE)


if __name__=='__main__':unittest.main()
