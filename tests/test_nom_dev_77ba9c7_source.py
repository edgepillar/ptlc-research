"""Source substitution controls; no native, signing or chain evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_dev_77ba9c7_source as selected

REFUSALS = (ValueError,AssertionError,KeyError,TypeError,OSError)


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        git_blob_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),mode='100644')


class CurrentSourceTests(unittest.TestCase):
    def test_complete_inventory_and_explicit_delta_keep_execution_unqualified(self):
        description,index=selected.inputs()
        self.assertEqual(len(index),521)
        self.assertEqual(selected.common.git_tree(index),selected.TREE)
        self.assertEqual((len(description['added']),len(description['changed']),description['unchanged']),(3,12,506))
        self.assertEqual(description['removed'],[])
        self.assertEqual(len(description['unchanged_ptlc_paths']),18)
        self.assertIn('vm/embedded/implementation/epoch_reward_bound_test.go',description['added'])
        self.assertIn('vm/vm.go',description['changed'])
        self.assertNotIn('vm/plasma.go',description['changed'])
        self.assertEqual(description['prior_core'],'661b5ef404487cd41685654bf87530f10adebbe4')
        self.assertEqual(description['application'],description['core'])
        self.assertEqual(description['core'],'NO-GO')
        self.assertEqual(description['native_compatibility'],'UNFILLED')
        self.assertEqual(description['native_execution'],'NOT_PERFORMED_BY_READER')
        self.assertEqual(description['journal_source_upgrade'],'NOT_SELECTED')

    def tiny(self):
        values={'one.go':b'// synthetic source\n','nested/two.go':b'// another public model\n'}
        return values,{name:pin(raw) for name,raw in values.items()}

    def validate(self,value,tree=None):
        raw=json.dumps(value,sort_keys=True).encode('ascii')
        return selected.validate_index(raw,digest=hashlib.sha256(raw).hexdigest(),count=2,
            tree=selected.common.git_tree(value) if tree is None else tree)

    def test_index_bodies_tree_ids_and_declared_sizes_are_separate_bindings(self):
        unused,index=self.tiny()
        self.assertEqual(self.validate(index),index)
        with self.assertRaises(REFUSALS):self.validate(index,'0'*40)
        raw=json.dumps(index).encode('ascii')
        with self.assertRaises(REFUSALS):
            selected.validate_index(raw+b' ',digest=hashlib.sha256(raw).hexdigest(),count=2,tree=selected.common.git_tree(index))
        for field,value in (('bytes',True),('bytes',-1),('mode','120000'),('sha256','0'),('git_blob_sha1','z'*40)):
            mutated=copy.deepcopy(index);mutated['one.go'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(REFUSALS):
                # Schema refusal precedes the tree check for an invalid object id.
                self.validate(mutated,'0'*40)

    def test_alias_paths_and_unselected_fields_refuse(self):
        unused,index=self.tiny()
        for path in ('../one.go','/one.go','a//one.go','a/./one.go','a\\one.go','x:one.go','.git/config'):
            mutated=copy.deepcopy(index);mutated[path]=mutated.pop('one.go')
            with self.subTest(path=path),self.assertRaises(REFUSALS):self.validate(mutated,'0'*40)
        mutated=copy.deepcopy(index);mutated['ONE.GO']=mutated.pop('nested/two.go')
        with self.assertRaises(REFUSALS):self.validate(mutated,'0'*40)
        mutated=copy.deepcopy(index);mutated['one.go']['authority']='trusted'
        with self.assertRaises(REFUSALS):self.validate(mutated,'0'*40)

    def frame(self,root):
        values,index=self.tiny()
        for name,raw in values.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        return index

    def test_synthetic_walker_frame_cannot_establish_native_or_source_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();index=self.frame(root)
            with patch.object(selected,'inputs',return_value=({'native_compatibility':'UNFILLED'},index)):
                result=selected.compare_upstream(root)
            self.assertEqual(result['content'],'EXACT_SELECTED_UPSTREAM_BYTES')
            self.assertEqual(result['producer_authentication'],'NOT_ESTABLISHED_BY_READER')
            self.assertEqual(result['source_build_authentication'],'UNFILLED')
            self.assertEqual(result['native_compatibility'],'UNFILLED')

    def test_missing_substituted_extra_directory_symlink_and_hardlink_refuse(self):
        for mode in ('missing','body','extra','directory','symlink','hardlink','ancestor-alias'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary).resolve();root=base/'source';root.mkdir();index=self.frame(root)
                target=root/'one.go'
                if mode=='missing':target.unlink()
                elif mode=='body':target.write_bytes(b'// substituted\n')
                elif mode=='extra':(root/'extra.go').write_bytes(b'// extra\n')
                elif mode=='directory':(root/'unexpected').mkdir()
                elif mode in ('symlink','hardlink'):
                    target.unlink()
                    if mode=='symlink':target.symlink_to(root/'nested/two.go')
                    else:os.link(root/'nested/two.go',target)
                else:
                    alias=base/'alias';alias.symlink_to(root,target_is_directory=True);root=alias
                with patch.object(selected,'inputs',return_value=({},index)),self.assertRaises(REFUSALS):
                    selected.compare_upstream(root)


if __name__=='__main__':unittest.main()
