"""Synthetic candidate controls only; no Go process, signer or chain evidence."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from qualification import nom_fee_original_boundary as selected
from scripts import prepare_nom_fee_original_boundary as preparation

def report():
    inputs = selected.input_bytes()
    expected = selected.expected_bytes()
    records = selected.declarations(inputs,expected)
    for row in records.values():
        row.update(spork_reads=['DYNAMIC_PLASMA'],packed_delta_hex='00' if row['pack_entered'] else '')
    value = dict(schema='private-nom-661b5ef-fee-original-boundary-result-v1',
        selected_core_commit=selected.CORE,records=records,new_keys=0,new_signatures=0,
        scope='DIAGNOSTIC MUTATED COPIES WITH SYNTHETIC MEMORY VIEWS; ORIGINALS NEVER REPLACED',
        application='NO-GO',core='NO-GO',independent_assessment='UNFILLED',
        pool_admission='NOT_CALLED',chain_insertion='NOT_CALLED',
        journal_source_upgrade='NOT_SELECTED',transaction_broadcast='NOT_PERFORMED')
    return value, inputs, expected


def frames(value, *, fragment=1024, record_text=None, record_newline=True):
    events = [dict(Action='run',Package=selected.PACKAGE,Test=selected.PARENT)]
    for identifier in sorted(value['records']):
        name = selected.PARENT+'/'+identifier
        events += [dict(Action='run',Package=selected.PACKAGE,Test=name),
            dict(Action='output',Package=selected.PACKAGE,Test=name,Output='=== RUN   '+name+'\n'),
            dict(Action='output',Package=selected.PACKAGE,Test=name,Output='--- PASS: '+name+' (0.00s)\n'),
            dict(Action='pass',Package=selected.PACKAGE,Test=name)]
    text = json.dumps(value,sort_keys=True,separators=(',',':')) if record_text is None else record_text
    text = '    '+selected.BASENAME+':250: '+text+('\n' if record_newline else '')
    for at in range(0,len(text),fragment):
        events.append(dict(Action='output',Package=selected.PACKAGE,Test=selected.PARENT,
            Output=text[at:at+fragment]))
    events += [dict(Action='pass',Package=selected.PACKAGE,Test=selected.PARENT),
        dict(Action='pass',Package=selected.PACKAGE)]
    return b'\n'.join(json.dumps(row,sort_keys=True).encode('ascii') for row in events)+b'\n'


class CurrentFeeOriginalReader(unittest.TestCase):
    def setUp(self):
        self.value,self.inputs,self.expected = report()

    def read(self,wire):
        return selected.read(wire,self.inputs,self.expected)

    def refuse(self,wire):
        with self.assertRaises((AssertionError,ValueError,KeyError,TypeError)):
            self.read(wire)

    def changed(self,change):
        value = copy.deepcopy(self.value)
        change(value)
        return frames(value)

    def test_synthetic_data_cannot_establish_native_origin(self):
        with mock.patch('subprocess.run',side_effect=AssertionError('No execution permitted')):
            result = self.read(frames(self.value))
        self.assertEqual(result['cases'],14)
        self.assertEqual(result['outcomes_including_parent'],15)
        self.assertEqual(result['native_execution_origin'],'NOT_ESTABLISHED_BY_DATA_READER')
        self.assertEqual(result['application'], 'NO-GO')
        self.assertEqual(result['recovery_action'], 'NONE')

    def test_fragmented_record_preserves_selected_case_values(self):
        result = self.read(frames(self.value,fragment=127))
        self.assertEqual((result['earlier_fee_refusals'],result['later_hash_refusals'],
            result['later_signature_refusals']),(6,4,4))

    def test_packed_delta_remains_an_observation(self):
        for row in self.value['records'].values():
            if row['pack_entered']:
                row['packed_delta_hex'] = 'ff'*64
        result = self.read(frames(self.value))
        self.assertEqual(result['packed_delta_semantics'],
            'OBSERVATIONS_ONLY; NO_STATE_ADMISSION_CLAIM')
        self.assertEqual(result['full_account_admission'],'NOT_ESTABLISHED')

    def test_early_fee_cannot_be_reported_as_later_signature_refusal(self):
        self.refuse(self.changed(lambda r:r['records']['long-dp-true-below-computed-hash'].update(
            returned_error='ErrABSignatureInvalid')))

    def test_funded_stale_hash_cannot_be_reported_as_signature_refusal(self):
        self.refuse(self.changed(lambda r:r['records']['long-dp-true-exact-stale-hash'].update(
            returned_error='ErrABSignatureInvalid')))

    def test_funded_copy_cannot_be_promoted_to_transaction(self):
        self.refuse(self.changed(lambda r:r['records']['short-dp-true-exact-computed-hash'].update(
            returned_error='PASS',transaction_present=True)))

    def test_copy_cannot_replace_original_wire_digest(self):
        def change(r):
            row = r['records']['long-dp-true-above-computed-hash']
            row['entry_wire_sha256'] = row['original_wire_sha256']
        self.refuse(self.changed(change))

    def test_replaced_signature_refuses(self):
        self.refuse(self.changed(lambda r:r['records']['long-dp-true-exact-computed-hash'].update(
            post_call_signature_sha256='00'*32)))

    def test_integer_boolean_refuses(self):
        self.refuse(self.changed(lambda r:r['records']['long-dp-true-original'].update(
            selected_signature_preserved=1)))

    def test_authority_and_action_promotions_refuse(self):
        for field,value in [('core','GO'),('pool_admission','PASS'),('chain_insertion','PASS'),
                ('independent_assessment','PASS'),('transaction_broadcast','PERFORMED'),
                ('new_signatures',1)]:
            with self.subTest(field=field):
                self.refuse(self.changed(lambda r:r.update({field:value})))
        self.refuse(self.changed(lambda r:r.update(release_original=True)))

    def test_wrong_source_refuses(self):
        self.refuse(self.changed(lambda r:r.update(selected_core_commit='00'*20)))

    def test_missing_case_refuses_even_with_remaining_complete_children(self):
        self.refuse(self.changed(lambda r:r['records'].pop('long-dp-true-original')))

    def test_missing_child_pass_refuses(self):
        rows = [json.loads(line) for line in frames(self.value).splitlines()]
        rows = [row for row in rows if not (row['Action']=='pass'
            and row.get('Test')==selected.PARENT+'/long-dp-true-original')]
        self.refuse(b'\n'.join(json.dumps(row).encode() for row in rows)+b'\n')

    def test_duplicate_record_keys_refuse(self):
        text = json.dumps(self.value,sort_keys=True,separators=(',',':'))
        self.assertEqual(text.count('"new_signatures":0'),1)
        text = text.replace('"new_signatures":0','"new_signatures":0,"new_signatures":0')
        self.refuse(frames(self.value,record_text=text))

    def test_wrong_source_filename_refuses(self):
        wire = frames(self.value).replace(selected.BASENAME.encode(),b'wrong_probe_test.go')
        self.refuse(wire)

    def test_unterminated_record_and_outer_stream_refuse(self):
        self.refuse(frames(self.value,record_newline=False))
        self.refuse(frames(self.value)[:-1])

    def test_forged_event_authority_refuses(self):
        rows = [json.loads(line) for line in frames(self.value).splitlines()]
        rows[0]['Verified'] = True
        self.refuse(b'\n'.join(json.dumps(row).encode() for row in rows)+b'\n')

    def test_missing_packed_delta_refuses(self):
        self.refuse(self.changed(lambda r:r['records']['long-dp-true-exact-stale-hash'].update(
            packed_delta_hex='')))


class FeeSourceBindings(unittest.TestCase):
    def test_generated_inputs_and_independent_values_keep_exact_native_content(self):
        raw = selected.input_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),selected.INPUT_SHA)
        self.assertEqual(selected.expected_values(),json.loads(selected.expected_bytes()))
        encoded = (json.dumps(selected.expected_values(),indent=2,sort_keys=True)+'\n').encode('ascii')
        self.assertEqual(hashlib.sha256(encoded).hexdigest(),selected.EXPECTED_SHA)
        value = json.loads(raw)
        self.assertNotIn('expected',value)
        self.assertNotIn(selected.VALUES,raw.decode())
        self.assertEqual(len(value['originals']),2)

    def test_manifest_selection_is_not_execution_or_recovery_permission(self):
        manifest,index = selected.inputs()
        self.assertEqual(len(index),518)
        self.assertEqual((manifest['cases'],manifest['outcomes'],manifest['combined_source_files']),(14,15,544))
        self.assertEqual(manifest['native_execution'],'NOT_PERFORMED_BY_READER')
        self.assertEqual(manifest['recovery_action'],'NONE')
        self.assertEqual(manifest['independent_assessment'],'UNFILLED')

    def test_originals_and_diagnostic_copies_keep_distinct_hashes_and_fee_stages(self):
        rows = selected.expected_values()['records']
        counts = {}
        for row in rows.values():
            counts[row['returned_error']] = counts.get(row['returned_error'],0)+1
            self.assertFalse(row['transaction_present'])
            self.assertEqual(row['application_signer_calls'],0)
            if row['variant']=='original':
                self.assertEqual(row['entry_wire_sha256'],row['original_wire_sha256'])
            else:
                self.assertNotEqual(row['entry_wire_sha256'],row['original_wire_sha256'])
                self.assertNotEqual(row['entry_computed_hash_hex'],row['original_hash_hex'])
        self.assertEqual(counts,{'ErrNotEnoughTotalPlasma':6,'ErrABHashInvalid':4,'ErrABSignatureInvalid':4})

    def test_scalar_diagnostic_refuses_unsupported_fields_types_and_missing_slots(self):
        raw = bytes.fromhex(selected.frozen_json(selected.SIGNED)['long-original']['original_wire_hex'])
        for field,value in ((4,84380),(True,84380),(15,True),(15,-1),(15,1<<64)):
            with self.subTest(field=field,value=value),self.assertRaises((AssertionError,ValueError)):
                selected.replace_scalar(raw,field,value)
        with self.assertRaises((AssertionError,ValueError)):
            selected.replace_scalar(b'\x08\x01',15,84380)

    def fixture(self,root):
        contents = {'one.go':b'// synthetic source\n','nested/two.go':b'// synthetic helper\n'}
        for name,raw in contents.items():
            path = root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw)
        return {name:hashlib.sha256(raw).hexdigest() for name,raw in contents.items()}

    def test_walker_refuses_missing_changed_extra_and_unknown_directories(self):
        for mode in ('complete','missing','changed','extra','directory'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                expected = self.fixture(root)
                if mode=='missing':(root/'one.go').unlink()
                elif mode=='changed':(root/'one.go').write_bytes(b'// substituted\n')
                elif mode=='extra':(root/'extra.go').write_bytes(b'// unselected\n')
                elif mode=='directory':(root/'unselected').mkdir()
                if mode=='complete':
                    self.assertEqual(selected.compare_files(root,expected)['files'],2)
                else:
                    with self.assertRaises((AssertionError,ValueError,OSError)):
                        selected.compare_files(root,expected)

    def test_walker_refuses_synthetic_links_and_ancestor_aliases(self):
        for mode in ('symlink','hardlink','ancestor'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                root = base/'source'
                root.mkdir()
                expected = self.fixture(root)
                if mode=='ancestor':
                    alias = base/'alias'
                    alias.symlink_to(root,target_is_directory=True)
                    root = alias
                else:
                    target = root/'one.go'
                    target.unlink()
                    if mode=='symlink':target.symlink_to(root/'nested/two.go')
                    else:os.link(root/'nested/two.go',target)
                with self.assertRaises((AssertionError,ValueError,OSError)):
                    selected.compare_files(root,expected)

    def test_cli_emits_only_the_fixed_public_projection(self):
        output = mock.Mock()
        output.buffer = io.BytesIO()
        with mock.patch.object(selected.sys,'argv',['fee-reader','--emit-public-inputs']), \
                mock.patch.object(selected.sys,'stdout',output), \
                mock.patch.object(selected.sys,'dont_write_bytecode',True):
            self.assertEqual(selected.main(),0)
        self.assertEqual(output.buffer.getvalue(),selected.input_bytes())
        error = io.StringIO()
        with mock.patch.object(selected.sys,'argv',['fee-reader','--emit-public-inputs','--inputs','unselected']), \
                mock.patch.object(selected.sys,'stderr',error), \
                mock.patch.object(selected.sys,'dont_write_bytecode',True):
            self.assertEqual(selected.main(),1)
        self.assertNotIn('unselected',error.getvalue())

    def test_preparation_never_overwrites_a_preexisting_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root/selected.DESTINATION
            target.parent.mkdir()
            held = b'// held synthetic probe\n'
            target.write_bytes(held)
            prior = dict(source=dict(combined_files=543),original_source_files=518)
            with mock.patch.object(selected,'inputs',return_value=({},{})), \
                    mock.patch.object(preparation.baseline,'prepare',return_value=prior), \
                    mock.patch.object(preparation.sys,'dont_write_bytecode',True), \
                    self.assertRaises(FileExistsError):
                preparation.prepare(root/'unused-archive',root)
            self.assertEqual(target.read_bytes(),held)


if __name__ == '__main__':
    unittest.main(verbosity=2)
