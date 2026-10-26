"""Manufactured reclaim controls, independent encodings and tiny source frames."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_dev_ac16bfd_reclaim as reader

ROOT=reader.ROOT
REFUSALS=(AssertionError,ValueError,KeyError,TypeError,OSError)


def events(report, fragment=1024):
    event=lambda action,**fields:dict(Action=action,Package=reader.PACKAGE,**fields)
    rows=[event('start'),event('run',Test=reader.PARENT)]
    for name in sorted(report['records']):
        rows.extend((event('run',Test=reader.PARENT+'/'+name),event('pass',Test=reader.PARENT+'/'+name)))
    text=json.dumps(report,sort_keys=True)+'\n'
    rows.extend(event('output',Test=reader.PARENT,Output=text[at:at+fragment]) for at in range(0,len(text),fragment))
    rows.extend((event('pass',Test=reader.PARENT),event('pass')))
    return rows


def encoded(rows):
    return b''.join(json.dumps(row,sort_keys=True).encode('ascii')+b'\n' for row in rows)


class CurrentReclaimTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.declared=reader.declaration()
        cls.expected=reader.expected_report(cls.declared)

    def data_read(self, rows):
        # These controls target event/value parsing only. Separate tests exercise
        # real source/manifest checks; no verification result is cached by code.
        with patch.object(reader,'inputs',return_value=({},self.declared)):
            return reader.report_from_events(encoded(rows),ROOT)

    def test_complete_selection_keeps_twenty_legacy_profiles_and_one_new_producer(self):
        manifest,declared=reader.inputs(ROOT)
        self.assertEqual(declared,self.declared)
        self.assertEqual(manifest['combined_source_files'],535)
        self.assertEqual((manifest['legacy_profiles'],manifest['legacy_outcomes']),(20,479))
        self.assertEqual((manifest['reclaim_cases'],manifest['reclaim_outcomes']),(76,77))
        producers=reader.probes(ROOT)
        self.assertEqual(len(producers),21)
        self.assertEqual(producers[reader.DESTINATION],reader.DRIVER)
        self.assertIn('vm/zz_research_nom_vm_path_test.go',producers)

    def test_finite_partition_covers_both_reclaim_types_and_all_claim_types(self):
        from collections import Counter
        cases=self.declared['cases']
        self.assertEqual(Counter(row['kind'] for row in cases),{'message':18,'send':18,'vm':40})
        selected={(row['claim_type'],row['reclaim_type']) for row in cases if row['kind']=='vm' and row['mode']=='unlock_before'}
        self.assertEqual(selected,{(claim,reclaim) for claim in range(3) for reclaim in range(2)})
        self.assertEqual(len({row['id'] for row in cases}),76)

    def test_reclaim_preimage_field_widths_and_id_independence_are_explicit(self):
        rows=self.expected['records']
        base=rows['message_base_c2_r0'];other=rows['message_other_id_c2_r0']
        self.assertEqual(base['reclaim_message_hex'],other['reclaim_message_hex'])
        self.assertNotEqual(base['unlock_message_hex'],other['unlock_message_hex'])
        raw=bytes.fromhex(base['reclaim_preimage_hex'])
        self.assertEqual(raw[:len(reader.DOMAIN)],reader.DOMAIN)
        self.assertEqual(raw[len(reader.DOMAIN):len(reader.DOMAIN)+8],(69).to_bytes(8,'big'))
        self.assertEqual(hashlib.sha3_256(raw).hexdigest(),base['reclaim_message_hex'])
        self.assertEqual(len(raw),len(reader.DOMAIN)+8+20+1+20+20+10+32+8+1+33)
        for name in ('other_creator','other_destination','other_token','amount_one','expiry_endian','other_claim_point'):
            self.assertNotEqual(rows['message_'+name+'_c2_r0']['reclaim_message_hex'],base['reclaim_message_hex'])

    def test_new_abi_offsets_sizes_and_legacy_selectors_stay_separate(self):
        rows=self.expected['records']
        create=bytes.fromhex(rows['send_create_canonical_c2_r0']['input_hex'])
        reclaim=bytes.fromhex(rows['send_reclaim_canonical_c2_r0']['input_hex'])
        self.assertEqual(create[:4],hashlib.sha3_256(b'CreateWithReclaimLock(int64,uint8,bytes,address,uint8,bytes)').digest()[:4])
        self.assertEqual(int.from_bytes(create[68:100],'big'),192)
        self.assertEqual(int.from_bytes(create[164:196],'big'),288)
        self.assertEqual(len(create),356)
        self.assertEqual(int.from_bytes(reclaim[36:68],'big'),64)
        self.assertEqual(len(reclaim),164)
        self.assertNotEqual(reclaim[:4],reader.nom_wire.method_selector('Unlock'))
        for method in ('create','reclaim'):
            for width in (1,32):
                row=rows['send_'+method+'_trailing_'+str(width)+'_c2_r0']
                self.assertNotEqual(row['input_hex'],row['post_validation_hex'])
                self.assertEqual(row['returned_error'],'NONE')

    def test_funding_hash_storage_slots_and_payout_failure_restoration_are_declared(self):
        for point_type in range(2):
            rows=self.expected['records'];suffix='_c2_r'+str(point_type)
            before=rows['vm_reclaim_before'+suffix];at=rows['vm_reclaim_at'+suffix]
            self.assertEqual(before['returned_error'],'ReclaimNotDue')
            self.assertEqual(before['before_target_entry_hex'],before['after_target_entry_hex'])
            self.assertEqual(at['returned_error'],'NONE')
            self.assertEqual(at['after_target_entry_hex'],at['after_target_lock_hex'])
            self.assertEqual(at['contract_balance_after'],'0')
            for mode in ('reclaim_payout_failure','unlock_payout_failure'):
                row=rows['vm_'+mode+suffix]
                self.assertEqual(row['returned_error'],'ErrInsufficientBalance')
                self.assertEqual(row['before_target_entry_hex'],row['after_target_entry_hex'])
                self.assertEqual(row['before_target_lock_hex'],row['after_target_lock_hex'])
                self.assertEqual(row['contract_balance_before'],row['contract_balance_after'])
                self.assertEqual((row['payouts'],row['receipt_status']),(0,'2'))

    def test_same_terms_fresh_key_and_scalar_witness_are_distinct(self):
        rows=self.expected['records']
        for point_type in range(2):
            suffix='_c2_r'+str(point_type)
            same=rows['vm_same_terms_other_id'+suffix]
            self.assertNotEqual(same['funding_id_hex'],same['target_id_hex'])
            self.assertTrue(same['same_terms_other_id_message_equal'])
            self.assertEqual(same['contract_balance_after'],'1000')
            self.assertNotEqual(same['after_primary_entry_hex'],'')
            self.assertEqual(rows['vm_fresh_reclaim_key'+suffix]['returned_error'],'ErrInvalidPointSignature')
            scalar=rows['vm_unlock_before'+suffix]
            self.assertEqual((scalar['witness_bytes'],scalar['signing_message_hex']),(32,''))
            plain=rows['vm_plain_reclaim_locked'+suffix]
            self.assertEqual((plain['witness_bytes'],plain['signing_message_hex']),(0,''))
            self.assertEqual(plain['returned_error'],'ErrReclaimSignatureRequired')

    def test_complete_fragmented_manufactured_stream_never_authenticates_execution(self):
        report,stats=self.data_read(events(self.expected,fragment=71))
        self.assertEqual(report,self.expected)
        self.assertEqual(stats['passed_including_parent'],77)
        self.assertEqual(stats['historical_summary_outcomes'],27)
        self.assertFalse(stats['imported_module_mutated'])
        with patch.object(reader,'inputs',return_value=({},self.declared)):
            result=reader.compare_payloads({reader.UNIT+'.stdout':encoded(events(self.expected)),reader.UNIT+'.stderr':b''})
        self.assertEqual(result['native_execution'],'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['recovery_action'],'NONE')
        self.assertEqual(result['core'],'NO-GO')

    def test_changed_storage_disclosure_and_payout_values_cannot_fill_report(self):
        for key,value in (('after_target_lock_hex',''),('after_target_entry_hex',''),('payouts',1),
                          ('contract_balance_after','0'),('receipt_status','1'),('returned_error','NONE'),
                          ('funding_id_hex','00'*32),('receipt_hash_self_consistent',False),('fundings',True)):
            report=copy.deepcopy(self.expected)
            report['records']['vm_reclaim_payout_failure_c2_r0'][key]=value
            with self.subTest(key=key),self.assertRaises(REFUSALS):self.data_read(events(report))

    def test_old_source_extra_fields_and_gate_promotions_refuse(self):
        for key,value in (('selected_core_commit',reader.legacy.prior.CORE),('application','GO'),
                          ('application_signer_calls',1),('independent_assessment','PASS'),
                          ('account_admission','PASS'),('recovery_action','RECLAIM'),('extra',False)):
            report=copy.deepcopy(self.expected);report[key]=value
            with self.subTest(key=key),self.assertRaises(REFUSALS):self.data_read(events(report))

    def test_missing_duplicate_foreign_and_incomplete_events_refuse(self):
        original=events(self.expected)
        for mode in ('missing_child','duplicate_pass','foreign_package','parent_pass_early','incomplete_line','missing_package_pass'):
            rows=copy.deepcopy(original)
            if mode=='missing_child':rows.pop(3)
            elif mode=='duplicate_pass':rows.insert(4,copy.deepcopy(rows[3]))
            elif mode=='foreign_package':rows[0]['Package']='foreign/package'
            elif mode=='parent_pass_early':rows[3]['Test']=reader.PARENT
            elif mode=='incomplete_line':rows[-3]['Output']=rows[-3]['Output'][:-2]
            else:rows.pop()
            with self.subTest(mode=mode),self.assertRaises(REFUSALS):self.data_read(rows)

    def test_manifest_nearby_source_counts_and_promoted_journal_refuse(self):
        original=reader.legacy.read_json;manifest=original(ROOT/reader.MANIFEST)
        for key,value in (('core_commit',reader.legacy.prior.CORE),('combined_source_files',520),
            ('reclaim_cases',75),('legacy_outcomes',478),('application','GO'),('journal_source_upgrade','SELECTED')):
            changed=copy.deepcopy(manifest);changed[key]=value
            def read(path):return changed if Path(path)==ROOT/reader.MANIFEST else original(path)
            # The positive selection above checks the real historical chain.
            # Each data-only refusal here targets this new manifest's fields.
            with self.subTest(key=key),patch.object(reader.legacy,'inputs',return_value=({},{})),\
                    patch.object(reader.legacy,'read_json',side_effect=read),self.assertRaises(REFUSALS):reader.inputs(ROOT)

    def test_source_walker_extra_and_replaced_producer_refuse_without_large_clones(self):
        with tempfile.TemporaryDirectory() as temporary:
            source=Path(temporary).resolve();name='synthetic/source.go';raw=b'// tiny source-frame control only\n'
            path=source/name;path.parent.mkdir();path.write_bytes(raw)
            index={name:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                git_blob_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())}
            target=source/reader.DESTINATION;target.parent.mkdir(parents=True,exist_ok=True)
            original=(ROOT/reader.DRIVER).read_bytes();target.write_bytes(original)
            with patch.object(reader,'inputs',return_value=({},self.declared)),\
                    patch.object(reader.legacy.source,'inputs',return_value=({},index)),\
                    patch.object(reader,'probes',return_value={reader.DESTINATION:reader.DRIVER}):
                result=reader.compare_source(source,ROOT)
                self.assertEqual(result['combined_files'],2)
                target.write_bytes(original+b'// unselected change\n')
                with self.assertRaises(REFUSALS):reader.compare_source(source,ROOT)
                target.write_bytes(original)
                (source/'extra.txt').write_bytes(b'unselected')
                with self.assertRaises(REFUSALS):reader.compare_source(source,ROOT)


if __name__=='__main__':unittest.main()
