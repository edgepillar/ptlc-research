"""Synthetic reader controls only; no native execution or new key/signature."""
import copy
import json
import unittest

from qualification import nom_keyless_supervisor as reader


def synthetic_report():
    declared,signed,plasma = reader.inputs()
    records = copy.deepcopy(reader.expected(declared,signed,plasma))
    for row in records.values():row['spork_reads']=['DYNAMIC_PLASMA']
    return dict(schema='private-nom-5cb-keyless-original-supervisor-result-v1',
        selected_core_commit=reader.CORE,records=records,new_keys=0,new_signatures=0,
        scope='SELECTED SUPERVISOR ENTRY WITH DECLARED SYNTHETIC MEMORY VIEWS',
        application='NO-GO',core='NO-GO',independent_assessment='UNFILLED',
        pool_admission='NOT_CALLED',chain_insertion='NOT_CALLED',
        journal_source_upgrade='NOT_SELECTED',transaction_broadcast='NOT_PERFORMED')


def synthetic_events(report=None,fragment=1024):
    report=synthetic_report() if report is None else report
    event=lambda action,**fields:dict(Action=action,Package=reader.PACKAGE,**fields)
    events=[event('start'),event('run',Test=reader.PARENT)]
    for name in sorted(reader.CASE_IDS):
        events.extend((event('run',Test=reader.PARENT+'/'+name),
                       event('pass',Test=reader.PARENT+'/'+name)))
    text='    '+reader.BASENAME+':1: '+json.dumps(report,sort_keys=True)+'\n'
    events.extend(event('output',Test=reader.PARENT,Output=text[at:at+fragment])
                  for at in range(0,len(text),fragment))
    events.extend((event('pass',Test=reader.PARENT),event('pass')))
    return events


def encoded(events):
    return b''.join(json.dumps(row,sort_keys=True).encode('ascii')+b'\n' for row in events)


class KeylessSupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.declared,cls.signed,cls.plasma=reader.inputs()
        cls.report=synthetic_report()

    def read(self,events):
        return reader.read(encoded(events),self.declared,self.signed,self.plasma)

    def refuse(self,events):
        with self.assertRaises((AssertionError,ValueError,KeyError,TypeError)):
            self.read(events)

    def test_complete_fragmented_values_do_not_authenticate_execution(self):
        report,stats=self.read(synthetic_events(self.report))
        self.assertEqual(report,self.report)
        self.assertEqual(stats['passed_including_parent'],25)
        self.assertEqual(stats['execution_origin'],'NOT_ESTABLISHED_BY_READER')
        self.assertEqual(stats['complete_account_admission'],'UNFILLED')
        self.assertEqual(stats['application'],stats['core'])
        self.assertEqual(stats['core'],'NO-GO')

    def test_frozen_case_set_and_verdict_counts(self):
        from collections import Counter
        records=self.report['records']
        self.assertEqual(set(records),reader.CASE_IDS)
        self.assertEqual(Counter(row['returned_error'] for row in records.values()),
            {'PASS':10,'TRAILING_DATA':2,'ErrABHashInvalid':4,
             'ErrABSignatureMissing':4,'ErrABSignatureInvalid':4})

    def test_normalization_preserves_original_and_selected_signature(self):
        for leg in ('long','short'):
            off=self.report['records'][leg+'-dp-false-trailing_abi_byte']
            on=self.report['records'][leg+'-dp-true-trailing_abi_byte']
            self.assertNotEqual(off['entry_data_sha256'],off['post_call_data_sha256'])
            self.assertEqual(off['original_wire_sha256'],off['post_call_wire_sha256'])
            self.assertEqual(on['entry_wire_sha256'],on['post_call_wire_sha256'])
            self.assertEqual(off['original_signature_sha256'],off['post_call_signature_sha256'])
            self.assertEqual(on['original_signature_sha256'],on['post_call_signature_sha256'])
            self.assertEqual(on['returned_wire_hex'],'')

    def test_repeated_protobuf_field_is_observed_before_decode(self):
        for leg in ('long','short'):
            row=self.report['records'][leg+'-dp-false-protobuf_repeated_version']
            self.assertNotEqual(row['raw_decode_input_sha256'],row['entry_wire_sha256'])
            self.assertEqual(row['entry_wire_sha256'],row['original_wire_sha256'])
            self.assertEqual(row['raw_decode_input_bytes'],586)

    def test_critical_byte_hash_signature_and_handoff_changes_refuse(self):
        for key,value in (('entry_data_sha256','00'*32),('post_call_wire_sha256','00'*32),
                          ('entry_signature_sha256','00'*32),('packed_delta_hex','00'),
                          ('returned_wire_hex',''),('base_patch_sha256','00'*32),
                          ('advertised_hash_preserved',False),('base_unchanged',False),
                          ('application_signer_calls',1),('verifier_trace',[])):
            changed=copy.deepcopy(self.report)
            changed['records']['long-dp-false-canonical'][key]=value
            with self.subTest(key=key):self.refuse(synthetic_events(changed))

    def test_absent_extra_and_substituted_cases_refuse(self):
        for mode in ('missing','extra','substitute'):
            report=copy.deepcopy(self.report)
            if mode=='missing':report['records'].pop('long-dp-false-canonical')
            elif mode=='extra':report['records']['unselected']=report['records']['long-dp-false-canonical']
            else:report['records']['long-dp-false-canonical']=report['records']['short-dp-false-canonical']
            with self.subTest(mode=mode):self.refuse(synthetic_events(report))

    def test_scope_and_new_key_or_signature_claims_refuse(self):
        for key,value in (('new_keys',1),('new_keys',False),('new_signatures',True),
                          ('selected_core_commit','00'*20),('application','GO'),
                          ('independent_assessment','PASS'),('journal_source_upgrade','SELECTED'),
                          ('transaction_broadcast','PERFORMED'),('extra',False)):
            report=copy.deepcopy(self.report);report[key]=value
            with self.subTest(key=key):self.refuse(synthetic_events(report))

    def test_spork_read_order_remains_observational(self):
        report=copy.deepcopy(self.report)
        report['records']['long-dp-false-canonical']['spork_reads']=[
            'OTHER_SELECTED_SPORK','DYNAMIC_PLASMA','OTHER_SELECTED_SPORK']
        unused,stats=self.read(synthetic_events(report))
        self.assertIn('EXACT ORDER NOT QUALIFIED',stats['spork_read_order'])

    def test_invalid_or_missing_spork_observations_refuse(self):
        for reads in ([],['OTHER_SELECTED_SPORK'],['UNKNOWN'],[True],['DYNAMIC_PLASMA']*65):
            report=copy.deepcopy(self.report)
            report['records']['long-dp-false-canonical']['spork_reads']=reads
            with self.subTest(reads=reads[:2]):self.refuse(synthetic_events(report))

    def test_partial_duplicate_and_foreign_test_results_refuse(self):
        original=synthetic_events(self.report)
        at=next(at for at,row in enumerate(original) if row['Action']=='pass' and '/' in row.get('Test',''))
        for mode in ('missing','duplicate','foreign','skip','fail'):
            changed=copy.deepcopy(original)
            if mode=='missing':changed.pop(at)
            elif mode=='duplicate':changed.insert(at,changed[at])
            elif mode=='foreign':changed[at]['Test']=reader.PARENT+'/unselected'
            else:changed[at]['Action']=mode
            with self.subTest(mode=mode):self.refuse(changed)

    def test_report_prefix_truncation_and_duplicate_report_refuse(self):
        original=synthetic_events(self.report)
        at=next(at for at,row in enumerate(original) if row['Action']=='output')
        for mode in ('prefix','truncated','duplicate'):
            changed=copy.deepcopy(original)
            if mode=='prefix':changed[at]['Output']=changed[at]['Output'].replace(reader.BASENAME,'unselected.go')
            elif mode=='truncated':changed.pop(at+1)
            else:changed.insert(at,copy.deepcopy(changed[at]))
            with self.subTest(mode=mode):self.refuse(changed)

    def test_noncanonical_and_truncated_outer_varints_refuse(self):
        for raw in (b'\x80\x00',b'\x80',b'\xff'*10+b'\x01'):
            with self.subTest(raw=raw),self.assertRaises((AssertionError,ValueError)):
                reader.number(raw,0)

    def test_outer_field_duplicates_absence_and_kind_refuse(self):
        for raw in (b'\x72\x01x\x72\x01y',b'\x08\x01',b'\x70\x01',b'\x75\0\0\0\0'):
            with self.subTest(raw=raw),self.assertRaises((AssertionError,ValueError)):
                reader.replace_bytes(raw,14,b'x')

    def test_stream_bound_refuses_before_record_parsing(self):
        with self.assertRaises(AssertionError):
            reader.read(b' '*(reader.MAX_STREAM+1),self.declared,self.signed,self.plasma)
