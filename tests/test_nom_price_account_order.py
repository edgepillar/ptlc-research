"""Synthetic framing/value controls; no native execution or recovery authorization."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qualification import nom_price_account_order as reader

ROOT=Path(__file__).resolve().parents[1]


def stream(records):
    events=[dict(Action='run',Package=reader.PACKAGE,Test=reader.TEST)]
    for key,row in sorted(records.items()):
        name=reader.TEST+'/'+key
        events.extend([dict(Action='run',Package=reader.PACKAGE,Test=name),
            dict(Action='output',Package=reader.PACKAGE,Test=name,Output=reader.MARKER+json.dumps(row)+'\n'),
            dict(Action='pass',Package=reader.PACKAGE,Test=name)])
    events.extend([dict(Action='pass',Package=reader.PACKAGE,Test=reader.TEST),dict(Action='pass',Package=reader.PACKAGE)])
    return b''.join(json.dumps(event).encode('ascii')+b'\n' for event in events)


class PriceAccountOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference=json.loads((ROOT/reader.FIXTURE).read_bytes())['records']
        cls.stdout=stream(cls.reference)

    def refuse(self,records):
        with self.assertRaises((ValueError,AssertionError,KeyError,TypeError)):
            reader.compare_stream(stream(records),b'',ROOT)

    def test_selection_and_reference_keep_declared_source_separate(self):
        manifest,index=reader.inputs(ROOT)
        self.assertEqual(reader.current.git_tree(index),reader.TREE)
        self.assertEqual(manifest['selected_records'],20)
        self.assertEqual(manifest['reference_scope'],'PUBLIC_SYNTHETIC_FINITE_VALUES; NOT_EXECUTION_EVIDENCE')

    def test_synthetic_complete_values_do_not_fill_execution_or_actions(self):
        result=reader.compare_stream(self.stdout,b'synthetic diagnostic\n',ROOT)
        self.assertEqual(result['selected_go_outcomes'],21)
        self.assertEqual(result['momentum_gate_counts'],{'PASS_DECLARED_COMPONENT':8,'REFUSE_PRICE':6,'REFUSE_ACCOUNT_ORDER':6})
        self.assertEqual(result['actions'],[])
        self.assertEqual(result['original_replacements'],0)
        self.assertEqual(result['complete_source'],'SEPARATE_CONTENT_CHECK_REQUIRED')
        self.assertEqual(result['actual_command_exit'],'NOT_ESTABLISHED_BY_THIS_READER')
        self.assertEqual(result['execution_origin'],'NOT_ESTABLISHED_BY_THIS_READER')
        self.assertEqual(result['native_execution'],'NOT_PERFORMED_BY_READER')
        for key in ('combined_admission','inclusion_before_timeout','source_authentication','durable_custody','disclosure_timing','reorg_finality_availability','independent_assessment'):
            self.assertEqual(result[key],'UNFILLED')
        self.assertEqual(result['journal_source_upgrade'],'NOT_SELECTED')
        self.assertEqual(result['unknown_work_ledger'],'NOT_READ_OR_CHANGED')
        self.assertEqual(result['application'],result['core'])
        self.assertEqual(result['core'],'NO-GO')

    def test_underpriced_original_cannot_be_reclassified_as_component_pass(self):
        for leg in ('long','short'):
            records=copy.deepcopy(self.reference)
            records[leg+'-fusion-rise']['momentum_gate']='PASS_DECLARED_COMPONENT'
            self.refuse(records)

    def test_missing_changed_or_reversed_frontier_cannot_be_reclassified(self):
        for case in ('missing-frontier','changed-frontier','reverse-order'):
            records=copy.deepcopy(self.reference)
            records['long-'+case]['momentum_gate']='PASS_DECLARED_COMPONENT'
            self.refuse(records)

    def test_metadata_copy_cannot_be_called_exact_original(self):
        records=copy.deepcopy(self.reference)
        records['long-untrusted-zero-base']['selected']=['exact-original']
        self.refuse(records)

    def test_premium_descendant_cannot_escort_the_underpriced_original(self):
        records=copy.deepcopy(self.reference)
        records['short-blocked-descendant']['selected']=['exact-original','unsigned-child','unsigned-unrelated-premium']
        self.refuse(records)

    def test_ordered_and_reversed_momentum_records_cannot_be_substituted(self):
        records=copy.deepcopy(self.reference)
        key='long-reverse-order'
        records[key]=copy.deepcopy(records['long-ordered-descendant']);records[key]['id']=key
        self.refuse(records)

    def test_exact_original_byte_digest_and_node_hash_bind_separately(self):
        for key in ('original_wire_sha256','original_node_hash_hex'):
            records=copy.deepcopy(self.reference);records['long-minimum'][key]='00'*32
            self.refuse(records)

    def test_missing_record_cannot_be_filled_from_reference(self):
        records=copy.deepcopy(self.reference);records.pop('short-minimum')
        # Retain all pass labels so the value boundary, rather than missing TAP,
        # must reject the absent selected record.
        events=[json.loads(line) for line in self.stdout.splitlines()]
        events=[e for e in events if not (e['Action']=='output' and e.get('Test')==reader.TEST+'/short-minimum')]
        with self.assertRaises(ValueError):
            reader.compare_stream(b''.join(json.dumps(e).encode('ascii')+b'\n' for e in events),b'',ROOT)

    def test_duplicate_or_wrong_test_record_refuses(self):
        events=[json.loads(line) for line in self.stdout.splitlines()]
        position=next(i for i,row in enumerate(events) if row['Action']=='output')
        for mode in ('duplicate','wrong-test'):
            changed=copy.deepcopy(events)
            if mode=='duplicate':changed.insert(position,copy.deepcopy(changed[position]))
            else:changed[position]['Test']=reader.TEST+'/short-minimum'
            with self.assertRaises(ValueError):
                reader.compare_stream(b''.join(json.dumps(e).encode('ascii')+b'\n' for e in changed),b'',ROOT)

    def test_boolean_and_integer_record_values_are_distinct(self):
        for key,value in (('canonical_calls',True),('original_bytes_preserved',1),('fusion_price',1000.0)):
            records=copy.deepcopy(self.reference);records['long-minimum'][key]=value
            self.refuse(records)

    def test_added_authority_and_unknown_record_fields_refuse(self):
        for key,value in (('authorized',True),('signing','PERMITTED'),('retry',True)):
            records=copy.deepcopy(self.reference);records['long-minimum'][key]=value
            self.refuse(records)

    def test_duplicate_record_json_keys_refuse(self):
        events=[json.loads(line) for line in self.stdout.splitlines()]
        record=next(e for e in events if e['Action']=='output')
        record['Output']=record['Output'].replace('{','{"canonical_calls":1,',1)
        with self.assertRaises(ValueError):
            reader.compare_stream(b''.join(json.dumps(e).encode('ascii')+b'\n' for e in events),b'',ROOT)

    def test_incomplete_failed_or_substituted_go_outcomes_refuse(self):
        for mode in ('missing-parent','failed','other-package'):
            events=[json.loads(line) for line in self.stdout.splitlines()]
            if mode=='missing-parent':events=[e for e in events if not (e['Action']=='pass' and e.get('Test')==reader.TEST)]
            elif mode=='failed':next(e for e in events if e['Action']=='pass' and 'Test' in e)['Action']='fail'
            else:events[0]['Package']='unselected/package'
            with self.assertRaises((ValueError,AssertionError)):
                reader.compare_stream(b''.join(json.dumps(e).encode('ascii')+b'\n' for e in events),b'',ROOT)

    def test_stderr_is_bounded_diagnostic_bytes(self):
        for value in (None,'',False,b' '*(reader.current.MAX_STDERR+1)):
            with self.assertRaises(ValueError):reader.compare_stream(self.stdout,value,ROOT)

    def test_partial_source_cannot_supply_complete_source_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):reader.compare_source(Path(temporary).resolve(),ROOT)

    def test_cli_refusal_keeps_unselected_argument_out_of_output(self):
        result=subprocess.run([sys.executable,'-B','-m','qualification.nom_price_account_order','--unselected-private-control'],
            cwd=ROOT,capture_output=True,timeout=30)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'REFUSED: price/account-order component comparison\n')

    def test_optimized_reader_refuses_before_source_or_stream_access(self):
        result=subprocess.run([sys.executable,'-B','-O','-m','qualification.nom_price_account_order'],
            cwd=ROOT,capture_output=True,timeout=30)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'price/account-order comparison requires assertions enabled\n')
