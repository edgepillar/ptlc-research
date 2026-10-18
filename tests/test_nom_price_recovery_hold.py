import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qualification import nom_price_recovery_hold as hold

ROOT=Path(__file__).resolve().parents[1]


class PriceRecoveryHoldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.originals=json.loads((ROOT/'compatibility/fixtures/nom_signed_originals_v1.json').read_bytes())
        cls.fixture=json.loads((ROOT/'compatibility/fixtures/nom_price_recovery_hold_v1.json').read_bytes())

    def request(self,case='minimum',custody=None):
        request=dict(schema=hold.SCHEMA,selection=hold.SELECTION,price_case=case,originals={})
        custody=custody or dict(long='both',short='both')
        for leg in hold.LEGS:
            state=custody[leg];original=self.originals[leg+'-original']
            request['originals'][leg]=dict(wire_hex=original['wire_hex'] if state in ('both','wire-only') else None,
                node_hash_hex=original['hash_hex'] if state in ('both','node-only') else None)
        return request

    def result(self,request):return hold.evaluate(request,ROOT)

    def refuses(self,request):
        with self.assertRaises((AssertionError,ValueError,KeyError,TypeError)):
            self.result(request)

    def cli(self,raw,extra=()):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'synthetic-private-request.json';path.write_bytes(raw)
            return subprocess.run([sys.executable,'-B',*extra,'-m','qualification.nom_price_recovery_hold',
                '--request',str(path)],cwd=ROOT,capture_output=True,timeout=30)

    def test_manifest_and_all_declared_vectors(self):
        self.assertEqual(hold.inputs(ROOT)['selection'],hold.SELECTION)
        self.assertEqual(len(self.fixture['cases']),12)
        self.assertEqual({row['price_case'] for row in self.fixture['cases']},{row[0] for row in hold.CASES})
        for row in self.fixture['cases']:
            with self.subTest(row['id']):
                result=self.result(self.request(row['price_case'],row['custody']))
                self.assertEqual(result['outcome'],'HOLD_REFERENCE_PRICE_AND_CUSTODY_ONLY')
                for leg in hold.LEGS:
                    self.assertEqual(result['legs'][leg]['hold_reasons'],row['expected_hold_reasons'][leg])
                    self.assertEqual(result['legs'][leg]['reference_canonical_price_component'],row['canonical_accepts'])

    def test_matching_price_is_still_hold(self):
        result=self.result(self.request())
        self.assertTrue(all(row['reference_canonical_price_component'] for row in result['legs'].values()))
        self.assertTrue(all(row['state']=='HOLD' for row in result['legs'].values()))
        self.assertEqual(result['actions'],[])

    def test_fusion_price_refusal_cannot_replace_or_release(self):
        result=self.result(self.request('fusion-one-above'))
        self.assertTrue(all('REFERENCE_CANONICAL_PRICE_COMPONENT_REFUSES' in row['hold_reasons'] for row in result['legs'].values()))
        self.assertEqual(result['original_replacements'],0)
        self.assertEqual(result['original_release'],'NOT_PERFORMED')

    def test_work_only_rise_does_not_authorize_progress(self):
        result=self.result(self.request('work-only-rise'))
        self.assertEqual(result['outcome'],'HOLD_REFERENCE_PRICE_AND_CUSTODY_ONLY')
        self.assertEqual(result['work_replenishment'],'NOT_PERFORMED')
        self.assertEqual(result['retry'],'NOT_PERFORMED')

    def test_diagnostic_zero_metadata_cannot_hide_canonical_refusal(self):
        result=self.result(self.request('untrusted-zero-base'))
        for row in result['legs'].values():
            self.assertTrue(row['reference_advertised_price_component'])
            self.assertFalse(row['reference_canonical_price_component'])
            self.assertIn('DIAGNOSTIC_METADATA_IS_NOT_AN_ORIGINAL',row['hold_reasons'])

    def test_diagnostic_max_metadata_cannot_make_a_release_decision(self):
        result=self.result(self.request('untrusted-max-base'))
        for row in result['legs'].values():
            self.assertFalse(row['reference_advertised_price_component'])
            self.assertTrue(row['reference_canonical_price_component'])
            self.assertEqual(row['state'],'HOLD')

    def test_legacy_constructor_reference_is_not_current_admission(self):
        result=self.result(self.request('before-first-v2'))
        self.assertTrue(all(row['reference_canonical_price_component'] for row in result['legs'].values()))
        self.assertEqual(result['complete_admission'],'UNFILLED')

    def test_maximum_work_integer_reference_stays_bounded(self):
        result=self.result(self.request('wide-work-price'))
        self.assertTrue(all(row['state']=='HOLD' for row in result['legs'].values()))
        self.assertLess(len(json.dumps(result)),16384)

    def test_absent_wire_is_not_rebuilt_from_public_fixture(self):
        result=self.result(self.request(custody=dict(long='node-only',short='both')))
        self.assertIsNone(result['legs']['long']['supplied_wire_sha256'])
        self.assertEqual(result['legs']['long']['supplied_node_hash_hex'],self.originals['long-original']['hash_hex'])
        self.assertIn('ORIGINAL_WIRE_UNAVAILABLE',result['legs']['long']['hold_reasons'])

    def test_absent_node_binding_is_not_derived_from_present_wire(self):
        result=self.result(self.request(custody=dict(long='both',short='wire-only')))
        self.assertIsNone(result['legs']['short']['supplied_node_hash_hex'])
        self.assertEqual(result['legs']['short']['supplied_wire_sha256'],self.originals['short-original']['wire_sha256'])

    def test_both_absent_values_stay_absent(self):
        result=self.result(self.request('fusion-rise',dict(long='neither',short='neither')))
        self.assertTrue(all(row['supplied_wire_sha256'] is None and row['supplied_node_hash_hex'] is None for row in result['legs'].values()))

    def test_supplied_bytes_and_bindings_are_not_mutated(self):
        request=self.request();before=copy.deepcopy(request)
        self.result(request)
        self.assertEqual(request,before)

    def test_report_does_not_serialize_original_wire(self):
        result=self.result(self.request());raw=json.dumps(result)
        for leg in hold.LEGS:
            self.assertNotIn(self.originals[leg+'-original']['wire_hex'],raw)
            self.assertEqual(result['legs'][leg]['supplied_wire_sha256'],hashlib.sha256(bytes.fromhex(self.originals[leg+'-original']['wire_hex'])).hexdigest())

    def test_all_independent_and_operational_requirements_stay_unfilled(self):
        result=self.result(self.request())
        for key in ('durable_custody','source_authentication','complete_admission','inclusion_before_timeout',
                'account_ordering','disclosure_timing','canonicality','finality','rollback_protection','availability','independent_assessment'):
            self.assertEqual(result[key],'UNFILLED')
        self.assertEqual(result['application'],result['core'])
        self.assertEqual(result['core'],'NO-GO')
        for key in ('journal_write','signing','retry','work_replenishment','original_release','transaction_broadcast'):
            self.assertEqual(result[key],'NOT_PERFORMED')
        self.assertEqual(result['journal_source_upgrade'],'NOT_SELECTED')
        self.assertEqual(result['unknown_work_ledger'],'NOT_READ_OR_CHANGED')

    def test_unknown_case_and_typed_authority_values_refuse(self):
        for value in ('unknown',True,False,1,None,[],{}):
            with self.subTest(value=value):
                request=self.request();request['price_case']=value;self.refuses(request)

    def test_top_level_shapes_and_missing_fields_refuse(self):
        for value in (None,[],True,'request',1):self.refuses(value)
        for key in self.request():
            request=self.request();request.pop(key);self.refuses(request)

    def test_unknown_authority_and_action_fields_refuse(self):
        for key in ('source_authenticated','allow_signing','retry','release_original','journal','source_snapshot'):
            request=self.request();request[key]=True;self.refuses(request)

    def test_unknown_schema_and_selection_refuse(self):
        for key in ('schema','selection'):
            request=self.request();request[key]='unselected';self.refuses(request)

    def test_missing_extra_and_wrong_leg_shapes_refuse(self):
        for value in (None,[],True,dict(long={}),dict(long={},short={},extra={})):
            request=self.request();request['originals']=value;self.refuses(request)

    def test_cross_leg_wire_and_node_binding_refuse(self):
        for key in ('wire_hex','node_hash_hex'):
            request=self.request();request['originals']['long'][key]=request['originals']['short'][key];self.refuses(request)

    def test_partial_replaced_and_noncanonical_wire_refuse(self):
        original=self.originals['long-original']['wire_hex']
        for value in (original[:-2],original+'00',original.upper(),'00',False,{},[],1):
            request=self.request();request['originals']['long']['wire_hex']=value;self.refuses(request)

    def test_wrong_hash_types_and_noncanonical_binding_refuse(self):
        original=self.originals['short-original']['hash_hex']
        for value in ('0'*64,original.upper(),original[:-1],False,{},[],1):
            request=self.request();request['originals']['short']['node_hash_hex']=value;self.refuses(request)

    def test_missing_extra_and_wrong_claim_shapes_refuse(self):
        for value in (None,[],False,{},dict(wire_hex=None),dict(wire_hex=None,node_hash_hex=None,authenticated=True)):
            request=self.request();request['originals']['long']=value;self.refuses(request)

    def test_json_roundtrip_and_request_cap(self):
        raw=json.dumps(self.request()).encode('ascii')
        self.assertEqual(hold.evaluate_json(raw,ROOT),self.result(self.request()))
        for value in (b'',b' '*(hold.MAX_REQUEST+1),'text',bytearray(raw)):
            with self.assertRaises(ValueError):hold.evaluate_json(value,ROOT)

    def test_duplicate_top_level_and_nested_json_keys_refuse(self):
        raw=json.dumps(self.request(),separators=(',',':'))
        for value in (raw.replace('{','{"schema":"duplicate",',1),raw.replace('"wire_hex":','"wire_hex":null,"wire_hex":',1)):
            with self.assertRaises((AssertionError,ValueError)):hold.evaluate_json(value.encode('ascii'),ROOT)

    def test_malformed_json_and_trailing_frames_refuse(self):
        raw=json.dumps(self.request()).encode('ascii')
        for value in (raw[:-1],raw+b'{}',b'\xff',b'null',b'[]'):
            with self.assertRaises((AssertionError,ValueError,TypeError)):hold.evaluate_json(value,ROOT)

    def test_cli_hold_is_data_only_and_does_not_echo_request_path(self):
        result=self.cli(json.dumps(self.request()).encode('ascii'))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['actions'],[])
        self.assertNotIn(b'synthetic-private-request',result.stdout+result.stderr)
        self.assertEqual(result.stderr,b'')

    def test_cli_refusal_is_sanitized(self):
        result=self.cli(b'{"private-control":"unselected"}')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'REFUSED: reference price/custody hold\n')

    def test_unknown_cli_arguments_cannot_echo_unselected_text(self):
        result=subprocess.run([sys.executable,'-B','-m','qualification.nom_price_recovery_hold',
            '--unselected-private-argument'],cwd=ROOT,capture_output=True,timeout=30)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stderr,b'REFUSED: reference price/custody hold\n')
        self.assertEqual(result.stdout,b'')

    def test_optimized_execution_refuses_before_request_processing(self):
        result=self.cli(json.dumps(self.request()).encode('ascii'),('-O',))
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'reference recovery hold requires assertions enabled\n')
