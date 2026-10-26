"""Independent boundary arithmetic and manufactured data controls; no Go run."""
import copy
import json
import unittest
from unittest.mock import patch

from qualification import nom_embedded_argument_pricing as reader

REFUSALS = (AssertionError,ValueError,KeyError,TypeError,OSError)


def events(report,fragment=71):
    event = lambda action,**fields:dict(Action=action,Package=reader.PACKAGE,**fields)
    rows = [event('start'),event('run',Test=reader.PARENT)]
    for name in sorted(report['records']):
        rows.extend([event('run',Test=reader.PARENT+'/'+name),event('pass',Test=reader.PARENT+'/'+name)])
    raw = json.dumps(report,sort_keys=True)+'\n'
    rows.extend(event('output',Test=reader.PARENT,Output=raw[i:i+fragment]) for i in range(0,len(raw),fragment))
    return rows+[event('pass',Test=reader.PARENT),event('pass')]


def encoded(rows):
    return b''.join(json.dumps(row,sort_keys=True).encode('ascii')+b'\n' for row in rows)


class ArgumentPricingTests(unittest.TestCase):
    def test_complete_source_and_inputs_preserve_unfilled_authority(self):
        manifest,declared = reader.inputs()
        self.assertEqual((manifest['source_files'],manifest['cases'],manifest['outcomes']),(518,85,86))
        self.assertEqual(declared,reader.declaration())
        self.assertEqual((manifest['application'],manifest['core'],manifest['independent_assessment']),('NO-GO','NO-GO','UNFILLED'))
        self.assertIn('ABI, ADMISSION, QUOTE AND RECOVERY NOT ESTABLISHED',manifest['scope'])

    def test_cross_product_covers_signed_lengths_selector_and_unsigned_tiers(self):
        declared = reader.declaration()
        self.assertEqual(len({(c['tier'],c['data_length']) for c in declared['cases']}),85)
        self.assertEqual(len({c['tier'] for c in declared['cases']}),5)
        self.assertEqual(len({c['data_length'] for c in declared['cases']}),17)
        self.assertIn(str(-(1<<63)),{c['data_length'] for c in declared['cases']})
        self.assertIn(str((1<<64)-1),{c['tier'] for c in declared['cases']})

    def test_hand_calculated_boundary_prices_do_not_count_selector_bytes(self):
        self.assertEqual(reader.cost(21000,4),(21000,'NONE'))
        self.assertEqual(reader.cost(21000,5),(21068,'NONE'))
        self.assertEqual(reader.cost(52500,36),(54676,'NONE'))
        self.assertEqual(reader.cost(21000,16384),(1134840,'NONE'))
        self.assertEqual(reader.cost(21000,16385),(0,'AB_DATA_TOO_BIG'))
        for length in [-(1<<63),-1,0,1,3,4]:self.assertEqual(reader.cost(73500,length),(73500,'NONE'))

    def test_machine_overflow_probe_cannot_be_promoted_to_a_user_quote(self):
        self.assertEqual(reader.cost((1<<64)-1,5),(67,'NONE'))
        for tier,length in [(True,4),(0,True),(-1,4),(1<<64,4),(0,1<<63),(0,-(1<<63)-1),('21000',4)]:
            with self.subTest(tier=tier,length=length),self.assertRaises(REFUSALS):reader.cost(tier,length)
        self.assertIn('QUOTE',reader.expected_report()['scope'])

    def test_go_bindings_never_supply_independent_expected_values(self):
        value = reader.input_bindings()
        self.assertEqual(value,{'PTLC_NOM_ARGUMENT_PRICING_INPUT':{'repository_file':reader.INPUT}})
        self.assertNotIn(reader.VALUES,json.dumps(value))
        self.assertEqual(reader.plan()['parent_and_child_outcomes'],86)
        self.assertIn('-count=1',reader.plan()['arguments'])
        self.assertNotIn('-vet=off',reader.plan()['arguments'])

    def test_complete_fragmented_manufactured_stream_is_only_data_comparison(self):
        report = reader.expected_report()
        result = reader.compare_payloads({reader.UNIT+'.stdout':encoded(events(report)),reader.UNIT+'.stderr':b''})
        self.assertEqual(result['outcome'],'PASS_FINITE_HELPER_VALUES_ONLY')
        self.assertEqual(result['stdout']['passed_including_parent'],86)
        self.assertEqual(result['native_execution'],'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['execution_origin'],'NOT_ESTABLISHED_BY_READER')

    def test_wrong_cost_error_or_case_type_cannot_fill_exact_values(self):
        original = reader.expected_report()
        for field,value in [('base_plasma','21000'),('base_plasma',21068),('returned_error','AB_DATA_TOO_BIG'),('data_length','6')]:
            report = copy.deepcopy(original);report['records']['base_first_argument'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(REFUSALS):reader.report_from_events(encoded(events(report)))
        for key,value in [('core_commit','0'*40),('application','GO'),('scope','QUOTE VERIFIED')]:
            report = copy.deepcopy(original);report[key]=value
            with self.subTest(field=key),self.assertRaises(REFUSALS):reader.report_from_events(encoded(events(report)))

    def test_missing_failed_skipped_foreign_and_incomplete_lifecycles_refuse(self):
        for mode in ['skip','fail','foreign','missing-child','missing-parent','duplicate-child','missing-eof']:
            rows = events(reader.expected_report())
            if mode in ['skip','fail']:rows[3]['Action']=mode
            elif mode=='foreign':rows[1]['Package']='synthetic/foreign'
            elif mode=='missing-child':del rows[2:4]
            elif mode=='missing-parent':rows.pop(-2)
            elif mode=='duplicate-child':rows.insert(4,copy.deepcopy(rows[3]))
            raw = encoded(rows)
            if mode=='missing-eof':raw=raw[:-1]
            with self.subTest(mode=mode),self.assertRaises(REFUSALS):reader.report_from_events(raw)

    def test_partial_streams_source_substitution_and_gate_promotions_refuse(self):
        raw = encoded(events(reader.expected_report()))
        for payload in [{reader.UNIT+'.stdout':raw}, {reader.UNIT+'.stdout':raw,reader.UNIT+'.stderr':b'','foreign.stdout':b''}]:
            with self.assertRaises(REFUSALS):reader.compare_payloads(payload)
        original = reader.common.decoded
        manifest = reader.inputs()[0]
        for key,value in [('core_commit','0'*40),('cases',84),('application','GO'),('independent_assessment','PASS')]:
            changed = copy.deepcopy(manifest);changed[key]=value
            def decode(raw,limit):
                parsed = original(raw,limit)
                return changed if type(parsed) is dict and parsed.get('schema')==manifest['schema'] else parsed
            with self.subTest(key=key),patch.object(reader.common,'decoded',side_effect=decode),self.assertRaises(REFUSALS):reader.inputs()


if __name__=='__main__':unittest.main()
