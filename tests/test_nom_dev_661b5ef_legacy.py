"""Manufactured legacy stream controls; no current-source execution evidence."""
import copy
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_dev_661b5ef_legacy as reader

ROOT=reader.ROOT
REFUSALS=(AssertionError,ValueError,KeyError,TypeError,OSError)


def load(name):
    spec=importlib.util.spec_from_file_location('current_legacy_control_'+name,ROOT/'tests'/('test_'+name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class CurrentLegacyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        old=load('nom_dev_5cb');old.Dev5cbTests.setUpClass()
        cls.old_payloads=dict(old.Dev5cbTests.payloads)
        cls.payloads=dict(cls.old_payloads)
        namespace,unused=reader.reference(ROOT)
        for kind in reader.AUXILIARY:
            ignored,expected,ignored2,module=namespace['auxiliary_reader'](kind,ROOT)
            cls.payloads[kind.replace('_','-')+'.stdout']=old.auxiliary_stream(module,expected)
        keyless=load('nom_keyless_supervisor')
        declared,signed,plasma=reader.keyless_inputs(ROOT)
        bound,unused=reader.keyless_reference(ROOT)
        report=copy.deepcopy(keyless.synthetic_report())
        report['selected_core_commit']=reader.CORE
        report['records']=bound['expected'](declared,signed,plasma)
        for row in report['records'].values():row['spork_reads']=['DYNAMIC_PLASMA']
        cls.payloads['keyless-supervisor.stdout']=keyless.encoded(keyless.synthetic_events(report))

    def test_current_source_and_twenty_profile_plan_keep_full_historical_selection(self):
        manifest,index=reader.inputs(ROOT)
        self.assertEqual(len(index),518)
        plan=reader.plan(ROOT)
        self.assertEqual((plan['core_commit'],plan['core_tree']),(reader.CORE,reader.TREE))
        self.assertEqual(len(plan['units']),20)
        self.assertEqual(sum(row['parent_and_child_outcomes'] for row in plan['units']),479)
        self.assertEqual(len(plan['producers']),20)
        self.assertEqual(plan['execution'],'NOT_PERFORMED')
        self.assertEqual(plan['reclaim_profile'],'SEPARATE_REQUIRED')
        for row in plan['units']:
            self.assertIn('-count=1',row['arguments'])
            self.assertIn('-mod=readonly',row['arguments'])
            self.assertNotIn('-vet=off',row['arguments'])

    def test_four_descendants_have_only_explicit_source_and_fee_edits(self):
        variants=reader.variants(ROOT)
        self.assertEqual(len(variants),4)
        old=reader.prior.probes(ROOT);new=reader.probes(ROOT)
        changed={name for name in old if old[name]!=new[name]}
        self.assertEqual(len(changed),4)
        self.assertEqual({new[name] for name in changed},reader.PRODUCERS)
        self.assertEqual(len(reader.probes(ROOT,'components')),19)
        self.assertEqual(len(reader.probes(ROOT,'keyless')),2)
        for parent,row in variants.items():
            source=(ROOT/row['selected']).read_text('ascii')
            for edit in reversed(row['edits']):
                at=edit['after_position']
                self.assertEqual(source[at:at+len(edit['after'])],edit['after'])
                source=source[:at]+edit['before']+source[at+len(edit['after']):]
            self.assertEqual(source.encode('ascii'),(ROOT/parent).read_bytes())

    def test_current_keyless_input_matches_selected_go_core_guard(self):
        bindings=reader.input_bindings('keyless-supervisor',root=ROOT)
        declared=reader.read_json(ROOT/bindings['PTLC_NOM_KEYLESS_ORIGINAL_INPUT']['repository_file'])
        destination='vm/research_nom_5cb_keyless_supervisor_test.go'
        selected=(ROOT/reader.probes(ROOT,'keyless')[destination]).read_text('ascii')
        historical=(ROOT/reader.prior.probes(ROOT,'keyless')[destination]).read_text('ascii')
        guards=lambda body:re.findall(r'input\.Core\s*!=\s*"([0-9a-f]{40})"',body)
        self.assertEqual(guards(selected),[declared['selected_core']])
        self.assertEqual(guards(historical),[reader.prior.CORE])
        self.assertNotEqual(guards(selected),guards(historical))
        self.assertEqual(len(declared['originals']),2)
        self.assertEqual(len(declared['declared_case_ids']),24)
        self.assertIn('"selected_core_commit":input.Core',selected)
        self.assertEqual(declared['new_keys'],0)
        self.assertEqual(declared['new_signatures'],0)

    def test_original_keyless_bytes_are_not_replaced(self):
        new,signed,plasma=reader.keyless_inputs(ROOT)
        old,ignored,ignored2=reader.prior_keyless.inputs(ROOT)
        inverse=copy.deepcopy(new);inverse.update(selected_core=reader.prior.CORE,selected_tree=reader.prior.TREE)
        self.assertEqual(inverse,old)
        self.assertEqual(new['new_keys'],0)
        self.assertEqual(new['new_signatures'],0)
        self.assertEqual(new['native_runs'],0)
        self.assertEqual(reader.input_bindings('keyless-supervisor',root=ROOT),
            {'PTLC_NOM_KEYLESS_ORIGINAL_INPUT':{'repository_file':reader.KEYLESS_INPUT}})

    def test_only_twelve_dynamic_rows_change_under_the_earlier_fee_check(self):
        declared,signed,plasma=reader.keyless_inputs(ROOT)
        old=reader.read_json(ROOT/reader.prior.KEYLESS_VALUES)['records']
        namespace,unused=reader.keyless_reference(ROOT)
        current=namespace['expected'](declared,signed,plasma)
        allowed={'returned_error','transaction_present','verifier_trace','pack_entered',
            'packed_delta_hex','packed_hash_matches','packed_data_sha256','returned_wire_hex',
            'post_call_wire_sha256'}
        changed=[]
        for name,row in current.items():
            differences={key for key in row if row[key]!=old[name][key]}
            if not row['declared_dynamic_plasma']:
                self.assertEqual(differences,set())
                continue
            changed.append(name)
            self.assertTrue(differences <= allowed)
            self.assertEqual(row['returned_error'],'ErrNotEnoughTotalPlasma')
            self.assertEqual(row['verifier_trace'],['ACCOUNT_PRECHECK_ENTER','ACCOUNT_PRECHECK_PASS'])
            self.assertFalse(row['transaction_present'] or row['pack_entered'])
            self.assertEqual(row['packed_delta_hex'],row['returned_wire_hex'])
            self.assertEqual(row['application_signer_calls'],0)
            self.assertTrue(row['immutable_original_unchanged'])
        self.assertEqual(len(changed),12)

    def test_hand_prices_change_only_derived_base_on_the_call_copy(self):
        declared,signed,unused=reader.keyless_inputs(ROOT)
        hold=reader.price_hold
        self.assertEqual(hold.pricing.cost(73500,164),(84380,'NONE'))
        self.assertEqual(hold.pricing.cost(73500,165),(84448,'NONE'))
        for leg in ('long','short'):
            original=bytes.fromhex(signed[leg+'-original']['original_wire_hex'])
            before=bytes(original)
            post=hold.derived_wire(original,84380)
            self.assertEqual(original,before)
            self.assertEqual(post,original.replace(bytes.fromhex('98019cbe04'),bytes.fromhex('98019c9305'),1))
            self.assertEqual(post.count(bytes.fromhex('a0019cbe04')),1)
            self.assertEqual(hold.sha(original),declared['originals'][leg]['original_wire_sha256'])
            self.assertNotEqual(post,original)

    def test_modified_funding_or_selector_cannot_fill_original_fee_hold(self):
        declared,signed,plasma=reader.keyless_inputs(ROOT)
        old=reader.read_json(ROOT/reader.prior.KEYLESS_VALUES)['records']
        for field,value in [('fused_plasma','84380'),('difficulty','1'),('data_hex','00'*164)]:
            changed=copy.deepcopy(signed);changed['long-original']['block'][field]=value
            with self.subTest(field=field),self.assertRaises(REFUSALS):
                reader.price_hold.expected(old,declared,changed)
        original=bytes.fromhex(signed['long-original']['original_wire_hex'])
        for raw in (original+b'\x98\x01\x01',original[:-1],original.replace(bytes.fromhex('98019cbe04'),bytes.fromhex('980100'),1)):
            with self.assertRaises(REFUSALS):reader.price_hold.derived_wire(raw,84380)

    def test_historical_successes_cannot_fill_current_source_fee_refusals(self):
        helper=load('nom_keyless_supervisor')
        report=helper.synthetic_report();report['selected_core_commit']=reader.CORE
        for row in report['records'].values():row['spork_reads']=['DYNAMIC_PLASMA']
        declared,signed,plasma=reader.keyless_inputs(ROOT)
        namespace,unused=reader.keyless_reference(ROOT)
        with self.assertRaises(REFUSALS):
            namespace['read'](helper.encoded(helper.synthetic_events(report)),declared,signed,plasma)

    def test_derived_wire_pack_and_error_substitutions_refuse_without_promotion(self):
        helper=load('nom_keyless_supervisor')
        declared,signed,plasma=reader.keyless_inputs(ROOT)
        namespace,binding=reader.keyless_reference(ROOT)
        rows=namespace['expected'](declared,signed,plasma)
        for field,value in [('post_call_wire_sha256',rows['long-dp-true-canonical']['entry_wire_sha256']),
            ('pack_entered',True),('returned_error','ErrABHashInvalid'),('application_admission','ESTABLISHED')]:
            report=helper.synthetic_report();report['selected_core_commit']=reader.CORE;report['records']=copy.deepcopy(rows)
            for row in report['records'].values():row['spork_reads']=['DYNAMIC_PLASMA']
            report['records']['long-dp-true-canonical'][field]=value
            with self.subTest(field=field),self.assertRaises(REFUSALS):
                namespace['read'](helper.encoded(helper.synthetic_events(report)),declared,signed,plasma)
        self.assertFalse(binding['immutable_originals_replaced'])
        self.assertEqual(binding['journal_source_upgrade'],'NOT_SELECTED')

    def test_repinning_unselected_producer_logic_does_not_authorize_it(self):
        variants=reader.variants(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            for name in {reader.VARIANTS}|set(variants)|{row['selected'] for row in variants.values()}:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
            parent='compatibility/nom_dev_5cb_keyless_supervisor_test.go.txt'
            row=variants[parent];selected=root/row['selected']
            selected.write_bytes(selected.read_bytes().replace(b'if dynamic { want=',b'if !dynamic { want=',1))
            variants[parent]['selected_sha256']=reader.sha(selected.read_bytes())
            manifest=reader.read_json(root/reader.VARIANTS);manifest['variants']=variants
            import json
            (root/reader.VARIANTS).write_text(json.dumps(manifest,sort_keys=True)+'\n',encoding='ascii')
            with self.assertRaises(REFUSALS):reader.variants(root)

    def test_private_function_namespaces_do_not_mutate_historical_readers(self):
        old_core=reader.prior.CORE;old_keyless=reader.prior_keyless.CORE
        namespace,binding=reader.reference(ROOT)
        keyless,key_binding=reader.keyless_reference(ROOT)
        self.assertEqual(namespace['CORE'],reader.CORE)
        self.assertEqual(keyless['CORE'],reader.CORE)
        self.assertEqual(reader.prior.CORE,old_core)
        self.assertEqual(reader.prior_keyless.CORE,old_keyless)
        self.assertFalse(binding['imported_module_mutated'])
        self.assertFalse(key_binding['imported_module_mutated'])

    def test_complete_manufactured_streams_never_claim_native_current_compatibility(self):
        result=reader.compare_payloads(self.payloads,ROOT)
        self.assertEqual(result['outcome'],'PASS_SELECTED_LEGACY_VALUES_ONLY')
        self.assertEqual(result['components']['source_files'],518)
        self.assertEqual(result['components']['selected_stateful_outcomes'],342)
        self.assertEqual(result['components']['wire_outcomes'],45)
        self.assertEqual(result['keyless']['cases'],24)
        self.assertEqual(result['reclaim_profile'],'SEPARATE_REQUIRED')
        self.assertEqual(result['native_execution'],'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['execution_origin'],'NOT_ESTABLISHED_BY_READER')
        self.assertEqual(result['core'],'NO-GO')
        self.assertEqual(result['journal_source_upgrade'],'NOT_SELECTED')
        for row in result['auxiliary'].values():self.assertEqual(row['native_report']['selected_core_commit'],reader.CORE)

    def test_old_source_labels_missing_extra_and_foreign_streams_refuse(self):
        with self.assertRaises(REFUSALS):reader.compare_payloads(self.old_payloads,ROOT)
        for mode in ('missing','extra','foreign'):
            values=dict(self.payloads)
            if mode=='missing':values.pop('keyless-supervisor.stderr')
            elif mode=='extra':values['unknown.stdout']=b''
            else:values['keyless-supervisor.stdout']=values['supervisor-plasma.stdout']
            with self.subTest(mode=mode),self.assertRaises(REFUSALS):reader.compare_payloads(values,ROOT)

    def test_cross_profile_stream_sets_cannot_be_substituted(self):
        for profile in ('components','keyless'):
            values={name:raw for name,raw in self.payloads.items() if name.rsplit('.',1)[0] in reader.units(profile)}
            result=reader.compare_payloads(values,ROOT,profile)
            self.assertEqual(result['profile'],profile)
            self.assertEqual('keyless' in result,profile=='keyless')
            with self.assertRaises(REFUSALS):reader.compare_payloads(values,ROOT,'all')

    def test_variant_appended_bytes_and_replaced_parent_cannot_fill_selection(self):
        variants=reader.variants(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            for name in {reader.VARIANTS}|set(variants)|{row['selected'] for row in variants.values()}:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
            parent,row=next(iter(variants.items()))
            selected=root/row['selected'];original=selected.read_bytes()
            selected.write_bytes(original+b'// unselected edit\n')
            with self.assertRaises(REFUSALS):reader.variants(root)
            selected.write_bytes(original)
            (root/parent).write_bytes((root/parent).read_bytes()+b'// changed parent\n')
            with self.assertRaises(REFUSALS):reader.variants(root)

    def test_manifest_nearby_source_wrong_count_and_gate_promotions_refuse(self):
        original=reader.read_json
        manifest=original(ROOT/reader.MANIFEST)
        for key,value in (('core_commit',reader.prior.CORE),('source_files',482),('legacy_outcomes',478),
                          ('application','GO'),('reclaim_profile','PASS'),('journal_source_upgrade','SELECTED')):
            mutated=copy.deepcopy(manifest);mutated[key]=value
            def read(path):return mutated if Path(path)==ROOT/reader.MANIFEST else original(path)
            with self.subTest(key=key),patch.object(reader,'read_json',side_effect=read),self.assertRaises(REFUSALS):reader.inputs(ROOT)


if __name__=='__main__':unittest.main()
