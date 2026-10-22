"""Synthetic source/value framing controls; not native or chain evidence."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_dev_5cb as reader
from qualification import nom_dev_5cb_reproduction as reproduction

ROOT = reader.ROOT
REFUSALS = (AssertionError,ValueError,KeyError,TypeError,OSError)


def load_control(name):
    spec=importlib.util.spec_from_file_location('selected_5cb_'+name,ROOT/'tests'/('test_'+name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def auxiliary_stream(module,report):
    # These event identities and values are manufactured parser controls.
    event=lambda action,**fields:dict(Action=action,Package=module.PACKAGE,**fields)
    rows=[event('start'),event('run',Test=module.PARENT)]
    for name in sorted(report['records']):
        rows.extend((event('run',Test=module.PARENT+'/'+name),event('pass',Test=module.PARENT+'/'+name)))
    text=json.dumps(report,sort_keys=True)+'\n'
    rows.extend(event('output',Test=module.PARENT,Output=text[at:at+1024]) for at in range(0,len(text),1024))
    rows.extend((event('pass',Test=module.PARENT),event('pass')))
    return b''.join(json.dumps(row).encode('ascii')+b'\n' for row in rows)


class Dev5cbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prior=load_control('nom_current_admission')
        prior.CurrentAdmissionTests.setUpClass()
        cls.payloads=dict(prior.CurrentAdmissionTests.payloads)
        cls.old_context_stream=cls.payloads['account-context.stdout']
        module=prior.CurrentAdmissionTests.modules['account_context']
        cls.payloads['account-context.stdout']=prior.synthetic_stream(
            prior.CurrentAdmissionTests.selected['account-context'],reader.context_fixture(ROOT)['records'],
            prefix=module.PREFIX,filename='zz_research_nom_account_context_test.go',test=module.TEST)
        for kind in reader.AUXILIARY:
            unused,expected,unused_binding,module=reader.auxiliary_reader(kind,ROOT)
            unit=kind.replace('_','-')
            cls.payloads[unit+'.stdout']=auxiliary_stream(module,expected)
            cls.payloads[unit+'.stderr']=b''
        keyless=load_control('nom_keyless_supervisor')
        cls.payloads['keyless-supervisor.stdout']=keyless.encoded(keyless.synthetic_events())
        cls.payloads['keyless-supervisor.stderr']=b''

    def test_immutable_source_inventory_and_frozen_historical_inputs(self):
        manifest,index=reader.inputs(ROOT)
        self.assertEqual(len(index),482)
        self.assertEqual(reader.earlier.git_tree(index),reader.TREE)
        self.assertEqual(manifest['prior_dev_source'],reader.previous.CORE)
        self.assertEqual(set(manifest['input_sha256']),reader.OWN_INPUTS)
        self.assertEqual(set(manifest['frozen_input_sha256']),reader.FROZEN_INPUTS)
        self.assertEqual({key:index[key] for key in ('go.mod','go.sum','LICENSE')},
            {key:reader.previous.inputs(ROOT)[1][key] for key in ('go.mod','go.sum','LICENSE')})

    def test_exact_source_variant_inverses_and_all_profile_selections(self):
        variants=reader.producer_variants(ROOT)
        self.assertEqual(len(variants),7)
        self.assertEqual(len(reader.probes(ROOT)),20)
        self.assertEqual(len(reader.probes(ROOT,'components')),19)
        self.assertEqual(len(reader.probes(ROOT,'keyless')),2)
        self.assertEqual(len(reader.units()),20)
        self.assertEqual(len(reader.units('keyless')),1)
        self.assertEqual({row['selected'] for row in variants.values()},reader.SELECTED_PRODUCERS)

    def test_sequencer_errors_chain_identifier_and_receiver_expectations_are_explicit(self):
        for kind in ('account_context','momentum_admission','pool_dependencies'):
            body=(ROOT/('compatibility/nom_dev_5cb_'+kind+'_test.go.txt')).read_text('ascii')
            pairs=re.findall(r'([A-Za-z_][A-Za-z0-9_]*), ([A-Za-z_][A-Za-z0-9_]*) := [^\n]+[.]SequencerSize\(\)',body)
            self.assertEqual(len(pairs),1)
            size,error=pairs[0]
            guard=r'if '+re.escape(error)+r' != nil \{\s+t[.]Fatal\("selected memory sequencer size lookup failed", '+re.escape(error)+r'\)\s+\}'
            self.assertTrue(re.search(guard,body),kind+' must refuse the returned size error')
            if kind=='account_context':
                self.assertTrue('i <= '+size+'; i++' in body,'context must bound the mailbox walk by the returned size')
            else:
                self.assertTrue('num('+size+')' in body,kind+' must report the returned size')
        body=(ROOT/'compatibility/nom_dev_5cb_vm_receipt_verifier_test.go.txt').read_text('ascii')
        self.assertIn('ChainIdentifier()',body)
        self.assertIn('parent.ChainIdentifier',body)
        rows=reader.producer_variants(ROOT)['compatibility/nom_vm_path_verifier_test.go.txt']['edits']
        self.assertEqual(len(rows),3)
        # One changed branch runs for both retained legs.
        self.assertEqual(sum('ErrABFromBlockReceiverMismatch' in row['after'] for row in rows),1)

    def test_variant_edit_extra_bytes_and_parent_replacement_refuse(self):
        variants=reader.producer_variants(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            names={reader.VARIANTS}|set(variants)|{row['selected'] for row in variants.values()}
            for name in names:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((ROOT/name).read_bytes())
            parent,row=next(iter(variants.items()));target=root/row['selected']
            original=target.read_bytes()
            for raw in ((root/parent).read_bytes(),original+b'// unselected change\n'):
                target.write_bytes(raw)
                with self.assertRaises(REFUSALS):reader.producer_variants(root)
            target.write_bytes(original)
            (root/parent).write_bytes((root/parent).read_bytes()+b'// unselected parent change\n')
            with self.assertRaises(REFUSALS):reader.producer_variants(root)

    def test_only_four_context_expectations_change_and_chain_69_is_retained(self):
        old=json.loads((ROOT/reader.context.FIXTURE).read_bytes())
        new=reader.context_fixture(ROOT)
        changed={name for name in old['records'] if old['records'][name]!=new['records'][name]}
        self.assertEqual(changed,reader.RECEIVER_IDS)
        for name in changed:
            self.assertEqual(new['records'][name]['block']['chain_id'],'69')
            self.assertEqual(new['records'][name]['checks']['structural'],reader.RECEIVER_ERROR)
            self.assertEqual(new['records'][name]['checks']['transaction'],'ErrABSignatureMissing')
        self.assertNotEqual(reader.context.vectors(),reader.vectors())
        self.assertEqual(reader.context.vectors(),old['vectors'])

    def test_historical_reader_module_and_fixtures_are_not_mutated(self):
        before=copy.deepcopy(reader.context.vectors())
        unused,binding=reader.context_reader(ROOT)
        self.assertEqual(binding['unchanged_function_bodies'],['collect_records','validate_record','validate_records'])
        self.assertFalse(binding['imported_module_mutated'])
        self.assertEqual(reader.context.vectors(),before)
        for kind in reader.AUXILIARY:
            unused,expected,binding,module=reader.auxiliary_reader(kind,ROOT)
            self.assertNotEqual(expected['selected_core_commit'],module.CORE)
            self.assertEqual(binding['unchanged_function_bodies'],['expected_report','report_from_events'])
            self.assertFalse(binding['imported_module_mutated'])

    def test_only_twelve_successful_balance_read_paths_add_a_query(self):
        unused,expected,binding,module=reader.auxiliary_reader('send_caller',ROOT)
        old=module.expected_report()['records'];new=expected['records']
        changed={name for name in old if old[name]!=new[name]}
        self.assertEqual(changed,set(binding['query_count_changes']))
        self.assertEqual(len(changed),12)
        for name in changed:
            row=copy.deepcopy(new[name]);row['dp_reads']-=1
            self.assertEqual(row,old[name])
        self.assertEqual(new['nonembedded_skips_abi']['dp_reads'],0)

    def test_complete_twenty_synthetic_streams_keep_all_authority_gates_open(self):
        result=reader.compare_payloads(self.payloads,ROOT)
        self.assertEqual(result['components']['selected_stateful_outcomes'],342)
        self.assertEqual(result['components']['wire_outcomes'],45)
        self.assertEqual(result['components']['pr138_outcomes'],1)
        self.assertEqual({key:row['cases'] for key,row in result['auxiliary'].items()},reader.AUXILIARY)
        self.assertEqual(result['keyless']['cases'],24)
        self.assertEqual(result['execution_origin'],'NOT_ESTABLISHED_BY_READER')
        self.assertEqual(result['native_execution'],'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['source_build_authentication'],'UNFILLED')
        self.assertEqual(result['complete_account_admission'],'UNFILLED')
        self.assertEqual(result['journal_source_upgrade'],'NOT_SELECTED')
        self.assertEqual(result['independent_assessment'],'UNFILLED')
        self.assertEqual(result['application'],result['core'])
        self.assertEqual(result['core'],'NO-GO')

    def test_component_and_keyless_profiles_require_distinct_exact_stream_sets(self):
        for profile in ('components','keyless'):
            values={name:raw for name,raw in self.payloads.items() if name.rsplit('.',1)[0] in reader.units(profile)}
            result=reader.compare_payloads(values,ROOT,profile)
            self.assertEqual(result['profile'],profile)
            self.assertEqual('keyless' in result,profile=='keyless')
            self.assertEqual('components' in result,profile=='components')

    def test_missing_extra_and_cross_profile_substitution_refuse(self):
        for mode in ('missing','extra','substitute'):
            values=dict(self.payloads)
            if mode=='missing':values.pop('keyless-supervisor.stderr')
            elif mode=='extra':values['unselected.stdout']=b''
            else:values['keyless-supervisor.stdout']=values['supervisor-plasma.stdout']
            with self.subTest(mode=mode),self.assertRaises(REFUSALS):reader.compare_payloads(values,ROOT)

    def test_old_receiver_success_stream_cannot_fill_new_context(self):
        values=dict(self.payloads)
        # This is deliberately manufactured old expected output, not an old run.
        values['account-context.stdout']=self.old_context_stream
        with self.assertRaises(REFUSALS):reader.compare_payloads(values,ROOT,'all')

    def test_nearby_source_counts_and_gate_promotion_cannot_fill_manifest(self):
        manifest=json.loads((ROOT/reader.MANIFEST).read_bytes());original=reader.read_json
        for key,value in (('core_commit',reader.previous.CORE),('core_tree',reader.previous.TREE),
            ('source_files',474),('keyless_cases',23),('combined_admission','PASS'),('application','GO')):
            changed=copy.deepcopy(manifest);changed[key]=value
            def read(path,*args):
                return changed if Path(path)==ROOT/reader.MANIFEST else original(path,*args)
            with self.subTest(key=key),patch.object(reader,'read_json',side_effect=read),self.assertRaises(REFUSALS):
                reader.inputs(ROOT)

    def frame(self,source):
        # Two tiny mocked upstream files and two real producer bytes exercise
        # the walker without repeatedly cloning hundreds of source files.
        index={}
        for name in ('synthetic/one.go','synthetic/two.go'):
            raw=b'// synthetic source frame only\n';path=source/name
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            index[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                git_blob_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
        probes=dict(list(reader.probes(ROOT,'keyless').items()))
        for name,parent in probes.items():
            path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((ROOT/parent).read_bytes())
        return index,probes

    def test_minimal_mock_source_frame_does_not_claim_upstream_authentication(self):
        with tempfile.TemporaryDirectory() as temporary:
            source=Path(temporary).resolve();index,probes=self.frame(source)
            with patch.object(reader,'inputs',return_value=({},index)),patch.object(reader,'probes',return_value=probes):
                result=reader.compare_source(source,ROOT,'keyless')
            self.assertEqual(result['combined_files'],4)
            self.assertEqual(result['upstream_files'],2)
            self.assertEqual(result['producer_authentication'],'NOT_ESTABLISHED_BY_READER')
            self.assertEqual(result['filesystem_mode_equality'],'NOT_ASSERTED')

    def test_missing_changed_extra_directory_link_and_hardlink_refuse(self):
        for mode in ('missing','changed','extra','empty-directory','symlink','hardlink','ancestor-alias','old-producer'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve();source=root/'source';source.mkdir()
                index,probes=self.frame(source);target=source/'synthetic/one.go'
                if mode=='missing':target.unlink()
                elif mode=='changed':target.write_bytes(b'changed\n')
                elif mode=='extra':(source/'extra.txt').write_bytes(b'extra\n')
                elif mode=='empty-directory':(source/'unselected').mkdir()
                elif mode in ('symlink','hardlink'):
                    target.unlink()
                    if mode=='symlink':target.symlink_to(source/'synthetic/two.go')
                    else:os.link(source/'synthetic/two.go',target)
                elif mode=='ancestor-alias':
                    alias=root/'alias';alias.symlink_to(source,target_is_directory=True);source=alias
                else:
                    (source/'vm/research_nom_5cb_keyless_supervisor_test.go').write_bytes(
                        (ROOT/'compatibility/nom_dev_supervisor_plasma_test.go.txt').read_bytes())
                with patch.object(reader,'inputs',return_value=({},index)),patch.object(reader,'probes',return_value=probes):
                    with self.assertRaises(REFUSALS):reader.compare_source(source,ROOT,'keyless')

    def test_reproduction_plan_selects_each_unit_once_without_execution(self):
        plan=reproduction.plan(ROOT)
        self.assertEqual(len(plan['units']),20)
        self.assertEqual(sum(row['parent_and_child_outcomes'] for row in plan['units']),479)
        self.assertEqual(plan['execution'],'NOT_PERFORMED')
        self.assertTrue(plan['normal_default_vet'])
        self.assertEqual(len(plan['producers']),20)
        for row in plan['units']:
            self.assertIn('-count=1',row['arguments'])
            self.assertIn('-mod=readonly',row['arguments'])
            self.assertNotIn('-vet=off',row['arguments'])
            self.assertEqual(row['arguments'][-1],'./'+row['package'])
        self.assertEqual(len(reproduction.plan(ROOT,'keyless')['units']),1)

    def test_reproduction_input_handoffs_use_supplied_vm_and_authorization_records(self):
        context=reproduction.input_bindings('account-context',self.payloads,ROOT)
        self.assertEqual(context['PTLC_NOM_CONTEXT_PLAN']['generated_json']['vectors'],reader.vectors())
        source=context['PTLC_NOM_CONTEXT_SOURCE']['generated_json']
        self.assertEqual(len(source['records']),126)
        self.assertEqual(set(source['patches']),{'long','short'})
        for unit in reader.units():
            values=reproduction.input_bindings(unit,self.payloads,ROOT)
            self.assertIs(type(values),dict)
            for row in values.values():self.assertEqual(len(row),1)
        self.assertEqual(reproduction.input_bindings('keyless-supervisor',root=ROOT),
            {'PTLC_NOM_KEYLESS_ORIGINAL_INPUT':{'repository_file':reader.KEYLESS_INPUT}})
        # Keep the required historical profile validation inside inputs(),
        # while refusing an additional pass just to prepare a keyless binding.
        with patch.object(reproduction.common,'profiles',wraps=reproduction.common.profiles) as profile_checks:
            self.assertEqual(reproduction.input_bindings('keyless-supervisor',root=ROOT),
                {'PTLC_NOM_KEYLESS_ORIGINAL_INPUT':{'repository_file':reader.KEYLESS_INPUT}})
            self.assertEqual(profile_checks.call_count,1)

    def test_reproduction_refuses_missing_or_foreign_handoff_streams(self):
        for unit in ('vm-verifier','account-authorization','account-context'):
            with self.subTest(unit=unit),self.assertRaises(REFUSALS):
                reproduction.input_bindings(unit,{},ROOT)
        for unit in ('vm-verifier','account-context'):
            prior=dict(self.payloads);prior['vm-path.stdout']=prior['vm-verifier.stdout']
            with self.subTest(unit=unit),self.assertRaises(REFUSALS):
                reproduction.input_bindings(unit,prior,ROOT)

    def test_cli_refusal_and_assertion_optimization_do_not_echo_arguments(self):
        for arguments,expected in ((['--unselected-private-control'],b'REFUSED: 5cb finite comparison\n'),
                                   ([],b'5cb comparison requires assertions enabled\n')):
            flags=['-O'] if not arguments else []
            result=subprocess.run([sys.executable,'-B',*flags,'-m','qualification.nom_dev_5cb',*arguments],
                cwd=ROOT,capture_output=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,expected)
