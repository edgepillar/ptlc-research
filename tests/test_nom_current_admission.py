"""Synthetic stream controls; these fixtures do not supply source execution evidence."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qualification import nom_current_admission as reader

ROOT=Path(__file__).resolve().parents[1]


def synthetic_stream(packages,records=None,*,prefix=None,filename=None,test=None):
    events=[]
    if records is not None:
        package=next(iter(packages))
        for name,record in records.items():
            events.append(dict(Action='output',Package=package,Test=test+'/'+name,
                Output='    '+filename+':1: '+prefix+json.dumps(record)+'\n'))
    for package,names in packages.items():
        events.extend(dict(Action='pass',Package=package,Test=name) for name in sorted(names))
        events.append(dict(Action='pass',Package=package))
    return b''.join(json.dumps(event).encode('ascii')+b'\n' for event in events)


class CurrentAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules,cls.fixtures,cls.selected=reader.profiles(ROOT)
        cls.reference=json.loads((ROOT/reader.REFERENCE).read_bytes())['records']
        cls.records={'vm-path':cls.reference}
        for name,module in cls.modules.items():
            key=name.replace('_','-')
            if name in ('account_pool','pool_dependencies'):
                cls.records[key]=reader.rebase.expected_records(ROOT)[key]
            else:cls.records[key]=cls.fixtures[key]['records']
        # The historical cap fixture stores normalized properties. Reconstruct
        # explicitly synthetic read observations only for this framing control.
        raw_cap=copy.deepcopy(cls.records['content-cap'])
        for row in raw_cap.values():
            properties=row.pop('observation_properties');row['observations']={}
            for label,value in properties.items():
                row['observations'][label]=[dict(all_indices=value['all_admissible_orders']['user-first'],
                    selection_indices=value['selection_admissible_orders']['contract-first'],
                    checkpoint_before_sha256=value['checkpoint_sha256'],checkpoint_after_sha256=value['checkpoint_sha256'],
                    signatures=0) for unused in range(cls.modules['content_cap'].READS)]
        cls.records['content-cap']=raw_cap
        cls.payloads={}
        for unit,packages in cls.selected.items():
            if unit=='vm-path':
                raw=synthetic_stream(packages,cls.reference,prefix=reader.vm.PREFIX,
                    filename='zz_research_nom_vm_path_test.go',test=reader.vm.VM_TEST)
            elif unit in ('pr138-corpus','wire-corpus','vm-verifier'):raw=synthetic_stream(packages)
            else:
                name=unit.replace('-','_');module=cls.modules[name]
                raw=synthetic_stream(packages,cls.records[unit],prefix=module.PREFIX,
                    filename='zz_research_nom_'+name+'_test.go',test=module.TEST)
            cls.payloads[unit+'.stdout']=raw;cls.payloads[unit+'.stderr']=b''

    def refuse_events(self,events,unit='vm-path'):
        raw=b''.join(json.dumps(event).encode('ascii')+b'\n' for event in events)
        with self.assertRaises((ValueError,AssertionError,KeyError,TypeError)):
            reader.event_stream(raw,self.selected[unit])

    def events(self,unit='vm-path'):
        return [json.loads(line) for line in self.payloads[unit+'.stdout'].splitlines()]

    def test_pinned_current_source_and_frozen_producers_are_separate(self):
        manifest,index,reference=reader.inputs(ROOT)
        self.assertEqual(manifest['core_commit'],reader.CORE)
        self.assertEqual(manifest['historical_value_source'],reader.rebase.CORE_COMMIT)
        self.assertEqual(reader.git_tree(index),reader.TREE)
        self.assertEqual(len(reader.probes(ROOT)),16)
        self.assertEqual(reference['scope'],'PUBLIC_SYNTHETIC_REFERENCE_VALUES; NOT EXECUTION EVIDENCE')

    def test_complete_synthetic_values_keep_execution_and_recovery_unfilled(self):
        result=reader.compare_payloads(self.payloads,ROOT)
        self.assertEqual(result['selected_stateful_outcomes'],342)
        self.assertEqual(result['wire_outcomes'],45)
        self.assertEqual(result['pr138_outcomes'],1)
        self.assertEqual(len(result['profiles']),16)
        self.assertEqual(result['execution_origin'],'NOT_ESTABLISHED_BY_THIS_READER')
        self.assertEqual(result['native_execution'],'NOT_PERFORMED_BY_READER')
        for key in ('combined_admission','inclusion_before_timeout','source_authentication','durable_custody','independent_assessment'):
            self.assertEqual(result[key],'UNFILLED')
        self.assertEqual(result['journal_source_upgrade'],'NOT_SELECTED')
        self.assertEqual(result['application'],result['core'])
        self.assertEqual(result['core'],'NO-GO')
        self.assertTrue(all(row['actual_command_exit']=='NOT_ESTABLISHED_BY_THIS_READER' for row in result['profiles'].values()))

    def test_each_profile_requires_its_exact_parent_and_children(self):
        for unit,packages in self.selected.items():
            with self.subTest(unit=unit):
                result=reader.event_stream(self.payloads[unit+'.stdout'],packages)
                self.assertEqual(result['passed_including_parent'],reader.COUNTS[unit])

    def test_missing_and_duplicate_test_outcomes_refuse(self):
        events=self.events();position=next(i for i,row in enumerate(events) if row['Action']=='pass' and 'Test' in row)
        self.refuse_events(events[:position]+events[position+1:])
        self.refuse_events([*events,events[position]])

    def test_missing_and_duplicate_package_terminal_refuse(self):
        events=self.events();self.refuse_events(events[:-1]);self.refuse_events([*events,events[-1]])

    def test_skip_fail_and_unselected_test_refuse(self):
        for action in ('skip','fail'):
            events=self.events();next(row for row in events if row['Action']=='pass' and 'Test' in row)['Action']=action
            self.refuse_events(events)
        events=self.events();events[0]['Test']='UnselectedTest';self.refuse_events(events)

    def test_unknown_package_and_unknown_event_fields_refuse(self):
        for name,value in (('Package','unselected/package'),('authority',True),('Action','authorized')):
            events=self.events();events[0][name]=value;self.refuse_events(events)

    def test_event_types_and_nonfinite_elapsed_refuse(self):
        for name,value in (('Action',False),('Test',False),('Output',False),('Time',True),('Elapsed',True),('Elapsed',-1),('Elapsed',float('nan'))):
            events=self.events();events[0][name]=value;self.refuse_events(events)

    def test_duplicate_outer_json_keys_refuse(self):
        raw=self.payloads['vm-path.stdout'];first,rest=raw.split(b'\n',1)
        changed=first.replace(b'{',b'{"Action":"pass",',1)+b'\n'+rest
        with self.assertRaises(ValueError):reader.event_stream(changed,self.selected['vm-path'])

    def test_empty_wrong_type_and_truncated_stream_refuse(self):
        for raw in (b'',None,False,'stream',bytearray(b'{}'),self.payloads['vm-path.stdout'][:-2],b'[]\n'):
            with self.subTest(kind=type(raw).__name__),self.assertRaises((ValueError,TypeError)):
                reader.event_stream(raw,self.selected['vm-path'])

    def test_stdout_bound_refuses_before_json_decoding(self):
        with self.assertRaises(ValueError):reader.event_stream(b' '*(reader.MAX_STDOUT+1),self.selected['vm-path'])

    def test_missing_stderr_and_extra_streams_cannot_be_filled(self):
        for mode in ('missing','extra'):
            changed=dict(self.payloads)
            if mode=='missing':changed.pop('vm-path.stderr')
            else:changed['unselected.stdout']=b''
            with self.assertRaises(ValueError):reader.compare_payloads(changed,ROOT)

    def test_cross_profile_substitution_refuses(self):
        changed=dict(self.payloads);changed['vm-path.stdout']=changed['vm-verifier.stdout']
        with self.assertRaises(ValueError):reader.compare_payloads(changed,ROOT)

    def test_vm_patch_substitution_cannot_satisfy_account_context(self):
        changed_records=copy.deepcopy(self.reference)
        changed_records['long-direct-success']['receipt_patches']['after_hex']='00000001'
        changed=dict(self.payloads)
        changed['vm-path.stdout']=synthetic_stream(self.selected['vm-path'],changed_records,
            prefix=reader.vm.PREFIX,filename='zz_research_nom_vm_path_test.go',test=reader.vm.VM_TEST)
        with self.assertRaises((ValueError,AssertionError)):reader.compare_payloads(changed,ROOT)

    def test_historical_pool_projection_is_not_the_selected_value_set(self):
        unit='account-pool';module=self.modules['account_pool']
        old=module.inputs(ROOT)[1]['records']
        raw=synthetic_stream(self.selected[unit],old,prefix=module.PREFIX,
            filename='zz_research_nom_account_pool_test.go',test=module.TEST)
        with self.assertRaises(ValueError):
            reader.rebase.exact(reader.rebase.expected_records(ROOT)[unit],reader.rebase.native_records(unit,raw))

    def test_partial_source_and_unexpected_source_content_refuse(self):
        for mode in ('missing','unexpected','changed'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                source=Path(temporary).resolve()
                if mode!='missing':(source/('go.mod' if mode=='changed' else 'unselected.txt')).write_bytes(b'synthetic source\n')
                with self.assertRaises(ValueError):reader.compare_source(source,ROOT)

    def test_source_and_ancestor_links_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary).resolve();target=parent/'target';target.mkdir()
            alias=parent/'alias';alias.symlink_to(target,target_is_directory=True)
            with self.assertRaises(ValueError):reader.compare_source(alias,ROOT)
            with self.assertRaises(ValueError):reader.physical(alias/'missing')

    def test_hard_linked_input_refuses(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary).resolve();source=parent/'source';source.write_bytes(b'synthetic bytes')
            os.link(source,parent/'second')
            with self.assertRaises(ValueError):reader.regular(source,1024)

    def test_input_bounds_and_nonfinite_json_refuse(self):
        for raw in (b'',b'{}'*1024,b'{"value":NaN}',b'{"key":1,"key":2}',b'[]{}'):
            with self.assertRaises(ValueError):reader.decoded(raw,1024)

    def test_stream_directory_requires_exact_registered_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary).resolve()
            with self.assertRaises(ValueError):reader.load_payloads(parent)
            for name in self.payloads:(parent/name).write_bytes(b'')
            (parent/'unselected.txt').write_bytes(b'')
            with self.assertRaises(ValueError):reader.load_payloads(parent)

    def test_manifest_reference_pin_matches_public_synthetic_values(self):
        manifest,unused_index,reference=reader.inputs(ROOT)
        self.assertEqual(hashlib.sha256((ROOT/reader.REFERENCE).read_bytes()).hexdigest(),manifest['input_sha256'][reader.REFERENCE])
        self.assertEqual(reference['records'],self.reference)

    def test_cli_refusal_does_not_echo_unselected_arguments(self):
        result=subprocess.run([sys.executable,'-B','-m','qualification.nom_current_admission','--unselected-private-control'],
            cwd=ROOT,capture_output=True,timeout=30)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'REFUSED: current admission component comparison\n')

    def test_optimized_execution_refuses_before_reading_inputs(self):
        result=subprocess.run([sys.executable,'-B','-O','-m','qualification.nom_current_admission'],
            cwd=ROOT,capture_output=True,timeout=30)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'current admission comparison requires assertions enabled\n')
