"""Joint selection and synthetic transport controls; no current node execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_dev_5a2593 as reader
from scripts import check_nom_5a2593_evidence as retention
from scripts import nom_5a2593_command as capture
from scripts import prepare_nom_5a2593 as preparation

ROOT = reader.ROOT
REFUSALS = (AssertionError,ValueError,KeyError,TypeError,OSError)


def load(name):
    spec = importlib.util.spec_from_file_location('joint_current_control_'+name,
        ROOT / 'tests' / ('test_'+name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CurrentCombinedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        legacy = load('nom_dev_5a2593_legacy')
        legacy.CurrentLegacyTests.setUpClass()
        cls.legacy = legacy.CurrentLegacyTests
        cls.payloads = dict(cls.legacy.payloads)
        new = load('nom_dev_5a2593_reclaim')
        cls.payloads[reader.reclaim.UNIT+'.stdout'] = new.encoded(new.events(reader.reclaim.expected_report()))
        cls.payloads[reader.reclaim.UNIT+'.stderr'] = b''

    def test_joint_plan_preserves_every_legacy_command_and_adds_one_complete_profile(self):
        manifest,index = reader.inputs(ROOT)
        plan = reader.plan(ROOT)
        old = reader.legacy.prior_reproduction.plan(ROOT)
        self.assertEqual((len(index),len(plan['producers'])),(500,21))
        self.assertEqual(plan['units'][:-1],old['units'])
        self.assertEqual(len(plan['units']),21)
        self.assertEqual(sum(row['parent_and_child_outcomes'] for row in plan['units']),556)
        self.assertEqual((plan['core_commit'],plan['core_tree']),(reader.CORE,reader.TREE))
        self.assertEqual((manifest['actual_native_commands'],manifest['complete_original_profile_streams']),(25,42))
        self.assertEqual(plan['execution'],'NOT_PERFORMED')
        self.assertEqual(plan['journal_source_upgrade'],'NOT_SELECTED')
        last = plan['units'][-1]
        self.assertEqual((last['unit'],last['parent_and_child_outcomes']),(reader.reclaim.UNIT,77))
        self.assertEqual(last['prior_streams_required'],[])
        self.assertIn('-count=1',last['arguments'])
        self.assertIn('-mod=readonly',last['arguments'])
        self.assertNotIn('-vet=off',last['arguments'])

    def test_input_selection_keeps_expected_values_out_of_the_new_producer(self):
        self.assertEqual(reader.input_bindings(reader.reclaim.UNIT,root=ROOT),
            {'PTLC_NOM_RECLAIM_CURRENT_INPUT':{'repository_file':reader.reclaim.INPUT}})
        self.assertNotIn(reader.reclaim.VALUES,json.dumps(reader.input_bindings(reader.reclaim.UNIT,root=ROOT)))
        self.assertEqual(reader.input_bindings('keyless-supervisor',root=ROOT),
            {'PTLC_NOM_KEYLESS_ORIGINAL_INPUT':{'repository_file':reader.legacy.KEYLESS_INPUT}})
        with self.assertRaises(KeyError):
            reader.input_bindings('vm-verifier',root=ROOT)
        with self.assertRaises(REFUSALS):
            reader.input_bindings('unselected-profile',root=ROOT)

    def test_all_manufactured_streams_compare_values_without_authenticating_a_run(self):
        result = reader.compare_payloads(self.payloads,ROOT)
        self.assertEqual(result['outcome'],'PASS_SELECTED_FINITE_VALUES_ONLY')
        self.assertEqual((result['complete_profiles'],result['selected_parent_and_child_outcomes'],
            result['complete_original_profile_streams']),(21,556,42))
        self.assertEqual(result['legacy']['outcome'],'PASS_SELECTED_LEGACY_VALUES_ONLY')
        self.assertEqual(result['reclaim']['reclaim_outcomes'],77)
        self.assertEqual(result['reclaim']['stdout']['passed_including_parent'],77)
        self.assertEqual(result['native_execution'],'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['execution_origin'],'NOT_ESTABLISHED_BY_READER')
        self.assertEqual((result['application'],result['core'],result['recovery_action']),('NO-GO','NO-GO','NONE'))
        self.assertFalse(result['historical_results_reclassified'])
        self.assertLess(len(json.dumps(result,sort_keys=True).encode('ascii')),2*1024**2)

    def test_missing_reclaim_old_source_and_foreign_streams_cannot_fill_joint_scope(self):
        for mode in ('legacy_only','reclaim_only','missing_stderr','extra','old_source','foreign'):
            payloads = dict(self.payloads)
            if mode == 'legacy_only':
                payloads = {key:value for key,value in payloads.items() if not key.startswith(reader.reclaim.UNIT+'.')}
            elif mode == 'reclaim_only':
                payloads = {key:value for key,value in payloads.items() if key.startswith(reader.reclaim.UNIT+'.')}
            elif mode == 'missing_stderr':
                payloads.pop(reader.reclaim.UNIT+'.stderr')
            elif mode == 'extra':
                payloads['unselected.stdout'] = b''
            elif mode == 'old_source':
                payloads.update(self.legacy.old_payloads)
            else:
                payloads[reader.reclaim.UNIT+'.stdout'] = payloads['wire-corpus.stdout']
            with self.subTest(mode=mode),self.assertRaises(REFUSALS):
                reader.compare_payloads(payloads,ROOT)
        for partial in ('components','keyless','reclaim'):
            with self.subTest(profile=partial),self.assertRaises(REFUSALS):
                reader.compare_payloads(self.payloads,ROOT,partial)

    def test_nearby_source_wrong_counts_and_gate_promotions_refuse(self):
        original = reader.read_json
        manifest = original(ROOT / reader.MANIFEST)
        for key,value in (('core_commit',reader.legacy.prior.CORE),('complete_profiles',20),
            ('selected_parent_and_child_outcomes',479),('actual_native_commands',24),
            ('complete_original_profile_streams',40),('application','GO'),
            ('historical_results_reclassified',True),('journal_source_upgrade','SELECTED')):
            changed = copy.deepcopy(manifest)
            changed[key] = value
            def read(path):
                return changed if Path(path) == ROOT / reader.MANIFEST else original(path)
            with self.subTest(key=key),patch.object(reader,'read_json',side_effect=read),self.assertRaises(REFUSALS):
                reader.inputs(ROOT)

    def test_self_repinning_unplanned_transport_logic_does_not_prove_descent(self):
        manifest = reader.read_json(ROOT / reader.MANIFEST)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            names = {reader.MANIFEST} | set(reader.TRANSPORT_PINS) | {
                name.replace('5cb','5a2593') for name in reader.TRANSPORT_PINS}
            for name in names:
                target = root / name
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            self.assertEqual(reader.transport_variants(root),manifest['transport_variants'])
            parent = 'scripts/nom_5cb_command.py'
            selected = root / manifest['transport_variants'][parent]['selected']
            selected.write_bytes(selected.read_bytes()+b'\nUNSELECTED_LOGIC = True\n')
            manifest['transport_variants'][parent]['selected_sha256'] = reader.sha(selected.read_bytes())
            (root / reader.MANIFEST).write_text(json.dumps(manifest,sort_keys=True),encoding='ascii')
            with self.assertRaises(REFUSALS):
                reader.transport_variants(root)

    def test_retention_requires_the_new_label_and_preparation_refuses_old_archive_width(self):
        expected = retention.expected_arguments(ROOT)
        self.assertEqual(len(expected),25)
        self.assertEqual(set(expected),capture.LABELS)
        self.assertIn(reader.reclaim.UNIT,expected)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive,destination = root/'wrong-width.zip',root/'new-source'
            archive.write_bytes(b'x'*1941926)
            digest = reader.sha(archive.read_bytes())
            with self.assertRaises(REFUSALS):
                preparation.prepare(archive,destination,root=ROOT)
            self.assertFalse(destination.exists())
            self.assertEqual(reader.sha(archive.read_bytes()),digest)

    def test_synthetic_python_transport_retains_exact_bytes_under_new_label(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            receipt = capture.run([sys.executable,'-B','-c',
                'import sys; sys.stdout.write("synthetic transport control\\n"); sys.stderr.write("synthetic notice\\n")'],
                environment={'PATH':os.defpath},directory=root,evidence=root,
                label=reader.reclaim.UNIT,timeout=5)
            self.assertEqual(receipt['schema'],'ptlc-nom-5a2593-native-command-v1')
            self.assertEqual(receipt['actual_exit'],0)
            self.assertEqual(receipt['complete'],{'stdout':True,'stderr':True})
            self.assertFalse(receipt['automatic_retry'])
            for suffix,raw in (('stdout',b'synthetic transport control\n'),('stderr',b'synthetic notice\n')):
                self.assertEqual((root/(reader.reclaim.UNIT+'.'+suffix)).read_bytes(),raw)
                self.assertEqual(receipt['sha256'][suffix],reader.sha(raw))
            self.assertEqual(receipt['argv'][0],sys.executable)

    def test_failed_transport_keeps_original_exit_and_duplicate_label_cannot_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            command = [sys.executable,'-B','-c','raise SystemExit(7)']
            kwargs = dict(environment={'PATH':os.defpath},directory=root,evidence=root,
                label=reader.reclaim.UNIT,timeout=5)
            with self.assertRaises(capture.WorkerError):
                capture.run(command,**kwargs)
            originals = {path.name:path.read_bytes() for path in root.iterdir()}
            receipt = json.loads(originals[reader.reclaim.UNIT+'.receipt.json'])
            self.assertEqual(receipt['actual_exit'],7)
            self.assertEqual(receipt['result'],'FAILURE_OR_INCOMPLETE')
            self.assertFalse(receipt['automatic_retry'])
            with self.assertRaises(capture.WorkerError):
                capture.run(command,**kwargs)
            self.assertEqual({path.name:path.read_bytes() for path in root.iterdir()},originals)


if __name__ == '__main__':
    unittest.main()
