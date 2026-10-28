"""Manufactured retention controls; no Go execution or source-origin evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from qualification import nom_dev_77ba9c7 as selected
from qualification import nom_fee_original_boundary as fee
from scripts import check_nom_77ba9c7_bundle as reader
from scripts import check_nom_77ba9c7_evidence as baseline
from scripts import qualify_nom_77ba9c7_native as native

ROOT = selected.ROOT
REFUSALS = (ValueError,AssertionError,KeyError,TypeError,OSError)


def encoded(value):
    return json.dumps(value,sort_keys=True).encode('ascii')


def write(directory,name,value):
    raw = value if type(value) is bytes else encoded(value)
    path = directory/name
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(raw)
    return dict(bytes=len(raw),sha256=selected.sha(raw))


class TwoStageRetentionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('retention_fee_fixture',
            ROOT/'tests/test_nom_fee_original_boundary.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        value,cls.input_raw,cls.expected_raw = helper.report()
        cls.fee_stream = helper.frames(value)
        cls.comparison = fee.read(cls.fee_stream,cls.input_raw,cls.expected_raw)
        cls.fee_source = reader.expected_fee_source(ROOT)

    def fixture(self,directory):
        source = copy.deepcopy(self.fee_source)
        base_source = dict(core_commit=selected.CORE,combined_files=546,
            reference_fixture_core=selected.FIXTURE_CORE)
        native_pin = write(directory,'native-result.json',dict(source_before=base_source))
        # The base reader's existing responsibilities are outside this test's
        # boundary. This trusted-interface stub supplies no native evidence.
        base = dict(full_attempt=True,files={'native-result.json':native_pin},
            execution_origin='NOT_ESTABLISHED_BY_CHECKER')
        retained = write(directory,'base-stage-retention.json',base)
        commands = {}
        for label,arguments in reader.ARGUMENTS.items():
            stdout = self.fee_stream if label=='fee-original-boundary' else b'all modules verified\n'
            write(directory,'fee-commands/'+label+'.stdout',stdout)
            write(directory,'fee-commands/'+label+'.stderr',b'')
            receipt = dict(schema='ptlc-nom-77ba9c7-native-command-v1',label=label,
                argv=[str(directory/'synthetic-go'),*arguments],automatic_retry=False,
                actual_exit=0,result='RETURNED_ZERO_WITH_COMPLETE_STREAMS',
                bytes={'stdout':len(stdout),'stderr':0},complete={'stdout':True,'stderr':True},
                sha256={'stdout':selected.sha(stdout),'stderr':selected.sha(b'')},
                elapsed_seconds=0.01,cleanup_complete=True)
            write(directory,'fee-commands/'+label+'.receipt.json',receipt)
            commands[label] = {key:receipt[key] for key in (
                'actual_exit','result','bytes','complete','sha256','elapsed_seconds')}
        fee_base = dict(schema='ptlc-nom-77ba9c7-fee-stage-v1',
            core_commit=selected.CORE,core_tree=selected.TREE,
            reference_fixture_core=fee.CORE,reference_fixture_tree=fee.TREE,
            reference_input=dict(bytes=len(self.input_raw),sha256=selected.sha(self.input_raw)),
            reference_expected=dict(bytes=len(self.expected_raw),sha256=selected.sha(self.expected_raw)),
            source_before=source,source_stage=2,compiler_workspace='SAME_LIVE_INVOCATION',
            test_result_cache='DISABLED_BY_COUNT_ONE',normal_default_vet=True,
            automatic_retry=False,new_keys=0,new_signatures=0,
            journal_source_upgrade='NOT_SELECTED',original_replacement='NOT_SELECTED',
            application='NO-GO',core='NO-GO',recovery_action='NONE',independent_assessment='UNFILLED')
        write(directory,'fee-native-intent.json',dict(fee_base,outcome='UNKNOWN',commands={}))
        comparison = write(directory,'fee-value-comparison.json',self.comparison)
        result = dict(fee_base,outcome='PASS_FRESH_NATIVE_FEE_ORIGINAL_REFUSALS_ONLY',
            commands=commands,source_after=source,source_unchanged=True,comparison=comparison,
            actual_native_commands=2,actual_cases=14,outcomes_including_parent=15,
            baseline_originals_unchanged=True,elapsed_seconds=0.5)
        write(directory,'fee-native-result.json',result)
        bundle = dict(schema='ptlc-nom-77ba9c7-two-stage-native-v1',
            outcome='PASS_TWO_FRESH_OFFLINE_NATIVE_STAGES_ONLY',
            core_commit=selected.CORE,core_tree=selected.TREE,
            reference_fixture_core=selected.FIXTURE_CORE,reference_fixture_tree=selected.FIXTURE_TREE,
            embedded_core_labels='UNCHANGED REFERENCE LABELS; NOT COMPILATION INPUT IDENTITIES',
            compiler_workspaces=1,physical_source_views=1,source_stages=2,
            normal_default_vet=True,test_result_cache='DISABLED_BY_COUNT_ONE',automatic_retry=False,
            original_streams_rewritten=False,journal_source_upgrade='NOT_SELECTED',
            application='NO-GO',core='NO-GO',recovery_action='NONE',independent_assessment='UNFILLED',
            baseline_retention=retained,baseline_result=native_pin,
            fee_producer=dict(bytes=(ROOT/fee.DRIVER).stat().st_size,
                sha256=selected.sha((ROOT/fee.DRIVER).read_bytes())),
            baseline_source=base_source,fee_source=source,
            baseline_profiles=34,fee_profiles=1,complete_profiles=35,
            baseline_native_commands=38,fee_native_commands=2,actual_native_commands=40,
            reference_outcomes=642,prior_runtime_outcomes=58,upstream_test_outcomes=41,
            fee_outcomes=15,total_outcomes=756,baseline_originals_unchanged=True,
            source_extractions_performed_by_runner=0,baseline_result_reused=False,
            historical_cache_adopted=False,elapsed_seconds=0.5)
        write(directory,'bundle-native-result.json',bundle)
        return base

    def read(self,directory,base,*,verify_source=False,**kwargs):
        with mock.patch.object(reader.baseline_checker,'inspect',return_value=base):
            if verify_source:
                return reader.inspect(directory,**kwargs)
            # Schema refusal cases share this test-local input. The complete
            # path still invokes the real provider; production stays uncached.
            with mock.patch.object(reader,'expected_fee_source',
                    return_value=copy.deepcopy(self.fee_source)):
                return reader.inspect(directory,**kwargs)

    def change(self,directory,name,mutate):
        value = json.loads((directory/name).read_bytes())
        mutate(value)
        write(directory,name,value)

    def test_complete_manufactured_selection_does_not_establish_execution_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve();base = self.fixture(directory)
            result = self.read(directory,base,verify_source=True)
            self.assertIs(result['full_attempt'],True)
            self.assertEqual(result['native_execution'],'NOT_PERFORMED_BY_CHECKER')
            self.assertEqual(result['execution_origin'],'NOT_ESTABLISHED_BY_CHECKER')
            self.assertEqual(result['application'],'NO-GO')
            self.assertFalse(any(name.endswith('.receipt.json') for name in result['files']))

    def test_missing_bundle_result_stays_unknown_and_preserves_original_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve();base = self.fixture(directory)
            (directory/'bundle-native-result.json').unlink()
            originals = {p.relative_to(directory).as_posix():p.read_bytes()
                for p in directory.rglob('*') if p.is_file()}
            result = self.read(directory,base,allow_incomplete=True)
            self.assertIs(result['full_attempt'],False)
            self.assertEqual(result['outcome'],'INCOMPLETE_RETENTION_ONLY')
            self.assertEqual(originals,{p.relative_to(directory).as_posix():p.read_bytes()
                for p in directory.rglob('*') if p.is_file()})
            with self.assertRaises(REFUSALS):self.read(directory,base)

    def test_missing_receipt_cannot_borrow_the_reported_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve();base = self.fixture(directory)
            (directory/'fee-commands/fee-original-boundary.receipt.json').unlink()
            result = self.read(directory,base,allow_incomplete=True)
            self.assertIs(result['full_attempt'],False)
            self.assertEqual(result['fee_commands']['fee-original-boundary']['result'],
                'UNKNOWN_ORIGINAL_RECEIPT_MISSING')
            self.assertIn('fee-commands/fee-original-boundary.stdout',result['files'])

    def test_reference_relabeling_and_new_authority_fields_refuse(self):
        changes=[('fee-native-result.json',lambda v:v.update(core_commit=selected.FIXTURE_CORE)),
            ('fee-native-result.json',lambda v:v.update(new_signatures=1)),
            ('bundle-native-result.json',lambda v:v.update(new_work_allowed=True)),
            ('fee-native-intent.json',lambda v:v.update(recovery_action='RELEASE'))]
        for name,mutate in changes:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temporary:
                directory=Path(temporary).resolve();base=self.fixture(directory)
                self.change(directory,name,mutate)
                with self.assertRaises(REFUSALS):self.read(directory,base)

    def test_elapsed_fields_are_typed_and_finite(self):
        for name in ('bundle-native-result.json','fee-native-result.json'):
            for value in (True,'0.5',-1,None,float('inf')):
                with self.subTest(name=name,value=value),tempfile.TemporaryDirectory() as temporary:
                    directory=Path(temporary).resolve();base=self.fixture(directory)
                    self.change(directory,name,lambda v:v.update(elapsed_seconds=value))
                    with self.assertRaises(REFUSALS):self.read(directory,base)

    def test_changed_baseline_manifest_prevents_complete_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary).resolve();base=self.fixture(directory)
            self.change(directory,'base-stage-retention.json',lambda v:v.update(full_attempt=False))
            result=self.read(directory,base,allow_incomplete=True)
            self.assertIs(result['full_attempt'],False)
            self.assertIs(result['baseline_manifest_matches'],False)

    def test_failure_flags_refuse_numeric_boolean_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary).resolve();base=self.fixture(directory)
            value=json.loads((directory/'bundle-native-result.json').read_bytes())
            keep={'schema','core_commit','core_tree','reference_fixture_core','reference_fixture_tree',
                'embedded_core_labels','compiler_workspaces','physical_source_views','source_stages',
                'normal_default_vet','test_result_cache','automatic_retry','original_streams_rewritten',
                'journal_source_upgrade','application','core','recovery_action','independent_assessment'}
            failed={key:value[key] for key in keep}
            failed.update(outcome='FAILURE_OR_INCOMPLETE_PRESERVED',exception_type='ValueError',
                fee_producer_appended=1,elapsed_seconds=0.5)
            (directory/'bundle-native-result.json').unlink()
            write(directory,'bundle-native-failure.json',failed)
            with self.assertRaises(REFUSALS):self.read(directory,base,allow_incomplete=True)

    def test_intent_only_baseline_retains_unknown_without_claiming_a_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary).resolve();(directory/'commands').mkdir()
            values=selected.source_payloads()
            source=dict(core_commit=selected.CORE,core_tree=selected.TREE,profile='all',
                upstream_files=521,project_producers=25,combined_files=546,
                snapshot=dict(files=546,sha256=selected.sha(encoded(values))),
                reference_fixture_core=selected.FIXTURE_CORE,
                content='EXACT_SELECTED_CONTENTS; UNCHANGED REFERENCE PRODUCERS',
                filesystem_mode_equality='NOT_ASSERTED',producer_authentication='NOT_ESTABLISHED_BY_READER')
            intent=dict(schema='ptlc-nom-77ba9c7-native-attempt-v1',outcome='UNKNOWN',
                core_commit=selected.CORE,core_tree=selected.TREE,profile='all',source_before=source,
                go_sha256='a'*64,cc_sha256='b'*64,platform_sdk='NOT_SELECTED',
                compiler_identity_scope='MEASURED_EXECUTABLES_ONLY; TRANSITIVE_TOOLCHAIN_NOT_AUTHENTICATED',
                cgo_diagnostic_profile=selected.runtime.DEFAULT_CGO_PROFILE,
                go_source_path_profile='GOFLAGS_TRIMPATH',compiler_workspaces=1,source_views=1,
                selected_commands=34,reference_fixture_core=selected.FIXTURE_CORE,
                reference_fixture_tree=selected.FIXTURE_TREE,embedded_core_labels='REFERENCE_PROGRAM_LABELS_ONLY',
                free_space_floor=native.FLOOR,expected_reservation=native.RESERVATION,
                os_filesystem_quota='NOT_CLAIMED',normal_default_vet=True,
                test_result_cache='DISABLED_BY_COUNT_ONE',commands={},automatic_native_retry=False,
                complete_account_admission='UNFILLED',source_build_authentication='UNFILLED',
                journal_source_upgrade='NOT_SELECTED',application='NO-GO',core='NO-GO',
                independent_assessment='UNFILLED')
            write(directory,'native-intent.json',intent)
            result=baseline.inspect(directory,allow_incomplete=True)
            self.assertIs(result['full_attempt'],False)
            self.assertIs(result['intent_only_outcome_unknown'],True)
            self.assertIn('native-intent.json',result['files'])
            with self.assertRaises(REFUSALS):baseline.inspect(directory)


if __name__=='__main__':unittest.main()
