"""Actual process exits with a named fixture worker, not cryptographic proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from offline_session import nom_recovery as base
from offline_session.nom_verifier import NomPublicVerifier
from scripts import qualify_nom_signed_process_cuts as profile
from scripts.nom_signed_process_evidence import inspect,check_report,decode,canonical,names,selected_artifact_names
from nom_signed_process_frames import mutations

ROOT=Path(__file__).resolve().parents[1]


class SignedProcessCutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup)
        cls.directory=Path(cls.temp.name);cls.directory.chmod(0o700)
        terms=json.loads((ROOT/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())['terms']
        completions=json.loads((ROOT/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())
        builder=NomPublicVerifier.__new__(NomPublicVerifier);builder._terms=terms;builder._pair=completions['pair']
        builder.context_digest_hex=base.verification_context_digest(terms,completions['pair'])
        selected={}
        for mode in ('verify-pair','verify-short','recover-long','verify-long'):
            signature='' if mode=='verify-pair' else completions[('short' if mode in ('verify-short','recover-long') else 'long')+'_signature_hex']
            wire=canonical(builder.request(mode,signature))
            output=canonical(dict(schema='ptlc-nom-public-verification-result-v1',request_digest_hex=hashlib.sha256(wire).hexdigest(),
                valid=True,completed_long_hex=completions['long_signature_hex'] if mode=='recover-long' else ''))
            selected[wire.hex()]=output.hex()
        cls.worker=cls.directory/'fixture-worker.py'
        cls.worker.with_suffix('.json').write_bytes(canonical(selected))
        cls.worker.write_text('#!'+str(Path(sys.executable).resolve())+'\n'+'''# Disclosed exact public fixture oracle; no signature mathematics.
import json
from pathlib import Path
import sys
request=sys.stdin.buffer.read(8193)
answer=json.loads(Path(__file__).with_suffix('.json').read_bytes()).get(request.hex())
if answer is None:raise SystemExit(2)
sys.stdout.buffer.write(bytes.fromhex(answer))
''','ascii')
        cls.worker.chmod(0o700);cls.pin=hashlib.sha256(cls.worker.read_bytes()).hexdigest()
        cls.evidence=cls.directory/'evidence';cls.evidence.mkdir(mode=0o700)
        cls.report=profile.qualify(ROOT,ROOT/'scripts/nom_signed_process_actor.py',cls.worker,cls.pin,cls.evidence)
        profile.retain_manifest(cls.evidence,cls.report,None)
        cls.payloads={name:(cls.evidence/name).read_bytes() for name in names()}

    def test_actual_self_exit_receipts_and_reopen_preserve_charges(self):
        self.assertEqual([row['actor_exit'] for row in self.report['cases']],[72]*6)
        self.assertTrue(all(row['actor_complete'] for row in self.report['cases']))
        self.assertEqual([row['charge'] for row in self.report['cases']],[0,1,1,1,1,1])

    def test_public_diagnostic_is_absent_from_reply_cut_journal(self):
        row=self.report['cases'][2]
        self.assertTrue(row['diagnostic_result_present']);self.assertFalse(row['completion_present'])
        self.assertNotIn(b'"kind":"signed-recovered"',self.payloads['after-public-reply/journal.log'])

    def test_separate_long_original_stays_absent_until_supplied(self):
        self.assertEqual([row['signed_long_present'] for row in self.report['cases']],[False]*4+[True]*2)
        self.assertTrue(self.report['cases'][3]['completion_present'])
        self.assertNotIn(b'"leg":"long","wire_hex"',self.payloads['after-signed-recovered/journal.log'])

    def test_reopen_and_unknown_retry_do_not_reenter_fixture_recovery(self):
        self.assertEqual(self.report['actor_worker_calls'],21)
        self.assertEqual(self.report['reopen_worker_calls'],17)
        self.assertEqual(self.report['additional_recovery_entries_on_reopen_or_retry'],0)
        self.assertTrue(all(row['reopen_recovery_entries']==0 for row in self.report['cases']))
        self.assertTrue(all(self.report['cases'][i]['unknown_retry_refused'] for i in (1,2)))

    def test_unknown_handoff_is_durable_before_exact_output(self):
        row=self.report['cases'][5]
        self.assertEqual(row['attempts'],{'long':1});self.assertEqual(row['long_phase'],'OUTCOME_UNKNOWN')
        self.assertEqual(decode(self.payloads['after-signed-attempt/journal.log'].splitlines()[-1])['event']['kind'],'signed-attempt')

    def test_manifest_selects_191_known_files_and_exact_content(self):
        manifest=decode((self.evidence/'retention-manifest.json').read_bytes())
        self.assertTrue(manifest['originals_complete']);self.assertIsNone(manifest['subject_commit'])
        self.assertEqual(set(manifest['files']),set(names())|{'qualification-result.json'})
        for name,pin in manifest['files'].items():
            raw=(self.evidence/name).read_bytes()
            self.assertEqual(pin,dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
        self.assertEqual(len(manifest['files'])+1,191)

    def test_configuration_omits_runtime_paths_and_environment(self):
        for cut in profile.CUTS:
            selected=decode(self.payloads[cut+'/configuration-before-spawn.json'])
            self.assertEqual(set(selected),{'schema','cut','source_input_sha256','actor_sha256','python_sha256','worker_sha256'})
        private=str(self.directory).encode('ascii')
        self.assertTrue(all(private not in raw for raw in self.payloads.values()))
        self.assertTrue(all(not Path(name).is_absolute() for name in names()))

    def test_original_reader_refuses_18_adverse_frame_sets(self):
        controls=mutations(self.payloads,ROOT);self.assertEqual(len(controls),18)
        for label,payload in controls:
            with self.subTest(label=label),self.assertRaises((ValueError,TypeError,KeyError,AssertionError)):
                inspect(payload,self.report,ROOT)

    def test_report_reader_refuses_13_false_summary_claims(self):
        controls=[(('cases',),self.report['cases'][:-1]),(('cases',2,'cut'),profile.CUTS[1]),
            (('cases',1,'charge'),True),(('cases',2,'actor_recovery_entries'),True),
            (('cases',2,'completion_present'),True),(('cases',3,'signed_long_present'),True),
            (('cases',1,'unknown_retry_refused'),False),(('cases',2,'reopen_recovery_entries'),1),
            (('cases',5,'long_phase'),'ORIGINAL_RETAINED'),(('cases',5,'attempts','long'),True),
            (('original_files',),names()[:-1]),(('power_loss',),'VERIFIED'),(('independent_assessment',),'PASS')]
        for path,value in controls:
            report=copy.deepcopy(self.report);target=report
            for key in path[:-1]:target=target[key]
            target[path[-1]]=value
            with self.subTest(path=path),self.assertRaises((ValueError,TypeError,KeyError,AssertionError)):
                check_report(report)

    def test_pure_original_reader_uses_no_journal_apply_or_process(self):
        with (patch('offline_session.nom_signed_recovery.SignedNomRecoveryCandidate._apply',side_effect=AssertionError('replay forbidden')),
                patch('subprocess.Popen',side_effect=AssertionError('spawn forbidden'))):
            selected=inspect(self.payloads,self.report,ROOT)
        self.assertFalse(selected['journal_apply_method_used']);self.assertEqual(selected['additional_native_execution'],0)

    def test_optimized_cli_refuses_before_evidence_access(self):
        nonexistent=self.directory/'must-not-exist'
        result=subprocess.run([sys.executable,'-B','-O',str(ROOT/'scripts/qualify_nom_signed_process_cuts.py'),
            '--executable',str(nonexistent),'--expect-executable-sha256','00'*32,'--evidence',str(nonexistent)],
            cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(result.returncode,1);self.assertIn(b'assertions enabled',result.stderr)
        self.assertFalse(nonexistent.exists())

    def test_wrong_worker_pin_refuses_before_actor_or_evidence_write(self):
        evidence=self.directory/'wrong-worker';evidence.mkdir(mode=0o700)
        with patch('subprocess.Popen',side_effect=AssertionError('spawn forbidden')):
            with self.assertRaises((ValueError,AssertionError)):
                profile.qualify(ROOT,ROOT/'scripts/nom_signed_process_actor.py',self.worker,'00'*32,evidence)
        self.assertEqual(list(evidence.iterdir()),[])

    def test_stale_subject_cannot_bind_new_sources(self):
        with self.assertRaises(ValueError):profile.verify_subject('35298ee88478f04fd62a976deab1900fd0588215')

    def test_failed_partial_manifest_retains_original_without_success(self):
        evidence=self.directory/'partial';evidence.mkdir(mode=0o700)
        raw=b'{"selected":"incomplete"}'
        (evidence/'subject-before-first-spawn.json').write_bytes(raw)
        report=dict(schema='ptlc-nom-signed-process-cuts-v1',outcome='FAILED_OR_INCOMPLETE',
            actual_worker_count='NOT_QUALIFIED',application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
        profile.retain_manifest(evidence,report,None)
        manifest=decode((evidence/'retention-manifest.json').read_bytes())
        self.assertFalse(manifest['originals_complete']);self.assertEqual(manifest['qualification_outcome'],'FAILED_OR_INCOMPLETE')
        self.assertEqual((evidence/'subject-before-first-spawn.json').read_bytes(),raw)

    def test_existing_evidence_is_refused_without_modification(self):
        before={name:(self.evidence/name).read_bytes() for name in ('qualification-result.json','retention-manifest.json')}
        with self.assertRaises(AssertionError):profile.qualify(ROOT,ROOT/'scripts/nom_signed_process_actor.py',self.worker,self.pin,self.evidence)
        self.assertEqual(before,{name:(self.evidence/name).read_bytes() for name in before})

    def test_duplicate_and_nonfinite_json_are_refused(self):
        for raw in (b'{"number":1,"number":2}',b'{"value":NaN}',b'{"value":Infinity}'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):decode(raw)

    def test_artifact_selector_uses_only_191_relative_manifest_members(self):
        unknown=self.evidence/'unselected-file';unknown.write_bytes(b'held outside the selected artifact')
        try:selected=selected_artifact_names(self.evidence,ROOT)
        finally:unknown.unlink()
        self.assertEqual(set(selected),set(names())|{'qualification-result.json','retention-manifest.json'})
        self.assertEqual(len(selected),191);self.assertTrue(all(not Path(name).is_absolute() for name in selected))

    def test_partial_artifact_selection_keeps_explicit_failure(self):
        evidence=self.directory/'partial-selection';evidence.mkdir(mode=0o700)
        report=dict(schema='ptlc-nom-signed-process-cuts-v1',outcome='FAILED_OR_INCOMPLETE',
            actual_worker_count='NOT_QUALIFIED',application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
        profile.retain_manifest(evidence,report,None)
        self.assertEqual(selected_artifact_names(evidence,ROOT),['qualification-result.json','retention-manifest.json'])

    def test_artifact_selector_refuses_private_shaped_content_even_with_rebound_digest(self):
        evidence=self.directory/'private-control';evidence.mkdir(mode=0o700)
        report=dict(schema='ptlc-nom-signed-process-cuts-v1',outcome='FAILED_OR_INCOMPLETE',
            actual_worker_count='NOT_QUALIFIED',application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
        profile.retain_manifest(evidence,report,None)
        report_path=evidence/'qualification-result.json';value=decode(report_path.read_bytes())
        value['private_control']='/'+'Users'+'/'+'synthetic-owner'+'/'+'file'
        raw=canonical(value);report_path.write_bytes(raw)
        manifest_path=evidence/'retention-manifest.json';manifest=decode(manifest_path.read_bytes())
        manifest['files']['qualification-result.json']=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        manifest_path.write_bytes(canonical(manifest))
        with self.assertRaises(ValueError):selected_artifact_names(evidence,ROOT)

    def test_optimized_actor_refuses_before_configuration_access(self):
        result=subprocess.run([sys.executable,'-B','-O',str(ROOT/'scripts/nom_signed_process_actor.py')],
            cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(result.returncode,1);self.assertIn(b'assertions enabled',result.stderr)

    def test_changed_actor_source_map_refuses_before_import_and_native_execution(self):
        evidence=self.directory/'source-control';evidence.mkdir(mode=0o700)
        value=decode(self.payloads['after-signed-short/configuration-before-spawn.json'])
        value['source_input_sha256']['offline_session/nom_signed_recovery.py']='00'*32
        configuration=self.directory/'source-control.json';configuration.write_bytes(canonical(value))
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/nom_signed_process_actor.py'),
            '--source-root',str(ROOT),'--directory',str(evidence),'--executable',str(self.worker),
            '--configuration',str(configuration)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(result.returncode,1);self.assertEqual(list(evidence.iterdir()),[])
        self.assertEqual(result.stderr,b'FAIL: signed process-cut actor; preserve all originals\n')


if __name__=='__main__':unittest.main()
