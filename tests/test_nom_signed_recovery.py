"""Actual candidate journals with named fixture oracles, not live-chain proof."""
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import nom_recovery as base
from offline_session.nom_signed_recovery import SignedNomRecoveryCandidate, CONTEXT_SCHEMA
from scripts.nom_signed_corpus import SourceCorpusAllowlist, signed_observation
from nom_signed_fixture_oracle import FixturePublicMath

ROOT = Path(__file__).resolve().parents[1]
INPUTS = json.loads((ROOT/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())
TERMS = INPUTS['terms']
COMPLETIONS = json.loads((ROOT/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())
PAIR = COMPLETIONS['pair']


class SignedRecoveryCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.records = json.loads((ROOT/'compatibility/fixtures/nom_signed_originals_v1.json').read_bytes())
        self.selection = dict(schema=CONTEXT_SCHEMA,
            source_commit='137fc528f10ad1ac37ca6d9c4f90ed4b9ee8e598',
            source_tree='1897e82296a7cc0d558a39d00398840495638bfd',
            corpus_sha256=hashlib.sha256(json.dumps(self.records,sort_keys=True).encode('ascii')).hexdigest(),
            contract_hex=self.records['long-original']['block']['to_address_hex'])
        self.oracle = SourceCorpusAllowlist(TERMS, PAIR, self.selection, self.records)
        self.math = FixturePublicMath(TERMS, COMPLETIONS)
        self.short = bytes.fromhex(self.records['short-original']['wire_hex'])
        self.long = bytes.fromhex(self.records['long-original']['wire_hex'])
        self.allowed = {self.proof(leg,'funded') for leg in ('long','short')}
        self.allowed |= {self.proof('short',kind,self.short) for kind in ('unseen','send-confirmed','unlock-confirmed')}

    def proof(self, leg, kind, raw=None):
        return signed_observation(TERMS, COMPLETIONS, self.oracle, leg, kind, raw)

    def open(self, role='bob', observer=None, hook=None, name=None, selection=None, oracle=None):
        path = self.root/(name or role+'.log')
        store = SignedNomRecoveryCandidate.open(path, TERMS, PAIR, role=role, verifier=self.math,
            raw_verifier=self.oracle if oracle is None else oracle,
            observation_verifier=(lambda wire:wire in self.allowed) if observer is None else observer,
            selection=self.selection if selection is None else selection, hook=hook)
        self.addCleanup(store.close)
        return store

    def fund(self, store):
        for leg in ('long','short'): store.record_signed_observation(self.proof(leg,'funded'))

    def recover(self, store):
        return store.recover_long_completion(self.short,self.proof('short','unlock-confirmed',self.short))

    def test_completion_and_real_long_original_are_separate_across_reopen(self):
        store=self.open(); self.fund(store)
        self.assertEqual(self.recover(store),COMPLETIONS['long_signature_hex'])
        self.assertNotIn('long',store.status()['signed_originals'])
        self.assertNotIn('long',store.status()['synthetic_reference_derivatives']['owned'])
        with self.assertRaises(base.RecoveryError): store.prepare_signed_attempt('long')
        store.close(); store=self.open()
        self.assertEqual(store.status()['long_completion_hex'],COMPLETIONS['long_signature_hex'])
        self.assertNotIn('long',store.status()['signed_originals'])
        store.retain_signed_original('long',self.long)
        self.assertEqual(store.prepare_signed_attempt('long'),self.long)
        self.assertEqual(store.status()['phases']['long'],'OUTCOME_UNKNOWN')
        store.close(); store=self.open()
        self.assertEqual(store.prepare_signed_attempt('long'),self.long)
        self.assertEqual(self.recover(store),COMPLETIONS['long_signature_hex'])
        self.assertEqual(self.math.recovery_entries,1)

    def test_same_node_hash_different_bytes_cannot_replace_the_selected_original(self):
        store=self.open('alice'); store.retain_signed_original('short',self.short)
        alias=bytes.fromhex(self.records['short-unknown-protobuf-field']['wire_hex'])
        self.assertNotEqual(alias,self.short)
        self.assertEqual(self.records['short-original']['hash_hex'],self.records['short-unknown-protobuf-field']['hash_hex'])
        before=(self.root/'alice.log').read_bytes(); calls=self.oracle.calls
        with self.assertRaises(base.RecoveryError): store.retain_signed_original('short',alias)
        self.assertEqual((self.root/'alice.log').read_bytes(),before)
        self.assertEqual(self.oracle.calls,calls)
        self.assertEqual(bytes.fromhex(store.status()['signed_originals']['short']['wire_hex']),self.short)

    def test_long_signed_original_cannot_precede_public_completion(self):
        store=self.open(); before=(self.root/'bob.log').read_bytes(); calls=self.oracle.calls
        with self.assertRaises(base.RecoveryError): store.retain_signed_original('long',self.long)
        self.assertEqual((self.root/'bob.log').read_bytes(),before)
        self.assertEqual(self.oracle.calls,calls)

    def test_changed_observation_context_refuses_without_recovery(self):
        store=self.open(); self.fund(store)
        proof=base.decode(self.proof('short','unlock-confirmed',self.short)); proof['context_digest_hex']='00'*32
        with self.assertRaises(base.RecoveryError): store.recover_long_completion(self.short,base.canonical(proof))
        self.assertEqual(store.status()['recovery_charges'],0)
        self.assertEqual(self.math.recovery_entries,0)
        self.assertEqual(bytes.fromhex(store.status()['signed_originals']['short']['wire_hex']),self.short)

    def test_send_acknowledgement_cannot_authorize_recovery(self):
        store=self.open(); self.fund(store)
        with self.assertRaises(base.RecoveryError): store.recover_long_completion(self.short,self.proof('short','send-confirmed',self.short))
        self.assertEqual(store.status()['recovery_charges'],0)
        self.assertEqual(self.math.recovery_entries,0)

    def test_alias_confirmation_cannot_authorize_the_selected_raw_original(self):
        observed=[]; store=self.open(observer=lambda wire:observed.append(wire) or True)
        self.fund(store); store.retain_signed_original('short',self.short)
        alias=bytes.fromhex(self.records['short-unknown-protobuf-field']['wire_hex'])
        proof=self.proof('short','unlock-confirmed',alias); before=(self.root/'bob.log').read_bytes(); count=len(observed)
        with self.assertRaises(base.RecoveryError): store.record_signed_observation(proof)
        self.assertEqual((self.root/'bob.log').read_bytes(),before)
        self.assertEqual(len(observed),count)

    def test_lost_worker_reply_keeps_charge_and_refuses_new_recovery_after_reopen(self):
        def lost(): raise base.RecoveryError('synthetic lost worker reply')
        self.math.recovery_hook=lost
        store=self.open(); self.fund(store)
        with self.assertRaises(base.RecoveryError): self.recover(store)
        self.assertEqual(store.status()['recovery_outcome'],'UNKNOWN')
        self.assertEqual(store.status()['recovery_charges'],1)
        store.close(); self.math.recovery_hook=None; store=self.open()
        with self.assertRaises(base.Quarantined): self.recover(store)
        self.assertEqual(self.math.recovery_entries,1)
        self.assertNotIn('long',store.status()['signed_originals'])

    def test_lost_completion_acknowledgement_reopens_without_manufacturing_long_wire(self):
        def lost(kind):
            if kind=='signed-recovered': raise RuntimeError('synthetic lost append acknowledgement')
        store=self.open(hook=lost); self.fund(store)
        with self.assertRaises(base.Quarantined): self.recover(store)
        store.close(); store=self.open()
        self.assertEqual(store.status()['long_completion_hex'],COMPLETIONS['long_signature_hex'])
        self.assertNotIn('long',store.status()['signed_originals'])
        self.assertEqual(self.recover(store),COMPLETIONS['long_signature_hex'])
        self.assertEqual(self.math.recovery_entries,1)

    def test_uncertain_raw_append_cannot_enter_public_recovery(self):
        store=self.open(); self.fund(store)
        with patch('offline_session.nom_recovery.os.fsync',side_effect=OSError('synthetic fsync refusal')):
            with self.assertRaises(base.Quarantined): self.recover(store)
        self.assertEqual(self.math.recovery_entries,0)
        with self.assertRaises(base.Quarantined): store.status()
        store.close(); store=self.open()
        self.assertEqual(store.status()['recovery_charges'],0)
        self.assertNotIn('long',store.status()['signed_originals'])

    def test_same_size_external_edit_poison_preserves_the_changed_evidence(self):
        store=self.open('alice'); self.fund(store); store.retain_signed_original('short',self.short)
        path=self.root/'alice.log'; altered=bytearray(path.read_bytes()); altered[10]^=1; path.write_bytes(altered)
        with self.assertRaises(base.Quarantined): store.prepare_signed_attempt('short')
        self.assertEqual(path.read_bytes(),bytes(altered))
        with self.assertRaises(base.Quarantined): store.status()

    def test_historical_journal_is_not_migrated_or_reauthenticated(self):
        path=self.root/'bob.log'
        with base.NomRecovery.open(path,TERMS,PAIR,role='bob',verifier=self.math,observation_verifier=lambda _:True): pass
        before=path.read_bytes()
        with self.assertRaises(base.RecoveryError): self.open()
        self.assertEqual(path.read_bytes(),before)

    def test_defensive_status_and_frozen_source_oracle_preserve_exact_bytes(self):
        store=self.open('alice'); returned=store.retain_signed_original('short',self.short)
        returned['node_hash_hex']='00'*32
        view=store.status(); view['signed_originals']['short']['wire_hex']='00'
        self.records['short-original']['wire_hex']='00'
        store.close(); store=self.open('alice')
        self.assertEqual(bytes.fromhex(store.status()['signed_originals']['short']['wire_hex']),self.short)
        self.assertEqual(self.oracle.verify_original('short',self.short),bytes.fromhex(store.status()['signed_originals']['short']['facts_wire_hex']))

    def test_context_mismatch_refuses_before_file_creation(self):
        changed=copy.deepcopy(self.selection); changed['source_tree']='00'*20
        with self.assertRaises(base.RecoveryError): self.open(selection=changed)
        self.assertFalse((self.root/'bob.log').exists())

    def test_unqualified_raw_bytes_refuse_without_append(self):
        store=self.open('alice'); before=(self.root/'alice.log').read_bytes()
        invalid=bytes.fromhex(self.records['short-invalid-signature']['wire_hex'])
        with self.assertRaises(base.RecoveryError): store.retain_signed_original('short',invalid)
        self.assertEqual((self.root/'alice.log').read_bytes(),before)

    def test_callback_reentry_cannot_disclose_or_charge_an_original(self):
        target={}; refused=[]
        def observe(wire):
            if base.decode(wire)['reference']['kind']=='unseen':
                try: target['store'].prepare_signed_attempt('short')
                except base.RecoveryError as error: refused.append(str(error))
            return wire in self.allowed
        store=self.open('alice',observer=observe); target['store']=store
        self.fund(store); store.retain_signed_original('short',self.short)
        store.record_signed_observation(self.proof('short','unseen',self.short))
        self.assertEqual(refused,['signed-wire callback reentry refused'])
        self.assertEqual(store.status()['attempts'],{})

    def test_legacy_synthetic_output_methods_are_not_selected(self):
        store=self.open(); before=(self.root/'bob.log').read_bytes()
        for operation in (lambda:store.recover_long(b'',{}),lambda:store.prepare_attempt('long'),
                lambda:store.retain_original('long',b''),lambda:store.record_observation({})):
            with self.assertRaises(base.RecoveryError): operation()
        self.assertEqual((self.root/'bob.log').read_bytes(),before)

    def test_torn_history_refuses_without_truncation_or_reconstruction(self):
        store=self.open('alice'); store.retain_signed_original('short',self.short); store.close()
        path=self.root/'alice.log'; corrupted=path.read_bytes()+b'{unfinished'; path.write_bytes(corrupted)
        with self.assertRaises(base.Quarantined): self.open('alice')
        self.assertEqual(path.read_bytes(),corrupted)

    def test_invalid_recovered_completion_keeps_unknown_charge_and_no_long_original(self):
        self.math.recovery_result='00'*64
        store=self.open(); self.fund(store)
        with self.assertRaises(base.RecoveryError): self.recover(store)
        self.assertEqual(store.status()['recovery_outcome'],'UNKNOWN')
        self.assertIsNone(store.status()['long_completion_hex'])
        self.assertNotIn('long',store.status()['signed_originals'])

    def test_coherent_old_restore_still_loses_charge_without_an_external_fence(self):
        store=self.open(); self.fund(store); store.retain_signed_original('short',self.short)
        path=self.root/'bob.log'; old=path.read_bytes()
        def lost(): raise base.RecoveryError('synthetic lost reply')
        self.math.recovery_hook=lost
        with self.assertRaises(base.RecoveryError): self.recover(store)
        self.assertEqual(store.status()['recovery_charges'],1)
        store.close(); path.write_bytes(old); store=self.open()
        self.assertEqual(store.status()['recovery_charges'],0)
        self.assertEqual(self.math.recovery_entries,1)
        self.assertEqual(store.status()['observation_authority'],'UNFILLED')

    def test_changed_post_fsync_image_refuses_acknowledgement_and_retains_corruption(self):
        path=self.root/'alice.log'
        def corrupt(kind):
            if kind=='signed-original':
                altered=bytearray(path.read_bytes()); altered[-10]^=1; path.write_bytes(altered)
        store=self.open('alice',hook=corrupt)
        with self.assertRaises(base.Quarantined): store.retain_signed_original('short',self.short)
        corrupted=path.read_bytes(); store.close()
        with self.assertRaises(base.Quarantined): self.open('alice')
        self.assertEqual(path.read_bytes(),corrupted)


class SignedQualifierOptimization(unittest.TestCase):
    def test_all_optimized_entries_refuse_before_input_evidence_or_worker_access(self):
        program='''
from pathlib import Path
from unittest.mock import patch
from scripts import qualify_nom_signed_recovery as recovery
from scripts import qualify_nom_signed_originals as source
from scripts import prepare_nom_signed_originals as prepare
with patch.object(recovery,"source_inputs",side_effect=AssertionError("fixture accessed")), \\
     patch.object(source,"inputs",side_effect=AssertionError("source accessed")), \\
     patch.object(prepare,"inputs",side_effect=AssertionError("archive accessed")), \\
     patch.object(recovery,"NomPublicVerifier",side_effect=AssertionError("worker accessed")), \\
     patch.object(Path,"is_absolute",side_effect=AssertionError("evidence accessed")):
    cases=(
        (lambda: recovery.qualify(Path("unselected"),"00"*32,Path("unselected")),"signed-wire qualification requires assertions enabled"),
        (lambda: source.qualify(Path("unselected"),Path("unselected"),Path("unselected")),"signed-original qualification requires assertions enabled"),
        (lambda: prepare.prepare(Path("unselected"),Path("unselected")),"signed-original preparation requires assertions enabled"))
    for operation,message in cases:
        try:operation()
        except ValueError as error:
            if str(error)!=message:raise RuntimeError("unexpected optimized refusal") from None
        else:raise RuntimeError("optimized qualification admitted")
print("PASS: all optimized entries refused before selected inputs, evidence or worker access")
'''
        result=subprocess.run([sys.executable,'-B','-O','-c',program],cwd=ROOT,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
        self.assertEqual(result.returncode,0)
        self.assertEqual(result.stderr,b'')
        self.assertEqual(result.stdout,b'PASS: all optimized entries refused before selected inputs, evidence or worker access\n')


if __name__=='__main__': unittest.main()
