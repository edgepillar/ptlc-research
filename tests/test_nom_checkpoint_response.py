"""Directed role/response controls; curve mathematics is independently native."""
import ast
import copy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest

from offline_session import nom_checkpoint_response as framing
from offline_session import nom_checkpoint_discovery as discovery
from scripts import qualify_nom_checkpoint_response as q


class NoMCheckpointResponseControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases=q.fixture_cases()
        cls.vectors=q.public_fixture()

    def case(self,name='newer_candidate'):
        case=self.cases[name]
        envelope=framing.codec._canonical(self.vectors['positive_vectors'][name]['envelope'])
        return case,envelope

    def inspect(self,name='newer_candidate',*,local=None,checker=None):
        case,envelope=self.case(name)
        if checker is None: checker=lambda request:framing.expected_result(framing.request_digest(request))
        return framing.inspect_signed_discovery(case['local'] if local is None else local,
            case['selected'],case['reply'],envelope,case['opening'],verify_public=checker)

    def assert_held(self,value):
        self.assertEqual((value['state'],value['recovery_action']),('HOLD','NONE'))
        self.assertEqual(value['work_outcome'],'UNKNOWN')
        self.assertTrue(value['disclosure_possible'])
        self.assertEqual(value['core_worker_calls'],0)
        self.assertEqual(value['candidate_latest'],'NOT_ESTABLISHED')
        self.assertEqual(value['root_provisioning'],'UNFILLED')
        self.assertEqual((value['application'],value['core']),('NO-GO','NO-GO'))
        for key in ('new_work_allowed','automatic_retry','replenish_work','replacement_original_allowed','automatic_bootstrap'):
            self.assertIs(value[key],False)

    def test_selected_role_and_complete_response_match_public_native_vectors(self):
        case,envelope=self.case()
        request=framing.response_signature_request(case['selected'],case['reply'],envelope,case['opening'])
        vector=self.vectors['positive_vectors']['newer_candidate']
        self.assertEqual(request,vector['request'])
        self.assertEqual(case['selected'].declaration_message_digest_hex,vector['declaration_message_digest_hex'])
        self.assertEqual(framing.response_signed_message_digest(request),vector['signed_response_message_digest_hex'])
        self.assertEqual(framing.expected_result(framing.request_digest(request)),vector['result'])

    def test_service_policy_fixes_the_signer_and_complete_work_scope(self):
        selected=self.cases['newer_candidate']['selected']
        declaration=selected.as_dict();query=selected._read.as_dict()
        self.assertEqual(declaration['service_selection'],query['service_selection'])
        self.assertEqual(declaration['work_scope_digest_hex'],query['work_scope_digest_hex'])
        self.assertNotEqual(declaration['root_key_hex'],declaration['service_selection']['checkpoint_key_hex'])
        self.assertNotIn('response_key_hex',declaration)

    def test_new_challenge_preserves_the_grant_but_changes_the_signed_response(self):
        older=self.cases['minimum_candidate']['selected'];fresh=self.cases['fresh_old_candidate']['selected']
        self.assertEqual(older.canonical_bytes,fresh.canonical_bytes)
        first=self.vectors['positive_vectors']['minimum_candidate']['request']
        second=self.vectors['positive_vectors']['fresh_old_candidate']['request']
        self.assertNotEqual(framing.response_signed_message_digest(first),framing.response_signed_message_digest(second))
        self.assertEqual(first['root_signature_hex'],second['root_signature_hex'])
        self.assertNotEqual(first['response_signature_hex'],second['response_signature_hex'])

    def test_root_cannot_alias_the_service_signer_or_historical_roles(self):
        selected=self.cases['newer_candidate']['selected'];read=selected._read
        keys=framing._historical_keys(read._minimum)|{read.as_dict()['service_selection']['checkpoint_key_hex']}
        for key in keys:
            with self.assertRaises(framing.CheckpointResponseRefused):
                framing.select_response_authority(read,root_key_hex=key,epoch=1)

    def test_epoch_and_root_encodings_refuse_numeric_or_length_aliases(self):
        read=self.cases['minimum_candidate']['selected']._read
        for epoch in (True,1.0,0,-1,9007199254740992):
            with self.assertRaises(framing.CheckpointResponseRefused):
                framing.select_response_authority(read,root_key_hex=q.ROOT_KEY,epoch=epoch)
        for key in (q.ROOT_KEY.upper(),'ff'*31,'ff'*33,None):
            with self.assertRaises(framing.CheckpointResponseRefused):
                framing.select_response_authority(read,root_key_hex=key,epoch=1)

    def test_signature_width_and_lowercase_are_distinct_from_key_width(self):
        selected=self.cases['minimum_candidate']['selected']
        valid=framing.response_envelope(selected,root_signature_hex='00'*64,response_signature_hex='01'*64)
        self.assertEqual(len(json.loads(valid)['response_signature_hex']),128)
        for signature in ('00'*32,'00'*63,'00'*65,'AA'*64,'gg'*64,False):
            with self.assertRaises(framing.CheckpointResponseRefused):
                framing.response_envelope(selected,root_signature_hex=signature,response_signature_hex='00'*64)

    def test_peer_root_or_epoch_replacement_refuses_before_a_verifier_call(self):
        case,_=self.case();calls=[]
        for name in ('root_rotation','new_epoch'):
            envelope=framing.codec._canonical(self.vectors['positive_vectors'][name]['envelope'])
            with self.assertRaises(framing.CheckpointResponseRefused):
                framing.inspect_signed_discovery(case['local'],case['selected'],case['reply'],envelope,case['opening'],
                    verify_public=lambda request:calls.append(request))
        self.assertEqual(calls,[])

    def test_peer_service_rebinding_cannot_reuse_the_selected_authority(self):
        case,envelope=self.case();value=json.loads(envelope)
        value['declaration']['service_selection']['service_id_hex']='c2'*32
        value['declaration']['service_selection_digest_hex']=framing.protocol._hash(framing.protocol.POLICY_DOMAIN,value['declaration']['service_selection'])
        with self.assertRaises(framing.CheckpointResponseRefused):
            framing.response_signature_request(case['selected'],case['reply'],framing.codec._canonical(value),case['opening'])

    def test_missing_actual_opening_refuses_even_with_valid_public_signatures(self):
        case,envelope=self.case();calls=[]
        with self.assertRaises(framing.CheckpointResponseRefused):
            framing.inspect_signed_discovery(case['local'],case['selected'],case['reply'],envelope,None,
                verify_public=lambda request:calls.append(request))
        self.assertEqual(calls,[])

    def test_descriptor_dict_cannot_reconstruct_a_complete_opening(self):
        case,envelope=self.case()
        with self.assertRaises(framing.CheckpointResponseRefused):
            framing.response_signature_request(case['selected'],case['reply'],envelope,case['opening'].as_dict())

    def test_old_result_cannot_match_a_new_challenge(self):
        case,_=self.case('fresh_old_candidate')
        old=self.vectors['positive_vectors']['minimum_candidate']
        old_envelope=framing.codec._canonical(old['envelope'])
        request=framing.response_signature_request(case['selected'],case['reply'],old_envelope,case['opening'])
        self.assertNotEqual(framing.request_digest(request),old['result']['request_digest_hex'])
        with self.assertRaises(framing.CheckpointResponseRefused):
            framing.inspect_signed_discovery(case['local'],case['selected'],case['reply'],old_envelope,case['opening'],
                verify_public=lambda request:copy.deepcopy(old['result']))

    def test_old_result_cannot_match_a_different_complete_candidate(self):
        case=self.cases['later_minimum'];older=self.vectors['positive_vectors']['newer_candidate']
        envelope=framing.codec._canonical(older['envelope'])
        request=framing.response_signature_request(case['selected'],case['reply'],envelope,case['opening'])
        self.assertNotEqual(framing.request_digest(request),older['result']['request_digest_hex'])
        with self.assertRaises(framing.CheckpointResponseRefused):
            framing.inspect_signed_discovery(case['local'],case['selected'],case['reply'],envelope,case['opening'],
                verify_public=lambda request:copy.deepcopy(older['result']))

    def test_verifier_argument_mutation_cannot_rebind_the_expected_result(self):
        def mutate(request):
            request['discovery_message_digest_hex']='81'*32
            return framing.expected_result(framing.request_digest(request))
        with self.assertRaises(framing.CheckpointResponseRefused): self.inspect(checker=mutate)

    def test_verifier_flags_require_exact_booleans_and_complete_fields(self):
        for mode in ('numeric','missing','extra','wrong-digest'):
            def wrong(request):
                value=framing.expected_result(framing.request_digest(request))
                if mode=='numeric':value['root_signature_valid']=1
                elif mode=='missing':value.pop('response_signature_valid')
                elif mode=='extra':value['trusted']=True
                else:value['request_digest_hex']='81'*32
                return value
            with self.assertRaises(framing.CheckpointResponseRefused):self.inspect(checker=wrong)

    def test_verifier_failure_or_missing_callback_grants_no_action(self):
        def fail(request):raise RuntimeError('synthetic verifier unavailable')
        with self.assertRaises(framing.CheckpointResponseRefused):self.inspect(checker=fail)
        case,envelope=self.case()
        with self.assertRaises(framing.CheckpointResponseRefused):
            framing.inspect_signed_discovery(case['local'],case['selected'],case['reply'],envelope,case['opening'],verify_public=None)

    def test_local_ahead_retains_the_larger_complete_unknown_list(self):
        local=self.cases['later_minimum']['opening']._candidate._context
        value=self.inspect(local=local);self.assert_held(value)
        self.assertEqual(value['journal_relation'],'LOCAL_AHEAD_CANDIDATE')
        self.assertEqual(len(value['effective_charged_work']),3)

    def test_signed_newer_candidate_retains_unknown_work_without_permission(self):
        value=self.inspect();self.assert_held(value)
        self.assertEqual(value['discovery'],'NEWER_CANDIDATE')
        self.assertEqual(value['signature_verifier_calls'],1)
        self.assertIn('CALLBACK ASSERTION',value['signature_mathematics'])

    def test_signed_outage_proves_no_absence_and_accepts_no_cached_opening(self):
        value=self.inspect('unavailable_service');self.assert_held(value)
        self.assertIsNone(value['candidate_checkpoint_digest_hex'])
        case,envelope=self.case('unavailable_service')
        with self.assertRaises(framing.CheckpointResponseRefused):
            framing.response_signature_request(case['selected'],case['reply'],envelope,self.cases['newer_candidate']['opening'])

    def test_freshly_signed_old_candidate_still_has_no_currentness(self):
        value=self.inspect('fresh_old_candidate');self.assert_held(value)
        self.assertEqual(value['discovery'],'MINIMUM_CANDIDATE')
        self.assertEqual(value['candidate_sequence'],value['minimum_sequence'])

    def test_signed_siblings_can_both_match_the_same_old_minimum(self):
        first=self.inspect();second=self.inspect('sibling_candidate')
        self.assert_held(first);self.assert_held(second)
        self.assertEqual(first['candidate_sequence'],second['candidate_sequence'])
        self.assertNotEqual(first['candidate_checkpoint_digest_hex'],second['candidate_checkpoint_digest_hex'])

    def test_frozen_selection_defensive_views_and_no_application_io_entry(self):
        selected=self.cases['newer_candidate']['selected'];before=selected.canonical_bytes
        with self.assertRaises(FrozenInstanceError):selected._epoch=2
        value=selected.as_dict();value['service_selection']['service_id_hex']='81'*32
        self.assertEqual(selected.canonical_bytes,before)
        with self.assertRaises(TypeError):framing.NoMCheckpointResponseAuthority()
        tree=ast.parse(Path(framing.__file__).read_text('ascii'))
        imports={node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom)}
        imports.update(alias.name for node in ast.walk(tree) if isinstance(node,ast.Import) for alias in node.names)
        self.assertFalse(imports & {'subprocess','os','socket','urllib','pathlib'})
        names={node.id for node in ast.walk(tree) if isinstance(node,ast.Name)}
        self.assertFalse(names & {'open','run_public_worker','SecretKey','sign_schnorr'})

    def test_peer_wire_fields_numeric_alias_depth_and_size_refuse(self):
        case,envelope=self.case();value=json.loads(envelope)
        alias=copy.deepcopy(value);alias['declaration']['authority_epoch']=1.0
        extra=copy.deepcopy(value);extra['peer_selection']=True
        for wire in (b' '+envelope,envelope+b'\n',envelope.replace(b'{',b'{"schema":"duplicate",',1),
                     framing.codec._canonical(alias),framing.codec._canonical(extra),b'['*13+b']'*13,b'x'*8193):
            with self.assertRaises(framing.CheckpointResponseRefused):
                framing.response_signature_request(case['selected'],case['reply'],wire,case['opening'])

    def test_alternate_valid_signature_encoding_needs_its_own_exact_result(self):
        case,envelope=self.case();value=json.loads(envelope)
        value['response_signature_hex']=self.vectors['alternate_response_signature_hex']
        alternate=framing.codec._canonical(value)
        original=self.vectors['positive_vectors']['newer_candidate']['request']
        request=framing.response_signature_request(case['selected'],case['reply'],alternate,case['opening'])
        self.assertEqual(framing.response_signed_message_digest(request),framing.response_signed_message_digest(original))
        self.assertNotEqual(framing.request_digest(request),framing.request_digest(original))
        with self.assertRaises(framing.CheckpointResponseRefused):
            framing.inspect_signed_discovery(case['local'],case['selected'],case['reply'],alternate,case['opening'],
                verify_public=lambda request:copy.deepcopy(self.vectors['positive_vectors']['newer_candidate']['result']))

    def test_native_original_parser_refuses_missing_or_altered_receipts(self):
        # Synthetic parser controls do not assert that any native worker ran.
        calls=[]
        for number,(phase,request,code) in enumerate(q.expected_native_requests(),1):
            wire=framing.codec._canonical(request)
            output=b'' if code else framing.codec._canonical(framing.expected_result(framing.request_digest(request)))+b'\n'
            error=b'selected public checkpoint signature check refused\n' if code else b''
            calls.append(dict(number=number,phase=phase,request_hex=wire.hex(),request_sha256=q.sha(wire),
                stdout_hex=output.hex(),stdout_sha256=q.sha(output),stderr_hex=error.hex(),stderr_sha256=q.sha(error),
                exit_code=code,stream_completeness='COMPLETE'))
        q.validate_native_calls(calls)
        for mode in ('missing','incomplete','exit','stdout','request',
                     'boolean-exit','float-exit','boolean-number','float-number'):
            changed=copy.deepcopy(calls)
            if mode=='missing':changed.pop()
            elif mode=='incomplete':changed[0]['stream_completeness']='PARTIAL; NOT_ESTABLISHED'
            elif mode=='exit':changed[0]['exit_code']=None
            elif mode=='stdout':changed[0]['stdout_hex']=''
            elif mode=='request':changed[0]['request_sha256']='81'*32
            elif mode=='boolean-exit':changed[0]['exit_code']=False
            elif mode=='float-exit':changed[0]['exit_code']=0.0
            elif mode=='boolean-number':changed[0]['number']=True
            else:changed[0]['number']=1.0
            with self.assertRaises(ValueError):q.validate_native_calls(changed)


if __name__=='__main__':unittest.main()
