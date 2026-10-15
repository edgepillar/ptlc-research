"""Actual reference lifecycle and lost acknowledgment controls; no work permission."""
import copy
from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from offline_session import enrollment_contract as codec
from offline_session import nom_anchor_lifecycle as lifecycle
from offline_session import nom_checkpoint_read_ordering as ordering
from offline_session import nom_checkpoint_protocol as protocol
from scripts import qualify_nom_anchor_lifecycle as q


class NoMAnchorLifecycleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = q.fixture_contexts()
        cls.a, cls.t = cls.f['anchors'], cls.f['traces']
        cls.requests, cls.holds = cls.f['requests'], cls.f['holds']

    def inspect(self, anchor='active', hold='first', local='primary'):
        return q.inspect(self.f, anchor, hold, local)

    def hold(self, value):
        self.assertEqual((value['state'],value['recovery_action'],value['application'],value['core']),('HOLD','NONE','NO-GO','NO-GO'))
        self.assertEqual(value['publication_outcome'],'UNKNOWN')
        self.assertIs(value['disclosure_possible'],True)
        self.assertEqual((value['worker_calls'],value['additional_signature_requests'],value['new_core_source_outcomes']),(0,0,0))
        self.assertEqual(value['current_anchor_authenticated'],'NOT_ESTABLISHED')
        self.assertEqual(value['current_at_delivery'],'NOT_ESTABLISHED')
        self.assertEqual(value['service_nonrollback'],'NOT_IMPLEMENTED')
        self.assertEqual(value['checkpoint_storage'],'NOT_IMPLEMENTED')
        self.assertTrue(all(row['outcome']=='UNKNOWN' for row in value['effective_charged_work']))
        for field in ('new_work_allowed','automatic_retry','same_request_republication','replenish_work',
            'replacement_original_allowed','automatic_bootstrap','automatic_reenrollment'):
            self.assertIs(value[field],False)

    def clone(self, value, **updates):
        result=object.__new__(type(value))
        for field in value.__dataclass_fields__:
            object.__setattr__(result,field,updates.get(field,getattr(value,field)))
        return result

    def test_explicit_enrollment_retains_the_actual_initial_trace_without_absence(self):
        value=self.a['initial'].as_dict()
        self.assertEqual((value['revision'],value['phase'],value['transitions']),(0,'ACTIVE',[]))
        self.assertEqual(value['selection']['anchor_id_hex'],'e1'*32)
        self.assertEqual(value['current_trace']['trace_digest_hex'],self.t['initial'].digest_hex)
        self.hold(self.inspect('initial'))

    def test_transition_binds_full_preceding_state_and_exact_next_order_event(self):
        value=self.requests['first'].as_dict()
        self.assertEqual(value['expected_anchor_digest_hex'],self.a['initial'].digest_hex)
        self.assertEqual(value['before_trace']['event_count'],0)
        self.assertEqual(value['next_trace']['event_count'],1)
        self.assertEqual(value['selection'],self.a['initial'].as_dict()['selection'])
        self.assertEqual(self.a['initial'].as_dict()['transitions'],[])

    def test_functional_commit_retains_one_exact_request_without_rewriting_the_base(self):
        initial=self.a['initial'].canonical_bytes
        value=self.a['active'].as_dict()
        self.assertEqual((value['revision'],value['phase']),(1,'ACTIVE'))
        self.assertEqual(value['transitions'][0]['request_digest_hex'],self.requests['first'].digest_hex)
        self.assertEqual(self.a['initial'].canonical_bytes,initial)
        self.hold(self.inspect())

    def test_lost_ack_before_commit_never_becomes_safe_absence_or_retry(self):
        value=self.inspect('initial')
        self.assertEqual(value['reference_acknowledgment_relation'],'REFERENCE_REQUEST_NOT_FOUND')
        self.assertEqual(len(value['effective_charged_work']),2)
        self.hold(value)

    def test_lost_ack_after_commit_matches_only_a_reference_record_and_stays_unknown(self):
        value=self.inspect()
        self.assertEqual(value['reference_acknowledgment_relation'],'EXACT_RETAINED_REFERENCE_REQUEST')
        self.assertEqual(value['held_request_digest_hex'],self.requests['first'].digest_hex)
        self.assertEqual(value['reference_anchor_revision'],1)
        self.hold(value)

    def test_ordered_read_advances_anchor_revision_without_minting_a_checkpoint_charge(self):
        before=self.a['active'].as_dict();after=self.a['after_read'].as_dict()
        self.assertEqual((before['revision'],after['revision']),(1,2))
        self.assertEqual(before['current_trace']['checkpoint_sequence'],after['current_trace']['checkpoint_sequence'])
        self.assertNotEqual(before['current_trace']['trace_digest_hex'],after['current_trace']['trace_digest_hex'])
        self.assertEqual(len(self.inspect('after_read')['effective_charged_work']),2)

    def test_later_retained_publication_preserves_the_exact_old_request_and_larger_work(self):
        value=self.inspect('after_third')
        self.assertEqual(value['reference_acknowledgment_relation'],'EXACT_RETAINED_REFERENCE_REQUEST')
        self.assertEqual(value['reference_anchor_revision'],3)
        self.assertEqual(value['effective_charged_work'],self.f['refs']['tail'].as_dict()['charged_work'])
        self.hold(value)

    def test_repeated_lookup_does_not_commit_republish_or_mutate_any_reference(self):
        anchor=self.a['active'].canonical_bytes;held=self.holds['first']._wire
        with patch.object(lifecycle,'commit_reference_anchor',side_effect=AssertionError('lookup must not commit')):
            first=self.inspect();second=self.inspect()
        self.assertEqual(first,second)
        self.assertEqual(self.a['active'].canonical_bytes,anchor)
        self.assertEqual(self.holds['first']._wire,held)
        self.hold(second)

    def test_retirement_tombstone_preserves_history_and_rejects_all_later_transitions(self):
        value=self.a['retired'].as_dict();prior=self.a['after_third'].as_dict()
        self.assertEqual((value['phase'],value['revision']),('RETIRED',4))
        self.assertEqual(value['transitions'][:-1],prior['transitions'])
        self.assertEqual(value['current_trace'],prior['current_trace'])
        for operation in (lambda:q.advance(self.a['retired'],self.t['third'],'e9'),lambda:q.retire(self.a['retired'],'e9')):
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):operation()

    def test_lost_retirement_ack_preserves_the_tombstone_but_grants_no_work(self):
        value=self.inspect('retired','retirement')
        self.assertEqual(value['reference_acknowledgment_relation'],'EXACT_RETAINED_REFERENCE_REQUEST')
        self.assertEqual(value['reference_anchor_phase'],'RETIRED')
        self.assertEqual(len(value['effective_charged_work']),3)
        self.hold(value)

    def test_stale_expected_pins_and_duplicate_commit_cannot_create_another_transition(self):
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):
            lifecycle.prepare_anchor_advance(self.a['active'],self.t['read'],transition_nonce_hex='e9'*32,
                expected_anchor_digest_hex=self.a['initial'].digest_hex)
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):
            lifecycle.commit_reference_anchor(self.a['initial'],self.requests['first'],expected_anchor_digest_hex='00'*32)
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):q.commit(self.a['active'],self.requests['first'])

    def test_used_request_nonce_refuses_for_both_advance_and_retirement(self):
        for operation in (lambda:q.advance(self.a['active'],self.t['read'],'e2'),lambda:q.retire(self.a['active'],'e2')):
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):operation()

    def test_skipped_duplicate_regressed_and_sibling_order_histories_refuse(self):
        sibling=q.prior.publish(self.t['initial'],self.f['refs']['sibling'])
        for anchor,trace in ((self.a['initial'],self.t['read']), (self.a['active'],self.t['initial']),
            (self.a['active'],self.t['second']), (self.a['active'],sibling)):
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):q.advance(anchor,trace,'e9')

    def test_changed_service_epoch_key_and_historical_source_view_require_migration(self):
        fields=dict(service_id_hex='c1'*32,service_epoch=1,checkpoint_key_hex=self.f['policy'].as_dict()['checkpoint_key_hex'])
        for updates in (dict(service_id_hex='f1'*32),dict(service_epoch=2),dict(checkpoint_key_hex='83'*32)):
            selected=protocol.select_service(self.f['contexts']['primary'],**dict(fields,**updates))
            old=protocol.bootstrap_reference(selected,self.f['contexts']['primary'])
            new=protocol.advance_reference(old,self.f['contexts']['extended'],expected_current_digest_hex=old.digest_hex)
            trace=q.prior.publish(ordering.bootstrap_order_trace(old),new)
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):q.advance(self.a['initial'],trace,'e9')
        changed=protocol.bootstrap_reference(self.f['policy'],self.f['contexts']['source_rotation'])
        changed_next=protocol.advance_reference(changed,self.f['contexts']['extended'],expected_current_digest_hex=changed.digest_hex)
        trace=q.prior.publish(ordering.bootstrap_order_trace(changed),changed_next)
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):q.advance(self.a['initial'],trace,'e9')

    def test_different_anchor_identity_or_epoch_cannot_replace_independent_custody(self):
        for identity,epoch in (('f1',1),('e1',2)):
            other=lifecycle.bootstrap_reference_anchor(self.t['initial'],anchor_id_hex=identity*32,anchor_epoch=epoch)
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):
                lifecycle.inspect_anchor_acknowledgment(self.f['contexts']['primary'],self.holds['first'],other)

    def test_regressed_anchor_and_conflicting_exact_next_request_refuse(self):
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):self.inspect('initial','read')
        competing=q.commit(self.a['initial'],q.advance(self.a['initial'],self.t['second'],'e9'))
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):
            lifecycle.inspect_anchor_acknowledgment(self.f['contexts']['primary'],self.holds['first'],competing)

    def test_descriptors_or_missing_actual_objects_cannot_reopen_requests_and_holds(self):
        local=self.f['contexts']['primary']
        for anchor,hold in ((self.a['active'].as_dict(),self.holds['first']),
            (self.a['active'],self.holds['first'].as_dict()),(self.a['active'],None)):
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):lifecycle.inspect_anchor_acknowledgment(local,hold,anchor)
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):q.commit(self.a['initial'],self.requests['first'].as_dict())
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):q.advance(self.a['initial'],self.t['second'].as_dict(),'e9')
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):lifecycle.retain_unknown_anchor_acknowledgment(self.requests['first'].as_dict())

    def test_numeric_aliases_extra_fields_and_reframed_transition_bytes_refuse(self):
        for epoch in (True,1.0,'1',0,-1):
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):
                lifecycle.bootstrap_reference_anchor(self.t['initial'],anchor_id_hex='e1'*32,anchor_epoch=epoch)
        for value,field,replacement in ((self.a['active'],'revision',1.0),(self.a['active'],'revision',True),
            (self.requests['first'],'extra',False),(self.holds['first'],'work_permission',True)):
            wire=value.as_dict();wire[field]=replacement
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):self.clone(value,_wire=codec._canonical(wire)).as_dict()
        wire=self.a['active'].as_dict();wire['transitions'][0]['position']=1.0
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):self.clone(self.a['active'],_wire=codec._canonical(wire)).as_dict()

    def test_early_canonical_byte_depth_and_transition_bounds_cover_both_lookups(self):
        for value,limit in ((self.a['active'],lifecycle.MAX_STATE_BYTES),(self.requests['first'],lifecycle.MAX_REQUEST_BYTES),
            (self.holds['first'],lifecycle.MAX_REQUEST_BYTES)):
            for wire in (b' '+value._wire,value._wire+b'\n',b'['*13+b']'*13,b'x'*(limit+1)):
                with self.assertRaises(lifecycle.AnchorLifecycleRefused):self.clone(value,_wire=wire).as_dict()
        many=self.a['active']._events*(lifecycle.MAX_TRANSITIONS+1)
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):self.clone(self.a['active'],_events=many).as_dict()
        # Pure-model cap only; no storage policy or production free-space change.
        with patch.object(lifecycle,'MAX_REQUEST_BYTES',1):
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):self.inspect()
            with self.assertRaises(lifecycle.AnchorLifecycleRefused):
                lifecycle.inspect_anchor_acknowledgment_outage(self.f['contexts']['primary'],self.holds['first'])

    def test_frozen_custody_defensive_exports_and_fresh_validation_detect_later_changes(self):
        for value,field in ((self.a['active'],'_events'),(self.requests['first'],'_before'),(self.holds['first'],'_wire')):
            with self.assertRaises(FrozenInstanceError):setattr(value,field,None)
        export=self.a['active'].as_dict();export['transitions'].clear()
        self.assertEqual(len(self.a['active'].as_dict()['transitions']),1)
        cloned=self.clone(self.requests['first'])
        self.assertEqual(cloned.as_dict(),self.requests['first'].as_dict())
        object.__setattr__(cloned,'_wire',codec._canonical(dict(cloned.as_dict(),extra=True)))
        with self.assertRaises(lifecycle.AnchorLifecycleRefused):cloned.as_dict()

    def test_larger_local_unknown_work_and_unavailable_source_do_not_reduce_charges(self):
        for local in ('third','unavailable'):
            value=self.inspect(local=local);self.hold(value)
            if local=='third':self.assertEqual(value['effective_charged_work'],self.f['contexts']['third']._binding.as_dict()['charged_work'])

    def test_outage_has_no_current_anchor_or_cached_ack_and_retains_proposed_work(self):
        before=self.holds['first']._wire
        value=lifecycle.inspect_anchor_acknowledgment_outage(self.f['contexts']['primary'],self.holds['first'])
        self.assertIsNone(value['reference_anchor_digest_hex'])
        self.assertIsNone(value['reference_anchor_revision'])
        self.assertIsNone(value['reference_anchor_phase'])
        self.assertIn('NO CURRENT ANCHOR OR ABSENCE CLAIM',value['reference_acknowledgment_relation'])
        self.assertEqual(len(value['effective_charged_work']),2)
        self.assertEqual(self.holds['first']._wire,before)
        self.hold(value)

    def test_coherent_restore_copies_and_explicit_reenrollment_remain_unsafe_controls(self):
        self.hold(self.inspect())
        competing_request=q.advance(self.a['initial'],self.t['second'],'e9')
        competing=q.commit(self.a['initial'],competing_request)
        self.assertEqual(competing.as_dict()['revision'],self.a['active'].as_dict()['revision'])
        self.assertNotEqual(competing.digest_hex,self.a['active'].digest_hex)
        self.hold(lifecycle.inspect_anchor_acknowledgment(self.f['contexts']['primary'],
            lifecycle.retain_unknown_anchor_acknowledgment(competing_request),competing))
        reenrolled=lifecycle.bootstrap_reference_anchor(self.t['third'],anchor_id_hex='f3'*32,anchor_epoch=2)
        self.assertEqual((reenrolled.as_dict()['phase'],reenrolled.as_dict()['revision']),('ACTIVE',0))
        resumed=q.commit(self.a['active'],self.requests['read'])
        self.assertEqual(resumed.as_dict()['phase'],'ACTIVE')
        self.assertEqual(self.a['retired'].as_dict()['phase'],'RETIRED')

    def test_diagnostics_use_no_io_and_distinct_commitments_supply_no_authentication(self):
        self.assertEqual(len({lifecycle.STATE_DOMAIN,lifecycle.REQUEST_DOMAIN,lifecycle.HOLD_DOMAIN,ordering.TRACE_DOMAIN}),4)
        before=copy.deepcopy(self.holds['first'].as_dict())
        with patch('builtins.open',side_effect=AssertionError('pure comparison must not open files')):
            value=self.inspect()
        self.assertEqual(before,self.holds['first'].as_dict())
        self.hold(value)


if __name__=='__main__':unittest.main()
