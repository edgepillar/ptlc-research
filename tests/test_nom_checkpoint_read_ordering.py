"""Actual complete reference order controls; never service or work authority."""
import ast
import copy
from dataclasses import FrozenInstanceError
from pathlib import Path
import unittest
from unittest.mock import patch

from offline_session import enrollment_contract as codec
from offline_session import nom_checkpoint_read_ordering as ordering
from offline_session import nom_checkpoint_discovery as discovery, nom_checkpoint_protocol as protocol
from scripts import qualify_nom_checkpoint_read_ordering as q


class NoMCheckpointReadOrderingControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy,cls.contexts,cls.retained,cls.refs=q.fixture_contexts()
        cls.initial=ordering.bootstrap_order_trace(cls.refs['initial'])
        cls.latest=q.publish(cls.initial,cls.refs['latest'])
        cls.tail=q.publish(cls.latest,cls.refs['tail'])
        cls.query=discovery.checkpoint_read(cls.refs['initial'],challenge_hex='d1'*32)
        cls.early_state,cls.early=q.read(cls.initial,cls.query)
        cls.middle_state,cls.middle=q.read(cls.latest,cls.query)
        cls.late_state,cls.late=q.read(cls.tail,cls.query)
        cls.early_later=q.publish(q.publish(cls.early_state,cls.refs['latest']),cls.refs['tail'])
        cls.middle_later=q.publish(cls.middle_state,cls.refs['tail'])
        cls.anchor=ordering.select_order_anchor(cls.middle_state)
        cls.packet=discovery.discovery_reply(cls.query,cls.middle._opening)

    def inspect(self,trace=None,read=None,local='primary'):
        return q.inspect(self.contexts[local],self.middle_state if trace is None else trace,self.middle if read is None else read)

    def hold(self,value):
        self.assertEqual((value['state'],value['recovery_action'],value['application'],value['core']),('HOLD','NONE','NO-GO','NO-GO'))
        self.assertEqual(value['worker_calls'],0)
        self.assertEqual(value['new_core_source_outcomes'],0)
        self.assertEqual(value['current_at_delivery'],'NOT_ESTABLISHED')
        self.assertEqual(value['service_nonrollback'],'NOT_IMPLEMENTED')
        self.assertEqual(value['checkpoint_storage'],'NOT_IMPLEMENTED')
        self.assertTrue(all(row['outcome']=='UNKNOWN' for row in value['effective_charged_work']))
        for field in ('new_work_allowed','automatic_retry','replenish_work','replacement_original_allowed','automatic_bootstrap'):
            self.assertIs(value[field],False)

    def clone(self,value,**updates):
        result=object.__new__(type(value))
        for field in value.__dataclass_fields__:object.__setattr__(result,field,updates.get(field,getattr(value,field)))
        return result

    def test_explicit_bootstrap_keeps_complete_actual_initial_opening(self):
        value=self.initial.as_dict()
        self.assertEqual(value['initial_opening'],discovery.checkpoint_opening(self.refs['initial']).as_dict())
        self.assertEqual(value['service_selection'],self.policy.as_dict())
        self.assertEqual(value['events'],[])
        self.assertEqual(value['retained_head']['checkpoint']['sequence'],1)

    def test_publish_appends_one_actual_lineage_record_and_retains_old_trace(self):
        before=self.initial.canonical_bytes
        value=self.latest.as_dict()
        self.assertEqual(len(value['events']),1)
        self.assertEqual(value['events'][0]['event'],'PUBLISH')
        self.assertEqual(value['events'][0]['complete_opening'],discovery.checkpoint_opening(self.refs['latest']).as_dict())
        self.assertEqual(self.initial.canonical_bytes,before)

    def test_read_before_publish_remains_at_the_old_reference_instant(self):
        value=self.inspect(self.early_later,self.early)
        self.assertEqual((value['evaluated_event_position'],value['later_reference_events'],value['candidate_sequence']),(1,2,1))
        self.assertEqual(len(value['effective_charged_work']),3)
        self.hold(value)

    def test_publish_before_read_requires_the_published_reference_head(self):
        value=self.inspect()
        self.assertEqual((value['evaluated_event_position'],value['candidate_sequence']),(2,2))
        self.assertEqual(value['later_reference_events'],0)
        self.hold(value)

    def test_write_after_read_keeps_the_read_position_and_larger_unknown_work(self):
        value=self.inspect(self.middle_later,self.middle)
        self.assertEqual((value['evaluated_event_position'],value['candidate_sequence'],value['later_reference_events']),(2,2,1))
        self.assertEqual(value['effective_charged_work'],self.refs['tail'].as_dict()['charged_work'])
        self.hold(value)

    def test_read_after_two_publications_binds_the_third_complete_checkpoint(self):
        value=self.inspect(self.late_state,self.late)
        self.assertEqual((value['evaluated_event_position'],value['candidate_sequence']),(3,3))
        self.hold(value)

    def test_exact_read_result_is_repeatable_without_dispatch_or_trace_mutation(self):
        before=self.middle_state.canonical_bytes
        first=self.inspect();second=self.inspect()
        self.assertEqual(first,second)
        self.assertEqual(before,self.middle_state.canonical_bytes)
        self.hold(second)

    def test_stale_publish_pin_refuses_after_a_read_changed_the_state(self):
        with self.assertRaises(ordering.CheckpointReadOrderRefused):
            ordering.publish_reference(self.middle_state,self.refs['tail'],expected_state_digest_hex=self.latest.digest_hex)

    def test_stale_read_pin_refuses_even_without_a_new_checkpoint_counter(self):
        fresh=discovery.checkpoint_read(self.refs['initial'],challenge_hex='d2'*32)
        with self.assertRaises(ordering.CheckpointReadOrderRefused):
            ordering.evaluate_reference_read(self.middle_state,fresh,expected_state_digest_hex=self.latest.digest_hex)
        self.assertEqual(self.middle_state.as_dict()['retained_head'],self.latest.as_dict()['retained_head'])

    def test_duplicate_or_regressed_publication_never_mints_an_event(self):
        for candidate in (self.refs['initial'],self.refs['latest']):
            with self.assertRaises(ordering.CheckpointReadOrderRefused):q.publish(self.latest,candidate)

    def test_skipped_checkpoint_cannot_replace_the_exact_next_publish(self):
        with self.assertRaises(ordering.CheckpointReadOrderRefused):q.publish(self.initial,self.refs['tail'])

    def test_sibling_counter_cannot_replace_the_selected_retained_lineage(self):
        self.assertEqual(self.refs['latest'].as_dict()['sequence'],self.refs['sibling'].as_dict()['sequence'])
        with self.assertRaises(ordering.CheckpointReadOrderRefused):q.publish(self.latest,self.refs['sibling'])

    def test_service_identity_epoch_and_key_changes_need_independent_migration(self):
        for fields in (dict(service_id_hex='c2'*32),dict(service_epoch=2),dict(checkpoint_key_hex='82'*32)):
            parameters=dict(service_id_hex='c1'*32,service_epoch=1,checkpoint_key_hex=self.policy.as_dict()['checkpoint_key_hex'])
            other=protocol.select_service(self.contexts['primary'],**dict(parameters,**fields))
            start=protocol.bootstrap_reference(other,self.contexts['primary'])
            candidate=protocol.advance_reference(start,self.contexts['extended'],expected_current_digest_hex=start.digest_hex)
            with self.assertRaises(ordering.CheckpointReadOrderRefused):q.publish(self.initial,candidate)

    def test_changed_historical_source_view_refuses_at_the_same_header_digest(self):
        changed=protocol.bootstrap_reference(self.policy,self.contexts['source_rotation'])
        self.assertEqual(changed.digest_hex,self.refs['initial'].digest_hex)
        candidate=protocol.advance_reference(changed,self.contexts['extended'],expected_current_digest_hex=changed.digest_hex)
        with self.assertRaises(ordering.CheckpointReadOrderRefused):q.publish(self.initial,candidate)

    def test_fresh_read_from_restored_old_trace_refuses_the_new_retained_prefix(self):
        fresh=discovery.checkpoint_read(self.refs['initial'],challenge_hex='d3'*32)
        restored,old=q.read(self.initial,fresh)
        current,new=q.read(self.tail,fresh)
        with self.assertRaises(ordering.CheckpointReadOrderRefused):self.inspect(current,old)
        self.hold(self.inspect(current,new))

    def test_forked_read_refuses_even_with_valid_old_minimum_and_equal_counter(self):
        sibling=q.publish(self.initial,self.refs['sibling'])
        sibling_state,read=q.read(sibling,self.query)
        with self.assertRaises(ordering.CheckpointReadOrderRefused):self.inspect(self.middle_state,read)
        self.hold(self.inspect(sibling_state,read,local='divergent'))

    def test_anchor_before_selected_read_cannot_supply_missing_read_event(self):
        with self.assertRaises(ordering.CheckpointReadOrderRefused):self.inspect(self.latest,self.middle)

    def test_same_challenge_is_not_reused_after_a_changed_minimum(self):
        next_trace=q.publish(self.middle_state,self.refs['tail'])
        changed=discovery.checkpoint_read(self.refs['latest'],challenge_hex='d1'*32)
        self.assertNotEqual(changed.digest_hex,self.query.digest_hex)
        with self.assertRaises(ordering.CheckpointReadOrderRefused):q.read(next_trace,changed)

    def test_reply_from_before_or_after_evaluation_cannot_choose_the_read_head(self):
        for read,trace,candidate in ((self.middle,self.middle_state,'initial'),(self.early,self.early_later,'latest')):
            opening=discovery.checkpoint_opening(self.refs[candidate])
            packet=discovery.discovery_reply(self.query,opening)
            with self.assertRaises(ordering.CheckpointReadOrderRefused):
                ordering.inspect_ordered_reply(self.contexts['primary'],ordering.select_order_anchor(trace),read,packet,opening)

    def test_public_descriptors_and_missing_openings_are_not_actual_order_evidence(self):
        for anchor,read,opening in ((self.anchor.as_dict(),self.middle,self.middle._opening),
            (self.anchor,self.middle.as_dict(),self.middle._opening),(self.anchor,self.middle,None),
            (self.anchor,self.middle,self.middle._opening.as_dict())):
            with self.assertRaises(ordering.CheckpointReadOrderRefused):
                ordering.inspect_ordered_reply(self.contexts['primary'],anchor,read,self.packet,opening)

    def test_numeric_event_and_receipt_aliases_or_extra_fields_refuse(self):
        for field,value in (('position',True),('position',2.0),('position','2'),('extra',True)):
            descriptor=self.middle.as_dict();descriptor[field]=value
            forged=self.clone(self.middle,_wire=codec._canonical(descriptor))
            with self.assertRaises(ordering.CheckpointReadOrderRefused):forged.as_dict()
        event_wire=self.middle_state.as_dict();event_wire['events'][-1]['position']=2.0
        with self.assertRaises(ordering.CheckpointReadOrderRefused):
            self.clone(self.middle_state,_wire=codec._canonical(event_wire)).as_dict()

    def test_canonical_depth_size_and_finite_event_limits_refuse(self):
        for wire in (b' '+self.middle._wire,self.middle._wire+b'\n',b'['*13+b']'*13,b'x'*(ordering.MAX_RECEIPT_BYTES+1)):
            with self.assertRaises(ordering.CheckpointReadOrderRefused):self.clone(self.middle,_wire=wire).as_dict()
        oversized=self.middle_state._events*(ordering.MAX_EVENTS+1)
        with self.assertRaises(ordering.CheckpointReadOrderRefused):self.clone(self.middle_state,_events=oversized).as_dict()
        with self.assertRaises(ordering.CheckpointReadOrderRefused):ordering._decode(b'x'*(ordering.MAX_TRACE_BYTES+1),ordering.MAX_TRACE_BYTES)
        # Isolated pure-model cap control; no storage policy or production floor changes.
        with patch.object(ordering,'MAX_RECEIPT_BYTES',1):
            with self.assertRaises(ordering.CheckpointReadOrderRefused):
                ordering.inspect_ordered_reply(self.contexts['primary'],self.anchor,self.middle,self.packet,self.middle._opening)
            with self.assertRaises(ordering.CheckpointReadOrderRefused):
                ordering.inspect_ordering_outage(self.contexts['primary'],self.anchor,self.query,discovery.unavailable_reply(self.query))

    def test_frozen_objects_defensive_exports_and_fresh_validation_per_operation(self):
        for value,field in ((self.initial,'_events'),(self.middle,'_wire'),(self.anchor,'_trace')):
            with self.assertRaises(FrozenInstanceError):setattr(value,field,None)
        exported=self.middle_state.as_dict();exported['events'].clear()
        self.assertEqual(len(self.middle_state.as_dict()['events']),2)
        clone=self.clone(self.middle_state)
        self.assertEqual(clone.as_dict(),self.middle_state.as_dict())
        object.__setattr__(clone,'_wire',codec._canonical(dict(clone.as_dict(),extra=True)))
        with self.assertRaises(ordering.CheckpointReadOrderRefused):clone.as_dict()
        tree=ast.parse(Path(ordering.__file__).read_text('ascii'))
        imports=[n.names[0].name for n in ast.walk(tree) if isinstance(n,ast.Import)]
        self.assertEqual(imports,[])
        calls=[n.func.id for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
        self.assertNotIn('open',calls)

    def test_larger_local_unknown_list_is_preserved_without_advancing_the_anchor(self):
        before=self.middle_state.canonical_bytes
        value=self.inspect(local='third')
        self.assertEqual(value['effective_charged_work'],self.contexts['third']._binding.as_dict()['charged_work'])
        self.assertEqual(self.middle_state.canonical_bytes,before)
        self.hold(value)

    def test_unavailable_source_and_outage_retain_larger_anchor_work_without_fallback(self):
        self.hold(self.inspect(local='unavailable'))
        value=ordering.inspect_ordering_outage(self.contexts['primary'],ordering.select_order_anchor(self.tail),self.query,discovery.unavailable_reply(self.query))
        self.assertIsNone(value['candidate_checkpoint_digest_hex'])
        self.assertEqual(len(value['effective_charged_work']),3)
        self.hold(value)
        with self.assertRaises(ordering.CheckpointReadOrderRefused):
            ordering.inspect_ordered_reply(self.contexts['primary'],self.anchor,self.middle,discovery.unavailable_reply(self.query),self.middle._opening)

    def test_journal_extension_without_new_charge_creates_no_new_allowance(self):
        trace=q.publish(self.latest,self.refs['uncharged'])
        trace,read=q.read(trace,discovery.checkpoint_read(self.refs['latest'],challenge_hex='d4'*32))
        value=self.inspect(trace,read)
        self.assertEqual((value['candidate_sequence'],len(value['effective_charged_work'])),(3,2))
        self.hold(value)

    def test_coherent_old_anchor_restore_and_lost_read_bootstrap_still_match_unsafely(self):
        old=self.inspect(self.early_state,self.early)
        fresh=discovery.checkpoint_read(self.refs['initial'],challenge_hex='d5'*32)
        restarted=ordering.bootstrap_order_trace(self.refs['latest']);restarted,read=q.read(restarted,fresh)
        reset=self.inspect(restarted,read)
        self.assertEqual((old['evaluated_event_position'],reset['evaluated_event_position']),(1,1))
        self.hold(old);self.hold(reset)

    def test_separate_sibling_traces_both_match_without_shared_service_authority(self):
        left=self.inspect()
        sibling=q.publish(self.initial,self.refs['sibling']);sibling,read=q.read(sibling,self.query)
        right=self.inspect(sibling,read,local='divergent')
        self.assertEqual(left['candidate_sequence'],right['candidate_sequence'])
        self.assertNotEqual(left['candidate_checkpoint_digest_hex'],right['candidate_checkpoint_digest_hex'])
        self.hold(left);self.hold(right)


if __name__=='__main__':unittest.main()
