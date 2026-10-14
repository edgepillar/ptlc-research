#!/usr/bin/env python3
"""Qualify reference read order without a live service or nonrollback store."""
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from offline_session import enrollment_contract as codec  # noqa: E402
from offline_session import nom_checkpoint_read_ordering as ordering  # noqa: E402
from offline_session import nom_checkpoint_discovery as discovery  # noqa: E402
from offline_session import nom_checkpoint_protocol as protocol  # noqa: E402
from scripts import qualify_nom_checkpoint_discovery as fixtures  # noqa: E402
from scripts import qualify_nom_checkpoint_response as prior  # noqa: E402
from scripts.nom_cut_capture import sha  # noqa: E402

PROFILE = "ptlc-nom-checkpoint-read-ordering-qualification-v1"
BASE = "c5460ad8ad46b4cf338d3163c4223ac6879de868"
MANIFEST = "compatibility/nom_checkpoint_read_ordering_manifest.json"
FIXTURE = "compatibility/fixtures/nom_checkpoint_read_ordering_v1.json"
SELECTED = ("offline_session/nom_checkpoint_read_ordering.py", "scripts/qualify_nom_checkpoint_read_ordering.py",
    "tests/test_nom_checkpoint_read_ordering.py", FIXTURE)
RELATIONS = ("read_before_publish", "publish_before_read", "read_between_publishes", "read_after_publishes",
    "later_minimum", "local_ahead", "unavailable_source", "extension_without_charge", "outage")
REFUSALS = ("stale_write_pin", "skipped_publish", "regressed_publish", "sibling_publication", "changed_service",
    "changed_known_source_view", "old_read_after_newer_write", "forked_read", "anchor_before_read",
    "duplicate_challenge", "reply_before_evaluation", "reply_after_evaluation", "missing_actual_opening",
    "descriptor_only_anchor", "descriptor_only_read", "outage_cached_positive")
UNSAFE = ("coherent_old_trace_and_anchor", "bootstrap_after_lost_read_history",
    "independent_sibling_traces", "delivery_is_later_than_read")
BOUNDARY = dict(application="NO-GO",core="NO-GO",recovery_action="NONE",ordering_worker_calls=0,
    additional_signature_requests=0,reference_order="EXPLICIT FUNCTIONAL TRACE; INDEPENDENT SELECTION PREMISE",
    current_service_read="NOT_IMPLEMENTED",current_at_delivery="NOT_ESTABLISHED",response_authentication="NOT_PERFORMED; PRIOR MATH SEPARATE",
    root_provisioning="UNFILLED",service_nonrollback="NOT_IMPLEMENTED",checkpoint_storage="NOT_IMPLEMENTED",
    atomic_service_cas="NOT_IMPLEMENTED",atomic_work_entry="NOT_IMPLEMENTED",independent_assessment="UNFILLED",
    physical_power_loss="UNFILLED",preserved_core_source_outcomes=342,new_core_source_outcomes=0,
    actual_openings="COMPLETE REFERENCE STATES/CONTEXTS REQUIRED; NEVER RECONSTRUCTED FROM DESCRIPTORS")


def corpus():
    return dict(schema=PROFILE,research_baseline_commit=BASE,relation_controls=list(RELATIONS),refusal_controls=list(REFUSALS),
        unsafe_controls=list(UNSAFE),max_reference_events=ordering.MAX_EVENTS,max_trace_bytes=ordering.MAX_TRACE_BYTES,
        max_read_bytes=ordering.MAX_RECEIPT_BYTES,synthetic_notice="Finite public reference orders; no clock, durable storage or work entry",boundary=BOUNDARY)


def inputs(root=ROOT):
    _,preserved=prior.inputs(root)
    selected={name:sha((root/name).read_bytes()) for name in SELECTED}
    expected=dict(schema="ptlc-nom-checkpoint-read-ordering-manifest-v1",profile=PROFILE,research_baseline_commit=BASE,
        input_sha256=selected,preserved_file_sha256=preserved,boundary=BOUNDARY)
    if json.loads((root/FIXTURE).read_text('ascii'))!=corpus() or json.loads((root/MANIFEST).read_text('ascii'))!=expected:
        raise ValueError('selected checkpoint read ordering inputs changed')
    return expected,{**preserved,**selected,MANIFEST:sha((root/MANIFEST).read_bytes())}


def fixture_contexts(root=ROOT):
    policy,contexts,retained,refs=fixtures.fixture_contexts(root)
    return policy,contexts,retained,refs


def publish(trace,candidate):
    return ordering.publish_reference(trace,candidate,expected_state_digest_hex=trace.digest_hex)


def read(trace,selection):
    return ordering.evaluate_reference_read(trace,selection,expected_state_digest_hex=trace.digest_hex)


def inspect(local,trace,receipt):
    return ordering.inspect_ordered_reply(local,ordering.select_order_anchor(trace),receipt,
        discovery.discovery_reply(receipt._selection,receipt._opening),receipt._opening)


def qualify(root=ROOT):
    _,measured=inputs(root);policy,contexts,retained,refs=fixture_contexts(root)
    initial=ordering.bootstrap_order_trace(refs['initial'])
    latest=publish(initial,refs['latest']);tail=publish(latest,refs['tail'])
    queries={name:discovery.checkpoint_read(refs[minimum],challenge_hex=challenge*32) for name,minimum,challenge in
        (('first','initial','d1'),('later','latest','d2'),('fresh','initial','d3'),('local','initial','d4'),('uncharged','latest','d5'),('outage','initial','d6'))}
    initial_read,early=read(initial,queries['first'])
    early_later=publish(publish(initial_read,refs['latest']),refs['tail'])
    latest_read,middle=read(latest,queries['first']);middle_later=publish(latest_read,refs['tail'])
    tail_read,late=read(tail,queries['first'])
    minimum_read,later=read(tail,queries['later'])
    local_read,local=read(latest,queries['local'])
    uncharged=publish(latest,refs['uncharged']);uncharged_read,uncharged_receipt=read(uncharged,queries['uncharged'])
    results=dict(read_before_publish=inspect(contexts['primary'],early_later,early),
        publish_before_read=inspect(contexts['primary'],latest_read,middle),
        read_between_publishes=inspect(contexts['primary'],middle_later,middle),
        read_after_publishes=inspect(contexts['primary'],tail_read,late),
        later_minimum=inspect(contexts['primary'],minimum_read,later),local_ahead=inspect(contexts['third'],local_read,local),
        unavailable_source=inspect(contexts['unavailable'],latest_read,middle),
        extension_without_charge=inspect(contexts['primary'],uncharged_read,uncharged_receipt),
        outage=ordering.inspect_ordering_outage(contexts['primary'],ordering.select_order_anchor(tail),queries['outage'],discovery.unavailable_reply(queries['outage'])))
    for result in results.values():
        assert result['state']=='HOLD' and result['recovery_action']=='NONE' and result['worker_calls']==0
        assert not any(result[n] for n in ('new_work_allowed','automatic_retry','replenish_work','replacement_original_allowed','automatic_bootstrap'))
        assert result['current_at_delivery']=='NOT_ESTABLISHED' and result['service_nonrollback']=='NOT_IMPLEMENTED'
    refused=[]
    def refuse(name,operation):
        try:operation()
        except ValueError:refused.append(name)
        else:raise AssertionError('expected checkpoint read ordering refusal missing')
    refuse('stale_write_pin',lambda:ordering.publish_reference(latest_read,refs['tail'],expected_state_digest_hex=latest.digest_hex))
    refuse('skipped_publish',lambda:publish(initial,refs['tail']))
    refuse('regressed_publish',lambda:publish(latest,refs['initial']))
    refuse('sibling_publication',lambda:publish(latest,refs['sibling']))
    other_policy=protocol.select_service(contexts['primary'],service_id_hex='c2'*32,service_epoch=1,checkpoint_key_hex=policy.as_dict()['checkpoint_key_hex'])
    other_initial=protocol.bootstrap_reference(other_policy,contexts['primary'])
    other_latest=protocol.advance_reference(other_initial,contexts['extended'],expected_current_digest_hex=other_initial.digest_hex)
    refuse('changed_service',lambda:publish(initial,other_latest))
    view_initial=protocol.bootstrap_reference(policy,contexts['source_rotation'])
    view_latest=protocol.advance_reference(view_initial,contexts['extended'],expected_current_digest_hex=view_initial.digest_hex)
    refuse('changed_known_source_view',lambda:publish(initial,view_latest))
    restored_read,restored=read(initial,queries['fresh'])
    fresh_current,fresh_receipt=read(tail,queries['fresh'])
    refuse('old_read_after_newer_write',lambda:inspect(contexts['primary'],fresh_current,restored))
    sibling_state=publish(initial,refs['sibling']);sibling_read,sibling=read(sibling_state,queries['first'])
    refuse('forked_read',lambda:inspect(contexts['primary'],latest_read,sibling))
    refuse('anchor_before_read',lambda:inspect(contexts['primary'],latest,middle))
    refuse('duplicate_challenge',lambda:read(latest_read,queries['first']))
    old_opening=discovery.checkpoint_opening(refs['initial']);new_opening=discovery.checkpoint_opening(refs['latest'])
    refuse('reply_before_evaluation',lambda:ordering.inspect_ordered_reply(contexts['primary'],ordering.select_order_anchor(latest_read),middle,
        discovery.discovery_reply(queries['first'],old_opening),old_opening))
    refuse('reply_after_evaluation',lambda:ordering.inspect_ordered_reply(contexts['primary'],ordering.select_order_anchor(early_later),early,
        discovery.discovery_reply(queries['first'],new_opening),new_opening))
    packet=discovery.discovery_reply(queries['first'],middle._opening)
    anchor=ordering.select_order_anchor(latest_read)
    refuse('missing_actual_opening',lambda:ordering.inspect_ordered_reply(contexts['primary'],anchor,middle,packet,None))
    refuse('descriptor_only_anchor',lambda:ordering.inspect_ordered_reply(contexts['primary'],anchor.as_dict(),middle,packet,middle._opening))
    refuse('descriptor_only_read',lambda:ordering.inspect_ordered_reply(contexts['primary'],anchor,middle.as_dict(),packet,middle._opening))
    refuse('outage_cached_positive',lambda:ordering.inspect_ordered_reply(contexts['primary'],anchor,middle,discovery.unavailable_reply(queries['first']),middle._opening))
    unsafe={}
    unsafe['coherent_old_trace_and_anchor']=inspect(contexts['primary'],restored_read,restored)
    lost_history=ordering.bootstrap_order_trace(refs['latest']);lost_read,lost=read(lost_history,queries['fresh'])
    unsafe['bootstrap_after_lost_read_history']=inspect(contexts['primary'],lost_read,lost)
    left=inspect(contexts['primary'],latest_read,middle);right=inspect(contexts['divergent'],sibling_read,sibling)
    unsafe['independent_sibling_traces']=dict(left_head=left['candidate_checkpoint_digest_hex'],right_head=right['candidate_checkpoint_digest_hex'],
        same_checkpoint_sequence=left['candidate_sequence']==right['candidate_sequence'],shared_atomic_service_cas='NOT_IMPLEMENTED')
    unsafe['delivery_is_later_than_read']=results['read_between_publishes']
    return dict(schema='ptlc-nom-checkpoint-read-ordering-result-v1',profile=PROFILE,outcome='PASS',input_sha256=measured,
        complete_reference_inputs='ACTUAL FINITE ORIGINAL CONTEXTS; NO REOPENING FROM PUBLIC DESCRIPTORS',
        comparison_results=results,refusal_controls=refused,unsafe_controls=unsafe,
        reference_traces=dict(read_before_publish=early_later.as_dict(),read_between_publishes=middle_later.as_dict(),read_after_publishes=tail_read.as_dict()),
        reference_reads=dict(before_publish=early.as_dict(),between_publishes=middle.as_dict(),after_publishes=late.as_dict()),boundary=BOUNDARY)


def check_cases(value,root=ROOT):
    if codec._canonical(value)!=codec._canonical(qualify(root)):raise ValueError('complete checkpoint read ordering result changed')


def main():
    try:value=qualify()
    except (ValueError,TypeError,OSError,KeyError):
        print('selected checkpoint read ordering qualification refused',file=sys.stderr);return 1
    print(json.dumps(value,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
