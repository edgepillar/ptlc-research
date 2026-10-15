#!/usr/bin/env python3
"""Qualify exact reference anchor requests and lost acknowledgments; no store."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import enrollment_contract as codec  # noqa: E402
from offline_session import nom_anchor_lifecycle as lifecycle  # noqa: E402
from offline_session import nom_checkpoint_read_ordering as ordering  # noqa: E402
from offline_session import nom_checkpoint_discovery as discovery  # noqa: E402
from offline_session import nom_checkpoint_protocol as protocol  # noqa: E402
from scripts import qualify_nom_checkpoint_read_ordering as prior  # noqa: E402
from scripts.nom_cut_capture import sha  # noqa: E402

PROFILE = "ptlc-nom-anchor-lifecycle-qualification-v1"
BASE = "6e7e629a199b8e2cba79fbba3aeb288fb3ea5c3c"
MANIFEST = "compatibility/nom_anchor_lifecycle_manifest.json"
FIXTURE = "compatibility/fixtures/nom_anchor_lifecycle_v1.json"
SELECTED = ("offline_session/nom_anchor_lifecycle.py", "scripts/qualify_nom_anchor_lifecycle.py",
    "tests/test_nom_anchor_lifecycle.py", FIXTURE)
RELATIONS = ("ack_lost_before_reference_commit", "ack_lost_after_reference_commit",
    "lookup_after_later_reference_update", "retirement_request_found", "lookup_after_retirement",
    "larger_local_unknown", "unavailable_source_context", "anchor_outage")
REFUSALS = ("stale_prepare_pin", "stale_commit_pin", "duplicate_commit", "nonce_reuse", "skipped_order_event",
    "regressed_order_trace", "forked_order_trace", "changed_anchor_identity", "changed_anchor_epoch",
    "changed_source_service", "descriptor_only_request", "descriptor_only_hold", "descriptor_only_anchor",
    "missing_actual_trace", "conflicting_next_request", "restored_independent_anchor", "update_after_retirement",
    "retirement_after_retirement")
UNSAFE = ("coherent_old_anchor_and_hold", "cloned_expected_state", "explicit_reenrollment_after_retirement",
    "restored_pre_retirement_anchor")
BOUNDARY = dict(application="NO-GO", core="NO-GO", recovery_action="NONE", lifecycle_worker_calls=0,
    additional_signature_requests=0, new_core_source_outcomes=0, preserved_core_source_outcomes=342,
    lifecycle="FUNCTIONAL COMPLETE REFERENCE HISTORY ONLY", current_anchor_authentication="NOT_ESTABLISHED",
    publication_outcome="UNKNOWN", checkpoint_storage="NOT_IMPLEMENTED", service_nonrollback="NOT_IMPLEMENTED",
    shared_atomic_cas="NOT_IMPLEMENTED", atomic_work_entry="NOT_IMPLEMENTED", authority_provisioning="UNFILLED",
    independent_assessment="UNFILLED", physical_power_loss="UNFILLED", automatic_republication=False,
    actual_custody="COMPLETE ACTUAL TRACE AND REQUEST REQUIRED; NO DESCRIPTOR REOPENING")


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE, relation_controls=list(RELATIONS),
        refusal_controls=list(REFUSALS), unsafe_controls=list(UNSAFE), max_transitions=lifecycle.MAX_TRANSITIONS,
        max_state_bytes=lifecycle.MAX_STATE_BYTES, max_request_bytes=lifecycle.MAX_REQUEST_BYTES,
        synthetic_notice="Public finite lifecycle comparisons; no actual store, dispatch, acknowledgment or work entry",
        boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name:sha((root/name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-anchor-lifecycle-manifest-v1", profile=PROFILE, research_baseline_commit=BASE,
        input_sha256=selected, preserved_file_sha256=preserved, boundary=BOUNDARY)
    if json.loads((root/FIXTURE).read_text('ascii')) != corpus() or json.loads((root/MANIFEST).read_text('ascii')) != expected:
        raise ValueError('selected anchor lifecycle inputs changed')
    return expected, {**preserved, **selected, MANIFEST:sha((root/MANIFEST).read_bytes())}


def advance(anchor, trace, nonce):
    return lifecycle.prepare_anchor_advance(anchor, trace, transition_nonce_hex=nonce*32,
        expected_anchor_digest_hex=anchor.digest_hex)


def retire(anchor, nonce):
    return lifecycle.prepare_anchor_retirement(anchor, transition_nonce_hex=nonce*32,
        expected_anchor_digest_hex=anchor.digest_hex)


def commit(anchor, request):
    return lifecycle.commit_reference_anchor(anchor, request, expected_anchor_digest_hex=anchor.digest_hex)


def fixture_contexts(root=ROOT):
    policy, contexts, retained, refs = prior.fixture_contexts(root)
    first = ordering.bootstrap_order_trace(refs['initial'])
    second = prior.publish(first, refs['latest'])
    query = discovery.checkpoint_read(refs['initial'], challenge_hex='e6'*32)
    read_trace, read = prior.read(second, query)
    third = prior.publish(read_trace, refs['tail'])
    initial = lifecycle.bootstrap_reference_anchor(first, anchor_id_hex='e1'*32, anchor_epoch=1)
    request = advance(initial, second, 'e2'); active = commit(initial, request)
    read_request = advance(active, read_trace, 'e3'); after_read = commit(active, read_request)
    third_request = advance(after_read, third, 'e4'); after_third = commit(after_read, third_request)
    retirement = retire(after_third, 'e5'); retired = commit(after_third, retirement)
    return dict(policy=policy, contexts=contexts, retained=retained, refs=refs,
        traces=dict(initial=first, second=second, read=read_trace, third=third), read=read,
        anchors=dict(initial=initial, active=active, after_read=after_read, after_third=after_third, retired=retired),
        requests=dict(first=request, read=read_request, third=third_request, retirement=retirement),
        holds=dict(first=lifecycle.retain_unknown_anchor_acknowledgment(request),
            read=lifecycle.retain_unknown_anchor_acknowledgment(read_request),
            retirement=lifecycle.retain_unknown_anchor_acknowledgment(retirement)))


def inspect(fixtures, anchor='active', hold='first', local='primary'):
    return lifecycle.inspect_anchor_acknowledgment(fixtures['contexts'][local], fixtures['holds'][hold], fixtures['anchors'][anchor])


def qualify(root=ROOT):
    _, measured = inputs(root); f = fixture_contexts(root)
    a, t, requests = f['anchors'], f['traces'], f['requests']
    results = dict(ack_lost_before_reference_commit=inspect(f, 'initial'), ack_lost_after_reference_commit=inspect(f),
        lookup_after_later_reference_update=inspect(f, 'after_third'), retirement_request_found=inspect(f, 'retired', 'retirement'),
        lookup_after_retirement=inspect(f, 'retired'), larger_local_unknown=inspect(f, local='third'),
        unavailable_source_context=inspect(f, local='unavailable'),
        anchor_outage=lifecycle.inspect_anchor_acknowledgment_outage(f['contexts']['primary'], f['holds']['first']))
    for value in results.values():
        assert value['state']=='HOLD' and value['recovery_action']=='NONE' and value['publication_outcome']=='UNKNOWN'
        assert not any(value[n] for n in ('new_work_allowed','automatic_retry','same_request_republication',
            'replenish_work','replacement_original_allowed','automatic_bootstrap','automatic_reenrollment'))
        assert all(row['outcome']=='UNKNOWN' for row in value['effective_charged_work'])
    refused = []
    def refuse(name, operation):
        try:operation()
        except ValueError:refused.append(name)
        else:raise AssertionError('expected anchor lifecycle refusal missing')
    refuse('stale_prepare_pin',lambda:lifecycle.prepare_anchor_advance(a['active'],t['read'],transition_nonce_hex='e7'*32,
        expected_anchor_digest_hex=a['initial'].digest_hex))
    refuse('stale_commit_pin',lambda:lifecycle.commit_reference_anchor(a['initial'],requests['first'],expected_anchor_digest_hex='00'*32))
    refuse('duplicate_commit',lambda:commit(a['active'],requests['first']))
    refuse('nonce_reuse',lambda:advance(a['active'],t['read'],'e2'))
    refuse('skipped_order_event',lambda:advance(a['initial'],t['read'],'e7'))
    refuse('regressed_order_trace',lambda:advance(a['active'],t['initial'],'e7'))
    sibling = prior.publish(t['initial'],f['refs']['sibling'])
    refuse('forked_order_trace',lambda:advance(a['active'],sibling,'e7'))
    other = lifecycle.bootstrap_reference_anchor(t['initial'],anchor_id_hex='f1'*32,anchor_epoch=1)
    refuse('changed_anchor_identity',lambda:lifecycle.inspect_anchor_acknowledgment(f['contexts']['primary'],f['holds']['first'],other))
    other_epoch = lifecycle.bootstrap_reference_anchor(t['initial'],anchor_id_hex='e1'*32,anchor_epoch=2)
    refuse('changed_anchor_epoch',lambda:lifecycle.inspect_anchor_acknowledgment(f['contexts']['primary'],f['holds']['first'],other_epoch))
    other_policy = protocol.select_service(f['contexts']['primary'],service_id_hex='f2'*32,service_epoch=1,
        checkpoint_key_hex=f['policy'].as_dict()['checkpoint_key_hex'])
    other_start = protocol.bootstrap_reference(other_policy,f['contexts']['primary'])
    other_next = protocol.advance_reference(other_start,f['contexts']['extended'],expected_current_digest_hex=other_start.digest_hex)
    other_trace = prior.publish(ordering.bootstrap_order_trace(other_start),other_next)
    refuse('changed_source_service',lambda:advance(a['initial'],other_trace,'e7'))
    refuse('descriptor_only_request',lambda:commit(a['initial'],requests['first'].as_dict()))
    refuse('descriptor_only_hold',lambda:lifecycle.inspect_anchor_acknowledgment(f['contexts']['primary'],f['holds']['first'].as_dict(),a['active']))
    refuse('descriptor_only_anchor',lambda:lifecycle.inspect_anchor_acknowledgment(f['contexts']['primary'],f['holds']['first'],a['active'].as_dict()))
    refuse('missing_actual_trace',lambda:advance(a['initial'],t['second'].as_dict(),'e7'))
    competing = advance(a['initial'],t['second'],'e8'); competing_anchor = commit(a['initial'],competing)
    refuse('conflicting_next_request',lambda:lifecycle.inspect_anchor_acknowledgment(f['contexts']['primary'],f['holds']['first'],competing_anchor))
    refuse('restored_independent_anchor',lambda:inspect(f,'initial','read'))
    refuse('update_after_retirement',lambda:advance(a['retired'],t['third'],'e7'))
    refuse('retirement_after_retirement',lambda:retire(a['retired'],'e7'))
    reenrolled = lifecycle.bootstrap_reference_anchor(t['third'],anchor_id_hex='f3'*32,anchor_epoch=2)
    resumed = commit(a['active'],requests['read'])
    unsafe = dict(coherent_old_anchor_and_hold=inspect(f),
        cloned_expected_state=dict(left=a['active'].as_dict(),right=competing_anchor.as_dict(),shared_atomic_cas='NOT_IMPLEMENTED'),
        explicit_reenrollment_after_retirement=dict(old=a['retired'].as_dict(),new=reenrolled.as_dict(),prior_tombstone_provisioning='UNFILLED'),
        restored_pre_retirement_anchor=dict(restored=a['active'].as_dict(),resumed=resumed.as_dict(),hidden_retired=a['retired'].as_dict()))
    return dict(schema='ptlc-nom-anchor-lifecycle-result-v1',profile=PROFILE,outcome='PASS',input_sha256=measured,
        comparison_results=results,refusal_controls=refused,unsafe_controls=unsafe,
        actual_reference_custody='COMPLETE BEFORE STATES, REQUESTS AND ORDERED TRACES; NO DESCRIPTOR REOPENING',
        reference_lifecycle=dict(initial=a['initial'].as_dict(),active=a['active'].as_dict(),retired=a['retired'].as_dict()),
        reference_requests={name:value.as_dict() for name,value in requests.items()},
        reference_holds={name:value.as_dict() for name,value in f['holds'].items()},boundary=BOUNDARY)


def check_cases(value, root=ROOT):
    if codec._canonical(value) != codec._canonical(qualify(root)):
        raise ValueError('complete anchor lifecycle result changed')


def main():
    try:value=qualify()
    except (ValueError,TypeError,OSError,KeyError):
        print('selected anchor lifecycle qualification refused',file=sys.stderr);return 1
    print(json.dumps(value,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
