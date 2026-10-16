"""Bounded public experiment bytes; they never reconstruct missing actual custody."""
import hashlib
import json

from offline_session import enrollment_contract as codec
from offline_session import nom_anchor_lifecycle as lifecycle
from offline_session import nom_checkpoint_read_ordering as ordering
from offline_session import nom_checkpoint_protocol as protocol

PROFILE = 'ptlc-nom-anchor-sqlite-comparison-v1'
MAX_STATE_BYTES = 2 * 1024**2
MAX_REQUEST_BYTES = 4 * 1024**2
MAX_CATALOG = 64
_INPUT_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError)


class MaterialRefused(ValueError):
    """Complete actual public reference material is unavailable; no retry verdict."""

def bounded(value, maximum):
    wire = codec._canonical(value)
    if not 0 < len(wire) <= maximum:
        raise ValueError('finite SQL comparison material exceeds selected bound')
    assert wire == codec._canonical(json.loads(wire)) and wire.isascii()
    return wire

def _anchor_bytes(anchor):
    if type(anchor) is not lifecycle.ReferenceAnchorState:
        raise ValueError('complete actual reference anchor required')
    lifecycle._Validation().anchor(anchor)
    catalog = {}

    def reference(value, seen=()):
        if type(value) is not protocol.ReferenceCheckpoint or id(value) in seen or len(seen) >= protocol.MAX_SNAPSHOTS:
            raise ValueError('complete finite checkpoint lineage required')
        prior = None if value._prior is None else reference(value._prior, seen + (id(value),))
        context = value._context
        complete = dict(checkpoint_hex=value.canonical_bytes.hex(), policy_hex=value._policy.canonical_bytes.hex(),
            source_context_hex=context.canonical_bytes.hex(), role_declaration_hex=context._declaration.canonical_bytes.hex(),
            capsule_hex=context._binding._capsule.canonical_bytes.hex(),
            original_read_query_hex=context._binding._query.canonical_bytes.hex(),
            original_source_claim_hex=context._claim_wire.hex(), prior=prior)
        raw = bounded(complete, MAX_STATE_BYTES)
        key = hashlib.sha256(b'ptlc-nom-sqlite-complete-opening-v1\0' + raw).hexdigest()
        if key in catalog and catalog[key] != complete:
            raise ValueError('complete opening key conflict')
        catalog[key] = complete
        if len(catalog) > MAX_CATALOG:
            raise ValueError('complete opening catalog bound exceeded')
        return key

    def trace(value):
        if type(value) is not ordering.CheckpointOrderTrace:
            raise ValueError('complete actual trace required')
        value.as_dict()
        events = []
        for event in value._events:
            if type(event) is ordering._Publish:
                events.append(dict(kind='PUBLISH', expected_state_digest_hex=event.expected_state_digest_hex,
                    candidate=reference(event.candidate)))
            elif type(event) is ordering._Read:
                events.append(dict(kind='READ', expected_state_digest_hex=event.expected_state_digest_hex,
                    complete_query_hex=event.selection.canonical_bytes.hex(),
                    minimum=reference(event.selection._minimum)))
            else:
                raise ValueError('unknown complete trace event')
        return dict(trace_hex=value.canonical_bytes.hex(), initial=reference(value._initial), events=events)

    initial = trace(anchor._initial)
    events = []
    for event in anchor._events:
        events.append(dict(kind=event.kind, transition_nonce_hex=event.transition_nonce_hex,
            expected_anchor_digest_hex=event.expected_anchor_digest_hex,
            trace=None if event.candidate is None else trace(event.candidate)))
    return bounded(dict(schema=PROFILE, purpose='complete-public-storage-comparison-only',
        anchor_hex=anchor.canonical_bytes.hex(), initial=initial, events=events, complete_openings=catalog,
        actual_custody='REQUIRED SEPARATELY; THESE BYTES ARE NOT AN ACTUAL-OBJECT DESERIALIZER',
        application='NO-GO', core='NO-GO', recovery_action='NONE'), MAX_STATE_BYTES)

def _request_material(request):
    if type(request) is not lifecycle.ReferenceAnchorTransition:
        raise ValueError('complete actual reference request required')
    description = request.as_dict()
    before = request._before
    after = lifecycle.commit_reference_anchor(before, request, expected_anchor_digest_hex=before.digest_hex)
    hold = lifecycle.retain_unknown_anchor_acknowledgment(request)
    before_wire, after_wire = anchor_bytes(before), anchor_bytes(after)
    wire = bounded(dict(schema=PROFILE, purpose='exact-reference-request-storage-only',
        reference_request_hex=request._wire.hex(), pending_hold_hex=hold._wire.hex(),
        complete_before_hex=before_wire.hex(), complete_after_hex=after_wire.hex(),
        publication_outcome='UNKNOWN', application='NO-GO', core='NO-GO', recovery_action='NONE'), MAX_REQUEST_BYTES)
    return dict(request_id=request.digest_hex, nonce=description['transition_nonce_hex'], kind=description['kind'],
        before=before_wire, request=wire, after=after_wire,
        before_revision=before.as_dict()['revision'], after_revision=after.as_dict()['revision'])


def anchor_bytes(anchor):
    """Compare complete actual custody; a descriptor or stored image cannot replace it."""
    try:
        return _anchor_bytes(anchor)
    except _INPUT_ERRORS:
        raise MaterialRefused('complete actual reference anchor material refused') from None


def request_material(request):
    """Retain the one actual request and both states without publication or work entry."""
    try:
        return _request_material(request)
    except _INPUT_ERRORS:
        raise MaterialRefused('complete actual reference request material refused') from None
