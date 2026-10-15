"""Finite anchor lifecycle and lost-acknowledgment comparisons; always HOLD.

The caller selects the complete independent reference. No nonrollback store,
service, authenticated acknowledgment, shared CAS or original work is implemented.
"""
from dataclasses import dataclass

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_checkpoint_read_ordering as ordering
from . import nom_checkpoint_discovery as discovery


STATE_SCHEMA = "ptlc-nom-reference-anchor-lifecycle-v1"
REQUEST_SCHEMA = "ptlc-nom-reference-anchor-transition-v1"
HOLD_SCHEMA = "ptlc-nom-anchor-acknowledgment-hold-v1"
STATE_DOMAIN = b"ptlc-nom-reference-anchor-lifecycle-v1"
REQUEST_DOMAIN = b"ptlc-nom-reference-anchor-transition-v1"
HOLD_DOMAIN = b"ptlc-nom-anchor-acknowledgment-hold-v1"
MAX_TRANSITIONS = 16
MAX_STATE_BYTES = authority.MAX_WIRE_BYTES
MAX_REQUEST_BYTES = 8192
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError)


class AnchorLifecycleRefused(ValueError):
    """Sanitized reference refusal; never a recovery or absence verdict."""


def _require(condition):
    if not condition:
        raise AnchorLifecycleRefused("selected anchor lifecycle refused")


def _hash(domain, value):
    return authority._digest(domain, codec._canonical(value))


def _decode(wire, limit):
    _require(type(wire) is bytes and 0 < len(wire) <= limit)
    value = authority._decode(wire)
    _require(wire == codec._canonical(value))
    return value


@dataclass(frozen=True)
class _Transition:
    kind: str
    candidate: object
    transition_nonce_hex: str
    expected_anchor_digest_hex: str


class _Validation:
    """Actual-input validation deduplicated only inside one pure operation."""
    def __init__(self):
        self.order = ordering._Validation()
        self.anchors, self.requests = {}, {}

    def trace(self, trace):
        _require(type(trace) is ordering.CheckpointOrderTrace)
        return self.order.state(trace)

    def anchor(self, anchor):
        _require(type(anchor) is ReferenceAnchorState)
        if id(anchor) not in self.anchors:
            _decode(anchor._wire, MAX_STATE_BYTES)
            current, value = _evaluate(anchor._initial, anchor._anchor_id_hex,
                anchor._anchor_epoch, anchor._events, self)
            _require(anchor._wire == codec._canonical(value))
            self.anchors[id(anchor)] = current, value
        return self.anchors[id(anchor)]

    def request(self, request):
        _require(type(request) is ReferenceAnchorTransition)
        if id(request) not in self.requests:
            _decode(request._wire, MAX_REQUEST_BYTES)
            current, value = self.anchor(request._before)
            expected, candidate = _request_description(current, value, request._transition, self)
            _require(request._wire == codec._canonical(expected))
            self.requests[id(request)] = expected, candidate
        return self.requests[id(request)]


def _trace_summary(trace, validate):
    _, value = validate.trace(trace)
    return dict(trace_digest_hex=ordering._hash(ordering.TRACE_DOMAIN, value),
        event_count=len(value["events"]), checkpoint_digest_hex=value["retained_head"]["checkpoint_digest_hex"],
        checkpoint_sequence=value["retained_head"]["checkpoint"]["sequence"],
        opening_digest_hex=value["retained_opening_digest_hex"])


def _selection(initial, anchor_id_hex, anchor_epoch, validate):
    codec._hex(anchor_id_hex)
    authority._number(anchor_epoch, positive=True)
    _, value = validate.trace(initial)
    return dict(anchor_id_hex=anchor_id_hex, anchor_epoch=anchor_epoch,
        service_selection=value["service_selection"], work_scope_digest_hex=value["work_scope_digest_hex"],
        initial_trace=_trace_summary(initial, validate), max_transitions=MAX_TRANSITIONS)


def _descriptor(selection, current, rows, phase, validate):
    return dict(schema=STATE_SCHEMA, purpose="selected-reference-anchor-lifecycle-only",
        selection=selection, revision=len(rows), phase=phase, transitions=rows,
        current_trace=_trace_summary(current, validate))


def _next_trace(current, candidate, validate):
    _require(type(candidate) is ordering.CheckpointOrderTrace)
    _, before = validate.trace(current)
    _, after = validate.trace(candidate)
    for field in ("service_selection", "work_scope_digest_hex", "initial_opening"):
        _require(codec._canonical(before[field]) == codec._canonical(after[field]))
    _require(len(after["events"]) == len(before["events"])+1)
    _require(codec._canonical(after["events"][:-1]) == codec._canonical(before["events"]))
    return candidate


def _request_description(current, value, transition, validate):
    _require(type(transition) is _Transition and value["phase"] == "ACTIVE")
    _require(len(value["transitions"]) < MAX_TRANSITIONS)
    _require(type(transition.kind) is str and transition.kind in ("ADVANCE", "RETIRE"))
    codec._hex(transition.transition_nonce_hex)
    codec._hex(transition.expected_anchor_digest_hex)
    _require(transition.expected_anchor_digest_hex == _hash(STATE_DOMAIN, value))
    _require(transition.transition_nonce_hex not in [row["transition_nonce_hex"] for row in value["transitions"]])
    if transition.kind == "ADVANCE":
        candidate = _next_trace(current, transition.candidate, validate)
    else:
        _require(transition.candidate is None)
        candidate = current
    return dict(schema=REQUEST_SCHEMA, purpose="exact-reference-transition-only", selection=value["selection"],
        kind=transition.kind, transition_nonce_hex=transition.transition_nonce_hex,
        expected_anchor_digest_hex=transition.expected_anchor_digest_hex,
        before_trace=_trace_summary(current, validate), next_trace=_trace_summary(candidate, validate)), candidate


def _evaluate(initial, anchor_id_hex, anchor_epoch, events, validate):
    _require(type(events) is tuple and len(events) <= MAX_TRANSITIONS)
    selected = _selection(initial, anchor_id_hex, anchor_epoch, validate)
    current, rows, phase = initial, [], "ACTIVE"
    for number, event in enumerate(events, 1):
        before = _descriptor(selected, current, rows, phase, validate)
        request, candidate = _request_description(current, before, event, validate)
        rows.append(dict(position=number, kind=event.kind, transition_nonce_hex=event.transition_nonce_hex,
            expected_anchor_digest_hex=event.expected_anchor_digest_hex,
            request_digest_hex=_hash(REQUEST_DOMAIN, request), next_trace=request["next_trace"]))
        current = candidate
        if event.kind == "RETIRE":
            phase = "RETIRED"
    value = _descriptor(selected, current, rows, phase, validate)
    _decode(codec._canonical(value), MAX_STATE_BYTES)
    return current, value


@dataclass(frozen=True, init=False)
class ReferenceAnchorState:
    """Complete functional history; independent nonrollback selection is a premise."""
    _initial: ordering.CheckpointOrderTrace
    _anchor_id_hex: str
    _anchor_epoch: int
    _events: tuple
    _wire: bytes

    def __init__(self):
        raise TypeError("use bootstrap_reference_anchor")

    def as_dict(self):
        try:
            return _Validation().anchor(self)[1]
        except _ERRORS:
            raise AnchorLifecycleRefused("invalid complete reference anchor") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _hash(STATE_DOMAIN, self.as_dict())


def _freeze(initial, anchor_id_hex, anchor_epoch, events, validate):
    _, value = _evaluate(initial, anchor_id_hex, anchor_epoch, events, validate)
    result = object.__new__(ReferenceAnchorState)
    for field, selected in (("_initial", initial), ("_anchor_id_hex", anchor_id_hex),
        ("_anchor_epoch", anchor_epoch), ("_events", events), ("_wire", codec._canonical(value))):
        object.__setattr__(result, field, selected)
    return result


def bootstrap_reference_anchor(initial_trace, *, anchor_id_hex, anchor_epoch):
    """Explicit research enrollment; neither safe absence nor independent provisioning."""
    try:
        return _freeze(initial_trace, anchor_id_hex, anchor_epoch, (), _Validation())
    except _ERRORS:
        raise AnchorLifecycleRefused("reference anchor enrollment refused") from None


@dataclass(frozen=True, init=False)
class ReferenceAnchorTransition:
    """Exact complete before-state and proposed trace; a digest cannot reconstruct it."""
    _before: ReferenceAnchorState
    _transition: _Transition
    _wire: bytes

    def __init__(self):
        raise TypeError("use prepare_anchor_advance or prepare_anchor_retirement")

    def as_dict(self):
        try:
            return _Validation().request(self)[0]
        except _ERRORS:
            raise AnchorLifecycleRefused("invalid complete anchor transition") from None

    @property
    def digest_hex(self):
        return _hash(REQUEST_DOMAIN, self.as_dict())


def _prepare(anchor, candidate, kind, transition_nonce_hex, expected_anchor_digest_hex):
    validate = _Validation()
    current, value = validate.anchor(anchor)
    transition = _Transition(kind, candidate, transition_nonce_hex, expected_anchor_digest_hex)
    request, _ = _request_description(current, value, transition, validate)
    wire = codec._canonical(request)
    _decode(wire, MAX_REQUEST_BYTES)
    result = object.__new__(ReferenceAnchorTransition)
    for field, selected in (("_before", anchor), ("_transition", transition), ("_wire", wire)):
        object.__setattr__(result, field, selected)
    return result


def prepare_anchor_advance(anchor, next_trace, *, transition_nonce_hex, expected_anchor_digest_hex):
    """Bind exactly one complete ordered event and the full preceding anchor state."""
    try:
        return _prepare(anchor, next_trace, "ADVANCE", transition_nonce_hex, expected_anchor_digest_hex)
    except _ERRORS:
        raise AnchorLifecycleRefused("anchor advance preparation refused") from None


def prepare_anchor_retirement(anchor, *, transition_nonce_hex, expected_anchor_digest_hex):
    """Prepare an irreversible reference tombstone retaining all actual history."""
    try:
        return _prepare(anchor, None, "RETIRE", transition_nonce_hex, expected_anchor_digest_hex)
    except _ERRORS:
        raise AnchorLifecycleRefused("anchor retirement preparation refused") from None


def commit_reference_anchor(anchor, request, *, expected_anchor_digest_hex):
    """Functional expected-state transition; no live shared CAS or acknowledgment."""
    try:
        validate = _Validation()
        _, current = validate.anchor(anchor)
        value, _ = validate.request(request)
        codec._hex(expected_anchor_digest_hex)
        _require(expected_anchor_digest_hex == value["expected_anchor_digest_hex"] == _hash(STATE_DOMAIN, current))
        _require(anchor._wire == request._before._wire)
        return _freeze(anchor._initial, anchor._anchor_id_hex, anchor._anchor_epoch,
            anchor._events+(request._transition,), validate)
    except _ERRORS:
        raise AnchorLifecycleRefused("reference anchor commit refused") from None


def _hold_description(request, validate):
    value, _ = validate.request(request)
    return dict(schema=HOLD_SCHEMA, purpose="lost-acknowledgment-retention-only",
        request_digest_hex=_hash(REQUEST_DOMAIN, value), transition_nonce_hex=value["transition_nonce_hex"],
        expected_anchor_digest_hex=value["expected_anchor_digest_hex"], next_trace=value["next_trace"],
        publication_outcome="UNKNOWN", disclosure_possible=True, work_permission=False)


@dataclass(frozen=True, init=False)
class AnchorAcknowledgmentHold:
    """Actual complete pending request; missing replies never mean safe absence."""
    _request: ReferenceAnchorTransition
    _wire: bytes

    def __init__(self):
        raise TypeError("use retain_unknown_anchor_acknowledgment")

    def as_dict(self):
        try:
            return _validated_hold(self, _Validation())
        except _ERRORS:
            raise AnchorLifecycleRefused("invalid complete acknowledgment hold") from None

    @property
    def digest_hex(self):
        return _hash(HOLD_DOMAIN, self.as_dict())


def _validated_hold(hold, validate):
    _require(type(hold) is AnchorAcknowledgmentHold)
    _decode(hold._wire, MAX_REQUEST_BYTES)
    expected = _hold_description(hold._request, validate)
    _require(hold._wire == codec._canonical(expected))
    return expected


def retain_unknown_anchor_acknowledgment(request):
    """Record a caller-declared possible publication; dispatch is not performed."""
    try:
        wire = codec._canonical(_hold_description(request, _Validation()))
        _decode(wire, MAX_REQUEST_BYTES)
        result = object.__new__(AnchorAcknowledgmentHold)
        object.__setattr__(result, "_request", request)
        object.__setattr__(result, "_wire", wire)
        return result
    except _ERRORS:
        raise AnchorLifecycleRefused("unknown anchor acknowledgment retention refused") from None


def _inspection(local, hold, possible_trace, relation, anchor_value, validate):
    current, _ = validate.trace(possible_trace)
    journal_relation, charged, _, _ = discovery._compare(local, current)
    return dict(schema="ptlc-nom-anchor-lifecycle-inspection-v1", state="HOLD", recovery_action="NONE",
        application="NO-GO", core="NO-GO", reference_acknowledgment_relation=relation,
        held_request_digest_hex=hold["request_digest_hex"], publication_outcome="UNKNOWN", disclosure_possible=True,
        reference_anchor_digest_hex=None if anchor_value is None else _hash(STATE_DOMAIN, anchor_value),
        reference_anchor_revision=None if anchor_value is None else anchor_value["revision"],
        reference_anchor_phase=None if anchor_value is None else anchor_value["phase"],
        effective_charged_work=charged, reference_retention_relation=journal_relation,
        new_work_allowed=False, automatic_retry=False, same_request_republication=False,
        replenish_work=False, replacement_original_allowed=False, automatic_bootstrap=False, automatic_reenrollment=False,
        worker_calls=0, additional_signature_requests=0, new_core_source_outcomes=0,
        current_anchor_authenticated="NOT_ESTABLISHED", current_at_delivery="NOT_ESTABLISHED",
        reference_cas="FUNCTIONAL EXPECTED STATE ONLY", service_nonrollback="NOT_IMPLEMENTED",
        checkpoint_storage="NOT_IMPLEMENTED", atomic_work_entry="NOT_IMPLEMENTED", physical_power_loss="UNFILLED")


def inspect_anchor_acknowledgment(local, hold, independently_selected_anchor):
    """Look up one exact retained request without dispatch, retry or replenishment.

A matching reference record is not an operational acknowledgment. An unchanged
reference proves no real absence. A different selected continuation refuses.
"""
    try:
        validate = _Validation()
        held = _validated_hold(hold, validate)
        request, proposed = validate.request(hold._request)
        _, before = validate.anchor(hold._request._before)
        current, retained = validate.anchor(independently_selected_anchor)
        _require(codec._canonical(before["selection"]) == codec._canonical(retained["selection"]))
        prefix, rows = before["transitions"], retained["transitions"]
        _require(len(rows) >= len(prefix) and codec._canonical(rows[:len(prefix)]) == codec._canonical(prefix))
        if len(rows) == len(prefix):
            relation, possible = "REFERENCE_REQUEST_NOT_FOUND", proposed
        else:
            _require(rows[len(prefix)]["request_digest_hex"] == _hash(REQUEST_DOMAIN, request))
            relation, possible = "EXACT_RETAINED_REFERENCE_REQUEST", current
        return _inspection(local, held, possible, relation, retained, validate)
    except _ERRORS:
        raise AnchorLifecycleRefused("anchor acknowledgment comparison refused") from None


def inspect_anchor_acknowledgment_outage(local, hold):
    """No anchor, cached positive record or absence claim is inferred from outage."""
    try:
        validate = _Validation()
        held = _validated_hold(hold, validate)
        _, proposed = validate.request(hold._request)
        return _inspection(local, held, proposed, "UNAVAILABLE; NO CURRENT ANCHOR OR ABSENCE CLAIM", None, validate)
    except _ERRORS:
        raise AnchorLifecycleRefused("anchor acknowledgment outage comparison refused") from None
