"""Finite reference order for checkpoint reads; no live service or durable anchor.

Actual complete states are retained before framing. Independently selecting the
trace is a caller premise. Coherent old trace/anchor restore still matches HOLD.
"""
from dataclasses import dataclass

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_checkpoint_discovery as discovery, nom_checkpoint_protocol as protocol


TRACE_SCHEMA = "ptlc-nom-checkpoint-read-order-trace-v1"
READ_SCHEMA = "ptlc-nom-checkpoint-ordered-read-v1"
ANCHOR_SCHEMA = "ptlc-nom-checkpoint-order-anchor-v1"
TRACE_DOMAIN = b"ptlc-nom-checkpoint-read-order-trace-v1"
READ_DOMAIN = b"ptlc-nom-checkpoint-ordered-read-v1"
EVENT_DOMAIN = b"ptlc-nom-checkpoint-read-order-event-v1"
MAX_EVENTS = 32
MAX_TRACE_BYTES = authority.MAX_WIRE_BYTES
MAX_RECEIPT_BYTES = 8192
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError)


class CheckpointReadOrderRefused(ValueError):
    """Sanitized reference ordering refusal; never a live currentness verdict."""


def _require(condition):
    if not condition:
        raise CheckpointReadOrderRefused("selected checkpoint read order refused")


def _hash(domain, value):
    return authority._digest(domain, codec._canonical(value))


def _decode(wire, limit):
    _require(type(wire) is bytes and 0 < len(wire) <= limit)
    value = authority._decode(wire)
    _require(wire == codec._canonical(value))
    return value


@dataclass(frozen=True)
class _Publish:
    candidate: protocol.ReferenceCheckpoint
    expected_state_digest_hex: str


@dataclass(frozen=True)
class _Read:
    selection: discovery.NoMCheckpointReadSelection
    expected_state_digest_hex: str


class _Validation:
    """Operation-local actual-input validation; never a persistent trust cache.

Each public operation starts fresh. Complete context replays are deduplicated
only within that pure operation, which invokes no foreign callback or I/O.
"""
    def __init__(self):
        self._openings, self._queries, self._traces = {}, {}, {}

    def opening(self, reference):
        _require(type(reference) is protocol.ReferenceCheckpoint)
        if id(reference) not in self._openings:
            self._openings[id(reference)] = discovery.checkpoint_opening(reference).as_dict()
        return self._openings[id(reference)]

    def query(self, selection):
        _require(type(selection) is discovery.NoMCheckpointReadSelection)
        if id(selection) not in self._queries:
            self._queries[id(selection)] = selection.as_dict()
        return self._queries[id(selection)]

    def lineage(self, selection, reference):
        query = self.query(selection)
        _require(reference._policy.canonical_bytes == selection._minimum._policy.canonical_bytes)
        complete, known = self.opening(reference), self.opening(selection._minimum)
        history, minimum = complete["checkpoint_lineage"], known["checkpoint_lineage"]
        _require(len(history) >= len(minimum) and codec._canonical(history[:len(minimum)]) == codec._canonical(minimum))
        _require(history[-1]["checkpoint"]["work_scope_digest_hex"] == query["work_scope_digest_hex"])
        return complete, history[-1]

    def state(self, trace):
        _require(type(trace) is CheckpointOrderTrace)
        if id(trace) not in self._traces:
            _decode(trace._wire, MAX_TRACE_BYTES)
            current, value = _evaluate(trace._initial, trace._events, self)
            _require(trace._wire == codec._canonical(value))
            self._traces[id(trace)] = current, _decode(trace._wire, MAX_TRACE_BYTES)
        return self._traces[id(trace)]


def _descriptor(initial, current, rows, validate):
    opening = validate.opening(current)
    return dict(schema=TRACE_SCHEMA, purpose="reference-read-order-only",
        service_selection=initial._policy.as_dict(),
        work_scope_digest_hex=validate.opening(initial)["checkpoint_lineage"][-1]["checkpoint"]["work_scope_digest_hex"],
        initial_opening=validate.opening(initial), events=rows,
        retained_head=opening["checkpoint_lineage"][-1], retained_opening_digest_hex=opening["opening_digest_hex"])


def _evaluate(initial, events, validate=None):
    validate = _Validation() if validate is None else validate
    _require(type(initial) is protocol.ReferenceCheckpoint and type(events) is tuple and len(events) <= MAX_EVENTS)
    validate.opening(initial)
    current, rows, challenges = initial, [], set()
    for number, event in enumerate(events, 1):
        _require(type(event) in (_Publish, _Read))
        codec._hex(event.expected_state_digest_hex)
        before = _hash(TRACE_DOMAIN, _descriptor(initial, current, rows, validate))
        _require(event.expected_state_digest_hex == before)
        if type(event) is _Publish:
            candidate = event.candidate
            _require(type(candidate) is protocol.ReferenceCheckpoint)
            _require(candidate._policy.canonical_bytes == initial._policy.canonical_bytes)
            old = validate.opening(current)["checkpoint_lineage"]
            complete = validate.opening(candidate)
            history = complete["checkpoint_lineage"]
            _require(len(history) == len(old)+1 and codec._canonical(history[:-1]) == codec._canonical(old))
            row = dict(event="PUBLISH", position=number, before_state_digest_hex=before, complete_opening=complete)
            current = candidate
        else:
            _require(type(event.selection) is discovery.NoMCheckpointReadSelection)
            query = validate.query(event.selection)
            _require(query["challenge_hex"] not in challenges)
            complete, head = validate.lineage(event.selection, current)
            row = dict(event="READ", position=number, before_state_digest_hex=before, complete_query=query,
                query_digest_hex=discovery._hash(discovery.QUERY_DOMAIN, query), evaluated_head=head,
                evaluated_opening_digest_hex=complete["opening_digest_hex"])
            challenges.add(query["challenge_hex"])
        rows.append(row)
    value = _descriptor(initial, current, rows, validate)
    _decode(codec._canonical(value), MAX_TRACE_BYTES)
    return current, value


@dataclass(frozen=True, init=False)
class CheckpointOrderTrace:
    """Functional complete event sequence; no shared CAS or storage operation."""
    _initial: protocol.ReferenceCheckpoint
    _events: tuple
    _wire: bytes

    def __init__(self):
        raise TypeError("use bootstrap_order_trace")

    def as_dict(self):
        try:
            _require(type(self) is CheckpointOrderTrace)
            _, value = _Validation().state(self)
            return value
        except _ERRORS:
            raise CheckpointReadOrderRefused("invalid complete checkpoint order trace") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _hash(TRACE_DOMAIN, self.as_dict())


def _freeze(initial, events, validate=None):
    _, value = _evaluate(initial, events, validate)
    result = object.__new__(CheckpointOrderTrace)
    for field, selected in (("_initial", initial), ("_events", events), ("_wire", codec._canonical(value))):
        object.__setattr__(result, field, selected)
    return result


def bootstrap_order_trace(reference):
    """Explicit research bootstrap; an old reference cannot certify safe absence."""
    try:
        return _freeze(reference, ())
    except _ERRORS:
        raise CheckpointReadOrderRefused("checkpoint order bootstrap refused") from None


def publish_reference(trace, candidate, *, expected_state_digest_hex):
    """Append exactly one complete lineage extension under a supplied state pin."""
    try:
        _require(type(trace) is CheckpointOrderTrace)
        validate = _Validation()
        validate.state(trace)
        return _freeze(trace._initial, trace._events+(_Publish(candidate, expected_state_digest_hex),), validate)
    except _ERRORS:
        raise CheckpointReadOrderRefused("checkpoint order publication refused") from None


def _read_description(before, after, selection, opening, validate=None):
    validate = _Validation() if validate is None else validate
    _require(type(before) is type(after) is CheckpointOrderTrace)
    _require(type(selection) is discovery.NoMCheckpointReadSelection)
    _require(type(opening) is discovery.NoMCheckpointEvidenceOpening)
    _, original = validate.state(before)
    _, value = validate.state(after)
    _require(len(after._events) == len(before._events)+1 and type(after._events[-1]) is _Read)
    _require(codec._canonical(original["initial_opening"]) == codec._canonical(value["initial_opening"]))
    _require(codec._canonical(value["events"][:-1]) == codec._canonical(original["events"]))
    event = value["events"][-1]
    query = validate.query(selection)
    _require(codec._canonical(event["complete_query"]) == codec._canonical(query))
    complete, head = validate.lineage(selection, opening._candidate)
    _require(codec._canonical(head) == codec._canonical(original["retained_head"]) == codec._canonical(event["evaluated_head"]))
    _require(complete["opening_digest_hex"] == original["retained_opening_digest_hex"] == event["evaluated_opening_digest_hex"])
    return dict(schema=READ_SCHEMA, purpose="selected-reference-read-instant-only", position=event["position"],
        before_state_digest_hex=_hash(TRACE_DOMAIN, original), after_state_digest_hex=_hash(TRACE_DOMAIN, value),
        event_digest_hex=_hash(EVENT_DOMAIN, event), complete_query=query, evaluated_head=head,
        evaluated_opening_digest_hex=complete["opening_digest_hex"])


@dataclass(frozen=True, init=False)
class OrderedCheckpointRead:
    """Actual complete before/after states and opening; descriptors cannot reopen."""
    _before: CheckpointOrderTrace
    _after: CheckpointOrderTrace
    _selection: discovery.NoMCheckpointReadSelection
    _opening: discovery.NoMCheckpointEvidenceOpening
    _wire: bytes

    def __init__(self):
        raise TypeError("use evaluate_reference_read")

    def as_dict(self):
        try:
            _require(type(self) is OrderedCheckpointRead)
            _decode(self._wire, MAX_RECEIPT_BYTES)
            expected = _read_description(self._before, self._after, self._selection, self._opening)
            _require(self._wire == codec._canonical(expected))
            return _decode(self._wire, MAX_RECEIPT_BYTES)
        except _ERRORS:
            raise CheckpointReadOrderRefused("invalid actual checkpoint read ordering") from None

    @property
    def digest_hex(self):
        return _hash(READ_DOMAIN, self.as_dict())


def evaluate_reference_read(trace, selection, *, expected_state_digest_hex):
    """Order a selected read after actual prior events, without signing or I/O."""
    try:
        _require(type(trace) is CheckpointOrderTrace)
        validate = _Validation()
        current, _ = validate.state(trace)
        after = _freeze(trace._initial, trace._events+(_Read(selection, expected_state_digest_hex),), validate)
        opening = discovery.checkpoint_opening(current)
        wire = codec._canonical(_read_description(trace, after, selection, opening, validate))
        _decode(wire, MAX_RECEIPT_BYTES)
        result = object.__new__(OrderedCheckpointRead)
        for field, value in (("_before", trace), ("_after", after), ("_selection", selection), ("_opening", opening), ("_wire", wire)):
            object.__setattr__(result, field, value)
        return after, result
    except _ERRORS:
        raise CheckpointReadOrderRefused("checkpoint reference read evaluation refused") from None


@dataclass(frozen=True, init=False)
class CheckpointOrderAnchor:
    """Independently supplied complete trace; not durable nonrollback protection."""
    _trace: CheckpointOrderTrace
    _wire: bytes

    def __init__(self):
        raise TypeError("use select_order_anchor")

    def as_dict(self):
        try:
            _require(type(self) is CheckpointOrderAnchor and type(self._trace) is CheckpointOrderTrace)
            _decode(self._wire, MAX_RECEIPT_BYTES)
            expected = _anchor_description(self._trace, _Validation())
            _require(self._wire == codec._canonical(expected))
            return _decode(self._wire, MAX_RECEIPT_BYTES)
        except _ERRORS:
            raise CheckpointReadOrderRefused("invalid selected checkpoint order anchor") from None


def _anchor_description(trace, validate):
    _, value = validate.state(trace)
    return dict(schema=ANCHOR_SCHEMA, purpose="independent-complete-reference-selection-only",
        trace_digest_hex=_hash(TRACE_DOMAIN, value), event_count=len(value["events"]),
        retained_head=value["retained_head"], retained_opening_digest_hex=value["retained_opening_digest_hex"])


def select_order_anchor(trace):
    """Select a full actual reference independently of reply/consumer snapshots."""
    try:
        _require(type(trace) is CheckpointOrderTrace)
        wire = codec._canonical(_anchor_description(trace, _Validation()))
        _decode(wire, MAX_RECEIPT_BYTES)
        result = object.__new__(CheckpointOrderAnchor)
        object.__setattr__(result, "_trace", trace)
        object.__setattr__(result, "_wire", wire)
        return result
    except _ERRORS:
        raise CheckpointReadOrderRefused("checkpoint order anchor selection refused") from None


def _retain_larger(local, anchor, validate):
    current, _ = validate.state(anchor._trace)
    relation, charged, _, _ = discovery._compare(local, current)
    return relation, charged


def inspect_ordered_reply(local, anchor, read, reply_wire, opening):
    """Match a read in an independently retained reference prefix; always HOLD.

Later publications do not invalidate its old read instant or make it current at
delivery. Coherently restoring the caller's anchor still matches: no store exists.
"""
    try:
        _require(type(anchor) is CheckpointOrderAnchor and type(read) is OrderedCheckpointRead)
        _decode(anchor._wire, MAX_RECEIPT_BYTES)
        _decode(read._wire, MAX_RECEIPT_BYTES)
        validate = _Validation()
        anchored = _anchor_description(anchor._trace, validate)
        _require(anchor._wire == codec._canonical(anchored))
        selected = _read_description(read._before, read._after, read._selection, read._opening, validate)
        _require(read._wire == codec._canonical(selected))
        _, retained = validate.state(anchor._trace)
        _, observed = validate.state(read._after)
        _require(codec._canonical(retained["service_selection"]) == codec._canonical(observed["service_selection"]))
        _require(retained["work_scope_digest_hex"] == observed["work_scope_digest_hex"])
        _require(codec._canonical(retained["initial_opening"]) == codec._canonical(observed["initial_opening"]))
        _require(len(retained["events"]) >= len(observed["events"]))
        _require(codec._canonical(retained["events"][:len(observed["events"])]) == codec._canonical(observed["events"]))
        _require(type(opening) is discovery.NoMCheckpointEvidenceOpening)
        _require(codec._canonical(validate.opening(opening._candidate)) == codec._canonical(validate.opening(read._opening._candidate)))
        comparison = discovery.inspect_discovery(local, read._selection, reply_wire, opening)
        _require(comparison["candidate_checkpoint_digest_hex"] == selected["evaluated_head"]["checkpoint_digest_hex"])
        relation, charged = _retain_larger(local, anchor, validate)
        comparison.update(effective_charged_work=charged, reference_retention_relation=relation,
            reference_read_order="MATCHES COMPLETE INDEPENDENTLY SELECTED REFERENCE PREFIX",
            ordered_read_digest_hex=_hash(READ_DOMAIN, selected), evaluated_event_position=selected["position"],
            retained_event_count=anchored["event_count"], later_reference_events=anchored["event_count"]-selected["position"],
            retained_trace_digest_hex=anchored["trace_digest_hex"], current_at_delivery="NOT_ESTABLISHED",
            current_service_read="REFERENCE ORDER ONLY; INDEPENDENT TRACE SELECTION IS A CALLER PREMISE",
            response_authentication="NOT_PERFORMED; PRIOR SIGNATURE MATHEMATICS IS SEPARATE",
            service_nonrollback="NOT_IMPLEMENTED", checkpoint_storage="NOT_IMPLEMENTED", atomic_service_cas="NOT_IMPLEMENTED",
            new_core_source_outcomes=0, physical_power_loss="UNFILLED")
        return comparison
    except _ERRORS:
        raise CheckpointReadOrderRefused("checkpoint ordered reply comparison refused") from None


def inspect_ordering_outage(local, anchor, selection, reply_wire):
    """Outage has no read receipt or cached positive opening and grants no work."""
    try:
        _require(type(anchor) is CheckpointOrderAnchor and type(selection) is discovery.NoMCheckpointReadSelection)
        _decode(anchor._wire, MAX_RECEIPT_BYTES)
        validate = _Validation()
        anchored = _anchor_description(anchor._trace, validate)
        _require(anchor._wire == codec._canonical(anchored))
        current, _ = validate.state(anchor._trace)
        validate.lineage(selection, current)
        result = discovery.inspect_discovery(local, selection, reply_wire, None)
        _require(result["candidate_checkpoint_digest_hex"] is None)
        relation, charged = _retain_larger(local, anchor, validate)
        result.update(effective_charged_work=charged, reference_retention_relation=relation,
            reference_read_order="NOT_ESTABLISHED; OUTAGE CREATES NO READ EVENT", current_at_delivery="NOT_ESTABLISHED",
            current_service_read="NOT_ESTABLISHED", new_core_source_outcomes=0, physical_power_loss="UNFILLED")
        return result
    except _ERRORS:
        raise CheckpointReadOrderRefused("checkpoint ordering outage comparison refused") from None
