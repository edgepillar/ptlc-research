"""Minimum-bound checkpoint discovery over complete retained reference openings.

Candidates are untrusted. Exact lineage and public message framing establish no
authenticated current service, nonrollback storage or application work permission.
"""
from dataclasses import dataclass

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_checkpoint_protocol as protocol


QUERY_SCHEMA = "ptlc-nom-checkpoint-discovery-query-v1"
REPLY_SCHEMA = "ptlc-nom-checkpoint-discovery-reply-v1"
MESSAGE_SCHEMA = "ptlc-nom-checkpoint-discovery-message-v1"
QUERY_DOMAIN = b"ptlc-nom-checkpoint-discovery-query-v1"
CONTEXT_DOMAIN = b"ptlc-nom-checkpoint-discovery-source-context-v1"
OPENING_DOMAIN = b"ptlc-nom-checkpoint-discovery-opening-v1"
MESSAGE_DOMAIN = b"ptlc-nom-checkpoint-discovery-response-message-v1"
MAX_WIRE_BYTES = authority.MAX_WIRE_BYTES
MAX_CHECKPOINTS = protocol.MAX_SNAPSHOTS
_QUERY_FIELDS = ("schema", "purpose", "service_selection", "service_selection_digest_hex",
    "work_scope_digest_hex", "minimum_checkpoint_digest_hex", "minimum_sequence",
    "minimum_opening_digest_hex", "challenge_hex")
_REPLY_FIELDS = ("schema", "query_digest_hex", "observation", "checkpoint_head",
    "opening_digest_hex", "checkpoint_lineage")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError)


class CheckpointDiscoveryRefused(ValueError):
    """Sanitized lineage or opening refusal; never a currentness verdict."""


def _require(condition):
    if not condition:
        raise CheckpointDiscoveryRefused("selected NoM checkpoint discovery refused")


def _hash(domain, value):
    return authority._digest(domain, codec._canonical(value))


def _decode(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE_BYTES)
    return authority._decode(wire)


def _history(candidate):
    _require(type(candidate) is protocol.ReferenceCheckpoint)
    nodes, seen = [], set()
    current = candidate
    while current is not None:
        _require(type(current) is protocol.ReferenceCheckpoint and id(current) not in seen)
        _require(len(nodes) < MAX_CHECKPOINTS)
        seen.add(id(current))
        snapshot = current.as_dict()
        # A source-context hash commits to its complete actual declaration/read
        # view; it cannot construct an absent original or opening from this hash.
        context = current._context.as_dict()
        nodes.append(dict(checkpoint_digest_hex=protocol._hash(protocol.SNAPSHOT_DOMAIN, snapshot),
            checkpoint=snapshot, source_context_digest_hex=_hash(CONTEXT_DOMAIN, context)))
        current = current._prior
    nodes.reverse()
    _require(len(nodes) == nodes[-1]["checkpoint"]["sequence"])
    return nodes


def _query(minimum, challenge_hex):
    _require(type(minimum) is protocol.ReferenceCheckpoint)
    codec._hex(challenge_hex)
    value = minimum.as_dict()
    history = _history(minimum)
    return dict(schema=QUERY_SCHEMA, purpose="inspect-minimum-checkpoint-lineage",
        service_selection=minimum._policy.as_dict(), service_selection_digest_hex=minimum._policy.digest_hex,
        work_scope_digest_hex=value["work_scope_digest_hex"], minimum_checkpoint_digest_hex=minimum.digest_hex,
        minimum_sequence=value["sequence"], minimum_opening_digest_hex=_hash(OPENING_DOMAIN, history),
        challenge_hex=challenge_hex)


@dataclass(frozen=True, init=False)
class NoMCheckpointReadSelection:
    """A complete independently retained minimum, never an incoming capability."""
    _minimum: protocol.ReferenceCheckpoint
    _wire: bytes

    def __init__(self):
        raise TypeError("use checkpoint_read")

    def as_dict(self):
        try:
            _require(type(self) is NoMCheckpointReadSelection)
            value = _decode(self._wire)
            codec._object(value, _QUERY_FIELDS)
            expected = _query(self._minimum, value["challenge_hex"])
            _require(self._wire == codec._canonical(expected))
            return value
        except _ERRORS:
            raise CheckpointDiscoveryRefused("invalid checkpoint discovery selection") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _hash(QUERY_DOMAIN, self.as_dict())


def checkpoint_read(minimum, *, challenge_hex):
    """Bind a known minimum and full service selection before a candidate reply."""
    try:
        wire = codec._canonical(_query(minimum, challenge_hex))
        _decode(wire)
        result = object.__new__(NoMCheckpointReadSelection)
        object.__setattr__(result, "_minimum", minimum)
        object.__setattr__(result, "_wire", wire)
        return result
    except _ERRORS:
        raise CheckpointDiscoveryRefused("checkpoint discovery selection refused") from None


@dataclass(frozen=True, init=False)
class NoMCheckpointEvidenceOpening:
    """Complete actual reference contexts; typed bytes establish no producer truth."""
    _candidate: protocol.ReferenceCheckpoint

    def __init__(self):
        raise TypeError("use checkpoint_opening")

    def as_dict(self):
        try:
            _require(type(self) is NoMCheckpointEvidenceOpening)
            history = _history(self._candidate)
            return dict(checkpoint_lineage=history, opening_digest_hex=_hash(OPENING_DOMAIN, history))
        except _ERRORS:
            raise CheckpointDiscoveryRefused("invalid complete checkpoint opening") from None


def checkpoint_opening(candidate):
    """Keep actual complete originals/history; a descriptor cannot replace them."""
    try:
        _history(candidate)
        result = object.__new__(NoMCheckpointEvidenceOpening)
        object.__setattr__(result, "_candidate", candidate)
        return result
    except _ERRORS:
        raise CheckpointDiscoveryRefused("complete checkpoint opening refused") from None


def _lineage(selection, opening):
    _require(type(selection) is NoMCheckpointReadSelection)
    _require(type(opening) is NoMCheckpointEvidenceOpening)
    query = selection.as_dict()
    candidate = opening._candidate
    _require(candidate._policy.canonical_bytes == selection._minimum._policy.canonical_bytes)
    value = opening.as_dict()
    history = value["checkpoint_lineage"]
    known = _history(selection._minimum)
    _require(len(history) >= len(known) and codec._canonical(history[:len(known)]) == codec._canonical(known))
    head = history[-1]
    _require(head["checkpoint"]["work_scope_digest_hex"] == query["work_scope_digest_hex"])
    return value, head


def discovery_reply(selection, opening):
    """Frame an unsigned candidate lineage at/above the supplied known minimum."""
    try:
        value, head = _lineage(selection, opening)
        reply = dict(schema=REPLY_SCHEMA, query_digest_hex=selection.digest_hex,
            observation="CHECKPOINT_CANDIDATE", checkpoint_head=dict(
                checkpoint_digest_hex=head["checkpoint_digest_hex"], sequence=head["checkpoint"]["sequence"]),
            **value)
        wire = codec._canonical(reply)
        _decode(wire)
        return wire
    except _ERRORS:
        raise CheckpointDiscoveryRefused("checkpoint discovery reply refused") from None


def unavailable_reply(selection):
    """Represent an unsigned outage, never absence or a cached permission."""
    try:
        _require(type(selection) is NoMCheckpointReadSelection)
        wire = codec._canonical(dict(schema=REPLY_SCHEMA, query_digest_hex=selection.digest_hex,
            observation="UNAVAILABLE", checkpoint_head=None, opening_digest_hex=None, checkpoint_lineage=[]))
        _decode(wire)
        return wire
    except _ERRORS:
        raise CheckpointDiscoveryRefused("checkpoint outage framing refused") from None


def _validated_reply(selection, wire, opening):
    _require(type(selection) is NoMCheckpointReadSelection)
    reply = _decode(wire)
    codec._object(reply, _REPLY_FIELDS)
    if reply["observation"] == "UNAVAILABLE":
        _require(opening is None and wire == unavailable_reply(selection))
    else:
        _require(reply["observation"] == "CHECKPOINT_CANDIDATE")
        _require(wire == discovery_reply(selection, opening))
    return reply


def _message(query, reply):
    value = dict(schema=MESSAGE_SCHEMA, purpose="checkpoint-response-preimage-only", query=query, reply=reply)
    return _hash(MESSAGE_DOMAIN, value)


def response_message_digest(selection, wire, opening=None):
    """Domain-separated exact public preimage for a later authority construction.

    No signature algorithm, signer, verifier, role provisioning or current read
    is implemented. A freshly challenged old candidate still has a valid preimage.
    """
    try:
        reply = _validated_reply(selection, wire, opening)
        return _message(selection.as_dict(), reply)
    except _ERRORS:
        raise CheckpointDiscoveryRefused("checkpoint response preimage refused") from None


def _compare(local, reference):
    retained, local_fields = protocol._compatible(reference._policy, local)
    remote = reference.as_dict()
    _require(local_fields["work_scope_digest_hex"] == remote["work_scope_digest_hex"])
    original, candidate = reference._context._binding._capsule, retained._capsule
    if candidate.journal_bytes.startswith(original.journal_bytes):
        relation = protocol.continuity.compare_continuation(original, candidate.canonical_bytes,
            expected_candidate_digest_hex=candidate.digest_hex).review()["journal_relation"]
        relation = "LOCAL_AHEAD_CANDIDATE" if relation == "STRICT_EXTENSION" else "MATCHING_JOURNAL"
        charged = local_fields["charged_work"]
    else:
        protocol.continuity.compare_continuation(candidate, original.canonical_bytes,
            expected_candidate_digest_hex=original.digest_hex).review()
        relation, charged = "LOCAL_BEHIND_CANDIDATE", remote["charged_work"]
    return relation, charged, local_fields, remote


def inspect_discovery(local, selection, wire, opening=None):
    """Inspect an untrusted candidate against a retained minimum; always HOLD.

    The candidate is not independently selected as current. The complete opening
    is required separately and never built from reply hashes or recovered bytes.
    """
    try:
        reply = _validated_reply(selection, wire, opening)
        query = selection.as_dict()
        if reply["observation"] == "UNAVAILABLE":
            reference = selection._minimum
            candidate_head, candidate_sequence, added = None, None, 0
            discovery = "UNAVAILABLE; MINIMUM AND LOCAL UNKNOWN WORK RETAINED"
        else:
            reference = opening._candidate
            head = reply["checkpoint_head"]
            candidate_head, candidate_sequence = head["checkpoint_digest_hex"], head["sequence"]
            added = candidate_sequence - query["minimum_sequence"]
            discovery = "NEWER_CANDIDATE" if added else "MINIMUM_CANDIDATE"
        relation, charged, local_fields, remote = _compare(local, reference)
        return dict(schema="ptlc-nom-checkpoint-discovery-comparison-v1", discovery=discovery,
            minimum_checkpoint_digest_hex=query["minimum_checkpoint_digest_hex"],
            minimum_sequence=query["minimum_sequence"], minimum_opening_digest_hex=query["minimum_opening_digest_hex"],
            candidate_checkpoint_digest_hex=candidate_head, candidate_sequence=candidate_sequence,
            new_checkpoint_records=added, journal_relation=relation,
            local_journal_sequence=local_fields["journal_sequence"], inspected_journal_sequence=remote["journal_sequence"],
            effective_charged_work=charged, disclosure_possible=True, work_outcome="UNKNOWN",
            state="HOLD", recovery_action="NONE", new_work_allowed=False, automatic_retry=False,
            replenish_work=False, replacement_original_allowed=False, automatic_bootstrap=False,
            worker_calls=0, response_authentication="NOT_PERFORMED; UNSIGNED REFERENCE CANDIDATE",
            response_message_digest_hex=_message(query, reply),
            signature_mathematics="NOT_PERFORMED", candidate_latest="NOT_ESTABLISHED",
            root_provisioning="UNFILLED", service_nonrollback="NOT_IMPLEMENTED", checkpoint_storage="NOT_IMPLEMENTED",
            atomic_service_cas="NOT_IMPLEMENTED", atomic_work_entry="NOT_IMPLEMENTED",
            source_currentness="UNFILLED", application="NO-GO", core="NO-GO")
    except _ERRORS:
        raise CheckpointDiscoveryRefused("checkpoint discovery comparison refused") from None
