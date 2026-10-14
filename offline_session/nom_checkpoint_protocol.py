"""Selected external-checkpoint reference transitions, never a live service.

The caller supplies the current reference independently of restored local state.
All comparisons retain UNKNOWN work and HOLD. Authentication, provisioning,
nonrollback storage and atomic work entry are separate unfilled requirements.
"""
from dataclasses import dataclass

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_capsule_continuity as continuity, nom_source_checkpoint as source


POLICY_SCHEMA = "ptlc-nom-checkpoint-service-selection-v1"
SNAPSHOT_SCHEMA = "ptlc-nom-reference-checkpoint-v1"
QUERY_SCHEMA = "ptlc-nom-reference-checkpoint-query-v1"
REPLY_SCHEMA = "ptlc-nom-reference-checkpoint-reply-v1"
POLICY_DOMAIN = b"ptlc-nom-checkpoint-service-selection-v1"
SNAPSHOT_DOMAIN = b"ptlc-nom-reference-checkpoint-v1"
QUERY_DOMAIN = b"ptlc-nom-reference-checkpoint-query-v1"
MAX_WIRE_BYTES = 8192
MAX_SNAPSHOTS = 16
REALM_FIELDS = ("core_commit", "chain_id", "genesis_hash_hex", "binary_digest_hex",
    "spork_state_digest_hex", "canonicality_policy_digest_hex", "finality_policy_digest_hex",
    "freshness_policy_digest_hex", "restore_policy_digest_hex")
_POLICY_FIELDS = ("schema", "purpose", "service_id_hex", "service_epoch", "checkpoint_key_hex", "realm", "max_snapshots")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError)


class CheckpointProtocolRefused(ValueError):
    """Sanitized reference comparison refusal, never a chain or custody verdict."""


def _require(condition):
    if not condition:
        raise CheckpointProtocolRefused("selected NoM checkpoint protocol refused")


def _hash(domain, value):
    return authority._digest(domain, codec._canonical(value))


def _decode(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE_BYTES)
    return authority._decode(wire)


def _context(value):
    _require(type(value) is source.NoMSourceCheckpointSelection)
    value.as_dict()
    retained = value._binding
    fields = retained.as_dict()
    _require(all(row["outcome"] == "UNKNOWN" for row in fields["charged_work"]))
    network = value._declaration.as_dict()["network_selection"]
    return retained, fields, {key: network[key] for key in REALM_FIELDS}


def _policy(value):
    codec._object(value, _POLICY_FIELDS)
    _require(value["schema"] == POLICY_SCHEMA and value["purpose"] == "external-reference-retention-only")
    for key in ("service_id_hex", "checkpoint_key_hex"):
        codec._hex(value[key])
    authority._number(value["service_epoch"], positive=True)
    _require(type(value["max_snapshots"]) is int and 1 <= value["max_snapshots"] <= MAX_SNAPSHOTS)
    realm = value["realm"]
    codec._object(realm, REALM_FIELDS)
    _require(realm["core_commit"] == authority.CORE_COMMIT)
    authority.decimal(realm["chain_id"], 64, positive=True)
    for key in REALM_FIELDS[2:]:
        codec._hex(realm[key])
    return value


@dataclass(frozen=True, init=False)
class CheckpointServiceSelection:
    """Independent complete expectation; no provisioned key or service proof."""
    _wire: bytes

    def __init__(self):
        raise TypeError("use select_service")

    def as_dict(self):
        try:
            _require(type(self) is CheckpointServiceSelection)
            return _policy(_decode(self._wire))
        except _ERRORS:
            raise CheckpointProtocolRefused("invalid checkpoint service selection") from None

    @property
    def canonical_bytes(self):
        return codec._canonical(self.as_dict())

    @property
    def digest_hex(self):
        return _hash(POLICY_DOMAIN, self.as_dict())


def _compatible(policy, context):
    _require(type(policy) is CheckpointServiceSelection)
    retained, fields, realm = _context(context)
    selected = policy.as_dict()
    _require(codec._canonical(selected["realm"]) == codec._canonical(realm))
    declaration = context._declaration.as_dict()
    _require(selected["checkpoint_key_hex"] not in [declaration[key] for key in
        ("root_key_hex", "source_response_key_hex", "consumer_checkpoint_key_hex")])
    return retained, fields


def select_service(context, *, service_id_hex, service_epoch, checkpoint_key_hex, max_snapshots=MAX_SNAPSHOTS):
    """Select before peer input; a fourth encoding establishes no independent owner."""
    try:
        _, _, realm = _context(context)
        value = _policy(dict(schema=POLICY_SCHEMA, purpose="external-reference-retention-only",
            service_id_hex=service_id_hex, service_epoch=service_epoch, checkpoint_key_hex=checkpoint_key_hex,
            realm=realm, max_snapshots=max_snapshots))
        result = object.__new__(CheckpointServiceSelection)
        object.__setattr__(result, "_wire", codec._canonical(value))
        _compatible(result, context)
        return result
    except _ERRORS:
        raise CheckpointProtocolRefused("checkpoint service selection refused") from None


def _snapshot(value, seen):
    _require(type(value) is ReferenceCheckpoint and id(value) not in seen and len(seen) < MAX_SNAPSHOTS)
    seen = seen | {id(value)}
    retained, fields = _compatible(value._policy, value._context)
    if value._prior is None:
        sequence, previous = 1, "00" * 32
    else:
        before = _snapshot(value._prior, seen)
        _require(value._policy.canonical_bytes == value._prior._policy.canonical_bytes)
        _require(fields["work_scope_digest_hex"] == before["work_scope_digest_hex"])
        continuation = continuity.compare_continuation(value._prior._context._binding._capsule,
            retained._capsule.canonical_bytes, expected_candidate_digest_hex=retained._capsule.digest_hex).review()
        _require(continuation["journal_relation"] == "STRICT_EXTENSION")
        sequence, previous = before["sequence"]+1, _hash(SNAPSHOT_DOMAIN, before)
    _require(sequence <= value._policy.as_dict()["max_snapshots"])
    return dict(schema=SNAPSHOT_SCHEMA, service_selection_digest_hex=value._policy.digest_hex,
        sequence=sequence, previous_checkpoint_digest_hex=previous,
        work_scope_digest_hex=fields["work_scope_digest_hex"], capsule_sha256=fields["capsule_sha256"],
        journal_sha256=fields["journal_sha256"], journal_head_hex=fields["journal_head_hex"],
        journal_sequence=fields["journal_sequence"], charged_work=fields["charged_work"],
        disclosure_possible=True, work_outcome="UNKNOWN")


@dataclass(frozen=True, init=False)
class ReferenceCheckpoint:
    """Finite immutable history; selecting it is not nonrollback storage."""
    _policy: CheckpointServiceSelection
    _context: source.NoMSourceCheckpointSelection
    _prior: object

    def __init__(self):
        raise TypeError("use bootstrap_reference or advance_reference")

    def as_dict(self):
        try:
            return _snapshot(self, set())
        except _ERRORS:
            raise CheckpointProtocolRefused("invalid retained reference checkpoint") from None

    @property
    def canonical_bytes(self):
        wire = codec._canonical(self.as_dict())
        _decode(wire)
        return wire

    @property
    def digest_hex(self):
        return _hash(SNAPSHOT_DOMAIN, self.as_dict())


def _freeze(policy, context, prior):
    result = object.__new__(ReferenceCheckpoint)
    object.__setattr__(result, "_policy", policy)
    object.__setattr__(result, "_context", context)
    object.__setattr__(result, "_prior", prior)
    result.canonical_bytes
    return result


def bootstrap_reference(policy, context):
    """Explicit research bootstrap, never a certificate of absence or cold-start safety.

    An old local copy can bootstrap an old reference. Nothing here proves that
    an earlier external service or charge existed. No automatic bootstrap exists.
    """
    try:
        _compatible(policy, context)
        return _freeze(policy, context, None)
    except _ERRORS:
        raise CheckpointProtocolRefused("checkpoint reference bootstrap refused") from None


def advance_reference(current, candidate, *, expected_current_digest_hex):
    """Functional compare-and-advance against a supplied current reference.

    This is not a shared-server CAS, durable transaction or work-entry receipt.
    Read challenges and source rotations cannot create another work allowance.
    """
    try:
        _require(type(current) is ReferenceCheckpoint)
        codec._hex(expected_current_digest_hex)
        before = current.as_dict()
        _require(current.digest_hex == expected_current_digest_hex)
        retained, fields = _compatible(current._policy, candidate)
        _require(fields["work_scope_digest_hex"] == before["work_scope_digest_hex"])
        result = continuity.compare_continuation(current._context._binding._capsule,
            retained._capsule.canonical_bytes, expected_candidate_digest_hex=retained._capsule.digest_hex).review()
        if result["journal_relation"] != "STRICT_EXTENSION":
            return current
        return _freeze(current._policy, candidate, current)
    except _ERRORS:
        raise CheckpointProtocolRefused("checkpoint reference advance refused") from None


def checkpoint_query(current, *, challenge_hex):
    """Select an exact current expectation; challenge supplies no freshness proof."""
    try:
        _require(type(current) is ReferenceCheckpoint)
        codec._hex(challenge_hex)
        value = current.as_dict()
        result = dict(schema=QUERY_SCHEMA, service_selection_digest_hex=current._policy.digest_hex,
            work_scope_digest_hex=value["work_scope_digest_hex"], expected_checkpoint_digest_hex=current.digest_hex,
            expected_sequence=value["sequence"], challenge_hex=challenge_hex)
        _decode(codec._canonical(result))
        return result
    except _ERRORS:
        raise CheckpointProtocolRefused("checkpoint query selection refused") from None


def reference_reply(current, query):
    """Frame an unsigned selected reply. A peer can forge it; no signer exists."""
    try:
        _require(type(current) is ReferenceCheckpoint)
        codec._object(query, ("schema", "service_selection_digest_hex", "work_scope_digest_hex",
            "expected_checkpoint_digest_hex", "expected_sequence", "challenge_hex"))
        expected = checkpoint_query(current, challenge_hex=query["challenge_hex"])
        _require(codec._canonical(query) == codec._canonical(expected))
        wire = codec._canonical(dict(schema=REPLY_SCHEMA, query_digest_hex=_hash(QUERY_DOMAIN, expected),
            checkpoint_digest_hex=current.digest_hex, checkpoint=current.as_dict()))
        _decode(wire)
        return wire
    except _ERRORS:
        raise CheckpointProtocolRefused("checkpoint reference reply refused") from None


def compare_reference_reply(local, current, query, wire):
    """Compare exact selected reply and complete journals without filling custody.

    The supplied current reference is an independent caller premise. Restoring
    both it and local context together still matches. No signature is checked.
    """
    try:
        _require(type(current) is ReferenceCheckpoint)
        _decode(wire)
        _require(wire == reference_reply(current, query))
        retained, local_fields = _compatible(current._policy, local)
        remote = current.as_dict()
        _require(local_fields["work_scope_digest_hex"] == remote["work_scope_digest_hex"])
        old_capsule, local_capsule = current._context._binding._capsule, retained._capsule
        if local_capsule.journal_bytes.startswith(old_capsule.journal_bytes):
            relation = continuity.compare_continuation(old_capsule, local_capsule.canonical_bytes,
                expected_candidate_digest_hex=local_capsule.digest_hex).review()["journal_relation"]
            relation = "LOCAL_AHEAD_REFERENCE" if relation == "STRICT_EXTENSION" else "MATCHING_JOURNAL"
            effective = local_fields["charged_work"]
        else:
            continuity.compare_continuation(local_capsule, old_capsule.canonical_bytes,
                expected_candidate_digest_hex=old_capsule.digest_hex).review()
            relation, effective = "LOCAL_BEHIND_REFERENCE", remote["charged_work"]
        return dict(schema="ptlc-nom-checkpoint-comparison-v1", journal_relation=relation,
            selected_checkpoint_digest_hex=current.digest_hex, selected_checkpoint_sequence=remote["sequence"],
            local_journal_sequence=local_fields["journal_sequence"], reference_journal_sequence=remote["journal_sequence"],
            local_charged_work=len(local_fields["charged_work"]), reference_charged_work=len(remote["charged_work"]),
            effective_charged_work=effective, disclosure_possible=True, work_outcome="UNKNOWN",
            state="HOLD", recovery_action="NONE", automatic_retry=False, replenish_work=False,
            replacement_original_allowed=False, new_work_allowed=False, worker_calls=0,
            reply_authentication="NOT_PERFORMED; UNSIGNED REFERENCE FRAME",
            root_provisioning="UNFILLED", service_nonrollback="CALLER PREMISE; NOT_IMPLEMENTED",
            atomic_service_cas="NOT_IMPLEMENTED", checkpoint_storage="NOT_IMPLEMENTED", atomic_work_entry="NOT_IMPLEMENTED",
            source_currentness="UNFILLED", application="NO-GO", core="NO-GO")
    except _ERRORS:
        raise CheckpointProtocolRefused("checkpoint reference comparison refused") from None
