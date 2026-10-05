"""Unsigned historical reads from one owned, completely retained local store.

Local labels and honest SQLite/VFS behavior are premises. This experiment does
not sign, authenticate, transport, recover, allocate, refund or enter. Coherent
restores and clones reproduce the same checkpoints without external lineage.
"""

from dataclasses import dataclass
import hashlib

from qualification import original_read_contract as reads
from qualification import policy_effect_store as local
from qualification import source_read_ordering as ordering


LINEAGE_DOMAIN = b"PTLC/offline-local-original-record-lineage/v1\0"


def _record_head(store, declaration):
    # Called only inside the owned transaction, after complete store validation.
    revision, profile, active, mode = store._source()
    policies = [dict(revision=rev, profile_hex=wire.hex(), active=bool(enabled), event_sequence=seq)
        for rev, wire, enabled, seq in store._db.execute("SELECT * FROM policies ORDER BY revision")]
    operations = [dict(original_operation=reads.original_operation(operation_id_hex=op,
        expected_revision=rev, profile_wire=wire, proposal_digest_hex=proposal).as_dict(),
        charge_sequence=charge, effect_sequence=effect)
        for op, rev, wire, proposal, charge, effect in store._db.execute(
            "SELECT * FROM operations ORDER BY operation_id")]
    effects = [dict(operation_id_hex=op, event_sequence=seq, payload=payload)
        for op, seq, payload in store._db.execute("SELECT * FROM effects ORDER BY operation_id")]
    events = [dict(event_sequence=seq, kind=kind, revision=rev, operation_id_hex=op, detail=detail)
        for seq, kind, rev, op, detail in store._db.execute("SELECT * FROM events ORDER BY seq")]
    material = dict(root_declaration=declaration, retention_rule=reads.RETENTION_RULE,
        source=dict(revision=revision, profile_hex=profile.hex(), active=bool(active), mode=mode),
        policies=policies, operations=operations, effects=effects, events=events)
    return reads.RecordCheckpoint(len(events),
        hashlib.sha256(LINEAGE_DOMAIN+ordering._canonical(material)).hexdigest())


@dataclass(frozen=True, init=False)
class LocalOriginalHeads:
    """One unsigned diagnostic sample, not authenticated latest checkpoints."""

    policy_checkpoint: object
    record_checkpoint: reads.RecordCheckpoint

    def __init__(self):
        raise TypeError("use local_checkpoints")

    def as_dict(self):
        return dict(policy_checkpoint=self.policy_checkpoint.as_dict(),
            record_checkpoint=self.record_checkpoint.as_dict())


def local_checkpoints(store, selected_root):
    """Select both local heads together; a later lookup uses another transaction.

    Intervening managed policy/mode/record mutations must make the selected query
    refuse. Reading this diagnostic does not establish authenticated freshness.
    """
    declaration = ordering._selection(store, selected_root)
    with store._transaction("original-read-heads"):
        checkpoint, _, _ = ordering._head(store, declaration)
        record = _record_head(store, declaration)
        result = object.__new__(LocalOriginalHeads)
        object.__setattr__(result, "policy_checkpoint", checkpoint)
        object.__setattr__(result, "record_checkpoint", record)
        return result


def sample_original(store, selected_root, query):
    """Return the exact unsigned grammar claim from one BEGIN IMMEDIATE read.

    Complete history is checked before and after the snapshot. Historical profile
    provenance here means equality with a retained local policy row, not an
    authenticated declaration for that old profile. A return follows COMMIT and
    may already be stale. Lost returns grant no retry, refund or new operation id.
    """
    declaration = ordering._selection(store, selected_root)
    if type(query) is not reads.OriginalReadQuery:
        raise local.StoreRefused("an exact independently prepared original query is required")
    try:
        read = query.as_dict()
        if query._root.as_dict() != declaration:
            raise local.StoreRefused("query changes its independently selected complete root")
        original = read["original_operation"]
        request = local.OriginalRequest(original["operation_id_hex"], original["expected_revision"],
            ordering._canonical(original["governor_profile"]), original["proposal_digest_hex"])
        local._request(request, store._labels)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise local.StoreRefused("invalid complete local original query selection") from None
    with store._transaction("original-read-sample"):
        checkpoint, active, mode = ordering._head(store, declaration)
        record_head = _record_head(store, declaration)
        if (read["expected_checkpoint"] != checkpoint.as_dict()
                or read["expected_record_checkpoint"] != record_head.as_dict()):
            raise local.StoreRefused("selected original query differs from the owned local heads")
        historical = store._db.execute("SELECT profile FROM policies WHERE revision=?",
            (request.expected_revision,)).fetchone()
        if historical is None or historical[0] != request.profile_wire:
            raise local.StoreRefused("original profile differs from retained local policy history")
        # A conflicting complete original is refused even when the source is unavailable.
        record = store._record(request)
        if mode in ("ambiguous", "compromise-detected"):
            raise local.StoreRefused("local original sample is ambiguous or known compromised")
        observation = ("unavailable" if mode == "unavailable" else "absent" if record is None
            else "pending" if record.effect_sequence is None else "completed")
        unavailable = observation == "unavailable"
        claim = dict(schema=reads.CLAIM_SCHEMA, query_digest_hex=query.digest_hex,
            root_declaration_digest_hex=read["root_declaration_digest_hex"],
            source_context_digest_hex=reads._digest(b"PTLC/observation-policy-source-context/v1\0",
                read["source_context"]), challenge_hex=read["challenge_hex"], observation=observation,
            claimed_checkpoint=None if unavailable else checkpoint.as_dict(),
            claimed_record_checkpoint=None if unavailable else record_head.as_dict(),
            head_policy=None if unavailable else dict(governor_profile=declaration["governor_profile"],
                active=bool(active)), original_record=None if unavailable or record is None else dict(
                original_operation=original, charge_sequence=record.charge_sequence,
                effect_sequence=record.effect_sequence))
        result = reads.parse_claim(query, ordering._canonical(claim))
        store._cut("original-read-snapshot-selected")
        return result
