"""Owned local read samples, never an authenticated policy source or use gate.

BEGIN IMMEDIATE serializes one unsigned snapshot with local policy mutations.
The existing store's synthetic allocation/effect transactions remain separate.
No signing, verifier callback, remote source, external lineage or physical entry
is added. A coherent database restore can repeat reads, charges and effects.
"""

from dataclasses import dataclass
import hashlib
import json

from offline_session import current_authority_contract as current
from qualification import policy_effect_store as store_contract
from qualification import source_response as responses, source_root_roles as roots


STATE_DOMAIN = b"PTLC/offline-local-policy-read-state/v1\0"
SAMPLE_DOMAIN = b"PTLC/offline-local-original-read-sample/v1\0"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _selection(store, selected_root):
    if (type(store) is not store_contract.OfflinePolicyEffectStore
            or type(selected_root) is not roots.RootDeclaration):
        raise store_contract.StoreRefused("exact local store and independently selected root required")
    declaration = selected_root.as_dict()
    labels = store._labels
    context = declaration["source_context"]
    if (context["source_id_hex"], context["source_incarnation_hex"],
            context["authority_id_hex"], context["resource_digest_hex"]) != (
            labels.source_id_hex, labels.incarnation_id_hex,
            labels.authority_id_hex, labels.resource_digest_hex):
        raise store_contract.StoreRefused("selected root differs from the owned local source labels")
    return declaration


def _head(store, declaration):
    revision, profile, active, mode = store._source()
    if profile != _canonical(declaration["governor_profile"]):
        raise store_contract.StoreRefused("selected complete root profile differs from the local policy")
    material = dict(root_declaration=declaration, revision=revision,
        profile_hex=profile.hex(), active=bool(active), mode=mode)
    return current.PolicyCheckpoint(revision, hashlib.sha256(STATE_DOMAIN+_canonical(material)).hexdigest()), active, mode


def local_checkpoint(store, selected_root):
    """Unsigned diagnostic for preparing a test query, never a trusted latest head.

    This observation and a later sample are separate transactions. An intervening
    policy or mode mutation must make the old selected query refuse.
    """
    declaration = _selection(store, selected_root)
    with store._transaction("read-head"):
        checkpoint, _, _ = _head(store, declaration)
        return checkpoint


@dataclass(frozen=True, init=False)
class LocalReadSample:
    """An unsigned local association with an original request, not a receipt.

    The historical response schema does not sign an original operation/proposal.
    This diagnostic association and digest must never be treated as such a proof.
    """

    original: store_contract.OriginalRequest
    response: responses.SourceResponse
    original_record: object
    event_sequence: int
    digest_hex: str

    def __init__(self):
        raise TypeError("use sample_original")


def sample_original(store, selected_root, query, original):
    """Read at one owned transaction snapshot; do not charge, refund or enter.

    The read linearization point is the completed snapshot under BEGIN IMMEDIATE,
    before releasing that transaction. A successful return follows COMMIT. Lost
    returns are unknown reads, not an allocation retry or a new operation id.
    """
    declaration = _selection(store, selected_root)
    if type(query) is not current.PolicyReadQuery:
        raise store_contract.StoreRefused("an exact independently prepared read query is required")
    store_contract._request(original, store._labels)
    read = query.as_dict()
    responses._query(read, declaration)
    with store._transaction("read-sample"):
        checkpoint, active, mode = _head(store, declaration)
        if read["expected_checkpoint"] != checkpoint.as_dict():
            raise store_contract.StoreRefused("selected query is not the current owned local snapshot")
        if mode in ("ambiguous", "compromise-detected"):
            raise store_contract.StoreRefused("local policy sample is ambiguous or known compromised")
        record = store._record(original)
        if record is None and (original.expected_revision != checkpoint.revision
                or original.profile_wire != _canonical(declaration["governor_profile"])):
            raise store_contract.StoreRefused("uncharged original differs from the complete local snapshot")
        observation = "unavailable" if mode == "unavailable" else "active" if active else "revoked"
        response = responses.source_response(selected_root, query, observation=observation)
        sequence = store._db.execute("SELECT count(*) FROM events").fetchone()[0]
        material = dict(root_declaration=declaration, original=dict(operation_id_hex=original.operation_id_hex,
            expected_revision=original.expected_revision, profile_hex=original.profile_wire.hex(),
            proposal_digest_hex=original.proposal_digest_hex), response=response.as_dict(),
            event_sequence=sequence, original_record=None if record is None else dict(
                charge_sequence=record.charge_sequence, effect_sequence=record.effect_sequence))
        sample = object.__new__(LocalReadSample)
        for field, value in (("original", original), ("response", response),
                ("original_record", record), ("event_sequence", sequence),
                ("digest_hex", hashlib.sha256(SAMPLE_DOMAIN+_canonical(material)).hexdigest())):
            object.__setattr__(sample, field, value)
        store._cut("read-snapshot-selected")
        return sample
