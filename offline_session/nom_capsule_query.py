"""Bind retained full capsule knowledge to a separate unauthenticated NoM read.

Missing originals stay missing. This pure construction supplies no current
source, restore checkpoint, worker admission, network operation or capability.
"""
from dataclasses import dataclass
import hashlib

from . import enrollment_contract as codec, nom_authority_contract as authority
from . import nom_capsule as capsule, nom_partial_custody as partial
from . import nom_recovery as recovery, nom_uncertainty as framing


PROFILE = "ptlc-nom-capsule-read-binding-v1"
CLAIM_SCHEMA = "ptlc-nom-capsule-read-claim-v1"
MAX_WIRE_BYTES = framing.MAX_WIRE_BYTES
_CLAIM = ("schema", "binding_digest_hex", "source_claim_hex")
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError)


class CapsuleQueryRefused(recovery.RecoveryError):
    """Retained-byte or framing refusal; never a verdict on source truth."""


def _require(condition):
    if not condition:
        raise CapsuleQueryRefused("selected capsule and read query do not agree")


def _fields(retained, query):
    _require(type(retained) is capsule.CapsuleView and type(query) is authority.NoMReadQuery)
    # Reuse one complete validation within this call, without a retained cache.
    wire = retained._wire
    value, _, held = capsule._decode(wire)
    selected = held.selection(); read = query.as_dict()
    _require(selected["original_long_hex"] is not None
        and selected["recovered_long_signature_hex"] is not None
        and selected["terms"] == read["terms"]
        and read["originals_hex"] == dict(long=selected["original_long_hex"], short=selected["remote_short_hex"])
        and selected["disclosure_possible"] is True and read["consumer_selection"]["disclosure_possible"] is True)
    projection = value["selected_projection"]
    work_scope = recovery.digest(b"ptlc-nom-capsule-read-work-scope-v1", dict(
        verification_context_digest_hex=selected["verification_context_digest_hex"],
        short_original_digest_hex=partial.short_digest(bytes.fromhex(selected["remote_short_hex"]))))
    return dict(schema=PROFILE, capsule_sha256=hashlib.sha256(wire).hexdigest(),
        journal_sha256=projection["journal_sha256"], journal_head_hex=projection["journal_head_hex"],
        journal_sequence=projection["journal_sequence"], projection_selection_digest_hex=held.selection_digest_hex,
        verification_context_digest_hex=selected["verification_context_digest_hex"], work_scope_digest_hex=work_scope,
        charged_work=selected["charged_work"], query_hex=query.canonical_bytes.hex())


@dataclass(frozen=True, init=False)
class CapsuleReadBinding:
    """Immutable local comparison of independently supplied retained inputs."""
    _capsule: capsule.CapsuleView
    _query: authority.NoMReadQuery

    def __init__(self):
        raise TypeError("use bind_read_query")

    def as_dict(self):
        try:
            _require(type(self) is CapsuleReadBinding)
            return _fields(self._capsule, self._query)
        except _ERRORS:
            raise CapsuleQueryRefused("invalid selected capsule read binding") from None

    @property
    def canonical_bytes(self):
        wire = codec._canonical(self.as_dict())
        framing._decode(wire)
        return wire

    @property
    def digest_hex(self):
        return authority._digest(b"ptlc-nom-capsule-read-binding-v1", self.canonical_bytes)

    def review(self):
        value = self.as_dict()
        return dict(profile=PROFILE, binding_digest_hex=self.digest_hex, work_scope_digest_hex=value["work_scope_digest_hex"],
            capsule_sha256=value["capsule_sha256"], journal_sha256=value["journal_sha256"],
            journal_sequence=value["journal_sequence"], query_digest_hex=self._query.digest_hex,
            charged_work=len(value["charged_work"]), work_outcome="UNKNOWN FOR EVERY PERSISTED CHARGED ORDINAL",
            original_bytes="BOTH EXACT RETAINED SYNTHETIC ENVELOPES", state="HOLD", recovery_action="NONE",
            consumer_retention_pins="SEPARATE CALLER ASSERTIONS; NOT DERIVED FROM RECOVERY JOURNAL",
            signature_mathematics="NOT_PERFORMED", source_authentication="NOT_PERFORMED",
            source_currentness="UNFILLED", restore_fence="UNFILLED", atomic_entry="NOT_IMPLEMENTED",
            durable_binding="NOT_IMPLEMENTED", automatic_retry=False, replenish_work=False,
            replacement_original_allowed=False, application="NO-GO", core="NO-GO")


def bind_read_query(retained, query):
    """Bind only two actually retained originals; never build or fill a query.

    Recovery-journal pins and observer-retention pins remain distinct. Capsule
    knowledge enters this separate binding, not the frozen source query schema.
    The stable work scope excludes challenge, read position and custody progress.
    """
    try:
        _fields(retained, query)
        result = object.__new__(CapsuleReadBinding)
        object.__setattr__(result, "_capsule", retained); object.__setattr__(result, "_query", query)
        result.canonical_bytes
        return result
    except _ERRORS:
        raise CapsuleQueryRefused("complete retained capsule read binding refused") from None


def parse_binding(expected, wire):
    """Exact local replay only; a coherent old selection can still match."""
    try:
        _require(type(expected) is CapsuleReadBinding)
        framing._decode(wire)
        _require(wire == expected.canonical_bytes)
        return expected
    except _ERRORS:
        raise CapsuleQueryRefused("capsule read binding differs from retained selection") from None


def parse_claim(expected, wire):
    """Match a forgeable outer binding and the unchanged unauthenticated claim."""
    try:
        _require(type(expected) is CapsuleReadBinding)
        expected.as_dict()
        value = framing._decode(wire); codec._object(value, _CLAIM)
        _require(value["schema"] == CLAIM_SCHEMA and value["binding_digest_hex"] == expected.digest_hex)
        raw = framing._bytes(value["source_claim_hex"], authority.MAX_WIRE_BYTES)
        claim = authority.parse_claim(expected._query, raw)
        return dict(framing="MATCHED_UNAUTHENTICATED_CAPSULE_READ_CLAIM", coverage=claim["coverage"],
            source_claim=claim, selected_binding=expected.review(), source_authentication="NOT_PERFORMED",
            source_currentness="UNFILLED", restore_fence="UNFILLED", atomic_entry="NOT_IMPLEMENTED",
            state="HOLD", recovery_action="NONE", automatic_retry=False, replenish_work=False,
            replacement_original_allowed=False, application="NO-GO", core="NO-GO")
    except _ERRORS:
        raise CapsuleQueryRefused("capsule source claim framing refused") from None
