"""Exact retained-journal continuation, without current or restore authority.

The caller must independently retain the prior capsule. Coherent rollback of
both inputs still compares; this pure boundary is not a nonrollback service.
"""
from dataclasses import dataclass
import hashlib
import json

from . import nom_capsule as capsule, nom_recovery as recovery


PROFILE = "ptlc-nom-capsule-continuity-v1"
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError)


class ContinuityRefused(recovery.RecoveryError):
    """Local retention refusal; no statement about chain or execution truth."""


def _require(condition):
    if not condition:
        raise ContinuityRefused("capsule does not preserve the retained journal")


def _compare(retained, candidate):
    _require(type(retained) is capsule.CapsuleView and type(candidate) is capsule.CapsuleView)
    old, new = retained.partial_hold.selection(), candidate.partial_hold.selection()
    _require(old["terms"] == new["terms"] and old["pair"] == new["pair"]
        and old["verification_context_digest_hex"] == new["verification_context_digest_hex"]
        and old["remote_short_hex"] == new["remote_short_hex"])
    before, after = retained.journal_bytes, candidate.journal_bytes
    # Complete canonical event hashes and equal counters cannot replace these
    # exact retained bytes. Both journals have already been replayed separately.
    _require(after.startswith(before))
    _require(new["charged_work"][:len(old["charged_work"])] == old["charged_work"]
        and old["disclosure_possible"] is True and new["disclosure_possible"] is True)
    for field in ("recovered_long_signature_hex", "original_long_hex"):
        _require(old[field] is None or new[field] == old[field])
    if before == after:
        relation = "EXACT_REPLAY" if retained.canonical_bytes == candidate.canonical_bytes else "SAME_JOURNAL"
    else:
        relation = "STRICT_EXTENSION"
    prior, following = retained.projection(), candidate.projection()
    return dict(profile=PROFILE, state="HOLD", recovery_action="NONE", journal_relation=relation,
        retained_capsule_sha256=retained.digest_hex, candidate_capsule_sha256=candidate.digest_hex,
        retained_journal_sha256=prior["journal_sha256"], candidate_journal_sha256=following["journal_sha256"],
        retained_journal_head_hex=prior["journal_head_hex"], candidate_journal_head_hex=following["journal_head_hex"],
        retained_journal_sequence=prior["journal_sequence"], candidate_journal_sequence=following["journal_sequence"],
        verification_context_digest_hex=old["verification_context_digest_hex"],
        retained_charged_work=len(old["charged_work"]), candidate_charged_work=len(new["charged_work"]),
        disclosure_possible=True, signature_mathematics="NOT_PERFORMED",
        worker_execution="UNKNOWN FOR EVERY PERSISTED CHARGED ORDINAL",
        retain_original_capsules="BOTH REQUIRED; COMPARISON IMPLEMENTS NO DURABLE STORE",
        source_authentication="NOT_PERFORMED", source_currentness="UNFILLED",
        consumer_restore_fence="UNFILLED", atomic_work_admission="UNFILLED",
        independent_retained_checkpoint="CALLER PREMISE; NOT PROVISIONED OR AUTHENTICATED",
        coherent_old_pair="CAN MATCH; NO CURRENTNESS OR NONROLLBACK GUARANTEE",
        automatic_retry=False, replenish_work=False, replacement_original_allowed=False,
        application="NO-GO", core="NO-GO")


@dataclass(frozen=True, init=False)
class CapsuleContinuation:
    """Immutable comparison of two inputs, never a recovery capability."""
    _retained: capsule.CapsuleView
    _candidate: capsule.CapsuleView

    def __init__(self):
        raise TypeError("use compare_continuation")

    def review(self):
        try:
            _require(type(self) is CapsuleContinuation)
            return _compare(self._retained, self._candidate)
        except _ERRORS:
            raise ContinuityRefused("invalid selected capsule continuation") from None

    @property
    def canonical_bytes(self):
        return json.dumps(self.review(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")

    @property
    def digest_hex(self):
        return hashlib.sha256(b"ptlc-nom-capsule-continuity-v1\0" + self.canonical_bytes).hexdigest()


def compare_continuation(retained, candidate_wire, *, expected_candidate_digest_hex):
    """Refuse regression or divergence relative to an independently retained view.

    No current-head selection, persistence, I/O, worker, query conversion or
    retry occurs. An extension may record new public custody, not permission.
    Restoring the retained selection together with an old candidate still passes.
    """
    try:
        _require(type(retained) is capsule.CapsuleView)
        candidate = capsule.read_capsule(candidate_wire, expected_digest_hex=expected_candidate_digest_hex)
        _compare(retained, candidate)
        result = object.__new__(CapsuleContinuation)
        object.__setattr__(result, "_retained", retained)
        object.__setattr__(result, "_candidate", candidate)
        return result
    except _ERRORS:
        raise ContinuityRefused("selected capsule is not a retained journal continuation") from None
