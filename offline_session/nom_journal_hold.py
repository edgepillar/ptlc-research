"""Selected read-only journal custody projection into the frozen partial HOLD.

Only persisted charged ordinals are selected. They are research identifiers,
never authenticated execution receipts. Missing output stays missing, even if
a diagnostic reply exists elsewhere. The caller retains the full original bytes
separately; this object implements no durable store, restore fence or recovery.
"""

from dataclasses import dataclass
import hashlib
import os

from . import nom_partial_custody as partial, nom_recovery as recovery
from .nom_strict_open import StrictNomRecovery, PROFILE as OPEN_PROFILE


PROFILE = "ptlc-nom-journal-partial-hold-v1"
WORK_DOMAIN = b"ptlc-nom-journal-charged-work-v1"


class JournalProjectionRefused(recovery.RecoveryError):
    """Sanitized selected custody refusal, without a chain-state verdict."""


def _require(condition):
    if not condition:
        raise JournalProjectionRefused("selected journal partial HOLD refused")


def _replay(wire):
    """Replay the frozen parser in memory; never open a path or verify a signature."""
    _require(type(wire) is bytes and 0 < len(wire) <= recovery.MAX_LOG and wire.endswith(b"\n"))
    lines = wire.splitlines()
    _require(1 <= len(lines) <= recovery.MAX_EVENTS)
    first = recovery.decode(lines[0])["event"]
    recovery.fields(first, ("kind", "terms", "pair", "role"))
    _require(first["kind"] == "init" and first["role"] == "bob")
    replay = object.__new__(recovery.NomRecovery)
    replay._terms = recovery.validate_terms(first["terms"])
    replay._pair = recovery.validate_pair(first["pair"]); replay._role = first["role"]
    replay._state = {"initialized": False, "funded": {}, "originals": {}, "remote_short_hex": "",
        "recovery_count": 0, "recovered_long_hex": "", "attempts": {}, "phases": {},
        "disclosure_possible": False, "observations": [], "confirmations": {}}
    head = "00" * 32
    for sequence, line in enumerate(lines, 1):
        row = recovery.decode(line)
        recovery.fields(row, ("schema", "sequence", "previous_hash_hex", "event", "hash_hex"))
        body = {key: value for key, value in row.items() if key != "hash_hex"}
        _require(row["schema"] == "ptlc-nom-recovery-log-v1" and type(row["sequence"]) is int
            and row["sequence"] == sequence and row["previous_hash_hex"] == head
            and row["hash_hex"] == recovery.digest(b"ptlc-nom-log-v1", body))
        replay._state = replay._apply(row["event"]); head = row["hash_hex"]
    return replay, head, len(lines)


def _hold(replay, challenge_hex):
    state = replay._state; count = state["recovery_count"]
    _require(type(count) is int and 1 <= count <= recovery.MAX_RECOVERIES
        and state["disclosure_possible"] is True and bool(state["remote_short_hex"]))
    short = bytes.fromhex(state["remote_short_hex"])
    context = recovery.verification_context_digest(replay.terms, replay.pair)
    short_pin = partial.short_digest(short)
    work = [dict(attempt_id_hex=recovery.digest(WORK_DOMAIN, dict(
        verification_context_digest_hex=context, short_original_digest_hex=short_pin,
        charged_ordinal=ordinal)), short_original_digest_hex=short_pin, outcome="UNKNOWN")
        for ordinal in range(1, count + 1)]
    original = state["originals"].get("long")
    return partial.select_partial_hold(replay.terms, replay.pair, short, charged_work=work,
        prior_evidence=[], recovered_long_signature=state["recovered_long_hex"] or None,
        original_long=None if original is None else bytes.fromhex(original), challenge_hex=challenge_hex)


def _read(owner):
    """Bounded reads through the same owned descriptor, without changing its offset."""
    owner._check(); size = owner._size
    _require(type(size) is int and 0 < size <= recovery.MAX_LOG)
    wire = b""
    while len(wire) < size:
        part = os.pread(owner._fd, min(65536, size - len(wire)), len(wire))
        _require(type(part) is bytes and 0 < len(part) <= size - len(wire))
        wire += part
    _require(os.pread(owner._fd, 1, size) == b"")
    owner._check()
    return wire


@dataclass(frozen=True, init=False)
class JournalPartialHold:
    """Immutable exact-byte custody in memory, not a transferable authority token."""

    _journal: bytes
    _hold: partial.PartialCustodyHold

    def __init__(self):
        raise TypeError("use project_partial_hold")

    def as_dict(self):
        try:
            _require(type(self) is JournalPartialHold and type(self._hold) is partial.PartialCustodyHold)
            replay, head, sequence = _replay(self._journal)
            expected = _hold(replay, self._hold.selection()["challenge_hex"])
            partial.compare_hold(expected, self._hold.canonical_bytes)
            return dict(schema=PROFILE, journal_hex=self._journal.hex(),
                journal_sha256=hashlib.sha256(self._journal).hexdigest(), journal_bytes=len(self._journal),
                journal_head_hex=head, journal_sequence=sequence, role=replay.role,
                partial_hold_hex=self._hold.canonical_bytes.hex(),
                selection_digest_hex=self._hold.selection_digest_hex)
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
            raise JournalProjectionRefused("invalid selected journal partial HOLD") from None

    @property
    def journal_bytes(self):
        self.as_dict()
        return self._journal

    @property
    def partial_hold(self):
        self.as_dict()
        return self._hold

    def review(self):
        selected = self.as_dict(); hold = self._hold.selection()
        return dict(profile=PROFILE, state="HOLD", recovery_action="NONE",
            journal_sha256=selected["journal_sha256"], journal_head_hex=selected["journal_head_hex"],
            journal_sequence=selected["journal_sequence"], selected_open=OPEN_PROFILE,
            present_result_gate="ABSENT" if hold["recovered_long_signature_hex"] is None
                else "VERIFIED BY SELECTED STRICT OPEN BEFORE OWNER RETURN",
            work_identity="CONTEXT, EXACT SHORT AND PERSISTED ORDINAL; RESEARCH ONLY",
            work_execution="UNKNOWN; NO INDIVIDUAL EXECUTION RECEIPTS IN V1 JOURNAL",
            source_currentness="UNFILLED", source_authentication="NOT_PERFORMED",
            restore_fence="UNFILLED", durable_retention="NOT_IMPLEMENTED",
            atomic_work_admission="UNFILLED", native_query_context_pairing="NOT_COMPOSED",
            complete_query_conversion="NOT_PROVIDED", automatic_retry=False, replenish_work=False,
            frozen_partial_review=self._hold.review(), application="NO-GO", core="NO-GO")


def project_partial_hold(owner, *, challenge_hex):
    """Select an existing strict owner; no reopen, worker entry, mutation or close."""
    try:
        _require(type(owner) is StrictNomRecovery)
        status = owner.status(); terms, pair, role = owner.terms, owner.pair, owner.role
        wire = _read(owner); replay, head, sequence = _replay(wire)
        _require(replay._state == status and replay.terms == terms and replay.pair == pair
            and replay.role == role and head == owner._head and sequence == owner._sequence)
        hold = _hold(replay, challenge_hex)
        _require(owner.status() == status and owner.terms == terms and owner.pair == pair
            and owner.role == role and owner._head == head and owner._sequence == sequence
            and _read(owner) == wire)
        result = object.__new__(JournalPartialHold)
        object.__setattr__(result, "_journal", wire); object.__setattr__(result, "_hold", hold)
        return result
    except recovery.RecoveryError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise JournalProjectionRefused("unable to select journal partial HOLD") from None
