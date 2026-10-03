"""POSIX-only offline ownership journal for public, synthetic operations.

This is not a cryptographic nonce store or a signer. The callback must be a pure
synthetic producer: the journal cannot undo callback side effects. An external
checkpoint detects one-sided rollback, not restoration of both copies. Advisory
locks protect cooperating processes, not a hostile host or modified journal code.
"""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import threading
from urllib.parse import quote

try:
    import fcntl
except ImportError:  # Import remains possible so unsupported hosts fail clearly.
    fcntl = None

from . import authentication, completion, exchange
from .transcript import agree_terms, validate_signing_context


MAX_OUTPUT_BYTES = 65536
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_RECOVERY_ATTEMPTS = 64
VERSION = 7
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_PURPOSES = {
    "bitcoin-claim-partial", "zenon-claim-partial",
    "bitcoin-claim-complete", "zenon-claim-complete",
}
_STATUSES = {"RESERVED", "RETIRED", "CONSUMED", "OUTCOME_UNKNOWN", "OUTPUT_RECORDED"}


class JournalError(Exception):
    """Sanitized journal error; messages contain no supplied paths or data."""


class InvalidInput(JournalError):
    pass


class Conflict(JournalError):
    pass


class RecoveryExhausted(JournalError):
    pass


class OutcomeUnknown(JournalError):
    pass


class Quarantined(JournalError):
    pass


class Busy(JournalError):
    pass


class OwnershipError(JournalError):
    pass


def _hex(value):
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise InvalidInput("expected a lowercase 32-byte identifier")
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _decode(data):
    return json.loads(data, object_pairs_hook=_unique_object)


def _digest(lineage, sequence, state):
    material = {"version": VERSION, "lineage": lineage, "sequence": sequence, "state": state}
    return hashlib.sha256(b"ptlc-offline-journal-v7\x00" + _canonical(material)).hexdigest()


def _public_nonce_digest(encoded):
    # Excluding role/session/leg from this domain detects identical public bytes
    # across those scopes. It proves neither freshness nor secret nonce ownership.
    return hashlib.sha256(b"ptlc-offline-public-nonce-v1\x00" + bytes.fromhex(encoded)).hexdigest()


def _context_fields(context):
    """Read pins only after the complete immutable context has been validated."""
    context_session, digest, purpose = validate_signing_context(context)
    payload = context.as_dict()
    role = payload["role"]
    binding = payload["binding"]
    bitcoin = binding["bitcoin"] if payload["leg"] == "zenon" else binding
    terms_digest = bitcoin["terms_digest_hex"]
    bitcoin_digest = binding["bitcoin_digest_hex"] if payload["leg"] == "zenon" else payload["binding_digest_hex"]
    zenon_digest = payload["binding_digest_hex"] if payload["leg"] == "zenon" else None
    leg = payload["leg"]
    round_digest = payload.get("nonce_round_digest_hex")
    nonce_digests = None
    if round_digest is not None:
        nonces = payload["nonce_round"]["public_nonces"]
        nonce_digests = [_public_nonce_digest(nonces[party]) for party in ("alice", "bob")]
    return (context_session, terms_digest, digest, purpose, role, bitcoin_digest,
            zenon_digest, leg, round_digest, nonce_digests)


def _bob_authentication_context(state, pins):
    """Rebuild public authentication inputs from stored Bob terms and local pins.

    This checks pin encodings and key separation, not curve validity or how the
    caller selected the pins. The actual public verifier parses both curve keys.
    """
    if (type(pins) is not dict or any(type(key) is not str for key in pins)
            or set(pins) != {"alice_auth_key_hex", "bob_auth_key_hex"}
            or any(type(value) is not str for value in pins.values())):
        raise ValueError("invalid Bob authentication pins")
    bitcoin = exchange.contexts(state)[0]
    terms = agree_terms(bitcoin.as_dict()["binding"]["terms"])
    return authentication.context(terms, **pins)


def _validate_state(state):
    """Validate the complete materialized state before accepting its checkpoint."""
    if not isinstance(state, dict) or set(state) != {"sessions"} or not isinstance(state["sessions"], dict):
        raise ValueError("invalid state")
    nonce_tags = set()
    public_nonce_digests = set()
    for session_id, session in state["sessions"].items():
        _hex(session_id)
        if not isinstance(session, dict) or set(session) != {
            "terms_digest", "possible_exposure", "operations", "observations",
            "bitcoin_binding_digest", "zenon_binding_digest",
            "signing_rounds", "signing_round_nonces", "exchange", "alice", "recovery_budget",
            "authentication_pins",
        }:
            raise ValueError("invalid session")
        _hex(session["terms_digest"])
        for binding in ("bitcoin_binding_digest", "zenon_binding_digest"):
            if session[binding] is not None:
                _hex(session[binding])
        if type(session["possible_exposure"]) is not bool:
            raise ValueError("invalid exposure")
        if not isinstance(session["operations"], dict) or not isinstance(session["observations"], list):
            raise ValueError("invalid session collections")
        rounds = session["signing_rounds"]
        if not isinstance(rounds, dict) or not set(rounds).issubset({"bitcoin", "zenon"}):
            raise ValueError("invalid signing round pins")
        for round_digest in rounds.values():
            if round_digest is not None:
                _hex(round_digest)
        round_nonces = session["signing_round_nonces"]
        if not isinstance(round_nonces, dict) or set(round_nonces) != {
            leg for leg, digest in rounds.items() if digest is not None
        }:
            raise ValueError("invalid public nonce pins")
        for nonce_digests in round_nonces.values():
            if not isinstance(nonce_digests, list) or len(nonce_digests) != 2:
                raise ValueError("invalid public nonce pair")
            for digest in nonce_digests:
                _hex(digest)
                if digest in public_nonce_digests:
                    raise ValueError("public nonce encoding reused across round scopes")
                public_nonce_digests.add(digest)
        scopes, contexts, observed_legs = set(), set(), set()
        if session["exchange"] is not None and session["alice"] is not None:
            raise ValueError("managed participant ownership is exclusive")
        budget = session["recovery_budget"]
        pins = session["authentication_pins"]
        if session["exchange"] is None:
            if budget is not None:
                raise ValueError("recovery allowance requires a managed Bob exchange")
            if pins is not None:
                raise ValueError("authentication pins require a managed Bob exchange")
        elif (type(budget) is not dict or set(budget) != {"limit", "consumed"}
              or type(budget["limit"]) is not int or not 1 <= budget["limit"] <= MAX_RECOVERY_ATTEMPTS
              or type(budget["consumed"]) is not int or not 0 <= budget["consumed"] <= budget["limit"]):
            raise ValueError("invalid Bob recovery allowance")
        managed = None
        if session["alice"] is not None:
            completion.validate_state(session["alice"])
            exposed = session["alice"]["stage"] in {
                "COMPLETION_CONSUMED", "OUTCOME_UNKNOWN", "COMPLETION_RECORDED",
            }
            if session["possible_exposure"] != exposed:
                raise ValueError("Alice completion exposure contradicts stored state")
            managed = completion.contexts(session["alice"])
        elif session["exchange"] is not None:
            exchange.validate_state(session["exchange"])
            if pins is not None:
                _bob_authentication_context(session["exchange"], pins)
            exchange_stage = session["exchange"]["stage"]
            candidate = session["exchange"]["zenon_completion_packet_hex"] is not None
            if exchange_stage not in {"RELEASE_RECORDED", "BTC_COMPLETION_RECORDED"} and budget["consumed"] != 0:
                raise ValueError("Bob recovery admission precedes release")
            if candidate and budget["consumed"] < 1:
                raise ValueError("Bob observation lacks a recovery admission")
            if not candidate and budget["consumed"] != 0:
                raise ValueError("Bob recovery admission lacks its observation")
            if exchange_stage == "BTC_COMPLETION_RECORDED" and budget["consumed"] < 1:
                raise ValueError("Bitcoin completion lacks a recovery admission")
            if session["exchange"]["superseded_zenon_completion_packet_hex"] is not None and budget["consumed"] < 2:
                raise ValueError("reconciliation lacks separate observation and replacement admissions")
            if candidate != session["possible_exposure"]:
                raise ValueError("Bob observation contradicts possible witness exposure")
            if exchange_stage == "BTC_COMPLETION_RECORDED" and not session["possible_exposure"]:
                raise ValueError("Bitcoin completion lacks possible witness exposure")
            if session["possible_exposure"] and exchange_stage not in {"RELEASE_RECORDED", "BTC_COMPLETION_RECORDED"}:
                raise ValueError("Bob witness exposure precedes the completion observation")
            managed = exchange.contexts(session["exchange"])
        if managed is not None:
            if session["operations"]:
                raise ValueError("managed exchange cannot contain generic operations")
            for context in managed:
                (context_session, terms_digest, _, _, _, bitcoin_digest,
                 zenon_digest, leg, round_digest, nonce_digests) = _context_fields(context)
                if context_session != session_id or terms_digest != session["terms_digest"]:
                    raise ValueError("managed exchange terms mismatch")
                if session["bitcoin_binding_digest"] != bitcoin_digest:
                    raise ValueError("managed exchange Bitcoin pin mismatch")
                if zenon_digest is not None and session["zenon_binding_digest"] != zenon_digest:
                    raise ValueError("managed exchange Zenon pin mismatch")
                if round_digest is None or rounds.get(leg) != round_digest:
                    raise ValueError("managed exchange round pin mismatch")
                if round_nonces.get(leg) != nonce_digests:
                    raise ValueError("managed exchange public nonce pin mismatch")
                observed_legs.add(leg)
            if ("zenon" in observed_legs) != (session["zenon_binding_digest"] is not None):
                raise ValueError("managed exchange orphan Zenon pin")
        for operation_id, operation in session["operations"].items():
            if session["bitcoin_binding_digest"] is None:
                raise ValueError("missing Bitcoin stage binding")
            _hex(operation_id)
            if not isinstance(operation, dict) or set(operation) != {
                "context_digest", "role", "purpose", "nonce_tag", "status", "output_b64",
                "nonce_round_digest",
            }:
                raise ValueError("invalid operation")
            _hex(operation["context_digest"])
            _hex(operation["nonce_tag"])
            if operation["role"] not in {"alice", "bob"} or operation["purpose"] not in _PURPOSES:
                raise ValueError("invalid operation scope")
            if operation["purpose"] == "zenon-claim-complete" and operation["role"] != "alice":
                raise ValueError("invalid completing role")
            if operation["purpose"] == "bitcoin-claim-complete" and operation["role"] != "bob":
                raise ValueError("invalid completing role")
            if operation["purpose"].startswith("zenon-") and session["zenon_binding_digest"] is None:
                raise ValueError("missing Zenon stage binding")
            leg = operation["purpose"].split("-", 1)[0]
            observed_legs.add(leg)
            round_digest = operation["nonce_round_digest"]
            if round_digest is not None:
                _hex(round_digest)
            if leg not in rounds or rounds[leg] != round_digest:
                raise ValueError("operation signing round differs from session pin")
            scope = (operation["role"], operation["purpose"])
            if scope in scopes or operation["context_digest"] in contexts or operation["nonce_tag"] in nonce_tags:
                raise ValueError("duplicate ownership")
            scopes.add(scope)
            contexts.add(operation["context_digest"])
            nonce_tags.add(operation["nonce_tag"])
            if operation["status"] not in _STATUSES:
                raise ValueError("invalid operation status")
            if operation["status"] == "OUTPUT_RECORDED":
                output = base64.b64decode(operation["output_b64"], validate=True)
                if len(output) > MAX_OUTPUT_BYTES or base64.b64encode(output).decode("ascii") != operation["output_b64"]:
                    raise ValueError("invalid public output")
            elif operation["output_b64"] is not None:
                raise ValueError("unexpected output")
            if (operation["purpose"] == "zenon-claim-complete"
                    and operation["status"] in {"CONSUMED", "OUTCOME_UNKNOWN", "OUTPUT_RECORDED"}
                    and not session["possible_exposure"]):
                raise ValueError("missing exposure")
        if set(rounds) != observed_legs:
            raise ValueError("signing round pin has no corresponding operation")
        for observation in session["observations"]:
            if not isinstance(observation, dict) or set(observation) != {"digest", "reorg"}:
                raise ValueError("invalid observation")
            _hex(observation["digest"])
            if type(observation["reorg"]) is not bool:
                raise ValueError("invalid reorg marker")


def _regular_private(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise Quarantined("journal files require private regular-file ownership")


def _sync_directory(path):
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Journal:
    """A context-owned SQLite state and independently stored checkpoint.

    All identifiers and digests are lowercase 64-character hexadecimal strings.
    A nonce_tag is public opaque metadata, never a nonce or a secret. Each
    (session, role, purpose) can be reserved only once, even after retirement.
    Each leg also pins one validated public nonce round, or static context mode.
    Dynamic rounds reject duplicate public nonce encodings visible in this journal;
    this public-byte check cannot prove freshness or ownership of secret nonces.
    Versions 1 through 6 are quarantined; this experiment has no migration.
    Managed exchanges retain public artifacts under a caller-supplied verifier;
    that verifier is a trusted local boundary, not automatic cryptographic proof.
    """

    @classmethod
    def open(cls, rootdir, anchorpath, *, hook=None):
        """Acquire persistent nonblocking locks before opening either state copy."""
        instance = cls.__new__(cls)
        instance._pid = os.getpid()
        instance._thread = threading.current_thread()
        instance._connection = None
        instance._locks = []
        instance._closed = False
        instance._poisoned = False
        instance._producing = False
        instance._writing = False
        instance._hook = hook
        try:
            instance._open(rootdir, anchorpath)
            return instance
        except BaseException as error:
            instance._poisoned = True
            instance._release()
            if isinstance(error, JournalError):
                raise error from None
            raise Quarantined("journal initialization failed") from None

    def _open(self, rootdir, anchorpath):
        if os.name != "posix" or fcntl is None:
            raise InvalidInput("this journal requires POSIX advisory locks")
        if self._hook is not None and not callable(self._hook):
            raise InvalidInput("hook must be callable")
        root = Path(rootdir).absolute()
        anchor = Path(anchorpath).absolute()
        if root.is_symlink() or anchor.is_symlink():
            raise Quarantined("symlink state paths are unsupported")
        root.mkdir(mode=0o700, exist_ok=True)
        info = root.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or info.st_uid != os.geteuid():
            raise Quarantined("journal directory ownership is unsupported")
        self._root = root.resolve()
        self._anchor = anchor.parent.resolve() / anchor.name
        if self._anchor == self._root or self._root in self._anchor.parents:
            raise InvalidInput("checkpoint must be outside the journal directory")
        if not self._anchor.parent.is_dir():
            raise InvalidInput("checkpoint parent must already exist")
        self._dbpath = self._root / "journal.sqlite3"
        self._take_lock(self._root / "journal.lock")
        self._take_lock(self._anchor.with_name(self._anchor.name + ".lock"))
        # No checkpoint contents or SQLite state are read until both locks exist.
        db_exists = self._dbpath.exists() or self._dbpath.is_symlink()
        anchor_exists = self._anchor.exists() or self._anchor.is_symlink()
        if db_exists != anchor_exists:
            raise Quarantined("journal and checkpoint must both exist or both be absent")
        for suffix in ("-wal", "-shm"):
            if Path(str(self._dbpath) + suffix).exists():
                raise Quarantined("unsupported SQLite sidecar")
        rollback = Path(str(self._dbpath) + "-journal")
        if rollback.exists() or rollback.is_symlink():
            _regular_private(rollback)
        if db_exists:
            _regular_private(self._dbpath)
            _regular_private(self._anchor)
        else:
            descriptor = os.open(str(self._dbpath), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            _sync_directory(self._root)
        self._connection = sqlite3.connect(
            "file:" + quote(str(self._dbpath), safe="/") + "?mode=rw",
            uri=True, isolation_level=None, timeout=0,
        )
        if self._connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
            raise Quarantined("unsupported SQLite journal mode")
        self._connection.execute("PRAGMA synchronous=FULL")
        if self._connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise Quarantined("SQLite durability mode unavailable")
        if self._connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise Quarantined("SQLite integrity check failed")
        if not db_exists:
            self._lineage = os.urandom(32).hex()  # Public lineage metadata only.
            self._sequence = -1
            self._state = {"sessions": {}}
            self._persist(self._state, initializing=True)
        else:
            try:
                self._load()
            except Exception:
                raise Quarantined("journal checkpoint validation failed") from None
            recovered = copy.deepcopy(self._state)
            changed = False
            for session in recovered["sessions"].values():
                if session["alice"] is not None and session["alice"]["stage"] == "COMPLETION_CONSUMED":
                    session["alice"] = completion.recover(session["alice"])
                    changed = True
                for operation in session["operations"].values():
                    if operation["status"] == "RESERVED":
                        operation["status"] = "RETIRED"
                        changed = True
                    elif operation["status"] == "CONSUMED":
                        operation["status"] = "OUTCOME_UNKNOWN"
                        changed = True
            if changed:
                self._persist(recovered)

    def _take_lock(self, path):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
                raise Quarantined("lock ownership is unsupported")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy("journal ownership is already held") from None
            self._locks.append(descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def _load(self):
        rows = self._connection.execute(
            "SELECT slot, version, lineage, sequence, state_json, digest FROM checkpoint"
        ).fetchall()
        if len(rows) != 1:
            raise Quarantined("unsupported checkpoint table")
        slot, version, lineage, sequence, raw, stored_digest = rows[0]
        if slot != 1 or version != VERSION or type(sequence) is not int or sequence < 0:
            raise Quarantined("unsupported checkpoint version")
        _hex(lineage)
        _hex(stored_digest)
        if not isinstance(raw, str) or len(raw) > MAX_STATE_BYTES:
            raise Quarantined("checkpoint state is invalid")
        state = _decode(raw)
        _validate_state(state)
        if _canonical(state).decode("ascii") != raw:
            raise Quarantined("checkpoint state is not canonical")
        calculated = _digest(lineage, sequence, state)
        if calculated != stored_digest:
            raise Quarantined("checkpoint content digest mismatch")
        with self._anchor.open("rb") as stream:
            anchor_raw = stream.read(1025)
        if len(anchor_raw) > 1024:
            raise Quarantined("checkpoint anchor is invalid")
        anchor = _decode(anchor_raw)
        expected = {"version": VERSION, "lineage": lineage, "sequence": sequence, "digest": calculated}
        if anchor != expected or _canonical(expected) != anchor_raw:
            raise Quarantined("journal checkpoint divergence")
        self._lineage, self._sequence, self._state = lineage, sequence, state

    def _check(self, *, mutation=False):
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            raise OwnershipError("inherited journal ownership is invalid")
        if self._closed:
            raise OwnershipError("journal ownership is closed")
        if self._poisoned:
            raise Quarantined("journal instance is quarantined")
        if mutation and (self._producing or self._writing):
            raise Conflict("journal mutation reentrancy is unsupported")

    def _checkpoint(self, name):
        if self._hook is not None:
            self._hook(name)

    def _write_anchor(self, anchor):
        descriptor, temporary = tempfile.mkstemp(prefix=".ptlc-checkpoint-", dir=str(self._anchor.parent))
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(_canonical(anchor))
                stream.flush()
                os.fsync(stream.fileno())
            if self._anchor.is_symlink():
                raise Quarantined("symlink checkpoint is unsupported")
            os.replace(temporary, self._anchor)
            self._checkpoint("after_anchor_replace")
            _sync_directory(self._anchor.parent)
            self._checkpoint("after_anchor_commit")
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _persist(self, state, *, initializing=False):
        self._check()
        _validate_state(state)
        if not initializing:
            for session_id, current in state["sessions"].items():
                new_budget = current["recovery_budget"]
                previous = self._state["sessions"].get(session_id)
                if (new_budget is not None
                        and (previous is None or previous["recovery_budget"] is None)
                        and new_budget["consumed"] != 0):
                    raise Conflict("Bob recovery allowance must start unconsumed")
            for session_id, previous in self._state["sessions"].items():
                current = state["sessions"].get(session_id)
                if previous["exchange"] is not None:
                    if (current is None or current["exchange"] is None
                            or current["authentication_pins"] != previous["authentication_pins"]
                            or current["terms_digest"] != previous["terms_digest"]
                            or _canonical(current["exchange"]["bitcoin_context"])
                            != _canonical(previous["exchange"]["bitcoin_context"])):
                        raise Conflict("Bob authentication choice and Bitcoin context cannot change")
                old_budget = previous["recovery_budget"]
                if old_budget is None:
                    continue
                new_budget = None if current is None else current["recovery_budget"]
                if (new_budget is None or new_budget["limit"] != old_budget["limit"]
                        or new_budget["consumed"] < old_budget["consumed"]
                        or new_budget["consumed"] > old_budget["consumed"] + 1):
                    raise Conflict("Bob recovery allowance cannot be reset or changed")
        raw = _canonical(state)
        if len(raw) > MAX_STATE_BYTES:
            raise InvalidInput("journal state exceeds its offline bound")
        sequence = self._sequence + 1
        digest = _digest(self._lineage, sequence, state)
        self._writing = True
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            if initializing:
                self._connection.execute(
                    "CREATE TABLE checkpoint (slot INTEGER PRIMARY KEY CHECK(slot=1), "
                    "version INTEGER NOT NULL, lineage TEXT NOT NULL, sequence INTEGER NOT NULL, "
                    "state_json TEXT NOT NULL, digest TEXT NOT NULL)"
                )
            self._connection.execute(
                "INSERT OR REPLACE INTO checkpoint VALUES (1, ?, ?, ?, ?, ?)",
                (VERSION, self._lineage, sequence, raw.decode("ascii"), digest),
            )
            self._checkpoint("before_db_commit")
            self._connection.commit()
            self._checkpoint("after_db_commit")
            self._write_anchor({"version": VERSION, "lineage": self._lineage, "sequence": sequence, "digest": digest})
            self._state, self._sequence = state, sequence
        except BaseException:
            self._poisoned = True
            try:
                self._connection.rollback()
            except BaseException:
                pass
            raise Quarantined("journal durability outcome is uncertain") from None
        finally:
            self._writing = False

    def _context(self, session_id, context):
        _hex(session_id)
        try:
            (context_session, terms_digest, digest, purpose, role, bitcoin_digest,
             zenon_digest, leg, round_digest, nonce_digests) = _context_fields(context)
        except Exception:
            raise InvalidInput("validated signing context required") from None
        if context_session != session_id:
            raise Conflict("signing context session mismatch")
        session = self._session(session_id)
        if session["terms_digest"] != terms_digest:
            raise Conflict("signing context terms mismatch")
        if session["bitcoin_binding_digest"] not in (None, bitcoin_digest):
            raise Conflict("signing context Bitcoin stage mismatch")
        if zenon_digest is not None and session["zenon_binding_digest"] not in (None, zenon_digest):
            raise Conflict("signing context Zenon stage mismatch")
        if leg in session["signing_rounds"] and session["signing_rounds"][leg] != round_digest:
            raise Conflict("signing context nonce round mismatch")
        if (leg in session["signing_round_nonces"]
                and session["signing_round_nonces"][leg] != nonce_digests):
            raise Conflict("signing context public nonce mismatch")
        return digest, purpose, role, bitcoin_digest, zenon_digest, leg, round_digest, nonce_digests

    def _pin_context(self, state, session_id, context):
        """Pin a validated context while retaining the complete local nonce history."""
        (_, _, _, bitcoin_digest, zenon_digest,
         leg, round_digest, nonce_digests) = self._context(session_id, context)
        if nonce_digests is not None:
            for previous_id, previous_session in self._state["sessions"].items():
                for previous_leg, previous_nonces in previous_session["signing_round_nonces"].items():
                    if (previous_id, previous_leg) != (session_id, leg) and set(nonce_digests).intersection(previous_nonces):
                        raise Conflict("public nonce encoding is already pinned to another round scope")
        session = state["sessions"][session_id]
        session["bitcoin_binding_digest"] = bitcoin_digest
        if zenon_digest is not None:
            session["zenon_binding_digest"] = zenon_digest
        session["signing_rounds"][leg] = round_digest
        if nonce_digests is not None:
            session["signing_round_nonces"][leg] = nonce_digests

    def _session(self, session_id):
        _hex(session_id)
        if session_id not in self._state["sessions"]:
            raise Conflict("session is not recorded")
        return self._state["sessions"][session_id]

    def _operation(self, session_id, operation_id, expected_context):
        self._generic_session(session_id)
        digest, purpose, role, _, _, _, round_digest, _ = self._context(session_id, expected_context)
        _hex(operation_id)
        operation = self._session(session_id)["operations"].get(operation_id)
        if operation is None:
            raise Conflict("operation is not recorded")
        if (operation["context_digest"], operation["purpose"], operation["role"]) != (digest, purpose, role):
            raise Conflict("operation context mismatch")
        if operation["nonce_round_digest"] != round_digest:
            raise Conflict("operation nonce round mismatch")
        return operation

    def _generic_session(self, session_id):
        session = self._session(session_id)
        if session["exchange"] is not None or session["alice"] is not None:
            raise Conflict("managed exchange excludes generic operations")
        return session

    def create_session(self, session_id, terms_digest):
        self._check(mutation=True)
        _hex(session_id)
        _hex(terms_digest)
        if session_id in self._state["sessions"]:
            raise Conflict("session identifier is already recorded")
        state = copy.deepcopy(self._state)
        state["sessions"][session_id] = {
            "terms_digest": terms_digest, "possible_exposure": False,
            "bitcoin_binding_digest": None, "zenon_binding_digest": None,
            "signing_rounds": {}, "signing_round_nonces": {}, "operations": {}, "observations": [],
            "exchange": None, "alice": None, "recovery_budget": None,
            "authentication_pins": None,
        }
        self._persist(state)

    def reserve(self, session_id, operation_id, context, nonce_tag):
        self._check(mutation=True)
        digest, purpose, role, _, _, _, round_digest, _ = self._context(session_id, context)
        _hex(operation_id)
        _hex(nonce_tag)
        session = self._generic_session(session_id)
        if operation_id in session["operations"]:
            raise Conflict("operation identifier is already recorded")
        for previous_session in self._state["sessions"].values():
            for operation in previous_session["operations"].values():
                if operation["nonce_tag"] == nonce_tag:
                    raise Conflict("nonce ownership tag is already recorded")
        for operation in session["operations"].values():
            if operation["context_digest"] == digest or (operation["role"], operation["purpose"]) == (role, purpose):
                raise Conflict("signing scope is already sealed")
        state = copy.deepcopy(self._state)
        self._pin_context(state, session_id, context)
        state["sessions"][session_id]["operations"][operation_id] = {
            "context_digest": digest, "purpose": purpose, "role": role,
            "nonce_tag": nonce_tag, "status": "RESERVED", "output_b64": None,
            "nonce_round_digest": round_digest,
        }
        self._persist(state)

    def produce_once(self, session_id, operation_id, *, expected_context, callback):
        """Consume ownership, call a synthetic producer once, then record its bytes.

        This method never replays a completed operation; use replay explicitly.
        Failure after consumption seals the operation, even if no bytes escaped.
        """
        self._check(mutation=True)
        operation = self._operation(session_id, operation_id, expected_context)
        if operation["status"] != "RESERVED":
            raise OutcomeUnknown("operation cannot invoke a producer again")
        if not callable(callback):
            raise InvalidInput("synthetic producer must be callable")
        state = copy.deepcopy(self._state)
        state["sessions"][session_id]["operations"][operation_id]["status"] = "CONSUMED"
        if operation["purpose"] == "zenon-claim-complete":
            state["sessions"][session_id]["possible_exposure"] = True
        self._producing = True
        try:
            self._persist(state)
            try:
                self._checkpoint("after_consume")
            except BaseException:
                self._poisoned = True
                raise Quarantined("producer checkpoint outcome is uncertain") from None
            try:
                self._check()
                output = callback()
            except BaseException:
                raise OutcomeUnknown("synthetic producer outcome is unknown") from None
            try:
                self._checkpoint("after_callback")
            except BaseException:
                self._poisoned = True
                raise Quarantined("producer checkpoint outcome is uncertain") from None
            if type(output) is not bytes or len(output) > MAX_OUTPUT_BYTES:
                raise OutcomeUnknown("synthetic output failed its public byte bound")
            state = copy.deepcopy(self._state)
            record = state["sessions"][session_id]["operations"][operation_id]
            record["status"] = "OUTPUT_RECORDED"
            record["output_b64"] = base64.b64encode(output).decode("ascii")
            self._persist(state)
            try:
                self._checkpoint("after_output_commit")
            except BaseException:
                self._poisoned = True
                raise Quarantined("producer checkpoint outcome is uncertain") from None
            return output
        finally:
            self._producing = False

    def replay(self, session_id, operation_id, *, expected_context):
        self._check()
        operation = self._operation(session_id, operation_id, expected_context)
        if operation["status"] != "OUTPUT_RECORDED":
            raise OutcomeUnknown("no durable public output is available")
        return base64.b64decode(operation["output_b64"], validate=True)

    def _exchange_transition(self, session_id, transition, *, context=None,
                             starting=False, releasing=False, checkpoint=None, recovery_limit=None,
                             authentication_pins=None):
        """Keep the complete verifier, reducer and commit under one owner guard."""
        self._check(mutation=True)
        session = self._session(session_id)
        if starting:
            if session["exchange"] is not None or session["alice"] is not None or session["operations"]:
                raise Conflict("session is already owned by another operation flow")
        elif session["exchange"] is None:
            raise Conflict("managed exchange is not recorded")
        state = copy.deepcopy(self._state)
        if context is not None:
            self._pin_context(state, session_id, context)
        self._producing = True
        try:
            try:
                result = transition(copy.deepcopy(session["exchange"]))
            except exchange.ExchangeError:
                raise Conflict("managed exchange transition rejected") from None
            output = None
            if releasing:
                result, output = result
            state["sessions"][session_id]["exchange"] = result
            if starting:
                if authentication_pins is not None:
                    try:
                        if type(authentication_pins) is not dict:
                            raise ValueError("invalid Bob authentication pins")
                        stored_pins = authentication_pins.copy()
                        _bob_authentication_context(result, stored_pins)
                    except Exception:
                        raise InvalidInput("valid local Bob authentication pins are required") from None
                    state["sessions"][session_id]["authentication_pins"] = stored_pins
                state["sessions"][session_id]["recovery_budget"] = {"limit": recovery_limit, "consumed": 0}
            self._check()
            self._persist(state)
            if checkpoint is not None:
                try:
                    self._checkpoint(checkpoint)
                except BaseException:
                    self._poisoned = True
                    raise Quarantined("managed exchange checkpoint outcome is uncertain") from None
            self._check()
            return output
        finally:
            self._producing = False

    def start_exchange(self, session_id, bitcoin_context, *, recovery_limit, authentication_pins=None):
        """Freeze Bob's recovery allowance and optional locally selected pins.

        Both the configured pair and the choice of no pins are immutable. Pins
        add an optional envelope helper; raw public recovery remains independent.
        """
        self._check(mutation=True)
        if type(recovery_limit) is not int or not 1 <= recovery_limit <= MAX_RECOVERY_ATTEMPTS:
            raise InvalidInput("Bob recovery limit must be an integer from 1 through 64")
        return self._exchange_transition(
            session_id, lambda _: exchange.start(bitcoin_context),
            context=bitcoin_context, starting=True, recovery_limit=recovery_limit,
            authentication_pins=authentication_pins,
        )

    def authenticate_exchange_envelope(self, session_id, envelope_bytes, *, verifier):
        """Authenticate exact opaque bytes relative to the durable local pins.

        No receipt, observation, exposure, recovery debit or stage is written.
        Success does not establish payload validity, freshness or an admission
        permit. The caller may separately use the ordinary public recovery APIs.
        """
        self._check(mutation=True)
        session = self._session(session_id)
        if session["exchange"] is None:
            raise Conflict("managed exchange is not recorded")
        if session["authentication_pins"] is None:
            raise Conflict("Bob authentication pins are not configured")
        if not callable(verifier):
            raise InvalidInput("public authentication verifier must be callable")
        self._producing = True
        try:
            try:
                context = _bob_authentication_context(
                    copy.deepcopy(session["exchange"]), session["authentication_pins"].copy(),
                )
                payload = authentication.authenticate(context, envelope_bytes, verifier=verifier)
            except Exception:
                raise Conflict("Bob envelope authentication rejected") from None
            self._check()
            return payload
        finally:
            self._producing = False

    def bind_exchange_zenon(self, session_id, zenon_context):
        return self._exchange_transition(
            session_id, lambda state: exchange.bind_zenon(state, zenon_context),
            context=zenon_context,
        )

    def retain_exchange_bitcoin(self, session_id, bundle, *, verifier):
        """Retain public artifacts only after the trusted verifier accepts them."""
        return self._exchange_transition(
            session_id, lambda state: exchange.retain_bitcoin(state, bundle, verifier),
        )

    def retain_exchange_alice_partial(self, session_id, partial_hex, *, verifier):
        return self._exchange_transition(
            session_id, lambda state: exchange.retain_alice_partial(state, partial_hex, verifier),
        )

    def retain_exchange_zenon(self, session_id, bundle, *, verifier):
        return self._exchange_transition(
            session_id, lambda state: exchange.retain_zenon(state, bundle, verifier),
            checkpoint="after_exchange_retained",
        )

    def release_exchange_zenon(self, session_id):
        """Durably mark possible release before returning exact public bytes."""
        return self._exchange_transition(
            session_id, exchange.release, releasing=True,
            checkpoint="after_exchange_release_commit",
        )

    def replay_exchange_release(self, session_id):
        """Read the exact durable release without invoking a verifier or signer."""
        self._check()
        state = self._session(session_id)["exchange"]
        if state is None:
            raise Conflict("managed exchange is not recorded")
        try:
            return exchange.replay(copy.deepcopy(state))
        except exchange.ExchangeError:
            raise OutcomeUnknown("no durable managed release is available") from None

    def get_exchange(self, session_id):
        self._check()
        state = self._session(session_id)["exchange"]
        if state is None:
            raise Conflict("managed exchange is not recorded")
        return copy.deepcopy(state)

    def _alice_transition(self, session_id, transition, *, context=None, starting=False):
        self._check(mutation=True)
        session = self._session(session_id)
        if starting:
            if session["alice"] is not None or session["exchange"] is not None or session["operations"]:
                raise Conflict("session is already owned by another operation flow")
        elif session["alice"] is None:
            raise Conflict("managed Alice completion is not recorded")
        state = copy.deepcopy(self._state)
        if context is not None:
            self._pin_context(state, session_id, context)
        self._producing = True
        try:
            try:
                result = transition(copy.deepcopy(session["alice"]))
            except exchange.ExchangeError:
                raise Conflict("managed Alice transition rejected") from None
            state["sessions"][session_id]["alice"] = result
            self._check()
            self._persist(state)
            self._check()
        finally:
            self._producing = False

    def start_alice(self, session_id, context, own_partial_hex, *, verifier):
        """Retain a verified public own partial in a fresh Alice completion flow."""
        return self._alice_transition(
            session_id, lambda _: completion.start(context, own_partial_hex, verifier),
            context=context, starting=True,
        )

    def accept_alice_release(self, session_id, packet, *, verifier):
        return self._alice_transition(
            session_id, lambda state: completion.accept_release(state, packet, verifier),
        )

    def _completion_checkpoint(self, name):
        try:
            self._checkpoint(name)
        except BaseException:
            self._poisoned = True
            raise Quarantined("managed completion checkpoint outcome is uncertain") from None

    def complete_alice(self, session_id, *, producer, verifier):
        """Burn completion ownership before calling a trusted synthetic producer.

        The producer returns public final-signature bytes. This owner is not a
        signer or a nonce store and cannot undo callback side effects.
        """
        self._check(mutation=True)
        session = self._session(session_id)
        if session["alice"] is None:
            raise Conflict("managed Alice completion is not recorded")
        if not callable(producer) or not callable(verifier):
            raise InvalidInput("managed completion requires callable local adapters")
        try:
            consumed = completion.consume(copy.deepcopy(session["alice"]))
        except exchange.ExchangeError:
            raise OutcomeUnknown("Alice completion cannot invoke a producer again") from None
        state = copy.deepcopy(self._state)
        state["sessions"][session_id]["alice"] = consumed
        state["sessions"][session_id]["possible_exposure"] = True
        self._producing = True
        try:
            self._persist(state)
            self._completion_checkpoint("after_alice_consume")
            try:
                self._check()
                signature = producer()
            except BaseException:
                raise OutcomeUnknown("Alice producer outcome is unknown") from None
            self._completion_checkpoint("after_alice_producer")
            try:
                self._check()
                result, output = completion.record(copy.deepcopy(consumed), signature, verifier)
            except exchange.ExchangeError:
                raise OutcomeUnknown("Alice completion verification outcome is unknown") from None
            state = copy.deepcopy(self._state)
            state["sessions"][session_id]["alice"] = result
            self._check()
            self._persist(state)
            self._completion_checkpoint("after_alice_output_commit")
            self._check()
            return output
        finally:
            self._producing = False

    def replay_alice_completion(self, session_id):
        self._check()
        state = self._session(session_id)["alice"]
        if state is None:
            raise Conflict("managed Alice completion is not recorded")
        try:
            return completion.replay(copy.deepcopy(state))
        except exchange.ExchangeError:
            raise OutcomeUnknown("no durable Alice completion is available") from None

    def get_alice(self, session_id):
        self._check()
        state = self._session(session_id)["alice"]
        if state is None:
            raise Conflict("managed Alice completion is not recorded")
        return copy.deepcopy(state)

    def _admit_bob_recovery(self, state, session_id):
        """Consume an allowance in a staged state; the caller persists it first."""
        budget = state["sessions"][session_id]["recovery_budget"]
        if budget["consumed"] >= budget["limit"]:
            raise RecoveryExhausted("Bob recovery allowance is exhausted")
        budget["consumed"] += 1

    def complete_exchange_bitcoin(self, session_id, completion_packet=None, *, recoverer):
        """Retain a bound observation, verify and adapt it, then record output.

        Omitting the packet retries only the exact retained public observation.
        A rejected observation remains pinned; this API cannot replace it.
        A different candidate requires explicit positive-verification reconciliation.
        Each admitted recovery consumes its durable allowance before invocation.
        """
        self._check(mutation=True)
        session = self._session(session_id)
        if session["exchange"] is None:
            raise Conflict("managed exchange is not recorded")
        if not callable(recoverer):
            raise InvalidInput("public completion recoverer must be callable")
        self._producing = True
        try:
            if completion_packet is None:
                retained = session["exchange"]["zenon_completion_packet_hex"]
                if retained is None:
                    raise Conflict("no Bitcoin completion observation is retained")
                completion_packet = bytes.fromhex(retained)
            try:
                completion.bob_request(copy.deepcopy(session["exchange"]), completion_packet)
                observed = completion.observe_bob(copy.deepcopy(session["exchange"]), completion_packet)
            except exchange.ExchangeError:
                raise Conflict("Bitcoin completion observation rejected") from None
            state = copy.deepcopy(self._state)
            state["sessions"][session_id]["possible_exposure"] = True
            state["sessions"][session_id]["exchange"] = observed
            self._admit_bob_recovery(state, session_id)
            self._persist(state)
            self._completion_checkpoint("after_bob_recovery_admission_commit")
            self._completion_checkpoint("after_bob_observation_commit")
            self._check()
            try:
                result, output = completion.complete_bob(
                    copy.deepcopy(state["sessions"][session_id]["exchange"]), completion_packet, recoverer,
                )
            except exchange.ExchangeError:
                raise Conflict("Bitcoin completion verification rejected") from None
            self._completion_checkpoint("after_bitcoin_recoverer")
            state = copy.deepcopy(self._state)
            state["sessions"][session_id]["exchange"] = result
            self._check()
            self._persist(state)
            self._completion_checkpoint("after_bitcoin_completion_commit")
            self._check()
            return output
        finally:
            self._producing = False

    def replay_exchange_bitcoin(self, session_id):
        self._check()
        state = self._session(session_id)["exchange"]
        if state is None:
            raise Conflict("managed exchange is not recorded")
        try:
            return completion.replay_bob(copy.deepcopy(state))
        except exchange.ExchangeError:
            raise OutcomeUnknown("no durable Bitcoin completion is available") from None

    def reconcile_exchange_bitcoin(self, session_id, completion_packet, *,
                                   expected_observation_digest, recoverer):
        """Complete a verified replacement while preserving the old observation.

        The caller must identify the exact retained observation. Admission is
        persisted before public recovery and is never refunded; recovery rejection
        leaves the observation unchanged. Persistence uncertainty quarantines the
        journal. Retained bytes are not labeled cryptographically invalid.
        """
        self._check(mutation=True)
        session = self._session(session_id)
        if session["exchange"] is None:
            raise Conflict("managed exchange is not recorded")
        if not callable(recoverer):
            raise InvalidInput("public completion recoverer must be callable")
        self._producing = True
        try:
            try:
                self._check()
                completion.bob_reconciliation_request(
                    copy.deepcopy(session["exchange"]), completion_packet,
                    expected_observation_digest=expected_observation_digest,
                )
            except exchange.ExchangeError:
                raise Conflict("Bitcoin completion reconciliation rejected") from None
            state = copy.deepcopy(self._state)
            self._admit_bob_recovery(state, session_id)
            self._persist(state)
            self._completion_checkpoint("after_bob_recovery_admission_commit")
            self._check()
            try:
                result, output = completion.reconcile_bob(
                    copy.deepcopy(self._session(session_id)["exchange"]), completion_packet,
                    expected_observation_digest=expected_observation_digest,
                    recoverer=recoverer,
                )
            except exchange.ExchangeError:
                raise Conflict("Bitcoin completion reconciliation rejected") from None
            self._check()
            self._completion_checkpoint("after_bitcoin_reconciliation_recoverer")
            state = copy.deepcopy(self._state)
            state["sessions"][session_id]["exchange"] = result
            self._persist(state)
            self._completion_checkpoint("after_bitcoin_reconciliation_commit")
            self._check()
            return output
        finally:
            self._producing = False

    def observe(self, session_id, observation_digest, *, reorg=False):
        """Append untrusted observation metadata; it never changes exposure."""
        self._check(mutation=True)
        self._session(session_id)
        _hex(observation_digest)
        if type(reorg) is not bool:
            raise InvalidInput("reorg marker must be boolean")
        state = copy.deepcopy(self._state)
        state["sessions"][session_id]["observations"].append({"digest": observation_digest, "reorg": reorg})
        self._persist(state)

    def get_session(self, session_id):
        self._check()
        return copy.deepcopy(self._session(session_id))

    def get_operation(self, session_id, operation_id):
        self._check()
        _hex(operation_id)
        operation = self._session(session_id)["operations"].get(operation_id)
        if operation is None:
            raise Conflict("operation is not recorded")
        return copy.deepcopy(operation)

    def _release(self):
        # A fork child must never LOCK_UN the parent's shared open description.
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            return
        if self._connection is not None:
            try:
                self._connection.close()
            except BaseException:
                self._poisoned = True
            self._connection = None
        for descriptor in reversed(self._locks):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        self._locks = []
        self._closed = True

    def close(self):
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            raise OwnershipError("inherited journal ownership is invalid")
        if self._producing or self._writing:
            raise Conflict("active mutation cannot close its journal")
        if not self._closed:
            self._release()

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
