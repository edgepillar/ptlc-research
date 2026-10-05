"""Isolated SQLite ordering qualification, never an authenticated source service.

Only a synthetic row inside this database is the protected effect. Current local
labels, owned storage, provisioning and honest SQLite/VFS behavior are premises.
No existing runner, journal, signer, network or physical-entry gate uses this code.
"""

from contextlib import closing, contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading

from offline_session import governor_profile as governor


MODES = ("live", "unavailable", "ambiguous", "compromise-detected")
MAX_REVISION = 32
MAX_EVENTS = 256
_DDL = (
    "CREATE TABLE source (id INTEGER PRIMARY KEY CHECK(id=1), source_id TEXT NOT NULL, incarnation TEXT NOT NULL, authority_id TEXT NOT NULL, resource_id TEXT NOT NULL, revision INTEGER NOT NULL, profile BLOB NOT NULL, active INTEGER NOT NULL, mode TEXT NOT NULL)",
    "CREATE TABLE policies (revision INTEGER PRIMARY KEY, profile BLOB NOT NULL, active INTEGER NOT NULL, event_seq INTEGER NOT NULL UNIQUE)",
    "CREATE TABLE operations (operation_id TEXT PRIMARY KEY, revision INTEGER NOT NULL REFERENCES policies(revision), profile BLOB NOT NULL, proposal TEXT NOT NULL, charge_seq INTEGER NOT NULL UNIQUE, effect_seq INTEGER UNIQUE)",
    "CREATE TABLE effects (operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id), event_seq INTEGER NOT NULL UNIQUE, payload TEXT NOT NULL)",
    "CREATE TABLE events (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, revision INTEGER NOT NULL, operation_id TEXT, detail TEXT NOT NULL)",
)


class StoreRefused(ValueError):
    """Malformed input, conflicting original record or refused local policy."""


class StoreOutcomeUnknown(RuntimeError):
    """No conclusive reply; reconcile the original operation without refund."""


@dataclass(frozen=True)
class SourceLabels:
    """Independently selected synthetic labels, not authenticated identities."""

    source_id_hex: str
    incarnation_id_hex: str
    authority_id_hex: str
    resource_digest_hex: str


@dataclass(frozen=True)
class OriginalRequest:
    operation_id_hex: str
    expected_revision: int
    profile_wire: bytes
    proposal_digest_hex: str


@dataclass(frozen=True)
class OperationRecord:
    operation_id_hex: str
    revision: int
    profile_wire: bytes
    proposal_digest_hex: str
    charge_sequence: int
    effect_sequence: object


@dataclass(frozen=True)
class LocalPolicyView:
    revision: int
    profile_wire: bytes
    active: bool
    mode: str
    charged_operations: int
    synthetic_effects: int
    event_sequence: int


def _number(value, maximum=MAX_REVISION):
    if type(value) is not int or not 0 <= value <= maximum:
        raise StoreRefused("invalid bounded qualification number")


def _hex(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise StoreRefused("invalid synthetic label")


def _labels(value):
    if type(value) is not SourceLabels:
        raise StoreRefused("exact independently selected source labels required")
    for field in ("source_id_hex", "incarnation_id_hex", "authority_id_hex", "resource_digest_hex"):
        _hex(getattr(value, field))


def _profile(wire, labels):
    if type(wire) is not bytes:
        raise StoreRefused("exact complete profile bytes required")
    try:
        value = governor._decode(wire)
    except ValueError:
        raise StoreRefused("invalid complete local profile") from None
    if (value["authority_id_hex"] != labels.authority_id_hex
            or value["resource_digest_hex"] != labels.resource_digest_hex):
        raise StoreRefused("profile changes the retained synthetic namespace")
    return value


def _request(value, labels):
    if type(value) is not OriginalRequest:
        raise StoreRefused("exact original qualification request required")
    _hex(value.operation_id_hex); _hex(value.proposal_digest_hex)
    _number(value.expected_revision)
    _profile(value.profile_wire, labels)


class OfflinePolicyEffectStore:
    """One owned local database; records are diagnostics, never capabilities.

    Policy updates, charges and synthetic effects use BEGIN IMMEDIATE. The only
    chosen use cutoff is the commit of a synthetic effect row in the same database.
    A restored or cloned coherent database remains an explicit unsafe boundary.
    """

    def __init__(self, path, labels, *, initial_profile=None):
        _labels(labels)
        if type(path) is not str or not path or len(path) > 4096:
            raise StoreRefused("an owned qualification database path is required")
        if initial_profile is not None:
            _profile(initial_profile, labels)
        self._owner = (os.getpid(), threading.get_ident())
        self._labels, self._busy, self._closed = labels, False, False
        self._db = None
        file = Path(path).absolute()
        if file.is_symlink():
            raise StoreRefused("a qualification database must not be a symlink")
        try:
            if initial_profile is not None:
                descriptor = os.open(str(file), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.close(descriptor)
            self._db = sqlite3.connect(file.as_uri()+"?mode=rw", uri=True,
                timeout=0, isolation_level=None, detect_types=0)
            if self._db.execute("PRAGMA journal_mode").fetchone() != ("delete",):
                raise StoreRefused("rollback-journal DELETE mode is required")
            self._db.execute("PRAGMA synchronous=EXTRA")
            self._db.execute("PRAGMA foreign_keys=ON")
            if (self._db.execute("PRAGMA synchronous").fetchone() != (3,)
                    or self._db.execute("PRAGMA foreign_keys").fetchone() != (1,)):
                raise StoreRefused("required qualification SQLite settings unavailable")
            if initial_profile is not None:
                self._db.execute("BEGIN IMMEDIATE")
                for statement in _DDL:
                    self._db.execute(statement)
                self._db.execute("INSERT INTO source VALUES (1,?,?,?,?,0,?,1,'live')",
                    (labels.source_id_hex, labels.incarnation_id_hex, labels.authority_id_hex,
                     labels.resource_digest_hex, initial_profile))
                self._db.execute("INSERT INTO policies VALUES (0,?,1,0)", (initial_profile,))
                self._db.execute("COMMIT")
            with self._transaction("open"):
                pass
        except StoreRefused:
            self._dispose(); raise
        except (OSError, sqlite3.Error):
            self._dispose()
            raise StoreOutcomeUnknown("qualification source open has no conclusive result") from None
        except BaseException:
            self._dispose(); raise

    def _owner_only(self):
        if self._closed or self._owner != (os.getpid(), threading.get_ident()) or self._busy:
            raise StoreRefused("closed, inherited, foreign-thread or recursive source access")

    def _cut(self, label):
        """No-op qualification-only crash hook; never an application callback."""

    def _rollback(self):
        try:
            if self._db is not None and self._db.in_transaction:
                self._db.execute("ROLLBACK")
            return self._db is None or not self._db.in_transaction
        except sqlite3.Error:
            return False

    @contextmanager
    def _transaction(self, name):
        self._owner_only(); self._busy = True
        committed = False
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._validate()
            yield
            self._validate()
            self._cut(name+"-before-commit")
            self._db.execute("COMMIT")
            committed = True
            self._cut(name+"-after-commit")
        except StoreRefused:
            rolled_back = self._rollback()
            if not rolled_back:
                self._dispose()
            if committed or not rolled_back:
                raise StoreOutcomeUnknown("qualification command has no conclusive result") from None
            raise
        except Exception:
            if not self._rollback():
                self._dispose()
            raise StoreOutcomeUnknown("qualification command has no conclusive result") from None
        except BaseException:
            if not self._rollback():
                self._dispose()
            raise
        finally:
            self._busy = False

    def _source(self):
        return self._db.execute("SELECT revision,profile,active,mode FROM source").fetchone()

    def _validate(self):
        if (self._db.execute("PRAGMA journal_mode").fetchone() != ("delete",)
                or self._db.execute("PRAGMA synchronous").fetchone() != (3,)
                or self._db.execute("PRAGMA foreign_keys").fetchone() != (1,)):
            raise StoreRefused("selected native transaction settings changed")
        schema = self._db.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
        if {row[0] for row in schema} != set(_DDL) or len(schema) != len(_DDL):
            raise StoreRefused("unexpected qualification schema")
        sources = self._db.execute("SELECT * FROM source").fetchall()
        binding = self._labels
        if len(sources) != 1 or sources[0][:5] != (1, binding.source_id_hex,
                binding.incarnation_id_hex, binding.authority_id_hex, binding.resource_digest_hex):
            raise StoreRefused("qualification source labels changed")
        revision, profile, active, mode = sources[0][5:]
        _number(revision); _profile(profile, binding)
        if type(active) is not int or active not in (0, 1) or type(mode) is not str or mode not in MODES:
            raise StoreRefused("invalid local policy labels")
        policies = self._db.execute("SELECT * FROM policies ORDER BY revision").fetchall()
        if len(policies) != revision+1 or [row[0] for row in policies] != list(range(revision+1)):
            raise StoreRefused("incomplete local policy history")
        for index, wire, enabled, seq in policies:
            _number(index); _profile(wire, binding); _number(seq, MAX_EVENTS)
            if type(enabled) is not int or enabled not in (0, 1):
                raise StoreRefused("invalid historical policy")
        if policies[0][2:] != (1, 0) or policies[-1][1:3] != (profile, active):
            raise StoreRefused("local policy head disagrees with its history")
        operations = self._db.execute("SELECT * FROM operations").fetchall()
        effects = self._db.execute("SELECT * FROM effects").fetchall()
        events = self._db.execute("SELECT * FROM events ORDER BY seq").fetchall()
        if len(operations) > 64 or len(effects) > 64 or len(events) > MAX_EVENTS:
            raise StoreRefused("qualification history exceeds finite bounds")
        by_id = {}
        for op, rev, wire, proposal, charge, effect in operations:
            _request(OriginalRequest(op, rev, wire, proposal), binding)
            _number(charge, MAX_EVENTS)
            if charge == 0 or rev > revision or wire != policies[rev][1]:
                raise StoreRefused("invalid original charge binding")
            if effect is not None:
                _number(effect, MAX_EVENTS)
                if effect <= charge:
                    raise StoreRefused("invalid synthetic effect order")
            by_id[op] = (rev, wire, proposal, charge, effect)
        seen_charge, seen_effect, current, source_mode = set(), set(), 0, "live"
        for expected_seq, (seq, kind, rev, op, detail) in enumerate(events, 1):
            _number(seq, MAX_EVENTS); _number(rev)
            if seq != expected_seq or type(kind) is not str or type(detail) is not str:
                raise StoreRefused("incomplete qualification event order")
            if kind == "policy":
                if (op is not None or detail != "" or rev != current+1
                        or rev > revision or policies[rev][3] != seq):
                    raise StoreRefused("invalid policy event")
                current = rev
            elif kind == "mode":
                if op is not None or rev != current or detail not in MODES or detail == source_mode:
                    raise StoreRefused("invalid source-mode event")
                source_mode = detail
            elif kind in ("charge", "effect"):
                if (op not in by_id or detail != "" or rev != current or source_mode != "live"
                        or not policies[current][2] or by_id[op][:2] != (current, policies[current][1])):
                    raise StoreRefused("event lacks matching live local policy")
                if kind == "charge":
                    if (op in seen_charge or by_id[op][3] != seq
                            or len(seen_charge) >= _profile(policies[current][1], binding)["max_attempt_limit"]):
                        raise StoreRefused("charge history exceeds its selected local cap")
                    seen_charge.add(op)
                else:
                    if op not in seen_charge or op in seen_effect or by_id[op][4] != seq:
                        raise StoreRefused("effect has no unique earlier charge")
                    seen_effect.add(op)
            else:
                raise StoreRefused("unexpected qualification event")
        if (current != revision or source_mode != mode or seen_charge != set(by_id)
                or seen_effect != {op for op, row in by_id.items() if row[4] is not None}
                or {op for op, _, _ in effects} != seen_effect):
            raise StoreRefused("qualification records disagree with their event history")
        for op, seq, payload in effects:
            if seq != by_id[op][4] or payload != "synthetic-effect":
                raise StoreRefused("synthetic effect row changed its original record")

    def _event(self, kind, revision, operation=None, detail=""):
        sequence = self._db.execute("SELECT count(*) FROM events").fetchone()[0]+1
        if sequence > MAX_EVENTS:
            raise StoreRefused("qualification event bound exhausted")
        self._db.execute("INSERT INTO events VALUES (?,?,?,?,?)", (sequence, kind, revision, operation, detail))
        return sequence

    def _live(self, source):
        if source[3] != "live":
            raise StoreRefused("local source unavailable, ambiguous or known compromised")

    def _current(self, source, request):
        self._live(source)
        if not source[2] or source[:2] != (request.expected_revision, request.profile_wire):
            raise StoreRefused("request does not match the current local policy checkpoint")

    def _record(self, request):
        row = self._db.execute("SELECT * FROM operations WHERE operation_id=?", (request.operation_id_hex,)).fetchone()
        if row is not None and row[1:4] != (request.expected_revision, request.profile_wire, request.proposal_digest_hex):
            raise StoreRefused("original operation cannot be rebound")
        return None if row is None else OperationRecord(*row)

    def local_view(self):
        """Operator diagnostic only; no current-source certificate or permission."""
        with self._transaction("view"):
            revision, profile, active, mode = self._source()
            counts = [self._db.execute("SELECT count(*) FROM "+table).fetchone()[0]
                      for table in ("operations", "effects", "events")]
            return LocalPolicyView(revision, profile, bool(active), mode, *counts)

    def lookup_original(self, request):
        _request(request, self._labels)
        with self._transaction("lookup"):
            self._live(self._source())
            return self._record(request)

    def allocate_synthetic(self, request):
        _request(request, self._labels)
        with self._transaction("allocation"):
            source = self._source(); self._live(source)
            original = self._record(request)
            if original is not None:
                return original
            self._current(source, request)
            consumed = self._db.execute("SELECT count(*) FROM operations").fetchone()[0]
            if consumed >= _profile(source[1], self._labels)["max_attempt_limit"]:
                raise StoreRefused("retained synthetic allocation cap exhausted")
            seq = self._event("charge", source[0], request.operation_id_hex)
            self._db.execute("INSERT INTO operations VALUES (?,?,?,?,?,NULL)",
                (request.operation_id_hex, request.expected_revision, request.profile_wire, request.proposal_digest_hex, seq))
            self._cut("allocation-written")
            return self._record(request)

    def apply_synthetic_effect(self, request):
        _request(request, self._labels)
        with self._transaction("effect"):
            source = self._source(); self._live(source)
            original = self._record(request)
            if original is None:
                raise StoreRefused("synthetic effect requires its original charge")
            if original.effect_sequence is not None:
                return original
            self._current(source, request)
            seq = self._event("effect", source[0], request.operation_id_hex)
            self._db.execute("INSERT INTO effects VALUES (?,?,'synthetic-effect')", (request.operation_id_hex, seq))
            self._db.execute("UPDATE operations SET effect_seq=? WHERE operation_id=?", (seq, request.operation_id_hex))
            self._cut("effect-written")
            return self._record(request)

    def replace_local_policy(self, expected_revision, profile_wire, *, active):
        """Offline administrator premise; no administrator authentication occurs."""
        _number(expected_revision); _profile(profile_wire, self._labels)
        if type(active) is not bool:
            raise StoreRefused("an exact local policy status is required")
        with self._transaction("policy"):
            revision = self._source()[0]
            if revision != expected_revision or revision == MAX_REVISION:
                raise StoreRefused("stale or exhausted local policy revision")
            new = revision+1
            seq = self._event("policy", new)
            self._db.execute("INSERT INTO policies VALUES (?,?,?,?)", (new, profile_wire, int(active), seq))
            self._db.execute("UPDATE source SET revision=?,profile=?,active=?", (new, profile_wire, int(active)))
            self._cut("policy-written")
            return new

    def set_local_source_mode(self, mode):
        if type(mode) is not str or mode not in MODES:
            raise StoreRefused("invalid qualification source mode")
        with self._transaction("mode"):
            revision, _, _, old = self._source()
            if old == mode:
                raise StoreRefused("qualification source mode already selected")
            self._event("mode", revision, detail=mode)
            self._db.execute("UPDATE source SET mode=?", (mode,))

    def _dispose(self):
        if self._db is not None:
            self._rollback()
            try:
                self._db.close()
            except sqlite3.Error:
                pass
        self._closed = True

    def close(self):
        self._owner_only(); self._dispose()

    def __enter__(self):
        self._owner_only(); return self

    def __exit__(self, *ignored):
        self.close()


def runtime_report():
    """Report a native temporary-file mode probe without private environment data."""
    with tempfile.TemporaryDirectory(prefix="synthetic-policy-runtime-") as directory:
        with closing(sqlite3.connect(str(Path(directory)/"probe.sqlite3"), isolation_level=None)) as db:
            mode = db.execute("PRAGMA journal_mode").fetchone()[0]
            db.execute("PRAGMA synchronous=EXTRA")
            sync = db.execute("PRAGMA synchronous").fetchone()[0]
    if mode != "delete" or sync != 3 or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", sqlite3.sqlite_version) is None:
        raise StoreRefused("native SQLite qualification mode probe refused")
    return dict(qualification="isolated-policy-effect-store", sqlite_version=sqlite3.sqlite_version,
                journal_mode=mode, synchronous=sync, authentication=False,
                protected_effect="synthetic row in one local database", physical_entry=False)


if __name__ == "__main__":
    print(json.dumps(runtime_report(), sort_keys=True, separators=(",", ":")))
