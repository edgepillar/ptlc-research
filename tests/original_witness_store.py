"""Bounded test-only owned SQLite witness transaction, never an authority.

The selected directory, SQLite/VFS, process and verifier are trusted premises.
BEGIN IMMEDIATE covers the persisted read, comparison and replacement. This
does not survive coherent rollback or copying into independent writer domains.
No application store, signer, source read, recovery or protected effect is wired.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
import threading

from offline_session.current_authority_contract import PolicyCheckpoint
from qualification import original_read_contract as reads
import original_snapshot_opening as opening
import original_snapshot_prefix_response as composition


MAX_UPDATES = 64
MAX_RESPONSE_BYTES = 16384
_DDL = (
    "CREATE TABLE binding(id INTEGER PRIMARY KEY CHECK(id=1),root BLOB NOT NULL,original BLOB NOT NULL)",
    "CREATE TABLE witness(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,query BLOB NOT NULL,opening BLOB NOT NULL,response BLOB NOT NULL)",
)


class WitnessRefused(ValueError):
    """A bounded comparison or owned-handle precondition refused."""


class WitnessOutcomeUnknown(RuntimeError):
    """No conclusive local command result; never source-outcome recovery."""


@dataclass(frozen=True)
class RetainedDescription:
    """Unsigned local scalar observation, with no permission or truth flags."""

    version: int
    query_digest_hex: str
    event_sequence: int
    observation: str


class OfflineOriginalWitnessStore:
    """One externally selected complete Root/original binding per owned file.

    An empty store has no prior knowledge. Reopening does not authenticate its
    history. Each inspection/retention revalidates the stored complete opening
    and public packet; arbitrary callback flags remain an unsafe control.
    """

    def __init__(self, path, binding, *, verifier):
        if type(path) is not str or type(binding) is not reads.OriginalReadQuery or not callable(verifier):
            raise WitnessRefused("exact independent binding and selected verifier required")
        try:
            binding.as_dict()
            self._root = binding._root
            self._original = binding._original
            self._binding = (self._root.canonical_bytes, self._original.canonical_bytes)
        except (ValueError, TypeError, AttributeError):
            raise WitnessRefused("invalid independent witness binding") from None
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._busy = self._closed = False
        self._db = None
        self._verifier = verifier
        location = Path(path)
        self._busy = True
        try:
            # The directory and pathname are owned external premises, not a
            # defense against an attacker changing ancestors or file aliases.
            if location.is_symlink() or (location.exists() and not location.is_file()):
                raise WitnessRefused("synthetic witness path refused")
            fresh = not location.exists()
            if fresh:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                try:
                    self._cut("create-file-opened")
                finally:
                    os.close(descriptor)
                self._cut("create-file-closed")
            self._db = sqlite3.connect(location.resolve().as_uri()+"?mode=rw", uri=True,
                timeout=0, isolation_level=None)
            if fresh:
                self._cut("create-connected")
            if self._db.execute("PRAGMA journal_mode").fetchone() != ("delete",):
                raise WitnessRefused("selected witness journal mode refused")
            self._db.execute("PRAGMA synchronous=EXTRA")
            self._db.execute("PRAGMA trusted_schema=OFF")
            if fresh:
                self._db.execute("BEGIN IMMEDIATE")
                self._cut("create-locked")
                for statement, label in zip(_DDL, ("create-binding-table", "create-witness-table")):
                    self._db.execute(statement)
                    self._cut(label)
                self._db.execute("INSERT INTO binding VALUES(1,?,?)", self._binding)
                self._cut("create-bound")
                self._cut("create-before-commit")
                self._db.execute("COMMIT")
                self._cut("create-after-commit")
            self._busy = False
            with self._transaction("open"):
                self._load()
        except WitnessRefused:
            self._dispose()
            raise
        except Exception:
            self._dispose()
            raise WitnessOutcomeUnknown("synthetic witness command has no conclusive result") from None
        except BaseException:
            self._dispose()
            raise
        finally:
            self._busy = False

    def _owner_only(self):
        if self._closed or os.getpid() != self._pid or threading.get_ident() != self._thread or self._busy:
            raise WitnessRefused("closed, inherited, foreign or reentrant witness handle")

    def _dispose(self):
        if self._db is not None:
            try:
                self._db.close()
            except sqlite3.Error:
                pass
        self._closed = True

    def close(self):
        self._owner_only()
        self._dispose()

    def __enter__(self):
        self._owner_only()
        return self

    def __exit__(self, *unused):
        if not self._closed:
            self.close()

    def _cut(self, label):
        """Qualification-only fault/death cuts, never an application callback."""

    def _rollback(self):
        try:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            return True
        except sqlite3.Error:
            return False

    @contextmanager
    def _transaction(self, name):
        self._owner_only()
        self._busy = True
        committed = False
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._validate()
            self._cut(name+"-locked")
            yield
            self._validate()
            self._cut(name+"-before-commit")
            self._db.execute("COMMIT")
            committed = True
            self._cut(name+"-after-commit")
        except WitnessRefused:
            rolled_back = self._rollback()
            if committed or not rolled_back:
                self._dispose()
                raise WitnessOutcomeUnknown("synthetic witness command has no conclusive result") from None
            raise
        except Exception:
            self._rollback()
            self._dispose()
            raise WitnessOutcomeUnknown("synthetic witness command has no conclusive result") from None
        except BaseException:
            self._rollback()
            self._dispose()
            raise
        finally:
            self._busy = False

    def _validate(self):
        if (self._db.execute("PRAGMA journal_mode").fetchone() != ("delete",)
                or self._db.execute("PRAGMA synchronous").fetchone() != (3,)
                or self._db.execute("PRAGMA trusted_schema").fetchone() != (0,)):
            raise WitnessRefused("selected native witness settings changed")
        schema = self._db.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
        if len(schema) != len(_DDL) or {row[0] for row in schema} != set(_DDL):
            raise WitnessRefused("unexpected synthetic witness schema")
        bindings = self._db.execute("SELECT id,typeof(root),length(root),typeof(original),length(original) FROM binding").fetchall()
        if bindings != [(1, "blob", len(self._binding[0]), "blob", len(self._binding[1]))]:
            raise WitnessRefused("synthetic witness binding shape changed")
        if self._db.execute("SELECT root,original FROM binding").fetchall() != [self._binding]:
            raise WitnessRefused("complete independent witness binding changed")
        shape = self._db.execute("SELECT id,version,typeof(version),typeof(query),length(query),typeof(opening),length(opening),typeof(response),length(response) FROM witness").fetchall()
        if len(shape) > 1:
            raise WitnessRefused("synthetic witness row bound exceeded")
        if shape:
            row = shape[0]
            if (row[0] != 1 or type(row[1]) is not int or not 1 <= row[1] <= MAX_UPDATES or row[2] != "integer"
                    or row[3] != "blob" or not 0 < row[4] <= reads.MAX_WIRE_BYTES
                    or row[5] != "blob" or not 0 < row[6] <= opening.MAX_WIRE_BYTES
                    or row[7] != "blob" or not 0 < row[8] <= MAX_RESPONSE_BYTES):
                raise WitnessRefused("synthetic witness row shape refused")

    def _selected_query(self, wire):
        try:
            value = reads._decode(wire)
            head = value["expected_checkpoint"]
            record = value["expected_record_checkpoint"]
            expected = reads.original_read_query(self._root, self._original,
                checkpoint=PolicyCheckpoint(head["revision"], head["policy_state_digest_hex"]),
                record_checkpoint=reads.RecordCheckpoint(record["event_sequence"], record["record_lineage_digest_hex"]),
                challenge_hex=value["challenge_hex"])
            reads.parse_query(expected, wire)
            return expected
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
            raise WitnessRefused("stored query changes its independently selected binding") from None

    def _load(self):
        row = self._db.execute("SELECT version,query,opening,response FROM witness").fetchone()
        if row is None:
            return None
        version, query_wire, opened, packet = row
        query = self._selected_query(query_wire)
        try:
            opening.derive_claim(query, opened)
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
            raise WitnessRefused("stored complete witness opening refused") from None
        return version, query, opened, packet

    def _compare(self, earlier, later):
        try:
            return composition.compare_public_responses(*earlier, *later, verifier=self._verifier)
        except composition.PrefixResponseRefused:
            raise WitnessRefused("synthetic signed witness comparison refused") from None

    @staticmethod
    def _description(version, comparison):
        return RetainedDescription(version, comparison.later_query_digest_hex,
            comparison.later_event_sequence, comparison.later_observation)

    def inspect_retained(self):
        """Recheck historical bytes; this cannot reconcile source uncertainty."""
        with self._transaction("inspect"):
            previous = self._load()
            if previous is None:
                result = None
            else:
                comparison = self._compare(previous[1:], previous[1:])
                result = self._description(previous[0], comparison)
        return result

    def retain(self, query, opened, packet):
        """Compare with the persisted witness and replace it under one lock.

        No pre-read scalar, packet-selected Root/original, or cached witness is
        authority. Each successful call consumes one of 64 local update slots,
        including same-history redelivery. No automatic retry is performed.
        """
        self._owner_only()
        if (type(query) is not reads.OriginalReadQuery or type(opened) is not bytes or type(packet) is not bytes
                or not 0 < len(opened) <= opening.MAX_WIRE_BYTES
                or not 0 < len(packet) <= MAX_RESPONSE_BYTES):
            raise WitnessRefused("exact bounded witness inputs required")
        try:
            selected = self._selected_query(query.canonical_bytes)
        except (ValueError, TypeError, AttributeError):
            raise WitnessRefused("invalid independently selected witness query") from None
        incoming = selected, opened, packet
        with self._transaction("retain"):
            previous = self._load()
            self._cut("retain-loaded")
            version = 0 if previous is None else previous[0]
            if version >= MAX_UPDATES:
                raise WitnessRefused("synthetic witness update bound reached")
            comparison = self._compare(incoming if previous is None else previous[1:], incoming)
            self._cut("retain-compared")
            self._db.execute("INSERT OR REPLACE INTO witness VALUES(1,?,?,?,?)",
                (version+1, selected.canonical_bytes, opened, packet))
            self._cut("retain-written")
            result = self._description(version+1, comparison)
        return result
