"""Owned local disk records for one explicitly selected public verifier.

This offline store is separate from recovery admission and the session journal.
Cooperating POSIX owners retain both locks through admission, work and result.
The selected guard and cooperative worker retain inherited lock references.
A required shared pool slot is acquired before pending persistence and retained
through selected work/result commit. Matching restored copies, a hostile host,
CPU/memory accounting and fairness are not solved.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import threading
from urllib.parse import quote

try:
    import fcntl
except ImportError:
    fcntl = None

from . import exchange, observation_evidence as evidence, observation_records as records
from .observation_verifier import SubprocessObservation
from .worker_pool import PublicWorkerPool, PoolBusy, PoolError


VERSION = 3
MAX_DATABASE_BYTES = 8 * 1024 * 1024
MAX_CHECKPOINT_BYTES = 1024


class StoreError(ValueError):
    """Sanitized local storage/configuration failure; no private diagnostics."""


class StoreBusy(StoreError):
    pass


class StoreOwnershipError(StoreError):
    pass


class StoreConflict(StoreError):
    pass


class StoreQuarantined(StoreError):
    pass


def _private_regular(path, maximum):
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
            or metadata.st_uid != os.geteuid() or metadata.st_size > maximum):
        raise StoreQuarantined("invalid observation storage file")


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _checkpoint(store_id, revision, wire, pool_profile):
    value = {"version": VERSION, "store_id_hex": store_id, "revision": revision,
             "records_digest_hex": hashlib.sha256(wire).hexdigest(),
             "worker_pool_profile_digest_hex": pool_profile}
    value["digest_hex"] = hashlib.sha256(
        b"PTLC/observation-store-checkpoint/v3\x00" + exchange.canonical(value)).hexdigest()
    return value


class ObservationStore:
    """Lifetime ownership and bounded records on a trusted local POSIX host.

    Only this owner invokes the selected SubprocessObservation and commits its
    return; workers receive public verification bytes, never a storage handle.
    Guard and cooperative worker retain the two lock references through exit.
    Owner death is watched; a live inherited reference excludes another owner.
    A selected shared pool bounds simultaneous admitted work for cooperating
    stores using the same physical pool. CPU/memory, fairness, host containment
    and restored-copy protection remain separate requirements.
    """

    @classmethod
    def open(cls, directory, checkpoint, *, store_id_hex, verifier, worker_pool,
             attempt_limit, target_limit, hook=None):
        self = cls()
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._connection = None
        self._locks = []
        self._closed = False
        self._poisoned = False
        self._active = False
        self._hook = hook
        try:
            if (os.name != "posix" or sys.platform not in {"linux", "darwin"}
                    or fcntl is None or type(verifier) is not SubprocessObservation
                    or type(worker_pool) is not PublicWorkerPool
                    or (hook is not None and not callable(hook))):
                raise StoreError("unsupported observation store configuration")
            evidence._profile(store_id_hex)
            self._store_id = store_id_hex
            self._verifier = verifier
            self._profile = verifier.profile_digest_hex
            worker_pool.check_store_locations(directory, checkpoint)
            self._pool = worker_pool
            self._pool_profile = worker_pool.profile_digest_hex
            self._attempt_limit = attempt_limit
            self._target_limit = target_limit
            self._wire = records.create(verifier_profile_digest_hex=self._profile,
                attempt_limit=attempt_limit, target_limit=target_limit)
            self._open(directory, checkpoint)
            return self
        except BaseException as error:
            self._poisoned = True
            self._release()
            if isinstance(error, StoreError):
                raise
            raise StoreQuarantined("observation store open rejected") from None

    def _take_lock(self, path):
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
                    or metadata.st_uid != os.geteuid()):
                raise StoreQuarantined("invalid observation owner lock")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StoreBusy("observation storage already owned") from None
            self._locks.append(descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def _open(self, directory, checkpoint):
        root = Path(directory).absolute()
        anchor = Path(checkpoint).absolute()
        if root.is_symlink() or anchor.is_symlink():
            raise StoreQuarantined("observation storage symlink rejected")
        root.mkdir(mode=0o700, parents=False, exist_ok=True)
        metadata = root.stat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077
                or metadata.st_uid != os.geteuid()):
            raise StoreQuarantined("observation storage directory is not private")
        root = root.resolve()
        parent = anchor.parent.resolve(strict=True)
        anchor = parent / anchor.name
        if (not parent.is_dir() or anchor == root or root in anchor.parents
                or anchor.name in {"", ".", ".."}):
            raise StoreQuarantined("separate observation checkpoint required")
        self._root, self._anchor = root, anchor
        self._database = root / "observations.sqlite3"
        # Persistent lock files are never unlinked or replaced by managed code.
        self._take_lock(root / "observations.lock")
        self._take_lock(anchor.with_name(anchor.name + ".lock"))
        existed = self._database.exists()
        if existed != anchor.exists():
            raise StoreQuarantined("incomplete observation storage pair")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = self._database.with_name(self._database.name + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                if suffix != "-journal" or not existed:
                    raise StoreQuarantined("unsupported observation storage sidecar")
                _private_regular(sidecar, MAX_DATABASE_BYTES)
        if existed:
            _private_regular(self._database, MAX_DATABASE_BYTES)
            _private_regular(anchor, MAX_CHECKPOINT_BYTES)
        else:
            descriptor = os.open(self._database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            _sync_directory(root)
        self._connection = sqlite3.connect(
            "file:" + quote(str(self._database), safe="/") + "?mode=rw",
            uri=True, isolation_level=None, timeout=0)
        if self._connection.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
            raise StoreQuarantined("unsupported observation journal mode")
        self._connection.execute("PRAGMA synchronous=FULL")
        if (self._connection.execute("PRAGMA synchronous").fetchone() != (2,)
                or self._connection.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]):
            raise StoreQuarantined("observation database check failed")
        if not existed:
            self._persist(self._wire, "initialize", initializing=True)
            return
        self._load()
        # Locked publisher ownership excludes a live/stale managed record writer.
        # A cooperative live worker retains the locks, so this reopen cannot
        # acquire ownership until those references are closed. Workers receive
        # only lock capabilities, never the database/checkpoint connection.
        pending = [item["id"] for item in json.loads(self._wire)["attempts"] if item["outcome"] is None]
        if pending:
            wire = self._wire
            for number in pending:
                wire = records.interrupt(wire, number, expected_verifier_profile_digest_hex=self._profile)
            self._persist(wire, "recovery")

    def _validated(self, wire):
        summary = records.inspect(wire, expected_verifier_profile_digest_hex=self._profile)
        value = json.loads(wire)
        if (value["attempt_limit"] != self._attempt_limit or value["target_limit"] != self._target_limit
                or summary.pending_attempts > 1):
            raise StoreQuarantined("observation storage configuration mismatch")
        return summary

    def _read_anchor(self):
        descriptor = os.open(self._anchor, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
                    or metadata.st_uid != os.geteuid() or metadata.st_size > MAX_CHECKPOINT_BYTES):
                raise StoreQuarantined("invalid observation checkpoint")
            wire = os.read(descriptor, MAX_CHECKPOINT_BYTES + 1)
            if len(wire) != metadata.st_size:
                raise StoreQuarantined("observation checkpoint changed")
            return wire
        finally:
            os.close(descriptor)

    def _load(self):
        rows = self._connection.execute(
            "SELECT slot, version, store_id, revision, length(record_bytes), digest FROM checkpoint LIMIT 2").fetchall()
        if len(rows) != 1:
            raise StoreQuarantined("invalid observation checkpoint rows")
        slot, version, identity, revision, length, digest = rows[0]
        if (type(slot) is not int or slot != 1 or type(version) is not int or version != VERSION
                or identity != self._store_id or type(revision) is not int or not 0 <= revision <= 128
                or type(length) is not int or not 0 < length <= records.MAX_RECORD_BYTES):
            raise StoreQuarantined("invalid observation checkpoint metadata")
        pool_length = self._connection.execute("SELECT length(worker_pool_profile) FROM checkpoint WHERE slot=1").fetchone()[0]
        if type(pool_length) is not int or pool_length != 64:
            raise StoreQuarantined("invalid worker pool profile length")
        wire = self._connection.execute("SELECT record_bytes FROM checkpoint WHERE slot=1").fetchone()[0]
        summary = self._validated(wire)
        pool_profile = self._connection.execute("SELECT worker_pool_profile FROM checkpoint WHERE slot=1").fetchone()[0]
        expected = _checkpoint(self._store_id, summary.revision, wire, self._pool_profile)
        if (revision != summary.revision or digest != expected["digest_hex"]
                or pool_profile != self._pool_profile or self._read_anchor() != exchange.canonical(expected)):
            raise StoreQuarantined("observation checkpoint divergence")
        self._wire = wire

    def _owned(self):
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            raise StoreOwnershipError("inherited observation ownership is invalid")
        if self._closed:
            raise StoreOwnershipError("observation store is closed")
        if self._poisoned:
            raise StoreQuarantined("observation store is quarantined")

    def _public(self):
        self._owned()
        if self._active:
            raise StoreConflict("observation store operation already active")

    def _checkpoint(self, name):
        try:
            if self._hook is not None:
                self._hook(name)
        except BaseException:
            self._poisoned = True
            raise StoreQuarantined("observation operation interrupted") from None

    def _write_anchor(self, value, phase):
        descriptor, temporary = tempfile.mkstemp(prefix=".observation-checkpoint-", dir=self._anchor.parent)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(exchange.canonical(value))
                output.flush()
                os.fsync(output.fileno())
            if self._anchor.is_symlink():
                raise StoreQuarantined("observation checkpoint symlink rejected")
            os.replace(temporary, self._anchor)
            self._checkpoint(phase + ".after_checkpoint_replace")
            _sync_directory(self._anchor.parent)
            self._checkpoint(phase + ".after_checkpoint_commit")
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _persist(self, wire, phase, initializing=False):
        self._owned()
        summary = self._validated(wire)
        if not initializing and summary.revision <= self._validated(self._wire).revision:
            raise StoreQuarantined("observation revision cannot regress")
        value = _checkpoint(self._store_id, summary.revision, wire, self._pool_profile)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            if initializing:
                self._connection.execute("CREATE TABLE checkpoint (slot INTEGER PRIMARY KEY CHECK (slot=1), "
                    "version INTEGER NOT NULL, store_id TEXT NOT NULL, revision INTEGER NOT NULL, "
                    "record_bytes BLOB NOT NULL, digest TEXT NOT NULL, worker_pool_profile TEXT NOT NULL)")
            self._connection.execute("INSERT OR REPLACE INTO checkpoint VALUES (1, ?, ?, ?, ?, ?, ?)",
                (VERSION, self._store_id, summary.revision, wire, value["digest_hex"], self._pool_profile))
            self._checkpoint(phase + ".before_db_commit")
            self._connection.commit()
            self._checkpoint(phase + ".after_db_commit")
            self._write_anchor(value, phase)
            self._wire = wire
        except BaseException:
            self._poisoned = True
            try:
                self._connection.rollback()
            except BaseException:
                pass
            raise StoreQuarantined("observation durability outcome is uncertain") from None

    def summary(self):
        self._public()
        return self._validated(self._wire)

    def known_statement(self, state, signature):
        self._public()
        return records.known_statement(self._wire, state, signature,
                                       expected_verifier_profile_digest_hex=self._profile)

    def observe(self, state, signature, *, recheck=False):
        """Charge before selected work and commit its bound result before return.

        No incoming statement, arbitrary callback, retry loop or journal mutation
        is accepted. Shared pool saturation rejects before pending persistence
        without a charge or worker. Unknown after admission is charged; a conflicting normal result is retained
        before RecordConflict is raised. Caller cancellation is committed unknown
        before propagation when storage succeeds; persistence uncertainty poisons
        the handle and requires a separately successful locked reopen.
        """
        self._public()
        if self._verifier.profile_digest_hex != self._profile:
            raise StoreError("selected observation profile changed")
        if self._pool.profile_digest_hex != self._pool_profile:
            raise StoreError("selected worker pool profile changed")
        if not self._validated(self._wire).attempts_remaining:
            raise records.RecordExhausted("observation attempt limit exhausted")
        snapshot = copy.deepcopy(state)
        self._active = True
        lease = None
        try:
            wire, number = records.begin(self._wire, snapshot, signature,
                expected_verifier_profile_digest_hex=self._profile, recheck=recheck)
            try:
                lease = self._pool.acquire()
            except PoolBusy:
                raise StoreBusy("shared worker capacity is unavailable") from None
            except PoolError:
                self._poisoned = True
                raise StoreQuarantined("shared worker admission rejected") from None
            self._persist(wire, "admission")
            self._checkpoint("admission.committed")
            try:
                statement = self._verifier.observe_admitted(snapshot, signature,
                    ownership_descriptors=tuple(self._locks), admission_descriptor=lease.fileno())
            except Exception:
                statement = evidence.unknown_statement(snapshot, signature, verifier_profile_digest_hex=self._profile)
            except BaseException:
                wire = records.interrupt(self._wire, number, expected_verifier_profile_digest_hex=self._profile)
                self._persist(wire, "result")
                self._checkpoint("result.committed")
                raise
            self._checkpoint("worker.returned")
            try:
                wire = records.finish(self._wire, snapshot, signature, number, statement,
                                       expected_verifier_profile_digest_hex=self._profile)
            except records.RecordError:
                statement = evidence.unknown_statement(snapshot, signature, verifier_profile_digest_hex=self._profile)
                wire = records.interrupt(self._wire, number, expected_verifier_profile_digest_hex=self._profile)
            self._persist(wire, "result")
            self._checkpoint("result.committed")
            if json.loads(statement)["outcome"] != "unknown":
                records.known_statement(self._wire, snapshot, signature,
                                         expected_verifier_profile_digest_hex=self._profile)
            return statement
        finally:
            self._active = False
            if lease is not None:
                lease.close()

    def _release(self):
        # A fork/foreign thread must not unlock the original owner's description.
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            return
        if self._connection is not None:
            try:
                self._connection.close()
            except BaseException:
                self._poisoned = True
            self._connection = None
        for descriptor in reversed(self._locks):
            # Explicit LOCK_UN would release a still-live worker's shared lock.
            # Close only this owner's reference; the last cooperative holder
            # releases the lock when its own reference closes.
            os.close(descriptor)
        self._locks = []
        self._closed = True

    def close(self):
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            raise StoreOwnershipError("inherited observation ownership is invalid")
        if self._active:
            raise StoreConflict("active observation cannot close its store")
        if not self._closed:
            self._release()

    def __enter__(self):
        self._public()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
