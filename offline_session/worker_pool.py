"""Shared live-worker admission for cooperating local public observation stores.

This is a finite lease pool, not CPU/memory accounting, fairness, source trust or
host-wide containment. All participating callers must select the same physical
pool files. A public profile authenticates neither that selection nor a clone.
"""

import hashlib
import os
from pathlib import Path
import stat
import sys
import threading

try:
    import fcntl
except ImportError:
    fcntl = None

from . import exchange, observation_evidence as evidence


VERSION = 1
MAX_SLOTS = 16
MAX_CONFIG_BYTES = 512


class PoolError(ValueError):
    """Sanitized admission failure without paths, slot numbers or diagnostics."""


class PoolBusy(PoolError):
    pass


class PoolQuarantined(PoolError):
    pass


class PoolOwnershipError(PoolError):
    pass


def _private(descriptor, maximum):
    value = os.fstat(descriptor)
    if (not stat.S_ISREG(value.st_mode) or value.st_mode & 0o077
            or value.st_uid != os.geteuid() or value.st_size > maximum):
        raise PoolQuarantined("invalid worker pool file")
    return value.st_dev, value.st_ino


def _file(path, flags):
    return os.open(path, flags | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), 0o600)


def _sync(root):
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class WorkerLease:
    """One held slot; close only this reference, never unlock shared holders."""

    def __init__(self, descriptor):
        self._descriptor = descriptor
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._closed = False

    def _owned(self):
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            raise PoolOwnershipError("inherited worker lease is invalid")

    def fileno(self):
        self._owned()
        if self._closed:
            raise PoolOwnershipError("worker lease is closed")
        return self._descriptor

    def close(self):
        self._owned()
        if not self._closed:
            os.close(self._descriptor)
            self._closed = True

    def __enter__(self):
        self.fileno()
        return self

    def __exit__(self, *_):
        self.close()
        return False


class PublicWorkerPool:
    """Explicit fixed pool of private advisory lock files on Linux/macOS.

    Configuration is serialized during open, then immutable through this API.
    Slots are acquired nonblocking and never reset, unlinked or replaced.
    Metadata consistency and process/thread ownership do not resist a hostile
    caller or storage administrator. Legacy public helpers bypass this pool.
    """

    @classmethod
    def open(cls, directory, *, pool_id_hex, slot_limit):
        self = cls()
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        try:
            if (os.name != "posix" or sys.platform not in {"linux", "darwin"}
                    or fcntl is None or type(slot_limit) is not int or not 1 <= slot_limit <= MAX_SLOTS):
                raise PoolError("unsupported worker pool configuration")
            evidence._profile(pool_id_hex)
            self._config = exchange.canonical({"version": VERSION, "pool_id_hex": pool_id_hex,
                                               "slot_limit": slot_limit})
            self._profile = hashlib.sha256(b"PTLC/public-worker-pool/v1\x00" + self._config).hexdigest()
            self._slots = tuple("slot-" + str(number) + ".lock" for number in range(slot_limit))
            self._open(directory)
            return self
        except BaseException as error:
            if isinstance(error, PoolError):
                raise
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise PoolQuarantined("worker pool open rejected") from None

    def _inventory(self, initializing=False):
        expected = {"pool.lock"} if initializing else {"pool.lock", "pool.json", *self._slots}
        found = set()
        with os.scandir(self._root) as entries:
            for entry in entries:
                if entry.name not in expected or len(found) >= MAX_SLOTS + 2:
                    raise PoolQuarantined("unexpected worker pool contents")
                found.add(entry.name)
        if found != expected:
            raise PoolQuarantined("incomplete worker pool configuration")

    def _open(self, directory):
        root = Path(directory).absolute()
        if root.is_symlink():
            raise PoolQuarantined("worker pool symlink rejected")
        root.mkdir(mode=0o700, parents=False, exist_ok=True)
        metadata = root.stat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077
                or metadata.st_uid != os.geteuid()):
            raise PoolQuarantined("worker pool directory is not private")
        self._root = root.resolve()
        lock_path = self._root / "pool.lock"
        if not lock_path.exists() and not lock_path.is_symlink():
            with os.scandir(self._root) as entries:
                if next(entries, None) is not None:
                    raise PoolQuarantined("incomplete worker pool configuration")
        lock = _file(lock_path, os.O_RDWR | os.O_CREAT)
        try:
            lock_identity = _private(lock, 0)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PoolBusy("worker pool configuration already owned") from None
            config = self._root / "pool.json"
            if not config.exists() and not config.is_symlink():
                self._inventory(initializing=True)
                for name in self._slots:
                    descriptor = _file(self._root / name, os.O_RDWR | os.O_CREAT | os.O_EXCL)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                descriptor = _file(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(self._config)
                    output.flush()
                    os.fsync(output.fileno())
                _sync(self._root)
            self._inventory()
            descriptor = _file(config, os.O_RDONLY)
            try:
                config_identity = _private(descriptor, MAX_CONFIG_BYTES)
                wire = os.read(descriptor, MAX_CONFIG_BYTES + 1)
                if wire != self._config:
                    raise PoolQuarantined("worker pool configuration mismatch")
            finally:
                os.close(descriptor)
            self._config_identity = config_identity
            identities = {lock_identity, config_identity}
            if len(identities) != 2:
                raise PoolQuarantined("worker pool file identities overlap")
            self._identities = {}
            for name in self._slots:
                descriptor = _file(self._root / name, os.O_RDWR)
                try:
                    identity = _private(descriptor, 0)
                    if identity in identities:
                        raise PoolQuarantined("worker pool slot identities overlap")
                    identities.add(identity)
                    self._identities[name] = identity
                finally:
                    os.close(descriptor)
        finally:
            os.close(lock)

    def _owned(self):
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            raise PoolOwnershipError("inherited worker pool is invalid")

    @property
    def profile_digest_hex(self):
        self._owned()
        return self._profile

    def check_store_locations(self, directory, checkpoint):
        self._owned()
        root, anchor = Path(directory).resolve(), Path(checkpoint).resolve()
        if (root == self._root or root in self._root.parents or self._root in root.parents
                or anchor == self._root or self._root in anchor.parents):
            raise PoolError("separate worker pool storage required")

    def acquire(self):
        """Take one slot without waiting, queuing, retrying or writing a record."""
        self._owned()
        try:
            self._inventory()
            descriptor = _file(self._root / "pool.json", os.O_RDONLY)
            try:
                if (_private(descriptor, MAX_CONFIG_BYTES) != self._config_identity
                        or os.read(descriptor, MAX_CONFIG_BYTES + 1) != self._config):
                    raise PoolQuarantined("worker pool configuration changed")
            finally:
                os.close(descriptor)
            for name in self._slots:
                descriptor = _file(self._root / name, os.O_RDWR)
                try:
                    if _private(descriptor, 0) != self._identities[name]:
                        raise PoolQuarantined("worker pool slot changed")
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        continue
                    lease = WorkerLease(descriptor)
                    descriptor = None
                    return lease
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
            raise PoolBusy("shared worker capacity is unavailable")
        except BaseException as error:
            if isinstance(error, PoolError):
                raise
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise PoolQuarantined("worker pool admission rejected") from None
