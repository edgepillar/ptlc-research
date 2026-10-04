"""Synthetic failures around real storage operations, never native EIO proof.

The exact application persist method still runs. Phase tagging, connection/file
proxies and one-shot faults are trusted test instrumentation, not a public API.
Only a returned real operation can reach an after-operation fault.
"""

from contextlib import ExitStack, contextmanager
import errno
import os
import sqlite3
import stat
from unittest.mock import patch

from offline_session.observation_store import ObservationStore


PHASES = {"initialize", "admission", "result", "recovery"}
OPERATIONS = {"sqlite.begin", "sqlite.schema", "sqlite.write", "sqlite.commit", "sqlite.rollback",
              "checkpoint.write", "checkpoint.flush", "checkpoint.fsync", "checkpoint.replace",
              "directory.fsync", "checkpoint.unlink"}


class StorageFaults:
    """Run real operations, with explicitly synthetic before/after failures."""

    def __init__(self, *points):
        if (not points or len(set(points)) != len(points) or any(
                type(point) is not tuple or len(point) != 3 or point[0] not in PHASES
                or point[1] not in OPERATIONS or point[2] not in {"before", "after"} for point in points)):
            raise ValueError("invalid synthetic storage fault")
        self.points = points
        self.hits = []
        self.events = []
        self.phase = None

    def _fire(self, operation, timing):
        point = (self.phase, operation, timing)
        if point in self.points and point not in self.hits:
            self.hits.append(point)
            if operation.startswith("sqlite."):
                raise sqlite3.OperationalError("synthetic storage fault")
            raise OSError(errno.ENOSPC if operation == "checkpoint.write" else errno.EIO,
                          "synthetic storage fault")

    def run(self, operation, callback):
        if self.phase is None:
            return callback()
        self.events.append((self.phase, operation, "entered"))
        self._fire(operation, "before")
        result = callback()
        self.events.append((self.phase, operation, "returned"))
        self._fire(operation, "after")
        return result

    def assert_fired(self, case):
        case.assertCountEqual(self.hits, self.points)
        for phase, operation, timing in self.points:
            if timing == "after":
                case.assertIn((phase, operation, "returned"), self.events)

    @contextmanager
    def inject(self, *owners):
        original_persist = ObservationStore._persist
        original_connect, original_fdopen = sqlite3.connect, os.fdopen
        original_fsync, original_replace, original_unlink = os.fsync, os.replace, os.unlink
        wrapped = []

        def persist(owner, wire, phase, initializing=False):
            previous, self.phase = self.phase, phase
            try:
                return original_persist(owner, wire, phase, initializing=initializing)
            finally:
                self.phase = previous

        def connect(*arguments, **options):
            return _Connection(original_connect(*arguments, **options), self)

        def fdopen(*arguments, **options):
            stream = original_fdopen(*arguments, **options)
            return _File(stream, self) if self.phase is not None else stream

        def fsync(descriptor):
            operation = "directory.fsync" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "checkpoint.fsync"
            return self.run(operation, lambda: original_fsync(descriptor))

        with ExitStack() as controls:
            controls.enter_context(patch.object(ObservationStore, "_persist", persist))
            controls.enter_context(patch("sqlite3.connect", side_effect=connect))
            controls.enter_context(patch("os.fdopen", side_effect=fdopen))
            controls.enter_context(patch("os.fsync", side_effect=fsync))
            controls.enter_context(patch("os.replace", side_effect=lambda *args, **kwargs:
                self.run("checkpoint.replace", lambda: original_replace(*args, **kwargs))))
            controls.enter_context(patch("os.unlink", side_effect=lambda *args, **kwargs:
                self.run("checkpoint.unlink", lambda: original_unlink(*args, **kwargs))))
            for owner in owners:
                previous = owner._connection
                connection = _Connection(previous, self)
                owner._connection = connection
                wrapped.append((owner, connection, previous))
            try:
                yield self
            finally:
                for owner, connection, previous in wrapped:
                    if owner._connection is connection:
                        owner._connection = previous


class _Connection:
    def __init__(self, connection, faults):
        self.connection, self.faults = connection, faults

    def execute(self, statement, *arguments):
        if statement == "BEGIN IMMEDIATE":
            operation = "sqlite.begin"
        elif statement.startswith("CREATE TABLE checkpoint"):
            operation = "sqlite.schema"
        elif statement.startswith("INSERT OR REPLACE INTO checkpoint"):
            operation = "sqlite.write"
        else:
            return self.connection.execute(statement, *arguments)
        return self.faults.run(operation, lambda: self.connection.execute(statement, *arguments))

    def commit(self):
        return self.faults.run("sqlite.commit", self.connection.commit)

    def rollback(self):
        return self.faults.run("sqlite.rollback", self.connection.rollback)

    def __getattr__(self, name):
        return getattr(self.connection, name)


class _File:
    def __init__(self, stream, faults):
        self.stream, self.faults = stream, faults

    def write(self, data):
        return self.faults.run("checkpoint.write", lambda: self.stream.write(data))

    def flush(self):
        return self.faults.run("checkpoint.flush", self.stream.flush)

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *arguments):
        return self.stream.__exit__(*arguments)

    def __getattr__(self, name):
        return getattr(self.stream, name)
