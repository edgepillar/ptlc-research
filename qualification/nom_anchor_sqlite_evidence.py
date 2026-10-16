"""Original synthetic SQL qualification output, with no adoption or cleanup API.

The caller admits this finite output inside its resource-controlled workspace.
An existing directory is refused. This format is not a general task manager,
independent authority, protected store or original-operation journal.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

SCHEMA = "ptlc-nom-anchor-sqlite-evidence-v1"
MAX_OBJECT_BYTES = 20 * 1024**2
MAX_TOTAL_BYTES = 128 * 1024**2
MAX_OBJECTS = 256
MAX_EVENTS = 2048


class EvidenceRefused(ValueError):
    """The exact new evidence output or an original association is unavailable."""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _sync(directory):
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _exclusive(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    _sync(path.parent)


class OriginalEvidence:
    """One new finite output: unique byte objects and immutable original labels.

    Intent and completion events surround each object retention. No event is a
    SQLite acknowledgment. Files remain on failure; this class never deletes,
    trims, repairs, adopts or automatically resumes any directory.
    """

    def __init__(self, directory):
        requested = Path(directory).absolute()
        self.root = requested.parent.resolve() / requested.name
        if self.root.exists() or self.root.is_symlink():
            raise EvidenceRefused("a new exclusive qualification output is required")
        self.root.mkdir(mode=0o700)
        info = self.root.lstat()
        self._identity = info.st_dev, info.st_ino
        self._objects, self._labels, self._events = {}, {}, 0
        self._bytes, self._finished = 0, False
        (self.root / "objects").mkdir(mode=0o700)
        (self.root / "events").mkdir(mode=0o700)
        self._children = {name: ((self.root / name).stat().st_dev, (self.root / name).stat().st_ino)
                          for name in ("objects", "events")}
        self.identifier = uuid.uuid4().hex
        _exclusive(self.root / "enrollment.json", _json(dict(schema=SCHEMA, identifier=self.identifier,
            purpose="synthetic-original-sql-output-only", max_object_bytes=MAX_OBJECT_BYTES,
            max_total_bytes=MAX_TOTAL_BYTES, max_objects=MAX_OBJECTS, max_events=MAX_EVENTS,
            application="NO-GO", core="NO-GO", recovery_action="NONE")))

    def _guard(self):
        info = self.root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self._identity
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
                or self._finished):
            raise EvidenceRefused("selected evidence output changed or is complete")
        for name in ("objects", "events"):
            selected = (self.root / name).lstat()
            if (not stat.S_ISDIR(selected.st_mode)
                    or (selected.st_dev, selected.st_ino) != self._children[name]
                    or selected.st_uid != os.getuid() or stat.S_IMODE(selected.st_mode) != 0o700):
                raise EvidenceRefused("selected evidence child boundary changed")

    def _event(self, kind, label, reference):
        if self._events >= MAX_EVENTS:
            raise EvidenceRefused("finite evidence event bound reached")
        self._events += 1
        _exclusive(self.root / "events" / ("{:04d}.json".format(self._events)),
            _json(dict(schema=SCHEMA, position=self._events, kind=kind, label=label, object=reference)))

    def put(self, label, raw):
        self._guard()
        if (type(label) is not str or re.fullmatch(r"[a-z0-9][a-z0-9._/-]{0,127}", label) is None
                or any(part in ("", ".", "..") for part in label.split("/"))
                or type(raw) is not bytes or len(raw) > MAX_OBJECT_BYTES):
            raise EvidenceRefused("invalid bounded original evidence")
        digest = hashlib.sha256(raw).hexdigest()
        reference = dict(sha256=digest, bytes=len(raw))
        if label in self._labels and self._labels[label] != reference:
            raise EvidenceRefused("original evidence label cannot be replaced")
        existing = self._objects.get(digest)
        if existing is None and (len(self._objects) >= MAX_OBJECTS or self._bytes + len(raw) > MAX_TOTAL_BYTES):
            raise EvidenceRefused("finite original evidence capacity reached")
        self._event("RETAIN_INTENT", label, reference)
        path = self.root / "objects" / digest
        if existing is None:
            _exclusive(path, raw)
            info = path.lstat()
            self._objects[digest] = dict(identity=(info.st_dev, info.st_ino), bytes=len(raw))
            self._bytes += len(raw)
        self.read(digest)
        self._labels[label] = reference
        self._event("RETAINED", label, reference)
        return reference

    def read(self, digest):
        self._guard()
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None or digest not in self._objects:
            raise EvidenceRefused("an original retained object is required")
        expected = self._objects[digest]
        path = self.root / "objects" / digest
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (info.st_dev, info.st_ino) != expected["identity"] or info.st_size != expected["bytes"]
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise EvidenceRefused("original retained object identity changed")
        raw = path.read_bytes()
        if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != digest:
            raise EvidenceRefused("original retained object bytes changed")
        return raw

    def path(self, digest):
        self.read(digest)
        return self.root / "objects" / digest

    def finalize(self, status, report):
        self._guard()
        if status not in ("COMPLETE_FINITE_COMPARISON", "NOT_QUALIFIED") or type(report) is not dict:
            raise EvidenceRefused("explicit qualification disposition required")
        result = self.put("comparison-report", _json(report))
        manifest = dict(schema=SCHEMA, identifier=self.identifier, status=status, report=result,
            objects={digest: dict(bytes=row["bytes"]) for digest, row in sorted(self._objects.items())},
            labels=self._labels, event_count=self._events, retained_bytes=self._bytes,
            application="NO-GO", core="NO-GO", recovery_action="NONE")
        raw = _json(manifest)
        if len(raw) > 1024**2:
            raise EvidenceRefused("finite evidence manifest bound reached")
        _exclusive(self.root / "manifest.json", raw)
        self._finished = True
        return dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), report=result,
            object_count=len(self._objects), event_count=self._events)
