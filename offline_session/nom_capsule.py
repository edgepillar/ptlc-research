"""Create-only full projection custody under a cooperating private POSIX owner.

Readable bytes supply HOLD, never currentness, execution receipts or recovery.
Successful fsync calls are OS observations, not power-loss qualification.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import threading

try:
    import fcntl
except ImportError:
    fcntl = None

from . import nom_journal_hold as projection, nom_partial_custody as partial
from . import nom_recovery as recovery


PROFILE = "ptlc-nom-full-projection-capsule-v1"
OWNER_PROFILE = "ptlc-nom-capsule-owner-v1"
MAX_BYTES = 5 * 1024 * 1024
CAPSULE_NAME = "projection.capsule"
LOCK_NAME = "owner.lock"
LOCK_BYTES = b"ptlc-nom-capsule-owner-v1\n"
PHASES = ("capsule-created", "capsule-written", "capsule-file-fsync-returned",
          "capsule-readonly-mode", "capsule-metadata-fsync-returned",
          "capsule-directory-fsync-returned", "capsule-before-return")


class CapsuleRefused(recovery.RecoveryError):
    """Selected custody refusal; no source, chain or execution verdict."""


def _require(value):
    if not value:
        raise CapsuleRefused("selected full projection capsule refused")


def _wire(value):
    result = json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False).encode("ascii")
    _require(0 < len(result) <= MAX_BYTES)
    return result


def _phase(_name):
    """No-op selected process-cut seam; supplies no durable evidence by itself."""


def _selected(value):
    _require(type(value) is dict and value.keys() == {
        "schema", "journal_hex", "journal_sha256", "journal_bytes", "journal_head_hex",
        "journal_sequence", "role", "partial_hold_hex", "selection_digest_hex"})
    _require(value["schema"] == projection.PROFILE)
    journal = bytes.fromhex(value["journal_hex"])
    replay, head, sequence = projection._replay(journal)
    held = partial._state(partial.uncertainty._decode(bytes.fromhex(value["partial_hold_hex"])))
    selection = partial._selection(partial.uncertainty._decode(bytes.fromhex(held["selection_hex"])))
    expected = projection._hold(replay, selection["challenge_hex"])
    _require(value == dict(schema=projection.PROFILE, journal_hex=journal.hex(),
        journal_sha256=hashlib.sha256(journal).hexdigest(), journal_bytes=len(journal),
        journal_head_hex=head, journal_sequence=sequence, role=replay.role,
        partial_hold_hex=expected.canonical_bytes.hex(), selection_digest_hex=expected.selection_digest_hex))
    return journal, expected


def encode_capsule(selected):
    """Encode an exact selected in-memory projection, without entering a worker."""
    try:
        _require(type(selected) is projection.JournalPartialHold)
        value = selected.as_dict(); _selected(value)
        return _wire(dict(schema=PROFILE, selected_projection=value))
    except recovery.RecoveryError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise CapsuleRefused("invalid full projection capsule encoding") from None


@dataclass(frozen=True, init=False)
class CapsuleView:
    """Immutable comparison bytes in memory; no transferable authority token."""
    _wire: bytes

    def __init__(self):
        raise TypeError("use read_capsule")

    @property
    def canonical_bytes(self):
        _decode(self._wire)
        return self._wire

    @property
    def digest_hex(self):
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    def projection(self):
        return _decode(self._wire)[0]["selected_projection"]

    @property
    def journal_bytes(self):
        return _decode(self._wire)[1]

    @property
    def partial_hold(self):
        return _decode(self._wire)[2]

    def review(self):
        held = self.partial_hold
        return dict(profile=PROFILE, state="HOLD", recovery_action="NONE",
            capsule_sha256=self.digest_hex, journal_sha256=self.projection()["journal_sha256"],
            full_original_bytes="RETAINED; EXACT STRUCTURAL COMPARISON",
            signature_mathematics="NOT_PERFORMED BY CAPSULE CONSUMER",
            producer_origin="NOT_AUTHENTICATED", source_currentness="UNFILLED",
            work_execution="UNKNOWN; NO INDIVIDUAL EXECUTION RECEIPTS",
            durability="READABILITY DOES NOT PROVE FSYNC OR POWER-LOSS SURVIVAL",
            restore_fence="UNFILLED", atomic_work_admission="UNFILLED",
            complete_query_conversion="NOT_PROVIDED", automatic_retry=False,
            replenish_work=False, frozen_partial_review=held.review(),
            application="NO-GO", core="NO-GO")


def _decode(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_BYTES)
    value = json.loads(wire.decode("ascii"))
    _require(type(value) is dict and value.keys() == {"schema", "selected_projection"}
        and value["schema"] == PROFILE and _wire(value) == wire)
    journal, held = _selected(value["selected_projection"])
    return value, journal, held


def read_capsule(wire, *, expected_digest_hex):
    """Compare one explicitly selected digest; perform no reopen or mathematics."""
    try:
        _require(type(expected_digest_hex) is str and len(expected_digest_hex) == 64
            and bytes.fromhex(expected_digest_hex).hex() == expected_digest_hex)
        _decode(wire)
        _require(hashlib.sha256(wire).hexdigest() == expected_digest_hex)
        value = object.__new__(CapsuleView)
        object.__setattr__(value, "_wire", wire)
        return value
    except recovery.RecoveryError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError):
        raise CapsuleRefused("invalid selected full projection capsule") from None


def _path(value):
    path = Path(value)
    _require(path.name not in ("", ".", "..") and ".." not in path.parts)
    path = path.absolute()
    for parent in reversed(path.parents):
        _require(stat.S_ISDIR(parent.lstat().st_mode) and not parent.is_symlink())
    return path


def _file(info, mode):
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == mode)


def _pin(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _write(fd, wire):
    offset = 0
    while offset < len(wire):
        size = os.write(fd, wire[offset:offset + 65536])
        _require(type(size) is int and 0 < size <= min(65536, len(wire) - offset))
        offset += size


class CapsuleOwner:
    """One process and thread holding the selected private directory lease."""
    @classmethod
    def create(cls, path):
        _require(cls is CapsuleOwner and fcntl is not None and os.name == "posix")
        parent_fd = root_fd = lock_fd = None
        try:
            path = _path(path)
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            parent = os.fstat(parent_fd)
            _require(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700)
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            root_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            lock_fd = os.open(LOCK_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=root_fd)
            _write(lock_fd, LOCK_BYTES); os.fsync(lock_fd); os.fsync(root_fd); os.fsync(parent_fd)
        except recovery.RecoveryError:
            raise
        except (OSError, ValueError, TypeError, AttributeError):
            raise CapsuleRefused("capsule owner initialization refused; preserve created bytes") from None
        finally:
            for fd in (lock_fd, root_fd, parent_fd):
                if fd is not None: os.close(fd)
        return cls.open(path)

    @classmethod
    def open(cls, path):
        _require(cls is CapsuleOwner and fcntl is not None and os.name == "posix")
        value = object.__new__(cls)
        value._fd = value._lock = None; value._closed = False; value._poisoned = False
        value._pid = os.getpid(); value._thread = threading.current_thread()
        try:
            value._path = _path(path)
            value._fd = os.open(value._path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            root = os.fstat(value._fd)
            _require(root.st_uid == os.getuid() and stat.S_IMODE(root.st_mode) == 0o700)
            value._root_pin = (root.st_dev, root.st_ino)
            value._lock = os.open(LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=value._fd)
            _file(os.fstat(value._lock), 0o600)
            fcntl.flock(value._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _require(os.pread(value._lock, len(LOCK_BYTES) + 1, 0) == LOCK_BYTES)
            value._lock_pin = _pin(os.fstat(value._lock)); value._check()
            return value
        except recovery.RecoveryError:
            value.close(); raise
        except (OSError, ValueError, TypeError, AttributeError):
            value.close(); raise CapsuleRefused("existing capsule owner refused") from None

    def _check(self):
        _require(type(self) is CapsuleOwner and not self._closed and not self._poisoned
            and self._pid == os.getpid() and self._thread is threading.current_thread())
        root = os.fstat(self._fd); path = self._path.lstat()
        _require(stat.S_ISDIR(root.st_mode) and root.st_uid == os.getuid()
            and stat.S_IMODE(root.st_mode) == 0o700 and not self._path.is_symlink()
            and self._root_pin == (root.st_dev, root.st_ino) == (path.st_dev, path.st_ino))
        locked = os.fstat(self._lock); named = os.stat(LOCK_NAME, dir_fd=self._fd, follow_symlinks=False)
        _file(locked, 0o600); _file(named, 0o600)
        _require(self._lock_pin == _pin(locked) == _pin(named))

    def store(self, selected):
        """Create one capsule only; failures retain partial bytes and poison ownership."""
        self._check()
        fd = None
        try:
            wire = encode_capsule(selected)
            fd = os.open(CAPSULE_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self._fd)
            _file(os.fstat(fd), 0o600); _phase(PHASES[0])
            _write(fd, wire); _phase(PHASES[1])
            os.fsync(fd); _phase(PHASES[2])
            os.fchmod(fd, 0o400); _phase(PHASES[3])
            os.fsync(fd); _phase(PHASES[4])
            os.fsync(self._fd); _phase(PHASES[5]); self._check()
            _file(os.fstat(fd), 0o400)
            _require(_pin(os.fstat(fd)) == _pin(os.stat(CAPSULE_NAME, dir_fd=self._fd, follow_symlinks=False)))
            os.close(fd); fd = None; _phase(PHASES[6])
            return dict(schema=PROFILE, capsule_sha256=hashlib.sha256(wire).hexdigest(),
                capsule_bytes=len(wire), file_fsync="RETURNED; INCLUDING READONLY METADATA",
                directory_fsync="RETURNED", power_loss="NOT_QUALIFIED", state="HOLD",
                source_currentness="UNFILLED", restore_fence="UNFILLED", recovery_action="NONE")
        except BaseException as error:
            self._poisoned = True
            if isinstance(error, recovery.RecoveryError): raise
            if isinstance(error, (OSError, ValueError, TypeError, AttributeError, RecursionError, OverflowError)):
                raise CapsuleRefused("capsule persistence refused; preserve original partial bytes") from None
            raise
        finally:
            if fd is not None: os.close(fd)

    def read(self, *, expected_digest_hex):
        """Read two exact bounded snapshots; supply only a structural HOLD view."""
        self._check()
        fd = None
        try:
            fd = os.open(CAPSULE_NAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._fd)
            info = os.fstat(fd); _file(info, 0o400); _require(0 < info.st_size <= MAX_BYTES)
            def snapshot():
                _require(_pin(os.fstat(fd)) == _pin(info))
                wire = b""
                while len(wire) < info.st_size:
                    piece = os.pread(fd, min(65536, info.st_size - len(wire)), len(wire))
                    _require(type(piece) is bytes and 0 < len(piece) <= info.st_size - len(wire))
                    wire += piece
                _require(os.pread(fd, 1, info.st_size) == b"")
                named = os.stat(CAPSULE_NAME, dir_fd=self._fd, follow_symlinks=False)
                _file(named, 0o400); _require(_pin(info) == _pin(os.fstat(fd)) == _pin(named))
                self._check()
                return wire
            wire = snapshot(); selected = read_capsule(wire, expected_digest_hex=expected_digest_hex)
            _require(snapshot() == wire)
            return selected
        except BaseException as error:
            self._poisoned = True
            if isinstance(error, recovery.RecoveryError): raise
            if isinstance(error, (OSError, ValueError, TypeError, AttributeError, RecursionError, OverflowError)):
                raise CapsuleRefused("capsule consumer refused; preserve original bytes") from None
            raise
        finally:
            if fd is not None: os.close(fd)

    def close(self):
        _require(self._pid == os.getpid() and self._thread is threading.current_thread())
        if not self._closed:
            for name in ("_lock", "_fd"):
                fd = getattr(self, name)
                if fd is not None: os.close(fd)
                setattr(self, name, None)
            self._closed = True

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
