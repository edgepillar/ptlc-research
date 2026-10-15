"""Selected POSIX retention of one complete reference transition; never authority.

Actual typed custody is supplied separately on every open. Retained public bytes
cannot reconstruct absent requests or contexts. The host, filesystem and complete
parent pathname are trusted. Coherent copies and restores remain unprotected.
"""
import hashlib
import os
import re
import stat
import threading

try:
    import fcntl
except ImportError:
    fcntl = None

from . import enrollment_contract as codec
from . import nom_anchor_lifecycle as lifecycle


PROFILE = "ptlc-nom-anchor-transition-journal-v1"
RECORD_DOMAIN = b"ptlc-nom-anchor-transition-journal-record-v1\0"
MAX_RECORD_BYTES = 96 * 1024
MAX_LOG_BYTES = 192 * 1024
WRITE_CHUNK_BYTES = 1024
ZERO = "00" * 32
_INPUT_ERRORS = (ValueError, TypeError, AttributeError, KeyError, RecursionError,
                 OverflowError, UnicodeError)


class AnchorJournalRefused(ValueError):
    """The fixed reference request or a finite bound was refused."""


class AnchorJournalQuarantined(AnchorJournalRefused):
    """Selected local continuity is unavailable; no absence or retry verdict."""


class AnchorJournalMissing(AnchorJournalQuarantined):
    """The selected existing journal is unavailable; automatic creation is forbidden."""


class AnchorJournalBusy(AnchorJournalQuarantined):
    """Another cooperating owner holds the selected physical file."""


class AnchorJournalOutcomeUnknown(RuntimeError):
    """A local write has no conclusive acknowledgment; preserve the exact request."""


def _require(condition):
    if not condition:
        raise AnchorJournalRefused("selected anchor transition journal refused")


def _record(position, previous, kind, payload):
    value = dict(schema=PROFILE, position=position, previous_record_digest_hex=previous,
                 kind=kind, payload=payload)
    digest = hashlib.sha256(RECORD_DOMAIN + codec._canonical(value)).hexdigest()
    wire = codec._canonical(dict(value, record_digest_hex=digest)) + b"\n"
    _require(len(wire) <= MAX_RECORD_BYTES)
    return wire, digest


def _material(before, hold):
    """Fresh actual validation inside one operation, with no global trust cache."""
    try:
        validate = lifecycle._Validation()
        _, anchor = validate.anchor(before)
        held = lifecycle._validated_hold(hold, validate)
        request, _ = validate.request(hold._request)
        _require(before._wire == hold._request._before._wire)
        _require(request["expected_anchor_digest_hex"] == lifecycle._hash(lifecycle.STATE_DOMAIN, anchor))
        after = lifecycle._freeze(before._initial, before._anchor_id_hex, before._anchor_epoch,
                                  before._events + (hold._request._transition,), validate)
        _, next_anchor = validate.anchor(after)
        initial, first = _record(1, ZERO, "RETAIN_EXACT_REQUEST", dict(
            before_anchor=anchor, pending_request=request, pending_hold=held,
            publication_outcome="UNKNOWN", application="NO-GO", core="NO-GO", recovery_action="NONE"))
        transition, second = _record(2, first, "RETAIN_REFERENCE_TRANSITION", dict(
            request_digest_hex=held["request_digest_hex"], after_anchor=next_anchor,
            publication_outcome="UNKNOWN", application="NO-GO", core="NO-GO", recovery_action="NONE"))
        _require(len(initial) + len(transition) <= MAX_LOG_BYTES)
        return initial, transition, first, second, after
    except _INPUT_ERRORS:
        raise AnchorJournalRefused("complete actual anchor request custody refused") from None


class AnchorTransitionJournal:
    """One cooperating owner, two bounded records, one fixed reference request.

Creation is explicit and exclusive. Opening an existing file never creates,
truncates, repairs or replays a write. A complete unacknowledged image is fsynced
on reopen, then inspected separately. This is no independently selected anchor,
service acknowledgment, nonrollback domain or original-operation journal.
"""
    def __init__(self):
        raise TypeError("use create or open_existing with complete actual custody")

    @classmethod
    def create(cls, path, before_anchor, pending_hold):
        """Explicit research enrollment; exclusive local creation proves no uniqueness."""
        return cls._open(path, before_anchor, pending_hold, create=True)

    @classmethod
    def open_existing(cls, path, before_anchor, pending_hold):
        """Require the existing exact record and the original complete typed inputs."""
        return cls._open(path, before_anchor, pending_hold, create=False)

    @classmethod
    def _open(cls, path, before, hold, *, create):
        initial, transition, first, second, after = _material(before, hold)
        owner = cls.__new__(cls)
        owner._fd = owner._directory = None
        owner._closed = owner._poisoned = owner._busy = False
        owner._pid, owner._thread = os.getpid(), threading.current_thread()
        owner._before, owner._hold, owner._after = before, hold, after
        owner._initial, owner._transition = initial, transition
        owner._digests, owner._image, owner._applied = (first, second), b"", False
        try:
            _require(os.name == "posix" and fcntl is not None)
            parent, owner._name = os.path.split(os.fspath(path))
            _require(type(owner._name) is str and re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", owner._name) is not None)
            owner._directory = os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(owner._directory)
            _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            if create:
                flags |= os.O_CREAT | os.O_EXCL
            try:
                owner._fd = os.open(owner._name, flags, 0o600, dir_fd=owner._directory)
            except FileNotFoundError:
                raise AnchorJournalMissing("selected existing anchor journal unavailable") from None
            except FileExistsError:
                raise AnchorJournalRefused("explicit anchor journal creation refused") from None
            owner._boundary()
            try:
                fcntl.flock(owner._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AnchorJournalBusy("selected anchor journal already has an owner") from None
            if create:
                owner._append(initial, creating=True)
            else:
                data = owner._read()
                _require(data in (initial, initial + transition))
                owner._image, owner._applied = data, data == initial + transition
                owner._busy = True
                try:
                    owner._cut("reopen-before-fsync")
                    os.fsync(owner._fd)
                    os.fsync(owner._directory)
                    owner._cut("reopen-after-fsync")
                except Exception:
                    owner._poisoned = True
                    raise AnchorJournalOutcomeUnknown("selected reopen synchronization outcome unknown") from None
                finally:
                    owner._busy = False
                owner._guard()
            return owner
        except (AnchorJournalRefused, AnchorJournalOutcomeUnknown):
            owner._dispose()
            raise
        except (OSError,) + _INPUT_ERRORS:
            owner._dispose()
            raise AnchorJournalQuarantined("selected anchor journal could not be opened") from None
        except BaseException:
            owner._dispose()
            raise

    def _cut(self, label):
        """Test subclass fault/death cuts; no application callback is accepted."""

    def _boundary(self):
        directory = os.fstat(self._directory)
        _require(directory.st_uid == os.getuid() and stat.S_IMODE(directory.st_mode) == 0o700)
        info = os.fstat(self._fd)
        entry = os.stat(self._name, dir_fd=self._directory, follow_symlinks=False)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_LOG_BYTES
                 and (info.st_dev, info.st_ino) == (entry.st_dev, entry.st_ino))

    def _read(self):
        self._boundary()
        os.lseek(self._fd, 0, os.SEEK_SET)
        parts, size = [], 0
        while True:
            part = os.read(self._fd, min(65536, MAX_LOG_BYTES + 1 - size))
            if not part:
                break
            parts.append(part)
            size += len(part)
            _require(size <= MAX_LOG_BYTES)
        self._boundary()
        return b"".join(parts)

    def _guard(self):
        if (self._closed or self._poisoned or self._busy or self._pid != os.getpid()
                or self._thread is not threading.current_thread()):
            raise AnchorJournalQuarantined("selected anchor journal owner unavailable")
        try:
            initial, transition, first, second, after = _material(self._before, self._hold)
            _require((initial, transition, (first, second)) == (self._initial, self._transition, self._digests))
            _require(self._read() == self._image)
            # Recompute derived reference state from original actual custody.
            # Neither serialized descriptors nor an old derived object reopen it.
            self._after = after
        except (OSError,) + _INPUT_ERRORS:
            self._poisoned = True
            raise AnchorJournalQuarantined("selected anchor journal continuity changed") from None

    def _append(self, wire, *, creating=False):
        _require(len(self._image) + len(wire) <= MAX_LOG_BYTES)
        self._busy = True
        try:
            self._cut("append-before-write")
            os.lseek(self._fd, 0, os.SEEK_END)
            offset = 0
            while offset < len(wire):
                count = os.write(self._fd, wire[offset:offset + WRITE_CHUNK_BYTES])
                if count <= 0:
                    raise OSError("selected anchor write made no progress")
                offset += count
                if offset == count:
                    self._cut("append-first-write")
            self._cut("append-after-write")
            self._cut("append-before-fsync")
            os.fsync(self._fd)
            self._cut("append-after-fsync")
            if creating:
                os.fsync(self._directory)
                self._cut("create-directory-synced")
            expected = self._image + wire
            _require(self._read() == expected)
            self._image = expected
            self._applied = not creating
            self._cut("append-before-ack")
        except Exception:
            self._poisoned = True
            raise AnchorJournalOutcomeUnknown("selected local anchor write outcome unknown") from None
        except BaseException:
            self._poisoned = True
            raise
        finally:
            self._busy = False
        return self._receipt()

    def _receipt(self):
        return dict(profile=PROFILE, state="HOLD", reference_transition_retained=self._applied,
            record_count=2 if self._applied else 1, record_digest_hex=self._digests[int(self._applied)],
            file_sha256=hashlib.sha256(self._image).hexdigest(),
            reference_anchor_phase="RETIRED" if self._applied and self._hold._request._transition.kind == "RETIRE" else "ACTIVE",
            publication_outcome="UNKNOWN", local_retention="SELECTED_FSYNC_ACKNOWLEDGED",
            actual_custody="COMPLETE ORIGINAL TYPED INPUTS REQUIRED SEPARATELY",
            service_acknowledgment="NOT_ESTABLISHED", current_at_delivery="NOT_ESTABLISHED",
            nonrollback="UNPROTECTED", physical_power_loss="UNQUALIFIED", shared_atomic_cas="NOT_IMPLEMENTED",
            new_work_allowed=False, automatic_retry=False, same_request_republication=False,
            replenish_work=False, replacement_original_allowed=False, automatic_bootstrap=False,
            automatic_reenrollment=False, application="NO-GO", core="NO-GO", recovery_action="NONE")

    def status(self):
        self._guard()
        return self._receipt()

    def commit_retained_reference(self):
        """Append the fixed functional transition once; never an original operation."""
        self._guard()
        _require(not self._applied)
        return self._append(self._transition)

    def inspect(self, local_context):
        """Compare retained reference history; never a service lookup or write retry."""
        self._guard()
        selected = self._after if self._applied else self._before
        result = lifecycle.inspect_anchor_acknowledgment(local_context, self._hold, selected)
        result["local_reference_retention"] = self._receipt()
        return result

    def _dispose(self):
        # Closing a fork-inherited descriptor must not explicitly unlock its parent.
        for field in ("_fd", "_directory"):
            descriptor = getattr(self, field, None)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, field, None)
        self._closed = True

    def close(self):
        if self._busy or self._thread is not threading.current_thread():
            raise AnchorJournalQuarantined("foreign or reentrant anchor journal close refused")
        if not self._closed:
            self._dispose()

    def __enter__(self):
        self._guard()
        return self

    def __exit__(self, *unused):
        self.close()
