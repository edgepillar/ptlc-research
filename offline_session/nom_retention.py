"""Bounded POSIX retention of public synthetic NoM evidence, never authority.

The selected host, filesystem, fsync implementation and complete pathname are
trusted. A hash chain detects accidental changes, not a coherent rewrite,
rollback or copied owner. No observer, signer or recovery journal is connected.
"""

import copy
import hashlib
import json
import os
import re
import stat
import threading

try:
    import fcntl
except ImportError:
    fcntl = None

from . import nom_momentum as momentum
from . import nom_recovery as recovery


PROFILE = "ptlc-nom-public-retention-v1"
MAX_BINDING_BYTES = 32768
MAX_RECORD_BYTES = 2 * momentum.MAX_WIRE_BYTES + 128 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 128
MAX_OBSERVATIONS = 64
ZERO = "00" * 32


class RetentionRefused(ValueError):
    """An input or finite retention allowance was refused before writing."""


class RetentionBusy(RetentionRefused):
    """Another cooperating owner holds the selected file."""


class RetentionQuarantined(RetentionRefused):
    """Continuity or owned-handle conditions cannot be established."""


class RetentionOutcomeUnknown(RuntimeError):
    """A write has no conclusive acknowledgement; close and inspect separately."""


def _require(condition):
    if not condition:
        raise RetentionRefused("public retention input or allowance refused")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result)
        result[key] = value
    return result


def _hex(value, maximum):
    _require(type(value) is str and len(value) <= 2 * maximum and len(value) % 2 == 0
             and re.fullmatch("[0-9a-f]*", value) is not None)
    return bytes.fromhex(value)


def _identifier(value):
    _require(type(value) is str and re.fullmatch("[a-z][a-z0-9_-]{0,63}", value) is not None)


def _binding(terms, anchor, inclusions):
    try:
        terms = recovery.validate_terms(terms)
        momentum.decimal(terms["chain_id"], 64, positive=True)
        momentum.context(anchor)
        momentum._inclusions(inclusions)
        value = {"schema": PROFILE, "core_commit": momentum.CORE_COMMIT,
                 "momentum_profile": momentum.PROFILE, "terms": terms,
                 "selected_anchor_claim": anchor, "retained_inclusions": inclusions,
                 "limits": {"log_bytes": MAX_LOG_BYTES, "record_bytes": MAX_RECORD_BYTES,
                            "events": MAX_EVENTS, "observations": MAX_OBSERVATIONS}}
        wire = _canonical(value)
        _require(len(wire) <= MAX_BINDING_BYTES)
        return copy.deepcopy(value), wire
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise RetentionRefused("complete fixed public selection refused") from None


def _inspect(wire, binding):
    selection = {"chain_id": binding["terms"]["chain_id"],
                 "selected_anchor_claim": binding["selected_anchor_claim"],
                 "required_inclusions": binding["retained_inclusions"]}
    try:
        result = momentum.parse_branch_wire(wire, **selection)
    except momentum.MomentumRefused as error:
        result = momentum.inspect_branch(None, **selection)
        result["reason"] = str(error)
        return None, result
    # The frozen bounded parser has already refused duplicate keys, nonfinite
    # values, excessive depth and non-ASCII input. Preserve the original wire.
    return json.loads(wire.decode("ascii")), result


def _analysis(wire, previous_wire, binding):
    candidate, inspection = _inspect(wire, binding)
    plan = None
    if previous_wire is not None:
        previous, unused = _inspect(previous_wire, binding)
        plan = momentum.compare_candidates(previous, candidate,
            chain_id=binding["terms"]["chain_id"], selected_anchor_claim=binding["selected_anchor_claim"],
            retained_inclusions=binding["retained_inclusions"])
    return {"inspection": inspection, "comparison": plan,
            "revalidate_funding_before_recovery": True, "revalidate_live_entry_before_recovery": True,
            "recovery_action": "NONE", "source_authority": "UNFILLED",
            "application": "NO-GO", "core": "NO-GO"}


class NomEvidenceRetention:
    """One cooperating owner of an append-only, bounded public evidence file.

    A receipt follows the selected file fsync, and creation also fsyncs the
    directory. This is local process-restart qualification, not power-loss or
    anti-rollback proof. Retention neither authenticates a supplied chain nor
    verifies the original signature. The original is a synthetic claim envelope,
    not a signed Zenon account block or a broadcastable transaction.
    """

    @classmethod
    def open(cls, path, terms, *, selected_anchor_claim, retained_inclusions):
        instance = cls.__new__(cls)
        instance._fd = instance._directory = None
        instance._closed = instance._poisoned = instance._busy = False
        instance._pid, instance._thread = os.getpid(), threading.current_thread()
        try:
            instance._binding, instance._binding_wire = _binding(terms, selected_anchor_claim, retained_inclusions)
            instance._selection_digest = hashlib.sha3_256(b"ptlc-nom-retention-selection-v1\0" + instance._binding_wire).hexdigest()
            _require(fcntl is not None and os.name == "posix")
            parent, instance._name = os.path.split(os.fspath(path))
            _require(instance._name not in ("", ".", ".."))
            instance._directory = os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(instance._directory)
            _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
            created = False
            try:
                instance._fd = os.open(instance._name, os.O_RDWR | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL,
                                       0o600, dir_fd=instance._directory)
                created = True
            except FileExistsError:
                instance._fd = os.open(instance._name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=instance._directory)
            try:
                fcntl.flock(instance._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RetentionBusy("public retention file already has an owner") from None
            instance._state = {"initialized": False, "originals": {}, "observations": {}, "disclosure_possible": False}
            instance._sequence, instance._head, instance._data = 0, ZERO, b""
            instance._file_boundary()
            if created:
                instance._cut("create-file")
                instance._append({"kind": "init", "binding_hex": instance._binding_wire.hex()}, sync_directory=True)
            else:
                instance._load()
                # A complete record can survive process death before its first
                # sync. Reopen syncs the validated image before any local ack;
                # this does not authenticate that image or its earlier history.
                instance._cut("reopen-before-fsync")
                os.fsync(instance._fd)
                os.fsync(instance._directory)
                instance._cut("reopen-after-fsync")
            return instance
        except (RetentionRefused, RetentionOutcomeUnknown):
            instance._dispose()
            raise
        except (OSError, ValueError, TypeError, RecursionError, OverflowError):
            instance._dispose()
            raise RetentionQuarantined("public retention file could not be opened") from None
        except BaseException:
            instance._dispose()
            raise

    def _cut(self, label):
        """Test subclass death/fault cuts; no application callback is accepted."""

    def _file_boundary(self):
        info = os.fstat(self._fd)
        entry = os.stat(self._name, dir_fd=self._directory, follow_symlinks=False)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_LOG_BYTES
                 and (info.st_dev, info.st_ino) == (entry.st_dev, entry.st_ino))

    def _read(self):
        self._file_boundary()
        os.lseek(self._fd, 0, os.SEEK_SET)
        chunks, total = [], 0
        while True:
            part = os.read(self._fd, min(65536, MAX_LOG_BYTES + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
            _require(total <= MAX_LOG_BYTES)
        return b"".join(chunks)

    def _guard(self):
        if (self._closed or self._poisoned or self._busy or self._pid != os.getpid()
                or self._thread is not threading.current_thread()):
            raise RetentionQuarantined("public retention owner is unavailable")
        try:
            _require(self._read() == self._data)
        except (RetentionRefused, OSError):
            self._poisoned = True
            raise RetentionQuarantined("public retention continuity changed") from None

    def _load(self):
        try:
            data = self._read()
            _require(bool(data) and data.endswith(b"\n"))
            lines = data.split(b"\n")[:-1]
            _require(len(lines) <= MAX_EVENTS)
            for line in lines:
                _require(0 < len(line) <= MAX_RECORD_BYTES)
                value = json.loads(line.decode("ascii"), object_pairs_hook=_pairs,
                                   parse_constant=lambda unused: _require(False))
                _require(type(value) is dict and set(value) == {"schema", "sequence", "previous_hash_hex", "event", "hash_hex"}
                         and value["schema"] == "ptlc-nom-retention-record-v1"
                         and type(value["sequence"]) is int and value["sequence"] == self._sequence + 1
                         and value["previous_hash_hex"] == self._head and _canonical(value) == line)
                unhashed = {key: item for key, item in value.items() if key != "hash_hex"}
                _require(self._record_hash(unhashed) == value["hash_hex"])
                self._state = self._apply(value["event"], value["sequence"], value["hash_hex"])
                self._head, self._sequence = value["hash_hex"], value["sequence"]
            _require(self._state["initialized"])
            self._data = data
        except (RetentionRefused, OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
            raise RetentionQuarantined("public retention history refused without repair") from None

    @staticmethod
    def _record_hash(value):
        return hashlib.sha3_256(b"ptlc-nom-retention-record-v1\0" + _canonical(value)).hexdigest()

    def _apply(self, event, sequence, record_hash):
        _require(type(event) is dict)
        state = copy.deepcopy(self._state)
        if not state["initialized"]:
            _require(event == {"kind": "init", "binding_hex": self._binding_wire.hex()})
            state["initialized"] = True
            return state
        kind = event.get("kind")
        if kind == "original":
            _require(set(event) == {"kind", "leg", "wire_hex"} and event["leg"] in ("long", "short")
                     and event["leg"] not in state["originals"])
            wire = _hex(event["wire_hex"], recovery.MAX_WIRE)
            try:
                recovery.claim_signature(self._binding["terms"], event["leg"], wire)
            except recovery.RecoveryError:
                raise RetentionRefused("synthetic original envelope refused") from None
            state["originals"][event["leg"]] = {"wire": wire, "sequence": sequence, "record_hash_hex": record_hash,
                "synthetic_original_digest_hex": recovery.synthetic_transaction_hash(wire)}
        elif kind == "observation":
            _require(set(event) == {"kind", "id", "previous_id", "wire_hex", "disclosure_possible", "analysis"})
            _identifier(event["id"])
            _require(event["id"] not in state["observations"] and len(state["observations"]) < MAX_OBSERVATIONS
                     and type(event["disclosure_possible"]) is bool)
            previous = None
            if event["previous_id"] is not None:
                _identifier(event["previous_id"])
                _require(event["previous_id"] in state["observations"])
                previous = state["observations"][event["previous_id"]]["wire"]
            wire = _hex(event["wire_hex"], momentum.MAX_WIRE_BYTES)
            _require(_canonical(event["analysis"]) == _canonical(_analysis(wire, previous, self._binding)))
            state["observations"][event["id"]] = {"wire": wire, "previous_id": event["previous_id"],
                "disclosure_possible": event["disclosure_possible"], "analysis": copy.deepcopy(event["analysis"]),
                "sequence": sequence, "record_hash_hex": record_hash}
            state["disclosure_possible"] |= event["disclosure_possible"]
        elif kind == "possible-disclosure":
            _require(event == {"kind": "possible-disclosure"} and not state["disclosure_possible"])
            state["disclosure_possible"] = True
        else:
            raise RetentionRefused("public retention event refused")
        return state

    def _append(self, event, *, sync_directory=False):
        _require(self._sequence < MAX_EVENTS)
        value = {"schema": "ptlc-nom-retention-record-v1", "sequence": self._sequence + 1,
                 "previous_hash_hex": self._head, "event": event}
        value["hash_hex"] = self._record_hash(value)
        wire = _canonical(value) + b"\n"
        _require(len(wire) - 1 <= MAX_RECORD_BYTES and len(self._data) + len(wire) <= MAX_LOG_BYTES)
        state = self._apply(event, value["sequence"], value["hash_hex"])
        self._busy = True
        try:
            self._cut("append-before-write")
            os.lseek(self._fd, 0, os.SEEK_END)
            offset = 0
            while offset < len(wire):
                count = os.write(self._fd, wire[offset:offset + 65536])
                if count <= 0:
                    raise OSError("public retention write made no progress")
                offset += count
                if offset == count:
                    self._cut("append-first-write")
            self._cut("append-before-fsync")
            os.fsync(self._fd)
            self._cut("append-after-fsync")
            if sync_directory:
                os.fsync(self._directory)
                self._cut("create-directory-synced")
            self._data += wire
            self._state, self._sequence, self._head = state, value["sequence"], value["hash_hex"]
            self._cut("append-before-ack")
        except Exception:
            self._poisoned = True
            raise RetentionOutcomeUnknown("public retention write outcome is unknown") from None
        except BaseException:
            self._poisoned = True
            raise
        finally:
            self._busy = False
        return self._ack(value)

    def _ack(self, value):
        return {"schema": "ptlc-nom-retention-ack-v1", "selection_digest_hex": self._selection_digest,
                "sequence": value["sequence"], "record_hash_hex": value["record_hash_hex"] if "record_hash_hex" in value else value["hash_hex"],
                "local_retention": "SELECTED_FSYNC_ACKNOWLEDGED", "power_loss": "UNQUALIFIED",
                "rollback_or_clone": "UNPROTECTED", "source_authority": "UNFILLED",
                "recovery_action": "NONE", "application": "NO-GO", "core": "NO-GO"}

    def retain_original(self, leg, wire):
        self._guard()
        _require(type(leg) is str and leg in ("long", "short") and type(wire) is bytes
                 and 0 < len(wire) <= recovery.MAX_WIRE)
        old = self._state["originals"].get(leg)
        if old is not None:
            _require(old["wire"] == wire)
            return self._ack(old)
        return self._append({"kind": "original", "leg": leg, "wire_hex": wire.hex()})

    def retain_observation(self, observation_id, wire, *, previous_id=None, disclosure_possible=False):
        self._guard()
        _identifier(observation_id)
        _require(type(wire) is bytes and len(wire) <= momentum.MAX_WIRE_BYTES and type(disclosure_possible) is bool)
        if previous_id is not None:
            _identifier(previous_id)
            _require(previous_id in self._state["observations"])
        old = self._state["observations"].get(observation_id)
        if old is not None:
            _require(old["wire"] == wire and old["previous_id"] == previous_id
                     and old["disclosure_possible"] == disclosure_possible)
            return self._ack(old)
        previous = None if previous_id is None else self._state["observations"][previous_id]["wire"]
        return self._append({"kind": "observation", "id": observation_id, "wire_hex": wire.hex(),
            "previous_id": previous_id, "disclosure_possible": disclosure_possible,
            "analysis": _analysis(wire, previous, self._binding)})

    def note_possible_disclosure(self):
        self._guard()
        if self._state["disclosure_possible"]:
            return self.status()
        return self._append({"kind": "possible-disclosure"})

    def original(self, leg):
        self._guard()
        _require(type(leg) is str and leg in self._state["originals"])
        return self._state["originals"][leg]["wire"]

    def observation(self, observation_id):
        self._guard()
        _identifier(observation_id)
        _require(observation_id in self._state["observations"])
        return copy.deepcopy(self._state["observations"][observation_id])

    def status(self):
        self._guard()
        return {"profile": PROFILE, "selection_digest_hex": self._selection_digest, "sequence": self._sequence,
                "head_hex": self._head, "originals": {leg: row["synthetic_original_digest_hex"] for leg, row in self._state["originals"].items()},
                "observation_ids": list(self._state["observations"]), "disclosure_possible": self._state["disclosure_possible"],
                "source_authority": "UNFILLED", "accepted_branch": "NONE", "recovery_action": "NONE",
                "power_loss": "UNQUALIFIED", "rollback_or_clone": "UNPROTECTED", "application": "NO-GO", "core": "NO-GO"}

    def _dispose(self):
        # Closing an inherited descriptor must not unlock the parent's flock.
        for name in ("_fd", "_directory"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, None)
        self._closed = True

    def close(self):
        if self._busy or self._thread is not threading.current_thread():
            raise RetentionQuarantined("foreign or reentrant close of the public retention owner")
        if not self._closed:
            self._dispose()

    def __enter__(self):
        self._guard()
        return self

    def __exit__(self, *unused):
        self.close()
