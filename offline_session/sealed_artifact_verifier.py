"""Opt-in Linux snapshot execution for an explicitly trusted public ELF entry.

Seals bind the bytes measured here to the inherited descriptor launched here.
They do not authenticate the caller's pin, source, loader, environment or runtime
dependencies. This is not a sandbox, signer, persistent descriptor owner or a
replacement for the leased observation profiles. Existing consumers are exact.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

try:
    import fcntl
except ImportError:
    fcntl = None

from .exchange import RESULT_SCHEMA, VerificationError, canonical, request_digest
from .public_worker import WorkerError, _remaining, _run


_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_CHUNK_BYTES = 65536


def _platform():
    if (os.name != "posix" or sys.platform != "linux" or fcntl is None
            or not callable(getattr(os, "memfd_create", None))
            or any(type(getattr(os, name, None)) is not int for name in
                   ("MFD_CLOEXEC", "MFD_ALLOW_SEALING", "O_CLOEXEC", "O_NOFOLLOW"))
            or any(type(getattr(fcntl, name, None)) is not int for name in
                   ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW",
                    "F_SEAL_SHRINK", "F_SEAL_SEAL"))):
        raise VerificationError("sealed public execution requires supported Linux capabilities")


def _selection(executable, pin, timeout):
    if (type(executable) not in (str, type(Path()))
            or type(pin) is not str or re.fullmatch(r"[0-9a-f]{64}", pin) is None
            or type(timeout) not in (int, float) or not 0 < timeout <= 30):
        raise VerificationError("invalid sealed public verifier selection")
    path = Path(executable)
    if not path.is_absolute() or "\x00" in str(path):
        raise VerificationError("invalid sealed public verifier selection")
    return path


def _close_fd(fd):
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass


@contextmanager
def _snapshot(path, pin, deadline):
    """Own a fresh anonymous snapshot; never expose an unsealed descriptor."""
    source = snapshot = None
    try:
        _remaining(deadline)
        source = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(source)
        if (not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111
                or not 0 < metadata.st_size <= _MAX_EXECUTABLE_BYTES):
            raise VerificationError("selected public verifier snapshot is unavailable")
        chunk = os.read(source, _CHUNK_BYTES)
        if not chunk.startswith(b"\x7fELF"):
            raise VerificationError("sealed public execution requires a direct ELF entry")
        snapshot = os.memfd_create("ptlc-public-verifier", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        # Honor the host's memfd execution policy; do not override it or retry
        # with an execution-enabling flag when permissions or launch refuse.
        os.fchmod(snapshot, 0o500)
        consumed = 0
        while chunk:
            _remaining(deadline)
            consumed += len(chunk)
            if consumed > metadata.st_size or consumed > _MAX_EXECUTABLE_BYTES:
                raise VerificationError("selected public verifier snapshot is unavailable")
            offset = 0
            while offset < len(chunk):
                _remaining(deadline)
                count = os.write(snapshot, chunk[offset:])
                if count <= 0:
                    raise VerificationError("selected public verifier snapshot is unavailable")
                offset += count
            chunk = os.read(source, _CHUNK_BYTES)
        if consumed != metadata.st_size or os.fstat(snapshot).st_size != consumed:
            raise VerificationError("selected public verifier snapshot is unavailable")
        _close_fd(source)
        source = None
        required = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, required)
        if fcntl.fcntl(snapshot, fcntl.F_GET_SEALS) & required != required:
            raise VerificationError("selected public verifier snapshot is unavailable")
        os.lseek(snapshot, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        measured = 0
        while True:
            _remaining(deadline)
            chunk = os.read(snapshot, _CHUNK_BYTES)
            if not chunk:
                break
            measured += len(chunk)
            if measured > consumed:
                raise VerificationError("selected public verifier snapshot is unavailable")
            digest.update(chunk)
        if measured != consumed or digest.hexdigest() != pin:
            raise VerificationError("selected public verifier snapshot is unavailable")
        os.lseek(snapshot, 0, os.SEEK_SET)
        _remaining(deadline)
        yield snapshot
    finally:
        _close_fd(source)
        _close_fd(snapshot)


class SealedSubprocessVerifier:
    """One measured snapshot per call, with no persistent file descriptor.

    Constructor selection is syntactic and capability-only. Each call opens,
    bounds, seals and hashes the entry before launch. ELF magic is an entry
    policy, not binary validation or proof of a complete runtime closure.
    """

    def __init__(self, executable, *, expected_executable_sha256_hex, timeout=5):
        _platform()
        self._executable = str(_selection(executable, expected_executable_sha256_hex, timeout))
        self._expected_executable_sha256_hex = expected_executable_sha256_hex
        self._timeout = timeout

    def __call__(self, request):
        _platform()
        path = _selection(self._executable, self._expected_executable_sha256_hex, self._timeout)
        try:
            wire = canonical(request)
        except (TypeError, ValueError, RecursionError):
            raise VerificationError("invalid public verification request") from None
        if len(wire) > 32768:
            raise VerificationError("public verification request exceeds its bound")
        deadline = time.monotonic() + self._timeout
        try:
            with _snapshot(path, self._expected_executable_sha256_hex, deadline) as descriptor:
                response = _run(["/proc/self/fd/" + str(descriptor)], wire,
                    timeout=_remaining(deadline), max_output_bytes=4096,
                    pass_fds=(descriptor,))
            result = json.loads(response.decode("ascii"))
            expected = {"schema": RESULT_SCHEMA, "request_digest_hex": request_digest(request), "valid": True}
            if (type(result) is not dict or result != expected or result.get("valid") is not True
                    or response not in (canonical(expected), canonical(expected) + b"\n")):
                raise VerificationError("public verifier returned an invalid bound result")
            return expected
        except (OSError, ValueError, RecursionError, WorkerError):
            raise VerificationError("sealed public verifier failed") from None
