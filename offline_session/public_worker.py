"""Bounded pipe transport for explicitly trusted Linux/macOS public workers.

This is not a sandbox or a global concurrency/resource limiter. On failure an
unreaped direct child's process group is killed before a bounded reap attempt.
Once the child has been reaped, its cached process-group identifier is not used:
descendants that already closed inherited pipes or escaped the group are outside
this cleanup guarantee. Process creation and kernel scheduling have no hard
wall-clock bound here. The leased observation path adds a parent-watching guard
and inherited lock references for one cooperative nonforking worker. The caller
must not independently reap these children or configure automatic SIGCHLD
reaping. Leases prevent another cooperating owner while a live holder remains;
they do not contain malicious workers or bound aggregate resource consumption.
"""

import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time


MAX_INPUT_BYTES = 65536
MAX_OUTPUT_BYTES = 4096
_REAP_GRACE_SECONDS = 1.0
_IO_CHUNK_BYTES = 4096
_OWNER_POLL_SECONDS = 0.05


class WorkerError(Exception):
    """Sanitized worker failure without executable paths or process output."""


def _remaining(deadline, owner_pid=None):
    if owner_pid is not None and os.getppid() != owner_pid:
        raise WorkerError("public worker owner is unavailable")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WorkerError("public worker deadline exceeded")
    return remaining


def _close(stream):
    if stream is not None:
        try:
            stream.close()
        except OSError:
            pass


def _cleanup(process, *, kill_group=True):
    """Reap the owned child without signaling a group after its known reap."""
    if process is None:
        return True
    _close(process.stdin)
    _close(process.stdout)
    if process.returncode is not None:
        return True
    # Under exclusive child-reaping ownership, this leader remains unreaped and
    # its process-group ID cannot have been reassigned. Escaped descendants are
    # not contained.
    try:
        if kill_group:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=_REAP_GRACE_SECONDS)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _validate(executable, request_bytes, timeout, max_input_bytes, max_output_bytes):
    if os.name != "posix" or sys.platform not in {"linux", "darwin"}:
        raise WorkerError("public workers require a supported POSIX host")
    if (type(timeout) not in (int, float) or not 0 < timeout <= 30
            or type(max_input_bytes) is not int or not 0 < max_input_bytes <= MAX_INPUT_BYTES
            or type(max_output_bytes) is not int or not 0 < max_output_bytes <= MAX_OUTPUT_BYTES
            or type(request_bytes) is not bytes or len(request_bytes) > max_input_bytes):
        raise WorkerError("invalid public worker bounds or request")
    try:
        path = Path(executable)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise WorkerError("an existing absolute public worker executable is required")
    except (OSError, TypeError, ValueError):
        raise WorkerError("invalid public worker executable") from None
    return path


def _run(command, request_bytes, *, timeout, max_output_bytes,
         pass_fds=(), start_new_session=True, owner_pid=None):
    """Internal transport: watched guards signal only their owned direct child.

    The outer guard has its own group; its nonforking worker stays in that group.
    The guard watches its actual parent relationship, not a kill(pid, 0) probe.
    Inherited leases remain held by a cooperative worker even if its guard dies.
    """

    process = None
    selection = None
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, close_fds=True,
            start_new_session=start_new_session, pass_fds=pass_fds,
        )
        _remaining(deadline, owner_pid)
        selection = selectors.DefaultSelector()
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        selection.register(process.stdout, selectors.EVENT_READ, "output")
        if request_bytes:
            selection.register(process.stdin, selectors.EVENT_WRITE, "input")
        else:
            process.stdin.close()
        offset = 0
        response = bytearray()
        while selection.get_map():
            interval = _remaining(deadline, owner_pid)
            if owner_pid is not None:
                interval = min(interval, _OWNER_POLL_SECONDS)
            for key, _ in selection.select(interval):
                _remaining(deadline, owner_pid)
                if key.data == "input":
                    try:
                        count = os.write(key.fd, request_bytes[offset:offset + _IO_CHUNK_BYTES])
                    except BlockingIOError:
                        continue
                    if count <= 0:
                        raise WorkerError("public worker input delivery failed")
                    offset += count
                    if offset == len(request_bytes):
                        selection.unregister(process.stdin)
                        process.stdin.close()
                else:
                    # Reading one sentinel byte detects overflow without an
                    # unbounded allocation or an output file on disk.
                    allowance = min(_IO_CHUNK_BYTES, max_output_bytes + 1 - len(response))
                    try:
                        chunk = os.read(key.fd, allowance)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selection.unregister(process.stdout)
                        process.stdout.close()
                    else:
                        response.extend(chunk)
                        if len(response) > max_output_bytes:
                            raise WorkerError("public worker exceeded its output bound")
        while True:
            interval = _remaining(deadline, owner_pid)
            if owner_pid is not None:
                interval = min(interval, _OWNER_POLL_SECONDS)
            try:
                status = process.wait(timeout=interval)
                break
            except subprocess.TimeoutExpired:
                if owner_pid is None:
                    raise
        if status != 0:
            raise WorkerError("public worker rejected the request")
        _remaining(deadline, owner_pid)
        return bytes(response)
    except BaseException as error:
        if not _cleanup(process, kill_group=start_new_session):
            raise WorkerError("public worker cleanup could not reap the child") from None
        if isinstance(error, (WorkerError, KeyboardInterrupt, SystemExit)):
            raise
        raise WorkerError("public worker failed") from None
    finally:
        if selection is not None:
            try:
                selection.close()
            except OSError:
                pass
        if process is not None:
            _close(process.stdin)
            _close(process.stdout)


def run_public_worker(executable, request_bytes, *, timeout, max_input_bytes,
                      max_output_bytes=MAX_OUTPUT_BYTES):
    """Legacy bounded transport without ownership leases or parent monitoring.

    The deadline covers pipe exchange and direct-child completion. Failure
    attempts bounded cleanup; descendants and uninterruptible children retain
    the existing limitations. This path acquires or inherits no store lock.
    """
    path = _validate(executable, request_bytes, timeout, max_input_bytes, max_output_bytes)
    return _run([str(path)], request_bytes, timeout=timeout, max_output_bytes=max_output_bytes)


def _lease_descriptors(descriptors):
    try:
        if (type(descriptors) is not tuple or len(descriptors) != 2
                or any(type(fd) is not int or fd < 3 for fd in descriptors)
                or len(set(descriptors)) != 2):
            raise WorkerError("two explicit ownership descriptors are required")
        identities = set()
        for descriptor in descriptors:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
                    or metadata.st_uid != os.geteuid()):
                raise WorkerError("invalid ownership descriptor")
            identities.add((metadata.st_dev, metadata.st_ino))
        if len(identities) != 2:
            raise WorkerError("distinct ownership files are required")
        return descriptors
    except (OSError, ValueError, TypeError):
        raise WorkerError("invalid ownership descriptors") from None


def _admission_descriptor(descriptor, ownership_descriptors):
    """Validate one additional private capability, not its actual enrollment."""
    try:
        if type(descriptor) is not int or descriptor < 3 or descriptor in ownership_descriptors:
            raise WorkerError("one distinct admission descriptor is required")
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
                or metadata.st_uid != os.geteuid()):
            raise WorkerError("invalid admission descriptor")
        identity = metadata.st_dev, metadata.st_ino
        if any(identity == (os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in ownership_descriptors):
            raise WorkerError("admission and ownership files must differ")
        return descriptor
    except (OSError, ValueError, TypeError):
        raise WorkerError("invalid admission descriptor") from None


def _guarded(executable, request_bytes, *, timeout, max_input_bytes,
             expected_executable_sha256_hex, ownership_descriptors,
             max_output_bytes, admission_descriptor=None):
    path = _validate(executable, request_bytes, timeout, max_input_bytes, max_output_bytes)
    leases = _lease_descriptors(ownership_descriptors)
    if admission_descriptor is not None:
        leases += (_admission_descriptor(admission_descriptor, leases),)
    if (type(expected_executable_sha256_hex) is not str or len(expected_executable_sha256_hex) != 64
            or any(item not in "0123456789abcdef" for item in expected_executable_sha256_hex)):
        raise WorkerError("an exact selected executable pin is required")
    guard = Path(__file__).with_name("worker_guard.py").resolve()
    interpreter = Path(sys.executable).resolve()
    command = [str(interpreter), "-B", str(guard), str(path), expected_executable_sha256_hex,
               str(os.getpid()), repr(float(timeout)), ",".join(str(fd) for fd in leases[:2]),
               "-" if admission_descriptor is None else str(admission_descriptor)]
    return _run(command, request_bytes, timeout=timeout, max_output_bytes=max_output_bytes,
                pass_fds=leases)


def run_guarded_public_worker(executable, request_bytes, *, timeout,
                              max_input_bytes, expected_executable_sha256_hex,
                              ownership_descriptors, max_output_bytes=MAX_OUTPUT_BYTES):
    """Pass already-held private ownership files to a guard and trusted worker.

    Only cooperating workers that retain these descriptors without unlocking,
    closing, forking or escaping the guard group are supported. These are lock
    capabilities, not database/checkpoint handles or a sandbox. Metadata checks
    do not prove that an arbitrary caller actually acquired the two locks.
    """
    return _guarded(executable, request_bytes, timeout=timeout, max_input_bytes=max_input_bytes,
        expected_executable_sha256_hex=expected_executable_sha256_hex,
        ownership_descriptors=ownership_descriptors, max_output_bytes=max_output_bytes)


def run_admitted_public_worker(executable, request_bytes, *, timeout,
                               max_input_bytes, expected_executable_sha256_hex,
                               ownership_descriptors, admission_descriptor,
                               max_output_bytes=MAX_OUTPUT_BYTES):
    """Retain a required shared admission lease as well as both owner leases."""
    leases = _lease_descriptors(ownership_descriptors)
    _admission_descriptor(admission_descriptor, leases)
    return _guarded(executable, request_bytes, timeout=timeout, max_input_bytes=max_input_bytes,
        expected_executable_sha256_hex=expected_executable_sha256_hex,
        ownership_descriptors=leases, max_output_bytes=max_output_bytes,
        admission_descriptor=admission_descriptor)
