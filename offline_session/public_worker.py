"""Bounded pipe transport for explicitly trusted Linux/macOS public workers.

This is not a sandbox or a global concurrency/resource limiter. On failure an
unreaped direct child's process group is killed before a bounded reap attempt.
Once the child has been reaped, its cached process-group identifier is not used:
descendants that already closed inherited pipes or escaped the group are outside
this cleanup guarantee. Process creation and kernel scheduling have no hard
wall-clock bound here. The caller must not independently reap these children or
configure automatic SIGCHLD reaping.
"""

import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time


MAX_INPUT_BYTES = 65536
MAX_OUTPUT_BYTES = 4096
_REAP_GRACE_SECONDS = 1.0
_IO_CHUNK_BYTES = 4096


class WorkerError(Exception):
    """Sanitized worker failure without executable paths or process output."""


def _remaining(deadline):
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


def _cleanup(process):
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
        os.killpg(process.pid, signal.SIGKILL)
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


def run_public_worker(executable, request_bytes, *, timeout, max_input_bytes,
                      max_output_bytes=MAX_OUTPUT_BYTES):
    """Deliver bounded input while collecting at most the output limit plus one.

    The one monotonic deadline covers pipe exchange and direct-child completion.
    Success requires complete input delivery, stdout EOF and a zero exit status.
    Cleanup requests a bounded additional reap wait; an uninterruptible process
    may remain unreaped and is reported as failure.
    """
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

    process = None
    selection = None
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            [str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, close_fds=True, start_new_session=True,
        )
        _remaining(deadline)
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
            for key, _ in selection.select(_remaining(deadline)):
                _remaining(deadline)
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
        if process.wait(timeout=_remaining(deadline)) != 0:
            raise WorkerError("public worker rejected the request")
        _remaining(deadline)
        return bytes(response)
    except BaseException as error:
        if not _cleanup(process):
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
