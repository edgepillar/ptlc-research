"""Internal public-worker guard; no signer, journal or record-writing handle.

The selected nonforking worker and this guard retain the owner's lock references.
Guard death cannot release a cooperative live worker's references. A worker that
closes/unlocks them or escapes the group violates the selected trust boundary.
Admitted work also retains one distinct shared-pool slot through worker exit.
"""

import os
from pathlib import Path
import selectors
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.observation_verifier import _file_digest
from offline_session.public_worker import (MAX_INPUT_BYTES, MAX_OUTPUT_BYTES,
    WorkerError, _OWNER_POLL_SECONDS, _admission_descriptor, _lease_descriptors, _remaining, _run, _validate)


def _input(deadline, owner_pid):
    value = bytearray()
    os.set_blocking(sys.stdin.fileno(), False)
    with selectors.DefaultSelector() as selection:
        selection.register(sys.stdin, selectors.EVENT_READ)
        while True:
            interval = min(_remaining(deadline, owner_pid), _OWNER_POLL_SECONDS)
            if not selection.select(interval):
                continue
            try:
                chunk = os.read(sys.stdin.fileno(), min(4096, MAX_INPUT_BYTES + 1 - len(value)))
            except BlockingIOError:
                continue
            if not chunk:
                return bytes(value)
            value.extend(chunk)
            if len(value) > MAX_INPUT_BYTES:
                raise WorkerError("guard input exceeds the public bound")


def main():
    try:
        if len(sys.argv) != 7:
            raise WorkerError("invalid guard arguments")
        entry, pin, raw_owner, raw_timeout, raw_leases, raw_admission = sys.argv[1:]
        owner_pid, timeout = int(raw_owner), float(raw_timeout)
        if str(owner_pid) != raw_owner or owner_pid <= 0:
            raise WorkerError("invalid guard owner")
        leases = tuple(int(value) for value in raw_leases.split(","))
        if ",".join(str(value) for value in leases) != raw_leases:
            raise WorkerError("invalid guard ownership encoding")
        _lease_descriptors(leases)
        if raw_admission != "-":
            admission = int(raw_admission)
            if str(admission) != raw_admission:
                raise WorkerError("invalid guard admission encoding")
            leases += (_admission_descriptor(admission, leases),)
        _validate(entry, b"", timeout, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        deadline = time.monotonic() + timeout
        _remaining(deadline, owner_pid)
        request = _input(deadline, owner_pid)
        if _file_digest(Path(entry)) != pin:
            raise WorkerError("selected guarded entry changed")
        remaining = _remaining(deadline, owner_pid)
        # The outer caller owns this guard's process group. The guard separately
        # owns/reaps this direct child and never signals its own shared group.
        response = _run([entry], request, timeout=remaining, max_output_bytes=MAX_OUTPUT_BYTES,
                        pass_fds=leases, start_new_session=False, owner_pid=owner_pid)
        _remaining(deadline, owner_pid)
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Never print arguments, selected paths, process identifiers or output.
        sys.stderr.write("public worker ownership unavailable\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
