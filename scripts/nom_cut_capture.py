"""Original stream capture for one explicitly trusted offline public worker.

This qualification transport replaces the adapter's runner in one single-thread
scenario only. It is not an application runner or hostile-process sandbox.
communicate retains complete observed streams in memory before checking size;
process creation, aggregate memory and escaped descendants are not contained.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess

from offline_session.public_worker import WorkerError


def sha(wire):
    return hashlib.sha256(wire).hexdigest()


def retain(path, wire):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(wire)
        stream.flush()
        os.fsync(stream.fileno())


class OriginalCapture:
    """No retries; preserve the request before spawn and the original reply."""

    def __init__(self, directory, executable, expected_pin):
        self.directory = Path(directory)
        self.executable = Path(executable)
        self.pin = expected_pin
        self.calls = []
        self.phase = "UNSELECTED"

    def run(self, executable, wire, *, timeout, max_input_bytes, max_output_bytes=4096):
        if (Path(executable) != self.executable or sha(self.executable.read_bytes()) != self.pin
                or type(wire) is not bytes or not 0 < len(wire) <= max_input_bytes <= 8192
                or timeout != 5 or max_output_bytes != 4096):
            raise WorkerError("invalid selected capture request")
        number = len(self.calls) + 1
        prefix = f"call-{number:03d}"
        retain(self.directory / (prefix + ".stdin"), wire)
        row = dict(number=number, phase=self.phase, request_hex=wire.hex(),
                   request_sha256=sha(wire), stdout_hex="", stderr_hex="",
                   exit_code=None, stream_completeness="NOT_ESTABLISHED")
        self.calls.append(row)
        process = None
        output = error = b""
        try:
            process = subprocess.Popen([str(self.executable)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, close_fds=True,
                start_new_session=True)
            try:
                output, error = process.communicate(wire, timeout=timeout)
                row["stream_completeness"] = "COMPLETE"
            except subprocess.TimeoutExpired:
                # The selected worker is nonforking. This direct-child cleanup
                # does not qualify arbitrary descendants or kernel scheduling.
                process.kill()
                output, error = process.communicate(timeout=1)
                row["stream_completeness"] = "COMPLETE_AFTER_TIMEOUT"
                raise WorkerError("selected public worker timed out") from None
            row["exit_code"] = process.returncode
            if len(output) > max_output_bytes or len(error) > 4096:
                raise WorkerError("selected worker stream exceeds the scenario boundary")
            if process.returncode != 0:
                raise WorkerError("selected public worker rejected the request")
            if sha(self.executable.read_bytes()) != self.pin:
                raise WorkerError("selected public executable changed")
            return output
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                try:
                    output, error = process.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    row["stream_completeness"] = "PARTIAL; CLEANUP UNRESOLVED"
            if process is not None:
                row["exit_code"] = process.returncode
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            row.update(stdout_hex=output.hex(), stderr_hex=error.hex(),
                       stdout_sha256=sha(output), stderr_sha256=sha(error))
            retain(self.directory / (prefix + ".stdout"), output)
            retain(self.directory / (prefix + ".stderr"), error)
            retain(self.directory / (prefix + ".receipt.json"),
                   json.dumps(row, sort_keys=True, separators=(",", ":")).encode("ascii"))
