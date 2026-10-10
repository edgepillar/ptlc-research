"""Bounded native command execution with retained private stdout/stderr.

Selected tools, environment, ancestors and host are trusted. These logs record
one observed execution; they do not attest producer identity or contain arbitrary
descendants. No command, output or private path is printed by this helper.
"""

import hashlib
import json
import os
import selectors
import subprocess
import time

from offline_session.public_worker import WorkerError, _cleanup, _close


MAX_STDOUT = 16 * 1024 * 1024
MAX_STDERR = 4 * 1024 * 1024


def private_create(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")


def run(command, *, environment, directory, evidence, label, timeout=240):
    if (type(command) is not list or not command or len(command) > 32
            or any(type(item) is not str or not item or len(item) > 8192 or "\0" in item for item in command)
            or not command[0].startswith("/")
            or type(environment) is not dict or type(label) is not str
            or label not in ("metadata-apple", "metadata-linux", "build")
            or type(timeout) not in (int, float) or not 0 < timeout <= 240):
        raise WorkerError("invalid selected native command")
    output, error = evidence / (label + ".stdout"), evidence / (label + ".stderr")
    process = selection = None
    started = time.monotonic()
    retained = bytearray()
    record = dict(label=label, argv=command, result="UNKNOWN", bytes={"stdout": 0, "stderr": 0},
                  complete={"stdout": False, "stderr": False})
    hashes = {name: hashlib.sha256() for name in ("stdout", "stderr")}
    try:
        with private_create(output) as out, private_create(error) as err:
            process = subprocess.Popen(command, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                       start_new_session=True, bufsize=0)
            selection = selectors.DefaultSelector()
            for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os_stream = stream.fileno()
                os.set_blocking(os_stream, False)
                selection.register(stream, selectors.EVENT_READ, name)
            while selection.get_map():
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise WorkerError("selected native deadline exceeded")
                for key, _ in selection.select(remaining):
                    name = key.data
                    try:
                        chunk = key.fileobj.read(65536)
                    except BlockingIOError:
                        continue
                    if chunk is None:
                        continue
                    if not chunk:
                        record["complete"][name] = True
                        selection.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    bound = MAX_STDOUT if name == "stdout" else MAX_STDERR
                    remaining_bytes = bound - record["bytes"][name]
                    accepted = chunk[:remaining_bytes]
                    (out if name == "stdout" else err).write(accepted)
                    record["bytes"][name] += len(accepted)
                    hashes[name].update(accepted)
                    if name == "stdout":
                        retained.extend(accepted)
                    if len(chunk) > remaining_bytes:
                        record["truncated_stream"] = name
                        raise WorkerError("selected native stream bound exceeded")
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise WorkerError("selected native deadline exceeded")
            record["exit_status"] = process.wait(timeout=remaining)
            if record["exit_status"] != 0:
                record["result"] = "FAILED"
                raise WorkerError("selected native command failed; private evidence retained")
            record["result"] = "RETURNED ZERO"
            return bytes(retained)
    except BaseException as failure:
        if not _cleanup(process):
            raise WorkerError("selected native cleanup failed; private evidence retained") from None
        if isinstance(failure, (WorkerError, KeyboardInterrupt, SystemExit)):
            raise
        raise WorkerError("selected native command interrupted; private evidence retained") from None
    finally:
        if selection is not None:
            selection.close()
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                _close(stream)
        record["sha256"] = {name: digest.hexdigest() for name, digest in hashes.items()}
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        # The exact private argv and original streams are never public evidence.
        descriptor = os.open(evidence / "commands.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "a", encoding="ascii") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
