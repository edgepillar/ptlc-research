"""Capture one explicitly selected local public checker; no action authority.

The local owner must trust the executable, its build and its filesystem path.
Digest consistency does not authenticate source or sandbox an arbitrary program.
Public preparation input cannot select a program, environment or arguments.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

from offline_session.pr138 import CompatibilityError
from .__main__ import _Parser, _discard_shutdown_buffers, _object, _read_input, _refuse
from .plan import canonical
from .presignature import (
    MAX_CRYPTO_RESULT, RESULT_INSPECTION_SCHEMA,
    inspect_presignature_result, prepare_presignature,
)

MAX_EXECUTABLE = 128 * 1024 * 1024
MAX_STDERR = 16 * 1024
MAX_RESPONSE = 8192
PROCESS_SECONDS = 10
REAP_SECONDS = 1


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _selected_executable(value, expected):
    if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
            or type(expected) is not str or re.fullmatch("[0-9a-f]{64}", expected) is None):
        raise CompatibilityError("unsupported local checker selection")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise CompatibilityError("ambiguous local checker selection")
    for parent in path.parents:
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise CompatibilityError("indirect local checker path")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or not before.st_mode & 0o111 or before.st_mode & 0o022
            or not 0 < before.st_size <= MAX_EXECUTABLE):
        raise CompatibilityError("unsupported local checker file")
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if _identity(os.fstat(descriptor)) != _identity(before):
            raise CompatibilityError("changed local checker selection")
        total = 0
        while True:
            part = os.read(descriptor, min(65536, MAX_EXECUTABLE + 1 - total))
            if not part:
                break
            total += len(part)
            if total > MAX_EXECUTABLE:
                raise CompatibilityError("oversized local checker file")
            digest.update(part)
        if (total != before.st_size or _identity(os.fstat(descriptor)) != _identity(before)
                or _identity(path.lstat()) != _identity(before) or digest.hexdigest() != expected):
            raise CompatibilityError("changed local checker selection")
    finally:
        os.close(descriptor)
    # No binary is copied, adopted as evidence or authenticated by this read.
    # The owner must protect the path and every alias throughout execution.
    return path, _identity(before)


def _capture(path, request):
    """Drain both bounded pipes through EOF and observe the owned child exit."""
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": MAX_CRYPTO_RESULT, "stderr": MAX_STDERR}
    child = None
    with selectors.DefaultSelector() as selector:
        try:
            child = subprocess.Popen([str(path)], cwd=path.parent,
                env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True)
            for name in ("stdin", "stdout", "stderr"):
                pipe = getattr(child, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_WRITE if name == "stdin"
                                  else selectors.EVENT_READ, name)
            deadline = time.monotonic() + PROCESS_SECONDS
            offset = 0
            while selector.get_map() or child.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CompatibilityError("public checker deadline exceeded")
                for key, unused in selector.select(min(.05, remaining)):
                    pipe, name = key.fileobj, key.data
                    try:
                        if name == "stdin":
                            written = os.write(pipe.fileno(), request[offset:])
                            if written <= 0:
                                raise OSError("incomplete public request write")
                            offset += written
                            if offset == len(request):
                                selector.unregister(pipe)
                                pipe.close()
                        else:
                            part = os.read(pipe.fileno(), min(65536, limits[name] + 1 - len(streams[name])))
                            if not part:
                                selector.unregister(pipe)
                                pipe.close()
                            else:
                                streams[name].extend(part)
                                if len(streams[name]) > limits[name]:
                                    raise CompatibilityError("public checker stream limit exceeded")
                    except (BlockingIOError, InterruptedError):
                        continue
            if offset != len(request) or child.returncode != 0:
                raise CompatibilityError("public checker did not complete the request")
            return bytes(streams["stdout"]), bytes(streams["stderr"])
        finally:
            active_error = sys.exc_info()[0]
            cleanup_failed = False
            if child is not None:
                for name in ("stdin", "stdout", "stderr"):
                    pipe = getattr(child, name)
                    if pipe is not None:
                        try:
                            pipe.close()
                        except OSError:
                            cleanup_failed = True
                try:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=REAP_SECONDS)
                except (OSError, subprocess.TimeoutExpired):
                    cleanup_failed = True
            if cleanup_failed and active_error is None:
                raise CompatibilityError("owned public checker completion unknown")


def check_preparation(value, *, executable, executable_sha256):
    """Capture a selected process result, without authenticating its build."""
    prepared = prepare_presignature(value)
    request = canonical(prepared["crypto_request"])
    path, before = _selected_executable(executable, executable_sha256)
    stdout, stderr = _capture(path, request)
    if _selected_executable(executable, executable_sha256) != (path, before):
        raise CompatibilityError("changed local checker selection")
    associated = inspect_presignature_result(dict(schema=RESULT_INSPECTION_SCHEMA,
        preparation=value, result_json=stdout.decode("ascii")))
    return dict(schema="ptlc-nom-client-captured-public-check-v1",
        association=associated["association"], leg=associated["leg"],
        agreement_digest_hex=associated["agreement_digest_hex"],
        declared_entry_id_hex=associated["declared_entry_id_hex"],
        request_digest_hex=associated["request_digest_hex"],
        context_digest_hex=associated["context_digest_hex"],
        checker_result_json=stdout.decode("ascii"),
        result_digest_hex=associated["supplied_result_digest_hex"],
        backend_execution="COMPLETE_SELECTED_LOCAL_PROCESS",
        executable_selection="LOCAL_OWNER_SUPPLIED",
        executable_sha256=executable_sha256, executable_bytes=before[6],
        source_authentication="NOT_ESTABLISHED_BY_THIS_TOOL",
        filesystem_trust="LOCAL_OWNER_ASSUMPTION; NO ADVERSARIAL_REPLACEMENT_PROOF",
        process_exit=0, process_stdout_complete=True, process_stderr_complete=True,
        process_stderr_bytes=len(stderr), process_stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        process_timeout_seconds=PROCESS_SECONDS,
        scope="PUBLIC_MATHEMATICS_ONLY", verification="CAPTURE_AND_ASSOCIATION_ONLY",
        mathematical_result="SELECTED_EXECUTABLE_REPORTED_VALID",
        context_authentication="NOT_VERIFIED", chain_state="DECLARED_ONLY",
        outer_signature="NOT_VERIFIED", contract_execution="NOT_VERIFIED",
        signer_safety="NOT_ASSESSED", timing_policy="UNSELECTED",
        action_permission="NONE", application="NO-GO", core="NO-GO",
        independent_assessment="UNFILLED")


def main(argv=None, *, input_stream=None, output_stream=None, error_stream=None):
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--sha256", required=True)
    source = sys.stdin.buffer if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    errors = sys.stderr if error_stream is None else error_stream
    try:
        args = parser.parse_args(argv)
        value = json.loads(_read_input(source).decode("ascii"), object_pairs_hook=_object,
            parse_constant=lambda unused: (_ for _ in ()).throw(ValueError()))
        result = check_preparation(value, executable=args.executable, executable_sha256=args.sha256)
        encoded = canonical(result).decode("ascii") + "\n"
        if len(encoded) > MAX_RESPONSE:
            raise CompatibilityError("public capture response exceeds its boundary")
        written = output.write(encoded)
        if type(written) is not int or written != len(encoded):
            raise OSError("incomplete public output")
        output.flush()
        return 0
    except (CompatibilityError, UnicodeError, ValueError, TypeError, RecursionError,
            OSError, subprocess.SubprocessError):
        return _refuse(errors, "REFUSED: public checker result incomplete or invalid; no action authorized")


if __name__ == "__main__":
    status = main()
    if status:
        _discard_shutdown_buffers()
    raise SystemExit(status)
