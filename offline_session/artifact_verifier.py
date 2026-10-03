"""Bounded subprocess adapter for an explicitly selected trusted public verifier.

This runs a locally built qualification executable, not a network service or
signing worker. Its result is a local trust boundary, never a peer credential.
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile

from .exchange import RESULT_SCHEMA, VerificationError, canonical, request_digest


class SubprocessVerifier:
    def __init__(self, executable, *, timeout=5):
        path = Path(executable)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise VerificationError("an existing absolute verifier executable is required")
        if type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise VerificationError("invalid verifier deadline")
        self._executable = str(path)
        self._timeout = timeout

    def __call__(self, request):
        wire = canonical(request)
        if len(wire) > 32768:
            raise VerificationError("public verification request exceeds its bound")
        try:
            # Disk-backed output prevents an unbounded pipe buffer in Python.
            # The executable remains trusted; this is not an OS resource sandbox.
            with tempfile.TemporaryFile() as output:
                process = subprocess.run(
                    [self._executable], input=wire, stdout=output, stderr=subprocess.DEVNULL,
                    timeout=self._timeout, check=False,
                )
                output.seek(0)
                response = output.read(4097)
            if process.returncode != 0 or len(response) > 4096:
                raise VerificationError("public verifier rejected or exceeded its output bound")
            result = json.loads(response.decode("ascii"))
            expected = {"schema": RESULT_SCHEMA, "request_digest_hex": request_digest(request), "valid": True}
            if (type(result) is not dict or result != expected or result.get("valid") is not True
                    or response not in (canonical(expected), canonical(expected) + b"\n")):
                raise VerificationError("public verifier returned an invalid bound result")
            return expected
        except (OSError, ValueError, RecursionError, subprocess.SubprocessError):
            raise VerificationError("public verifier failed") from None
