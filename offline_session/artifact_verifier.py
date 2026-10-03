"""Bounded subprocess adapter for an explicitly selected trusted public verifier.

This runs a locally built qualification executable, not a network service or
signing worker. Its result is a local trust boundary, never a peer credential.
"""

import json
import os
from pathlib import Path

from .exchange import RESULT_SCHEMA, VerificationError, canonical, request_digest
from .public_worker import WorkerError, run_public_worker


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
            response = run_public_worker(
                self._executable, wire, timeout=self._timeout, max_input_bytes=32768,
            )
            result = json.loads(response.decode("ascii"))
            expected = {"schema": RESULT_SCHEMA, "request_digest_hex": request_digest(request), "valid": True}
            if (type(result) is not dict or result != expected or result.get("valid") is not True
                    or response not in (canonical(expected), canonical(expected) + b"\n")):
                raise VerificationError("public verifier returned an invalid bound result")
            return expected
        except (OSError, ValueError, RecursionError, WorkerError):
            raise VerificationError("public verifier failed") from None
