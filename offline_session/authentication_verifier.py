"""Bounded adapter to the separately selected public BIP340 auth qualifier."""

import json
import math
import os
from pathlib import Path

from .authentication import (
    AuthenticationError, MAX_WIRE_BYTES, RESULT_SCHEMA, _canonical, request_digest,
)
from .public_worker import WorkerError, run_public_worker


class SubprocessAuthentication:
    def __init__(self, executable, *, timeout=5):
        path = Path(executable)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise AuthenticationError("an existing absolute authentication executable is required")
        if type(timeout) not in (int, float) or not 0 < timeout <= 30 or not math.isfinite(timeout):
            raise AuthenticationError("invalid authentication verifier deadline")
        self._executable = str(path)
        self._timeout = timeout

    def __call__(self, request):
        digest = request_digest(request)
        wire = _canonical(request)
        if len(wire) > MAX_WIRE_BYTES:
            raise AuthenticationError("authentication request exceeds its byte boundary")
        expected = {"schema": RESULT_SCHEMA, "request_digest_hex": digest, "valid": True}
        try:
            response = run_public_worker(self._executable, wire, timeout=self._timeout,
                                         max_input_bytes=MAX_WIRE_BYTES)
            if response not in (_canonical(expected), _canonical(expected) + b"\n"):
                raise AuthenticationError("invalid bound authentication result")
            return json.loads(response)
        except (OSError, ValueError, RecursionError, WorkerError):
            raise AuthenticationError("public authentication verifier failed") from None
