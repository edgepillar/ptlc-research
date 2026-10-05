"""Bounded public original-read checker; no source or recovery adapter.

Repeated entry measurement is not atomic launch, provenance or a sandbox.
Independent selections and selected worker/runtime trust remain premises.
"""

import os
from pathlib import Path

from offline_session.observation_verifier import _file_digest
from offline_session.public_worker import WorkerError, run_public_worker
from qualification import original_read_response as response


class PublicOriginalResponseCheck:
    """Two historical signature checks with complete request/result binding."""

    def __init__(self, executable, *, expected_executable_sha256_hex, timeout=5):
        try:
            response._hex(expected_executable_sha256_hex, 32)
            path = Path(executable)
            if (not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK)
                    or type(timeout) not in (int, float) or not 0 < timeout <= 30
                    or _file_digest(path) != expected_executable_sha256_hex):
                raise response.OriginalResponseError("invalid selected public original response check")
            self._entry, self._digest, self._timeout = path, expected_executable_sha256_hex, timeout
        except (OSError, ValueError, TypeError):
            raise response.OriginalResponseError("invalid selected public original response check") from None

    def __call__(self, request):
        digest = response.request_digest(request)
        wire, expected = response._canonical(request), response.expected_result(digest)
        try:
            if _file_digest(self._entry) != self._digest:
                raise response.OriginalResponseError("selected public original response check changed")
            output = run_public_worker(str(self._entry), wire, timeout=self._timeout,
                max_input_bytes=response.MAX_WIRE_BYTES, max_output_bytes=512)
            if output not in (response._canonical(expected), response._canonical(expected) + b"\n"):
                raise response.OriginalResponseError("invalid complete original response result")
            return expected
        except (OSError, ValueError, TypeError, RecursionError, WorkerError):
            raise response.OriginalResponseError("public original response check unavailable") from None
