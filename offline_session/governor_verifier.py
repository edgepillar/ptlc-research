"""Pinned public issuer/owner worker, using the existing bounded pipe runner.

Measurement is neither atomic launch nor provenance. This is not a sandbox,
current-authority service or admission policy; runtime/host assumptions remain.
"""

import os
from pathlib import Path

from . import governor_authentication as signature
from .observation_verifier import _file_digest
from .public_worker import WorkerError, run_public_worker


class SubprocessGovernorSignature:
    """Repeated entry-file pinning and exact complete request/result binding."""

    def __init__(self, executable, *, expected_executable_sha256_hex, timeout=5):
        try:
            signature._hex(expected_executable_sha256_hex, 32)
            path = Path(executable)
            if (not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK)
                    or type(timeout) not in (int, float) or not 0 < timeout <= 30
                    or _file_digest(path) != expected_executable_sha256_hex):
                raise signature.GovernorSignatureError("invalid selected governor signature verifier")
            self._executable, self._digest, self._timeout = path, expected_executable_sha256_hex, timeout
        except (OSError, ValueError, TypeError):
            raise signature.GovernorSignatureError("invalid selected governor signature verifier") from None

    def __call__(self, request):
        digest = signature.request_digest(request)
        wire = signature._canonical(request)
        expected = signature.result_for_digest(digest)
        try:
            if _file_digest(self._executable) != self._digest:
                raise signature.GovernorSignatureError("selected governor signature verifier changed")
            response = run_public_worker(str(self._executable), wire, timeout=self._timeout,
                max_input_bytes=signature.MAX_WIRE_BYTES, max_output_bytes=signature.MAX_RESULT_BYTES)
            if response not in (signature._canonical(expected), signature._canonical(expected) + b"\n"):
                raise signature.GovernorSignatureError("invalid bound governor signature result")
            return expected
        except (OSError, ValueError, TypeError, RecursionError, WorkerError):
            raise signature.GovernorSignatureError("public governor signature verifier failed") from None
