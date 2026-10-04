"""Explicitly pinned public enrollment signature worker on Linux/macOS.

The reused bounded entry-file measurement and pipe runner are not a sandbox,
atomic measured launch, provenance check or enrollment resource policy. Trusted
runtime/host assumptions and escaped-descendant limitations remain unchanged.
"""

import os
from pathlib import Path

from . import enrollment_authentication as signature
from .observation_verifier import _file_digest
from .public_worker import WorkerError, run_public_worker


class SubprocessEnrollmentSignature:
    """Repeated entry-file pinning, bounded exchange and exact result binding."""

    def __init__(self, executable, *, expected_executable_sha256_hex, timeout=5):
        try:
            signature._hex(expected_executable_sha256_hex, 32)
            path = Path(executable)
            if (not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK)
                    or type(timeout) not in (int, float) or not 0 < timeout <= 30
                    or _file_digest(path) != expected_executable_sha256_hex):
                raise signature.EnrollmentSignatureError("invalid selected enrollment signature verifier")
            self._executable = path
            self._digest = expected_executable_sha256_hex
            self._timeout = timeout
        except (OSError, ValueError, TypeError):
            raise signature.EnrollmentSignatureError("invalid selected enrollment signature verifier") from None

    def __call__(self, request):
        digest = signature.request_digest(request)
        wire = signature._canonical(request)
        expected = {"schema": signature.RESULT_SCHEMA, "request_digest_hex": digest, "signature_valid": True}
        try:
            if _file_digest(self._executable) != self._digest:
                raise signature.EnrollmentSignatureError("selected enrollment signature verifier changed")
            response = run_public_worker(str(self._executable), wire, timeout=self._timeout,
                max_input_bytes=signature.MAX_WIRE_BYTES, max_output_bytes=signature.MAX_RESULT_BYTES)
            if response not in (signature._canonical(expected), signature._canonical(expected) + b"\n"):
                raise signature.EnrollmentSignatureError("invalid bound enrollment signature result")
            return expected
        except (OSError, ValueError, TypeError, RecursionError, WorkerError):
            raise signature.EnrollmentSignatureError("public enrollment signature verifier failed") from None
