"""Qualification-only bounded public command worker; no policy source adapter.

Repeated entry measurement is not atomic launch, provenance or a sandbox.
Independent expectations and selected worker/runtime trust remain premises.
"""

import os
from pathlib import Path

from offline_session.observation_verifier import _file_digest
from offline_session.public_worker import WorkerError, run_public_worker
from qualification import source_admin_command as admin


class PublicAdminCheck:
    """Two historical signature checks with complete request/result binding."""

    def __init__(self, executable, *, expected_executable_sha256_hex, timeout=5):
        try:
            admin._hex(expected_executable_sha256_hex, 32)
            path = Path(executable)
            if (not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK)
                    or type(timeout) not in (int, float) or not 0 < timeout <= 30
                    or _file_digest(path) != expected_executable_sha256_hex):
                raise admin.AdminCommandError("invalid selected public administrator check")
            self._entry, self._digest, self._timeout = path, expected_executable_sha256_hex, timeout
        except (OSError, ValueError, TypeError):
            raise admin.AdminCommandError("invalid selected public administrator check") from None

    def __call__(self, request):
        digest = admin.request_digest(request)
        wire, expected = admin._canonical(request), admin.expected_result(digest)
        try:
            if _file_digest(self._entry) != self._digest:
                raise admin.AdminCommandError("selected public administrator check changed")
            response = run_public_worker(str(self._entry), wire, timeout=self._timeout,
                max_input_bytes=admin.MAX_WIRE_BYTES, max_output_bytes=512)
            if response not in (admin._canonical(expected), admin._canonical(expected) + b"\n"):
                raise admin.AdminCommandError("invalid complete administrator result")
            return expected
        except (OSError, ValueError, TypeError, RecursionError, WorkerError):
            raise admin.AdminCommandError("public administrator check unavailable") from None
