"""Qualification-only public worker selection; no application or source adapter.

Repeated file measurement is not atomic launch, provenance or a sandbox. The
selected worker verifies mathematics under the root carried in its request.
Independent root selection and runtime trust remain external premises.
"""

import os
from pathlib import Path

from offline_session.observation_verifier import _file_digest
from offline_session.public_worker import WorkerError, run_public_worker
from qualification import source_root_roles as root


class PublicRootCheck:
    """Bounded mathematical check with complete request/result byte binding."""

    def __init__(self, executable, *, expected_executable_sha256_hex, timeout=5):
        try:
            root._hex(expected_executable_sha256_hex, 32)
            path = Path(executable)
            if (not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK)
                    or type(timeout) not in (int, float) or not 0 < timeout <= 30
                    or _file_digest(path) != expected_executable_sha256_hex):
                raise root.RootStatementError("invalid selected public root check")
            self._entry, self._digest, self._timeout = path, expected_executable_sha256_hex, timeout
        except (OSError, ValueError, TypeError):
            raise root.RootStatementError("invalid selected public root check") from None

    def __call__(self, request):
        digest = root.request_digest(request)
        wire = root._canonical(request)
        expected = root.expected_result(digest)
        try:
            if _file_digest(self._entry) != self._digest:
                raise root.RootStatementError("selected public root check changed")
            response = run_public_worker(str(self._entry), wire, timeout=self._timeout,
                max_input_bytes=root.MAX_WIRE_BYTES, max_output_bytes=512)
            if response not in (root._canonical(expected), root._canonical(expected) + b"\n"):
                raise root.RootStatementError("invalid complete root result")
            return expected
        except (OSError, ValueError, TypeError, RecursionError, WorkerError):
            raise root.RootStatementError("public root check unavailable") from None
