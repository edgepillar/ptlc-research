"""Qualification-only public root/response mathematics; no service or signer."""
import os
from pathlib import Path

from offline_session import nom_checkpoint_response as framing
from offline_session.observation_verifier import _file_digest
from offline_session.public_worker import WorkerError, run_public_worker


class PublicCheckpointResponseCheck:
    """Selected executable and remeasurement are premises, not atomic launch."""
    def __init__(self, executable, *, expected_executable_sha256_hex, timeout=5):
        try:
            framing.codec._hex(expected_executable_sha256_hex)
            path = Path(executable)
            if (not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK)
                or type(timeout) not in (int, float) or not 0 < timeout <= 30
                or _file_digest(path) != expected_executable_sha256_hex):
                raise framing.CheckpointResponseRefused("invalid selected public checkpoint check")
            self._entry, self._digest, self._timeout = path, expected_executable_sha256_hex, timeout
        except (OSError, ValueError, TypeError):
            raise framing.CheckpointResponseRefused("invalid selected public checkpoint check") from None

    def __call__(self, request):
        expected = framing.expected_result(framing.request_digest(request))
        wire = framing.codec._canonical(request)
        try:
            if _file_digest(self._entry) != self._digest:
                raise framing.CheckpointResponseRefused("selected public checkpoint check changed")
            result = run_public_worker(str(self._entry), wire, timeout=self._timeout,
                max_input_bytes=framing.MAX_WIRE_BYTES, max_output_bytes=512)
            if result not in (framing.codec._canonical(expected), framing.codec._canonical(expected)+b"\n"):
                raise framing.CheckpointResponseRefused("public checkpoint result does not bind complete request")
            return expected
        except (OSError, ValueError, TypeError, RecursionError, WorkerError):
            raise framing.CheckpointResponseRefused("public checkpoint signature check unavailable") from None
