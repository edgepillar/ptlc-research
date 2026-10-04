"""Synthetic store workers are sequencing oracles, not mathematical evidence."""

from pathlib import Path
import sys

from offline_session.observation_verifier import SubprocessObservation, _file_digest


STORE_ID = "22" * 32


def synthetic_verifier():
    # The interpreter entry is measured only to construct a local test profile.
    # Its protocol call must be patched in synthetic tests; it verifies no math.
    path = Path(sys.executable).resolve()
    return SubprocessObservation(path, expected_executable_sha256_hex=_file_digest(path))
