"""Synthetic store workers are sequencing oracles, not mathematical evidence."""

from pathlib import Path
import sys
import time

from offline_session.observation_store import StoreBusy
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.worker_pool import PublicWorkerPool


STORE_ID = "22" * 32
POOL_ID = "66" * 32


def synthetic_pool(base, *, slot_limit=2, directory=None):
    return PublicWorkerPool.open(Path(base) / "worker-pool" if directory is None else directory,
                                pool_id_hex=POOL_ID, slot_limit=slot_limit)


def synthetic_verifier():
    # The interpreter entry is measured only to construct a local test profile.
    # Its protocol call must be patched in synthetic tests; it verifies no math.
    path = Path(sys.executable).resolve()
    return SubprocessObservation(path, expected_executable_sha256_hex=_file_digest(path))


def wait_for_store_ownership(opener, *, timeout=10):
    """Bound a test fixture's positive handoff; production open stays immediate.

    A free shared slot does not mean both independent store locks are free.
    Only StoreBusy is a transient fixture condition. An unavailable lock still
    fails the control at the deadline, and other failures propagate unchanged.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            return opener()
        except StoreBusy:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("controlled store ownership did not become available") from None
            time.sleep(min(0.005, remaining))
