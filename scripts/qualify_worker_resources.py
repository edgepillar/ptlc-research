"""Actual public observation under explicit Linux CPU/address-space limits.

The runtime policy is an experiment outside persistent store admission. No
signer, source authority, chain access, quota reset or funded guarantee is added.
"""

import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from offline_session import observation_evidence as evidence
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.public_worker import WorkerError
from offline_session.journal import Journal
from offline_session.worker_resources import WorkerResourceLimits, _supported
from completion_test_support import final_signatures
from exchange_test_support import prepare
from observation_store_test_support import synthetic_pool


class RealResourceTests(unittest.TestCase):
    verifier = None
    observer = None

    @classmethod
    def setUpClass(cls):
        cls.signature = final_signatures()[0]

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-resource-actual-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.journal = Journal.open(self.base / "source", self.base / "head.json")
        self.addCleanup(self.journal.close)
        self.session = prepare(self.journal, verifier=self.verifier)
        self.journal.release_exchange_zenon(self.session)
        self.state = self.journal.get_exchange(self.session)
        self.before = (copy.deepcopy(self.journal._state), self.journal._sequence,
                       (self.base / "source/journal.sqlite3").read_bytes(), (self.base / "head.json").read_bytes())
        self.pool = synthetic_pool(self.base, slot_limit=1)
        self.owners = []
        for name in ("a.lock", "b.lock"):
            fd = os.open(self.base / name, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.owners.append(fd)
            self.addCleanup(os.close, fd)
        self.policy = WorkerResourceLimits(2, 128 * 1024 * 1024)

    def observe(self, signature, policy):
        with self.pool.acquire() as lease:
            wire = self.observer.observe_limited(self.state, signature,
                ownership_descriptors=tuple(self.owners), admission_descriptor=lease.fileno(), resource_limits=policy)
        result = evidence.parse_statement(self.state, signature, wire,
            expected_verifier_profile_digest_hex=self.observer.profile_digest_hex)
        self.assertEqual((self.journal._state, self.journal._sequence,
            (self.base / "source/journal.sqlite3").read_bytes(), (self.base / "head.json").read_bytes()), self.before)
        return result.outcome

    def test_actual_positive_under_explicit_limits_preserves_journal_and_math_profile(self):
        profile = self.observer.profile_digest_hex
        self.assertEqual(self.observe(self.signature, self.policy), "verified")
        self.assertEqual(self.observer.profile_digest_hex, profile)

    def test_actual_invalid_completion_under_explicit_limits_is_a_normal_negative(self):
        self.assertEqual(self.observe(bytes(64), self.policy), "rejected")

    def test_missing_limits_is_unknown_without_starting_or_falling_back(self):
        with patch("offline_session.public_worker.subprocess.Popen") as spawn, \
                patch("offline_session.observation_verifier.run_admitted_public_worker") as fallback:
            self.assertEqual(self.observe(self.signature, None), "unknown")
            spawn.assert_not_called()
            fallback.assert_not_called()


def main():
    parser = argparse.ArgumentParser(description="Qualify explicit Linux resources with selected public workers")
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--observation", required=True)
    options = parser.parse_args()
    try:
        _supported(WorkerResourceLimits(2, 128 * 1024 * 1024))
    except WorkerError:
        parser.error("resource qualification requires an unprivileged supported Linux host")
    RealResourceTests.verifier = SubprocessVerifier(Path(options.verifier).resolve())
    path = Path(options.observation).resolve()
    RealResourceTests.observer = SubprocessObservation(path, expected_executable_sha256_hex=_file_digest(path))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealResourceTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
