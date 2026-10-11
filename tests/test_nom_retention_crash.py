"""Native POSIX process death, owner lifetime and torn-record evidence."""

import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest

from offline_session.nom_retention import RetentionBusy, RetentionQuarantined
from nom_retention_support import MOMENTA, ROOT, open_store, original, wire


class NoMRetentionCrashTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.path = self.root / "evidence.log"

    def seed(self):
        with open_store(self.path) as store:
            store.retain_original("short", original("short"))
            store.retain_observation("previous", wire(MOMENTA["baseline"]))
        return self.path.read_bytes()

    def actor(self, operation, point="unused", path=None):
        process = subprocess.Popen([sys.executable, "-B", "tests/nom_retention_actor.py",
                                   str(path or self.path), operation, point], cwd=ROOT,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)
        self.addCleanup(cleanup)
        return process

    def line(self, process):
        readable, unused, unused = select.select([process.stdout], [], [], 10)
        self.assertTrue(readable, "synthetic actor did not reach selected cut")
        return process.stdout.readline().decode("ascii").strip()

    def kill_at(self, operation, point, path=None):
        process = self.actor(operation, point, path)
        self.assertEqual(self.line(process), "CUT " + point)
        process.kill()
        output, errors = process.communicate(timeout=10)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual((output, errors), (b"", b""))

    def test_creation_death_keeps_empty_or_complete_init_without_repair(self):
        empty = ("create-file", "append-before-write")
        complete = ("append-first-write", "append-before-fsync", "append-after-fsync", "create-directory-synced", "append-before-ack")
        for number, point in enumerate(empty + complete):
            path = self.root / ("create-" + str(number) + ".log")
            self.kill_at("create", point, path)
            before = path.read_bytes()
            if point in empty:
                self.assertEqual(before, b"")
                with self.assertRaises(RetentionQuarantined):
                    open_store(path)
            else:
                with open_store(path) as reopened:
                    self.assertEqual(reopened.status()["sequence"], 1)
                    self.assertEqual(reopened.status()["power_loss"], "UNQUALIFIED")
            self.assertEqual(path.read_bytes(), before)

    def test_observation_death_before_write_retains_previous_and_after_write_retains_both(self):
        for point in ("append-before-write", "append-first-write", "append-before-fsync", "append-after-fsync", "append-before-ack"):
            if self.path.exists():
                self.path.unlink()
            before = self.seed()
            self.kill_at("observation", point)
            with open_store(self.path) as reopened:
                self.assertEqual(reopened.original("short"), original("short"))
                self.assertEqual(reopened.observation("previous")["wire"], wire(MOMENTA["baseline"]))
                if point == "append-before-write":
                    self.assertEqual(self.path.read_bytes(), before)
                    self.assertEqual(reopened.status()["observation_ids"], ["previous"])
                    self.assertFalse(reopened.status()["disclosure_possible"])
                else:
                    self.assertEqual(reopened.status()["observation_ids"], ["previous", "candidate"])
                    self.assertTrue(reopened.status()["disclosure_possible"])
                    self.assertEqual(reopened.status()["recovery_action"], "NONE")

    def test_large_record_death_after_first_chunk_keeps_torn_bytes_and_quarantines(self):
        before = self.seed()
        self.kill_at("large", "append-first-write")
        torn = self.path.read_bytes()
        self.assertTrue(torn.startswith(before))
        self.assertEqual(len(torn) - len(before), 65536)
        with self.assertRaises(RetentionQuarantined):
            open_store(self.path)
        self.assertEqual(self.path.read_bytes(), torn)

    def test_original_death_after_fsync_keeps_exact_bytes_and_free_local_replay(self):
        self.seed()
        self.kill_at("original", "append-after-fsync")
        with open_store(self.path) as reopened:
            self.assertEqual(reopened.original("long"), original("long"))
            before = reopened.status()
            reopened.retain_original("long", original("long"))
            self.assertEqual(reopened.status(), before)

    def test_disclosure_death_after_fsync_remains_monotone_after_unknown_reply(self):
        self.seed()
        self.kill_at("disclosure", "append-after-fsync")
        with open_store(self.path) as reopened:
            self.assertTrue(reopened.status()["disclosure_possible"])
            reopened.retain_observation("missing", b"", previous_id="previous", disclosure_possible=False)
        with open_store(self.path) as reopened:
            self.assertTrue(reopened.status()["disclosure_possible"])

    def test_native_owner_exclusion_survives_inherited_close_and_releases_after_death(self):
        self.seed()
        owner = open_store(self.path)
        try:
            child = os.fork()
            if child == 0:
                try:
                    try:
                        owner.status()
                    except RetentionQuarantined:
                        owner.close()
                        os._exit(0)
                    os._exit(2)
                except BaseException:
                    os._exit(3)
            unused, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            with self.assertRaises(RetentionBusy):
                open_store(self.path)
        finally:
            owner.close()
        process = self.actor("hold")
        self.assertEqual(self.line(process), "HELD")
        with self.assertRaises(RetentionBusy):
            open_store(self.path)
        process.kill()
        output, errors = process.communicate(timeout=10)
        self.assertEqual((process.returncode, output, errors), (-signal.SIGKILL, b"", b""))
        with open_store(self.path) as reopened:
            self.assertEqual(reopened.status()["observation_ids"], ["previous"])

    def test_real_native_file_size_limit_returns_unknown_and_preserves_torn_history(self):
        before = self.seed()
        process = self.actor("write-limit")
        output, errors = process.communicate(timeout=10)
        self.assertEqual((process.returncode, output, errors), (0, b"WRITE_OUTCOME_UNKNOWN\n", b""))
        torn = self.path.read_bytes()
        self.assertTrue(torn.startswith(before))
        self.assertEqual(len(torn) - len(before), 100)
        with self.assertRaises(RetentionQuarantined):
            open_store(self.path)
        self.assertEqual(self.path.read_bytes(), torn)


if __name__ == "__main__":
    unittest.main()
