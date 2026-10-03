"""Real process-death and stale-checkpoint tests with public synthetic state."""

import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from offline_session.journal import Conflict, Journal, JournalError, OwnershipError, Quarantined
from session_test_support import NONCE_TAG, OPERATION_ID, PUBLIC_OUTPUT, session_context


@unittest.skipUnless(os.name == "posix", "qualification requires POSIX file locks and process signals")
class SessionCrashTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ptlc-session-crash-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root = self.base / "state"
        checkpoint_directory = self.base / "checkpoints"
        checkpoint_directory.mkdir()
        self.anchor = checkpoint_directory / "head.json"
        self.terms, self.context = session_context()
        self._initialize()

    def _initialize(self):
        with Journal.open(self.root, self.anchor) as journal:
            journal.create_session(self.terms.session_id, self.terms.digest_hex)

    def _command(self, mode, *extra):
        actor = Path(__file__).with_name("session_crash_actor.py")
        return [sys.executable, "-B", str(actor), mode, str(self.root), str(self.anchor), *extra]

    def _probe(self, forbid_connect=False):
        extra = ("--forbid-connect",) if forbid_connect else ()
        return subprocess.run(
            self._command("probe", *extra), capture_output=True, text=True, timeout=10,
        )

    def _start(self, mode, *extra):
        child = subprocess.Popen(
            self._command(mode, *extra), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

        self.addCleanup(cleanup)
        return child

    def _wait_line(self, child, expected):
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=10), "child did not reach the bounded checkpoint")
        self.assertEqual(child.stdout.readline().strip(), expected, "child checkpoint mismatch")

    def test_sigkill_at_each_irreversible_boundary(self):
        self._kill_matrix(dynamic=False)

    def test_dynamic_nonce_round_sigkill_at_each_irreversible_boundary(self):
        self.terms, self.context = session_context(dynamic=True)
        self._kill_matrix(dynamic=True)

    def _kill_matrix(self, dynamic):
        cases = (
            ("before_db_commit", "RETIRED", False, 0),
            ("after_db_commit", "QUARANTINED", None, 0),
            ("after_anchor_replace", "OUTCOME_UNKNOWN", True, 0),
            ("after_anchor_commit", "OUTCOME_UNKNOWN", True, 0),
            ("after_consume", "OUTCOME_UNKNOWN", True, 0),
            ("after_callback", "OUTCOME_UNKNOWN", True, 1),
            ("after_output_commit", "OUTPUT_RECORDED", True, 1),
        )
        original_root, original_anchor = self.root, self.anchor
        for index, (checkpoint, status, exposed, calls) in enumerate(cases):
            with self.subTest(checkpoint=checkpoint):
                self.root = self.base / ("state-" + str(index))
                self.anchor = original_anchor.parent / ("head-" + str(index) + ".json")
                self._initialize()
                marker = self.base / ("calls-" + str(index))
                extra = ("--dynamic",) if dynamic else ()
                child = self._start("crash", "--checkpoint", checkpoint, "--marker", str(marker), *extra)
                self._wait_line(child, b"paused")
                child.kill()
                child.communicate(timeout=10)
                self.assertEqual(child.returncode, -signal.SIGKILL)
                self.assertEqual(len(marker.read_bytes()) if marker.exists() else 0, calls)
                if status == "QUARANTINED":
                    with self.assertRaises(Quarantined):
                        with Journal.open(self.root, self.anchor):
                            pass
                    continue
                with Journal.open(self.root, self.anchor) as journal:
                    self.assertEqual(journal.get_operation(self.terms.session_id, OPERATION_ID)["status"], status)
                    self.assertEqual(journal.get_session(self.terms.session_id)["possible_exposure"], exposed)
                    expected_round = self.context.as_dict().get("nonce_round_digest_hex")
                    self.assertEqual(journal.get_session(self.terms.session_id)["signing_rounds"]["zenon"], expected_round)
                    if status == "OUTPUT_RECORDED":
                        self.assertEqual(journal.replay(
                            self.terms.session_id, OPERATION_ID, expected_context=self.context,
                        ), PUBLIC_OUTPUT)
                    else:
                        invoked = []
                        with self.assertRaises(JournalError):
                            journal.produce_once(
                                self.terms.session_id, OPERATION_ID, expected_context=self.context,
                                callback=lambda: invoked.append(True) or PUBLIC_OUTPUT,
                            )
                        self.assertEqual(invoked, [])
                        with self.assertRaises(Conflict):
                            journal.reserve(self.terms.session_id, "63" * 32, self.context, "74" * 32)
                self.assertEqual(len(marker.read_bytes()) if marker.exists() else 0, calls)
        self.root, self.anchor = original_root, original_anchor

    def test_lock_precedes_state_read_and_survives_owner_death(self):
        child = self._start("hold")
        self._wait_line(child, b"held")
        lock = self.root / "journal.lock"
        original_inode = lock.stat().st_ino
        blocked = self._probe(forbid_connect=True)
        self.assertEqual(blocked.returncode, 20)
        self.assertEqual(blocked.stdout.strip(), "Busy")
        self.assertEqual(blocked.stderr, "")
        child.kill()
        child.communicate(timeout=10)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        opened = self._probe()
        self.assertEqual(opened.returncode, 0)
        self.assertEqual(opened.stdout.strip(), "opened")
        self.assertEqual(lock.stat().st_ino, original_inode, "lifetime lock file must not be replaced")

    def test_active_writer_preserves_exposure_for_the_next_process(self):
        with Journal.open(self.root, self.anchor) as journal:
            journal.reserve(self.terms.session_id, OPERATION_ID, self.context, NONCE_TAG)
            blocked = self._probe()
            self.assertEqual(blocked.stdout.strip(), "Busy")
            journal.produce_once(
                self.terms.session_id, OPERATION_ID, expected_context=self.context,
                callback=lambda: PUBLIC_OUTPUT,
            )
        with Journal.open(self.root, self.anchor) as journal:
            self.assertTrue(journal.get_session(self.terms.session_id)["possible_exposure"])
            self.assertEqual(journal.replay(
                self.terms.session_id, OPERATION_ID, expected_context=self.context,
            ), PUBLIC_OUTPUT)

    def test_forked_handle_cannot_operate_or_unlock_the_parent(self):
        manager = Journal.open(self.root, self.anchor)
        with manager as journal:
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                result = b"unsafe"
                try:
                    try:
                        journal.get_session(self.terms.session_id)
                    except OwnershipError:
                        try:
                            manager.__exit__(None, None, None)
                        except OwnershipError:
                            pass
                        result = b"safe"
                    os.write(write_fd, result)
                finally:
                    os.close(write_fd)
                    os._exit(0)
            os.close(write_fd)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(read_fd, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=10), "forked ownership check timed out")
                self.assertEqual(os.read(read_fd, 16), b"safe")
                blocked = self._probe()
                self.assertEqual(blocked.stdout.strip(), "Busy", "child close released the parent's lock")
                self.assertFalse(journal.get_session(self.terms.session_id)["possible_exposure"])
            finally:
                os.close(read_fd)
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)

    def test_foreign_thread_cannot_close_during_durable_consumption(self):
        armed = False
        failures, observations, invoked = [], [], []

        def hook(name):
            nonlocal armed
            if not armed or name != "after_anchor_commit":
                return
            armed = False

            def foreign_close():
                try:
                    journal.close()
                except BaseException as error:
                    failures.append(type(error))

            worker = threading.Thread(target=foreign_close, daemon=True)
            worker.start()
            worker.join(timeout=10)
            observations.append(worker.is_alive())
            observations.append(self._probe().stdout.strip())

        with Journal.open(self.root, self.anchor, hook=hook) as journal:
            journal.reserve(self.terms.session_id, OPERATION_ID, self.context, NONCE_TAG)
            armed = True
            output = journal.produce_once(
                self.terms.session_id, OPERATION_ID, expected_context=self.context,
                callback=lambda: invoked.append(True) or PUBLIC_OUTPUT,
            )
            self.assertEqual(output, PUBLIC_OUTPUT)
            self.assertEqual(failures, [OwnershipError])
            self.assertEqual(observations, [False, "Busy"])
            self.assertEqual(invoked, [True])

    def test_database_only_and_anchor_only_rollback_each_fail_closed(self):
        db = self.root / "journal.sqlite3"
        old_db, old_anchor = db.read_bytes(), self.anchor.read_bytes()
        with Journal.open(self.root, self.anchor) as journal:
            journal.reserve(self.terms.session_id, OPERATION_ID, self.context, NONCE_TAG)
            journal.produce_once(
                self.terms.session_id, OPERATION_ID, expected_context=self.context,
                callback=lambda: PUBLIC_OUTPUT,
            )
        new_db, new_anchor = db.read_bytes(), self.anchor.read_bytes()
        for database, anchor in ((old_db, new_anchor), (new_db, old_anchor)):
            with self.subTest(database_rollback=database == old_db):
                db.write_bytes(database)
                self.anchor.write_bytes(anchor)
                with self.assertRaises(Quarantined):
                    with Journal.open(self.root, self.anchor):
                        pass
        db.write_bytes(new_db)
        self.anchor.write_bytes(new_anchor)
        with Journal.open(self.root, self.anchor) as journal:
            self.assertTrue(journal.get_session(self.terms.session_id)["possible_exposure"])

    def test_matching_full_snapshot_rollback_is_an_explicit_detection_limit(self):
        db = self.root / "journal.sqlite3"
        old_db, old_anchor = db.read_bytes(), self.anchor.read_bytes()
        with Journal.open(self.root, self.anchor) as journal:
            journal.reserve(self.terms.session_id, OPERATION_ID, self.context, NONCE_TAG)
            journal.produce_once(
                self.terms.session_id, OPERATION_ID, expected_context=self.context,
                callback=lambda: PUBLIC_OUTPUT,
            )
        db.write_bytes(old_db)
        self.anchor.write_bytes(old_anchor)
        # An equally old matching checkpoint carries no outside history witness.
        # This counterexample prevents claiming hardware or remote anti-rollback.
        with Journal.open(self.root, self.anchor) as journal:
            self.assertFalse(journal.get_session(self.terms.session_id)["possible_exposure"])
            journal.reserve(self.terms.session_id, OPERATION_ID, self.context, NONCE_TAG)

    def test_valid_sqlite_payload_tampering_is_not_hidden_by_metadata(self):
        db = self.root / "journal.sqlite3"
        with sqlite3.connect(str(db)) as connection:
            state_text = connection.execute("SELECT state_json FROM checkpoint WHERE slot=1").fetchone()[0]
            state = json.loads(state_text)
            state["unexpected_public_field"] = True
            connection.execute("UPDATE checkpoint SET state_json=? WHERE slot=1", (json.dumps(state),))
        with self.assertRaises(Quarantined):
            with Journal.open(self.root, self.anchor):
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
