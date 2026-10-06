"""Test-only creation, cancellation and ownership; callback flags are forged.

The separate actual-worker qualifier replays these selected native cases.
No current source selection, hostile-path defense or antirollback is supplied.
"""

import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.qualify_original_snapshot_prefix_response import counter_query
from original_snapshot_vectors import OUTPUT, scenario
from original_witness_store_actor import callback_control, named_packet
import original_witness_store as witness


CREATE_CUTS = ("create-file-opened", "create-file-closed", "create-connected",
    "create-locked", "create-binding-table", "create-witness-table",
    "create-bound", "create-before-commit", "create-after-commit")
RETAIN_CUTS = ("retain-locked", "retain-loaded", "retain-compared",
    "retain-written", "retain-before-commit", "retain-after-commit")


class OriginalWitnessLifecycleTests(unittest.TestCase):
    check = staticmethod(callback_control)
    actor_mode = "flags"
    actor_context = {}

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-witness-lifecycle-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)/"witness.sqlite3"
        self.packets = {name: named_packet(name) for name in ("pending", "completed", "revoked_pending", "replaced_completed")}

    def open(self, path=None, binding=None, check=None, cls=None):
        return (cls or witness.OfflineOriginalWitnessStore)(str(path or self.path),
            binding or self.packets["pending"][0], verifier=check or self.check)

    def populated(self, name="pending", path=None):
        store = self.open(path)
        self.addCleanup(lambda: None if store._closed else store.close())
        store.retain(*self.packets[name])
        return store

    def assert_disposed(self, store):
        self.assertTrue(store._closed)
        self.assertFalse(store._busy)
        for command in (store.close, store.__enter__, store.inspect_retained,
                lambda: store.retain(*self.packets["completed"])):
            with self.assertRaises(witness.WitnessRefused):
                command()
        if store._db is not None:
            with self.assertRaises(sqlite3.ProgrammingError):
                store._db.execute("SELECT 1")

    def assert_creation_state(self, path, committed, *, native_recovery=False):
        calls = []
        def never(packet):
            calls.append(packet)
            raise AssertionError("constructor used a synthetic verifier")
        if committed:
            with self.open(path, check=never) as store:
                self.assertIsNone(store.inspect_retained())
                self.assertEqual(store._db.execute("SELECT count(*) FROM binding").fetchone(), (1,))
        else:
            before = path.read_bytes()
            with self.assertRaises(witness.WitnessRefused):
                self.open(path, check=never)
            if native_recovery:
                # A killed writer can leave a hot rollback journal. Native
                # recovery may change file bytes; it must not finish our DDL.
                connection = sqlite3.connect(str(path), isolation_level=None)
                try:
                    self.assertEqual(connection.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall(), [])
                finally:
                    connection.close()
            else:
                self.assertEqual(path.read_bytes(), before)
        self.assertEqual(calls, [])

    def interrupted_creation(self, point, exception):
        path = self.path.with_name(point+".sqlite3")
        captured, descriptors = [], []
        selected_open = os.open
        def descriptor(*args, **kwargs):
            value = selected_open(*args, **kwargs)
            descriptors.append(value)
            return value
        class Interrupted(witness.OfflineOriginalWitnessStore):
            def _cut(self, label):
                if label == point:
                    captured.append(self)
                    raise exception("synthetic constructor interruption")
        expected = witness.WitnessOutcomeUnknown if issubclass(exception, Exception) else exception
        with patch.object(witness.os, "open", side_effect=descriptor):
            with self.assertRaises(expected) as error:
                self.open(path, cls=Interrupted)
        if expected is witness.WitnessOutcomeUnknown:
            self.assertEqual(str(error.exception), "synthetic witness command has no conclusive result")
        self.assertEqual(len(captured), 1)
        self.assert_disposed(captured[0])
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])
        self.assertTrue(path.is_file())
        self.assert_creation_state(path, point == "create-after-commit")

    def actor(self, path, point):
        process = subprocess.Popen([sys.executable, "-B", "tests/original_witness_lifecycle_actor.py",
            str(path), point, self.actor_mode], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def clean():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)
        self.addCleanup(clean)
        process.stdin.write(json.dumps(self.actor_context)+"\n")
        process.stdin.flush()
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(ready.select(15), "bounded synthetic constructor response unavailable")
        self.assertEqual(process.stdout.readline().strip(), "paused")
        return process

    def test_new_owned_file_is_empty_completely_bound_and_never_verified_on_open(self):
        calls, cuts = [], []
        class Recorded(witness.OfflineOriginalWitnessStore):
            def _cut(self, label):
                cuts.append(label)
        with self.open(check=lambda value: calls.append(value), cls=Recorded) as store:
            self.assertIsNone(store.inspect_retained())
            self.assertEqual(store._db.execute("SELECT root,original FROM binding").fetchone(), store._binding)
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode) & 0o077, 0)
        self.assertEqual(cuts[:9], list(CREATE_CUTS))
        self.assertEqual(calls, [])
        self.assert_creation_state(self.path, True)

    def test_constructor_fault_at_each_selected_cut_is_unknown_disposed_and_not_repaired(self):
        for point in CREATE_CUTS:
            with self.subTest(point=point):
                self.interrupted_creation(point, RuntimeError)

    def test_constructor_keyboard_interrupt_at_each_cut_propagates_closes_and_preserves_binding_state(self):
        for point in CREATE_CUTS:
            with self.subTest(point=point):
                self.interrupted_creation(point, KeyboardInterrupt)

    def test_constructor_system_exit_before_and_after_commit_propagates_without_a_result(self):
        for point in ("create-bound", "create-after-commit"):
            with self.subTest(point=point):
                self.interrupted_creation(point, SystemExit)

    def test_constructor_cuts_cannot_reenter_close_inspection_retention_or_context_entry(self):
        commands, selected = [], self.packets["completed"]
        case = self
        class Reentrant(witness.OfflineOriginalWitnessStore):
            def _cut(self, label):
                if label not in CREATE_CUTS:
                    return
                for command in (self.close, self.__enter__, self.inspect_retained, lambda: self.retain(*selected)):
                    with case.assertRaises(witness.WitnessRefused):
                        command()
                    commands.append(label)
        with self.open(cls=Reentrant) as store:
            self.assertIsNone(store.inspect_retained())
        self.assertEqual(len(commands), 36)

    def test_real_constructor_process_death_at_nine_cuts_recovers_only_committed_empty_binding(self):
        for point in CREATE_CUTS:
            with self.subTest(point=point):
                path = self.path.with_name(point+".sqlite3")
                process = self.actor(path, point)
                process.kill()
                output, errors = process.communicate(timeout=10)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual((output, errors), ("", ""))
                self.assert_creation_state(path, point == "create-after-commit", native_recovery=True)

    def test_native_creation_writer_excludes_second_opener_without_automatic_initialization(self):
        process = self.actor(self.path, "create-before-commit")
        with self.assertRaises(witness.WitnessOutcomeUnknown):
            self.open()
        process.stdin.write("release\n")
        process.stdin.flush()
        output, errors = process.communicate(timeout=15)
        self.assertEqual((process.returncode, output.strip(), errors), (0, "empty", ""))
        self.assert_creation_state(self.path, True)

    def test_uncommitted_created_file_refuses_other_opener_without_deleting_creator_file(self):
        process = self.actor(self.path, "create-file-closed")
        before = self.path.read_bytes()
        with self.assertRaises(witness.WitnessRefused):
            self.open()
        self.assertEqual(self.path.read_bytes(), before)
        process.stdin.write("release\n")
        process.stdin.flush()
        output, errors = process.communicate(timeout=15)
        self.assertEqual((process.returncode, output.strip(), errors), (0, "empty", ""))

    def test_committed_partial_schema_missing_binding_and_wrong_blob_shapes_refuse_without_repair(self):
        root, original = self.packets["pending"][0]._root.canonical_bytes, self.packets["pending"][0]._original.canonical_bytes
        for index, (tables, row) in enumerate(((1, None), (2, None), (2, (root, b"x")),
                (2, ("synthetic-text", original)), (2, (root, original+b"x")))):
            with self.subTest(index=index):
                path = self.path.with_name("partial-"+str(index)+".sqlite3")
                connection = sqlite3.connect(str(path), isolation_level=None)
                try:
                    for statement in witness._DDL[:tables]:
                        connection.execute(statement)
                    if row is not None:
                        connection.execute("INSERT INTO binding VALUES(1,?,?)", row)
                finally:
                    connection.close()
                self.assert_creation_state(path, False)

    def test_nonregular_and_direct_symlink_paths_refuse_before_sqlite_or_verifier_use(self):
        directory = self.path.with_name("directory")
        directory.mkdir()
        fifo = self.path.with_name("synthetic-fifo")
        os.mkfifo(str(fifo))
        dangling = self.path.with_name("dangling")
        dangling.symlink_to(self.path)
        for path in (directory, fifo, dangling):
            with self.subTest(path=path.name), patch.object(witness.sqlite3, "connect", side_effect=AssertionError("unexpected SQLite open")):
                with self.assertRaises(witness.WitnessRefused):
                    self.open(path, check=lambda packet: self.fail("unexpected verifier"))
        self.assertTrue(fifo.exists())
        self.assertFalse(self.path.exists())

    def test_missing_owned_parent_is_sanitized_unknown_without_creation_or_callbacks(self):
        missing = self.path.with_name("missing")/"witness.sqlite3"
        with self.assertRaisesRegex(witness.WitnessOutcomeUnknown, "^synthetic witness command has no conclusive result$"):
            self.open(missing, check=lambda packet: self.fail("unexpected verifier"))
        self.assertFalse(missing.exists())

    def test_other_complete_root_proposal_and_profile_binding_cannot_erase_completed_owner(self):
        store = self.populated("completed")
        before = store.inspect_retained()
        queries = [self.packets["replaced_completed"][0]]
        fixture = json.loads(OUTPUT.read_text("ascii"))
        for name in ("same_id_other_proposal", "same_id_other_historical_profile"):
            with scenario(fixture["counterclaim_vectors"][name]["actual_scenario"]) as actual:
                queries.append(counter_query(actual, name)[0])
        for query in queries:
            with self.assertRaises(witness.WitnessRefused):
                self.open(binding=query, check=lambda packet: self.fail("unexpected verifier"))
            self.assertEqual(store.inspect_retained(), before)

    def test_real_inherited_process_refuses_every_owned_command_before_database_or_worker_use(self):
        store = self.populated()
        before = store.inspect_retained()
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            class ForbiddenDatabase:
                def __getattribute__(self, unused):
                    raise AssertionError("inherited SQLite access")
            # Keep the inherited connection alive without operating or
            # finalizing it. The child exits without Python cleanup.
            inherited_connection = store._db
            store._db = ForbiddenDatabase()
            store._verifier = lambda packet: (_ for _ in ()).throw(AssertionError("inherited worker access"))
            try:
                count = 0
                for command in (store.close, store.__enter__, store.inspect_retained,
                        lambda: store.retain(*self.packets["completed"])):
                    try:
                        command()
                    except witness.WitnessRefused:
                        count += 1
                    else:
                        os._exit(21)
                os.write(write_fd, str(count).encode("ascii"))
                os._exit(0)
            except BaseException:
                os._exit(22)
        os.close(write_fd)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(read_fd, selectors.EVENT_READ)
                self.assertTrue(ready.select(10), "bounded inherited-owner response unavailable")
            self.assertEqual(os.read(read_fd, 8), b"4")
            waited, status = os.waitpid(child, 0)
            self.assertEqual(waited, child)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
        finally:
            os.close(read_fd)
            try:
                waited, unused = os.waitpid(child, os.WNOHANG)
                if waited == 0:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
            except ChildProcessError:
                pass
        self.assertEqual(store.inspect_retained(), before)

    def test_retention_keyboard_interrupt_before_commit_preserves_pending_and_after_commit_preserves_completion(self):
        for point in RETAIN_CUTS:
            with self.subTest(point=point):
                path = self.path.with_name(point+".sqlite3")
                store = self.populated(path=path)
                def interrupt(label):
                    if label == point:
                        raise KeyboardInterrupt("synthetic cancellation")
                with patch.object(store, "_cut", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
                    store.retain(*self.packets["completed"])
                self.assert_disposed(store)
                with self.open(path) as reopened:
                    result = reopened.inspect_retained()
                self.assertEqual((result.version, result.observation), (2, "completed") if point.endswith("after-commit") else (1, "pending"))

    def test_verifier_cancellation_before_or_after_one_selected_result_never_retries_or_replaces_witness(self):
        for after_check in (False, True):
            with self.subTest(after_check=after_check):
                path = self.path.with_name("worker-"+str(after_check)+".sqlite3")
                store = self.populated(path=path)
                calls = []
                def interrupt(packet):
                    calls.append(packet)
                    if after_check:
                        self.check(packet)
                    raise KeyboardInterrupt("synthetic worker cancellation")
                with patch.object(store, "_verifier", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
                    store.retain(*self.packets["completed"])
                self.assertEqual(len(calls), 1)
                self.assert_disposed(store)
                with self.open(path) as reopened:
                    self.assertEqual((reopened.inspect_retained().version, reopened.inspect_retained().observation), (1, "pending"))

    def test_inspection_cancellation_at_lock_before_and_after_commit_preserves_completed_history(self):
        for point in ("inspect-locked", "inspect-before-commit", "inspect-after-commit"):
            with self.subTest(point=point):
                path = self.path.with_name(point+".sqlite3")
                store = self.populated("completed", path)
                def interrupt(label):
                    if label == point:
                        raise KeyboardInterrupt
                with patch.object(store, "_cut", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
                    store.inspect_retained()
                self.assert_disposed(store)
                with self.open(path) as reopened:
                    self.assertEqual(reopened.inspect_retained().observation, "completed")

    def test_reopening_cancellation_at_three_transaction_cuts_disposes_without_losing_completion(self):
        store = self.populated("completed")
        store.close()
        for point in ("open-locked", "open-before-commit", "open-after-commit"):
            captured = []
            class Interrupted(witness.OfflineOriginalWitnessStore):
                def _cut(self, label):
                    if label == point:
                        captured.append(self)
                        raise KeyboardInterrupt
            with self.subTest(point=point), self.assertRaises(KeyboardInterrupt):
                self.open(cls=Interrupted)
            self.assert_disposed(captured[0])
            with self.open() as reopened:
                self.assertEqual(reopened.inspect_retained().observation, "completed")

    def test_explicit_close_never_reuses_connection_or_completed_scalar_as_authority(self):
        store = self.populated("completed")
        retained = store.inspect_retained()
        store.close()
        self.assert_disposed(store)
        with self.open() as reopened:
            self.assertEqual(reopened.inspect_retained(), retained)
            with self.assertRaises(witness.WitnessRefused):
                reopened.retain(*self.packets["pending"])

    def test_recreated_owned_path_loses_completed_knowledge_and_accepts_other_first_future(self):
        store = self.populated("completed")
        completed = store.inspect_retained()
        store.close()
        saved = self.path.with_name("saved-completed.sqlite3")
        shutil.copyfile(self.path, saved)
        self.path.unlink()
        with self.open() as recreated:
            self.assertIsNone(recreated.inspect_retained())
            other = recreated.retain(*self.packets["revoked_pending"])
        self.assertEqual(other.version, 1)
        self.assertNotEqual(other.query_digest_hex, completed.query_digest_hex)
        with self.open(saved) as historical:
            self.assertEqual(historical.inspect_retained(), completed)

    def test_empty_and_non_database_existing_files_are_not_auto_initialized_or_deleted(self):
        for index, data in enumerate((b"", b"synthetic-non-database")):
            path = self.path.with_name("existing-"+str(index)+".sqlite3")
            path.write_bytes(data)
            with self.subTest(index=index), self.assertRaises((witness.WitnessRefused, witness.WitnessOutcomeUnknown)):
                self.open(path, check=lambda packet: self.fail("unexpected verifier"))
            self.assertEqual(path.read_bytes(), data)
