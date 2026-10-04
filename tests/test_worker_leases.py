"""Lease metadata/transport checks and native controlled owner/guard death.

Synthetic workers retain descriptors and do not fork or escape. They establish
ownership and cleanup behavior only; separate Rust qualifiers establish math.
"""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from offline_session import observation_evidence as evidence
from offline_session.observation_store import ObservationStore, StoreBusy
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.public_worker import WorkerError, run_admitted_public_worker, run_guarded_public_worker
from completion_test_support import final_signatures, released_bob
from observation_store_test_support import STORE_ID, synthetic_pool


@unittest.skipUnless(os.name == "posix", "lease qualification requires local POSIX locks and signals")
class WorkerLeaseTransportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-lease-transport-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.leases = []
        for name in ("a.lock", "b.lock"):
            descriptor = os.open(self.base / name, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.leases.append(descriptor)
            self.addCleanup(os.close, descriptor)
        self.leases = tuple(self.leases)
        self.entry = self.base / "entry"
        self.entry.write_text("#!/bin/sh\nprintf synthetic-public-output\n", encoding="ascii")
        self.entry.chmod(0o700)
        self.pin = _file_digest(self.entry)

    def run_guard(self, **options):
        config = dict(timeout=2, max_input_bytes=65536, expected_executable_sha256_hex=self.pin,
                      ownership_descriptors=self.leases)
        config.update(options)
        return run_guarded_public_worker(str(self.entry), b"synthetic", **config)

    def test_exact_public_output_roundtrip_preserves_parent_noninheritable_flags(self):
        before = tuple(os.get_inheritable(fd) for fd in self.leases)
        self.assertEqual(self.run_guard(), b"synthetic-public-output")
        self.assertEqual(tuple(os.get_inheritable(fd) for fd in self.leases), before)
        self.assertEqual(before, (False, False))

    def test_invalid_descriptor_types_counts_and_numbers_reject_before_guard_creation(self):
        for descriptors in (None, [], list(self.leases), (), (self.leases[0],),
                            (self.leases[0], self.leases[0]), (True, self.leases[1]),
                            (0, self.leases[1]), (-1, self.leases[1]), (999999, self.leases[1])):
            with self.subTest(kind=type(descriptors).__name__), patch("offline_session.public_worker.subprocess.Popen") as spawn:
                with self.assertRaises(WorkerError):
                    self.run_guard(ownership_descriptors=descriptors)
                spawn.assert_not_called()

    def test_duplicate_file_identity_rejects_different_descriptor_numbers(self):
        duplicate = os.dup(self.leases[0])
        self.addCleanup(os.close, duplicate)
        with patch("offline_session.public_worker.subprocess.Popen") as spawn, self.assertRaises(WorkerError):
            self.run_guard(ownership_descriptors=(self.leases[0], duplicate))
        spawn.assert_not_called()

    def test_nonprivate_regular_file_or_pipe_is_not_an_ownership_descriptor(self):
        os.chmod(self.base / "a.lock", 0o644)
        with self.assertRaises(WorkerError):
            self.run_guard()
        os.chmod(self.base / "a.lock", 0o600)
        reader, writer = os.pipe()
        self.addCleanup(os.close, reader)
        self.addCleanup(os.close, writer)
        with self.assertRaises(WorkerError):
            self.run_guard(ownership_descriptors=(reader, writer))

    def test_invalid_pin_deadline_or_input_bound_rejects_before_guard_creation(self):
        cases = (dict(expected_executable_sha256_hex=None), dict(expected_executable_sha256_hex="AA" * 32),
                 dict(expected_executable_sha256_hex="1"), dict(timeout=True), dict(timeout=0),
                 dict(timeout=float("nan")), dict(timeout=float("inf")), dict(max_input_bytes=0),
                 dict(max_output_bytes=4097))
        with patch("offline_session.public_worker.subprocess.Popen") as spawn:
            for config in cases:
                with self.subTest(config=tuple(config)), self.assertRaises(WorkerError):
                    self.run_guard(**config)
            spawn.assert_not_called()

    def test_guard_rechecks_pin_and_never_accepts_a_different_selected_entry(self):
        with self.assertRaises(WorkerError):
            self.run_guard(expected_executable_sha256_hex="11" * 32)
        self.assertEqual(self.run_guard(), b"synthetic-public-output")

    def test_guard_spawn_failure_is_sanitized_and_leaves_owner_descriptors_open(self):
        with patch("offline_session.public_worker.subprocess.Popen", side_effect=OSError("synthetic private diagnostic")):
            with self.assertRaises(WorkerError) as caught:
                self.run_guard()
        self.assertNotIn("synthetic private diagnostic", str(caught.exception))
        for fd in self.leases:
            os.fstat(fd)

    def test_success_and_known_guard_failure_do_not_signal_a_reaped_group(self):
        with patch("offline_session.public_worker.os.killpg", wraps=os.killpg) as signal_group:
            self.assertEqual(self.run_guard(), b"synthetic-public-output")
            with self.assertRaises(WorkerError):
                self.run_guard(expected_executable_sha256_hex="11" * 32)
            signal_group.assert_not_called()

    def test_guarded_output_limit_rejects_overflow_and_preserves_parent_locks(self):
        self.entry.write_text("#!/bin/sh\nprintf synthetic-public-output\n", encoding="ascii")
        with self.assertRaises(WorkerError):
            self.run_guard(max_output_bytes=4)
        self.assertEqual(self.run_guard(), b"synthetic-public-output")

    def test_guard_cli_failure_reports_no_arguments_paths_or_runtime_identifiers(self):
        guard = Path(__file__).resolve().parents[1] / "offline_session/worker_guard.py"
        result = subprocess.run([sys.executable, "-B", str(guard), "synthetic-invalid"],
                                capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (2, b"", b"public worker ownership unavailable\n"))

    def test_admitted_transport_retains_a_distinct_slot_and_parent_flags(self):
        with synthetic_pool(self.base, slot_limit=1).acquire() as lease:
            self.assertFalse(os.get_inheritable(lease.fileno()))
            output = run_admitted_public_worker(str(self.entry), b"synthetic", timeout=2,
                max_input_bytes=65536, expected_executable_sha256_hex=self.pin,
                ownership_descriptors=self.leases, admission_descriptor=lease.fileno())
            self.assertEqual(output, b"synthetic-public-output")
            self.assertFalse(os.get_inheritable(lease.fileno()))

    def test_invalid_or_overlapping_admission_descriptor_never_launches(self):
        duplicate = os.dup(self.leases[0])
        self.addCleanup(os.close, duplicate)
        with patch("offline_session.public_worker.subprocess.Popen") as spawn:
            for descriptor in (None, True, [], 0, -1, 999999, self.leases[0], duplicate):
                with self.subTest(kind=type(descriptor).__name__), self.assertRaises(WorkerError):
                    run_admitted_public_worker(str(self.entry), b"synthetic", timeout=2,
                        max_input_bytes=65536, expected_executable_sha256_hex=self.pin,
                        ownership_descriptors=self.leases, admission_descriptor=descriptor)
            spawn.assert_not_called()


@unittest.skipUnless(os.name == "posix", "native lease ownership requires POSIX locks and signals")
class WorkerLeaseDeathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.signature = released_bob(), final_signatures()[0]

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-lease-death-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root, self.anchor = self.base / "records", self.base / "head.json"
        self.marker, self.release = self.base / "started.json", self.base / "release"
        self.target = self.base / "public-target.json"
        self.target.write_text(json.dumps({"state": self.state, "signature_hex": self.signature.hex()}), encoding="ascii")

    def start(self, *, mode="raw", worker="hold", pause=False, timeout=30):
        actor = Path(__file__).with_name("lease_owner_actor.py")
        command = [sys.executable, "-B", str(actor), mode, str(self.root), str(self.anchor),
                   str(self.marker), str(self.release), "--worker", worker, "--target", str(self.target),
                   "--timeout", str(timeout)]
        if pause:
            command.append("--pause-after-guard")
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            self.release.touch()
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
            if mode == "legacy" and self.marker.exists():
                self.wait_release_ack()
        self.addCleanup(cleanup)
        return child

    def wait_marker(self):
        deadline = time.monotonic() + 10
        while not self.marker.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(self.marker.exists(), "controlled worker did not report lease state")
        value = json.loads(self.marker.read_bytes())
        self.assertFalse(value["unrelated_leaked"])
        return value

    def wait_release_ack(self):
        marker = self.marker.with_name(self.marker.name + ".released")
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(marker.exists(), "legacy control worker did not leave its hold loop")

    def first_lock(self, mode):
        return self.root / ("observations.lock" if mode == "store" else "lease-a.lock")

    @contextmanager
    def probe(self, mode="raw"):
        descriptors = []
        try:
            for path in (self.first_lock(mode), Path(str(self.anchor) + ".lock")):
                descriptor = os.open(path, os.O_RDWR)
                descriptors.append(descriptor)
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def wait_unlocked(self, mode="raw"):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with self.probe(mode):
                    return
            except BlockingIOError:
                time.sleep(0.005)
        self.fail("cooperative worker did not release ownership within the test window")

    def kill_owner(self, child):
        child.kill()
        _, diagnostics = child.communicate(timeout=10)
        self.assertEqual((child.returncode, diagnostics), (-signal.SIGKILL, b""))

    def send_kill_guard(self, child):
        child.stdin.write(b"kill-guard\n")
        child.stdin.flush()

    def test_normal_exit_releases_child_references_and_preserves_both_parent_locks_until_return(self):
        child = self.start()
        self.assertEqual(self.wait_marker()["leases"], 2)
        with self.assertRaises(BlockingIOError), self.probe():
            pass
        self.release.touch()
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (0, b"completed", b""))
        self.wait_unlocked()

    def test_owner_sigkill_stops_guarded_worker_waiting_for_output_and_releases_leases(self):
        child = self.start()
        self.assertEqual(self.wait_marker()["leases"], 2)
        self.kill_owner(child)
        self.wait_unlocked()
        self.assertFalse(self.release.exists(), "test must not release the worker to claim owner-death cleanup")

    def test_owner_sigkill_stops_worker_even_after_worker_stdout_eof(self):
        child = self.start(worker="eof-held")
        self.assertEqual(self.wait_marker()["leases"], 2)
        self.kill_owner(child)
        self.wait_unlocked()
        self.assertFalse(self.release.exists())

    def test_owner_sigkill_stops_worker_that_does_not_read_a_full_input_pipe(self):
        child = self.start(worker="never-read")
        self.assertEqual(self.wait_marker()["leases"], 2)
        self.kill_owner(child)
        self.wait_unlocked()
        self.assertFalse(self.release.exists())

    def test_guard_sigkill_leaves_live_worker_ownership_held_until_its_cooperative_exit(self):
        child = self.start()
        self.assertEqual(self.wait_marker()["leases"], 2)
        self.send_kill_guard(child)
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (20, b"WorkerError", b""))
        with self.assertRaises(BlockingIOError), self.probe():
            pass
        self.release.touch()
        self.wait_unlocked()

    def test_legacy_unowned_worker_inherits_no_leases_and_owner_death_has_no_guard(self):
        child = self.start(mode="legacy")
        self.assertEqual(self.wait_marker()["leases"], 0)
        self.kill_owner(child)
        with self.probe():
            pass
        self.release.touch()
        self.wait_release_ack()

    def test_guard_death_in_store_returns_charged_unknown_and_blocks_reopen_before_sqlite_read(self):
        child = self.start(mode="store")
        self.assertEqual(self.wait_marker()["leases"], 2)
        self.send_kill_guard(child)
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (0, b"unknown", b""))
        verifier = SubprocessObservation(self.root / "controlled-worker",
            expected_executable_sha256_hex=_file_digest(self.root / "controlled-worker"))
        with patch("sqlite3.connect", side_effect=AssertionError("live worker must block before database read")) as connect:
            with self.assertRaises(StoreBusy):
                ObservationStore.open(self.root, self.anchor, store_id_hex=STORE_ID, worker_pool=synthetic_pool(self.base),
                    verifier=verifier, attempt_limit=2, target_limit=2)
            connect.assert_not_called()
        self.release.touch()
        self.wait_unlocked("store")
        with ObservationStore.open(self.root, self.anchor, store_id_hex=STORE_ID, worker_pool=synthetic_pool(self.base),
                verifier=verifier, attempt_limit=2, target_limit=2) as store:
            self.assertEqual(store.summary().attempts_consumed, 1)
            self.assertEqual(store.summary().pending_attempts, 0)
            self.assertIsNone(store.known_statement(self.state, self.signature))

    def test_owner_death_in_store_recovers_unknown_without_replaying_selected_worker(self):
        child = self.start(mode="store")
        self.assertEqual(self.wait_marker()["leases"], 2)
        self.kill_owner(child)
        self.wait_unlocked("store")
        verifier = SubprocessObservation(self.root / "controlled-worker",
            expected_executable_sha256_hex=_file_digest(self.root / "controlled-worker"))
        with patch.object(SubprocessObservation, "observe_admitted") as worker:
            with ObservationStore.open(self.root, self.anchor, store_id_hex=STORE_ID, worker_pool=synthetic_pool(self.base),
                    verifier=verifier, attempt_limit=2, target_limit=2) as store:
                self.assertEqual(store.summary().attempts_consumed, 1)
                self.assertEqual(store.summary().pending_attempts, 0)
                self.assertIsNone(store.known_statement(self.state, self.signature))
            worker.assert_not_called()
        self.assertFalse(self.release.exists())

    def test_owner_death_after_guard_launch_before_input_never_starts_a_worker(self):
        child = self.start(mode="store", pause=True)
        with selectors.DefaultSelector() as selection:
            selection.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selection.select(timeout=10))
        self.assertEqual(child.stdout.readline().strip(), b"guard-started")
        self.kill_owner(child)
        self.wait_unlocked("store")
        self.assertFalse(self.marker.exists())
        verifier = SubprocessObservation(self.root / "controlled-worker",
            expected_executable_sha256_hex=_file_digest(self.root / "controlled-worker"))
        with ObservationStore.open(self.root, self.anchor, store_id_hex=STORE_ID, worker_pool=synthetic_pool(self.base),
                verifier=verifier, attempt_limit=2, target_limit=2) as store:
            self.assertEqual(store.summary().attempts_consumed, 1)
            self.assertEqual(store.summary().pending_attempts, 0)

    def test_guard_death_before_input_commits_unknown_without_launching_selected_worker(self):
        child = self.start(mode="store", pause=True)
        with selectors.DefaultSelector() as selection:
            selection.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selection.select(timeout=10))
        self.assertEqual(child.stdout.readline().strip(), b"guard-started")
        self.send_kill_guard(child)
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (0, b"unknown", b""))
        self.wait_unlocked("store")
        self.assertFalse(self.marker.exists())

    def test_guarded_deadline_stops_cooperative_worker_and_releases_child_leases(self):
        child = self.start(timeout=3)
        self.assertEqual(self.wait_marker()["leases"], 2)
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (20, b"WorkerError", b""))
        self.wait_unlocked()
        self.assertFalse(self.release.exists())

    def test_store_cancellation_cleans_guard_group_and_commits_charged_unknown(self):
        child = self.start(mode="store")
        self.assertEqual(self.wait_marker()["leases"], 2)
        child.stdin.write(b"cancel\n")
        child.stdin.flush()
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (20, b"KeyboardInterrupt", b""))
        self.wait_unlocked("store")
        self.assertFalse(self.release.exists())
        verifier = SubprocessObservation(self.root / "controlled-worker",
            expected_executable_sha256_hex=_file_digest(self.root / "controlled-worker"))
        with ObservationStore.open(self.root, self.anchor, store_id_hex=STORE_ID, worker_pool=synthetic_pool(self.base),
                verifier=verifier, attempt_limit=2, target_limit=2) as store:
            self.assertEqual(store.summary().attempts_consumed, 1)
            self.assertEqual(store.summary().pending_attempts, 0)
            self.assertIsNone(store.known_statement(self.state, self.signature))


@unittest.skipUnless(os.name == "posix", "owned adapter qualification requires POSIX descriptors")
class OwnedObservationAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.signature = released_bob(), final_signatures()[0]

    def test_owned_none_or_invalid_leases_become_unknown_without_legacy_fallback(self):
        path = Path(sys.executable).resolve()
        observer = SubprocessObservation(path, expected_executable_sha256_hex=_file_digest(path))
        expected = evidence.unknown_statement(self.state, self.signature,
            verifier_profile_digest_hex=observer.profile_digest_hex)
        with patch("offline_session.public_worker.subprocess.Popen") as spawn, \
                patch("offline_session.observation_verifier.run_public_worker") as legacy:
            for leases in (None, [], (), (True, False)):
                with self.subTest(kind=type(leases).__name__):
                    self.assertEqual(observer.observe_owned(self.state, self.signature,
                        ownership_descriptors=leases), expected)
            spawn.assert_not_called()
            legacy.assert_not_called()

    def test_missing_admission_never_falls_back_to_a_guarded_or_legacy_path(self):
        path = Path(sys.executable).resolve()
        observer = SubprocessObservation(path, expected_executable_sha256_hex=_file_digest(path))
        expected = evidence.unknown_statement(self.state, self.signature,
            verifier_profile_digest_hex=observer.profile_digest_hex)
        with tempfile.TemporaryDirectory(prefix="synthetic-admitted-adapter-") as directory:
            descriptors = []
            try:
                for name in ("a.lock", "b.lock"):
                    descriptor = os.open(Path(directory) / name, os.O_RDWR | os.O_CREAT, 0o600)
                    descriptors.append(descriptor)
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch("offline_session.public_worker.subprocess.Popen") as spawn, \
                        patch("offline_session.observation_verifier.run_guarded_public_worker") as guarded, \
                        patch("offline_session.observation_verifier.run_public_worker") as legacy:
                    self.assertEqual(observer.observe_admitted(self.state, self.signature,
                        ownership_descriptors=tuple(descriptors), admission_descriptor=None), expected)
                    spawn.assert_not_called()
                    guarded.assert_not_called()
                    legacy.assert_not_called()
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
