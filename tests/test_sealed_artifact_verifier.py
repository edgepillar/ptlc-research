"""Portable failure/ownership controls using a modeled public file API.

These tests do not qualify Linux seals or executable descriptors. The separate
actual-exchange script exercises the kernel and unchanged native equations.
"""

from contextlib import contextmanager
import hashlib
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from offline_session import sealed_artifact_verifier as sealed
from offline_session.exchange import RESULT_SCHEMA, VerificationError, canonical, request_digest
from offline_session.public_worker import WorkerError


class PublicFileAPI:
    """Small in-memory descriptor model; no real executable or syscall."""

    def __init__(self):
        self.data = b"\x7fELF synthetic public entry bytes"
        self.size = len(self.data)
        self.mode = stat.S_IFREG | 0o500
        self.next_fd = 10
        self.opened = {}
        self.closed = []
        self.events = []
        self.seals = {}
        self.short_write = False
        self.os = SimpleNamespace(name="posix", O_RDONLY=0, O_NONBLOCK=1,
            O_CLOEXEC=2, O_NOFOLLOW=4, MFD_CLOEXEC=1, MFD_ALLOW_SEALING=2, SEEK_SET=0,
            open=self.open, memfd_create=self.memfd_create, fstat=self.fstat,
            read=self.read, write=self.write, close=self.close,
            fchmod=self.fchmod, lseek=self.lseek)
        self.fcntl = SimpleNamespace(F_ADD_SEALS=1, F_GET_SEALS=2,
            F_SEAL_WRITE=1, F_SEAL_GROW=2, F_SEAL_SHRINK=4, F_SEAL_SEAL=8,
            fcntl=self.control)

    def allocate(self, role, data):
        fd = self.next_fd
        self.next_fd += 1
        self.opened[fd] = [role, bytearray(data), 0]
        self.events.append(("allocate", role, fd))
        return fd

    def open(self, path, flags):
        self.events.append(("open", path, flags))
        return self.allocate("source", self.data)

    def memfd_create(self, name, flags):
        self.events.append(("memfd", name, flags))
        return self.allocate("snapshot", b"")

    def fstat(self, fd):
        role, data, _ = self.opened[fd]
        return SimpleNamespace(st_mode=self.mode, st_size=self.size if role == "source" else len(data))

    def read(self, fd, count):
        _, data, offset = self.opened[fd]
        result = bytes(data[offset:offset + count])
        self.opened[fd][2] += len(result)
        self.events.append(("read", fd, len(result)))
        return result

    def write(self, fd, data):
        count = min(3, len(data)) if self.short_write else len(data)
        self.opened[fd][1].extend(data[:count])
        self.events.append(("write", fd, count))
        return count

    def close(self, fd):
        self.closed.append(fd)
        del self.opened[fd]

    def fchmod(self, fd, mode):
        self.events.append(("chmod", fd, mode))

    def lseek(self, fd, offset, whence):
        self.opened[fd][2] = offset

    def control(self, fd, command, value=None):
        self.events.append(("seal", fd, command))
        if command == self.fcntl.F_ADD_SEALS:
            self.seals[fd] = value
            return 0
        return self.seals.get(fd, 0)


class SealedVerifierTests(unittest.TestCase):
    def setUp(self):
        self.api = PublicFileAPI()
        self.path = Path("/synthetic/selected-public-verifier")
        self.pin = hashlib.sha256(self.api.data).hexdigest()
        self.request = {"synthetic": "public request"}
        self.result = {"schema": RESULT_SCHEMA,
            "request_digest_hex": request_digest(self.request), "valid": True}

    @contextmanager
    def modeled_host(self, **runner_options):
        clock = SimpleNamespace(monotonic=lambda: 0)
        with patch.object(sealed, "os", self.api.os), \
                patch.object(sealed, "sys", SimpleNamespace(platform="linux")), \
                patch.object(sealed, "fcntl", self.api.fcntl), \
                patch.object(sealed, "time", clock), \
                patch("offline_session.public_worker.time", clock), \
                patch.object(sealed, "_run", **runner_options) as runner:
            yield runner

    def select(self, **kwargs):
        return sealed.SealedSubprocessVerifier(self.path,
            expected_executable_sha256_hex=self.pin, **kwargs)

    def assert_closed(self):
        self.assertEqual(self.api.opened, {})
        self.assertEqual(len(self.api.closed), len(set(self.api.closed)))

    def test_snapshot_hashes_after_seals_and_passes_only_owned_descriptor(self):
        def response(command, wire, **options):
            fd, = options["pass_fds"]
            self.assertEqual(command, ["/proc/self/fd/" + str(fd)])
            self.assertEqual(wire, canonical(self.request))
            self.assertEqual(options["max_output_bytes"], 4096)
            self.assertEqual(options["timeout"], 5)
            self.assertEqual(list(self.api.opened), [fd])
            self.assertEqual(bytes(self.api.opened[fd][1]), self.api.data)
            self.assertEqual(self.api.opened[fd][2], 0)
            self.assertEqual(self.api.seals[fd], 15)
            seal = next(i for i, event in enumerate(self.api.events) if event[0] == "seal")
            self.assertTrue(all(i > seal for i, event in enumerate(self.api.events)
                                if event[0] == "read" and event[1] == fd))
            return canonical(self.result)
        with self.modeled_host(side_effect=response):
            adapter = self.select()
            self.assertEqual(self.api.events, [])
            self.assertEqual(adapter(self.request), self.result)
        self.assert_closed()

    def test_exact_receipt_and_one_lf_accept_without_authenticating_equations(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            for wire in (canonical(self.result), canonical(self.result) + b"\n"):
                runner.return_value = wire
                self.assertEqual(adapter(self.request), self.result)
                self.assert_closed()
            self.assertEqual(runner.call_count, 2)

    def test_malformed_unbound_alias_and_extra_receipts_refuse(self):
        wrong = dict(self.result, request_digest_hex="00" * 32)
        wires = (b"", b"\xff", b"[]", canonical(wrong),
            canonical(dict(self.result, valid=1)), canonical(dict(self.result, valid=False)),
            canonical(dict(self.result, extra="synthetic")),
            canonical(self.result) + b"\n\n", b" " + canonical(self.result),
            canonical(self.result) + canonical(self.result))
        with self.modeled_host() as runner:
            adapter = self.select()
            for wire in wires:
                with self.subTest(wire=wire):
                    runner.return_value = wire
                    with self.assertRaises(VerificationError):
                        adapter(self.request)
                    self.assert_closed()

    def test_hash_mismatch_closes_snapshot_without_launch(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            self.api.data = b"\x7fELF changed synthetic public entry"
            self.api.size = len(self.api.data)
            with self.assertRaises(VerificationError):
                adapter(self.request)
            runner.assert_not_called()
        self.assert_closed()

    def test_exact_selection_types_pin_and_deadline_refuse_before_io(self):
        class ForeignPath:
            def __fspath__(self):
                raise AssertionError("foreign path hook called")
        with self.modeled_host() as runner:
            for path in (ForeignPath(), "relative", "\x00/synthetic", b"/synthetic"):
                with self.assertRaises(VerificationError):
                    sealed.SealedSubprocessVerifier(path, expected_executable_sha256_hex=self.pin)
            for pin in (None, self.pin.upper(), "0" * 63, "0" * 65, True):
                with self.assertRaises(VerificationError):
                    sealed.SealedSubprocessVerifier(self.path, expected_executable_sha256_hex=pin)
            for timeout in (True, 0, -1, 31, float("nan"), float("inf"), "5"):
                with self.assertRaises(VerificationError):
                    self.select(timeout=timeout)
            runner.assert_not_called()
            self.assertEqual(self.api.events, [])

    def test_unsupported_host_and_missing_capability_never_allocate(self):
        with self.modeled_host() as runner:
            for platform in ("darwin", "win32", "synthetic"):
                with patch.object(sealed.sys, "platform", platform), self.assertRaises(VerificationError):
                    self.select()
            for owner, names in ((sealed.os, ("memfd_create", "MFD_ALLOW_SEALING", "O_NOFOLLOW")),
                                 (sealed.fcntl, ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE"))):
                for name in names:
                    with patch.object(owner, name, None), self.assertRaises(VerificationError):
                        self.select()
            runner.assert_not_called()
            self.assertEqual(self.api.events, [])

    def test_later_capability_loss_refuses_retained_selection_before_io(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            with patch.object(sealed.os, "memfd_create", None), self.assertRaises(VerificationError):
                adapter(self.request)
            runner.assert_not_called()
            self.assertEqual(self.api.events, [])

    def test_regular_nonempty_bounded_executable_metadata_is_required(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            for mode, size in ((stat.S_IFIFO | 0o500, self.api.size),
                               (stat.S_IFDIR | 0o500, self.api.size),
                               (stat.S_IFREG | 0o400, self.api.size),
                               (self.api.mode, 0), (self.api.mode, sealed._MAX_EXECUTABLE_BYTES + 1)):
                self.api.mode, self.api.size = mode, size
                with self.assertRaises(VerificationError):
                    adapter(self.request)
                self.assert_closed()
            runner.assert_not_called()
            self.assertFalse(any(event[0] == "memfd" for event in self.api.events))

    def test_script_wrapper_and_nonelf_refuse_without_snapshot_or_fallback(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            for data in (b"#!/bin/sh\nexit 0\n", b"synthetic public data", b"\x7fEL"):
                self.api.data, self.api.size = data, len(data)
                with self.assertRaises(VerificationError):
                    adapter(self.request)
                self.assert_closed()
            runner.assert_not_called()
            self.assertFalse(any(event[0] == "memfd" for event in self.api.events))

    def test_short_or_growing_source_refuses_before_launch(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            for delta in (-1, 1):
                self.api.size = len(self.api.data) + delta
                with self.assertRaises(VerificationError):
                    adapter(self.request)
                self.assert_closed()
            runner.assert_not_called()

    def test_partial_writes_preserve_complete_selected_bytes(self):
        self.api.short_write = True
        with self.modeled_host(return_value=canonical(self.result)):
            self.assertEqual(self.select()(self.request), self.result)
        self.assertTrue(len([event for event in self.api.events if event[0] == "write"]) > 1)
        self.assert_closed()

    def test_zero_write_refuses_and_closes_without_launch(self):
        with self.modeled_host() as runner, patch.object(self.api.os, "write", return_value=0):
            with self.assertRaises(VerificationError):
                self.select()(self.request)
            runner.assert_not_called()
        self.assert_closed()

    def test_incomplete_or_failed_seal_installation_never_launches(self):
        actual = self.api.control
        def incomplete(fd, command, value=None):
            if command == self.api.fcntl.F_GET_SEALS:
                return 7
            return actual(fd, command, value)
        with self.modeled_host() as runner:
            adapter = self.select()
            for operation in (incomplete, OSError("SYNTHETIC_PRIVATE_DETAIL")):
                with patch.object(self.api.fcntl, "fcntl", side_effect=operation), self.assertRaises(VerificationError):
                    adapter(self.request)
                self.assert_closed()
            runner.assert_not_called()

    def test_acquisition_io_and_permission_failures_close_and_sanitize(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            for name in ("open", "fstat", "read", "memfd_create", "fchmod", "write", "lseek"):
                with self.subTest(operation=name), \
                        patch.object(self.api.os, name, side_effect=OSError("SYNTHETIC_PRIVATE_DETAIL")), \
                        self.assertRaises(VerificationError) as caught:
                    adapter(self.request)
                self.assertNotIn("SYNTHETIC_PRIVATE_DETAIL", str(caught.exception))
                self.assert_closed()
            runner.assert_not_called()

    def test_cancellation_during_preparation_closes_owned_descriptors(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            for name in ("open", "read", "memfd_create", "fchmod", "write", "lseek"):
                for cancellation in (KeyboardInterrupt, SystemExit):
                    with patch.object(self.api.os, name, side_effect=cancellation), self.assertRaises(cancellation):
                        adapter(self.request)
                    self.assert_closed()
            runner.assert_not_called()

    def test_preparation_deadline_refuses_without_launch_or_leaked_snapshot(self):
        actual = sealed._remaining
        calls = 0
        def expire(deadline):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise WorkerError("public worker deadline exceeded")
            return actual(deadline)
        with self.modeled_host() as runner, patch.object(sealed, "_remaining", side_effect=expire):
            with self.assertRaises(VerificationError):
                self.select()(self.request)
            runner.assert_not_called()
        self.assert_closed()

    def test_preparation_and_transport_share_remaining_requested_deadline(self):
        with self.modeled_host(return_value=canonical(self.result)) as runner, \
                patch.object(sealed.time, "monotonic", side_effect=[0] + [2] * 20):
            self.assertEqual(self.select(timeout=5)(self.request), self.result)
            self.assertEqual(runner.call_args.kwargs["timeout"], 3)
        self.assert_closed()

    def test_runner_failure_and_cancellation_always_close_snapshot(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            for error in (OSError("SYNTHETIC_PRIVATE_DETAIL"), WorkerError("SYNTHETIC_PRIVATE_DETAIL"),
                          KeyboardInterrupt(), SystemExit()):
                runner.side_effect = error
                kind = type(error) if isinstance(error, (KeyboardInterrupt, SystemExit)) else VerificationError
                with self.assertRaises(kind) as caught:
                    adapter(self.request)
                self.assertNotIn("SYNTHETIC_PRIVATE_DETAIL", str(caught.exception))
                self.assert_closed()

    def test_request_bounds_refuse_before_any_file_acquisition(self):
        with self.modeled_host() as runner:
            adapter = self.select()
            for request in ({"synthetic": "x" * 32768}, {"synthetic": float("nan")}, {"synthetic": object()}):
                with self.assertRaises(VerificationError):
                    adapter(request)
            runner.assert_not_called()
            self.assertEqual(self.api.events, [])

    def test_each_call_has_fresh_ownership_and_changed_entry_refuses(self):
        with self.modeled_host(return_value=canonical(self.result)) as runner:
            adapter = self.select()
            for _ in range(2):
                self.assertEqual(adapter(self.request), self.result)
                self.assert_closed()
            self.assertNotEqual(runner.call_args_list[0].kwargs["pass_fds"],
                                runner.call_args_list[1].kwargs["pass_fds"])
            self.api.data = b"\x7fELF changed entry with selected length"
            self.api.size = len(self.api.data)
            with self.assertRaises(VerificationError):
                adapter(self.request)
            self.assertEqual(runner.call_count, 2)
            self.assert_closed()


if __name__ == "__main__":
    unittest.main()
