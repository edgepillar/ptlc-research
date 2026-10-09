"""Selected path faults and native provisioning failures retain one original."""

import errno
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

import policy_effect_store_actor as actor
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class PolicyEffectConstructorPathTests(prior.PolicyEffectStoreCase):
    def setUp(self):
        super().setUp()
        self.original = self.store.allocate_synthetic(self.request())

    def failure(self, path, *, point=None, primary=None, actor_entry=True,
                native=None, expected_errno=None, created=False):
        before = self.path.read_bytes()
        entries = sorted(item.name for item in self.path.parent.iterdir())
        store_class, real_path = source.OfflinePolicyEffectStore, source.Path
        real_connect, real_open, real_close = sqlite3.connect, os.open, os.close
        counts = dict(constructor=0, connect=0, file_open=0, file_close=0, allocation=0, public_close=0)
        disposals, native_errors, path_calls, descriptors = [], [], [], []
        owned_descriptors = set()
        output = io.StringIO()
        partial = store_class.__new__(store_class)

        class ForwardingPath:
            def __init__(self, value):
                self.path = real_path(value)

            def absolute(self):
                path_calls.append("absolute")
                if point == "absolute":
                    raise primary
                self.path = self.path.absolute()
                return self

            def is_symlink(self):
                path_calls.append("is_symlink")
                if point == "is_symlink":
                    raise primary
                return self.path.is_symlink()

            def as_uri(self):
                path_calls.append("as_uri")
                if point == "as_uri":
                    raise primary
                return self.path.as_uri()

            def __str__(self):
                return str(self.path)

        def connect(*args, **kwargs):
            counts["connect"] += 1
            try:
                connection = real_connect(*args, **kwargs)
            except sqlite3.Error as error:
                native_errors.append(error)
                raise
            connection.close()
            raise AssertionError("selected native path unexpectedly opened a database")

        def file_open(*args, **kwargs):
            counts["file_open"] += 1
            try:
                descriptor = real_open(*args, **kwargs)
            except OSError as error:
                native_errors.append(error)
                raise
            descriptors.append(descriptor)
            owned_descriptors.add(descriptor)
            def cleanup():
                if descriptor in owned_descriptors:
                    real_close(descriptor)
                    owned_descriptors.remove(descriptor)
            self.addCleanup(cleanup)
            return descriptor

        def file_close(descriptor):
            counts["file_close"] += 1
            result = real_close(descriptor)
            owned_descriptors.remove(descriptor)
            if point == "post_native_file_close":
                raise primary
            return result

        def dispose():
            disposals.append(sys.exc_info()[1])
            return store_class._dispose(partial)

        def close():
            counts["public_close"] += 1
            return store_class.close(partial)

        def allocate(request):
            counts["allocation"] += 1
            return store_class.allocate_synthetic(partial, request)

        def construct(path, labels):
            counts["constructor"] += 1
            partial._dispose, partial.close, partial.allocate_synthetic = dispose, close, allocate
            store_class.__init__(partial, path, labels,
                initial_profile=None if actor_entry else prior.WIRE)
            raise AssertionError("selected interrupted constructor unexpectedly returned")

        outside = point in ("absolute", "is_symlink")
        normalized = native is not None or isinstance(primary, OSError) and not outside
        expected = source.StoreOutcomeUnknown if normalized else type(primary)
        with patch.object(source, "Path", side_effect=ForwardingPath), \
                patch.object(source.sqlite3, "connect", side_effect=connect), \
                patch.object(source.os, "open", side_effect=file_open), \
                patch.object(source.os, "close", side_effect=file_close), \
                patch.object(actor, "ObservedConnection", wraps=actor.ObservedConnection) as observer:
            with self.assertRaises(expected) as caught:
                if actor_entry:
                    request = self.request()
                    context = dict(labels=prior.asdict(prior.LABELS), operation=request.operation_id_hex,
                        revision=0, profile_hex=prior.WIRE.hex(), proposal=request.proposal_digest_hex)
                    argv = ["synthetic-actor", str(path), "allocation", "unused", "direct", "native-execute-errors-v1"]
                    with patch.object(actor, "OfflinePolicyEffectStore", side_effect=construct), \
                            patch.object(sys, "argv", argv), patch.object(sys, "stdout", output), \
                            patch.object(sys, "stdin", io.StringIO(json.dumps(context) + "\n")):
                        actor.main()
                else:
                    construct(str(path), prior.LABELS)
            observer.assert_not_called()

        if native is not None:
            self.assertEqual(len(native_errors), 1)
            primary = native_errors[0]
            if native == "connect":
                self.assertIs(type(primary), sqlite3.OperationalError)
                self.assertEqual(primary.sqlite_errorcode & 0xff, sqlite3.SQLITE_CANTOPEN)
            else:
                self.assertIsInstance(primary, OSError)
                self.assertEqual(primary.errno, expected_errno)
        else:
            self.assertEqual(native_errors, [])
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        if normalized:
            self.assertIs(type(caught.exception), source.StoreOutcomeUnknown)
            self.assertIs(caught.exception.__context__, primary)
            self.assertIsNone(caught.exception.__cause__)
            self.assertTrue(caught.exception.__suppress_context__)
        else:
            self.assertIs(caught.exception, primary)
        self.assertEqual(disposals, [] if outside else [primary])
        self.assertEqual(counts, dict(constructor=1, connect=int(native == "connect"),
            file_open=int(not actor_entry), file_close=int(created), allocation=0, public_close=0))
        wanted_path_calls = ["absolute"]
        if point != "absolute":
            wanted_path_calls.append("is_symlink")
        if native == "connect" or point == "as_uri":
            wanted_path_calls.append("as_uri")
        self.assertEqual(path_calls, wanted_path_calls)
        self.assertIsNone(partial._db)
        self.assertFalse(partial._busy)
        self.assertEqual(partial._closed, not outside)
        self.assertEqual(partial._labels, prior.LABELS)
        if actor_entry:
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(prior.allocation_reply("unavailable", b"", b""),
                dict(exit_code="unavailable", response_class="empty", stderr_present=False))
        self.assertEqual(self.path.read_bytes(), before)
        expected_entries = sorted(entries + ([path.name] if created else []))
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), expected_entries)
        self.assertEqual(len(descriptors), int(created))
        self.assertEqual(owned_descriptors, set())
        if created:
            self.assertEqual(path.read_bytes(), b"")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptors[0])
            self.assertEqual(closed.exception.errno, errno.EBADF)
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(self.request()), self.original)
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def selected(self, point, *, cancel=False, actor_entry=True):
        primary = KeyboardInterrupt("synthetic-selected-path-cancellation") if cancel else OSError(errno.EIO, "synthetic-selected-path-failure")
        path = self.path if actor_entry else self.path.with_name("reserved-empty.sqlite3")
        self.failure(path, point=point, primary=primary, actor_entry=actor_entry, created=not actor_entry)

    def test_actor_selected_absolute_eio_survives_before_disposal_guard(self):
        self.selected("absolute")

    def test_actor_selected_absolute_cancellation_survives_before_disposal_guard(self):
        self.selected("absolute", cancel=True)

    def test_actor_selected_symlink_inspection_eio_survives_before_disposal_guard(self):
        self.selected("is_symlink")

    def test_actor_selected_symlink_inspection_cancellation_survives_before_disposal_guard(self):
        self.selected("is_symlink", cancel=True)

    def test_actor_selected_uri_eio_is_suppressed_unknown_after_disposal(self):
        self.selected("as_uri")

    def test_actor_selected_uri_cancellation_survives_exactly_after_disposal(self):
        self.selected("as_uri", cancel=True)

    def test_actor_native_directory_open_has_cantopen_context_without_reply(self):
        directory = self.path.with_name("selected-directory")
        directory.mkdir()
        self.failure(directory, native="connect")

    def test_actor_native_regular_parent_open_has_cantopen_context_without_reply(self):
        parent = self.path.with_name("regular-parent")
        parent.write_bytes(b"synthetic-regular-parent")
        self.failure(parent / "child.sqlite3", native="connect")
        self.assertEqual(parent.read_bytes(), b"synthetic-regular-parent")

    def test_direct_native_existing_provision_preserves_eexist_context_and_original(self):
        self.failure(self.path, actor_entry=False, native="file_open", expected_errno=errno.EEXIST)

    def test_direct_native_directory_provision_preserves_eexist_context_without_connect(self):
        directory = self.path.with_name("selected-directory")
        directory.mkdir()
        self.failure(directory, actor_entry=False, native="file_open", expected_errno=errno.EEXIST)

    def test_direct_native_regular_parent_provision_preserves_enotdir_context(self):
        parent = self.path.with_name("regular-parent")
        parent.write_bytes(b"synthetic-regular-parent")
        self.failure(parent / "child.sqlite3", actor_entry=False, native="file_open", expected_errno=errno.ENOTDIR)
        self.assertEqual(parent.read_bytes(), b"synthetic-regular-parent")

    def test_direct_selected_post_native_file_close_eio_retains_empty_reservation(self):
        self.selected("post_native_file_close", actor_entry=False)

    def test_direct_selected_uri_eio_after_provision_retains_empty_reservation(self):
        self.selected("as_uri", actor_entry=False)

    def test_direct_selected_uri_cancellation_after_provision_retains_empty_reservation(self):
        self.selected("as_uri", cancel=True, actor_entry=False)
