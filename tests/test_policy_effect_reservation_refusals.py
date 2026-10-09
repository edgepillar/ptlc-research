"""Retained empty reservations refuse native opens and exclusive provisioning."""

import errno
import io
import json
import os
import sqlite3
import sys
from unittest.mock import patch

import policy_effect_store_actor as actor
import test_policy_effect_constructor_paths as paths
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class PolicyEffectReservationFollowupTests(prior.PolicyEffectStoreCase):
    def setUp(self):
        super().setUp()
        self.original = self.store.allocate_synthetic(self.request())

    def followup(self, selected, entry):
        reservation = self.path.with_name("retained-empty.sqlite3")
        primary = KeyboardInterrupt("synthetic-reservation-cancellation") if selected == "uri-cancellation" else OSError(errno.EIO, "synthetic-reservation-failure")
        point = "post_native_file_close" if selected == "post-close-eio" else "as_uri"
        paths.PolicyEffectConstructorPathTests.failure(self, reservation, point=point,
            primary=primary, actor_entry=False, created=True)
        reservation_before = reservation.read_bytes()
        self.assertEqual(reservation_before, b"")
        reservation_identity = (reservation.stat().st_dev, reservation.stat().st_ino)
        original_bytes = self.path.read_bytes()
        before_entries = sorted(item.name for item in self.path.parent.iterdir())
        store_class = source.OfflinePolicyEffectStore
        real_connect, real_open, real_close = sqlite3.connect, os.open, os.close
        partial = store_class.__new__(store_class)
        counts = dict(constructor=0, returned=0, connect=0, dispose=0,
            file_open=0, file_close=0, allocation=0, public_close=0)
        native_errors, disposals, connections, statements = [], [], [], []
        owned_descriptors = set()
        output = io.StringIO()

        class ForwardingConnection:
            def __init__(self, connection):
                self.connection, self.closed, self.close_calls = connection, False, 0

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def execute(self, sql, *args):
                statements.append(sql)
                return self.connection.execute(sql, *args)

            def close(self):
                self.close_calls += 1
                result = self.connection.close()
                self.closed = True
                return result

        def connect(*args, **kwargs):
            counts["connect"] += 1
            connection = ForwardingConnection(real_connect(*args, **kwargs))
            connections.append(connection)
            def cleanup():
                if not connection.closed:
                    connection.close()
            self.addCleanup(cleanup)
            return connection

        def file_open(*args, **kwargs):
            counts["file_open"] += 1
            try:
                descriptor = real_open(*args, **kwargs)
            except OSError as error:
                native_errors.append(error)
                raise
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
            return result

        def dispose():
            counts["dispose"] += 1
            disposals.append(sys.exc_info()[1])
            return store_class._dispose(partial)

        def close():
            counts["public_close"] += 1
            return store_class.close(partial)

        def allocate(request):
            counts["allocation"] += 1
            return store_class.allocate_synthetic(partial, request)

        def construct(path, labels, **kwargs):
            counts["constructor"] += 1
            partial._dispose, partial.close, partial.allocate_synthetic = dispose, close, allocate
            store_class.__init__(partial, path, labels, **kwargs)
            counts["returned"] += 1
            return partial

        provisioning = entry == "direct-provision"
        expected = source.StoreOutcomeUnknown if provisioning else source.StoreRefused
        with patch.object(source.sqlite3, "connect", side_effect=connect), \
                patch.object(source.os, "open", side_effect=file_open), \
                patch.object(source.os, "close", side_effect=file_close), \
                patch.object(actor, "ObservedConnection", wraps=actor.ObservedConnection) as observer:
            with self.assertRaises(expected) as caught:
                if entry == "actor-open":
                    request = self.request()
                    context = dict(labels=prior.asdict(prior.LABELS), operation=request.operation_id_hex,
                        revision=0, profile_hex=prior.WIRE.hex(), proposal=request.proposal_digest_hex)
                    argv = ["synthetic-actor", str(reservation), "allocation", "unused", "direct", "native-execute-errors-v1"]
                    with patch.object(actor, "OfflinePolicyEffectStore", side_effect=construct), \
                            patch.object(sys, "argv", argv), patch.object(sys, "stdout", output), \
                            patch.object(sys, "stdin", io.StringIO(json.dumps(context) + "\n")):
                        actor.main()
                elif provisioning:
                    construct(str(reservation), prior.LABELS, initial_profile=prior.WIRE)
                else:
                    construct(str(reservation), prior.LABELS)
            observer.assert_not_called()

        self.assertEqual(counts, dict(constructor=1, returned=0, connect=int(not provisioning),
            dispose=1, file_open=int(provisioning), file_close=0, allocation=0, public_close=0))
        if provisioning:
            self.assertEqual(len(native_errors), 1)
            native = native_errors[0]
            self.assertIsInstance(native, FileExistsError)
            self.assertEqual(native.errno, errno.EEXIST)
            self.assertIsNone(native.__context__)
            self.assertIsNone(native.__cause__)
            self.assertFalse(native.__suppress_context__)
            self.assertIs(caught.exception.__context__, native)
            self.assertIsNone(caught.exception.__cause__)
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertEqual(disposals, [native])
            self.assertEqual(connections, [])
            self.assertIsNone(partial._db)
            self.assertEqual(statements, [])
        else:
            self.assertEqual(native_errors, [])
            self.assertIs(type(caught.exception), source.StoreRefused)
            self.assertIsNone(caught.exception.__context__)
            self.assertIsNone(caught.exception.__cause__)
            self.assertFalse(caught.exception.__suppress_context__)
            self.assertEqual(disposals, [caught.exception])
            self.assertEqual(len(connections), 1)
            self.assertIs(partial._db, connections[0])
            self.assertTrue(connections[0].closed)
            self.assertEqual(connections[0].close_calls, 1)
            self.assertEqual(statements.count("BEGIN IMMEDIATE"), 1)
            self.assertEqual(statements.count("ROLLBACK"), 1)
            self.assertEqual(statements.count("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"), 1)
            with self.assertRaises(sqlite3.ProgrammingError):
                connections[0].connection.execute("SELECT 1")
        self.assertEqual(owned_descriptors, set())
        self.assertTrue(partial._closed)
        self.assertFalse(partial._busy)
        self.assertEqual(partial._labels, prior.LABELS)
        self.assertEqual(partial._owner, (os.getpid(), source.threading.get_ident()))
        if entry == "actor-open":
            self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.path.read_bytes(), original_bytes)
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), before_entries)
        self.assertEqual(reservation.read_bytes(), reservation_before)
        self.assertEqual((reservation.stat().st_dev, reservation.stat().st_ino), reservation_identity)
        self.assertEqual(reservation.stat().st_mode & 0o777, 0o600)
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(self.request()), self.original)
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def test_post_close_eio_reservation_direct_open_refusal(self):
        self.followup("post-close-eio", "direct-open")

    def test_post_close_eio_reservation_actor_open_refusal(self):
        self.followup("post-close-eio", "actor-open")

    def test_post_close_eio_reservation_provision_eexist(self):
        self.followup("post-close-eio", "direct-provision")

    def test_uri_eio_reservation_direct_open_refusal(self):
        self.followup("uri-eio", "direct-open")

    def test_uri_eio_reservation_actor_open_refusal(self):
        self.followup("uri-eio", "actor-open")

    def test_uri_eio_reservation_provision_eexist(self):
        self.followup("uri-eio", "direct-provision")

    def test_uri_cancellation_reservation_direct_open_refusal(self):
        self.followup("uri-cancellation", "direct-open")

    def test_uri_cancellation_reservation_actor_open_refusal(self):
        self.followup("uri-cancellation", "actor-open")

    def test_uri_cancellation_reservation_provision_eexist(self):
        self.followup("uri-cancellation", "direct-provision")
