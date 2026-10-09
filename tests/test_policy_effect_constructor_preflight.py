"""Selected preconnection refusals retain an existing synthetic original."""

import io
import json
import sys
from unittest.mock import patch

import policy_effect_store_actor as actor
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class PolicyEffectConstructorPreflightTests(prior.PolicyEffectStoreCase):
    def setUp(self):
        super().setUp()
        self.original = self.store.allocate_synthetic(self.request())

    def refuse(self, path, labels, *, initial_profile=None, actor_entry=False,
               initialized=False, suppressed=False, label_field=None):
        before = self.path.read_bytes()
        entries = sorted(item.name for item in self.path.parent.iterdir())
        self.partial = None
        self.outward = None
        self.constructor_calls = self.disposal_calls = self.close_calls = self.allocation_calls = 0
        output = io.StringIO()
        store_class = source.OfflinePolicyEffectStore

        def forbidden(*args, **kwargs):
            raise AssertionError("preflight crossed a native resource boundary")

        def construct(path, labels, **kwargs):
            self.constructor_calls += 1
            store = store_class.__new__(store_class)
            self.partial = store

            def dispose():
                self.disposal_calls += 1
                return store_class._dispose(store)

            def close():
                self.close_calls += 1
                return store_class.close(store)

            def allocate(request):
                self.allocation_calls += 1
                return store_class.allocate_synthetic(store, request)

            store._dispose, store.close, store.allocate_synthetic = dispose, close, allocate
            try:
                store_class.__init__(store, path, labels, **kwargs)
            except BaseException as error:
                self.outward = error
                raise
            raise AssertionError("selected refusal unexpectedly returned a store")

        with patch.object(source.sqlite3, "connect", side_effect=forbidden) as connect, \
                patch.object(source.os, "open", side_effect=forbidden) as file_open, \
                patch.object(source, "Path", wraps=source.Path) as path_constructor, \
                patch.object(actor, "ObservedConnection", wraps=actor.ObservedConnection) as observer:
            with self.assertRaises(source.StoreRefused) as caught:
                if actor_entry:
                    request = self.request()
                    context = dict(labels=prior.asdict(labels), operation=request.operation_id_hex,
                        revision=0, profile_hex=prior.WIRE.hex(), proposal=request.proposal_digest_hex)
                    if label_field is not None:
                        context["labels"].update(label_field)
                    argv = ["synthetic-actor", path, "allocation", "unused", "direct", "native-execute-errors-v1"]
                    with patch.object(actor, "OfflinePolicyEffectStore", side_effect=construct), \
                            patch.object(sys, "argv", argv), \
                            patch.object(sys, "stdin", io.StringIO(json.dumps(context) + "\n")), \
                            patch.object(sys, "stdout", output):
                        actor.main()
                else:
                    construct(path, labels, initial_profile=initial_profile)
            self.assertIs(caught.exception, self.outward)
            self.assertIsNone(self.outward.__cause__)
            self.assertIs(self.outward.__suppress_context__, suppressed)
            if suppressed:
                self.assertIsInstance(self.outward.__context__, ValueError)
                self.assertNotIsInstance(self.outward.__context__, source.StoreRefused)
            else:
                self.assertIsNone(self.outward.__context__)
            connect.assert_not_called()
            file_open.assert_not_called()
            observer.assert_not_called()
            self.assertEqual(path_constructor.call_count, int(initialized))
        self.assertEqual((self.constructor_calls, self.disposal_calls, self.close_calls,
            self.allocation_calls), (1, 0, 0, 0))
        fields = ("_owner", "_labels", "_busy", "_closed", "_db")
        self.assertEqual([hasattr(self.partial, name) for name in fields], [initialized] * len(fields))
        if initialized:
            self.assertEqual(self.partial._labels, labels)
            self.assertFalse(self.partial._busy)
            self.assertFalse(self.partial._closed)
            self.assertIsNone(self.partial._db)
        if actor_entry:
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(prior.allocation_reply("unavailable", output.getvalue().encode("ascii"), b""),
                dict(exit_code="unavailable", response_class="empty", stderr_present=False))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), entries)
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(self.request()), self.original)
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def test_actor_uppercase_label_refuses_before_fields_without_reply_or_disposal(self):
        self.refuse(str(self.path), prior.LABELS, actor_entry=True,
            label_field=dict(source_id_hex="AB" * 32))

    def test_actor_numeric_label_refuses_before_fields_without_reply_or_disposal(self):
        self.refuse(str(self.path), prior.LABELS, actor_entry=True,
            label_field=dict(incarnation_id_hex=1))

    def test_actor_empty_path_refuses_before_fields_and_preserves_original(self):
        self.refuse("", prior.LABELS, actor_entry=True)

    def test_actor_overbound_path_refuses_before_path_or_native_calls(self):
        self.refuse("x" * 4097, prior.LABELS, actor_entry=True)

    def test_actor_existing_symlink_refuses_after_fields_without_native_connection(self):
        alias = self.path.with_name("existing-alias.sqlite3")
        alias.symlink_to(self.path)
        self.refuse(str(alias), prior.LABELS, actor_entry=True, initialized=True)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(alias.resolve(), self.path.resolve())

    def test_actor_dangling_symlink_refuses_without_creating_target_or_connection(self):
        missing = self.path.with_name("missing-target.sqlite3")
        alias = self.path.with_name("dangling-alias.sqlite3")
        alias.symlink_to(missing)
        self.refuse(str(alias), prior.LABELS, actor_entry=True, initialized=True)
        self.assertTrue(alias.is_symlink())
        self.assertFalse(missing.exists())

    def test_direct_inexact_labels_refuse_without_running_foreign_attribute_hook(self):
        class ForeignLabels:
            def __getattribute__(self, name):
                raise AssertionError("foreign labels hook ran")

        self.refuse(str(self.path), ForeignLabels())

    def test_direct_foreign_path_refuses_without_running_path_conversion_hook(self):
        class ForeignPath:
            def __fspath__(self):
                raise AssertionError("foreign path conversion ran")

        self.refuse(ForeignPath(), prior.LABELS)

    def test_direct_string_subclass_refuses_without_running_length_hook(self):
        class InexactPath(str):
            def __len__(self):
                raise AssertionError("inexact path length hook ran")

        self.refuse(InexactPath(str(self.path)), prior.LABELS)

    def test_direct_inexact_profile_refuses_without_provisioning_existing_database(self):
        self.refuse(str(self.path), prior.LABELS, initial_profile=bytearray(prior.WIRE))

    def test_direct_noncanonical_profile_preserves_suppressed_decode_context_before_fields(self):
        self.refuse(str(self.path), prior.LABELS, initial_profile=prior.WIRE + b" ", suppressed=True)

    def test_direct_profile_namespace_mismatch_refuses_before_provisioning_existing_database(self):
        self.refuse(str(self.path), prior.LABELS,
            initial_profile=self.wire(authority_id_hex="dd" * 32))
