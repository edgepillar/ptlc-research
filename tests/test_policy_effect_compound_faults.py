"""Selected primary actor faults, post-close faults and separate retained originals."""

import errno
import io
import json
import os
import sqlite3
import sys
import unittest
from unittest.mock import patch

import policy_effect_native_observation as observation
import policy_effect_store_actor as actor
import test_policy_effect_actor_cleanup as cleanup
import test_policy_effect_output_loss as output_loss
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


@unittest.skipUnless(os.name == "posix", "selected native pipe controls require POSIX")
class PolicyEffectCompoundFaultTests(prior.PolicyEffectStoreCase):
    def run_actor(self, terminal, *, cancellation=None, point="unused", mode="direct",
                  revision=0, lose_line=None, fail_flush=None, deny_setup=False,
                  rollback_denials=0):
        request = self.request(revision=revision)
        context = dict(labels=prior.asdict(prior.LABELS), operation=request.operation_id_hex,
                       revision=revision, profile_hex=prior.WIRE.hex(), proposal=request.proposal_digest_hex)
        line = json.dumps(context) + "\n"
        incoming = cleanup.CancellingInput(line, cancellation) if cancellation is not None else io.StringIO(line)
        self.output = output_loss.SelectedPipeOutput(lose_line=lose_line, fail_flush=fail_flush)
        self.addCleanup(self.output.close)
        self.constructor_calls = 0
        self.allocation_calls = 0
        self.closed_at_close = []
        self.primary_at_close = []
        self.transactions = []

        def construct(path, labels):
            self.constructor_calls += 1
            store = source.OfflinePolicyEffectStore(path, labels)
            self.actor_store = store
            self.addCleanup(lambda: store._dispose() if not store._closed else None)

            def authorizer(action, first, second, database, trigger):
                if action == sqlite3.SQLITE_TRANSACTION:
                    self.transactions.append(first)
                    if first == "ROLLBACK" and self.transactions.count("ROLLBACK") <= rollback_denials:
                        return sqlite3.SQLITE_DENY
                if deny_setup and action == sqlite3.SQLITE_PRAGMA and first == "cache_size":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            store._db.set_authorizer(authorizer)
            original_close, original_allocate = store.close, store.allocate_synthetic

            def close():
                self.closed_at_close.append(store._closed)
                self.primary_at_close.append(sys.exc_info()[1])
                original_close()
                raise terminal

            def allocate(request):
                self.allocation_calls += 1
                return original_allocate(request)

            store.close, store.allocate_synthetic = close, allocate
            return store

        argv = ["synthetic-actor", str(self.path), "allocation", point, mode, "native-execute-errors-v1"]
        with patch.object(actor, "OfflinePolicyEffectStore", side_effect=construct), \
                patch.object(sys, "argv", argv), patch.object(sys, "stdin", incoming), \
                patch.object(sys, "stdout", self.output):
            return actor.main()

    def assert_chain(self, caught, terminal, primary):
        self.assertIs(caught.exception, terminal)
        self.assertEqual(len(self.primary_at_close), 1)
        self.assertIs(self.primary_at_close[0], primary)
        self.assertIs(terminal.__context__, primary)
        self.assertIsNone(terminal.__cause__)
        self.assertFalse(terminal.__suppress_context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)

    def assert_state(self, *, allocations, transactions, retained, closes=1, errors=None, observed=True):
        self.assertEqual(self.constructor_calls, 1)
        self.assertEqual(self.allocation_calls, allocations)
        self.assertEqual(self.closed_at_close, [False] * closes)
        self.assertEqual(self.transactions, transactions)
        self.assertTrue(self.actor_store._closed)
        with self.assertRaises(source.StoreRefused):
            self.actor_store.local_view()
        with self.assertRaises(sqlite3.ProgrammingError):
            self.actor_store._db.in_transaction
        if observed:
            self.assertEqual(self.actor_store._db.report(), dict(schema=observation.SCHEMA,
                             errors=[] if errors is None else errors, overflow=False))
        else:
            self.assertIs(type(self.actor_store._db), sqlite3.Connection)
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=retained, raw_effects=0,
            retained_originals=[bool(retained)], charge_sequences=[1 if retained else None],
            effect_sequences=[None], charged_operations=retained, synthetic_effects=0,
            event_sequence=retained))

    def assert_output(self, *, lines=0, marker=b""):
        record = (json.dumps(dict(charge_sequence=1, effect_sequence=None)) + "\n").encode("ascii")
        report = observation.canonical(dict(schema=observation.SCHEMA, errors=[], overflow=False)) + b"\n"
        expected = marker if lines == 0 else record + (report if lines == 2 else b"")
        self.assertEqual(bytes(self.output.received), expected)
        self.assertFalse(b"synthetic-selected" in expected)
        if not marker:
            reply = prior.allocation_reply("unavailable", expected, b"")
            self.assertEqual(reply["exit_code"], "unavailable")
            self.assertEqual(reply["response_class"], "empty" if lines == 0 else "allocation-record")
            self.assertEqual("native_execute_errors" in reply, lines == 2)
            if lines == 2:
                self.assertEqual(reply["native_execute_errors"], [])
                self.assertFalse(reply["native_error_overflow"])

    def cancellation_pair(self, *, point="unused", mode="direct", retained, allocations, transactions, marker):
        primary = KeyboardInterrupt("synthetic-selected-primary-cancellation")
        terminal = OSError(errno.EIO, "synthetic-selected-post-close-fault")
        with self.assertRaises(OSError) as caught:
            self.run_actor(terminal, cancellation=primary, point=point, mode=mode)
        self.assert_chain(caught, terminal, primary)
        self.assertIsNone(primary.__context__)
        self.assertEqual(terminal.errno, errno.EIO)
        self.assertIsNone(self.output.failure)
        self.assert_output(marker=marker)
        self.assert_state(allocations=allocations, transactions=transactions, retained=retained)

    def test_readiness_cancellation_is_context_of_post_close_fault_without_transaction(self):
        self.cancellation_pair(mode="ready", retained=0, allocations=0, transactions=[], marker=b"ready\n")

    def test_precommit_cancellation_is_context_of_post_close_fault_after_rollback(self):
        self.cancellation_pair(point="allocation-written", retained=0, allocations=1,
                               transactions=["BEGIN", "ROLLBACK"], marker=b"paused\n")

    def test_postcommit_cancellation_is_context_of_post_close_fault_with_original_retained(self):
        self.cancellation_pair(point="allocation-after-commit", retained=1, allocations=1,
                               transactions=["BEGIN", "COMMIT"], marker=b"paused\n")

    def test_native_setup_authorizer_error_is_context_before_observer_installation(self):
        terminal = KeyboardInterrupt("synthetic-selected-terminal-cancellation")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(terminal, deny_setup=True)
        primary = self.primary_at_close[0]
        self.assertIs(type(primary), sqlite3.DatabaseError)
        self.assertEqual(primary.sqlite_errorcode, sqlite3.SQLITE_AUTH)
        self.assertIsNone(primary.__context__)
        self.assert_chain(caught, terminal, primary)
        self.assert_output()
        self.assert_state(allocations=0, transactions=[], retained=0, observed=False)

    def output_pair(self, *, lose_line=None, fail_flush=None, revision=0, lines=0):
        terminal = KeyboardInterrupt("synthetic-selected-terminal-cancellation")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(terminal, lose_line=lose_line, fail_flush=fail_flush, revision=revision)
        primary = self.output.failure
        self.assertIsNotNone(primary)
        self.assert_chain(caught, terminal, primary)
        if lose_line is not None:
            self.assertIs(type(primary), BrokenPipeError)
            self.assertEqual(primary.errno, errno.EPIPE)
        else:
            self.assertIs(type(primary), OSError)
            self.assertEqual(primary.errno, errno.EIO)
        if revision:
            self.assertIs(type(primary.__context__), source.StoreRefused)
            self.assertIsNone(primary.__context__.__context__)
            self.assertIsNone(primary.__context__.__cause__)
            self.assertFalse(primary.__context__.__suppress_context__)
        else:
            self.assertIsNone(primary.__context__)
        self.assert_output(lines=lines)
        self.assert_state(allocations=1, transactions=["BEGIN", "ROLLBACK" if revision else "COMMIT"],
                          retained=0 if revision else 1)

    def test_native_first_reply_fault_is_context_with_one_committed_original(self):
        self.output_pair(lose_line=1)

    def test_native_refusal_output_fault_preserves_three_object_chain_without_charge(self):
        self.output_pair(lose_line=1, revision=1)

    def test_native_report_fault_keeps_first_reply_and_primary_exception_context(self):
        self.output_pair(lose_line=2, lines=1)

    def test_selected_reply_flush_fault_keeps_delivered_record_and_primary_context(self):
        self.output_pair(fail_flush=1, lines=1)

    def test_selected_report_flush_fault_keeps_report_without_normal_completion(self):
        self.output_pair(fail_flush=2, lines=2)

    def test_already_disposed_cancellation_skips_selected_terminal_fault(self):
        primary = KeyboardInterrupt("synthetic-selected-disposed-primary")
        terminal = OSError(errno.EIO, "synthetic-selected-unreached-terminal")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(terminal, cancellation=primary, point="allocation-written", rollback_denials=2)
        self.assertIs(caught.exception, primary)
        self.assertEqual(self.primary_at_close, [])
        self.assertIsNone(terminal.__context__)
        self.assertIsNone(terminal.__cause__)
        self.assertFalse(terminal.__suppress_context__)
        self.assert_output(marker=b"paused\n")
        self.assert_state(allocations=1, transactions=["BEGIN", "ROLLBACK", "ROLLBACK"], retained=0,
                          closes=0, errors=[dict(phase="rollback", code=None)] * 2)
