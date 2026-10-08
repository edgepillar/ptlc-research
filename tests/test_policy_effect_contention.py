"""Native contention controls distinguish refusal, unknown and retained rows."""

import json
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import sys
import unittest

import test_policy_effect_store as prior
from qualification import policy_effect_store as source


@unittest.skipUnless(os.name == "posix", "native contention controls require POSIX child processes")
class PolicyEffectContentionTests(prior.PolicyEffectStoreCase):
    def install(self):
        wire = self.wire(max_attempt_limit=1)
        self.store.replace_local_policy(0, wire, active=True)
        return wire

    def request_for(self, slot):
        return self.request("01" if slot == "first" else "03", revision=1,
                            wire=self.wire(max_attempt_limit=1))

    def wait_line(self, child, expected):
        with selectors.DefaultSelector() as selection:
            selection.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selection.select(timeout=10), "synthetic contention cut was not reached")
        self.assertEqual(child.stdout.readline(4097), expected + b"\n")

    def resume(self, child):
        child.stdin.write(b"go\n")
        child.stdin.flush()

    def observed(self, slot="first", pause="plain", buffering="small"):
        actor = Path(__file__).with_name("policy_effect_contention_actor.py")
        child = subprocess.Popen([sys.executable, "-B", str(actor), str(self.path), slot, pause, buffering],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

        self.addCleanup(cleanup)
        self.wait_line(child, b"ready")
        return child

    def finish(self, child, outcome, errors=()):
        output, error = child.communicate(timeout=10)
        self.assertEqual(error, b"")
        self.assertLessEqual(len(output), 4096)
        self.assertEqual(child.returncode, 0 if outcome == "record" else 20)
        row = json.loads(output.decode("ascii"))
        self.assertEqual(set(row), {"outcome", "charge_sequence", "effect_sequence", "native_errors", "transaction_open"})
        self.assertEqual(row["outcome"], outcome)
        self.assertIs(row["transaction_open"], False)
        self.assertEqual(row["native_errors"], list(errors))
        self.assertIsNone(row["effect_sequence"])
        if outcome == "record":
            self.assertEqual(row["charge_sequence"], 2)
        else:
            self.assertIsNone(row["charge_sequence"])
        return row

    def reader(self, case=None):
        case = self if case is None else case
        connection = sqlite3.connect(str(case.path), timeout=0, isolation_level=None)
        self.addCleanup(connection.close)
        connection.execute("BEGIN")
        self.assertEqual(connection.execute("SELECT count(*) FROM operations").fetchone(), (0,))
        self.assertTrue(connection.in_transaction)
        return connection

    def retained(self, slots=(), case=None):
        case = self if case is None else case
        wire = case.wire(max_attempt_limit=1)
        requests = {slot: case.request("01" if slot == "first" else "03", revision=1, wire=wire)
                    for slot in ("first", "second")}
        self.assertEqual(case.store._db.execute("SELECT count(*) FROM operations").fetchone(), (len(slots),))
        self.assertEqual(case.store._db.execute("SELECT count(*) FROM effects").fetchone(), (0,))
        for slot, request in requests.items():
            self.assertEqual(case.store.lookup_original(request) is not None, slot in slots)
        view = case.store.local_view()
        self.assertEqual((view.charged_operations, view.synthetic_effects, view.event_sequence),
                         (len(slots), 0, 1 + len(slots)))
        case.store.close()
        with case.open() as reopened:
            for slot, request in requests.items():
                self.assertEqual(reopened.lookup_original(request) is not None, slot in slots)
            self.assertEqual((reopened.local_view().charged_operations, reopened.local_view().synthetic_effects),
                             (len(slots), 0))

    def test_unchanged_native_actors_can_both_report_unknown_with_zero_charges_under_explicit_reader(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                case = prior.PolicyEffectStoreNativeTests()
                case.setUp()
                self.addCleanup(case.doCleanups)
                wire = case.wire(max_attempt_limit=1)
                case.store.replace_local_policy(0, wire, active=True)
                requests = [case.request(revision=1, wire=wire), case.request("03", revision=1, wire=wire)]
                if reverse:
                    requests.reverse()
                children = [case.actor("allocation", request=request, ready=True) for request in requests]
                holder = self.reader(case)
                for child in children:
                    self.resume(child)
                outcomes = []
                for child in children:
                    output, error = child.communicate(timeout=10)
                    self.assertEqual(error, b"")
                    outcomes.append((child.returncode, output))
                self.assertEqual(outcomes, [(20, b"StoreOutcomeUnknown\n")] * 2)
                holder.execute("ROLLBACK")
                holder.close()
                self.retained(case=case)

    def test_small_cache_reader_reports_busy_after_begin_without_claiming_spill(self):
        self.install()
        child = self.observed(pause="before-first-write")
        self.resume(child)
        self.wait_line(child, b"paused-before-first-write")
        holder = self.reader()
        self.resume(child)
        output, error = child.communicate(timeout=10)
        self.assertEqual((child.returncode, error), (20, b""))
        row = json.loads(output.decode("ascii"))
        self.assertEqual(len(row["native_errors"]), 1)
        native = row["native_errors"][0]
        # The acknowledged cut proves BEGIN and validation already completed.
        # These fixed rows need not force a mid-transaction cache spill.
        self.assertIn(native["phase"], ("event-insert", "operation-insert", "commit"))
        self.assertEqual(native["code"], sqlite3.SQLITE_BUSY)
        self.finish(child, "StoreOutcomeUnknown", (native,))
        holder.execute("ROLLBACK")
        holder.close()
        self.retained()

    def test_observed_commit_busy_is_unknown_without_a_retained_allocation(self):
        self.install()
        child = self.observed(pause="before-commit", buffering="buffered")
        self.resume(child)
        self.wait_line(child, b"paused-before-commit")
        holder = self.reader()
        self.resume(child)
        self.finish(child, "StoreOutcomeUnknown", (dict(phase="commit", code=sqlite3.SQLITE_BUSY),))
        holder.execute("ROLLBACK")
        holder.close()
        self.retained()

    def test_begin_busy_keeps_the_held_winner_and_cannot_exceed_one_charge(self):
        self.install()
        winner = self.observed(pause="before-commit")
        peer = self.observed("second")
        self.resume(winner)
        self.wait_line(winner, b"paused-before-commit")
        self.resume(peer)
        self.finish(peer, "StoreOutcomeUnknown", (dict(phase="begin", code=sqlite3.SQLITE_BUSY),))
        self.resume(winner)
        self.finish(winner, "record")
        self.retained(("first",))

    def test_committed_lost_reply_and_exhausted_peer_can_both_exit_twenty_with_one_charge(self):
        self.install()
        winner = self.observed(pause="lose-after-commit")
        peer = self.observed("second")
        self.resume(winner)
        self.wait_line(winner, b"paused-after-commit")
        self.resume(peer)
        self.finish(peer, "StoreRefused")
        self.resume(winner)
        self.finish(winner, "StoreOutcomeUnknown")
        self.retained(("first",))

    def test_precommit_lost_reply_and_busy_peer_can_both_exit_twenty_with_zero_charges(self):
        self.install()
        winner = self.observed(pause="lose-before-commit")
        peer = self.observed("second")
        self.resume(winner)
        self.wait_line(winner, b"paused-before-commit")
        self.resume(peer)
        self.finish(peer, "StoreOutcomeUnknown", (dict(phase="begin", code=sqlite3.SQLITE_BUSY),))
        self.resume(winner)
        self.finish(winner, "StoreOutcomeUnknown")
        self.retained()

    def test_exact_original_lookup_after_commit_loss_does_not_reallocate_or_apply(self):
        self.install()
        child = self.observed(pause="lose-after-commit")
        self.resume(child)
        self.wait_line(child, b"paused-after-commit")
        self.resume(child)
        self.finish(child, "StoreOutcomeUnknown")
        request = self.request_for("first")
        original = self.store.lookup_original(request)
        self.assertIsNotNone(original)
        self.assertEqual(self.store.lookup_original(request), original)
        self.assertEqual((original.charge_sequence, original.effect_sequence), (2, None))
        self.retained(("first",))

    def test_same_original_peer_after_commit_loss_returns_only_the_retained_charge(self):
        self.install()
        winner = self.observed(pause="lose-after-commit")
        peer = self.observed()
        self.resume(winner)
        self.wait_line(winner, b"paused-after-commit")
        self.resume(peer)
        self.finish(peer, "record")
        self.resume(winner)
        self.finish(winner, "StoreOutcomeUnknown")
        self.retained(("first",))
