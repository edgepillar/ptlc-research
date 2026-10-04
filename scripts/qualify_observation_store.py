"""Actual public workers in separate owned disk records, with synthetic targets.

Entry-file measurement selects offline test builds, not production enrollment.
This qualifies local storage ordering, not a source, live chain, signing worker,
power loss, orphan containment, paired rollback or funded recovery policy.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from offline_session import completion, exchange, observation_records as records
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.observation_store import ObservationStore
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import final_signatures
from exchange_test_support import prepare
from observation_store_test_support import STORE_ID


class RealStoreTests(unittest.TestCase):
    verifier = None
    completer = None
    observer = None
    interrupted_observer = None
    observation_path = None

    @classmethod
    def setUpClass(cls):
        cls.signature = final_signatures()[0]
        assert cls.observer.profile_digest_hex == cls.interrupted_observer.profile_digest_hex
        with tempfile.TemporaryDirectory(prefix="synthetic-store-source-") as directory:
            base = Path(directory)
            with Journal.open(base / "source", base / "source-head.json") as journal:
                session = prepare(journal, verifier=cls.verifier)
                journal.release_exchange_zenon(session)
                cls.state = journal.get_exchange(session)

    def open(self, base, *, limit=3, observer=None):
        return ObservationStore.open(base / "evidence", base / "evidence-head.json",
            store_id_hex=STORE_ID, verifier=self.observer if observer is None else observer,
            attempt_limit=limit, target_limit=2)

    def test_actual_positive_negative_are_committed_and_reused_after_restart_without_more_work(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-store-normal-") as directory:
            base = Path(directory)
            with self.open(base, limit=2) as store:
                for signature, outcome in ((self.signature, "verified"), (bytes(64), "rejected")):
                    self.assertEqual(json.loads(store.observe(self.state, signature))["outcome"], outcome)
                self.assertEqual(store.summary().attempts_remaining, 0)
            with self.open(base, limit=2) as store, patch.object(SubprocessObservation, "observe_owned") as worker:
                self.assertEqual(json.loads(store.known_statement(self.state, self.signature))["outcome"], "verified")
                self.assertEqual(json.loads(store.known_statement(self.state, bytes(64)))["outcome"], "rejected")
                with self.assertRaises(records.RecordExhausted):
                    store.observe(self.state, self.signature, recheck=True)
                worker.assert_not_called()

    def test_actual_deadline_unknown_retry_and_recheck_survive_each_reopen_and_preserve_normal(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-store-unknown-") as directory:
            base = Path(directory)
            with self.open(base, observer=self.interrupted_observer) as store:
                self.assertEqual(json.loads(store.observe(self.state, self.signature))["outcome"], "unknown")
            with self.open(base) as store:
                normal = store.observe(self.state, self.signature)
                self.assertEqual(json.loads(normal)["outcome"], "verified")
            with self.open(base, observer=self.interrupted_observer) as store:
                self.assertEqual(json.loads(store.observe(self.state, self.signature, recheck=True))["outcome"], "unknown")
                self.assertEqual(store.known_statement(self.state, self.signature), normal)
            with self.open(base) as store:
                self.assertEqual(store.summary().attempts_consumed, 3)
                self.assertEqual(store.summary().pending_attempts, 0)
                self.assertEqual(store.known_statement(self.state, self.signature), normal)

    def test_actual_success_lost_before_result_commit_recovers_unknown_without_replaying_worker(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-store-result-death-") as directory:
            base = Path(directory)
            with self.open(base, limit=2):
                pass
            target = base / "public-target.json"
            target.write_bytes(exchange.canonical({"state": self.state, "signature_hex": self.signature.hex()}))
            marker = base / "completed-work"
            actor = ROOT / "tests/observation_store_actor.py"
            child = subprocess.Popen([sys.executable, "-B", str(actor), "crash", str(base / "evidence"),
                str(base / "evidence-head.json"), "--actual-observation", str(self.observation_path),
                "--target", str(target), "--marker", str(marker), "--point", "worker.returned"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=15), "actual worker actor did not reach result boundary")
                self.assertEqual(child.stdout.readline().strip(), b"paused")
                child.kill()
                _, diagnostics = child.communicate(timeout=10)
                self.assertEqual((child.returncode, diagnostics), (-signal.SIGKILL, b""))
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=10)
            with self.open(base, limit=2) as store, patch.object(SubprocessObservation, "observe_owned") as worker:
                self.assertEqual(store.summary().attempts_consumed, 1)
                self.assertEqual(store.summary().pending_attempts, 0)
                self.assertIsNone(store.known_statement(self.state, self.signature))
                worker.assert_not_called()
            self.assertEqual(marker.read_bytes(), b"verified")

    def test_changed_actual_entry_is_unknown_and_charged_without_launch(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-store-entry-change-") as directory:
            base = Path(directory)
            entry = base / "public-worker"
            shutil.copy2(self.observation_path, entry)
            observer = SubprocessObservation(entry, expected_executable_sha256_hex=_file_digest(entry))
            with self.open(base, observer=observer) as store:
                with entry.open("ab") as output:
                    output.write(b"synthetic entry change")
                with patch("offline_session.observation_verifier.run_guarded_public_worker",
                           side_effect=AssertionError("changed entry launched")) as worker:
                    self.assertEqual(json.loads(store.observe(self.state, self.signature))["outcome"], "unknown")
                    worker.assert_not_called()
            with self.open(base, observer=observer) as store:
                self.assertEqual(store.summary().attempts_consumed, 1)
                self.assertIsNone(store.known_statement(self.state, self.signature))

    def test_owned_actual_positive_leaves_reopened_exhausted_recovery_journal_exactly_unchanged(self):
        from offline_session.observation_evidence import prepare as target
        with tempfile.TemporaryDirectory(prefix="synthetic-store-exhaustion-") as directory:
            base = Path(directory)
            with Journal.open(base / "source", base / "source-head.json") as journal:
                session = prepare(journal, verifier=self.verifier, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, invalid, recoverer=self.completer)
            with Journal.open(base / "source", base / "source-head.json") as journal:
                state = journal.get_exchange(session)
                before = (copy.deepcopy(journal._state), journal._sequence,
                    (base / "source/journal.sqlite3").read_bytes(), (base / "source-head.json").read_bytes())
                with self.open(base) as store:
                    statement = store.observe(state, self.signature)
                    self.assertEqual(json.loads(statement)["outcome"], "verified")
                with self.open(base) as store:
                    self.assertEqual(store.known_statement(state, self.signature), statement)
                self.assertEqual((journal._state, journal._sequence,
                    (base / "source/journal.sqlite3").read_bytes(), (base / "source-head.json").read_bytes()), before)
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, target(state, self.signature).candidate_packet,
                        expected_observation_digest=completion.observation_digest(invalid),
                        recoverer=lambda request: calls.append(request))
                self.assertEqual(calls, [])


def main():
    parser = argparse.ArgumentParser(description="Qualify separately owned observation records with selected public workers")
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--completion", required=True)
    parser.add_argument("--observation", required=True)
    options = parser.parse_args()
    path = Path(options.observation).resolve()
    digest = _file_digest(path)
    RealStoreTests.verifier = SubprocessVerifier(Path(options.verifier).resolve())
    RealStoreTests.completer = SubprocessCompletion(Path(options.completion).resolve())
    RealStoreTests.observer = SubprocessObservation(path, expected_executable_sha256_hex=digest)
    RealStoreTests.interrupted_observer = SubprocessObservation(path,
        expected_executable_sha256_hex=digest, timeout=0.000001)
    RealStoreTests.observation_path = path
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealStoreTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
