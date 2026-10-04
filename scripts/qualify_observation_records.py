"""Actual public-worker verdicts in pure records, with no persistent cache.

Canonical roundtrip is not disk/restart evidence. Entry hashes are measured from
explicitly selected offline builds, not trusted production enrollment. All state
and signatures are public synthetic fixtures; no secret signer is connected.
"""

import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from offline_session import completion, observation_records as records
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import final_signatures
from exchange_test_support import prepare


class RealRecordTests(unittest.TestCase):
    verifier = None
    completer = None
    observer = None
    interrupted_observer = None

    @classmethod
    def setUpClass(cls):
        cls.signature = final_signatures()[0]
        cls.profile = cls.observer.profile_digest_hex
        assert cls.interrupted_observer.profile_digest_hex == cls.profile
        with tempfile.TemporaryDirectory(prefix="synthetic-record-source-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                session = prepare(journal, verifier=cls.verifier)
                journal.release_exchange_zenon(session)
                cls.state = journal.get_exchange(session)

    def create(self, limit=4):
        return records.create(verifier_profile_digest_hex=self.profile, attempt_limit=limit, target_limit=2)

    def inspect(self, wire):
        return records.inspect(wire, expected_verifier_profile_digest_hex=self.profile)

    def run_attempt(self, wire, signature, *, state=None, interrupted=False, recheck=False):
        state = self.state if state is None else state
        wire, attempt = records.begin(wire, state, signature,
                                      expected_verifier_profile_digest_hex=self.profile, recheck=recheck)
        self.assertGreater(self.inspect(wire).pending_attempts, 0)
        self.assertEqual(self.inspect(wire).attempts_consumed, attempt)
        worker = self.interrupted_observer if interrupted else self.observer
        statement = worker(state, signature)
        wire = records.finish(wire, state, signature, attempt, statement,
                               expected_verifier_profile_digest_hex=self.profile)
        return wire, json.loads(statement)["outcome"]

    def test_actual_positive_and_negative_claims_roundtrip_without_implicit_worker_calls(self):
        for signature, outcome in ((self.signature, "verified"), (bytes(64), "rejected")):
            with self.subTest(outcome=outcome):
                wire, result = self.run_attempt(self.create(), signature)
                self.assertEqual(result, outcome)
                roundtrip = bytes(wire)
                known = records.known_statement(roundtrip, self.state, signature,
                                                 expected_verifier_profile_digest_hex=self.profile)
                self.assertEqual(json.loads(known)["outcome"], outcome)
                self.assertEqual(self.inspect(roundtrip).attempts_consumed, 1)
                with self.assertRaises(records.RecordKnown):
                    records.begin(roundtrip, self.state, signature, expected_verifier_profile_digest_hex=self.profile)
                self.assertEqual(self.inspect(roundtrip).attempts_consumed, 1)

    def test_actual_unknown_retry_and_recheck_keep_normal_claim_and_exhaust_attempt_limit(self):
        # A deliberately tiny configured deadline exercises the actual process
        # failure channel. This is not a throughput or hard wall-time claim.
        wire, outcome = self.run_attempt(self.create(limit=3), self.signature, interrupted=True)
        self.assertEqual(outcome, "unknown")
        self.assertEqual(self.inspect(wire).verified_claims, 0)
        wire, outcome = self.run_attempt(wire, self.signature)
        self.assertEqual(outcome, "verified")
        known = records.known_statement(wire, self.state, self.signature,
                                        expected_verifier_profile_digest_hex=self.profile)
        wire, outcome = self.run_attempt(wire, self.signature, interrupted=True, recheck=True)
        self.assertEqual(outcome, "unknown")
        self.assertEqual(self.inspect(wire).attempts_consumed, 3)
        self.assertEqual(records.known_statement(wire, self.state, self.signature,
                         expected_verifier_profile_digest_hex=self.profile), known)
        self.assertEqual([item["outcome"] for item in json.loads(wire)["attempts"]], ["unknown", "verified", "unknown"])
        with self.assertRaises(records.RecordExhausted):
            records.begin(wire, self.state, self.signature, recheck=True,
                          expected_verifier_profile_digest_hex=self.profile)

    def test_actual_other_target_verdict_cannot_finish_the_pending_attempt(self):
        wire, attempt = records.begin(self.create(), self.state, self.signature,
                                      expected_verifier_profile_digest_hex=self.profile)
        other = self.observer(self.state, bytes(64))
        self.assertEqual(json.loads(other)["outcome"], "rejected")
        with self.assertRaises(records.RecordError):
            records.finish(wire, self.state, bytes(64), attempt, other,
                           expected_verifier_profile_digest_hex=self.profile)
        self.assertEqual(self.inspect(wire).pending_attempts, 1)
        self.assertEqual(self.inspect(wire).attempts_consumed, 1)
        wire = records.interrupt(wire, attempt, expected_verifier_profile_digest_hex=self.profile)
        self.assertEqual(self.inspect(wire).rejected_claims, 0)

    def test_real_recorded_positive_preserves_reopened_exhausted_recovery_journal(self):
        from offline_session.observation_evidence import prepare as target
        with tempfile.TemporaryDirectory(prefix="synthetic-record-exhaustion-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                session = prepare(journal, verifier=self.verifier, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, invalid, recoverer=self.completer)
            with Journal.open(base / "state", base / "head.json") as journal:
                state = journal.get_exchange(session)
                before = (copy.deepcopy(journal._state), journal._sequence,
                    (base / "state/journal.sqlite3").read_bytes(), (base / "head.json").read_bytes())
                wire, outcome = self.run_attempt(self.create(), self.signature, state=state)
                self.assertEqual(outcome, "verified")
                records.known_statement(wire, state, self.signature, expected_verifier_profile_digest_hex=self.profile)
                self.assertEqual((journal._state, journal._sequence,
                    (base / "state/journal.sqlite3").read_bytes(), (base / "head.json").read_bytes()), before)
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, target(state, self.signature).candidate_packet,
                        expected_observation_digest=completion.observation_digest(invalid),
                        recoverer=lambda request: calls.append(request))
                self.assertEqual(calls, [])


def main():
    parser = argparse.ArgumentParser(description="Qualify pure bounded record transitions with selected public workers")
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--completion", required=True)
    parser.add_argument("--observation", required=True)
    options = parser.parse_args()
    path = Path(options.observation).resolve()
    digest = _file_digest(path)
    RealRecordTests.verifier = SubprocessVerifier(Path(options.verifier).resolve())
    RealRecordTests.completer = SubprocessCompletion(Path(options.completion).resolve())
    RealRecordTests.observer = SubprocessObservation(path, expected_executable_sha256_hex=digest)
    RealRecordTests.interrupted_observer = SubprocessObservation(path,
        expected_executable_sha256_hex=digest, timeout=0.000001)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealRecordTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
