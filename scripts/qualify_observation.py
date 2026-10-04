"""Exercise actual public verdicts without selecting observation admission.

Executable hashes are measured from explicitly selected local builds for this
offline exercise only. That test setup is not trusted production enrollment.
All signatures, pins and journal inputs are existing public synthetic fixtures.
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

from offline_session import completion, exchange, observation_evidence as evidence
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.completion_verifier import SubprocessCompletion
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.public_worker import WorkerError, run_public_worker
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import final_signatures
from exchange_test_support import prepare


class RealObservationTests(unittest.TestCase):
    verifier = None
    completer = None
    observer = None

    @classmethod
    def setUpClass(cls):
        cls.signature, cls.bitcoin_signature = final_signatures()
        fields = json.loads((ROOT / "qualification/fixtures/authentication.json").read_text("ascii"))["request"]["context"]
        cls.pins = {field: fields[field] for field in ("alice_auth_key_hex", "bob_auth_key_hex")}
        with tempfile.TemporaryDirectory(prefix="synthetic-observation-source-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                session = prepare(journal, verifier=cls.verifier)
                journal.release_exchange_zenon(session)
                cls.state = journal.get_exchange(session)

    def statement(self, state, signature, worker=None):
        worker = self.observer if worker is None else worker
        raw = worker(state, signature)
        self.assertEqual(exchange.canonical(json.loads(raw)), raw)
        self.assertEqual(set(json.loads(raw)), {"schema", "predicate", "binding_digest_hex", "evidence_key_hex",
                                              "verifier_profile_digest_hex", "request_digest_hex", "outcome"})
        return evidence.parse_statement(state, signature, raw,
                                        expected_verifier_profile_digest_hex=worker.profile_digest_hex)

    def storage(self, journal, base):
        return (copy.deepcopy(journal._state), journal._sequence,
                (base / "state/journal.sqlite3").read_bytes(), (base / "head.json").read_bytes())

    def test_actual_normal_positive_is_bound_to_exact_local_target(self):
        before = copy.deepcopy(self.state)
        statement = self.statement(self.state, self.signature)
        self.assertEqual(statement.outcome, "verified")
        self.assertEqual(statement.evidence_key_hex, evidence.statement_key(self.state, self.signature,
                          verifier_profile_digest_hex=self.observer.profile_digest_hex))
        self.assertEqual(self.state, before)

    def test_actual_invalid_and_foreign_leg_signatures_are_normal_negatives(self):
        for signature in (bytes(64), b"\xff" * 64, self.bitcoin_signature):
            with self.subTest(signature_tag=signature[:1].hex()):
                self.assertEqual(self.statement(self.state, signature).outcome, "rejected")
                target = evidence.prepare(self.state, signature)
                with self.assertRaises(completion.CompletionError):
                    self.completer(json.loads(target.verification_request))

    def test_actual_worker_request_shape_failure_is_unavailable_not_a_negative(self):
        request = json.loads(evidence.prepare(self.state, self.signature).verification_request)
        variants = [b"{}", b"null", b"\xff", b"x" * 65536]
        for field, value in (("kind", "recover-bitcoin"), ("zenon_signature_hex", "00"), ("bitcoin", {})):
            invalid = dict(request, **{field: value})
            variants.append(exchange.canonical(invalid))
        for index, wire in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(WorkerError) as caught:
                run_public_worker(str(self.observer._executable), wire, timeout=5, max_input_bytes=65536)
            self.assertNotIn("observation verdict unavailable", str(caught.exception))

    def test_legacy_positive_and_failure_channels_remain_unknown_under_new_adapter(self):
        legacy = SubprocessObservation(self.completer._executable,
                                      expected_executable_sha256_hex=_file_digest(Path(self.completer._executable)))
        for signature in (self.signature, bytes(64)):
            with self.subTest(signature_tag=signature[:1].hex()):
                self.assertEqual(self.statement(self.state, signature, legacy).outcome, "unknown")

    def test_changed_executable_pin_is_unknown_even_for_known_invalid_signature(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-observation-pin-") as directory:
            entry = Path(directory) / "entry"
            entry.write_text("#!/bin/sh\nexit 2\n", encoding="ascii")
            entry.chmod(0o700)
            worker = SubprocessObservation(entry, expected_executable_sha256_hex=_file_digest(entry))
            entry.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            self.assertEqual(self.statement(self.state, bytes(64), worker).outcome, "unknown")

    def test_real_verdicts_after_reopen_preserve_exhausted_journal_and_pins(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-observation-exhausted-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                session = prepare(journal, verifier=self.verifier, recovery_limit=1, authentication_pins=self.pins)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, invalid, recoverer=self.completer)
            with Journal.open(base / "state", base / "head.json") as journal:
                state = journal.get_exchange(session)
                before = self.storage(journal, base)
                self.assertEqual(self.statement(state, bytes(64)).outcome, "rejected")
                self.assertEqual(self.statement(state, self.signature).outcome, "verified")
                self.assertEqual(self.storage(journal, base), before)
                self.assertEqual(journal.get_session(session)["authentication_pins"], self.pins)
                self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, evidence.prepare(state, self.signature).candidate_packet,
                        expected_observation_digest=completion.observation_digest(invalid),
                        recoverer=lambda request: calls.append(request))
                self.assertEqual(calls, [])
                self.assertEqual(self.storage(journal, base), before)

    def test_normal_positive_cannot_replace_retained_candidate_or_supply_recovery_output(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-observation-no-admission-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                session = prepare(journal, verifier=self.verifier)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, invalid, recoverer=self.completer)
                state = journal.get_exchange(session)
                before = self.storage(journal, base)
                self.assertEqual(self.statement(state, self.signature).outcome, "verified")
                self.assertEqual(self.storage(journal, base), before)
                self.assertEqual(journal.get_exchange(session)["zenon_completion_packet_hex"], invalid.hex())
                self.assertIsNone(journal.get_exchange(session)["superseded_zenon_completion_packet_hex"])
                self.assertIsNone(journal.get_exchange(session)["bitcoin_completion_packet_hex"])


def main():
    parser = argparse.ArgumentParser(description="Qualify exact observation verdicts with selected local public executables")
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--completion", required=True)
    parser.add_argument("--observation", required=True)
    options = parser.parse_args()
    observation = Path(options.observation).resolve()
    RealObservationTests.verifier = SubprocessVerifier(Path(options.verifier).resolve())
    RealObservationTests.completer = SubprocessCompletion(Path(options.completion).resolve())
    RealObservationTests.observer = SubprocessObservation(observation,
        expected_executable_sha256_hex=_file_digest(observation))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealObservationTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
