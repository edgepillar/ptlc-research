"""Pure record transitions use synthetic claims, not cryptographic certificates."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from offline_session import completion, exchange, observation_evidence as evidence
from offline_session import observation_records as records
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from completion_test_support import final_signatures, released_bob
from exchange_test_support import prepare


class ObservationRecordTests(unittest.TestCase):
    profile = "11" * 32

    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.signature = final_signatures()[0]
        cls.unresolved = evidence.unknown_statement(cls.state, cls.signature, verifier_profile_digest_hex=cls.profile)
        cls.fields = json.loads(cls.unresolved)
        del cls.fields["outcome"]
        cls.key = cls.fields["evidence_key_hex"]
        cls.empty = records.create(verifier_profile_digest_hex=cls.profile, attempt_limit=4, target_limit=2)
        cls.pending, cls.first = records.begin(cls.empty, cls.state, cls.signature,
                                               expected_verifier_profile_digest_hex=cls.profile)
        cls.unknown = records.interrupt(cls.pending, cls.first, expected_verifier_profile_digest_hex=cls.profile)
        cls.normal = records.finish(cls.pending, cls.state, cls.signature, cls.first,
            exchange.canonical(dict(cls.fields, outcome="verified")), expected_verifier_profile_digest_hex=cls.profile)
        cls.rechecking, cls.second = records.begin(cls.normal, cls.state, cls.signature, recheck=True,
                                                  expected_verifier_profile_digest_hex=cls.profile)
        cls.conflicting = records.finish(cls.rechecking, cls.state, cls.signature, cls.second,
            exchange.canonical(dict(cls.fields, outcome="rejected")), expected_verifier_profile_digest_hex=cls.profile)

    def create(self, attempts=4, targets=2):
        return records.create(verifier_profile_digest_hex=self.profile, attempt_limit=attempts, target_limit=targets)

    def inspect(self, wire):
        return records.inspect(wire, expected_verifier_profile_digest_hex=self.profile)

    def begin(self, wire, signature=None, **options):
        return records.begin(wire, self.state, self.signature if signature is None else signature,
                             expected_verifier_profile_digest_hex=self.profile, **options)

    def finish(self, wire, attempt, outcome, **options):
        statement = exchange.canonical(dict(self.fields, outcome=outcome))
        return records.finish(wire, self.state, self.signature, attempt, statement,
                               expected_verifier_profile_digest_hex=self.profile, **options)

    def interrupt(self, wire, attempt):
        return records.interrupt(wire, attempt, expected_verifier_profile_digest_hex=self.profile)

    def known(self, wire, signature=None):
        return records.known_statement(wire, self.state, self.signature if signature is None else signature,
                                       expected_verifier_profile_digest_hex=self.profile)

    def assert_rejected(self, value):
        with self.assertRaises(records.RecordError):
            self.inspect(exchange.canonical(value))

    def synthetic_target(self, tag):
        """Normalized target oracle for finite quota tests only; no new math."""
        fields = dict(self.fields, binding_digest_hex=hashlib.sha256(bytes([tag])).hexdigest())
        material = exchange.canonical({"binding_digest_hex": fields["binding_digest_hex"],
                                       "predicate": evidence.PREDICATE, "verifier_profile_digest_hex": self.profile})
        fields["evidence_key_hex"] = hashlib.sha256(b"PTLC/observation-evidence-key/v1\x00" + material).hexdigest()
        return fields

    def test_empty_canonical_value_has_no_attempts_targets_or_verdicts(self):
        self.assertEqual(self.empty, exchange.canonical(json.loads(self.empty)))
        summary = self.inspect(self.empty)
        self.assertEqual(summary, records.RecordSummary(0, 0, 4, 0, 2, 0, 0, 0, 0))
        self.assertIsNone(self.known(self.empty))

    def test_begin_charges_and_identifies_pending_work_before_any_verdict(self):
        value = json.loads(self.pending)
        self.assertEqual(self.first, 1)
        self.assertEqual(value["attempts"], [{"id": 1, "evidence_key_hex": self.key, "recheck": False,
            "started_revision": 1, "finished_revision": None, "outcome": None}])
        self.assertEqual(value["targets"], {self.key: self.fields})
        self.assertEqual(self.inspect(self.pending), records.RecordSummary(1, 1, 3, 1, 1, 1, 0, 0, 0))
        self.assertIsNone(self.known(self.pending))

    def test_pending_duplicate_is_busy_and_original_bytes_remain_unchanged(self):
        before = self.pending
        with self.assertRaises(records.RecordBusy):
            self.begin(before)
        self.assertEqual(before, self.pending)

    def test_unknown_is_finished_history_and_never_refunds_consumption(self):
        self.assertEqual(self.inspect(self.unknown), records.RecordSummary(2, 1, 3, 1, 1, 0, 0, 0, 0))
        self.assertIsNone(self.known(self.unknown))
        pending, second = self.begin(self.unknown)
        self.assertEqual(second, 2)
        self.assertEqual(self.inspect(pending).attempts_consumed, 2)
        self.assertEqual(self.inspect(pending).targets, 1)

    def test_exact_normal_claim_roundtrip_uses_existing_statement_schema(self):
        self.assertEqual(self.known(self.normal), exchange.canonical(dict(self.fields, outcome="verified")))
        parsed = evidence.parse_statement(self.state, self.signature, self.known(self.normal),
                                         expected_verifier_profile_digest_hex=self.profile)
        self.assertEqual(parsed.outcome, "verified")
        self.assertEqual(self.inspect(self.normal), records.RecordSummary(2, 1, 3, 1, 1, 0, 1, 0, 0))

    def test_negative_normal_claim_remains_separate_from_unknown_history(self):
        rejected = self.finish(self.pending, self.first, "rejected")
        self.assertEqual(json.loads(self.known(rejected))["outcome"], "rejected")
        self.assertEqual(self.inspect(rejected).rejected_claims, 1)
        self.assertNotEqual(rejected, self.unknown)

    def test_known_claim_requires_explicit_recheck_without_deleting_history(self):
        with self.assertRaises(records.RecordKnown):
            self.begin(self.normal)
        self.assertEqual(self.inspect(self.rechecking).attempts_consumed, 2)
        self.assertEqual(self.inspect(self.rechecking).pending_attempts, 1)
        self.assertEqual(self.known(self.rechecking), self.known(self.normal))

    def test_recheck_is_exact_bool_and_requires_prior_normal_claim(self):
        for choice in (None, 0, 1, "yes"):
            with self.subTest(choice=choice), self.assertRaises(records.RecordError):
                self.begin(self.empty, recheck=choice)
        for wire in (self.empty, self.unknown):
            with self.assertRaises(records.RecordError):
                self.begin(wire, recheck=True)

    def test_unknown_recheck_preserves_prior_normal_claim_and_both_attempts(self):
        value = self.interrupt(self.rechecking, self.second)
        self.assertEqual(self.known(value), self.known(self.normal))
        self.assertEqual(self.inspect(value).attempts_consumed, 2)
        self.assertEqual(self.inspect(value).verified_claims, 1)
        self.assertEqual([item["outcome"] for item in json.loads(value)["attempts"]], ["verified", "unknown"])

    def test_same_normal_recheck_retains_two_charged_attempts_and_one_claim(self):
        value = self.finish(self.rechecking, self.second, "verified")
        self.assertEqual(self.known(value), self.known(self.normal))
        self.assertEqual(self.inspect(value).attempts_consumed, 2)
        self.assertEqual([item["outcome"] for item in json.loads(value)["attempts"]], ["verified", "verified"])

    def test_conflicting_normal_results_are_retained_and_cannot_be_selected_or_retried(self):
        value = json.loads(self.conflicting)
        self.assertEqual([item["outcome"] for item in value["attempts"]], ["verified", "rejected"])
        self.assertEqual(self.inspect(self.conflicting).conflicting_targets, 1)
        self.assertEqual(self.inspect(self.conflicting).verified_claims, 0)
        self.assertEqual(self.inspect(self.conflicting).rejected_claims, 0)
        with self.assertRaises(records.RecordConflict):
            self.known(self.conflicting)
        with self.assertRaises(records.RecordConflict):
            self.begin(self.conflicting, recheck=True)

    def test_finished_attempt_rejects_duplicate_late_result_or_interruption(self):
        for wire in (self.normal, self.unknown):
            with self.assertRaises(records.RecordClosed):
                self.finish(wire, self.first, "rejected")
            with self.assertRaises(records.RecordClosed):
                self.interrupt(wire, self.first)

    def test_malformed_result_leaves_pending_attempt_charged_for_explicit_unknown(self):
        for statement in (b"{}", b"{", b"", self.unresolved + b"\n"):
            with self.subTest(statement=statement), self.assertRaises(records.RecordError):
                records.finish(self.pending, self.state, self.signature, self.first, statement,
                                expected_verifier_profile_digest_hex=self.profile)
        self.assertEqual(self.inspect(self.pending).pending_attempts, 1)
        self.assertEqual(self.inspect(self.pending).attempts_consumed, 1)
        self.assertEqual(self.interrupt(self.pending, self.first), self.unknown)

    def test_result_for_other_signature_is_not_admitted_to_this_attempt(self):
        other = evidence.unknown_statement(self.state, bytes(64), verifier_profile_digest_hex=self.profile)
        with self.assertRaises(records.RecordError):
            records.finish(self.pending, self.state, bytes(64), self.first, other,
                            expected_verifier_profile_digest_hex=self.profile)
        self.assertIsNone(self.known(self.normal, bytes(64)))

    def test_profile_is_supplied_locally_and_wrong_profiles_reject_before_target_work(self):
        with patch.object(records, "_target", side_effect=AssertionError("unexpected target preparation")):
            for profile in ("22" * 32, "AA" * 32, bytes(32), None, "11" * 32 + "\n"):
                with self.subTest(profile_type=type(profile).__name__), self.assertRaises(records.RecordError):
                    records.begin(self.normal, self.state, self.signature,
                                  expected_verifier_profile_digest_hex=profile)

    def test_invalid_attempt_identifiers_are_rejected_without_state_changes(self):
        for number in (True, False, 0, -1, 2, 1.0, "1", None):
            with self.subTest(number=number), self.assertRaises(records.RecordError):
                self.interrupt(self.pending, number)
        self.assertEqual(self.inspect(self.pending).revision, 1)

    def test_limit_configuration_uses_exact_bounded_integers(self):
        for limit in (True, False, 0, -1, 65, 1.0, "1", None):
            for field in ("attempt_limit", "target_limit"):
                options = dict(verifier_profile_digest_hex=self.profile, attempt_limit=4, target_limit=2)
                options[field] = limit
                with self.subTest(field=field, limit=limit), self.assertRaises(records.RecordError):
                    records.create(**options)

    def test_attempt_limit_covers_pending_unknown_and_normal_and_rejects_before_preparation(self):
        for outcome in (None, "unknown", "verified", "rejected"):
            with self.subTest(outcome=outcome):
                with patch.object(records, "_target", return_value=self.fields):
                    wire, attempt = self.begin(self.create(attempts=1))
                if outcome == "unknown":
                    wire = self.interrupt(wire, attempt)
                elif outcome is not None:
                    wire = self.finish(wire, attempt, outcome)
                with patch.object(records, "_target", side_effect=AssertionError("unexpected preparation")):
                    with self.assertRaises(records.RecordExhausted):
                        self.begin(wire)
                self.assertEqual(self.inspect(wire).attempts_consumed, 1)
                if outcome in ("verified", "rejected"):
                    self.assertEqual(json.loads(self.known(wire))["outcome"], outcome)

    def test_exact_maximum_attempts_remain_charged_after_canonical_roundtrip(self):
        wire = self.create(attempts=64, targets=1)
        with patch.object(records, "_target", return_value=self.fields):
            for number in range(1, 65):
                wire, attempt = self.begin(wire)
                self.assertEqual(attempt, number)
                wire = self.interrupt(wire, attempt)
        self.assertEqual(self.inspect(wire), records.RecordSummary(128, 64, 0, 1, 0, 0, 0, 0, 0))
        self.assertLess(len(wire), records.MAX_RECORD_BYTES)
        with self.assertRaises(records.RecordExhausted):
            self.begin(bytes(wire))

    def test_target_limit_retains_old_targets_and_permits_unknown_retry(self):
        wire = self.create(attempts=4, targets=1)
        first, second = self.synthetic_target(1), self.synthetic_target(2)
        with patch.object(records, "_target", return_value=first):
            wire, attempt = self.begin(wire)
        wire = self.interrupt(wire, attempt)
        with patch.object(records, "_target", return_value=second), self.assertRaises(records.RecordExhausted):
            self.begin(wire)
        with patch.object(records, "_target", return_value=first):
            wire, attempt = self.begin(wire)
        self.assertEqual(attempt, 2)
        self.assertEqual(self.inspect(wire).targets, 1)

    def test_distinct_pending_targets_have_independent_ids_and_can_finish_out_of_start_order(self):
        with patch.object(records, "_target", side_effect=[self.synthetic_target(1), self.synthetic_target(2)]):
            wire, first = self.begin(self.empty)
            wire, second = self.begin(wire)
        wire = self.interrupt(wire, second)
        wire = self.interrupt(wire, first)
        attempts = json.loads(wire)["attempts"]
        self.assertEqual([item["started_revision"] for item in attempts], [1, 2])
        self.assertEqual([item["finished_revision"] for item in attempts], [4, 3])
        self.assertEqual(self.inspect(wire).attempts_consumed, 2)

    def test_missing_extra_or_changed_top_fields_are_rejected(self):
        original = json.loads(self.normal)
        for field in original:
            changed = copy.deepcopy(original)
            del changed[field]
            self.assert_rejected(changed)
        for field, value in (("schema", "other-v1"), ("revision", True), ("revision", 3),
                             ("attempt_limit", 0), ("target_limit", 0), ("attempts", {}), ("targets", [])):
            changed = dict(original, **{field: value})
            self.assert_rejected(changed)
        self.assert_rejected(dict(original, source="synthetic"))

    def test_missing_extra_or_changed_target_fields_and_key_are_rejected(self):
        original = json.loads(self.normal)
        for field in self.fields:
            changed = copy.deepcopy(original)
            del changed["targets"][self.key][field]
            self.assert_rejected(changed)
            changed = copy.deepcopy(original)
            changed["targets"][self.key][field] = True
            self.assert_rejected(changed)
        changed = copy.deepcopy(original)
        changed["targets"][self.key]["authority"] = "synthetic"
        self.assert_rejected(changed)
        changed = copy.deepcopy(original)
        changed["targets"][self.key]["binding_digest_hex"] = "22" * 32
        self.assert_rejected(changed)

    def test_attempt_shape_terminal_fields_and_temporal_constraints_are_rejected(self):
        original = json.loads(self.normal)
        for field in original["attempts"][0]:
            changed = copy.deepcopy(original)
            del changed["attempts"][0][field]
            self.assert_rejected(changed)
        for field, value in (("id", True), ("id", 2), ("recheck", True), ("recheck", 1),
                             ("evidence_key_hex", "22" * 32), ("started_revision", 0),
                             ("finished_revision", 1), ("finished_revision", None), ("outcome", "other"),
                             ("outcome", None), ("outcome", False)):
            changed = copy.deepcopy(original)
            changed["attempts"][0][field] = value
            self.assert_rejected(changed)

    def test_import_replays_order_to_reject_overlap_gap_and_finish_before_start(self):
        original = json.loads(self.rechecking)
        changed = copy.deepcopy(original)
        changed["attempts"][0]["finished_revision"] = 3
        changed["attempts"][1]["started_revision"] = 2
        self.assert_rejected(changed)
        changed = copy.deepcopy(original)
        changed["attempts"][1]["started_revision"] = 4
        changed["revision"] = 4
        self.assert_rejected(changed)
        changed = copy.deepcopy(original)
        changed["attempts"][1]["recheck"] = False
        self.assert_rejected(changed)
        changed = json.loads(self.conflicting)
        changed["attempts"].append({"id": 3, "evidence_key_hex": self.key, "recheck": True,
                                    "started_revision": 5, "finished_revision": None, "outcome": None})
        changed["revision"] = 5
        self.assert_rejected(changed)

    def test_unreferenced_target_and_truncated_history_are_rejected(self):
        changed = json.loads(self.normal)
        other = self.synthetic_target(3)
        changed["targets"][other["evidence_key_hex"]] = other
        self.assert_rejected(changed)
        changed = json.loads(self.normal)
        changed["attempts"] = []
        changed["revision"] = 0
        self.assert_rejected(changed)

    def test_noncanonical_duplicate_nonascii_oversized_and_unsupported_input_is_rejected(self):
        variants = (b"", b"{", b"null", b"[]", b"\xff", self.empty + b"\n", b" " + self.empty,
                    json.dumps(json.loads(self.empty)).encode("ascii"), bytearray(self.empty),
                    b"x" * (records.MAX_RECORD_BYTES + 1),
                    self.empty[:-1] + b',"revision":0}')
        for index, wire in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(records.RecordError):
                self.inspect(wire)

    def test_hostile_bytes_subclass_does_not_execute_custom_decode_or_length(self):
        class Hostile(bytes):
            def __len__(self):
                raise AssertionError("unexpected length override")
            def decode(self, *args, **kwargs):
                raise AssertionError("unexpected decode override")
        with self.assertRaises(records.RecordError):
            self.inspect(Hostile(self.empty))

    def test_invalid_local_signature_or_state_is_rejected_without_mutating_records(self):
        for signature in (None, bytearray(64), bytes(63), bytes(65)):
            with self.subTest(signature_type=type(signature).__name__), self.assertRaises(records.RecordError):
                records.begin(self.empty, self.state, signature, expected_verifier_profile_digest_hex=self.profile)
        with self.assertRaises(records.RecordError):
            records.begin(self.empty, {}, self.signature, expected_verifier_profile_digest_hex=self.profile)
        self.assertEqual(self.inspect(self.empty).attempts_consumed, 0)

    def test_summary_is_immutable_and_inspection_does_not_prepare_targets(self):
        with patch.object(records, "_target", side_effect=AssertionError("unexpected target preparation")):
            summary = self.inspect(self.normal)
        with self.assertRaises(FrozenInstanceError):
            summary.attempts_consumed = 0

    def test_pure_transitions_and_lookup_open_no_files_or_workers(self):
        with patch("builtins.open", side_effect=AssertionError("unexpected file open")), \
                patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected worker")):
            wire, attempt = self.begin(self.empty)
            wire = self.finish(wire, attempt, "verified")
            self.assertEqual(json.loads(self.known(wire))["outcome"], "verified")
            self.assertEqual(self.inspect(wire).attempts_consumed, 1)

    def test_forged_matching_positive_is_only_a_claim_and_roundtrip_supplies_no_trust(self):
        invalid = bytes(64)
        forged = json.loads(evidence.unknown_statement(self.state, invalid, verifier_profile_digest_hex=self.profile))
        forged["outcome"] = "verified"
        wire, attempt = self.begin(self.empty, invalid)
        wire = records.finish(wire, self.state, invalid, attempt, exchange.canonical(forged),
                               expected_verifier_profile_digest_hex=self.profile)
        self.assertEqual(json.loads(self.known(bytes(wire), invalid))["outcome"], "verified")
        self.assertEqual(self.inspect(wire).verified_claims, 1)

    def test_valid_old_snapshot_restore_replenishes_pure_quota_without_an_external_owner(self):
        wire = self.create(attempts=1)
        saved = bytes(wire)
        wire, attempt = self.begin(wire)
        wire = self.interrupt(wire, attempt)
        with self.assertRaises(records.RecordExhausted):
            self.begin(wire)
        restored, attempt = self.begin(saved)
        self.assertEqual(attempt, 1)
        self.assertEqual(self.inspect(restored).attempts_consumed, 1)

    def test_record_operations_preserve_reopened_exhausted_recovery_journal(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-record-no-admission-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                session = prepare(journal, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, invalid, recoverer=lambda _: None)
            with Journal.open(base / "state", base / "head.json") as journal:
                state = journal.get_exchange(session)
                before = (copy.deepcopy(journal._state), journal._sequence,
                          (base / "state/journal.sqlite3").read_bytes(), (base / "head.json").read_bytes())
                wire, attempt = records.begin(self.empty, state, self.signature,
                                               expected_verifier_profile_digest_hex=self.profile)
                wire = records.finish(wire, state, self.signature, attempt,
                    exchange.canonical(dict(self.fields, outcome="verified")), expected_verifier_profile_digest_hex=self.profile)
                records.known_statement(wire, state, self.signature, expected_verifier_profile_digest_hex=self.profile)
                self.assertEqual((journal._state, journal._sequence,
                    (base / "state/journal.sqlite3").read_bytes(), (base / "head.json").read_bytes()), before)
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, evidence.prepare(state, self.signature).candidate_packet,
                        expected_observation_digest=completion.observation_digest(invalid),
                        recoverer=lambda request: calls.append(request))
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
