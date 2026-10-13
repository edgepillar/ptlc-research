"""Retention boundary controls over synthetic actual-cut journal bytes.

Unit fixture workers compare exact requests without signature mathematics.
Native public verification is a separate qualification scope.
"""
import copy
import dataclasses
import json
import unittest
from unittest.mock import patch

import test_nom_journal_hold as previous_tests
from offline_session import nom_capsule as capsule, nom_capsule_continuity as continuity
from offline_session import nom_recovery as recovery
from scripts import qualify_nom_capsule_continuity as qualification


class ContinuityControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class FixtureHost(previous_tests.JournalHoldControls):
            pass
        FixtureHost.setUpClass()
        cls.host = FixtureHost
        cls.views = [qualification.from_journal(bytes.fromhex(FixtureHost.report["cases"][index]["projection"]["journal_hex"]),
            challenge_hex="a1" * 32) for index in (1, 2, 3, 4)]

    @classmethod
    def tearDownClass(cls):
        cls.host.tearDownClass()

    def compare(self, retained, candidate):
        return continuity.compare_continuation(retained, candidate.canonical_bytes,
            expected_candidate_digest_hex=candidate.digest_hex)

    def rewritten(self, index, transform):
        events = [json.loads(line)["event"] for line in self.views[index].journal_bytes.splitlines()]
        transform(events)
        previous = "00" * 32; wire = b""
        for sequence, event in enumerate(events, 1):
            row = dict(schema="ptlc-nom-recovery-log-v1", sequence=sequence, previous_hash_hex=previous, event=event)
            row["hash_hex"] = recovery.digest(b"ptlc-nom-log-v1", row)
            wire += recovery.canonical(row) + b"\n"; previous = row["hash_hex"]
        return qualification.from_journal(wire, challenge_hex="a1" * 32)

    def test_exact_replays_supply_hold_only(self):
        for view in self.views:
            result = self.compare(view, view).review()
            self.assertEqual((result["journal_relation"], result["state"], result["recovery_action"]),
                             ("EXACT_REPLAY", "HOLD", "NONE"))

    def test_full_four_by_four_relation_matrix(self):
        matrix = []
        for old in self.views:
            row = []
            for new in self.views:
                try: row.append(self.compare(old, new).review()["journal_relation"])
                except continuity.ContinuityRefused: row.append("REFUSED")
            matrix.append(row)
        self.assertEqual(matrix, qualification.corpus()["relation_matrix"])

    def test_preappend_reply_does_not_invent_a_retained_result(self):
        self.assertEqual(self.views[0].canonical_bytes, self.views[1].canonical_bytes)
        for view in self.views[:2]:
            self.assertIsNone(view.partial_hold.selection()["recovered_long_signature_hex"])
            self.assertIsNone(view.partial_hold.selection()["original_long_hex"])
        self.assertEqual(self.compare(*self.views[:2]).review()["journal_relation"], "EXACT_REPLAY")

    def test_retained_public_result_cannot_regress_to_missing_output(self):
        for earlier in self.views[:2]:
            with self.assertRaises(continuity.ContinuityRefused): self.compare(self.views[2], earlier)

    def test_retained_original_cannot_regress_to_result_only(self):
        with self.assertRaises(continuity.ContinuityRefused): self.compare(self.views[3], self.views[2])

    def test_extension_preserves_exact_retained_originals_and_unknown_work(self):
        result = self.compare(self.views[0], self.views[3]).review()
        self.assertEqual(result["journal_relation"], "STRICT_EXTENSION")
        self.assertEqual((result["retained_charged_work"], result["candidate_charged_work"]), (1, 1))
        self.assertEqual(result["worker_execution"], "UNKNOWN FOR EVERY PERSISTED CHARGED ORDINAL")

    def test_new_challenge_changes_comparison_without_new_work(self):
        for old in self.views:
            new = qualification.from_journal(old.journal_bytes, challenge_hex="b2" * 32)
            result = self.compare(old, new).review()
            self.assertEqual(result["journal_relation"], "SAME_JOURNAL")
            self.assertEqual(old.partial_hold.selection()["charged_work"], new.partial_hold.selection()["charged_work"])
            self.assertNotEqual(result["retained_capsule_sha256"], result["candidate_capsule_sha256"])

    def test_equal_head_and_sequence_cannot_replace_exact_raw_bytes(self):
        for old in self.views:
            alias = qualification.from_journal(old.journal_bytes.replace(b"\n", b"\r\n"), challenge_hex="a1" * 32)
            self.assertEqual(old.projection()["journal_head_hex"], alias.projection()["journal_head_hex"])
            self.assertEqual(old.projection()["journal_sequence"], alias.projection()["journal_sequence"])
            with self.assertRaises(continuity.ContinuityRefused): self.compare(old, alias)

    def test_longer_rehashed_branch_with_same_charges_refuses(self):
        changed = self.rewritten(3, lambda events: events.insert(2, copy.deepcopy(events[1])))
        self.assertGreater(changed.projection()["journal_sequence"], self.views[3].projection()["journal_sequence"])
        self.assertEqual(changed.partial_hold.selection()["charged_work"], self.views[3].partial_hold.selection()["charged_work"])
        with self.assertRaises(continuity.ContinuityRefused): self.compare(self.views[3], changed)

    def test_equal_length_rehashed_branch_refuses(self):
        def change(events):
            events[1], events[2] = events[2], events[1]
        changed = self.rewritten(3, change)
        self.assertEqual(changed.projection()["journal_sequence"], self.views[3].projection()["journal_sequence"])
        with self.assertRaises(continuity.ContinuityRefused): self.compare(self.views[3], changed)

    def test_changed_pair_remains_structural_but_is_a_different_resource(self):
        def change(events):
            pair = events[0]["pair"]; old = pair["long_presignature_hex"]
            pair["long_presignature_hex"] = ("00" if old[:2] != "00" else "01") + old[2:]
        changed = self.rewritten(3, change)
        with self.assertRaises(continuity.ContinuityRefused): self.compare(self.views[3], changed)

    def test_second_selected_charge_extends_unknown_work_without_execution_claim(self):
        charged = self.rewritten(0, lambda events: events.append(dict(kind="recovery-admitted")))
        result = self.compare(self.views[0], charged).review()
        self.assertEqual((result["journal_relation"], result["candidate_charged_work"]), ("STRICT_EXTENSION", 2))
        self.assertEqual([r["outcome"] for r in charged.partial_hold.selection()["charged_work"]], ["UNKNOWN", "UNKNOWN"])

    def test_old_copy_cannot_erase_a_retained_second_charge(self):
        charged = self.rewritten(0, lambda events: events.append(dict(kind="recovery-admitted")))
        with self.assertRaises(continuity.ContinuityRefused): self.compare(charged, self.views[0])

    def test_coherent_old_retained_and_candidate_pair_still_matches(self):
        charged = self.rewritten(0, lambda events: events.append(dict(kind="recovery-admitted")))
        with self.assertRaises(continuity.ContinuityRefused): self.compare(charged, self.views[0])
        result = self.compare(self.views[0], self.views[0]).review()
        self.assertEqual((result["journal_relation"], result["candidate_charged_work"]), ("EXACT_REPLAY", 1))
        self.assertEqual(result["consumer_restore_fence"], "UNFILLED")

    def test_new_challenge_on_a_restored_pair_does_not_establish_currentness(self):
        old = self.views[0]; new = qualification.from_journal(old.journal_bytes, challenge_hex="b2" * 32)
        result = self.compare(old, new).review()
        self.assertEqual((result["journal_relation"], result["source_currentness"]), ("SAME_JOURNAL", "UNFILLED"))

    def test_comparison_never_mutates_either_input(self):
        before = [view.canonical_bytes for view in self.views]
        for old in self.views:
            for new in self.views:
                try: self.compare(old, new).review()
                except continuity.ContinuityRefused: pass
        self.assertEqual([view.canonical_bytes for view in self.views], before)

    def test_invalid_independent_selection_types_refuse(self):
        for old in (None, {}, self.views[0].canonical_bytes, object()):
            with self.assertRaises(continuity.ContinuityRefused): self.compare(old, self.views[0])

    def test_view_subclass_cannot_select_the_expected_journal(self):
        class ForeignView(capsule.CapsuleView):
            pass
        old = object.__new__(ForeignView); object.__setattr__(old, "_wire", self.views[0].canonical_bytes)
        with self.assertRaises(continuity.ContinuityRefused): self.compare(old, self.views[3])

    def test_candidate_selected_digest_mismatch_refuses(self):
        with self.assertRaises(continuity.ContinuityRefused):
            continuity.compare_continuation(self.views[0], self.views[3].canonical_bytes,
                                           expected_candidate_digest_hex="00" * 32)

    def test_malformed_oversized_and_noncanonical_candidates_refuse(self):
        wire = self.views[0].canonical_bytes
        for malformed in (b"", wire[:-1], wire + b"\n", b"x" * (capsule.MAX_BYTES + 1)):
            with self.assertRaises(continuity.ContinuityRefused):
                continuity.compare_continuation(self.views[0], malformed,
                    expected_candidate_digest_hex=qualification.sha(malformed))

    def test_corrupted_retained_view_refuses(self):
        old = object.__new__(capsule.CapsuleView); object.__setattr__(old, "_wire", b"invalid")
        with self.assertRaises(continuity.ContinuityRefused): self.compare(old, self.views[0])

    def test_no_direct_continuation_construction(self):
        with self.assertRaises(TypeError): continuity.CapsuleContinuation()

    def test_comparison_is_immutable_and_review_is_a_copy(self):
        result = self.compare(self.views[0], self.views[3]); original = result.canonical_bytes
        with self.assertRaises(dataclasses.FrozenInstanceError): result._candidate = self.views[0]
        altered = result.review(); altered["recovery_action"] = "ENTRY"
        self.assertEqual(result.canonical_bytes, original)

    def test_comparison_digest_binds_both_selected_capsules(self):
        first = self.compare(self.views[0], self.views[3])
        second = self.compare(self.views[2], self.views[3])
        self.assertNotEqual(first.digest_hex, second.digest_hex)
        self.assertEqual(first.digest_hex, self.compare(self.views[0], self.views[3]).digest_hex)

    def test_no_path_worker_source_or_clock_entry(self):
        with patch("offline_session.nom_capsule.os.open", side_effect=AssertionError("path entry")), \
             patch("subprocess.Popen", side_effect=AssertionError("process entry")), \
             patch("offline_session.nom_verifier.run_clean_environment_public_worker", side_effect=AssertionError("worker entry")):
            self.assertEqual(self.compare(self.views[0], self.views[3]).review()["recovery_action"], "NONE")

    def test_unchanged_previous_inputs_and_selected_bounds(self):
        manifest, measured = qualification.inputs()
        self.assertEqual(len(manifest["preserved_file_sha256"]), 169)
        self.assertEqual(len(measured), 174)
        self.assertEqual(manifest["boundary"]["new_core_source_outcomes"], 0)
