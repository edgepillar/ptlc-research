"""Journal projection fault controls using an exact fixture worker, without math.

The separate native qualifier supplies actual Rust execution evidence. Temporary
fixture actor streams are ordinary unit-test inputs, not persistent custody.
"""

import copy
import dataclasses
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from offline_session import nom_journal_hold as projection, nom_recovery as recovery
from offline_session.nom_strict_open import StrictNomRecovery
from offline_session.nom_verifier import NomPublicVerifier
from scripts import qualify_nom_journal_hold as q
from scripts.nom_cut_capture import retain, sha


class FixtureVerifier:
    """Structural test boundary only; mathematical validity is not asserted here."""

    def __init__(self, context, short, long):
        self.context_digest_hex = context; self.short = short; self.long = long; self.modes = []

    def verify_pair(self):
        self.modes.append("verify-pair")
        return True

    def verify_claim(self, leg, signature):
        self.modes.append("verify-" + leg)
        return signature == (self.short if leg == "short" else self.long)

    def recover_long(self, *_):
        raise AssertionError("projection entered recovery")


class JournalHoldControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name); cls.directory.chmod(0o700)
        cls.worker = cls.directory / "disclosed-exact-fixture-worker"
        cls.terms, cls.pair, _, _, _ = q.prior.prior.prior.selected_inputs()
        fixture = json.loads((q.ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
        cls.short = fixture["short_signature_hex"]; cls.long = fixture["long_signature_hex"]
        cls.context = recovery.verification_context_digest(cls.terms, cls.pair)
        cls.worker.write_text("#!" + sys.executable + "\n", encoding="ascii"); cls.worker.chmod(0o700)
        verifier = NomPublicVerifier(cls.worker, sha(cls.worker.read_bytes()), cls.terms, cls.pair)
        requests = {mode: verifier.request(mode, "" if mode == "verify-pair" else
            fixture[("short" if mode in ("verify-short", "recover-long") else "long") + "_signature_hex"])
            for mode in ("verify-pair", "verify-short", "verify-long", "recover-long")}
        cls.worker.write_text("#!" + sys.executable + "\nimport json,sys,hashlib\n"
            + "selected = " + repr(requests) + "\ncompletion = " + repr(cls.long) + "\n"
            + "wire=sys.stdin.buffer.read(); value=json.loads(wire)\n"
            + "if value != selected.get(value.get('mode')): sys.exit(2)\n"
            + "reply=dict(schema='ptlc-nom-public-verification-result-v1',request_digest_hex=hashlib.sha256(wire).hexdigest(),valid=True,completed_long_hex=completion if value['mode']=='recover-long' else '')\n"
            + "sys.stdout.buffer.write(json.dumps(reply,sort_keys=True,separators=(',',':')).encode('ascii'))\n",
            encoding="ascii")
        cls.originals = cls.directory / "originals"
        cls.report = q.qualify(cls.worker, evidence_directory=cls.originals)
        cls.sources = cls.report["strict_open_result"]["cases"]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        selected = tempfile.TemporaryDirectory(); self.addCleanup(selected.cleanup)
        self.path = Path(selected.name) / "journal.log"; self.path.parent.chmod(0o700)
        retain(self.path, bytes.fromhex(self.sources[3]["journal_hex"]))

    def opened(self, *, path=None, kind=StrictNomRecovery, terms=None, pair=None):
        terms = self.terms if terms is None else terms; pair = self.pair if pair is None else pair
        self.verifier = FixtureVerifier(recovery.verification_context_digest(terms, pair), self.short, self.long)
        return kind.open(path or self.path, terms, pair, role="bob", verifier=self.verifier,
            observation_verifier=lambda proof: False)

    def selected(self, owner, challenge=q.CHALLENGES[0]):
        return projection.project_partial_hold(owner, challenge_hex=challenge)

    def work(self, selected):
        return selected.partial_hold.selection()["charged_work"]

    def refused_report(self, change):
        value = copy.deepcopy(self.report); change(value)
        with self.assertRaises(ValueError):
            q.check_cases(value)

    def test_four_admitted_cuts_keep_exact_custody_and_unknown_execution(self):
        for index in range(1, 5):
            raw = bytes.fromhex(self.sources[index]["journal_hex"]); self.path.write_bytes(raw)
            with self.opened() as owner:
                selected = self.selected(owner)
                self.assertEqual(selected.journal_bytes, raw)
                self.assertEqual([row["outcome"] for row in self.work(selected)], ["UNKNOWN"])
                self.assertEqual(q.check_projection(selected.as_dict(), self.sources[index], q.CHALLENGES[0]),
                                 self.work(selected))
            self.assertEqual(self.path.read_bytes(), raw)

    def test_zero_charge_refuses_without_closing_owner_or_inventing_work(self):
        self.path.write_bytes(bytes.fromhex(self.sources[0]["journal_hex"]))
        with self.opened() as owner:
            with self.assertRaises(projection.JournalProjectionRefused):
                self.selected(owner)
            self.assertEqual(owner.status()["recovery_count"], 0)
            with self.assertRaises(BlockingIOError):
                q.prior.owner_available(self.path)

    def test_legacy_writer_is_not_a_selected_strict_owner(self):
        with self.opened(kind=recovery.NomRecovery) as owner:
            with self.assertRaises(projection.JournalProjectionRefused):
                self.selected(owner)
            self.assertEqual(owner.status()["recovery_count"], 1)

    def test_strict_subclass_does_not_supply_the_exact_selection(self):
        class Alternate(StrictNomRecovery):
            pass
        with self.opened(kind=Alternate) as owner:
            with self.assertRaises(projection.JournalProjectionRefused):
                self.selected(owner)

    def test_arbitrary_label_cannot_replace_a_selected_owner(self):
        for value in (None, {}, q.PROFILE, object()):
            with self.assertRaises(projection.JournalProjectionRefused):
                self.selected(value)

    def test_closed_owner_cannot_project(self):
        owner = self.opened(); owner.close()
        with self.assertRaises(recovery.Quarantined):
            self.selected(owner)

    def test_poisoned_owner_cannot_project(self):
        with self.opened() as owner:
            owner._poisoned = True
            with self.assertRaises(recovery.Quarantined):
                self.selected(owner)

    def test_cross_thread_owner_refuses_without_reading(self):
        with self.opened() as owner:
            failures = []
            def other():
                try:
                    self.selected(owner)
                except recovery.Quarantined as error:
                    failures.append(error)
            thread = threading.Thread(target=other); thread.start(); thread.join()
            self.assertEqual(len(failures), 1)
            self.assertEqual(owner.status()["recovery_count"], 1)

    def test_read_failure_is_sanitized_and_owner_stays_with_caller(self):
        with self.opened() as owner:
            with patch.object(projection.os, "pread", side_effect=OSError("disclosed fault")):
                with self.assertRaisesRegex(projection.JournalProjectionRefused, "unable to select"):
                    self.selected(owner)
            self.assertEqual(owner.status()["recovery_count"], 1)

    def test_read_interruption_is_not_retried_or_swallowed(self):
        with self.opened() as owner:
            interrupted = KeyboardInterrupt()
            with patch.object(projection.os, "pread", side_effect=interrupted) as read:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    self.selected(owner)
                self.assertIs(caught.exception, interrupted); self.assertEqual(read.call_count, 1)
            self.assertEqual(owner.status()["recovery_count"], 1)

    def test_short_read_cannot_return_partial_custody(self):
        with self.opened() as owner:
            with patch.object(projection.os, "pread", side_effect=[b"{", b""]):
                with self.assertRaises(projection.JournalProjectionRefused):
                    self.selected(owner)

    def test_growth_after_open_refuses(self):
        with self.opened() as owner:
            self.path.write_bytes(self.path.read_bytes() + b"\n")
            with self.assertRaises(recovery.Quarantined):
                self.selected(owner)

    def test_same_size_coherent_rewrite_after_open_refuses_loaded_head(self):
        with self.opened() as owner:
            original = self.path.read_bytes()
            changed = q.prior.prior.prior.rewrite_self_hashes(original,
                lambda rows: rows[4]["event"]["proof"].update(receive_timestamp="1110"))
            self.assertEqual(len(changed), len(original)); self.path.write_bytes(changed)
            with self.assertRaises(projection.JournalProjectionRefused):
                self.selected(owner)

    def test_replaced_path_cannot_supply_descriptor_custody(self):
        with self.opened() as owner:
            raw = self.path.read_bytes(); self.path.rename(self.path.with_suffix(".retained"))
            retain(self.path, raw)
            with self.assertRaises(recovery.Quarantined):
                self.selected(owner)

    def test_second_snapshot_difference_refuses(self):
        with self.opened() as owner:
            reference = projection._read; reads = []
            def changed(selected):
                raw = reference(selected); reads.append(raw)
                return raw if len(reads) == 1 else raw[:-1] + b" "
            with patch.object(projection, "_read", side_effect=changed):
                with self.assertRaises(projection.JournalProjectionRefused):
                    self.selected(owner)
            self.assertEqual(len(reads), 2)

    def test_frozen_state_must_equal_full_journal_replay(self):
        with self.opened() as owner:
            owner._state["recovery_count"] = 2
            with self.assertRaises(projection.JournalProjectionRefused):
                self.selected(owner)

    def test_descriptor_offset_is_preserved_and_no_path_is_reopened(self):
        with self.opened() as owner:
            before = os.lseek(owner._fd, 0, os.SEEK_CUR)
            with patch.object(projection.os, "open", side_effect=AssertionError("unexpected reopen")):
                selected = self.selected(owner)
            self.assertEqual(os.lseek(owner._fd, 0, os.SEEK_CUR), before)
            self.assertEqual(selected.journal_bytes, self.path.read_bytes())

    def test_projection_enters_no_worker_and_does_not_revalidate_history(self):
        with self.opened() as owner:
            before = list(self.verifier.modes)
            owner._observer = lambda _: self.fail("projection called observation source")
            with patch.object(self.verifier, "verify_claim", side_effect=AssertionError("unexpected worker")):
                self.selected(owner).review()
            self.assertEqual(self.verifier.modes, before)

    def test_missing_result_is_not_filled_from_returned_diagnostic_reply(self):
        self.path.write_bytes(bytes.fromhex(self.sources[2]["journal_hex"]))
        self.assertIsNotNone(self.sources[2]["death_receipt"]["returned_result"])
        with self.opened() as owner:
            held = self.selected(owner).partial_hold.selection()
            self.assertIsNone(held["recovered_long_signature_hex"]); self.assertIsNone(held["original_long_hex"])

    def test_absent_long_original_is_never_constructed(self):
        reference = recovery.synthetic_claim
        def existing_only(terms, leg, signature):
            self.assertEqual(leg, "short", "invented absent long original")
            return reference(terms, leg, signature)
        with self.opened() as owner:
            with patch.object(recovery, "synthetic_claim", side_effect=existing_only):
                held = self.selected(owner).partial_hold.selection()
                self.assertEqual(held["recovered_long_signature_hex"], self.long)
                self.assertIsNone(held["original_long_hex"])

    def test_actual_long_original_stays_exact_without_complete_query_conversion(self):
        self.path.write_bytes(bytes.fromhex(self.sources[4]["journal_hex"]))
        with self.opened() as owner:
            selected = self.selected(owner)
            self.assertEqual(selected.partial_hold.selection()["original_long_hex"],
                             self.sources[4]["retained_long_original"])
            self.assertEqual(selected.review()["complete_query_conversion"], "NOT_PROVIDED")

    def test_work_ids_ignore_challenge_and_result_progress(self):
        identifiers = []
        for source in self.sources[1:]:
            self.path.write_bytes(bytes.fromhex(source["journal_hex"]))
            with self.opened() as owner:
                first = self.selected(owner); second = self.selected(owner, q.CHALLENGES[1])
                self.assertEqual(self.work(first), self.work(second))
                self.assertNotEqual(first.partial_hold.selection_digest_hex, second.partial_hold.selection_digest_hex)
                identifiers.append(self.work(first))
        self.assertTrue(all(work == identifiers[0] for work in identifiers))

    def test_coherent_copy_retains_identical_work_without_restore_authority(self):
        copied = self.path.with_name("coherent-copy.log"); retain(copied, self.path.read_bytes())
        with self.opened() as owner:
            first = self.selected(owner)
        with self.opened(path=copied) as owner:
            second = self.selected(owner)
        self.assertEqual(first.as_dict(), second.as_dict())
        self.assertEqual(second.review()["restore_fence"], "UNFILLED")

    def test_sixteen_persisted_ordinals_are_distinct_and_all_unknown(self):
        def charge(rows):
            rows[5:5] = [copy.deepcopy(rows[5]) for _ in range(15)]
        changed = q.prior.prior.prior.rewrite_self_hashes(self.path.read_bytes(), charge)
        self.path.write_bytes(changed)
        with self.opened() as owner:
            work = self.work(self.selected(owner))
        self.assertEqual(len(work), 16); self.assertEqual(len({row["attempt_id_hex"] for row in work}), 16)
        self.assertEqual({row["outcome"] for row in work}, {"UNKNOWN"})

    def test_seventeenth_ordinal_is_refused_by_frozen_parser(self):
        def charge(rows):
            rows[5:5] = [copy.deepcopy(rows[5]) for _ in range(16)]
        self.path.write_bytes(q.prior.prior.prior.rewrite_self_hashes(self.path.read_bytes(), charge))
        with self.assertRaises(recovery.RecoveryError):
            self.opened()

    def test_changed_context_and_exact_short_have_distinct_work_identity(self):
        with self.opened() as owner:
            before = self.work(self.selected(owner))
        terms = copy.deepcopy(self.terms); terms["session_id_hex"] = "c3" * 32
        short = recovery.synthetic_claim(terms, "short", self.short)
        def reframe(rows):
            rows[0]["event"]["terms"] = terms
            for row in rows:
                event = row["event"]
                if event["kind"] == "remote-short":
                    event["wire_hex"] = short.hex()
                elif event["kind"] == "observation":
                    proof = event["proof"]
                    values = {key: proof[key] for key in ("transaction_hash_hex", "send_timestamp",
                        "send_momentum_hash_hex", "receive_timestamp", "receive_momentum_hash_hex")}
                    if proof["kind"] != "funded":
                        values["transaction_hash_hex"] = recovery.synthetic_transaction_hash(short)
                    event["proof"] = recovery.observation(terms, proof["leg"], proof["kind"], **values)
        self.path.write_bytes(q.prior.prior.prior.rewrite_self_hashes(self.path.read_bytes(), reframe))
        with self.opened(terms=terms) as owner:
            after = self.work(self.selected(owner))
        self.assertNotEqual(before[0]["attempt_id_hex"], after[0]["attempt_id_hex"])
        self.assertNotEqual(before[0]["short_original_digest_hex"], after[0]["short_original_digest_hex"])

    def test_full_journal_is_separate_from_bounded_prior_evidence(self):
        with self.opened() as owner:
            selected = self.selected(owner)
        self.assertGreater(len(selected.journal_bytes), 512)
        self.assertEqual(selected.partial_hold.selection()["prior_evidence_hex"], [])

    def test_frozen_pure_review_keeps_its_original_evidence_scope(self):
        with self.opened() as owner:
            review = self.selected(owner).review()
        self.assertEqual(review["present_result_gate"], "VERIFIED BY SELECTED STRICT OPEN BEFORE OWNER RETURN")
        self.assertEqual(review["frozen_partial_review"]["signature_mathematics"], "NOT_PERFORMED")
        self.assertEqual(review["frozen_partial_review"]["journal_composition"], "NOT_PERFORMED")
        self.assertEqual(review["durable_retention"], "NOT_IMPLEMENTED")
        self.assertEqual((review["application"], review["core"], review["recovery_action"]), ("NO-GO", "NO-GO", "NONE"))

    def test_invalid_challenge_refuses_without_changing_journal(self):
        raw = self.path.read_bytes()
        with self.opened() as owner:
            for challenge in (None, "", "A1" * 32, "00" * 31, True):
                with self.assertRaises(recovery.RecoveryError):
                    self.selected(owner, challenge)
        self.assertEqual(self.path.read_bytes(), raw)

    def test_projection_is_immutable_and_retained_bytes_survive_owner_close(self):
        with self.opened() as owner:
            selected = self.selected(owner)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            selected._journal = b""
        view = selected.as_dict(); view["journal_hex"] = ""
        self.assertEqual(selected.journal_bytes, self.path.read_bytes())

    def test_forged_projection_with_different_hold_is_refused(self):
        with self.opened() as owner:
            selected = self.selected(owner)
        forged = object.__new__(projection.JournalPartialHold)
        object.__setattr__(forged, "_journal", bytes.fromhex(self.sources[1]["journal_hex"]))
        object.__setattr__(forged, "_hold", selected.partial_hold)
        with self.assertRaises(projection.JournalProjectionRefused):
            forged.as_dict()

    def test_corpus_erased_charge_is_refused(self):
        self.refused_report(lambda value: value["cases"][1].update(projection=None))

    def test_corpus_invented_execution_is_refused(self):
        self.refused_report(lambda value: value["cases"][3]["review"].update(work_execution="COMPLETE"))

    def test_corpus_worker_reentry_is_refused(self):
        self.refused_report(lambda value: value["cases"][2].update(projection_worker_calls=1))

    def test_corpus_missing_original_journal_is_refused(self):
        self.refused_report(lambda value: value["cases"][1]["projection"].update(journal_hex="00"))

    def test_corpus_prior_invalid_worker_exit_is_not_relabelled(self):
        self.refused_report(lambda value: value["strict_open_result"]["reopen_worker_calls"][-1].update(exit_code=0))

    def test_prior_158_measured_sources_and_original_native_streams_are_preserved(self):
        _, prior = q.prior.inputs()
        self.assertEqual(len(prior), 158); self.assertEqual(len(q.inputs()[1]), 163)
        self.assertTrue(all(self.report["input_sha256"][name] == value for name, value in prior.items()))
        self.assertEqual(len(q.prior.read_calls(self.originals / "projection-worker")), 15)
        self.assertEqual(self.report["total_worker_calls"], 49)


if __name__ == "__main__":
    unittest.main()
