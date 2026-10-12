"""Scenario controls use a disclosed fixture oracle, not native crypto evidence.

The separate native qualifier supplies the actual Rust mathematical checks and
original streams. These controls prevent accidental retries, fixture filling,
lost original journals and overstated replay/restore authority.
"""

import copy
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from offline_session.nom_recovery import RecoveryError, canonical, verification_context_digest
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_recovery_cuts as q
from scripts.nom_cut_capture import OriginalCapture, retain, sha


class FixtureOracle:
    """Exact public fixture matching only; no signature arithmetic."""

    def __init__(self):
        self.terms, self.pair, _, _, _ = q.selected_inputs()
        self.fixture = json.loads((q.ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
        self.context_digest_hex = verification_context_digest(self.terms, self.pair)

    def verify_pair(self):
        return True

    def verify_claim(self, leg, signature):
        if signature != self.fixture[leg + "_signature_hex"]:
            raise RecoveryError("fixture oracle refused")
        return True

    def recover_long(self, signature):
        self.verify_claim("short", signature)
        return self.fixture["long_signature_hex"]


class JournalCutControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        cls.directory.chmod(0o700)
        cls.result = q.exercise(FixtureOracle(), cls.directory)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def row(self, cut):
        return copy.deepcopy(next(row for row in self.result["cases"] if row["cut"] == cut))

    def test_remote_short_cut_has_disclosure_without_admitted_work(self):
        row = self.row(q.CUTS[0])
        self.assertTrue(row["disclosure_possible"])
        self.assertEqual(row["charged"], 0)
        self.assertFalse(row["admitted_partial_profile"])

    def test_admission_precedes_any_recovery_worker_entry(self):
        row = self.row(q.CUTS[1])
        self.assertEqual((row["charged"], row["recovery_worker_entries"]), (1, 0))
        self.assertEqual(row["event_kinds"][-1], "recovery-admitted")

    def test_withheld_reply_is_absent_from_journal_even_when_captured_separately(self):
        row = self.row(q.CUTS[2])
        self.assertEqual(row["recovery_worker_returns"], 1)
        self.assertTrue(row["qualification_reply_retained"])
        self.assertIsNone(row["retained_result"])
        self.assertIsNone(row["retained_long_original"])

    def test_absent_journal_result_is_never_filled_from_known_fixture(self):
        for cut in q.CUTS[:3]:
            row = self.row(cut)
            self.assertIsNone(row["retained_result"])
            self.assertEqual(row["result_check"], "ABSENT; NOT SUPPLIED FROM FIXTURE")

    def test_result_record_does_not_establish_original_bytes(self):
        row = self.row(q.CUTS[3])
        self.assertIsNotNone(row["retained_result"])
        self.assertIsNone(row["retained_long_original"])
        self.assertEqual(row["event_kinds"][-1], "recovered")

    def test_original_record_retains_exact_completion_and_original_separately(self):
        row = self.row(q.CUTS[4])
        self.assertEqual(row["event_kinds"][-1], "original")
        self.assertEqual(q.decode(bytes.fromhex(row["retained_long_original"]))["signature_hex"], row["retained_result"])

    def test_reopen_never_reenters_recovery_or_appends(self):
        for row in self.result["cases"]:
            self.assertEqual(row["automatic_worker_entries_on_reopen"], 0)
            self.assertTrue(row["journal_unchanged_after_reopen"])
            self.assertNotIn("recover-long", row["reopen_modes"])

    def test_all_five_original_journal_bytes_survive_adversarial_controls(self):
        for row in self.result["cases"]:
            wire = (self.directory / (row["cut"] + ".log")).read_bytes()
            self.assertEqual(wire.hex(), row["journal_hex"])
            self.assertEqual(sha(wire), row["journal_sha256"])

    def test_result_only_open_performs_no_long_math(self):
        self.assertEqual(self.row(q.CUTS[3])["reopen_modes"], ["verify-pair", "verify-short"])

    def test_complete_original_open_checks_long_and_remote_short(self):
        self.assertEqual(self.row(q.CUTS[4])["reopen_modes"], ["verify-pair", "verify-long", "verify-short"])

    def test_result_verification_is_separate_from_read_only_open(self):
        for cut in q.CUTS[3:]:
            self.assertEqual(self.row(cut)["result_check"], "SEPARATELY PUBLIC-WORKER VERIFIED AFTER REOPEN")

    def test_replay_does_not_reinvoke_rejecting_observation_callback(self):
        for row in self.result["cases"]:
            self.assertEqual(row["observer_calls_on_replay"], 0)
        self.assertIn("HISTORICAL ONLY", self.result["adversarial_controls"]["replayed_funding"])

    def test_write_observations_match_disclosed_exact_allowlist(self):
        allowed = set(self.result["synthetic_allowlist_hex"])
        self.assertEqual(len(allowed), 3)
        for row in self.result["cases"]:
            self.assertTrue(set(row["observer_calls_before_cut"]) <= allowed)

    def test_rehashed_invalid_result_survives_open_but_is_separately_refused(self):
        controls = self.result["adversarial_controls"]
        self.assertEqual(controls["invalid_result_only_reopen"], "ACCEPTED ENCODING; NO LONG MATH ON OPEN")
        self.assertEqual(controls["separate_invalid_result_verification"], "REFUSED")

    def test_old_complete_prefix_has_no_restore_authority(self):
        self.assertEqual(self.result["adversarial_controls"]["coherent_old_prefix"], "ACCEPTED; NO RESTORE AUTHORITY")

    def test_post_fsync_exception_is_not_process_death_or_interior_disk_fault(self):
        self.assertEqual(q.BOUNDARY["process_death"], "NOT_PERFORMED")
        self.assertEqual(q.BOUNDARY["interior_write_or_fsync_fault"], "NOT_PERFORMED")
        for row in self.result["cases"]:
            self.assertEqual(len(row["post_fsync_hook"]), 0 if row["cut"] == q.CUTS[2] else 1)

    def test_charges_cannot_be_erased_in_comparison(self):
        result = copy.deepcopy(self.result)
        result["cases"][1]["charged"] = 0
        with self.assertRaises(ValueError):
            q.check_cases(result)

    def test_fixture_filled_original_is_rejected_as_absent_custody(self):
        result = copy.deepcopy(self.result)
        result["cases"][3]["retained_long_original"] = self.row(q.CUTS[4])["retained_long_original"]
        with self.assertRaises(ValueError):
            q.check_cases(result)

    def test_missing_interruption_case_is_refused(self):
        result = copy.deepcopy(self.result)
        result["cases"].pop()
        with self.assertRaises(ValueError):
            q.check_cases(result)

    def test_changed_reopen_worker_count_is_refused(self):
        result = copy.deepcopy(self.result)
        result["cases"][1]["automatic_worker_entries_on_reopen"] = 1
        with self.assertRaises(ValueError):
            q.check_cases(result)

    def test_incomplete_journal_tail_is_not_original_record_evidence(self):
        with self.assertRaises(ValueError):
            q.journal_records(bytes.fromhex(self.row(q.CUTS[3])["journal_hex"])[:-1])

    def test_hash_rewrite_is_an_adversarial_copy_and_never_authentication(self):
        wire = bytes.fromhex(self.row(q.CUTS[3])["journal_hex"])
        changed = q.rewrite_self_hashes(wire, lambda rows: rows[-1]["event"].update(signature_hex="00" * 64))
        self.assertNotEqual(wire, changed)
        self.assertEqual(q.journal_records(changed)[-1]["event"]["signature_hex"], "00" * 64)

    def test_changed_record_without_rehash_is_refused(self):
        wire = bytes.fromhex(self.row(q.CUTS[3])["journal_hex"])
        rows = q.journal_records(wire)
        rows[-1]["event"]["signature_hex"] = "00" * 64
        with self.assertRaises(ValueError):
            q.journal_records(b"".join(canonical(row) + b"\n" for row in rows))

    def test_hold_and_current_chain_authority_remain_uncomposed(self):
        self.assertEqual(q.BOUNDARY["hold_admission"], "NOT_COMPOSED")
        self.assertEqual(q.BOUNDARY["current_chain_authority"], "UNFILLED")
        self.assertEqual(q.BOUNDARY["recovery_action"], "NONE")

    def test_input_manifest_preserves_prior_profile_and_fixture(self):
        manifest, measured = q.inputs()
        self.assertEqual(len(manifest["preserved_file_sha256"]), 141)
        self.assertEqual(len(measured), 148)
        self.assertEqual(json.loads((q.ROOT / q.FIXTURE).read_text("ascii")), q.corpus())


class OriginalCaptureControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.worker = self.directory / "public-fixture-worker"
        self.worker.write_text("#!" + sys.executable + "\nimport sys\nsys.stdout.buffer.write(b'public response')\nsys.stderr.buffer.write(b'public diagnostic')\n", encoding="ascii")
        self.worker.chmod(0o700)
        self.capture = OriginalCapture(self.directory, self.worker, sha(self.worker.read_bytes()))

    def run_selected(self):
        return self.capture.run(str(self.worker), b"public synthetic request", timeout=5, max_input_bytes=8192)

    def test_capture_retains_complete_original_request_and_both_streams(self):
        self.assertEqual(self.run_selected(), b"public response")
        self.assertEqual((self.directory / "call-001.stdin").read_bytes(), b"public synthetic request")
        self.assertEqual((self.directory / "call-001.stderr").read_bytes(), b"public diagnostic")
        self.assertEqual(self.capture.calls[0]["stream_completeness"], "COMPLETE")

    def test_original_files_are_created_private(self):
        self.run_selected()
        for path in self.directory.glob("call-001.*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_failed_worker_streams_are_preserved_without_retry(self):
        self.worker.write_text("#!" + sys.executable + "\nimport sys\nsys.stdout.buffer.write(b'failed public output')\nsys.stderr.buffer.write(b'failed public diagnostic')\nsys.exit(2)\n", encoding="ascii")
        self.capture.pin = sha(self.worker.read_bytes())
        with self.assertRaises(WorkerError):
            self.run_selected()
        self.assertEqual(len(self.capture.calls), 1)
        self.assertEqual(self.capture.calls[0]["exit_code"], 2)
        self.assertEqual((self.directory / "call-001.stdout").read_bytes(), b"failed public output")

    def test_changed_selected_executable_is_refused_before_request(self):
        self.worker.write_bytes(b"changed public worker")
        with self.assertRaises(WorkerError):
            self.run_selected()
        self.assertEqual(self.capture.calls, [])

    def test_original_stream_file_cannot_be_overwritten(self):
        retain(self.directory / "call-001.stdin", b"prior evidence")
        with self.assertRaises(FileExistsError):
            self.run_selected()
        self.assertEqual((self.directory / "call-001.stdin").read_bytes(), b"prior evidence")

    def test_capture_selects_empty_environment_without_inheritance(self):
        import subprocess
        with patch("scripts.nom_cut_capture.subprocess.Popen", wraps=subprocess.Popen) as spawn:
            self.run_selected()
        self.assertEqual(spawn.call_args.kwargs["env"], {})

    def test_spawn_failure_preserves_request_and_missing_exit_honestly(self):
        with patch("scripts.nom_cut_capture.subprocess.Popen", side_effect=OSError("synthetic spawn failure")):
            with self.assertRaises(OSError):
                self.run_selected()
        self.assertIsNone(self.capture.calls[0]["exit_code"])
        self.assertEqual(self.capture.calls[0]["stream_completeness"], "NOT_ESTABLISHED")
        self.assertTrue((self.directory / "call-001.stdin").is_file())

    def test_invalid_input_does_not_spawn_or_allocate_a_call(self):
        with self.assertRaises(WorkerError):
            self.capture.run(str(self.worker), b"x" * 8193, timeout=5, max_input_bytes=8192)
        self.assertEqual(self.capture.calls, [])

    def test_capture_is_not_an_application_containment_claim(self):
        self.assertEqual(q.BOUNDARY["hostile_process_containment"], "NOT_ESTABLISHED")
        self.assertEqual(q.BOUNDARY["application"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
