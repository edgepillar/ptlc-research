"""Explicit Python exits and custody controls with an exact fixture worker.

This worker matches disclosed public requests and has no signature arithmetic.
Actual Rust mathematical evidence comes only from the separate native qualifier.
These tests do not replace independent runtime, chain or application assessment.
"""

import copy
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from offline_session.nom_recovery import canonical
from offline_session.nom_verifier import NomPublicVerifier
from scripts import qualify_nom_process_death as q
from scripts.nom_cut_capture import retain, sha


class ProcessDeathControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        cls.directory.chmod(0o700)
        cls.worker = cls.directory / "disclosed-exact-fixture-worker"
        terms, pair, _, _, _ = q.prior.selected_inputs()
        fixture = json.loads((q.ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
        # Request construction is not worker execution or native proof.
        cls.worker.write_text("#!" + sys.executable + "\n", encoding="ascii")
        cls.worker.chmod(0o700)
        verifier = NomPublicVerifier(cls.worker, sha(cls.worker.read_bytes()), terms, pair)
        requests = {mode: verifier.request(mode, "" if mode == "verify-pair" else
            fixture[("short" if mode in ("verify-short", "recover-long") else "long") + "_signature_hex"])
            for mode in ("verify-pair", "verify-short", "verify-long", "recover-long")}
        cls.worker.write_text("#!" + sys.executable + "\nimport json,sys,hashlib\n"
            + "selected = " + repr(requests) + "\ncompletion = " + repr(fixture["long_signature_hex"]) + "\n"
            + "wire=sys.stdin.buffer.read(); value=json.loads(wire)\n"
            + "if value != selected.get(value.get('mode')): sys.exit(2)\n"
            + "reply=dict(schema='ptlc-nom-public-verification-result-v1',request_digest_hex=hashlib.sha256(wire).hexdigest(),valid=True,completed_long_hex=completion if value['mode']=='recover-long' else '')\n"
            + "sys.stdout.buffer.write(json.dumps(reply,sort_keys=True,separators=(',',':')).encode('ascii'))\n",
            encoding="ascii")
        cls.originals = cls.directory / "originals"
        cls.report = q.qualify(cls.worker, evidence_directory=cls.originals)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def row(self, index):
        return copy.deepcopy(self.report["cases"][index])

    def refused(self, index, key, value):
        report = copy.deepcopy(self.report)
        report["cases"][index][key] = value
        with self.assertRaises(ValueError):
            q.check_cases(report)

    def test_all_five_selected_actors_exit_explicitly_without_python_cleanup(self):
        for row in self.report["cases"]:
            self.assertEqual(row["actor_streams"]["exit_code"], 72)
            self.assertEqual(row["death_receipt"]["method"], "os._exit(72)")

    def test_post_exit_owner_lock_is_released_for_read_only_reopen(self):
        for row in self.report["cases"]:
            self.assertTrue(row["journal_unchanged_after_reopen"])
            self.assertEqual(row["automatic_worker_entries_on_reopen"], 0)

    def test_remote_short_disclosure_has_no_fabricated_work_charge(self):
        row = self.row(0)
        self.assertTrue(row["disclosure_possible"])
        self.assertEqual(row["charged"], 0)
        self.assertFalse(row["admitted_partial_profile"])

    def test_admitted_charge_survives_death_before_first_recovery_worker(self):
        row = self.row(1)
        self.assertEqual((row["charged"], row["recovery_worker_entries"]), (1, 0))
        self.assertEqual(row["event_kinds"][-1], "recovery-admitted")

    def test_returned_public_reply_survives_only_as_separate_diagnostic_custody(self):
        row = self.row(2)
        self.assertEqual(row["recovery_worker_returns"], 1)
        self.assertTrue(row["qualification_reply_retained"])
        self.assertIsNone(row["retained_result"])
        self.assertIsNone(row["retained_long_original"])
        self.assertIsNotNone(row["death_receipt"]["returned_result"])

    def test_result_only_death_does_not_construct_an_absent_original(self):
        row = self.row(3)
        self.assertIsNotNone(row["retained_result"])
        self.assertIsNone(row["retained_long_original"])
        self.assertEqual(row["event_kinds"][-1], "recovered")

    def test_actual_retained_original_and_result_are_separate_journal_records(self):
        row = self.row(4)
        records = q.prior.journal_records(bytes.fromhex(row["journal_hex"]))
        self.assertEqual([value["event"]["kind"] for value in records[-2:]], ["recovered", "original"])
        self.assertEqual(q.decode(bytes.fromhex(row["retained_long_original"]))["signature_hex"], row["retained_result"])

    def test_missing_results_remain_null_despite_known_public_fixture(self):
        for index in range(3):
            self.assertIsNone(self.row(index)["retained_result"])
            self.assertEqual(self.row(index)["result_check"], "ABSENT; NOT SUPPLIED FROM FIXTURE")

    def test_all_original_journal_files_survive_read_only_reopen_exactly(self):
        for row in self.report["cases"]:
            wire = (self.originals / row["cut"] / "journal.log").read_bytes()
            self.assertEqual((wire.hex(), sha(wire)), (row["journal_hex"], row["journal_sha256"]))

    def test_reopen_has_zero_recovery_entries_and_no_attempts(self):
        for row in self.report["cases"]:
            self.assertNotIn("recover-long", row["reopen_modes"])
            self.assertNotIn("attempt", row["event_kinds"])

    def test_result_only_open_is_distinct_from_separate_long_verification(self):
        self.assertEqual(self.row(3)["reopen_modes"], ["verify-pair", "verify-short"])
        self.assertEqual(self.row(3)["result_check"], "SEPARATELY PUBLIC-WORKER VERIFIED AFTER REOPEN")

    def test_original_open_checks_retained_long_and_remote_short(self):
        self.assertEqual(self.row(4)["reopen_modes"], ["verify-pair", "verify-long", "verify-short"])

    def test_only_three_exact_disclosed_observations_are_admitted(self):
        allowed = set(self.report["synthetic_allowlist_hex"])
        self.assertEqual(len(allowed), 3)
        for row in self.report["cases"]:
            self.assertTrue(set(row["observer_calls_before_cut"]) <= allowed)

    def test_replayed_funding_does_not_reinvoke_rejecting_observer(self):
        for row in self.report["cases"]:
            self.assertEqual(row["observer_calls_on_replay"], 0)
        self.assertEqual(q.BOUNDARY["current_chain_authority"], "UNFILLED")

    def test_before_spawn_custody_includes_actor_runtime_worker_and_all_sources(self):
        subject = json.loads((self.originals / "subject-before-first-spawn.json").read_text("ascii"))
        self.assertTrue(subject["before_first_actor_or_worker_spawn"])
        self.assertEqual(subject["input_sha256"], q.inputs()[1])
        for index, name in enumerate(q.inputs()[1]):
            self.assertEqual((self.originals / f"source-{index:03d}.original").read_bytes(), (q.ROOT / name).read_bytes())
        self.assertEqual(sha((self.originals / "selected-public-executable.original").read_bytes()), subject["executable_sha256"])
        self.assertEqual(sha((self.originals / "selected-python-executable.original").read_bytes()), subject["python_executable_sha256"])

    def test_every_actor_stream_and_explicit_exit_are_retained_separately(self):
        for row in self.report["cases"]:
            directory = self.originals / row["cut"]
            self.assertEqual((directory / "actor.stdout").read_bytes().hex(), row["actor_streams"]["stdout_hex"])
            self.assertEqual((directory / "actor.stderr").read_bytes(), b"")
            self.assertEqual(json.loads((directory / "actor.receipt.json").read_text("ascii")), row["actor_streams"])

    def test_original_worker_requests_replies_and_exits_are_not_reconstructed(self):
        calls = []
        for cut in q.CUTS:
            actual = q.read_calls(self.originals / cut / "worker")
            self.assertEqual(actual, self.report["actor_worker_calls"][cut])
            calls.extend(actual)
        calls.extend(q.read_calls(self.originals / "reopen-worker"))
        self.assertEqual(len(calls), 29)
        self.assertTrue(all(row["exit_code"] == 0 for row in calls))

    def test_private_original_evidence_files_use_mode_0600(self):
        for path in self.originals.rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_erased_admitted_charge_is_refused(self):
        self.refused(1, "charged", 0)

    def test_fixture_filled_absent_original_is_refused(self):
        self.refused(3, "retained_long_original", self.row(4)["retained_long_original"])

    def test_successful_exit_is_not_selected_process_death_evidence(self):
        self.refused(1, "actor_exit_code", 0)

    def test_recovery_reentry_on_open_is_refused(self):
        self.refused(1, "automatic_worker_entries_on_reopen", 1)

    def test_missing_selected_case_is_refused(self):
        report = copy.deepcopy(self.report)
        report["cases"].pop()
        with self.assertRaises(ValueError):
            q.check_cases(report)

    def test_changed_original_worker_stream_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for source in (self.originals / q.CUTS[0] / "worker").iterdir():
                retain(directory / source.name, source.read_bytes())
            (directory / "call-001.stdout").write_bytes(b"changed synthetic response")
            with self.assertRaises(ValueError):
                q.read_calls(directory)

    def test_original_actor_configuration_cannot_be_overwritten(self):
        directory = self.originals / q.CUTS[0]
        before = (directory / "configuration-before-spawn.json").read_bytes()
        with self.assertRaises(FileExistsError):
            q.actor(directory, {"cut": q.CUTS[0]})
        self.assertEqual((directory / "configuration-before-spawn.json").read_bytes(), before)

    def test_spawn_failure_preserves_original_streams_and_missing_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch("scripts.qualify_nom_process_death.subprocess.Popen", side_effect=OSError("synthetic spawn failure")):
                with self.assertRaises(OSError):
                    q.actor(directory, {"cut": q.CUTS[0]})
            receipt = json.loads((directory / "actor.receipt.json").read_text("ascii"))
            self.assertIsNone(receipt["exit_code"])
            self.assertEqual(receipt["stream_completeness"], "NOT_ESTABLISHED")

    def test_explicit_exit_is_not_interior_fsync_fault_power_loss_or_containment(self):
        self.assertEqual(q.BOUNDARY["interior_write_or_fsync_fault"], "NOT_PERFORMED")
        self.assertEqual(q.BOUNDARY["power_loss"], "NOT_PERFORMED")
        self.assertEqual(q.BOUNDARY["hostile_process_containment"], "NOT_ESTABLISHED")

    def test_application_core_and_hold_composition_remain_no_go(self):
        self.assertEqual(q.BOUNDARY["application"], "NO-GO")
        self.assertEqual(q.BOUNDARY["core"], "NO-GO")
        self.assertEqual(q.BOUNDARY["hold_admission"], "NOT_COMPOSED")
        self.assertEqual(q.BOUNDARY["recovery_action"], "NONE")

    def test_process_death_manifest_preserves_prior_cut_inputs(self):
        manifest, measured = q.inputs()
        self.assertEqual(len(manifest["preserved_file_sha256"]), 148)
        self.assertEqual(len(measured), 153)
        self.assertEqual(json.loads((q.ROOT / q.FIXTURE).read_text("ascii")), q.corpus())


if __name__ == "__main__":
    unittest.main()
