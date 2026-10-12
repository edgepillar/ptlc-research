"""Selected read-only owner controls over disclosed synthetic reference bytes.

The executable matches exact fixture requests and contains no arithmetic. The
separate native qualifier supplies actual public-result mathematical evidence.
Fault injection here qualifies ownership and refusal, not an external runtime.
"""

import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from offline_session.nom_recovery import RecoveryError, Quarantined, canonical, fcntl
from offline_session.nom_strict_open import StrictNomRecovery
from offline_session.nom_verifier import NomPublicVerifier
from scripts import qualify_nom_strict_open as q
from scripts.nom_cut_capture import retain, sha


class SelectedVerifier:
    """Exact disclosed values only; no signature arithmetic or recovery."""

    def __init__(self, context, short, long, result=True):
        self.context_digest_hex = context
        self.short = short; self.long = long; self.result = result; self.modes = []

    def verify_pair(self):
        self.modes.append("verify-pair")
        return True

    def verify_claim(self, leg, signature):
        self.modes.append("verify-" + leg)
        if leg == "long":
            if isinstance(self.result, BaseException):
                raise self.result
            if callable(self.result):
                return self.result()
            return self.result if signature == self.long else False
        return signature == self.short

    def recover_long(self, *_):
        raise AssertionError("read-only open entered recovery")


class StrictOpenControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name); cls.directory.chmod(0o700)
        cls.worker = cls.directory / "disclosed-exact-fixture-worker"
        cls.terms, cls.pair, _, _, _ = q.prior.prior.selected_inputs()
        fixture = json.loads((q.ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
        cls.short = fixture["short_signature_hex"]; cls.long = fixture["long_signature_hex"]
        cls.worker.write_text("#!" + sys.executable + "\n", encoding="ascii"); cls.worker.chmod(0o700)
        verifier = NomPublicVerifier(cls.worker, sha(cls.worker.read_bytes()), cls.terms, cls.pair)
        cls.context = verifier.context_digest_hex
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

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.selected = tempfile.TemporaryDirectory()
        self.addCleanup(self.selected.cleanup)
        self.path = Path(self.selected.name) / "journal.log"
        self.path.parent.chmod(0o700)
        retain(self.path, bytes.fromhex(self.report["cases"][3]["journal_hex"]))

    def verifier(self, result=True):
        return SelectedVerifier(self.context, self.short, self.long, result)

    def opened(self, verifier=None, path=None):
        return StrictNomRecovery.open(path or self.path, self.terms, self.pair, role="bob",
            verifier=verifier or self.verifier(), observation_verifier=lambda proof: False)

    def refused_report(self, change):
        value = copy.deepcopy(self.report); change(value)
        with self.assertRaises(ValueError):
            q.check_cases(value)

    def test_valid_result_is_verified_before_result_only_owner_returns(self):
        verifier = self.verifier()
        with self.opened(verifier) as store:
            self.assertEqual(verifier.modes, ["verify-pair", "verify-short", "verify-long"])
            self.assertEqual(store.status()["recovered_long_hex"], self.long)

    def test_result_only_open_keeps_absent_original_and_charge(self):
        before = self.path.read_bytes()
        reference = q.prior.prior.synthetic_claim
        def existing_short_only(terms, leg, signature):
            self.assertEqual(leg, "short", "invented long original")
            return reference(terms, leg, signature)
        # The frozen parser checks the encoding of the actual retained short.
        # Only construction of an absent long original is forbidden here.
        with patch("offline_session.nom_recovery.synthetic_claim", side_effect=existing_short_only):
            with self.opened() as store:
                self.assertEqual(store.status()["originals"], {})
                self.assertEqual(store.status()["recovery_count"], 1)
        self.assertEqual(self.path.read_bytes(), before)

    def test_missing_results_never_call_long_verifier(self):
        for row in self.report["cases"][:3]:
            self.path.write_bytes(bytes.fromhex(row["journal_hex"]))
            verifier = self.verifier(AssertionError("invented result"))
            with self.opened(verifier) as store:
                self.assertEqual(store.status()["recovered_long_hex"], "")
            self.assertEqual(verifier.modes, ["verify-pair", "verify-short"])

    def test_complete_original_and_result_receive_separate_checks(self):
        self.path.write_bytes(bytes.fromhex(self.report["cases"][4]["journal_hex"]))
        verifier = self.verifier()
        with self.opened(verifier) as store:
            self.assertIn("long", store.status()["originals"])
        self.assertEqual(verifier.modes, ["verify-pair", "verify-long", "verify-short", "verify-long"])

    def test_false_result_refuses_and_releases_original_owner(self):
        before = self.path.read_bytes()
        with self.assertRaisesRegex(RecoveryError, "retained long completion verification failed"):
            self.opened(self.verifier(False))
        self.assertTrue(q.owner_available(self.path))
        self.assertEqual(self.path.read_bytes(), before)

    def test_non_boolean_truthy_result_does_not_pass(self):
        with self.assertRaises(RecoveryError):
            self.opened(self.verifier(1))
        self.assertTrue(q.owner_available(self.path))

    def test_worker_refusal_preserves_cause_and_owner_release(self):
        error = RecoveryError("disclosed selected worker refusal")
        with self.assertRaises(RecoveryError) as caught:
            self.opened(self.verifier(error))
        self.assertIs(caught.exception, error)
        self.assertTrue(q.owner_available(self.path))

    def test_unavailable_verifier_does_not_recover_or_write(self):
        before = self.path.read_bytes()
        with self.assertRaises(Quarantined):
            self.opened(self.verifier(OSError("disclosed unavailable worker")))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(q.owner_available(self.path))

    def test_unexpected_worker_exception_releases_owner_without_retry(self):
        error = RuntimeError("disclosed selected worker interruption"); verifier = self.verifier(error)
        with self.assertRaises(RuntimeError) as caught:
            self.opened(verifier)
        self.assertIs(caught.exception, error)
        self.assertEqual(verifier.modes.count("verify-long"), 1)
        self.assertTrue(q.owner_available(self.path))

    def test_keyboard_interrupt_releases_owner_and_preserves_bytes(self):
        before = self.path.read_bytes(); error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.opened(self.verifier(error))
        self.assertIs(caught.exception, error)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(q.owner_available(self.path))

    def test_system_exit_releases_selected_owner(self):
        with self.assertRaises(SystemExit) as caught:
            self.opened(self.verifier(SystemExit(73)))
        self.assertEqual(caught.exception.code, 73)
        self.assertTrue(q.owner_available(self.path))

    def test_interrupt_during_retained_original_check_also_releases_owner(self):
        self.path.write_bytes(bytes.fromhex(self.report["cases"][4]["journal_hex"]))
        with self.assertRaises(KeyboardInterrupt):
            self.opened(self.verifier(KeyboardInterrupt()))
        self.assertTrue(q.owner_available(self.path))

    def test_strict_owner_uses_read_only_descriptor(self):
        with self.opened() as store:
            self.assertEqual(fcntl.fcntl(store._fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)

    def test_missing_journal_is_refused_without_creation(self):
        target = self.path.parent / "missing.log"
        with self.assertRaises(Quarantined):
            self.opened(path=target)
        self.assertFalse(target.exists())
        self.assertEqual(sorted(p.name for p in self.path.parent.iterdir()), ["journal.log"])

    def test_symlink_selection_is_refused_without_modifying_target(self):
        target = self.path.parent / "alias.log"; target.symlink_to(self.path.name)
        before = self.path.read_bytes()
        with self.assertRaises(Quarantined):
            self.opened(path=target)
        self.assertEqual(self.path.read_bytes(), before)

    def test_nonprivate_journal_mode_is_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(Quarantined):
            self.opened()
        self.assertTrue(q.owner_available(self.path))

    def test_fifo_selection_is_refused_without_waiting_for_a_writer(self):
        target = self.path.parent / "fifo"; os.mkfifo(target, 0o600)
        with self.assertRaises(Quarantined):
            self.opened(path=target)

    def test_hard_linked_journal_is_refused(self):
        os.link(self.path, self.path.parent / "hard-link.log")
        with self.assertRaises(Quarantined):
            self.opened()
        self.assertTrue(q.owner_available(self.path))

    def test_nonprivate_parent_is_refused_before_file_ownership(self):
        self.path.parent.chmod(0o755)
        with self.assertRaises(RecoveryError):
            self.opened()
        self.assertTrue(q.owner_available(self.path))

    def test_incomplete_journal_refuses_and_releases_owner(self):
        before = self.path.read_bytes()[:-1]; self.path.write_bytes(before)
        with self.assertRaises(Quarantined):
            self.opened()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(q.owner_available(self.path))

    def test_wrong_verifier_context_refuses_before_file_ownership(self):
        verifier = self.verifier(); verifier.context_digest_hex = "00" * 32
        with self.assertRaisesRegex(RecoveryError, "pair verification failed"):
            self.opened(verifier)
        self.assertEqual(verifier.modes, [])
        self.assertTrue(q.owner_available(self.path))

    def test_second_cooperating_owner_is_refused_and_first_survives(self):
        with self.opened() as first:
            with self.assertRaisesRegex(RecoveryError, "already has an owner"):
                self.opened()
            self.assertEqual(first.status()["recovery_count"], 1)
        self.assertTrue(q.owner_available(self.path))

    def test_read_only_mutators_refuse_before_any_worker_or_write(self):
        verifier = self.verifier(); before = self.path.read_bytes()
        with self.opened(verifier) as store:
            modes = list(verifier.modes)
            for method, args in ((store.recover_long, (b"synthetic unused", {})),
                    (store.prepare_attempt, ("long",)), (store.retain_original, ("long", b"synthetic unused")),
                    (store.record_observation, ({},)), (store._append, ({},))):
                with self.assertRaisesRegex(RecoveryError, "read-only"):
                    method(*args)
            self.assertEqual(verifier.modes, modes)
            self.assertEqual(store.status()["attempts"], {})
        self.assertEqual(self.path.read_bytes(), before)

    def test_file_growth_during_result_check_refuses_and_releases_owner(self):
        def outside_change():
            with self.path.open("ab") as stream:
                stream.write(b"\n")
            return True
        with self.assertRaises(Quarantined):
            self.opened(self.verifier(outside_change))
        self.assertTrue(q.owner_available(self.path))

    def test_encoding_only_legacy_open_and_strict_refusal_are_distinct(self):
        row = self.report["adversarial_control"]
        self.assertEqual(row["legacy_result"], "00" * 64)
        self.assertEqual(row["legacy_modes"], ["verify-pair", "verify-short"])
        self.assertEqual(row["strict_modes"][-1], "verify-long")
        self.assertEqual(row["strict_outcome"], "REFUSED BEFORE OWNER RETURN")

    def test_invalid_copy_does_not_replace_actual_retained_result(self):
        self.assertEqual(self.report["cases"][3]["retained_result"], self.long)
        self.assertNotEqual(self.report["cases"][3]["journal_hex"], self.report["adversarial_control"]["copy_hex"])
        self.assertTrue(self.report["adversarial_control"]["owner_released"])
        self.assertTrue(self.report["adversarial_control"]["copy_unchanged"])

    def test_expected_invalid_worker_exit_and_empty_reply_remain_failure_evidence(self):
        row = self.report["reopen_worker_calls"][-1]
        self.assertEqual((row["exit_code"], row["stdout_hex"], row["stderr_hex"]), (2, "", ""))
        self.assertEqual(row["stream_completeness"], "COMPLETE")

    def test_strict_open_never_reinvokes_observer_or_enters_recovery(self):
        for row in self.report["cases"]:
            self.assertEqual(row["observer_calls_on_replay"], 0)
            self.assertEqual(row["automatic_worker_entries_on_reopen"], 0)
            self.assertNotIn("recover-long", row["reopen_modes"])
        self.assertEqual(q.BOUNDARY["current_chain_authority"], "UNFILLED")

    def test_before_spawn_custody_includes_all_sources_and_both_executables(self):
        subject = json.loads((self.originals / "subject-before-first-spawn.json").read_text("ascii"))
        self.assertTrue(subject["before_first_actor_or_worker_spawn"])
        self.assertEqual(subject["input_sha256"], q.inputs()[1])
        for index, name in enumerate(q.inputs()[1]):
            self.assertEqual((self.originals / f"source-{index:03d}.original").read_bytes(), (q.ROOT / name).read_bytes())
        for filename, key in (("selected-public-executable.original", "executable_sha256"),
                              ("selected-python-executable.original", "python_executable_sha256")):
            self.assertEqual(sha((self.originals / filename).read_bytes()), subject[key])

    def test_all_actual_actor_deaths_and_original_worker_exits_are_retained(self):
        calls = []
        for row in self.report["cases"]:
            directory = self.originals / row["cut"]
            self.assertEqual(row["actor_streams"]["exit_code"], 72)
            self.assertEqual((directory / "actor.stdout").read_bytes().hex(), row["actor_streams"]["stdout_hex"])
            values = q.prior.read_calls(directory / "worker")
            self.assertEqual(values, self.report["actor_worker_calls"][row["cut"]]); calls.extend(values)
        parent = q.read_calls(self.originals / "reopen-worker")
        self.assertEqual(parent, self.report["reopen_worker_calls"]); calls.extend(parent)
        self.assertEqual(len(calls), 34)
        self.assertEqual([v["exit_code"] for v in calls], [0] * 33 + [2])

    def test_original_custody_files_are_private_and_not_overwritable(self):
        for path in self.originals.rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            retain(self.originals / "adversarial-result-only.log", b"replacement")

    def test_missing_case_is_refused_by_qualification_gate(self):
        self.refused_report(lambda value: value["cases"].pop())

    def test_skipped_present_result_check_is_refused_by_qualification_gate(self):
        self.refused_report(lambda value: value["cases"][3].update(reopen_modes=["verify-pair", "verify-short"]))

    def test_erased_recovery_charge_is_refused_by_qualification_gate(self):
        self.refused_report(lambda value: value["cases"][1].update(charged=0))

    def test_invented_absent_original_is_refused_by_qualification_gate(self):
        self.refused_report(lambda value: value["cases"][3].update(retained_long_original=value["cases"][4]["retained_long_original"]))

    def test_recovery_reentry_is_refused_by_qualification_gate(self):
        self.refused_report(lambda value: value["cases"][2].update(automatic_worker_entries_on_reopen=1))

    def test_invalid_worker_exit_cannot_be_relabelled_success(self):
        self.refused_report(lambda value: value["reopen_worker_calls"][-1].update(exit_code=0))

    def test_selected_profile_preserves_previous_source_inputs_and_no_go(self):
        manifest, measured = q.inputs()
        self.assertEqual(manifest["preserved_file_sha256"], q.prior.inputs()[1])
        self.assertEqual(len(measured), len(q.prior.inputs()[1]) + 5)
        self.assertEqual((q.BOUNDARY["application"], q.BOUNDARY["core"], q.BOUNDARY["recovery_action"]),
                         ("NO-GO", "NO-GO", "NONE"))


if __name__ == "__main__":
    unittest.main()
