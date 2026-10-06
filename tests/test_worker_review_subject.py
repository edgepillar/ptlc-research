"""Synthetic source packet controls, never a worker or independent assessment."""

import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import check_worker_review_subject as subject
import test_witness_review_subject as fixtures


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_worker_review_subject.py"
SUBJECT_SHA256 = "f140380fe8c2a11387316c5b8ed7269cdce239f89592ded26588decf1c42c75e"


class WorkerSubjectTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.WitnessSubjectTests(methodName="runTest")
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture, self.root = fixture, fixture.root
        self.files = dict(fixture.files)
        report = b"UNFILLED witness report.\n"
        self.files[subject.witness.SUBJECT_PATH] = ("100644", fixture.raw)
        self.files[subject.WITNESS_REPORT_PATH] = ("100644", report)
        self.files["worker.txt"] = ("100644", b"Public synthetic worker source.\n")
        (self.root / subject.WITNESS_REPORT_PATH).write_bytes(report)
        fixture.fixture.index(subject.WITNESS_REPORT_PATH, report)
        self.commit = fixture.fixture.commit(self.files)
        self.pins = subject.Pins(self.commit, fixture.pins, fixture.digest,
                                 hashlib.sha256(report).hexdigest())
        self.expected = subject.generate(self.root, self.pins)
        self.raw = subject.encoded(self.expected)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        (self.root / subject.SUBJECT_PATH).write_bytes(self.raw)
        fixture.fixture.index(subject.SUBJECT_PATH, self.raw)

    def reject(self, value):
        raw = subject.encoded(value)
        with self.assertRaises(subject.SubjectError) as error:
            subject.verify_manifest(self.root, self.pins, raw, hashlib.sha256(raw).hexdigest())
        self.assertNotIn(str(self.root), str(error.exception))

    def test_complete_source_has_three_separate_scopes_and_no_assessment(self):
        self.assertEqual(subject.verify_checkout(self.root, self.pins, self.digest), self.expected)
        self.assertEqual(self.expected["file_count"], 10)
        self.assertEqual(self.expected["delta_from_witness"],
                         dict(added=3, changed=0, unchanged=7, removed_paths=[]))
        self.assertEqual(set(self.expected["prior_subjects"]),
                         {"construction", "observation", "witness"})
        self.assertEqual(len(self.expected["preserved_reports"]), 3)
        self.assertEqual(self.expected["boundary"]["assessment"], "NOT ASSESSED")

    def test_expected_commit_and_digest_are_independent_of_received_metadata(self):
        for value in (None, "HEAD", "0" * 64, self.pins.commit):
            with self.subTest(kind=value), self.assertRaises(subject.SubjectError):
                subject.verify_manifest(self.root, self.pins, self.raw, value)
        for value in ("HEAD", "0" * 40, self.fixture.commit):
            with self.subTest(pin=value), self.assertRaises(subject.SubjectError):
                subject.verify_manifest(self.root, replace(self.pins, commit=value), self.raw, self.digest)

    def test_received_tree_prior_scopes_and_boundaries_cannot_reselect_truth(self):
        for field in ("commit", "tree", "prior_subjects", "preserved_reports", "boundary"):
            value = copy.deepcopy(self.expected)
            value[field] = self.fixture.commit if field in {"commit", "tree"} else {}
            with self.subTest(field=field):
                self.reject(value)

    def test_missing_duplicate_extra_and_substituted_source_members_refuse(self):
        for kind in ("missing", "duplicate", "extra", "changed"):
            value = copy.deepcopy(self.expected)
            if kind == "missing":
                value["files"].pop()
            elif kind == "changed":
                value["files"][0]["sha256"] = "0" * 64
            else:
                row = copy.deepcopy(value["files"][0])
                if kind == "extra":
                    row["path"] = "extra.txt"
                value["files"].append(row)
            value["file_count"] = len(value["files"])
            with self.subTest(kind=kind):
                self.reject(value)

    def test_canonical_bytes_refuse_numeric_aliases_modes_status_and_extensions(self):
        for field, replacement in (("bytes", True), ("mode", "100755"),
                                   ("git_blob", "0" * 40), ("witness_status", "changed")):
            value = copy.deepcopy(self.expected)
            value["files"][0][field] = replacement
            with self.subTest(field=field):
                self.reject(value)
        value = copy.deepcopy(self.expected)
        value["delta_from_witness"]["changed"] = False
        self.assertEqual(value, self.expected)
        self.reject(value)
        self.reject(dict(self.expected, extra="unselected"))

    def test_unexamined_source_cannot_be_promoted_to_provenance_privacy_or_permission(self):
        for field in self.expected["boundary"]:
            value = copy.deepcopy(self.expected)
            value["boundary"][field] = "VERIFIED"
            with self.subTest(field=field):
                self.reject(value)

    def test_duplicate_keys_encoding_noncanonical_bytes_and_bound_refuse(self):
        for raw in (b'{"files":[],"files":[]}', self.raw.rstrip(b"\n"), b"null", b"\xff",
                    b" " * (subject.source.MAX_MANIFEST_BYTES + 1)):
            with self.subTest(length=len(raw)), self.assertRaises(subject.SubjectError):
                subject.verify_manifest(self.root, self.pins, raw, hashlib.sha256(raw).hexdigest())

    def test_all_six_prior_artifacts_are_protected_at_source_worktree_and_index(self):
        names = [p["manifest_path"] for p in self.expected["prior_subjects"].values()]
        names += [p["path"] for p in self.expected["preserved_reports"]]
        for name in names:
            original = self.files[name][1]
            with self.subTest(name=name):
                changed = dict(self.files, **{name: ("100644", b"Changed public artifact.\n")})
                with self.assertRaises(subject.SubjectError):
                    subject.generate(self.root, replace(self.pins, commit=self.fixture.fixture.commit(changed)))
                path = self.root / name
                path.write_bytes(b"Changed public artifact.\n")
                with self.assertRaises(subject.SubjectError):
                    subject.generate(self.root, self.pins)
                path.write_bytes(original)
                self.fixture.fixture.index(name, b"Changed public artifact.\n")
                with self.assertRaises(subject.SubjectError):
                    subject.generate(self.root, self.pins)
                self.fixture.fixture.index(name, original)

    def test_matching_witness_digest_cannot_hide_wrong_immutable_prior_subject(self):
        for pins in (replace(self.pins, witness_pins=replace(self.pins.witness_pins,
                                                           commit=self.fixture.fixture.current)),
                     replace(self.pins, witness_sha256="0" * 64),
                     replace(self.pins, witness_report_sha256="0" * 64)):
            with self.assertRaises(subject.SubjectError):
                subject.generate(self.root, pins)

    def test_current_source_edits_are_not_the_selected_immutable_inventory(self):
        path = self.root / "worker.txt"
        path.write_bytes(b"Changed public checkout bytes.\n")
        self.fixture.fixture.index("worker.txt", path.read_bytes())
        self.assertEqual(subject.generate(self.root, self.pins), self.expected)
        altered = self.fixture.fixture.commit(dict(self.files, **{
            "worker.txt": ("100644", b"Replacement public source.\n")}))
        self.fixture.fixture.git("replace", self.commit, altered)
        self.assertEqual(subject.generate(self.root, self.pins), self.expected)

    def test_new_manifest_worktree_and_index_must_match_selected_bytes(self):
        path = self.root / subject.SUBJECT_PATH
        path.write_bytes(b"{}\n")
        with self.assertRaises(subject.SubjectError):
            subject.verify_checkout(self.root, self.pins, self.digest)
        path.write_bytes(self.raw)
        self.fixture.fixture.index(subject.SUBJECT_PATH, b"{}\n")
        with self.assertRaises(subject.SubjectError):
            subject.verify_checkout(self.root, self.pins, self.digest)

    def test_unfilled_report_symlink_and_nonregular_index_refuse(self):
        name = subject.WITNESS_REPORT_PATH
        raw = self.files[name][1]
        self.fixture.fixture.index(name, raw, mode="120000")
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)
        self.fixture.fixture.index(name, raw)
        path = self.root / name
        path.unlink()
        target = self.root / "synthetic-report.txt"
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)

    def test_complete_archive_is_inspected_without_extraction_and_omissions_refuse(self):
        archive = self.root / "synthetic-worker-source.tar"
        self.fixture.fixture.git("archive", "--format=tar", "--output=" + str(archive), self.commit)
        before = set(self.root.rglob("*"))
        subject.source.verify_archive(archive, self.expected)
        self.assertEqual(set(self.root.rglob("*")), before)
        self.fixture.fixture.git("archive", "--format=tar", "--output=" + str(archive), self.fixture.commit)
        with self.assertRaises(subject.SubjectError):
            subject.source.verify_archive(archive, self.expected)

    def test_main_refuses_unknown_private_arguments_with_one_sanitized_error(self):
        result = subprocess.run([sys.executable, "-B", str(CHECKER), "--private-synthetic-value"],
                                capture_output=True, check=False, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1, b"", b"FAIL: worker subject inspection rejected\n"))


class PinnedWorkerSubjectTests(unittest.TestCase):
    def test_actual_complete_subject_preserves_three_fixed_subjects_and_reports(self):
        expected = subject.verify_checkout(ROOT, subject.Pins(subject.SUBJECT_COMMIT), SUBJECT_SHA256)
        self.assertEqual((expected["file_count"], expected["tree"]),
                         (423, "667260aee79ef353442feb9a9077731d0a76f88c"))
        self.assertEqual([expected["prior_subjects"][key]["file_count"]
                          for key in ("construction", "observation", "witness")], [119, 189, 360])
        self.assertEqual(expected["boundary"]["application_and_core"], "NO-GO")

    def test_cli_uses_independent_digest_and_emits_only_fixed_source_summary(self):
        result = subprocess.run([sys.executable, "-B", str(CHECKER),
            "--expect-commit", subject.SUBJECT_COMMIT, "--expect-manifest-sha256", SUBJECT_SHA256],
            capture_output=True, check=False, timeout=120)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0,
            b"PASS: complete worker subject: 423 files; three prior subjects and reports preserved; NOT ASSESSED\n", b""))


if __name__ == "__main__":
    unittest.main()
