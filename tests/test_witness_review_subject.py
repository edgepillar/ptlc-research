"""Complete source identity controls, never an independent witness assessment."""

import copy
from dataclasses import replace
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

from scripts import check_witness_subject as subject
import test_observation_review_subject as fixtures


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_witness_subject.py"
SUBJECT_SHA256 = "0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f"


class WitnessSubjectTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.ObservationSubjectTests(methodName="runTest")
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture, self.root = fixture, fixture.root
        self.files = dict(fixture.current_files)
        reports = ((subject.CONSTRUCTION_REPORT_PATH, b"UNFILLED construction report.\n"),
                   (subject.OBSERVATION_REPORT_PATH, b"UNFILLED observation report.\n"))
        self.files[subject.observation.SUBJECT_PATH] = ("100644", fixture.raw)
        for name, raw in reports:
            self.files[name] = ("100644", raw)
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
            fixture.index(name, raw)
        self.commit = fixture.commit(self.files)
        self.pins = subject.Pins(self.commit, fixture.current, hashlib.sha256(fixture.raw).hexdigest(),
            fixture.baseline, fixture.pins.baseline_sha256,
            hashlib.sha256(reports[0][1]).hexdigest(), hashlib.sha256(reports[1][1]).hexdigest())
        self.expected = subject.generate(self.root, self.pins)
        self.raw = subject.encoded(self.expected)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        (self.root / subject.SUBJECT_PATH).write_bytes(self.raw)
        fixture.index(subject.SUBJECT_PATH, self.raw)

    def reject(self, value):
        raw = subject.encoded(value)
        with self.assertRaises(subject.SubjectError) as error:
            subject.verify_manifest(self.root, self.pins, raw, hashlib.sha256(raw).hexdigest())
        self.assertNotIn(str(self.root), str(error.exception))

    def test_complete_tree_keeps_separate_prior_subjects_and_unfilled_reports(self):
        self.assertEqual(subject.verify_checkout(self.root, self.pins, self.digest), self.expected)
        self.assertEqual(self.expected["file_count"], 7)
        self.assertEqual(self.expected["delta_from_observation"],
                         {"added": 3, "changed": 0, "unchanged": 4, "removed_paths": []})
        self.assertEqual(self.expected["boundary"]["assessment"], "NOT ASSESSED")

    def test_expected_commit_and_digest_are_selected_outside_received_manifest(self):
        for value in (None, "HEAD", "0" * 64, self.pins.commit):
            with self.subTest(kind=str(value)), self.assertRaises(subject.SubjectError):
                subject.verify_manifest(self.root, self.pins, self.raw, value)
        for value in ("HEAD", "0" * 40, self.fixture.current):
            with self.subTest(pin=value), self.assertRaises(subject.SubjectError):
                subject.verify_manifest(self.root, replace(self.pins, commit=value), self.raw, self.digest)

    def test_received_commit_tree_and_prior_pins_cannot_reselect_subject(self):
        for field in ("commit", "tree", "prior_subjects", "preserved_reports", "boundary"):
            value = copy.deepcopy(self.expected)
            value[field] = self.fixture.baseline if field in {"commit", "tree"} else {}
            with self.subTest(field=field):
                self.reject(value)

    def test_missing_duplicate_extra_and_changed_inventory_members_refuse(self):
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

    def test_canonical_bytes_refuse_type_aliases_metadata_and_extensions(self):
        for field, replacement in (("bytes", True), ("mode", "100755"), ("git_blob", "0" * 40),
                                   ("observation_status", "changed")):
            value = copy.deepcopy(self.expected)
            value["files"][0][field] = replacement
            with self.subTest(field=field):
                self.reject(value)
        value = copy.deepcopy(self.expected)
        value["delta_from_observation"]["changed"] = False
        self.assertEqual(value, self.expected, "canonical bytes must reject boolean/integer aliases")
        self.reject(value)
        self.reject(dict(self.expected, extra="unselected"))

    def test_duplicate_keys_encoding_and_manifest_bound_refuse(self):
        for raw in (b'{"files":[],"files":[]}', self.raw.rstrip(b"\n"), b"null", b"\xff",
                    b" " * (subject.observation.MAX_MANIFEST_BYTES + 1)):
            with self.subTest(length=len(raw)), self.assertRaises(subject.SubjectError):
                subject.verify_manifest(self.root, self.pins, raw, hashlib.sha256(raw).hexdigest())

    def test_each_prior_artifact_is_protected_at_source_worktree_and_index(self):
        for name in (subject.observation.ORIGINAL_PATH, subject.observation.SUBJECT_PATH,
                     subject.CONSTRUCTION_REPORT_PATH, subject.OBSERVATION_REPORT_PATH):
            original = self.files[name][1]
            with self.subTest(name=name):
                changed = dict(self.files, **{name: ("100644", b"Changed public artifact.\n")})
                with self.assertRaises(subject.SubjectError):
                    subject.generate(self.root, replace(self.pins, commit=self.fixture.commit(changed)))
                path = self.root / name
                path.write_bytes(b"Changed public artifact.\n")
                with self.assertRaises(subject.SubjectError):
                    subject.generate(self.root, self.pins)
                path.write_bytes(original)
                self.fixture.index(name, b"Changed public artifact.\n")
                with self.assertRaises(subject.SubjectError):
                    subject.generate(self.root, self.pins)
                self.fixture.index(name, original)

    def test_old_inventory_digest_alone_cannot_hide_wrong_immutable_subject(self):
        altered = replace(self.pins, observation_commit=self.fixture.baseline)
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, altered)
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, replace(self.pins, observation_sha256="0" * 64))

    def test_new_manifest_worktree_and_index_must_agree_with_selected_bytes(self):
        path = self.root / subject.SUBJECT_PATH
        path.write_bytes(b"{}\n")
        with self.assertRaises(subject.SubjectError):
            subject.verify_checkout(self.root, self.pins, self.digest)
        path.write_bytes(self.raw)
        self.fixture.index(subject.SUBJECT_PATH, b"{}\n")
        with self.assertRaises(subject.SubjectError):
            subject.verify_checkout(self.root, self.pins, self.digest)

    def test_source_working_edits_cannot_redefine_immutable_review_bytes(self):
        path = self.root / "docs/a.txt"
        path.write_bytes(b"Different public worktree source.\n")
        self.fixture.index("docs/a.txt", path.read_bytes())
        self.assertEqual(subject.generate(self.root, self.pins), self.expected)

    def test_replacement_refs_do_not_substitute_selected_witness_source(self):
        altered = self.fixture.commit(dict(self.files, **{"run.py": ("100755", b"Replacement.\n")}))
        self.fixture.git("replace", self.commit, altered)
        self.assertEqual(subject.generate(self.root, self.pins), self.expected)

    def test_missing_local_objects_fail_without_lazy_fetch(self):
        row = next(row for row in self.expected["files"] if row["path"] == subject.CONSTRUCTION_REPORT_PATH)
        object_id = row["git_blob"]
        (self.root / ".git/objects" / object_id[:2] / object_id[2:]).unlink()
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)

    def test_nonregular_unresolved_and_symlinked_protected_artifacts_refuse(self):
        name = subject.OBSERVATION_REPORT_PATH
        path = self.root / name
        original = path.read_bytes()
        self.fixture.index(name, original, mode="120000")
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)
        self.fixture.git("update-index", "--force-remove", name)
        wire = ("100644 " + self.fixture.blob(original) + " 1\t" + name + "\n").encode("ascii")
        self.fixture.git("update-index", "--index-info", data=wire)
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)
        self.fixture.git("update-index", "--force-remove", name)
        self.fixture.index(name, original)
        target = self.root / "target.txt"
        target.write_bytes(original)
        path.unlink()
        path.symlink_to(target)
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)

    def test_dependency_blobs_are_not_silently_excluded(self):
        for name, raw, mode in (("dependency.txt", b"\xff", "100644"),
                                ("dependency", b"synthetic-target", "120000"),
                                ("large.txt", b"X" * (subject.observation.MAX_BLOB_BYTES + 1), "100644")):
            commit = self.fixture.commit(dict(self.files, **{name: (mode, raw)}))
            with self.subTest(name=name), self.assertRaises(subject.SubjectError):
                subject.generate(self.root, replace(self.pins, commit=commit))

    def archive(self, members):
        path = self.root / "witness-source.tar"
        with tarfile.open(path, "w") as handle:
            for info, raw in members:
                handle.addfile(info, io.BytesIO(raw) if info.isreg() else None)
        return path

    def members(self):
        result = []
        for row in self.expected["files"]:
            info = tarfile.TarInfo(row["path"])
            info.mode = 0o755 if row["mode"] == "100755" else 0o644
            raw = self.files[row["path"]][1]
            info.size = len(raw)
            result.append((info, raw))
        return result

    def test_complete_plain_git_archive_is_checked_without_extraction(self):
        path = self.root / "git-witness.tar"
        self.fixture.git("archive", "--format=tar", "--output=" + str(path), self.commit)
        before = set(self.root.rglob("*"))
        subject.observation.verify_archive(path, self.expected)
        self.assertEqual(set(self.root.rglob("*")), before)

    def test_archive_omissions_duplicates_extensions_and_payload_substitutions_refuse(self):
        for kind in ("missing", "duplicate", "extra", "payload"):
            members = self.members()
            if kind == "missing":
                members.pop()
            elif kind == "duplicate":
                members.append(copy.deepcopy(members[0]))
            elif kind == "extra":
                members.append((tarfile.TarInfo("extra.txt"), b""))
            else:
                info, raw = members[0]
                members[0] = (info, b"X" + raw[1:])
            with self.subTest(kind=kind), self.assertRaises(subject.SubjectError):
                subject.observation.verify_archive(self.archive(members), self.expected)

    def test_archive_links_unsafe_paths_and_appended_members_refuse(self):
        for kind in ("../extra", "symlink", "hardlink", "appended"):
            members = self.members()
            info, raw = members[0]
            if kind == "appended":
                first = self.archive(members).read_bytes()
                extra = self.archive([(tarfile.TarInfo("extra.txt"), b"")]).read_bytes()
                path = self.root / "appended.tar"
                path.write_bytes(first + extra)
            else:
                if kind == "../extra":
                    info.name = kind
                else:
                    info.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                    info.linkname, info.size, raw = "synthetic-target", 0, b""
                members[0] = (info, raw)
                path = self.archive(members)
            with self.subTest(kind=kind), self.assertRaises(subject.SubjectError):
                subject.observation.verify_archive(path, self.expected)

    def test_cli_requires_both_independent_pins_and_sanitizes_failures(self):
        for extra in ([], ["--expect-commit", subject.SUBJECT_COMMIT],
                      ["--expect-commit", str(self.root), "--expect-manifest-sha256", "0" * 64],
                      ["--private-option", str(self.root)]):
            result = subprocess.run([sys.executable, "-B", str(CHECKER), "--root", str(self.root), *extra],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (1, "", "FAIL: witness subject inspection rejected\n"))
            self.assertNotIn(str(self.root), result.stderr)


class PinnedWitnessSubjectTests(unittest.TestCase):
    def test_real_360_file_subject_preserves_both_prior_subjects_and_reports(self):
        value = subject.verify_checkout(ROOT, subject.Pins(subject.SUBJECT_COMMIT), SUBJECT_SHA256)
        self.assertEqual(value["file_count"], 360)
        self.assertEqual(value["prior_subjects"]["observation"]["file_count"], 189)
        self.assertEqual(value["prior_subjects"]["construction"]["file_count"], 119)
        self.assertEqual(value["delta_from_observation"]["removed_paths"], [])
        self.assertIn("tests/original_witness_store.py", {row["path"] for row in value["files"]})
        self.assertNotIn("scripts/check_witness_subject.py", {row["path"] for row in value["files"]})

    def test_real_cli_emits_exact_source_without_verifier_or_original_index_changes(self):
        names = (subject.observation.ORIGINAL_PATH, subject.observation.SUBJECT_PATH,
                 subject.CONSTRUCTION_REPORT_PATH, subject.OBSERVATION_REPORT_PATH)
        before = {name: subject.observation._index(ROOT, name) for name in names}
        result = subprocess.run([sys.executable, "-B", str(CHECKER), "--expect-commit", subject.SUBJECT_COMMIT,
                                 "--emit"], capture_output=True, timeout=30)
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(hashlib.sha256(result.stdout).hexdigest(), SUBJECT_SHA256)
        self.assertEqual({name: subject.observation._index(ROOT, name) for name in names}, before)
        with patch.object(subject.observation, "verify_archive", side_effect=AssertionError("unexpected archive")):
            self.assertEqual(subject.verify_manifest(ROOT, subject.Pins(subject.SUBJECT_COMMIT),
                                                    result.stdout, SUBJECT_SHA256)["file_count"], 360)


if __name__ == "__main__":
    unittest.main(verbosity=2)
