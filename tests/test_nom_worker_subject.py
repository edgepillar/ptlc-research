"""Real local Git controls for the separate source identity, never a native build."""

import copy
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import check_nom_worker_subject as check


class NomSourceFixture:
    def __init__(self, root):
        self.root = root
        self.environment = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                                GIT_AUTHOR_NAME="PTLC Synthetic", GIT_COMMITTER_NAME="PTLC Synthetic",
                                GIT_AUTHOR_EMAIL="synthetic" + chr(64) + "ptlc-research.invalid",
                                GIT_COMMITTER_EMAIL="synthetic" + chr(64) + "ptlc-research.invalid")
        self.git("init", "-q")
        for name in check.REQUIRED + check.PRESERVED_REPORTS + ("docs/extra.txt",):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"Synthetic source identity only; no compiled behavior.\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Freeze synthetic source")
        self.commit = self.git("rev-parse", "HEAD").strip()
        self.manifest = check.generate(root, self.commit)
        self.write(self.manifest)

    def git(self, *arguments):
        return subprocess.run(["git", *arguments], cwd=self.root, env=self.environment,
                              check=True, capture_output=True, text=True).stdout

    def write(self, value):
        path = self.root / check.SUBJECT_PATH
        path.parent.mkdir(exist_ok=True)
        raw = check.encoded(value)
        path.write_bytes(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        self.git("add", check.SUBJECT_PATH)

    def verify(self):
        return check.verify(self.root, self.commit, self.digest)


class NomSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = NomSourceFixture(Path(self.temp.name))

    def test_complete_immutable_inventory_includes_nonbuild_source(self):
        value, _ = self.fixture.verify()
        self.assertEqual(value["file_count"], len(check.REQUIRED + check.PRESERVED_REPORTS) + 1)
        self.assertIn("docs/extra.txt", [row["path"] for row in value["files"]])
        self.assertNotIn("docs/extra.txt", value["build_source_paths"])
        self.assertEqual(value["boundary"]["independent_assessment"], "NOT ASSESSED")

    def test_reselected_digest_cannot_hide_an_omitted_nonbuild_file(self):
        value = copy.deepcopy(self.fixture.manifest)
        value["files"] = [row for row in value["files"] if row["path"] != "docs/extra.txt"]
        value["file_count"] -= 1
        self.fixture.write(value)
        with self.assertRaises(check.SubjectError):
            self.fixture.verify()

    def test_reselected_digest_cannot_substitute_worker_or_source_selection(self):
        for field, value in (("worker", "verify_original_read_response"), ("commit", "f" * 40),
                             ("tree", "e" * 40), ("file_count", True)):
            changed = copy.deepcopy(self.fixture.manifest)
            changed[field] = value
            self.fixture.write(changed)
            with self.subTest(field=field), self.assertRaises(check.SubjectError):
                self.fixture.verify()

    def test_worktree_and_index_build_changes_are_refused_independently(self):
        name = "qualification/examples/verify_nom_swap.rs"
        path = self.fixture.root / name
        original = path.read_bytes()
        path.write_bytes(original + b"Changed synthetic source.\n")
        with self.assertRaises(check.SubjectError): self.fixture.verify()
        self.fixture.git("add", name)
        path.write_bytes(original)
        with self.assertRaises(check.SubjectError): self.fixture.verify()

    def test_preserved_assessment_change_is_refused_without_transferred_approval(self):
        path = self.fixture.root / check.PRESERVED_REPORTS[0]
        path.write_bytes(b"Synthetic asserted acceptance is not a frozen report.\n")
        self.fixture.git("add", check.PRESERVED_REPORTS[0])
        with self.assertRaises(check.SubjectError): self.fixture.verify()

    def test_manifest_index_and_noncanonical_bytes_are_refused(self):
        path = self.fixture.root / check.SUBJECT_PATH
        raw = path.read_bytes()
        path.write_bytes(raw + b" ")
        with self.assertRaises(check.SubjectError): self.fixture.verify()
        self.fixture.git("add", check.SUBJECT_PATH)
        self.fixture.digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(check.SubjectError): self.fixture.verify()

    def test_mutable_ref_and_missing_objects_have_no_fetch_fallback(self):
        for commit in ("main", "f" * 40):
            with self.subTest(commit=commit), self.assertRaises(check.SubjectError):
                check.generate(self.fixture.root, commit)

    def test_prepared_copy_is_exact_and_extra_or_changed_files_are_refused(self):
        destination = self.fixture.root / "prepared"
        destination.mkdir(mode=0o700)
        value, bodies = check.prepare(self.fixture.root, destination, self.fixture.commit, self.fixture.digest)
        self.assertEqual(check.selected_copy(destination, value, bodies), len(value["build_source_paths"]))
        path = destination / "qualification/extra.txt"
        path.write_bytes(b"Synthetic unexpected source.\n")
        with self.assertRaises(check.SubjectError): check.selected_copy(destination, value, bodies)
        path.unlink()
        path = destination / "qualification/Cargo.toml"
        path.write_bytes(b"Synthetic replacement manifest.\n")
        with self.assertRaises(check.SubjectError): check.selected_copy(destination, value, bodies)

    def test_preparation_refuses_nonempty_broad_and_linked_destinations(self):
        destination = self.fixture.root / "prepared"
        destination.mkdir(mode=0o755)
        destination.chmod(0o755)
        with self.assertRaises(check.SubjectError):
            check.prepare(self.fixture.root, destination, self.fixture.commit, self.fixture.digest)
        destination.chmod(0o700)
        (destination / "existing").write_bytes(b"Retain synthetic prior evidence.\n")
        with self.assertRaises(check.SubjectError):
            check.prepare(self.fixture.root, destination, self.fixture.commit, self.fixture.digest)
        link = self.fixture.root / "linked"
        link.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(check.SubjectError):
            check.prepare(self.fixture.root, link, self.fixture.commit, self.fixture.digest)


if __name__ == "__main__": unittest.main()
