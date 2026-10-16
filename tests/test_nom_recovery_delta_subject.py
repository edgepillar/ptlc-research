"""Real local Git controls for complete delta identity, never independent review."""

import copy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import check_nom_recovery_delta_subject as check


class DeltaFixture:
    def __init__(self, root):
        self.root = root
        self.environment = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                                GIT_AUTHOR_NAME="PTLC Synthetic", GIT_COMMITTER_NAME="PTLC Synthetic",
                                GIT_AUTHOR_EMAIL="synthetic" + chr(64) + "ptlc-research.invalid",
                                GIT_COMMITTER_EMAIL="synthetic" + chr(64) + "ptlc-research.invalid")
        self.git("init", "-q")
        initial = set(check.nom.REQUIRED + check.PRESERVED_BASELINE + ("docs/nonbuild.txt", "docs/retired.txt"))
        for name in sorted(initial):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"Synthetic source identity only; no construction assessment.\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Freeze synthetic prior source")
        baseline = self.git("rev-parse", "HEAD").strip()
        prior = check.encoded(check.nom.generate(root, baseline))
        (root / check.nom.SUBJECT_PATH).write_bytes(prior)
        report = b"UNFILLED synthetic report; no independent assessment.\n"
        (root / check.NOM_REPORT_PATH).write_bytes(report)
        (root / "docs/nonbuild.txt").write_bytes(b"Changed synthetic nonbuild material.\n")
        (root / "docs/retired.txt").unlink()
        (root / "docs/added.txt").write_bytes(b"Added synthetic context.\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "Freeze synthetic recovery delta")
        self.pins = check.Pins(self.git("rev-parse", "HEAD").strip(), baseline,
                               hashlib.sha256(prior).hexdigest(), hashlib.sha256(report).hexdigest())
        self.manifest = check.generate(root, self.pins)
        self.write(self.manifest)

    def git(self, *arguments):
        return subprocess.run(["git", *arguments], cwd=self.root, env=self.environment,
                              check=True, capture_output=True, text=True).stdout

    def write(self, value):
        raw = check.encoded(value)
        (self.root / check.SUBJECT_PATH).write_bytes(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        self.git("add", check.SUBJECT_PATH)

    def advance(self, *names):
        self.git("reset", "-q", "HEAD", "--", check.SUBJECT_PATH)
        self.git("add", "--", *names)
        self.git("commit", "-qm", "Freeze synthetic changed subject")
        self.pins = replace(self.pins, commit=self.git("rev-parse", "HEAD").strip())

    def verify(self):
        return check.verify(self.root, self.pins, self.digest)


class NomRecoveryDeltaSubjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = DeltaFixture(Path(self.temp.name))

    def test_complete_source_and_mode_aware_delta_include_nonbuild_and_removed_paths(self):
        value = self.fixture.verify()
        self.assertEqual(value["delta"], dict(added=3, changed=1, unchanged=15,
                                              removed_paths=["docs/retired.txt"]))
        self.assertEqual(value["source_bytes"], sum(row["bytes"] for row in value["files"]))
        self.assertEqual(value["boundary"]["independent_assessment"], "NOT ASSESSED")
        self.assertEqual(value["boundary"]["application_and_core"], "NO-GO")
        self.assertEqual(len(value["preserved_artifacts"]), 11)
        path = self.fixture.root / "docs/added.txt"
        self.fixture.git("reset", "-q", "HEAD", "--", check.SUBJECT_PATH)
        self.fixture.git("update-index", "--chmod=+x", "docs/added.txt")
        self.fixture.git("commit", "-qm", "Freeze synthetic executable class")
        self.fixture.pins = replace(self.fixture.pins, commit=self.fixture.git("rev-parse", "HEAD").strip())
        changed = check.generate(self.fixture.root, self.fixture.pins)
        self.assertEqual(next(row for row in changed["files"] if row["path"] == "docs/added.txt")["mode"], "100755")
        self.assertTrue(path.exists())

    def test_reselected_digest_cannot_hide_a_nonbuild_file_or_removed_history(self):
        for field in ("files", "delta"):
            value = copy.deepcopy(self.fixture.manifest)
            if field == "files":
                value["files"] = [row for row in value["files"] if row["path"] != "docs/added.txt"]
                value["file_count"] -= 1
            else:
                value["delta"]["removed_paths"] = []
            self.fixture.write(value)
            with self.subTest(field=field), self.assertRaises(check.SubjectError):
                self.fixture.verify()

    def test_reselected_digest_cannot_change_scope_tree_status_limits_or_assessment(self):
        mutations = (("tree", "e" * 40), ("commit", "f" * 40), ("file_count", True),
                     ("limits", {}), ("boundary", dict(independent_assessment="ASSESSED")))
        for field, replacement in mutations:
            value = copy.deepcopy(self.fixture.manifest)
            value[field] = replacement
            self.fixture.write(value)
            with self.subTest(field=field), self.assertRaises(check.SubjectError):
                self.fixture.verify()
        value = copy.deepcopy(self.fixture.manifest)
        next(row for row in value["files"] if row["path"] == "docs/added.txt")["nom_worker_status"] = "unchanged"
        self.fixture.write(value)
        with self.assertRaises(check.SubjectError): self.fixture.verify()

    def test_manifest_index_digest_duplicate_keys_and_noncanonical_bytes_are_separate_refusals(self):
        path = self.fixture.root / check.SUBJECT_PATH
        raw = path.read_bytes()
        path.write_bytes(raw + b" ")
        with self.assertRaises(check.SubjectError): self.fixture.verify()
        self.fixture.git("add", check.SUBJECT_PATH)
        self.fixture.digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(check.SubjectError): self.fixture.verify()
        with self.assertRaises(check.SubjectError):
            check.verify_manifest(self.fixture.root, self.fixture.pins,
                                  b'{"schema":1,"schema":2}', "0" * 64)
        self.fixture.write(self.fixture.manifest)
        with self.assertRaises(check.SubjectError):
            check.verify(self.fixture.root, self.fixture.pins, "0" * 64)

    def test_protected_baseline_artifact_changes_in_tree_worktree_and_index_are_refused(self):
        name = check.PRESERVED_BASELINE[0]
        path = self.fixture.root / name
        original = path.read_bytes()
        path.write_bytes(original + b"Changed synthetic retained artifact.\n")
        with self.assertRaises(check.SubjectError): self.fixture.verify()
        self.fixture.git("add", name)
        path.write_bytes(original)
        with self.assertRaises(check.SubjectError): self.fixture.verify()
        path.write_bytes(original + b"Changed synthetic retained artifact.\n")
        self.fixture.advance(name)
        with self.assertRaises(check.SubjectError): check.generate(self.fixture.root, self.fixture.pins)

    def test_separate_unfilled_nom_report_cannot_be_replaced_in_source_or_checkout(self):
        name = check.NOM_REPORT_PATH
        path = self.fixture.root / name
        path.write_bytes(b"Synthetic claimed approval is not the selected unfilled report.\n")
        with self.assertRaises(check.SubjectError): self.fixture.verify()
        self.fixture.advance(name)
        with self.assertRaises(check.SubjectError): check.generate(self.fixture.root, self.fixture.pins)

    def test_forged_prior_inventory_still_refuses_after_reselecting_its_digest(self):
        path = self.fixture.root / check.nom.SUBJECT_PATH
        prior = check.source._json(path.read_bytes())
        prior["files"].pop()
        prior["file_count"] -= 1
        raw = check.encoded(prior)
        path.write_bytes(raw)
        self.fixture.advance(check.nom.SUBJECT_PATH)
        pins = replace(self.fixture.pins, baseline_sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(check.SubjectError): check.generate(self.fixture.root, pins)

    def test_new_bounded_profile_reads_a_larger_blob_without_relaxing_older_readers(self):
        path = self.fixture.root / "docs/large.txt"
        path.write_bytes(b"0\n" * (check.source.MAX_BLOB_BYTES // 2 + 1))
        self.fixture.advance("docs/large.txt")
        value = check.generate(self.fixture.root, self.fixture.pins)
        self.assertEqual(next(row for row in value["files"] if row["path"] == "docs/large.txt")["bytes"], path.stat().st_size)
        with self.assertRaises(check.SubjectError):
            check.source._inventory(self.fixture.root, self.fixture.pins.commit)
        self.assertEqual(check.source.MAX_BLOB_BYTES, 2 * 1024 * 1024)
        self.assertEqual(check.source.MAX_SOURCE_BYTES, 16 * 1024 * 1024)

    def test_blob_and_total_source_bounds_refuse_before_accepting_the_snapshot(self):
        path = self.fixture.root / "docs/oversize.txt"
        path.write_bytes(b"0" * (check.MAX_BLOB_BYTES + 1))
        self.fixture.advance("docs/oversize.txt")
        with self.assertRaises(check.SubjectError): check.generate(self.fixture.root, self.fixture.pins)
        path.unlink()
        self.fixture.advance("docs/oversize.txt")
        names = []
        for number in range(6):
            name = "docs/bounded-{}.txt".format(number)
            (self.fixture.root / name).write_bytes(b"0\n" * (7 * 1024 * 1024 // 2))
            names.append(name)
        self.fixture.advance(*names)
        with self.assertRaises(check.SubjectError): check.generate(self.fixture.root, self.fixture.pins)

    def test_nonregular_source_and_case_aliases_are_not_silently_inventoried(self):
        root = self.fixture.root
        (root / "docs/linked").symlink_to("added.txt")
        self.fixture.advance("docs/linked")
        with self.assertRaises(check.SubjectError): check.generate(root, self.fixture.pins)
        self.fixture.git("rm", "-q", "docs/linked")
        oid = self.fixture.git("rev-parse", "HEAD:docs/added.txt").strip()
        self.fixture.git("update-index", "--add", "--cacheinfo", "100644", oid, "docs/CASE.txt")
        self.fixture.git("update-index", "--add", "--cacheinfo", "100644", oid, "docs/case.txt")
        self.fixture.git("commit", "-qm", "Freeze synthetic case aliases")
        pins = replace(self.fixture.pins, commit=self.fixture.git("rev-parse", "HEAD").strip())
        with self.assertRaises(check.SubjectError): check.generate(root, pins)

    def test_mutable_refs_missing_objects_and_disclosure_bytes_have_no_acceptance_fallback(self):
        for commit in ("main", "f" * 40):
            with self.subTest(commit=commit), self.assertRaises(check.SubjectError):
                check.generate(self.fixture.root, replace(self.fixture.pins, commit=commit))
        path = self.fixture.root / "docs/added.txt"
        path.write_text("/" + "Users/" + "synthetic/" + "private\n", encoding="ascii")
        self.fixture.advance("docs/added.txt")
        with self.assertRaises(check.SubjectError): check.generate(self.fixture.root, self.fixture.pins)

    def test_selected_report_symlink_and_nonascii_blob_are_refused(self):
        path = self.fixture.root / check.NOM_REPORT_PATH
        raw = path.read_bytes()
        path.unlink()
        path.symlink_to("added.txt")
        with self.assertRaises(check.SubjectError): self.fixture.verify()
        path.unlink()
        path.write_bytes(raw)
        (self.fixture.root / "docs/added.txt").write_bytes(bytes([0xFF]))
        self.fixture.advance("docs/added.txt")
        with self.assertRaises(check.SubjectError): check.generate(self.fixture.root, self.fixture.pins)


if __name__ == "__main__":
    unittest.main()
