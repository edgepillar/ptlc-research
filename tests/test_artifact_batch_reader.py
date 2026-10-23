"""Adversarial controls for exact, bounded Git index batch reads."""

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


CHECKER = Path(__file__).resolve().parents[1] / "scripts" / "check_artifacts_batch.py"
SPEC = importlib.util.spec_from_file_location("artifact_batch_checker", CHECKER)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


# Load a private copy of the unchanged historical tests so the batch CLI runs
# the same seven disclosure controls without changing their original module.
LEGACY_SPEC = importlib.util.spec_from_file_location(
    "artifact_hygiene_reference", Path(__file__).with_name("test_artifact_hygiene.py")
)
legacy_hygiene = importlib.util.module_from_spec(LEGACY_SPEC)
LEGACY_SPEC.loader.exec_module(legacy_hygiene)
legacy_hygiene.CHECKER = CHECKER


class BatchArtifactHygieneTests(legacy_hygiene.ArtifactHygieneTests):
    """Run the unchanged disclosure controls against the selected batch CLI."""


def identity(value, algorithm="sha1"):
    raw = b"blob " + str(len(value)).encode("ascii") + b"\0" + value
    return hashlib.new(algorithm, raw).hexdigest().encode("ascii")


def header(object_id, value):
    return object_id + b" blob " + str(len(value)).encode("ascii") + b"\n"


class BatchReaderRefusalTests(unittest.TestCase):
    def setUp(self):
        self.value = b"Public text.\n"
        self.object_id = identity(self.value)
        self.header = header(self.object_id, self.value)

    def refused(self, metadata, content=None):
        answers = [metadata] if content is None else [metadata, content]
        with patch.object(checker, "_git", side_effect=answers) as git:
            with self.assertRaises(RuntimeError):
                checker._index_blobs(Path("."), [self.object_id])
            self.assertEqual(git.call_count, len(answers))

    def test_empty_selection_does_not_run_git(self):
        with patch.object(checker, "_git") as git:
            self.assertEqual(checker._index_blobs(Path("."), []), [])
            git.assert_not_called()

    def test_invalid_and_mixed_object_formats_refused_before_git(self):
        selections = ([b"bad"], [self.object_id.decode("ascii")],
                      [self.object_id.upper()],
                      [self.object_id, identity(self.value, "sha256")])
        for selection in selections:
            with self.subTest(selection_type=type(selection[0]).__name__):
                with patch.object(checker, "_git") as git:
                    with self.assertRaises(RuntimeError):
                        checker._index_blobs(Path("."), selection)
                    git.assert_not_called()

    def test_excessive_selection_refused_before_git(self):
        with patch.object(checker, "_git") as git:
            with self.assertRaises(RuntimeError):
                checker._index_blobs(Path("."), [self.object_id] * 65537)
            git.assert_not_called()

    def test_metadata_identity_type_size_and_framing_refused(self):
        for value in (
            b"", self.header + self.header,
            self.header.replace(self.object_id, b"0" * 40),
            self.header.replace(b" blob ", b" tree "),
            self.object_id + b" missing\n",
            self.object_id + b" blob -1\n",
            self.object_id + b" blob 01\n",
            self.object_id + b" blob 1.0\n",
            self.header.rstrip(b"\n"), self.header.replace(b"\n", b"\r\n"),
        ):
            with self.subTest(metadata_bytes=len(value)):
                self.refused(value)

    def test_single_blob_bound_precedes_content_read(self):
        self.refused(self.object_id + b" blob 16777217\n")

    def test_aggregate_bound_precedes_content_read(self):
        object_ids = [self.object_id] * 9
        metadata = (self.object_id + b" blob 16777216\n") * 9
        with patch.object(checker, "_git", return_value=metadata) as git:
            with self.assertRaises(RuntimeError):
                checker._index_blobs(Path("."), object_ids)
            self.assertEqual(git.call_count, 1)

    def test_content_identity_type_size_and_framing_refused(self):
        original = self.header + self.value + b"\n"
        for value in (
            b"", original[:-1], original + b"\n", original[:-2],
            original.replace(self.object_id, b"0" * 40, 1),
            original.replace(b" blob ", b" tree ", 1),
            self.header + b"X" * len(self.value) + b"\n",
            self.header + self.value + b"!",
        ):
            with self.subTest(content_bytes=len(value)):
                self.refused(self.header, value)

    def test_git_failure_is_not_an_empty_success(self):
        with patch.object(checker, "_git", side_effect=RuntimeError("Git inspection failed")):
            with self.assertRaises(RuntimeError):
                checker._index_blobs(Path("."), [self.object_id])


class ActualGitBatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ptlc-batch-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        self.environment.update({
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        })

    def git(self, *arguments, input_data=None):
        value = subprocess.run(
            ["git", *arguments], cwd=self.root, env=self.environment,
            input=input_data, capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(value.returncode, 0, "temporary Git setup failed")
        return value.stdout

    def initialize(self, object_format):
        self.git("init", "--quiet", "--object-format=" + object_format)

    def test_both_git_formats_preserve_order_duplicates_empty_and_binary_bytes(self):
        for object_format in ("sha1", "sha256"):
            with self.subTest(object_format=object_format):
                # Separate real repositories avoid an object-format conversion.
                self.root = Path(self.directory.name) / object_format
                self.root.mkdir()
                self.initialize(object_format)
                values = [b"", b"line one\nline two\n", b"\0\xff\n"]
                object_ids = [self.git("hash-object", "-w", "--stdin", input_data=value).strip()
                              for value in values]
                selected = [object_ids[2], object_ids[0], object_ids[1], object_ids[2]]
                with patch.dict(os.environ, self.environment, clear=True):
                    self.assertEqual(checker._index_blobs(self.root, selected),
                                     [values[2], values[0], values[1], values[2]])

    def test_unmerged_index_stages_remain_individually_inspected(self):
        self.initialize("sha1")
        disclosed = b"fixture" + b"@" + b"example" + b".invalid"
        values = [b"Base text.\n", b"Public side.\n", disclosed]
        object_ids = [self.git("hash-object", "-w", "--stdin", input_data=value).strip()
                      for value in values]
        entries = b"".join(b"100644 " + object_id + b" " + str(stage).encode("ascii")
                           + b"\tcandidate.txt\0"
                           for stage, object_id in enumerate(object_ids, 1))
        self.git("update-index", "-z", "--index-info", input_data=entries)
        (self.root / "candidate.txt").write_bytes(b"Clean worktree text.\n")
        with patch.dict(os.environ, self.environment, clear=True):
            checked, failures = checker.check(self.root)
        self.assertEqual(checked, 4)
        self.assertEqual(sum("unresolved index entry" in value for value in failures), 3)
        self.assertIn("index candidate 3: possible email address", failures)
        self.assertNotIn(disclosed.decode("ascii"), "\n".join(failures))

    def test_replacement_ref_cannot_hide_original_index_content(self):
        self.initialize("sha1")
        disclosed = b"fixture" + b"@" + b"example" + b".invalid"
        path = self.root / "candidate.txt"
        path.write_bytes(disclosed)
        self.git("add", "candidate.txt")
        original = self.git("rev-parse", ":candidate.txt").strip().decode("ascii")
        clean = b"Clean replacement text.\n"
        replacement = self.git("hash-object", "-w", "--stdin", input_data=clean).strip().decode("ascii")
        # This isolated repository has no commits or project history.
        self.git("replace", original, replacement)
        path.write_bytes(clean)
        with patch.dict(os.environ, self.environment, clear=True):
            checked, failures = checker.check(self.root)
        self.assertEqual(checked, 2)
        self.assertEqual(failures, ["index candidate 1: possible email address"])

    def test_missing_promisor_blob_refuses_without_fetch(self):
        self.initialize("sha1")
        path = self.root / "candidate.txt"
        path.write_bytes(b"Public indexed text.\n")
        self.git("add", "candidate.txt")
        object_id = self.git("rev-parse", ":candidate.txt").strip().decode("ascii")
        binary = self.root / "bin"
        binary.mkdir()
        helper = binary / "git-remote-testdeny"
        helper.write_text(
            '#!/bin/sh\nprintf "attempted\\n" > "$PTLC_GIT_FETCH_MARKER"\nexit 1\n',
            encoding="ascii",
        )
        helper.chmod(0o700)
        marker = self.root / "fetch-marker"
        self.environment["PATH"] = str(binary) + os.pathsep + self.environment.get("PATH", os.defpath)
        self.environment["PTLC_GIT_FETCH_MARKER"] = str(marker)
        for name, value in (
            ("core.repositoryformatversion", "1"),
            ("extensions.partialClone", "origin"),
            ("remote.origin.url", "testdeny::fixture"),
            ("remote.origin.promisor", "true"),
            ("remote.origin.partialclonefilter", "blob:none"),
            ("protocol.testdeny.allow", "always"),
        ):
            self.git("config", name, value)
        (self.root / ".git" / "objects" / object_id[:2] / object_id[2:]).unlink()
        # Prove the local helper trap is reachable. It never opens a network
        # connection and returns failure after writing one disposable marker.
        control = subprocess.run(
            ["git", "cat-file", "-p", object_id], cwd=self.root,
            env=self.environment, capture_output=True, check=False, timeout=10,
        )
        self.assertNotEqual(control.returncode, 0)
        self.assertTrue(marker.is_file(), "isolated fetch control was not exercised")
        marker.unlink()
        with patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaises(RuntimeError):
                checker.check(self.root)
        self.assertFalse(marker.exists(), "index inspection attempted an automatic fetch")

    def test_multiple_index_files_use_four_git_calls(self):
        self.initialize("sha1")
        for name in ("first.txt", "second.txt", "third.txt"):
            (self.root / name).write_bytes(b"Public text.\n")
        self.git("add", "--all")
        original = checker._git
        with patch.dict(os.environ, self.environment, clear=True):
            with patch.object(checker, "_git", wraps=original) as git:
                self.assertEqual(checker.check(self.root), (6, []))
                self.assertEqual(git.call_count, 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
