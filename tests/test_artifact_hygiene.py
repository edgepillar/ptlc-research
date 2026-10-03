"""Offline regression cases for index and working-tree disclosure checks."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).resolve().parents[1] / "scripts" / "check_artifacts.py"


class ArtifactHygieneTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ptlc-hygiene-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        self.environment.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        })
        self._git("init", "--quiet")

    def _git(self, *arguments):
        result = subprocess.run(
            ["git", *arguments], cwd=self.root, env=self.environment,
            capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, "temporary Git setup failed")

    @staticmethod
    def _synthetic_disclosure():
        # Assemble the harmless fixture at runtime so this test source itself
        # does not contain a literal disclosure pattern.
        return "fixture" + "@" + "example" + "." + "invalid"

    def _write(self, text):
        path = self.root / "candidate.txt"
        path.write_text(text, encoding="ascii")
        return path

    def _check(self):
        result = subprocess.run(
            [sys.executable, "-B", str(CHECKER), "--root", str(self.root)],
            env=self.environment, capture_output=True, text=True,
            check=False, timeout=10,
        )
        output = result.stdout + result.stderr
        self.assertNotIn(str(self.root), output)
        self.assertNotIn(self._synthetic_disclosure(), output)
        return result

    def test_safe_staged_and_untracked_files_pass(self):
        self._write("Public staged text.\n")
        self._git("add", "candidate.txt")
        (self.root / "notes.txt").write_text("Public untracked text.\n", encoding="ascii")
        result = self._check()
        self.assertEqual(result.returncode, 0)
        self.assertIn("PASS:", result.stdout)

    def test_staged_disclosure_survives_clean_worktree_replacement(self):
        self._write(self._synthetic_disclosure())
        self._git("add", "candidate.txt")
        self._write("Clean worktree replacement.\n")
        result = self._check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("index candidate 1: possible email address", result.stderr)

    def test_staged_disclosure_survives_worktree_deletion(self):
        path = self._write(self._synthetic_disclosure())
        self._git("add", "candidate.txt")
        path.unlink()
        result = self._check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("index candidate 1: possible email address", result.stderr)

    def test_untracked_disclosure_fails(self):
        self._write(self._synthetic_disclosure())
        result = self._check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("worktree candidate 1: possible email address", result.stderr)

    def test_clean_index_does_not_hide_worktree_disclosure(self):
        self._write("Clean index version.\n")
        self._git("add", "candidate.txt")
        self._write(self._synthetic_disclosure())
        result = self._check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("worktree candidate 1: possible email address", result.stderr)

    def test_staged_symlink_rejected_after_regular_worktree_replacement(self):
        (self.root / "target.txt").write_text("Public target.\n", encoding="ascii")
        path = self.root / "candidate.txt"
        path.symlink_to("target.txt")
        self._git("add", "candidate.txt")
        path.unlink()
        self._write("Regular worktree replacement.\n")
        result = self._check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("index candidate 1: non-regular index entry", result.stderr)

    def test_sensitive_filename_is_redacted_and_rejected(self):
        path = self.root / (self._synthetic_disclosure() + ".txt")
        path.write_text("Public content.\n", encoding="ascii")
        result = self._check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("filename contains possible email address", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
