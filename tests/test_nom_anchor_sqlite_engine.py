"""Pinned source bytes and actual-source path refusals before compiler launch."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_nom_anchor_sqlite_engine as engine


class SqlEngineSourceRefusals(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'selected.zip'
        self.source.write_bytes(bytes(engine.ARCHIVE_BYTES))

    def test_wrong_complete_archive_refuses_before_compilation(self):
        with patch.object(engine.subprocess, 'Popen') as launch:
            with self.assertRaises(ValueError):
                engine.build(self.source, self.root / 'output', 'selected-compiler')
        launch.assert_not_called()
        self.assertFalse((self.root / 'output').exists())
        self.assertEqual(self.source.stat().st_size, engine.ARCHIVE_BYTES)

    def test_source_symlink_is_refused_before_reading_payload(self):
        alias = self.root / 'alias.zip'
        alias.symlink_to(self.source.name)
        with patch.object(Path, 'read_bytes') as read:
            with self.assertRaises(ValueError):
                engine.build(alias, self.root / 'output', 'selected-compiler')
        read.assert_not_called()
        self.assertTrue(alias.is_symlink())
        self.assertFalse((self.root / 'output').exists())

    def test_hard_link_is_not_accepted_as_an_independent_source(self):
        os.link(self.source, self.root / 'alias.zip')
        with patch.object(Path, 'read_bytes') as read:
            with self.assertRaises(ValueError):
                engine.build(self.source, self.root / 'output', 'selected-compiler')
        read.assert_not_called()
        self.assertFalse((self.root / 'output').exists())

    def test_optimized_runtime_refuses_without_native_compilation(self):
        script = Path(engine.__file__).resolve()
        output = self.root / 'output'
        result = subprocess.run([sys.executable, '-O', '-B', str(script), '--source-archive', str(self.source),
            '--output-directory', str(output), '--c-compiler', 'selected-compiler'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'')
        report = json.loads(result.stdout)
        self.assertEqual(report['outcome'], 'NOT_QUALIFIED')
        self.assertEqual(report['error_class'], 'ValueError')
        self.assertFalse(output.exists())

    def test_refused_source_does_not_read_an_existing_output_transcript(self):
        output = self.root / "preexisting"
        (output / "originals").mkdir(parents=True)
        original = output / "originals" / "compile.stdout"
        original.write_bytes(b"unrelated original build")
        arguments = [str(Path(engine.__file__)), "--source-archive", str(self.source),
            "--output-directory", str(output), "--c-compiler", "selected-compiler", "--ci-transcript"]
        captured = io.StringIO()
        with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(captured):
            status = engine.main()
        result = json.loads(captured.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(result["original_compile_and_probe"], {})
        self.assertNotIn("unrelated", captured.getvalue())
        self.assertEqual(original.read_bytes(), b"unrelated original build")
