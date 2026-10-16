"""Native CLI exit and unknown transport outcomes must remain distinct."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_anchor_sqlite_capture as capture


class SqlCaptureBoundaries(unittest.TestCase):
    def call_main(self, arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = capture.main(arguments)
        return status, json.loads(output.getvalue())

    def test_argument_refusal_has_no_inferred_native_exit(self):
        status, report = self.call_main(['selected synthetic argument'])
        self.assertEqual(status, 2)
        self.assertIsNone(report['actual_exit'])
        self.assertFalse(report['output_complete'])
        self.assertFalse(report['processes_reaped'])
        self.assertNotIn('selected synthetic argument', json.dumps(report))

    def test_changed_binary_pin_refuses_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.write_bytes(b'selected synthetic executable')
            with patch.object(capture.subprocess, 'Popen') as launch:
                status, report = self.call_main([str(binary), '00' * 32,
                    str(root / 'selected.db'), str(root / 'request.sql'), 'rw', 'none'])
            self.assertEqual(status, 2)
            self.assertIsNone(report['actual_exit'])
            launch.assert_not_called()

    def test_unselected_database_basename_refuses_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            raw = b'selected synthetic executable'
            binary.write_bytes(raw)
            request = root / 'request.sql'
            request.write_bytes(b'SELECT 1;\n')
            with patch.object(capture.subprocess, 'Popen') as launch:
                status, report = self.call_main([str(binary), hashlib.sha256(raw).hexdigest(),
                    str(root / 'unselected name.db'), str(request), 'rw', 'none'])
            self.assertEqual(status, 2)
            self.assertIsNone(report['actual_exit'])
            launch.assert_not_called()

    def test_complete_expected_refusal_preserves_nonzero_native_exit(self):
        original = dict(actual_exit=1, output_complete=True, processes_reaped=True,
            stdout_hex='', stderr_hex=b'selected native refusal'.hex(), numeric_sqlite_error_code='NOT_CAPTURED_BY_CLI')
        with patch.object(capture, 'capture', return_value=original):
            status, report = self.call_main([])
        self.assertEqual(status, 0)
        self.assertEqual(report, original)
        self.assertEqual(report['actual_exit'], 1)

    def test_incomplete_capture_is_not_wrapper_success(self):
        original = dict(actual_exit=-9, output_complete=False, processes_reaped=True)
        with patch.object(capture, 'capture', return_value=original):
            status, report = self.call_main([])
        self.assertEqual(status, 2)
        self.assertEqual(report['actual_exit'], -9)
        self.assertFalse(report['output_complete'])

    def test_unreaped_capture_is_not_wrapper_success(self):
        original = dict(actual_exit=None, output_complete=False, processes_reaped=False)
        with patch.object(capture, 'capture', return_value=original):
            status, report = self.call_main([])
        self.assertEqual(status, 2)
        self.assertIsNone(report['actual_exit'])
        self.assertFalse(report['processes_reaped'])
