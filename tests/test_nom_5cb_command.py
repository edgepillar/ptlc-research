"""Exercise original-stream failures without a Go compiler or application keys."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from scripts import nom_5cb_command as selected


class CommandOriginals(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(strict=True)

    def run_selected(self, body, *, label='wire-corpus', timeout=5):
        return selected.run([sys.executable, '-c', body], environment={},
            directory=self.root, evidence=self.root, label=label, timeout=timeout)

    def receipt(self, label='wire-corpus'):
        return json.loads((self.root / (label + '.receipt.json')).read_bytes())

    def test_complete_original_streams_and_exact_exit(self):
        receipt = self.run_selected("import os;os.write(1,b'public-output');os.write(2,b'public-error')")
        self.assertEqual(receipt, self.receipt())
        self.assertEqual(receipt['actual_exit'], 0)
        self.assertIs(type(receipt['process_group']), int)
        self.assertGreater(receipt['process_group'], 0)
        self.assertEqual(receipt['result'], 'RETURNED_ZERO_WITH_COMPLETE_STREAMS')
        self.assertTrue(receipt['cleanup_complete'])
        self.assertEqual(receipt['complete'], {'stdout': True, 'stderr': True})
        for name, raw in (('stdout', b'public-output'), ('stderr', b'public-error')):
            self.assertEqual((self.root / ('wire-corpus.' + name)).read_bytes(), raw)
            self.assertEqual(receipt['bytes'][name], len(raw))
            self.assertEqual(receipt['sha256'][name], hashlib.sha256(raw).hexdigest())

    def test_nonzero_retains_original_output_and_status(self):
        with self.assertRaises(selected.WorkerError):
            self.run_selected("import os;os.write(1,b'before-failure');os.write(2,b'refused');raise SystemExit(7)")
        receipt = self.receipt()
        self.assertEqual(receipt['actual_exit'], 7)
        self.assertEqual(receipt['failure'], 'NONZERO_EXIT')
        self.assertEqual(receipt['result'], 'FAILURE_OR_INCOMPLETE')
        self.assertTrue(receipt['cleanup_complete'])
        self.assertFalse(receipt['automatic_retry'])
        self.assertEqual((self.root / 'wire-corpus.stdout').read_bytes(), b'before-failure')
        self.assertEqual((self.root / 'wire-corpus.stderr').read_bytes(), b'refused')

    def test_deadline_preserves_incomplete_receipt(self):
        with self.assertRaises(selected.WorkerError):
            self.run_selected('import time;time.sleep(30)', timeout=0.2)
        receipt = self.receipt()
        self.assertEqual(receipt['failure'], 'DEADLINE_EXCEEDED')
        self.assertEqual(receipt['result'], 'FAILURE_OR_INCOMPLETE')
        self.assertIsNotNone(receipt['actual_exit'])
        self.assertTrue(receipt['cleanup_complete'])
        self.assertNotEqual(receipt['complete'], {'stdout': True, 'stderr': True})

    def test_stdout_truncation_never_becomes_success(self):
        with mock.patch.object(selected, 'MAX_STDOUT', 16):
            with self.assertRaises(selected.WorkerError):
                self.run_selected("import os;os.write(1,b'x'*33)")
        receipt = self.receipt()
        self.assertEqual(receipt['failure'], 'STREAM_LIMIT_EXCEEDED')
        self.assertEqual(receipt['truncated_stream'], 'stdout')
        self.assertEqual(receipt['bytes']['stdout'], 16)
        self.assertFalse(receipt['complete']['stdout'])
        self.assertEqual((self.root / 'wire-corpus.stdout').read_bytes(), b'x'*16)

    def test_stderr_truncation_never_becomes_success(self):
        with mock.patch.object(selected, 'MAX_STDERR', 16):
            with self.assertRaises(selected.WorkerError):
                self.run_selected("import os;os.write(2,b'e'*33)")
        receipt = self.receipt()
        self.assertEqual(receipt['truncated_stream'], 'stderr')
        self.assertEqual(receipt['bytes']['stderr'], 16)
        self.assertFalse(receipt['complete']['stderr'])
        self.assertEqual((self.root / 'wire-corpus.stderr').read_bytes(), b'e'*16)

    def test_both_pipes_are_drained(self):
        receipt = self.run_selected("import os;os.write(2,b'e'*131072);os.write(1,b'o'*131072)")
        self.assertEqual(receipt['bytes'], {'stdout': 131072, 'stderr': 131072})
        self.assertEqual(receipt['actual_exit'], 0)
        self.assertEqual(receipt['complete'], {'stdout': True, 'stderr': True})

    def test_original_label_cannot_be_reexecuted(self):
        self.run_selected("print('first')")
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        with mock.patch.object(selected.subprocess, 'Popen') as spawn:
            with self.assertRaises(selected.WorkerError):
                self.run_selected("print('replacement')")
        spawn.assert_not_called()
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.root.iterdir()})

    def test_other_unit_uses_distinct_originals(self):
        self.run_selected("print('wire')")
        before = (self.root / 'wire-corpus.receipt.json').read_bytes()
        self.run_selected("print('vm')", label='vm-path')
        self.assertEqual((self.root / 'wire-corpus.receipt.json').read_bytes(), before)
        self.assertEqual((self.root / 'vm-path.stdout').read_bytes(), b'vm\n')

    def test_preexisting_stream_is_preserved_before_spawn(self):
        path = self.root / 'wire-corpus.stderr'
        path.write_bytes(b'original-error')
        with mock.patch.object(selected.subprocess, 'Popen') as spawn:
            with self.assertRaises(selected.WorkerError):
                self.run_selected("print('new')")
        spawn.assert_not_called()
        self.assertEqual(path.read_bytes(), b'original-error')
        self.assertEqual({path.name for path in self.root.iterdir()}, {'wire-corpus.stderr'})

    def test_symlink_stream_is_never_followed(self):
        target = self.root / 'retained.txt'
        target.write_bytes(b'original')
        (self.root / 'wire-corpus.stdout').symlink_to(target)
        with mock.patch.object(selected.subprocess, 'Popen') as spawn:
            with self.assertRaises(selected.WorkerError):
                self.run_selected("print('new')")
        spawn.assert_not_called()
        self.assertEqual(target.read_bytes(), b'original')

    def test_invalid_bounds_and_labels_never_spawn(self):
        with mock.patch.object(selected.subprocess, 'Popen') as spawn:
            for timeout in (0, -1, 1201, float('inf'), float('nan'), True, '5'):
                with self.subTest(timeout=repr(timeout)):
                    with self.assertRaises(selected.WorkerError):
                        self.run_selected('pass', timeout=timeout)
            for label in ('../wire-corpus', 'unselected', '', 1):
                with self.subTest(label=label):
                    with self.assertRaises(selected.WorkerError):
                        self.run_selected('pass', label=label)
        spawn.assert_not_called()
        self.assertFalse(any(self.root.iterdir()))

    def test_unresolved_cleanup_is_explicit_unknown(self):
        with mock.patch.object(selected.subprocess, 'Popen', side_effect=OSError), \
                mock.patch.object(selected, '_cleanup', return_value=False):
            with self.assertRaises(selected.WorkerError):
                self.run_selected('pass')
        receipt = self.receipt()
        self.assertEqual(receipt['result'], 'UNKNOWN_CLEANUP_UNRESOLVED')
        self.assertIsNone(receipt['actual_exit'])
        self.assertIsNone(receipt['process_group'])
        self.assertFalse(receipt['cleanup_complete'])


if __name__ == '__main__':
    unittest.main()
