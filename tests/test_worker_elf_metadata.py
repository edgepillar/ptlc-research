"""Synthetic ELF declarations and private-output controls; no loader authority."""

import errno
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_worker_elf_metadata as check


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def elf(entries=(), *, kind=3, enclosure=True):
    count = len(entries)+int(enclosure)
    start = 64+56*count
    rows, payload = [], b""
    for program, body in entries:
        rows.append((program, 0, start+len(payload), 0, 0, len(body), len(body), 1))
        payload += body
    if enclosure:
        rows.insert(0, (1, 5, 0, 0, 0, start+len(payload), start+len(payload), 1))
    header = b"\x7fELF\x02\x01\x01"+b"\x00"*9
    header += struct.pack("<HHIQQQIHHHHHH", kind, 62, 1, 0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    return header+b"".join(struct.pack("<IIQQQQQQ", *row) for row in rows)+payload


def replace(raw, offset, fmt, *values):
    changed = bytearray(raw)
    struct.pack_into(fmt, changed, offset, *values)
    return bytes(changed)


class WorkerELFMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.worker = self.root/"synthetic-entry"
        self.raw = elf([(3, b"synthetic-interpreter\x00"), (2, b"synthetic-data!\x00")])
        self.save()

    def save(self, raw=None):
        if raw is not None:
            self.raw = raw
        self.worker.write_bytes(self.raw)

    def inspect(self, **changes):
        arguments = dict(worker=self.worker, expected_sha256=digest(self.raw), expected_bytes=len(self.raw))
        arguments.update(changes)
        return check.inspect(**arguments)

    def refuses(self, raw=None, **changes):
        if raw is not None:
            self.save(raw)
        with self.assertRaises(check.InputError) as caught:
            self.inspect(**changes)
        self.assertEqual(str(caught.exception), check.REFUSAL)
        self.assertTrue(caught.exception.__suppress_context__)

    def cli(self, *arguments):
        return subprocess.run([sys.executable, "-B", str(Path(check.__file__)), *arguments],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def test_entry_kind_and_presence_are_declared_observations(self):
        for kind in (2, 3):
            for interpreter in (False, True):
                for dynamic in (False, True):
                    rows = ([(3, b"synthetic-interpreter\x00")] if interpreter else [])
                    rows += [(2, b"\x00"*16)] if dynamic else []
                    self.save(elf(rows, kind=kind))
                    result = self.inspect()
                    self.assertEqual(result['declarations'], dict(format="ELF64 LITTLE ENDIAN",
                        declared_entry_kind="ET_EXEC" if kind == 2 else "ET_DYN",
                        declared_interpreter=interpreter, declared_dynamic_segment=dynamic))
                    self.assertEqual(result['measurement'], dict(sha256=digest(self.raw), bytes=len(self.raw)))

    def test_absent_interpreter_never_authenticates_runtime_closure(self):
        self.save(elf())
        result = self.inspect()
        self.assertFalse(result['declarations']['declared_interpreter'])
        for key, value in dict(runtime_closure="NOT AUTHENTICATED", source_to_worker="NOT VERIFIED",
                reproducibility="NOT VERIFIED", independent_privacy_assessment="NOT ASSESSED",
                selection_origin="CALLER SELECTED; NOT AUTHENTICATED", application_and_core="NO-GO").items():
            self.assertEqual(result[key], value)

    def test_interpreter_and_dynamic_strings_do_not_enter_observation(self):
        observed = check._observe(self.raw)
        for private in (b"synthetic-private-location", b"\xff"*37, b"synthetic-other-name"):
            dynamic = (private+b"\x00"*32)[:32]
            self.save(elf([(3, private+b"\x00"), (2, dynamic)]))
            self.assertEqual(check._observe(self.raw), observed)
            encoded = check.scanner.encoded(self.inspect())
            self.assertNotIn(private, encoded)
            self.assertNotIn(digest(private).encode('ascii'), encoded)
            self.assertTrue(encoded.isascii())

    def test_uninterpreted_headers_and_load_enclosure_remain_observation_only(self):
        raw = elf([(1, b""), (0x70000001, b"synthetic"), (0x70000001, b"synthetic")])
        raw = replace(raw, 18, '<H', 0)
        raw = replace(raw, 64+4, '<I', 0xffffffff)
        raw = replace(raw, 64+16, '<Q', 2**64-1)
        raw = replace(raw, 64+40, '<Q', 0)
        self.save(raw)
        self.assertEqual(self.inspect()['loader_conformance'], "NOT VALIDATED; SELECTED BOUNDS AND FRAMING ONLY")

    def test_unsupported_formats_versions_and_classes_refuse(self):
        for raw in (b"synthetic-script", b"\xcf\xfa\xed\xfe"+b"\x00"*60,
                    replace(self.raw, 4, '<B', 1), replace(self.raw, 5, '<B', 2),
                    replace(self.raw, 6, '<B', 2), replace(self.raw, 20, '<I', 2)):
            with self.subTest(case=len(raw)):
                self.refuses(raw)

    def test_header_kind_and_width_policy_refuses(self):
        original = self.raw
        for offset, values in ((16, (1, 4)), (52, (63, 65)), (54, (55, 57))):
            for value in values:
                self.refuses(replace(original, offset, '<H', value))

    def test_header_counts_and_extended_numbering_are_bounded(self):
        original = self.raw
        for value in (0, 1025, 65535):
            self.refuses(replace(original, 56, '<H', value))
        self.save(elf([(0, b"")]*1023))
        self.assertFalse(self.inspect()['declarations']['declared_interpreter'])

    def test_program_table_truncation_and_excessive_offsets_refuse(self):
        original = self.raw
        for value in (0, 63, len(original)-55, 2**64-1):
            self.refuses(replace(original, 32, '<Q', value))
        self.refuses(original[:119])

    def test_complete_file_and_unknown_segment_spans_are_bounded(self):
        for raw in (None, "synthetic", bytearray(self.raw), memoryview(self.raw), b"\x00"*63,
                    b"\x00"*(check.MAX_BYTES+1)):
            with self.assertRaises(check.InputError):
                check._observe(raw)
        original = elf([(0x70000001, b"synthetic")])
        for offset, value in ((64+56+8, 2**64-1), (64+56+32, 2**64-1)):
            self.refuses(replace(original, offset, '<Q', value))

    def test_duplicate_interpreter_or_dynamic_declarations_refuse(self):
        for program, body in ((3, b"synthetic\x00"), (2, b"\x00"*16)):
            self.refuses(elf([(program, body), (program, body)]))

    def test_metadata_inside_header_or_program_table_refuses(self):
        for program, body in ((3, b"synthetic\x00"), (2, b"\x00"*16)):
            original = elf([(program, body)])
            for offset in (0, 64):
                self.refuses(replace(original, 64+56+8, '<Q', offset))

    def test_selected_metadata_payloads_cannot_overlap(self):
        original = elf([(3, b"synthetic\x00"), (2, b"a\x00"+b"z"*14)])
        dynamic_start = struct.unpack_from('<Q', original, 64+112+8)[0]
        changed = replace(original, 64+56+8, '<Q', dynamic_start)
        self.refuses(replace(changed, 64+56+32, '<Q', 2))

    def test_interpreter_length_and_termination_policy_refuses(self):
        for body in (b"", b"\x00", b"a", b"\x00\x00", b"a\x00b\x00", b"a"*4096+b"\x00"):
            self.refuses(elf([(3, body)]))
        self.save(elf([(3, b"a"*4095+b"\x00")]))
        self.assertTrue(self.inspect()['declarations']['declared_interpreter'])

    def test_dynamic_payload_width_and_size_are_bounded(self):
        for size in (0, 15, 17, 65552):
            self.refuses(elf([(2, b"\x00"*size)]))
        self.save(elf([(2, b"\x00"*65536)]))
        self.assertTrue(self.inspect()['declarations']['declared_dynamic_segment'])

    def test_dynamic_bytes_are_not_dependency_or_loader_resolution(self):
        self.save(elf([(2, struct.pack('<QQ', 1, 2**64-1))]))
        result = self.inspect()
        self.assertTrue(result['declarations']['declared_dynamic_segment'])
        self.assertEqual(set(result['declarations']), {'format', 'declared_entry_kind',
                         'declared_interpreter', 'declared_dynamic_segment'})
        self.assertEqual(result['runtime_closure'], 'NOT AUTHENTICATED')

    def test_bound_and_pin_types_refuse_before_open(self):
        with patch.object(check.scanner, 'owned_file', side_effect=AssertionError("unexpected open")):
            for size in (True, False, 0, -1, 1.5, None, check.MAX_BYTES+1):
                self.refuses(expected_bytes=size)
            for pin in (None, True, "synthetic-private-pin", "A"*64, "0"*63):
                self.refuses(expected_sha256=pin)

    def test_whole_entry_pin_and_size_must_match(self):
        self.refuses(expected_sha256='00'*32)
        self.refuses(expected_bytes=len(self.raw)-1)
        self.refuses(expected_bytes=len(self.raw)+1)
        self.refuses(b"")

    def test_symlink_directory_fifo_and_missing_inputs_refuse(self):
        linked = self.root/'synthetic-link';linked.symlink_to(self.worker)
        directory = self.root/'synthetic-directory';directory.mkdir()
        fifo = self.root/'synthetic-fifo';os.mkfifo(fifo)
        for path in (linked, directory, fifo, self.root/'synthetic-missing'):
            self.refuses(worker=path)

    def test_foreign_owner_refuses_owned_metadata(self):
        with patch.object(check.os, 'geteuid', return_value=os.geteuid()+1):
            self.refuses()

    def test_inspection_opens_only_selected_entry_and_does_not_execute(self):
        opened, original = [], Path.open
        def selected(path, *args, **kwargs):
            self.assertEqual(path, self.worker)
            handle = original(path, *args, **kwargs);opened.append(handle.fileno())
            return handle
        with patch.object(Path, 'open', selected), patch('subprocess.run') as run, \
                patch('subprocess.Popen') as popen, patch('os.execve') as execute:
            self.assertTrue(self.inspect()['declarations']['declared_interpreter'])
            run.assert_not_called();popen.assert_not_called();execute.assert_not_called()
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError) as caught:
            os.fstat(opened[0])
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_refusal_after_read_closes_and_sanitizes(self):
        self.save(b"synthetic-private-malformed-entry"*4)
        opened, original = [], Path.open
        def selected(path, *args, **kwargs):
            handle = original(path, *args, **kwargs);opened.append(handle.fileno())
            return handle
        with patch.object(Path, 'open', selected):
            self.refuses()
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError) as caught:
            os.fstat(opened[0])
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_file_guard_change_after_read_refuses_observation(self):
        original = check._observe
        def changed(raw):
            result = original(raw)
            self.worker.write_bytes(raw+b"x")
            return result
        with patch.object(check, '_observe', changed):
            self.refuses()

    def test_cli_success_is_fixed_canonical_metadata_without_path_echo(self):
        expected = check.scanner.encoded(self.inspect())
        result = self.cli('--worker', str(self.worker), '--expect-sha256', digest(self.raw),
                          '--expect-bytes', str(len(self.raw)))
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))
        self.assertNotIn(str(self.worker).encode(), result.stdout)
        self.assertEqual(json.loads(result.stdout)['schema'], 'ptlc-offline-worker-elf-declarations-v1')

    def test_cli_refusals_never_echo_arguments_or_private_strings(self):
        for arguments in ((), ('--synthetic-private-option',),
                          ('--worker', str(self.worker), '--expect-sha256', 'synthetic-private-pin', '--expect-bytes', '1'),
                          ('--worker', str(self.worker), '--expect-sha256', digest(self.raw), '--expect-bytes', 'synthetic-private-size')):
            result = self.cli(*arguments)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (1, b"", ('FAIL: '+check.REFUSAL+'\n').encode('ascii')))


if __name__ == '__main__':
    unittest.main()
