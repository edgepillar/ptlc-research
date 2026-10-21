"""Synthetic reader controls; no native replay, runtime or chain evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_dev_admission as reader

ROOT = Path(__file__).resolve().parents[1]


class DevAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the earlier explicitly synthetic framing, without changing its
        # frozen file or treating its values as an original execution stream.
        spec = importlib.util.spec_from_file_location(
            'selected_earlier_synthetic_frames', ROOT/'tests/test_nom_current_admission.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.CurrentAdmissionTests.setUpClass()
        cls.payloads = dict(module.CurrentAdmissionTests.payloads)

    def test_separate_source_tree_and_value_origins(self):
        manifest, index = reader.inputs(ROOT)
        self.assertEqual(len(index), 474)
        self.assertEqual(reader.earlier.git_tree(index), reader.TREE)
        self.assertNotEqual(reader.CORE, reader.earlier.CORE)
        self.assertEqual(manifest['earlier_source'], reader.earlier.CORE)
        self.assertEqual(manifest['earlier_value_source'], reader.earlier.rebase.CORE_COMMIT)
        self.assertEqual(manifest['input_sha256'][reader.SOURCE], reader.INDEX_SHA256)

    def test_only_three_producers_change_and_error_is_not_ignored(self):
        old = reader.earlier.probes(ROOT)
        new = reader.probes(ROOT)
        self.assertEqual(set(old), set(new))
        self.assertEqual(sum(old[name] != new[name] for name in old), 3)
        selected = reader.producer_variants(ROOT)
        self.assertEqual(len(selected), 3)
        for original, row in selected.items():
            self.assertEqual(hashlib.sha256((ROOT/original).read_bytes()).hexdigest(), row['original_sha256'])
            self.assertEqual((ROOT/row['selected']).read_bytes().count(reader.ERROR_GUARD), 1)

    def test_ignored_sequencer_error_or_extra_edit_refuses(self):
        for mode in ('ignored-error', 'old-api', 'extra-edit', 'changed-original'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                for original, (selected, unused_digest, unused_before, unused_after) in reader.VARIANTS.items():
                    for name in (original, selected):
                        target = root/name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes((ROOT/name).read_bytes())
                original, (selected, unused_digest, unused_before, unused_after) = next(iter(reader.VARIANTS.items()))
                target = root/selected
                if mode == 'ignored-error':
                    target.write_bytes(target.read_bytes().replace(reader.ERROR_GUARD, b'', 1))
                elif mode == 'old-api':
                    target.write_bytes((root/original).read_bytes())
                elif mode == 'extra-edit':
                    target.write_bytes(target.read_bytes()+b'// synthetic extra edit\n')
                else:
                    (root/original).write_bytes((root/original).read_bytes()+b'// synthetic edit\n')
                with self.assertRaises(ValueError):
                    reader.producer_variants(root)

    def test_complete_synthetic_values_do_not_authenticate_dev_execution(self):
        result = reader.compare_payloads(self.payloads, ROOT)
        self.assertEqual(result['core_commit'], reader.CORE)
        self.assertEqual(result['earlier_source'], reader.earlier.CORE)
        self.assertEqual(result['selected_stateful_outcomes'], 342)
        self.assertEqual(result['wire_outcomes'], 45)
        self.assertEqual(result['pr138_outcomes'], 1)
        self.assertEqual(len(result['profiles']), 16)
        self.assertEqual(result['native_execution'], 'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['execution_origin'], 'NOT_ESTABLISHED_BY_THIS_READER')
        self.assertEqual(result['complete_source'], 'SEPARATE_CONTENT_CHECK_REQUIRED')
        self.assertEqual(result['application'], result['core'])
        self.assertEqual(result['core'], 'NO-GO')
        for key in ('combined_admission', 'independent_assessment', 'source_authentication', 'durable_custody'):
            self.assertEqual(result[key], 'UNFILLED')
        self.assertEqual(result['journal_source_upgrade'], 'NOT_SELECTED')
        self.assertEqual(result['native_vectors'], 'SEPARATE UPSTREAM SOURCE TESTS; NOT EXECUTED BY READER')

    def test_missing_profile_and_cross_profile_substitution_refuse(self):
        for mode in ('missing', 'substitute'):
            changed = dict(self.payloads)
            if mode == 'missing':
                changed.pop('supervisor-plasma.stderr')
            else:
                changed['supervisor-plasma.stdout'] = changed['bilateral-graph.stdout']
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                reader.compare_payloads(changed, ROOT)

    def test_old_manifest_is_not_the_new_selection(self):
        old = json.loads((ROOT/reader.earlier.MANIFEST).read_bytes())
        self.assertNotEqual(old['core_commit'], reader.CORE)
        with patch.object(reader.earlier, 'decoded', return_value=old):
            with self.assertRaises(ValueError):
                reader.inputs(ROOT)

    def test_nearby_source_or_variant_selection_cannot_fill_manifest(self):
        original = json.loads((ROOT/reader.MANIFEST).read_bytes())
        for key, value in (('core_commit', reader.earlier.CORE),
                           ('core_tree', reader.earlier.TREE),
                           ('source_files', 444), ('api_variant_files', 2),
                           ('combined_admission', 'PASS')):
            changed = dict(original)
            changed[key] = value
            with self.subTest(key=key), patch.object(reader.earlier, 'decoded', return_value=changed):
                with self.assertRaises(ValueError):
                    reader.inputs(ROOT)

    def source_frame(self, source):
        # Exact file-walk framing only. These 474 tiny synthetic files are not
        # the upstream inventory and inputs() is explicitly mocked below.
        raw = b'// public synthetic source framing only\n'
        index = {}
        for number in range(474):
            name = 'synthetic/source_'+str(number)+'.go'
            path = source/name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
            index[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                              git_blob_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
        for destination, producer in reader.probes(ROOT).items():
            path = source/destination
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT/producer).read_bytes())
        return index

    def test_exact_complete_synthetic_source_frame_and_content_refusals(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve()
            index = self.source_frame(source)
            with patch.object(reader, 'inputs', return_value=({}, index)):
                result = reader.compare_source(source, ROOT)
                self.assertEqual(result['combined_files'], 490)
                self.assertEqual(result['producer_authentication'], 'NOT_ESTABLISHED_BY_THIS_READER')
                path = source/'synthetic/source_0.go'
                original = path.read_bytes()
                for mode in ('missing', 'changed', 'extra'):
                    if mode == 'missing':
                        path.unlink()
                    elif mode == 'changed':
                        path.write_bytes(original+b'// synthetic change\n')
                    else:
                        (source/'unselected.txt').write_bytes(b'synthetic extra\n')
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        reader.compare_source(source, ROOT)
                    path.write_bytes(original)
                    if mode == 'extra':
                        (source/'unselected.txt').unlink()

    def test_old_producer_bytes_cannot_fill_selected_dev_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve()
            index = self.source_frame(source)
            old = reader.earlier.probes(ROOT)
            destination = next(name for name in old if old[name] in reader.VARIANTS)
            (source/destination).write_bytes((ROOT/old[destination]).read_bytes())
            with patch.object(reader, 'inputs', return_value=({}, index)), self.assertRaises(ValueError):
                reader.compare_source(source, ROOT)

    def test_source_symlink_and_ancestor_alias_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root/'source'
            source.mkdir()
            index = self.source_frame(source)
            alias = root/'alias'
            alias.symlink_to(source, target_is_directory=True)
            with patch.object(reader, 'inputs', return_value=({}, index)), self.assertRaises(ValueError):
                reader.compare_source(alias, ROOT)
            target = source/'synthetic/source_0.go'
            target.unlink()
            target.symlink_to(source/'synthetic/source_1.go')
            with patch.object(reader, 'inputs', return_value=({}, index)), self.assertRaises(ValueError):
                reader.compare_source(source, ROOT)

    def test_source_frame_cannot_weaken_fixed_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve()
            index = self.source_frame(source)
            del index['synthetic/source_0.go']
            (source/'synthetic/source_0.go').unlink()
            with patch.object(reader, 'inputs', return_value=({}, index)), self.assertRaises(ValueError):
                reader.compare_source(source, ROOT)

    def test_cli_refusal_does_not_echo_arguments(self):
        result = subprocess.run([sys.executable, '-B', '-m', 'qualification.nom_dev_admission',
                                 '--unselected-private-control'], cwd=ROOT, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'REFUSED: dev admission component comparison\n')

    def test_optimization_refuses_before_inputs(self):
        result = subprocess.run([sys.executable, '-B', '-O', '-m', 'qualification.nom_dev_admission'],
                                cwd=ROOT, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'dev admission comparison requires assertions enabled\n')
