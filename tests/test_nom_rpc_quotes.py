"""Finite source-corpus and retention controls; synthetic frames are not Go proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from qualification import nom_rpc_quote_generic as generic, nom_rpc_quote_ptlc as ptlc
from qualification import nom_rpc_quote_source as source
from scripts import prepare_nom_rpc_quotes as preparer, qualify_nom_rpc_quotes as cli
from scripts.qualify_nom_vm_path import selected_outcome
from tests import nom_rpc_quote_frames as frames

ROOT = Path(__file__).resolve().parents[1]
REFUSALS = (AssertionError, ValueError, KeyError, TypeError)


class NomRpcQuoteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generic = json.loads((ROOT / source.GENERIC_FIXTURE).read_bytes())
        cls.ptlc = json.loads((ROOT / source.PTLC_FIXTURE).read_bytes())
        cls.originals = json.loads((ROOT / 'compatibility/fixtures/nom_signed_originals_v1.json').read_bytes())
        cls.vm = json.loads((ROOT / 'compatibility/fixtures/nom_supervisor_plasma_v1.json').read_bytes())

    def generic_stream(self):
        return frames.stream(self.generic, generic)

    def ptlc_stream(self):
        return frames.stream(self.ptlc, ptlc)

    def check_generic(self, raw):
        return generic.inspect(raw, selected_outcome)

    def check_ptlc(self, raw):
        return ptlc.inspect(raw, selected_outcome, self.originals, self.vm)

    def copied_root(self, directory):
        target = Path(directory) / 'selected'
        target.mkdir()
        for name in (source.MANIFEST, *source.SELECTED_INPUTS):
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        return target

    def test_native_derived_records_match_two_finite_models(self):
        self.assertEqual(generic.expected_records(), self.generic)
        self.assertEqual(ptlc.expected_records(self.originals, self.vm), self.ptlc)
        self.assertEqual((len(self.generic), len(self.ptlc)), (14, 16))
        for leg in ('long', 'short'):
            quote = json.loads(bytes.fromhex(self.ptlc[leg + '-dynamic-fused-only']['typed_result_json_hex']))
            self.assertEqual((quote['basePlasma'], quote['requiredFusedPlasma']), (73500, 77175))

    def test_complete_fragmented_source_views_require_all_seventy_one_outcomes(self):
        payloads, report = frames.valid_artifact(ROOT)
        result = cli.inspect(payloads, report)
        self.assertEqual((result['actual_go_outcomes'], result['quote_records'], result['source_records']), (71, 30, 54))
        self.assertEqual(result['journal_source_upgrade'], 'NOT_SELECTED')
        self.assertEqual(result['application'], 'NO-GO')

    def test_total_fused_target_cannot_be_replaced_by_shortfall(self):
        raw = frames.rewrite_quote(self.generic_stream(), generic, 'dynamic-partial-fusion',
            lambda quote: quote.update(requiredFusedPlasma=3150))
        with self.assertRaises(REFUSALS):
            self.check_generic(raw)

    def test_both_ceiling_operations_refuse_floor_values(self):
        for identifier, change in (
            ('dynamic-one-byte', lambda q: q.update(requiredFusedPlasma=22121)),
            ('dynamic-ceil-work', lambda q: q.update(requiredDifficulty=q['requiredDifficulty'] - 1500)),
        ):
            with self.subTest(identifier=identifier), self.assertRaises(REFUSALS):
                self.check_generic(frames.rewrite_quote(self.generic_stream(), generic, identifier, change))

    def test_phase_is_bound_to_both_spork_and_frontier_version(self):
        for identifier, change in (
            ('before-first-v2-nonzero-prices', lambda r: r['input'].update(frontier_version='2')),
            ('before-enforcement-v2', lambda r: r['input'].update(dynamic_spork_enforced=True)),
        ):
            with self.subTest(identifier=identifier), self.assertRaises(REFUSALS):
                self.check_generic(frames.rewrite_record(self.generic_stream(), generic, identifier, change))

    def test_ptlc_quote_binds_leg_caller_contract_and_exact_original(self):
        for key, value in (('leg', 'short'), ('caller_hex', '00' * 20), ('contract_hex', '00' * 20),
                           ('original_wire_sha256', '00' * 32), ('original_node_hash_hex', '00' * 32), ('data_hex', '00')):
            with self.subTest(field=key), self.assertRaises(REFUSALS):
                raw = frames.rewrite_record(self.ptlc_stream(), ptlc, 'long-dynamic-fused-only',
                    lambda r: r['input'].update({key: value}))
                self.check_ptlc(raw)

    def test_ptlc_embedded_cost_cannot_be_promoted_from_plain_send(self):
        raw = frames.rewrite_quote(self.ptlc_stream(), ptlc, 'long-dynamic-fused-only',
            lambda q: q.update(basePlasma=21000, requiredFusedPlasma=22050))
        with self.assertRaises(REFUSALS):
            self.check_ptlc(raw)

    def test_source_flags_refuse_integer_boolean_aliases(self):
        for field, value in (('ptlc_spork_enforced', 1), ('ptlc_spork_enforced', False), ('dynamic_spork_enforced', 1)):
            with self.subTest(field=field, value=value), self.assertRaises(REFUSALS):
                self.check_ptlc(frames.rewrite_record(self.ptlc_stream(), ptlc, 'long-dynamic-fused-only',
                    lambda r: r['input'].update({field: value})))

    def test_numeric_quote_fields_refuse_boolean_negative_float_and_overflow(self):
        for value in (True, -1, 1.0, 2**64):
            with self.subTest(value=value), self.assertRaises(REFUSALS):
                self.check_generic(frames.rewrite_quote(self.generic_stream(), generic, 'dynamic-floor',
                    lambda q: q.update(requiredFusedPlasma=value)))

    def test_typed_quote_refuses_missing_extra_and_duplicate_keys(self):
        raw = self.generic_stream()
        cases = [frames.rewrite_quote(raw, generic, 'dynamic-floor', lambda q: q.pop('requiredFusedPlasma')),
            frames.rewrite_quote(raw, generic, 'dynamic-floor', lambda q: q.update(diagnostic=0))]
        def duplicate(record):
            quote = bytes.fromhex(record['typed_result_json_hex']).decode('ascii')
            record['typed_result_json_hex'] = (quote[:-1] + ',"requiredFusedPlasma":21000}').encode('ascii').hex()
        cases.append(frames.rewrite_record(raw, generic, 'dynamic-floor', duplicate))
        for number, selected in enumerate(cases):
            with self.subTest(case=number), self.assertRaises(REFUSALS):
                self.check_generic(selected)

    def test_source_views_refuse_missing_duplicate_and_cross_identity_frames(self):
        raw = self.ptlc_stream()
        events = [json.loads(line) for line in raw.splitlines()]
        name = ptlc.TEST + '/long-dynamic-fused-only'
        indices = [i for i, row in enumerate(events) if row.get('Action') == 'output' and row.get('Test') == name]
        self.assertGreater(len(indices), 3)
        def packed(rows):
            return b'\n'.join(json.dumps(row).encode('ascii') for row in rows) + b'\n'
        missing = [row for i, row in enumerate(events) if i not in indices]
        repeated = copy.deepcopy(events)
        repeated[indices[-1] + 1:indices[-1] + 1] = copy.deepcopy([events[i] for i in indices])
        crossed = copy.deepcopy(events)
        crossed[indices[1]]['Test'] = ptlc.TEST + '/short-dynamic-fused-only'
        wrong_package = copy.deepcopy(events)
        wrong_package[indices[0]]['Package'] = 'unselected/package'
        for label, selected in (('missing', missing), ('repeated', repeated), ('crossed', crossed), ('package', wrong_package)):
            with self.subTest(case=label), self.assertRaises(REFUSALS):
                self.check_ptlc(packed(selected))

    def test_same_child_fragment_order_is_bound(self):
        events = [json.loads(line) for line in self.ptlc_stream().splitlines()]
        chosen = [i for i, row in enumerate(events) if row.get('Action') == 'output'
            and row.get('Test') == ptlc.TEST + '/long-dynamic-fused-only']
        events[chosen[1]], events[chosen[2]] = events[chosen[2]], events[chosen[1]]
        raw = b'\n'.join(json.dumps(row).encode('ascii') for row in events) + b'\n'
        with self.assertRaises(REFUSALS):
            self.check_ptlc(raw)

    def test_reflected_corpus_hash_cannot_change_the_frozen_record_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copied_root(directory)
            path = root / source.GENERIC_FIXTURE
            selected = json.loads(path.read_bytes())
            selected['typed-zero-json']['kind'] = 'source-rpc'
            path.write_bytes(json.dumps(selected, sort_keys=True).encode('ascii'))
            manifest_path = root / source.MANIFEST
            manifest = json.loads(manifest_path.read_bytes())
            manifest['input_sha256'][source.GENERIC_FIXTURE] = source.sha(path)
            manifest['generic_payload_sha256'] = source.payload_pin(selected)
            manifest_path.write_bytes(json.dumps(manifest).encode('ascii'))
            with self.assertRaises(REFUSALS):
                source.inputs(root)

    def test_complete_source_view_requires_all_three_probes_and_no_extra_file(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            digest = hashlib.sha256(b'x').hexdigest()
            index = {}
            for i in range(443):
                name = 'file-' + str(i) + '.go'
                (checkout / name).write_bytes(b'x')
                index[name] = dict(bytes=1, sha256=digest)
            for name, selected in source.PROBES.items():
                path = checkout / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / selected).read_bytes())
            source.check_source(checkout, index, ROOT)
            selected_probe = checkout / next(iter(source.PROBES))
            original = selected_probe.read_bytes()
            selected_probe.write_bytes(original + b'\n')
            with self.assertRaises(REFUSALS):
                source.check_source(checkout, index, ROOT)
            selected_probe.write_bytes(original)
            (checkout / 'unselected.go').write_bytes(b'x')
            with self.assertRaises(REFUSALS):
                source.check_source(checkout, index, ROOT)

    def test_archive_structure_refusals_precede_destination_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = 'selected'
            for kind in ('traversal', 'symlink-metadata', 'wrong-root', 'case-alias'):
                archive = root / (kind + '.zip')
                with zipfile.ZipFile(archive, 'w') as packed:
                    name = prefix + '/file.go'
                    if kind == 'traversal':
                        name = prefix + '/../file.go'
                    elif kind == 'wrong-root':
                        name = 'other/file.go'
                    info = zipfile.ZipInfo(name)
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16 if kind == 'symlink-metadata' else (stat.S_IFREG | 0o644) << 16
                    packed.writestr(info, b'x')
                    if kind == 'case-alias':
                        packed.writestr(prefix + '/FILE.GO', b'x')
                data = archive.read_bytes()
                index = {'file.go': dict(bytes=1, sha256=hashlib.sha256(b'x').hexdigest(),
                    git_blob_sha1=hashlib.sha1(b'blob 1\0x').hexdigest())}
                destination = root / ('output-' + kind)
                with self.subTest(case=kind), patch.object(preparer, 'inputs', return_value=({}, index, {}, {})), \
                     patch.object(preparer, 'ARCHIVE_PREFIX', prefix), patch.object(preparer, 'ARCHIVE_BYTES', len(data)), \
                     patch.object(preparer, 'ARCHIVE_SHA256', hashlib.sha256(data).hexdigest()):
                    with self.assertRaises(REFUSALS):
                        preparer.prepare(archive, destination)
                    self.assertFalse(destination.exists())

    def test_over_limit_capture_retains_only_declared_original_prefixes(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            process = SimpleNamespace(returncode=0, communicate=lambda **kwargs: (b'a' * 100, b'b' * 80))
            with patch.object(cli.subprocess, 'Popen', return_value=process), patch.object(cli, 'MAX_FILE', 64):
                result = cli.capture(['synthetic'], evidence, {}, evidence, 'generic', 1)
            self.assertIs(result['output_complete'], False)
            self.assertEqual((result['stdout_bytes'], result['retained_stdout_bytes']), (100, 64))
            self.assertEqual(result['retention'], 'BOUNDED_ORIGINAL_PREFIXES_ONLY')
            self.assertEqual((evidence / 'generic.stdout').read_bytes(), b'a' * 64)
            self.assertEqual((evidence / 'generic.stderr').read_bytes(), b'b' * 64)

    def test_failed_retention_never_becomes_success_or_regenerates_missing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            payloads = {'generic.stdout': b'known incomplete original\n'}
            report = dict(schema=cli.RESULT_SCHEMA, outcome='FAILED_OR_INCOMPLETE', subject_commit=None,
                application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
            frames.write_artifact(evidence, payloads, report, ROOT)
            with self.assertRaises(REFUSALS):
                cli.selected_artifact_names(evidence)
            selected = cli.selected_artifact_names(evidence, allow_incomplete=True)
            self.assertEqual(selected, ['generic.stdout', 'qualification-result.json', 'retention-manifest.json'])
            self.assertEqual((evidence / 'generic.stdout').read_bytes(), payloads['generic.stdout'])
            self.assertFalse((evidence / 'originals.stdout').exists())

    def test_successful_artifact_has_exactly_thirteen_explicit_selected_files(self):
        payloads, report = frames.valid_artifact(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            frames.write_artifact(evidence, payloads, report, ROOT)
            names = cli.selected_artifact_names(evidence)
            self.assertEqual(len(names), 13)
            self.assertEqual(set(names), set(cli.original_names()) | {'qualification-result.json', 'retention-manifest.json'})
            (evidence / 'unselected-original.txt').write_bytes(b'preserve separately')
            self.assertEqual(cli.selected_artifact_names(evidence), names)
            self.assertEqual((evidence / 'unselected-original.txt').read_bytes(), b'preserve separately')

    def test_coherent_native_and_retention_hash_rewrites_cannot_promote_bad_quote(self):
        payloads, report = frames.valid_artifact(ROOT)
        payloads['ptlc.stdout'] = frames.rewrite_quote(payloads['ptlc.stdout'], ptlc,
            'long-dynamic-fused-only', lambda q: q.update(requiredFusedPlasma=73500))
        pin = hashlib.sha256(payloads['ptlc.stdout']).hexdigest()
        row = report['native_runs']['ptlc']
        row.update(stdout_sha256=pin, retained_stdout_sha256=pin,
            stdout_bytes=len(payloads['ptlc.stdout']), retained_stdout_bytes=len(payloads['ptlc.stdout']))
        with self.assertRaises(REFUSALS):
            cli.inspect(payloads, report)

    def test_artifact_metadata_refuses_boolean_exit_and_complete_prefix_claims(self):
        payloads, report = frames.valid_artifact(ROOT)
        for changes in ({'actual_exit': False}, {'retention': 'BOUNDED_ORIGINAL_PREFIXES_ONLY'}, {'output_complete': 1}):
            selected = copy.deepcopy(report)
            selected['native_runs']['ptlc'].update(changes)
            with self.subTest(changes=changes), self.assertRaises(REFUSALS):
                cli.inspect(payloads, selected)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            frames.write_artifact(evidence, payloads, report, ROOT)
            (evidence / 'ptlc.stdout').chmod(0o644)
            with self.assertRaises(REFUSALS):
                cli.selected_artifact_names(evidence)

    def test_both_optimized_entries_refuse_before_source_or_evidence_access(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'not-created'
            for name in ('prepare_nom_rpc_quotes.py', 'qualify_nom_rpc_quotes.py'):
                result = subprocess.run([sys.executable, '-B', '-O', str(ROOT / 'scripts' / name), '--evidence', str(missing)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b'requires assertions enabled', result.stderr)
                self.assertFalse(missing.exists())

    def test_independently_selected_git_subject_refuses_reflected_code_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copied_root(directory)
            environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
            def git(*arguments):
                result = subprocess.run(['git', '-c', 'user.name=Synthetic Fixture', '-c', 'user.email=fixture.invalid',
                    '-c', 'commit.gpgsign=false', *arguments], cwd=root, env=environment,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
                self.assertEqual(result.returncode, 0)
                return result.stdout.decode('ascii').strip()
            git('init', '-q')
            git('add', '.')
            git('commit', '-qm', 'Synthetic source subject')
            head = git('rev-parse', 'HEAD')
            cli.verify_subject(head, root)
            name = 'qualification/nom_rpc_quote_generic.py'
            path = root / name
            path.write_bytes(path.read_bytes() + b'\n')
            manifest_path = root / source.MANIFEST
            manifest = json.loads(manifest_path.read_bytes())
            manifest['input_sha256'][name] = source.sha(path)
            manifest_path.write_bytes(json.dumps(manifest).encode('ascii'))
            source.inputs(root)  # A coherent manifest is selection, not authentication.
            with self.assertRaises(REFUSALS):
                cli.verify_subject(head, root)


if __name__ == '__main__':
    unittest.main()
