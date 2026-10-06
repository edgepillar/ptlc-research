"""Synthetic retained C-carrier refusal, same-stream agreement and private CLI controls."""

from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import qualify_worker_c_symbols as q
import test_worker_c_debug as builders
import test_worker_sections as containers
import test_worker_symbols as symbols


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class CarrierFixture(builders.CFixture):
    def report(self, *args):
        report = super().report(*args)
        report['schema'] = 'ptlc-offline-selected-worker-build-evidence-v1'
        report['claims']['selected_root']['fresh'] = False
        return report


class WorkerCSymbolTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.fixture = CarrierFixture(Path(temporary.name).resolve())
        self.selected = {name: self.fixture.locations(name) for name in q.scanner.SELECTIONS}
        for name in q.scanner.SELECTIONS:
            self.fixture.payload[name] = self.macho(name)
        self.claim = self.fixture.qualify()
        self.carrier = self.fixture.root/'private-c-carrier'; self.save()

    def macho(self, name, flags=(0x66,), needle=None):
        value = self.selected[name][q.scanner.ROLES[1]] if needle is None else needle
        return symbols.macho(b' '+value+b'\x00', [(1, flag) for flag in flags])

    def save(self):
        self.carrier.write_bytes(q.scanner.encoded(self.claim)+q.TERMINAL); self.carrier.chmod(0o600)

    def refresh(self, bodies):
        for name, raw in bodies.items():
            self.fixture.worker(name).write_bytes(raw)
            self.claim['builds'][name]['measured_inputs']['original-response-worker'].update(
                bytes=len(raw), selected_sha256=digest(raw), measured_sha256=digest(raw))
        arguments = []
        for name in q.scanner.SELECTIONS:
            path = self.fixture.worker(name); raw = path.read_bytes()
            arguments.extend((path, digest(raw), len(raw)))
        self.claim['comparison'] = q.scanner.inspect(*arguments, self.selected)
        self.claim['debug_names'] = q.names.inspect(*arguments, self.selected)
        self.save()

    def qualify(self, **changes):
        values = dict(root=self.fixture.root, selections=self.fixture.pairs, home=self.fixture.home,
                      platform=self.fixture.platform, carrier=self.carrier)
        values.update(changes); return q.qualify(**values)

    def refuses(self, **changes):
        with self.assertRaises(q.InputError) as caught: self.qualify(**changes)
        self.assertEqual(str(caught.exception), q.REFUSAL)

    def command(self):
        f = self.fixture
        result = [sys.executable, '-B', 'scripts/qualify_worker_c_symbols.py', '--root', str(f.root),
                  '--cargo-home', str(f.home), '--platform', f.platform, '--private-pair-report', str(self.carrier)]
        for name, pair in f.pairs.items():
            result.extend(('--'+name+'-workspace', str(pair[0]), '--'+name+'-build-directory', str(pair[1])))
        return result

    def test_canonical_json_requires_exact_c_terminal_and_complete_body(self):
        raw = self.carrier.read_bytes(); self.assertEqual(q.decode_carrier(raw), self.claim)
        for changed in (raw[:-1], raw+b'\n', raw.replace(q.TERMINAL, b''), b'{}\n'+q.TERMINAL+b'extra'):
            with self.assertRaises(q.InputError): q.decode_carrier(changed)

    def test_negative_float_nonfinite_and_long_integer_tokens_refuse(self):
        for number in (b'-1', b'1.0', b'1e0', b'NaN', b'Infinity', b'12345678901'):
            with self.assertRaises(q.InputError): q.decode_carrier(b'{"value": '+number+b'}\n'+q.TERMINAL)

    def test_duplicate_alias_whitespace_and_alternate_serialization_refuse(self):
        for raw in (b'{"a": 1, "a": 1}\n', b'{"\\u0061": 1}\n', b'{"a":1}\n', b' {"a": 1}\n'):
            with self.assertRaises(q.InputError): q.decode_carrier(raw+q.TERMINAL)

    def test_carrier_bounds_ascii_depth_and_exact_bytes_are_required(self):
        raw = self.carrier.read_bytes()
        for changed in (bytearray(raw), raw+b'X'*q.MAX_CARRIER_BYTES, b'\xff'+raw,
                        b'{"a": '+b'['*13+b'0'+b']'*13+b'}\n'+q.TERMINAL):
            with self.assertRaises(q.InputError): q.decode_carrier(changed)
        with patch.object(q, 'MAX_CARRIER_BYTES', len(raw)): self.assertEqual(q.decode_carrier(raw), self.claim)
        with patch.object(q, 'MAX_CARRIER_BYTES', len(raw)-1):
            with self.assertRaises(q.InputError): q.decode_carrier(raw)

    def test_quoted_braces_and_escaped_quotes_do_not_change_container_depth(self):
        value = {'synthetic': '[{'+('"\\'*20)+'}]', 'value': 1234567890}
        self.assertEqual(q.decode_carrier(q.scanner.encoded(value)+q.TERMINAL), value)

    def test_private_carrier_mode_owner_and_symlink_checks_precede_artifacts(self):
        with patch.object(q, '_observe', side_effect=AssertionError('no artifact read')):
            self.carrier.chmod(0o644); self.refuses(); self.carrier.chmod(0o600)
            linked = self.carrier.with_name('linked'); linked.symlink_to(self.carrier); self.refuses(carrier=linked)
            with patch.object(q.os, 'geteuid', return_value=os.geteuid()+1): self.refuses()

    def test_object_stab_measurements_use_the_existing_fixed_symbol_class(self):
        result = self.qualify()
        for name in q.scanner.SELECTIONS:
            row = result['artifacts'][name]
            self.assertEqual(row['measured'], self.claim['comparison']['artifacts'][name])
            self.assertEqual([group for group, present in row['group_presence'][q.scanner.ROLES[1]].items() if present],
                             [q.symbols.GROUPS[0], q.symbols.GROUPS[3]])
        self.assertEqual(result['producer_attribution'], 'NOT DETERMINED')

    def test_other_stab_and_non_stab_cannot_be_promoted_to_object_declarations(self):
        for flag, group in ((0x64, 4), (0x84, 4), (0x67, 4), (0x0e, 5)):
            self.refresh({name: self.macho(name, (flag,)) for name in q.scanner.SELECTIONS})
            row = self.qualify()['artifacts']['first']['group_presence'][q.scanner.ROLES[1]]
            self.assertTrue(row[q.symbols.GROUPS[group]]); self.assertFalse(row[q.symbols.GROUPS[3]])

    def test_elf_debug_pool_and_symbol_table_regions_remain_independent(self):
        for raw in (containers.elf([(b'.debug_str', 1, 0, self.selected['first'][q.scanner.ROLES[1]]+b'\x00')]),
                    symbols.elf(b'\x00'+self.selected['first'][q.scanner.ROLES[1]]+b'\x00', [(1, 4)])):
            self.refresh({'first': raw})
            result = self.qualify(); self.assertEqual(result['artifacts']['first']['format'], 'ELF64 LITTLE ENDIAN')
            self.assertEqual(result['artifacts']['first']['measured'], self.claim['comparison']['artifacts']['first'])

    def test_zero_index_raw_matches_do_not_supply_referenced_names(self):
        value = self.selected['first'][q.scanner.ROLES[1]]
        self.refresh({'first': symbols.macho(b' '+value+b'\x00', [(0, 0x66)])})
        row = self.qualify()['artifacts']['first']['group_presence'][q.scanner.ROLES[1]]
        self.assertTrue(row[q.symbols.GROUPS[0]]); self.assertFalse(row[q.symbols.GROUPS[3]])

    def test_descriptor_section_and_value_changes_do_not_supply_identity(self):
        raw = self.fixture.worker('first').read_bytes(); offset = struct.unpack_from('<I', raw, 112)[0]
        expected = self.qualify()['artifacts']['first']['group_presence']
        for at, fmt, value in ((5, 'B', 255), (6, 'H', 65535), (8, 'Q', 2**64-1)):
            self.refresh({'first': containers.replace(raw, offset+at, fmt, value)})
            self.assertEqual(self.qualify()['artifacts']['first']['group_presence'], expected)

    def test_aliased_or_nested_source_build_directories_refuse_before_artifact_reads(self):
        original = self.fixture.pairs
        changes = dict(original); changes['second'] = original['first']; self.refuses(selections=changes)
        nested = original['first'][0]/'synthetic-nested'; nested.mkdir()
        changes = dict(original); changes['first'] = (original['first'][0], nested)
        self.refuses(selections=changes)

    def test_pair_and_selection_shapes_are_exact_before_carrier_acquisition(self):
        with patch.object(q, 'load_carrier', side_effect=AssertionError('no carrier read')):
            for selections in ({}, dict(self.fixture.pairs, extra=()),
                               dict(self.fixture.pairs, first=list(self.fixture.pairs['first'])),
                               dict(self.fixture.pairs, first=(self.fixture.pairs['first'][0],))):
                self.refuses(selections=selections)

    def test_unsupported_platform_and_numeric_profile_aliases_refuse(self):
        for platform in (True, 'synthetic-platform'): self.refuses(platform=platform)
        self.claim['selected_profile']['root_claim_profile']['debug_assertions'] = 1
        self.save(); self.refuses()

    def test_fixed_top_schema_profile_and_declarations_are_required(self):
        original = deepcopy(self.claim)
        for key in q.PAIR_DECLARATIONS:
            self.claim = deepcopy(original); self.claim[key] = 'synthetic-altered'; self.save(); self.refuses()
        self.claim = deepcopy(original); self.claim['extra'] = 'synthetic-claim'; self.save(); self.refuses()
        self.claim = deepcopy(original); self.claim['selected_profile'] = q.driver.rust.selected_profile()
        self.save(); self.refuses()

    def test_fixed_build_source_manifest_baseline_platform_and_prepared_count_are_required(self):
        original = deepcopy(self.claim)
        for field, value in (('schema', 'synthetic'), ('source_commit', '0'*40), ('witness_manifest_sha256', '0'*64),
                             ('resolution_baseline_sha256', '0'*64), ('platform', 'synthetic'),
                             ('prepared_source_files', True), ('prepared_source_files', 54)):
            self.claim = deepcopy(original); self.claim['builds']['first'][field] = value
            self.save(); self.refuses()

    def test_root_profile_features_fresh_and_relative_path_are_fixed_claims(self):
        original = deepcopy(self.claim)
        for field, value in (('profile', {}), ('features', [0]), ('features', {}), ('fresh', 0),
                             ('fresh', True), ('executable_relative_path', 'synthetic/other')):
            self.claim = deepcopy(original); self.claim['builds']['first']['claims']['selected_root'][field] = value
            self.save(); self.refuses()

    def test_pair_resolution_contents_root_and_native_rows_must_match_without_remeasurement(self):
        original = deepcopy(self.claim)
        for field in ('resolution_sha256', 'selected_contents_sha256'):
            self.claim = deepcopy(original); self.claim['builds']['first'][field] = '3'*64
            self.save(); self.refuses()
        self.claim = deepcopy(original); self.claim['builds']['first']['claims']['selected_root']['extra'] = 'synthetic'
        self.save(); self.refuses()
        self.claim = deepcopy(original); row = self.claim['builds']['first']['measured_inputs']['cargo']
        row['selected_sha256'] = row['measured_sha256'] = '3'*64
        self.save(); self.refuses()
        for field, value in (('bytes', True), ('status', 'synthetic-claimed'), ('measured_sha256', '0'*64)):
            self.claim = deepcopy(original)
            self.claim['builds']['first']['measured_inputs']['cargo'][field] = value
            self.save(); self.refuses()

    def test_measurement_hash_size_boolean_and_count_aliases_refuse(self):
        original = deepcopy(self.claim)
        for field, value in (('bytes', True), ('bytes', 1), ('sha256', '0'*64), ('present_role_count', True),
                             ('present_role_count', 0), ('selected_prefix_presence', {})):
            self.claim = deepcopy(original); self.claim['comparison']['artifacts']['first'][field] = value
            self.save(); self.refuses()

    def test_debug_shapes_class_booleans_format_and_complete_scan_union_are_required(self):
        original = deepcopy(self.claim)
        for part in ('shape', 'format', 'boolean', 'union'):
            self.claim = deepcopy(original); row = self.claim['debug_names']['artifacts']['first']
            if part == 'shape': row['group_presence'][q.scanner.ROLES[0]].pop(q.names.GROUPS[0])
            elif part == 'format': row['format'] = 'synthetic'
            elif part == 'boolean': row['group_presence'][q.scanner.ROLES[0]][q.names.GROUPS[0]] = 0
            else: row['group_presence'][q.scanner.ROLES[0]][q.names.GROUPS[8]] = True
            self.save(); self.refuses()

    def test_carrier_relation_and_complete_debug_measurements_cannot_disagree(self):
        original = deepcopy(self.claim)
        self.claim['debug_names']['byte_relation'] = 'MATCH'; self.save(); self.refuses()
        self.claim = deepcopy(original); self.claim['debug_names']['artifacts']['first']['measured']['bytes'] += 1
        self.save(); self.refuses()

    def test_retained_artifact_change_refuses_without_rebuilding_or_repair(self):
        path = self.fixture.worker('first'); raw = path.read_bytes()+b'synthetic-changed'; path.write_bytes(raw)
        self.refuses(); self.assertEqual(path.read_bytes(), raw)

    def test_artifact_link_alias_owner_and_named_replacement_are_refused(self):
        path = self.fixture.worker('first'); other = path.with_name('synthetic-copy'); other.write_bytes(path.read_bytes())
        path.unlink(); path.symlink_to(other); self.refuses(); path.unlink(); path.write_bytes(other.read_bytes())
        original = q.symbols._localize; replaced = [False]
        def replacement(raw, prefixes):
            result = original(raw, prefixes)
            if not replaced[0]: replaced[0] = True; other.write_bytes(path.read_bytes()); other.replace(path)
            return result
        with patch.object(q.symbols, '_localize', side_effect=replacement): self.refuses()
        body = symbols.macho(b'\x00synthetic-public\x00', [(1, 0x66)])
        self.refresh(dict.fromkeys(q.scanner.SELECTIONS, body))
        second = self.fixture.worker('second'); second.unlink(); os.link(path, second)
        self.refuses()
        second.unlink(); second.write_bytes(body)
        with patch.object(q.os, 'geteuid', return_value=os.geteuid()+1): self.refuses()

    def test_invalid_carrier_is_refused_before_two_artifact_acquisitions(self):
        self.claim['selected_profile']['c_option_count'] = 3; self.save()
        with patch.object(q, '_observe', side_effect=AssertionError('no artifact acquisition')): self.refuses()

    def test_debug_classes_are_revalidated_from_actual_same_stream_bytes(self):
        row = self.claim['debug_names']['artifacts']['first']['group_presence'][q.scanner.ROLES[1]]
        row[q.names.GROUPS[7]] = False; row[q.names.GROUPS[5]] = True; self.save()
        self.refuses()

    def test_same_stream_symbol_format_and_cross_reader_implications_are_required(self):
        actual = q.symbols._localize
        for part in ('format', 'raw', 'type'):
            def altered(raw, prefixes):
                report = actual(raw, prefixes)
                if part == 'format': report['format'] = 'synthetic'
                else:
                    row = report['group_presence'][q.scanner.ROLES[1]]
                    row[q.symbols.GROUPS[0 if part == 'raw' else 3]] = False
                return report
            with patch.object(q.symbols, '_localize', side_effect=altered): self.refuses()
        for flags in ((0x64, 0x66, 0x84, 0x0e), (0x64, 0x84), (0x67, 0x0e)):
            self.refresh({name: self.macho(name, flags) for name in q.scanner.SELECTIONS})
            self.qualify()

    def test_equal_absent_and_different_positive_artifacts_are_observations_only(self):
        body = symbols.macho(b'\x00synthetic-public\x00', [(1, 0x66)])
        self.refresh(dict.fromkeys(q.scanner.SELECTIONS, body)); report = self.qualify()
        self.assertEqual(report['byte_relation'], 'MATCH')
        for row in report['artifacts'].values(): self.assertEqual(row['measured']['present_role_count'], 0)
        self.refresh({'first': self.macho('first')}); report = self.qualify()
        self.assertEqual(report['byte_relation'], 'DIFFER'); self.assertEqual(report['application_and_core'], 'NO-GO')

    def test_exactly_one_carrier_and_two_artifact_streams_use_no_subprocess_or_historical_input_read(self):
        original = q.scanner.contents.regular; seen = []
        def opened(path, bound): seen.append(path); return original(path, bound)
        with patch.object(q.scanner.contents, 'regular', side_effect=opened), \
                patch.object(subprocess, 'run', side_effect=AssertionError('no native command')), \
                patch.object(q.driver.check.inputs, 'measure', side_effect=AssertionError('no historical measurement')):
            self.qualify()
        self.assertEqual(seen, [self.carrier, self.fixture.worker('first'), self.fixture.worker('second')])

    def test_private_carrier_named_replacement_refuses_before_artifacts(self):
        actual = q.decode_carrier
        def replaced(raw):
            result = actual(raw); other = self.carrier.with_name('synthetic-replacement')
            other.write_bytes(raw); other.chmod(0o600); other.replace(self.carrier); return result
        with patch.object(q, 'decode_carrier', side_effect=replaced), \
                patch.object(q, '_observe', side_effect=AssertionError('no artifact read')): self.refuses()

    def test_private_parser_failures_sanitize_and_cancellation_propagates(self):
        for module, method in ((q, 'load_carrier'), (q, '_claims'), (q.names, '_localize')):
            with patch.object(module, method, side_effect=RuntimeError('synthetic-private-detail')): self.refuses()
            for error in (KeyboardInterrupt, SystemExit):
                with patch.object(module, method, side_effect=error):
                    with self.assertRaises(error): self.qualify()

    def test_prefix_selection_is_copied_before_carrier_callbacks(self):
        actual = q.load_carrier; values = deepcopy(self.selected)
        def changed(path):
            result = actual(path)
            for row in values.values(): row[q.scanner.ROLES[1]] = b'/synthetic/changed-location'
            return result
        with patch.object(q.driver.rust, 'selected_locations', side_effect=lambda root, source, build, home:
                          values[next(name for name, pair in self.fixture.pairs.items() if pair[0] == source)]), \
                patch.object(q, 'load_carrier', side_effect=changed):
            self.assertTrue(self.qualify()['artifacts']['first']['measured']['selected_prefix_presence'][q.scanner.ROLES[1]])

    def test_private_names_locations_encodings_fingerprints_and_metadata_are_not_emitted(self):
        self.claim['builds']['first']['ignored-private-claim'] = str(self.fixture.root); self.save()
        raw = q.scanner.encoded(self.qualify()).decode('ascii')
        for row in self.selected.values():
            for value in row.values():
                for forbidden in (value.decode(), value.hex(), digest(value)): self.assertNotIn(forbidden, raw)
        for forbidden in (digest(self.carrier.read_bytes()), 'reference_count', 'entry_count', 'prefix_length', 'timestamp', 'offset'):
            self.assertNotIn(forbidden, raw)
        self.assertIn('NOT REQUALIFIED OR ATTESTED', raw); self.assertIn('KEEP BOTH ARTIFACTS PRIVATE', raw)

    def test_real_cli_success_emits_exact_fixed_observation_and_terminal(self):
        result = subprocess.run(self.command(), capture_output=True, check=False)
        self.assertEqual(result.returncode, 0); self.assertEqual(result.stderr, b'')
        report, end = json.JSONDecoder().raw_decode(result.stdout.decode('ascii'))
        self.assertEqual(report, self.qualify())
        self.assertEqual(result.stdout.decode('ascii')[end:], '\nPASS: retained C-worker symbols; two selected streams; NOT ASSESSED\n')

    def test_real_cli_changed_carrier_refuses_without_private_diagnostics(self):
        self.carrier.write_bytes(b'synthetic-private-malformed'); self.carrier.chmod(0o600)
        result = subprocess.run(self.command(), capture_output=True, check=False)
        self.assertEqual(result.returncode, 1); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, ('FAIL: '+q.REFUSAL+'\n').encode('ascii'))

    def test_real_cli_unknown_option_does_not_echo_its_private_value(self):
        result = subprocess.run(self.command()+['--unselected-option', str(self.fixture.root)], capture_output=True, check=False)
        self.assertEqual(result.returncode, 1); self.assertEqual(result.stdout, b'')
        self.assertNotIn(str(self.fixture.root).encode(), result.stderr)

    def test_cli_cancellation_propagates_without_partial_public_report(self):
        for error in (KeyboardInterrupt, SystemExit):
            with patch.object(sys, 'argv', self.command()[2:]), patch.object(q, 'qualify', side_effect=error), \
                    patch.object(sys, 'stdout', new_callable=io.StringIO) as stdout:
                with self.assertRaises(error): q.main()
                self.assertEqual(stdout.getvalue(), '')
