"""Synthetic private transport controls do not authenticate native producers."""

from copy import deepcopy
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import qualify_worker_macho_prefix as q
import test_worker_remapping as builders
import test_worker_sections as sections
import test_worker_symbols as symbols


class MachoFixture(builders.RemappingFixture):
    def __init__(self, parent):
        super().__init__(parent)
        self.platform = q.PLATFORM
        self.prefix = str(self.root)+'/'
        self.payload = {}
        for name in q.scanner.SELECTIONS:
            names = b'\x00'; entries = []
            for value in self.locations(name).values():
                entries.append((len(names), 0x66)); names += value+b'/synthetic.o\x00'
            self.payload[name] = symbols.macho(names, entries)

    def qualify(self):
        with self.gates(), patch.object(q.rust.original, 'native_platform', return_value=q.PLATFORM):
            return q.qualify(self.root, self.pairs, self.home, self.platform, self.tools, self.prefix)


class WorkerMachoPrefixTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = MachoFixture(Path(temporary.name).resolve())

    def refuses(self):
        with self.assertRaises(q.InputError) as caught:
            self.fixture.qualify()
        self.assertEqual(str(caught.exception), q.REFUSAL)

    def test_exact_single_linker_argument_follows_four_unchanged_rust_rules(self):
        f = self.fixture; values = q.encoded_flags(f.locations(), f.prefix).split('\x1f')
        self.assertEqual(values[:-1], q.rust.encoded_flags(f.locations()).split('\x1f'))
        self.assertEqual(values[-1], '-Clink-arg=-Wl,-oso_prefix,'+f.prefix)
        self.assertEqual(len(values), 5)
        self.assertEqual(values[-1].split(',')[1:], ['-oso_prefix', f.prefix])

    def test_explicit_prefix_does_not_follow_cwd_environment_or_pair_common_ancestor(self):
        f = self.fixture; prefix = str(f.home)+'/'
        with patch.dict(os.environ, OSO_PREFIX='/synthetic/ignored/', LD_FLAGS='-oso_prefix .'):
            self.assertEqual(q.object_prefix(prefix), prefix)
        self.assertFalse(str(f.pairs['first'][1]).startswith(prefix))
        self.assertTrue(q.encoded_flags(f.locations(), prefix).endswith(','+prefix))

    def test_missing_or_repeated_trailing_slash_dot_root_and_relative_inputs_refuse(self):
        f = self.fixture
        for value in (str(f.root), f.prefix+'/', '.', './', '/', '//', 'synthetic-relative/', f.prefix+'../', f.prefix+'./'):
            f.prefix = value
            with self.subTest(value=value): self.refuses()
        self.assertEqual(f.calls, [])

    def test_whitespace_comma_equals_unit_separator_and_shell_injection_refuse_before_native_work(self):
        f = self.fixture; selected = f.prefix
        for suffix in (' space', '\t', '\n', ',', '=', '\x1f', "'", '"', '\\', '$', '`', ';', '&', '(', ')', '*', '?', ':', '\x7f', '\u00e9'):
            f.prefix = selected[:-1]+suffix+'/'
            with self.subTest(suffix=suffix): self.refuses()
        self.assertEqual(f.calls, [])

    def test_foreign_string_hook_types_and_oversize_prefixes_refuse(self):
        class Foreign(str):
            def __len__(self): raise AssertionError('foreign hook')
        for value in (None, 1, True, b'/synthetic/directory/', Path('/synthetic/directory'),
                      Foreign(self.fixture.prefix), '/synthetic/'+('x'*4096)+'/'):
            self.fixture.prefix = value
            self.refuses()
        self.assertEqual(self.fixture.calls, [])

    def test_missing_file_symlink_and_ancestor_alias_prefixes_refuse(self):
        f = self.fixture; final = f.root/'synthetic-prefix'; final.write_bytes(b'synthetic')
        f.prefix = str(final)+'/'
        self.refuses(); final.unlink(); final.symlink_to(f.home, target_is_directory=True)
        self.refuses()
        f.prefix = str(final/'child')+'/'
        self.refuses(); f.prefix = str(f.root/'absent')+'/'
        self.refuses(); self.assertEqual(f.calls, [])

    def test_foreign_owned_prefix_refuses_without_measurement_or_launch(self):
        with patch.object(q.os, 'geteuid', return_value=os.geteuid()+1): self.refuses()
        self.assertEqual(self.fixture.calls, [])

    def test_platform_and_cross_host_selections_refuse_without_linux_no_op(self):
        f = self.fixture
        for value in ('x86_64-unknown-linux-gnu', 'x86_64-apple-darwin', None, True):
            f.platform = value
            self.refuses()
        f.platform = q.PLATFORM
        with f.gates(), patch.object(q.rust.original, 'native_platform', return_value='x86_64-unknown-linux-gnu'):
            with self.assertRaises(q.InputError): q.qualify(f.root, f.pairs, f.home, f.platform, f.tools, f.prefix)
        self.assertEqual(f.calls, [])

    def test_invalid_second_c_path_refuses_before_either_metadata_or_environment_change(self):
        f = self.fixture; source, build = f.pairs['second']; destination = source.with_name('synthetic source')
        source.rename(destination); f.pairs['second'] = destination, build
        before = dict(os.environ); self.refuses()
        self.assertEqual(f.calls, []); self.assertEqual(dict(os.environ), before)

    def test_nonempty_aliased_and_incomplete_pairs_refuse_before_native_work(self):
        f = self.fixture; (f.pairs['second'][0]/'synthetic').write_bytes(b'synthetic')
        self.refuses(); (f.pairs['second'][0]/'synthetic').unlink()
        f.pairs['second'] = f.pairs['first']; self.refuses()
        f.pairs.pop('second'); self.refuses(); self.assertEqual(f.calls, [])

    def test_selected_commands_keep_bounds_target_flags_and_c_profile(self):
        f = self.fixture; f.qualify()
        self.assertEqual([row[0][1] for row in f.calls], ['metadata', 'build', 'metadata', 'build'])
        for index, (command, env, cwd, request, bounds) in enumerate(f.calls):
            name = q.scanner.SELECTIONS[index//2]
            self.assertEqual(bounds['timeout'], 30 if index%2 == 0 else 240)
            self.assertEqual(env['CFLAGS'], q.c.c_flags(f.locations(name)))
            self.assertEqual(env['CARGO_ENCODED_RUSTFLAGS'], q.encoded_flags(f.locations(name), f.prefix))
            self.assertEqual(env['CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER'], str(f.tools['c-compiler']))
            self.assertIn('--offline', command); self.assertIn('--locked', command)
            self.assertEqual(request, b''); self.assertEqual(cwd, f.pairs[name][0])

    def test_inherited_c_and_rust_flag_controls_clear_and_restore_after_success(self):
        f = self.fixture; initial = dict(CFLAGS='private stale', TARGET_CFLAGS='private stale',
            CFLAGS_aarch64_apple_darwin='private stale', RUSTFLAGS='private stale',
            CARGO_ENCODED_RUSTFLAGS='private stale', CC_SHELL_ESCAPED_FLAGS='1', SYNTHETIC_UNRELATED='retained')
        with patch.dict(os.environ, initial):
            before = dict(os.environ); cwd = Path.cwd(); f.qualify()
            self.assertEqual(dict(os.environ), before); self.assertEqual(Path.cwd(), cwd)
        for _, env, _, _, _ in f.calls:
            self.assertNotIn('TARGET_CFLAGS', env); self.assertNotIn('CFLAGS_aarch64_apple_darwin', env)
            self.assertNotIn('RUSTFLAGS', env); self.assertEqual(env['CC_SHELL_ESCAPED_FLAGS'], '0')
            self.assertEqual(env['SYNTHETIC_UNRELATED'], 'retained')

    def test_build_failure_restores_both_environment_layers_without_retry_or_second_build(self):
        f = self.fixture; run = f.run
        def fail(command, request, **bounds):
            if command[1] == 'build': raise q.rust.original.WorkerError('private selected failure')
            return run(command, request, **bounds)
        before = dict(os.environ); cwd = Path.cwd()
        with f.gates(), patch.object(q.rust.original, 'native_platform', return_value=q.PLATFORM), patch.object(q.rust.original, '_run', side_effect=fail):
            with self.assertRaises(q.InputError) as caught: q.qualify(f.root, f.pairs, f.home, f.platform, f.tools, f.prefix)
        self.assertEqual(str(caught.exception), q.REFUSAL)
        self.assertEqual(len(f.calls), 1); self.assertEqual(dict(os.environ), before); self.assertEqual(Path.cwd(), cwd)

    def test_native_cancellation_propagates_and_restores_environment_and_cwd(self):
        f = self.fixture; before = dict(os.environ); cwd = Path.cwd()
        with f.gates(), patch.object(q.rust.original, 'native_platform', return_value=q.PLATFORM), patch.object(q.rust.original, '_run', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): q.qualify(f.root, f.pairs, f.home, f.platform, f.tools, f.prefix)
        self.assertEqual(dict(os.environ), before); self.assertEqual(Path.cwd(), cwd); self.assertEqual(f.calls, [])

    def test_changed_native_bytes_between_builds_refuse_without_symbol_reads(self):
        f = self.fixture
        f.after_build = lambda name: f.tools['rustc'].write_bytes(b'changed synthetic input') if name == 'first' else None
        with patch.object(q.symbols, 'inspect', side_effect=AssertionError('unselected symbol read')): self.refuses()
        self.assertEqual(len(f.calls), 2)

    def test_changed_pair_resolution_or_root_claim_refuses_before_observation(self):
        f = self.fixture
        def change(report, name):
            if name == 'second': report['claims']['selected_root']['features'] = ['synthetic-extra']
        f.report_change = change
        with patch.object(q.scanner, 'inspect', side_effect=AssertionError('early observation')): self.refuses()
        self.assertEqual(len(f.calls), 4)

    def test_first_artifact_changed_during_second_build_refuses_retained_measurement(self):
        f = self.fixture
        f.after_build = lambda name: f.worker('first').write_bytes(f.payload['first']+b'changed') if name == 'second' else None
        self.refuses(); self.assertEqual(len(f.calls), 4)

    def test_exactly_two_complete_and_two_symbol_streams_launch_no_worker_or_analysis_tool(self):
        f = self.fixture
        with patch.object(q.scanner, 'inspect', wraps=q.scanner.inspect) as scan, patch.object(q.symbols, 'inspect', wraps=q.symbols.inspect) as referenced:
            f.qualify()
        self.assertEqual(scan.call_count, 1); self.assertEqual(referenced.call_count, 1)
        self.assertEqual(scan.call_args, referenced.call_args); self.assertEqual(len(f.calls), 4)
        for command, _, _, _, _ in f.calls: self.assertIn(command[1], ('metadata', 'build'))

    def test_symbol_measurement_disagreement_refuses_without_retry(self):
        inspect = q.symbols.inspect
        def change(*args):
            report = inspect(*args); report['artifacts']['second']['measured']['bytes'] += 1
            return report
        with patch.object(q.symbols, 'inspect', side_effect=change): self.refuses()
        self.assertEqual(len(self.fixture.calls), 4)

    def test_symbol_byte_relation_disagreement_refuses_even_if_measurements_match(self):
        inspect = q.symbols.inspect
        def change(*args):
            report = inspect(*args); report['byte_relation'] = 'MATCH' if report['byte_relation'] == 'DIFFER' else 'DIFFER'
            return report
        with patch.object(q.symbols, 'inspect', side_effect=change): self.refuses()

    def test_elf_or_malformed_container_refuses_without_silent_platform_conversion(self):
        f = self.fixture
        f.payload['second'] = sections.elf([]); self.refuses()
        self.assertEqual(len(f.calls), 4)

    def test_fixed_object_class_is_observed_without_object_identity_or_existence(self):
        report = self.fixture.qualify()
        for artifact in report['symbols']['artifacts'].values():
            for groups in artifact['group_presence'].values():
                self.assertTrue(groups['referenced-macho-object-stab-name'])
                self.assertTrue(groups['raw-selected-string-table'])
        self.assertEqual(report['producer_attribution'], 'NOT DETERMINED')
        self.assertEqual(report['historical_comparison'], 'EARLIER RUST AND C PAIRS REMAIN SEPARATE; NO ISOLATED CAUSAL CONTROL')

    def test_equal_absent_and_different_positive_artifacts_are_permitted_observations(self):
        f = self.fixture; payload = symbols.macho(b'\x00synthetic-public-name\x00', [(1, 0x66)])
        f.payload = dict(first=payload, second=payload)
        report = f.qualify(); self.assertEqual(report['comparison']['byte_relation'], 'MATCH')
        self.assertTrue(all(row['present_role_count'] == 0 for row in report['comparison']['artifacts'].values()))
        self.assertEqual(report['independent_privacy_assessment'], 'NOT ASSESSED')
        self.assertEqual(report['application_and_core'], 'NO-GO')

    def test_equal_positive_artifacts_do_not_require_absence_as_success(self):
        f = self.fixture; f.payload['second'] = f.payload['first']
        report = f.qualify(); self.assertEqual(report['comparison']['byte_relation'], 'MATCH')
        self.assertGreater(report['comparison']['artifacts']['first']['present_role_count'], 0)

    def test_different_absent_artifacts_do_not_require_byte_equality_as_success(self):
        f = self.fixture
        f.payload = {name: symbols.macho(b'\x00synthetic-name\x00', [(1, 0x66)], name.encode()) for name in q.scanner.SELECTIONS}
        report = f.qualify(); self.assertEqual(report['comparison']['byte_relation'], 'DIFFER')
        self.assertTrue(all(row['present_role_count'] == 0 for row in report['comparison']['artifacts'].values()))

    def test_profile_is_defensive_and_report_omits_paths_arguments_encodings_and_names(self):
        f = self.fixture; profile = q.selected_profile(); profile['preceding_profile']['destinations'].clear()
        self.assertEqual(q.selected_profile()['preceding_profile'], q.c.selected_profile())
        self.assertEqual(q.selected_profile()['linker_option_count'], 1)
        raw = q.check.encoded(f.qualify())
        for value in (str(f.root).encode(), f.prefix.encode(), f.prefix.encode().hex().encode(), b'synthetic.o',
                      q.encoded_flags(f.locations(), f.prefix).encode()): self.assertNotIn(value, raw)
        self.assertNotIn(b'prefix_sha256', raw); self.assertNotIn(b'prefix_bytes', raw)

    def test_actual_cli_unknown_and_missing_private_arguments_are_not_echoed(self):
        result = subprocess.run([sys.executable, '-B', 'scripts/qualify_worker_macho_prefix.py', '--private-unknown', '/synthetic/private'], capture_output=True)
        self.assertEqual(result.returncode, 1); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, ('FAIL: '+q.REFUSAL+'\n').encode())

    def test_main_emits_exact_fixed_observation_and_terminal(self):
        f = self.fixture; argv = ['synthetic-main', '--root', str(f.root), '--cargo-home', str(f.home), '--platform', f.platform, '--object-prefix', f.prefix]
        for name, pair in f.pairs.items(): argv.extend(['--'+name+'-workspace', str(pair[0]), '--'+name+'-build-directory', str(pair[1])])
        for role, path in f.tools.items(): argv.extend(['--'+role, str(path)])
        output = io.TextIOWrapper(io.BytesIO(), encoding='ascii'); error = io.StringIO()
        with f.gates(), patch.object(q.rust.original, 'native_platform', return_value=q.PLATFORM), patch.object(sys, 'argv', argv), patch.object(sys, 'stdout', output), patch.object(sys, 'stderr', error):
            self.assertEqual(q.main(), 0); output.flush(); raw = output.buffer.getvalue()
        self.assertTrue(raw.endswith((q.TERMINAL+'\n').encode())); self.assertEqual(error.getvalue(), '')
        self.assertNotIn(f.prefix.encode(), raw)
