"""Synthetic C profile selection and composed native-driver refusal controls."""

import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import qualify_worker_c_debug as q
import test_worker_remapping as builders
import test_worker_sections as containers


class CFixture(builders.RemappingFixture):
    def __init__(self, parent):
        super().__init__(parent)
        self.payload = {name: containers.elf([(b'.debug_str', 1, 0,
                        b'\x00'.join(self.locations(name).values())+b'\x00')])
                        for name in q.scanner.SELECTIONS}

    def qualify(self):
        with self.gates():
            return q.qualify(self.root, self.pairs, self.home, self.platform, self.tools)


class WorkerCDebugTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = CFixture(Path(temporary.name).resolve())

    def refuses(self):
        with self.assertRaises(q.InputError) as caught:
            self.fixture.qualify()
        self.assertEqual(str(caught.exception), q.REFUSAL)

    def run_with(self, function, **patches):
        with self.fixture.gates(), patch.object(q.rust.original, '_run', side_effect=function), patch.dict(os.environ, patches):
            return q.qualify(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, self.fixture.tools)

    def test_exact_four_c_rules_use_shortest_first_with_unchanged_destinations(self):
        locations = self.fixture.locations()
        rules = q.c_flags(locations).split(' ')
        order = sorted(q.scanner.ROLES, key=lambda role: (len(locations[role]), q.scanner.ROLES.index(role)))
        self.assertEqual(rules, ['-fdebug-prefix-map='+locations[role].decode()+'/='+q.rust.DESTINATIONS[role] for role in order])
        self.assertEqual(len(rules), 4)
        self.assertNotIn('\x1f', q.c_flags(locations))

    def test_equal_length_c_rules_preserve_fixed_role_order(self):
        locations = {role: ('/synthetic/location/'+str(index)).encode() for index, role in enumerate(q.scanner.ROLES)}
        rules = q.c_flags(locations).split()
        self.assertEqual([rule.split('=', 1)[1].split('/=', 1)[0] for rule in rules], [locations[role].decode() for role in q.scanner.ROLES])

    def test_c_rules_allow_only_selected_literal_ascii_path_alphabet(self):
        locations = {role: ('/synthetic/A_b-c.1/'+str(index)).encode() for index, role in enumerate(q.scanner.ROLES)}
        self.assertEqual(len(q.c_flags(locations).split()), 4)
        for suffix in (b' space', b'\t', b'\n', b"'", b'"', b'\\', b'=', b'$', b'`', b';', b'&', b'(', b')', b'*', b'?', b'[', b']', b'!', b'~', b':', b'\x7f', b'\xc3\xa9'):
            bad = locations.copy(); bad[q.scanner.ROLES[0]] += suffix
            with self.subTest(suffix=suffix), self.assertRaises(q.InputError): q.c_flags(bad)

    def test_exact_prefix_types_roles_and_duplicate_values_refuse_without_hooks(self):
        locations = self.fixture.locations()
        class ForeignBytes(bytes):
            def decode(self, *args, **kwargs): raise AssertionError('foreign hook called')
        for bad in ({}, dict(locations, extra=b'/synthetic/other'),
                    {role: locations[q.scanner.ROLES[0]] for role in q.scanner.ROLES},
                    dict(locations, **{q.scanner.ROLES[0]: ForeignBytes(b'/synthetic/foreign')})):
            with self.assertRaises(q.InputError): q.c_flags(bad)

    def test_lexical_absolute_rules_are_kept_for_c_transport(self):
        locations = self.fixture.locations()
        for value in (b'synthetic-relative', b'/synthetic/../location', b'/synthetic/./location', b'/synthetic//location', b'/synthetic/location/'):
            bad = locations.copy(); bad[q.scanner.ROLES[0]] = value
            with self.subTest(value=value), self.assertRaises(q.InputError): q.c_flags(bad)

    def test_trailing_slash_c_scope_excludes_bare_directory_and_lexical_sibling(self):
        locations = self.fixture.locations()
        for role in q.scanner.ROLES:
            old = locations[role].decode()
            rule = next(rule for rule in q.c_flags(locations).split() if rule.endswith('='+q.rust.DESTINATIONS[role]))
            selected = rule[len('-fdebug-prefix-map='):].split('=', 1)[0]
            self.assertEqual(selected, old+'/')
            self.assertFalse(old.startswith(selected))
            self.assertFalse((old+'-sibling/file.c').startswith(selected))
            self.assertTrue((old+'/file.c').startswith(selected))

    def test_fixed_logical_profile_is_defensive_private_and_does_not_claim_all_producers(self):
        profile = q.selected_profile()
        self.assertEqual(profile['c_option_count'], 4)
        self.assertEqual(profile['rust_option_count'], 4)
        self.assertEqual(profile['root_claim_profile'], q.check.ROOT_PROFILE)
        self.assertEqual(profile['root_features'], [])
        self.assertIn('NOT ALL C', profile['c_scope'])
        self.assertEqual(profile['stripping_or_rewriting'], 'NONE')
        raw = q.check.encoded(profile)
        for prefix in self.fixture.locations().values(): self.assertNotIn(prefix, raw)
        profile['destinations'][q.scanner.ROLES[0]] = 'synthetic-change'
        self.assertEqual(q.selected_profile()['destinations'], q.rust.DESTINATIONS)

    def test_native_command_bounds_and_target_only_rust_rules_remain_exact(self):
        self.fixture.qualify()
        self.assertEqual([call[0][1] for call in self.fixture.calls], ['metadata', 'build', 'metadata', 'build'])
        for index, (command, environment, cwd, request, bounds) in enumerate(self.fixture.calls):
            name = q.scanner.SELECTIONS[index//2]
            self.assertEqual(environment['CFLAGS'], q.c_flags(self.fixture.locations(name)))
            self.assertEqual(environment['CARGO_ENCODED_RUSTFLAGS'], q.rust.encoded_flags(self.fixture.locations(name)))
            self.assertEqual(environment['CC_SHELL_ESCAPED_FLAGS'], '0')
            self.assertEqual(environment['CARGO_NET_OFFLINE'], 'true')
            self.assertEqual(cwd, self.fixture.pairs[name][0])
            self.assertEqual(request, b'')
            self.assertIn('--locked', command); self.assertIn('--offline', command)
            self.assertEqual(command[0], str(self.fixture.tools['cargo']))
            if command[1] == 'metadata':
                self.assertEqual(bounds, dict(timeout=30, max_output_bytes=q.check.resolution.MAX_JSON_BYTES))
                self.assertEqual(command[-2:], ['--filter-platform', self.fixture.platform])
            else:
                self.assertEqual(bounds, dict(timeout=240, max_output_bytes=q.check.MAX_STREAM_BYTES))
                self.assertEqual(command[-4:], ['--target', self.fixture.platform, '--target-dir', str(self.fixture.pairs[name][1])])

    def test_inherited_c_namespaces_clear_without_repeating_selected_arguments(self):
        inherited = {base+suffix: 'synthetic-private-override' for base in q.C_CONTROLS for suffix in ('', '_native', '_OTHER')}
        inherited.update(HOST_CC='synthetic-host-compiler', CXXFLAGS='synthetic-cpp', CUSTOM_CFLAGS='synthetic-project')
        inherited['CFLAGS_'+self.fixture.platform] = 'synthetic-literal-target'
        inherited['CFLAGS_'+self.fixture.platform.replace('-', '_')] = 'synthetic-underscore-target'
        with patch.dict(os.environ, inherited):
            previous = dict(os.environ); self.fixture.qualify(); self.assertEqual(dict(os.environ), previous)
        for _, environment, _, _, _ in self.fixture.calls:
            for key in inherited:
                if key in ('HOST_CC', 'CXXFLAGS', 'CUSTOM_CFLAGS'): self.assertEqual(environment[key], inherited[key])
                elif key not in ('CFLAGS', 'CC_SHELL_ESCAPED_FLAGS'): self.assertNotIn(key, environment)
            self.assertEqual(len(environment['CFLAGS'].split()), 4)

    def test_environment_success_restores_preceding_namespace_and_unrelated_entries(self):
        with patch.dict(os.environ, CFLAGS='synthetic-before', SYNTHETIC_PRESERVED='unchanged'):
            before = dict(os.environ)
            with q._c_environment('synthetic-selected'):
                self.assertEqual(os.environ['CFLAGS'], 'synthetic-selected')
                os.environ['SYNTHETIC_TRANSIENT'] = 'private'
            self.assertEqual(dict(os.environ), before)

    def test_environment_exception_restores_all_entries_without_repair(self):
        before = dict(os.environ)
        with self.assertRaises(OSError):
            with q._c_environment('synthetic-selected'):
                os.environ.clear(); raise OSError('synthetic-private')
        self.assertEqual(dict(os.environ), before)

    def test_environment_keyboard_interrupt_and_system_exit_propagate_and_restore(self):
        before = dict(os.environ)
        for error in (KeyboardInterrupt, SystemExit):
            with self.assertRaises(error):
                with q._c_environment('synthetic-selected'): raise error()
            self.assertEqual(dict(os.environ), before)

    def test_nested_c_environment_unwinds_when_old_cwd_restoration_is_refused(self):
        before, directory = dict(os.environ), Path.cwd(); actual = os.chdir
        def chdir(path):
            if path == directory: raise OSError('synthetic-private-cwd')
            actual(path)
        try:
            with patch.object(q.rust.os, 'chdir', side_effect=chdir), self.fixture.gates():
                with self.assertRaises(q.InputError) as caught:
                    q.qualify(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, self.fixture.tools)
            self.assertEqual(str(caught.exception), q.REFUSAL)
            self.assertEqual(dict(os.environ), before)
            self.assertEqual(len(self.fixture.calls), 2)
        finally: actual(directory)

    def test_both_c_selections_validate_before_first_metadata_or_environment_change(self):
        source, build = self.fixture.pairs['second']; other = source.with_name('second source'); other.mkdir()
        self.fixture.pairs['second'] = (other, build)
        before = dict(os.environ)
        with patch.object(q, '_c_environment', side_effect=AssertionError('environment changed too early')): self.refuses()
        self.assertEqual(self.fixture.calls, [])
        self.assertEqual(dict(os.environ), before)

    def test_nonempty_second_selection_refuses_before_either_native_operation(self):
        (self.fixture.pairs['second'][1]/'synthetic').write_bytes(b'synthetic')
        self.refuses(); self.assertEqual(self.fixture.calls, [])

    def test_aliased_or_nested_pair_refuses_before_either_native_operation(self):
        source, _ = self.fixture.pairs['first']; other = source/'nested'; other.mkdir()
        self.fixture.pairs['second'] = (other, self.fixture.pairs['first'][1])
        self.refuses(); self.assertEqual(self.fixture.calls, [])

    def test_cross_platform_selection_refuses_before_c_or_rust_native_work(self):
        self.fixture.platform = next(value for value in q.check.resolution.PLATFORMS if value != self.fixture.platform)
        self.refuses(); self.assertEqual(self.fixture.calls, [])

    def test_incomplete_native_tool_roles_refuse_before_environment_or_source_use(self):
        self.fixture.tools.pop('rustc')
        self.refuses(); self.assertEqual(self.fixture.calls, [])

    def test_prebuild_content_change_keeps_private_metadata_and_never_builds(self):
        before, directory = dict(os.environ), Path.cwd()
        with self.fixture.gates(), patch.object(q.check.resolution, 'inspect', return_value=dict(
                resolution=self.fixture.resolution, selected_contents_sha256='0'*64)):
            with self.assertRaises(q.InputError):
                q.qualify(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, self.fixture.tools)
        self.assertEqual([call[0][1] for call in self.fixture.calls], ['metadata'])
        self.assertEqual(dict(os.environ), before); self.assertEqual(Path.cwd(), directory)

    def test_changed_selected_native_bytes_refuse_before_second_build_or_observation(self):
        self.fixture.after_build = lambda name: self.fixture.tools['cargo'].write_bytes(b'Changed synthetic tool.\n')
        with patch.object(q.names, 'inspect', side_effect=AssertionError('too early')): self.refuses()
        self.assertEqual(len(self.fixture.calls), 2)

    def test_second_logical_or_native_report_substitution_refuses_before_scanners(self):
        def change(report, name):
            if name == 'second': report['measured_inputs']['rustc']['selected_sha256'] = '0'*64
        self.fixture.report_change = change
        with patch.object(q.scanner, 'inspect', side_effect=AssertionError('too early')): self.refuses()
        self.assertEqual(len(self.fixture.calls), 4)

    def test_selected_root_claim_change_refuses_before_complete_comparison(self):
        def change(report, name):
            if name == 'second': report['claims']['selected_root']['synthetic-extra'] = 'changed'
        self.fixture.report_change = change
        with patch.object(q.scanner, 'inspect', side_effect=AssertionError('too early')): self.refuses()

    def test_changed_first_artifact_during_second_build_refuses_retained_expectation(self):
        def change(name):
            if name == 'second': self.fixture.worker('first').write_bytes(b'Changed synthetic output.\n')
        self.fixture.after_build = change
        self.refuses(); self.assertEqual(len(self.fixture.calls), 4)

    def test_debug_complete_row_disagreement_refuses_without_retry_or_reselection(self):
        actual = q.names.inspect
        def substitute(*args):
            report = actual(*args); report['artifacts']['first']['measured']['bytes'] += 1; return report
        with patch.object(q.names, 'inspect', side_effect=substitute) as read: self.refuses()
        self.assertEqual(read.call_count, 1); self.assertEqual(len(self.fixture.calls), 4)

    def test_debug_byte_relation_disagreement_refuses_even_with_matching_rows(self):
        actual = q.names.inspect
        def substitute(*args):
            report = actual(*args); report['byte_relation'] = 'MATCH'; return report
        with patch.object(q.names, 'inspect', side_effect=substitute): self.refuses()
        self.assertEqual(len(self.fixture.calls), 4)

    def test_invalid_debug_grammar_refuses_after_builds_without_native_analysis_or_repair(self):
        self.fixture.payload['second'] = b'Synthetic malformed container, not a native artifact.\n'
        self.refuses(); self.assertEqual(len(self.fixture.calls), 4)

    def test_debug_acquisition_error_sanitizes_and_restores_process_state(self):
        before, directory = dict(os.environ), Path.cwd()
        with patch.object(q.names, 'inspect', side_effect=OSError('synthetic-private-raw-name')): self.refuses()
        self.assertEqual(dict(os.environ), before); self.assertEqual(Path.cwd(), directory)
        self.assertEqual(len(self.fixture.calls), 4)

    def test_debug_acquisition_cancellation_propagates_after_builds_without_retry(self):
        before, directory = dict(os.environ), Path.cwd()
        with self.fixture.gates(), patch.object(q.names, 'inspect', side_effect=KeyboardInterrupt()) as read:
            with self.assertRaises(KeyboardInterrupt):
                q.qualify(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, self.fixture.tools)
        self.assertEqual(read.call_count, 1); self.assertEqual(len(self.fixture.calls), 4)
        self.assertEqual(dict(os.environ), before); self.assertEqual(Path.cwd(), directory)

    def test_positive_different_artifacts_report_fixed_classes_without_release_or_attribution(self):
        report = self.fixture.qualify()
        self.assertEqual(report['comparison']['byte_relation'], 'DIFFER')
        for name in q.scanner.SELECTIONS:
            self.assertEqual(report['comparison']['artifacts'][name]['present_role_count'], 4)
            self.assertEqual(report['debug_names']['artifacts'][name]['measured'], report['comparison']['artifacts'][name])
            for row in report['debug_names']['artifacts'][name]['group_presence'].values():
                self.assertEqual([group for group, value in row.items() if value], list(q.names.GROUPS[:2]))
        self.assertEqual(report['producer_attribution'], 'NOT DETERMINED')
        self.assertEqual(report['artifact_publication'], 'KEEP BOTH ARTIFACTS PRIVATE')

    def test_absent_prefixes_and_equal_copies_are_measurements_without_authentication(self):
        self.fixture.payload = {name: containers.elf() for name in q.scanner.SELECTIONS}
        report = self.fixture.qualify()
        self.assertEqual(report['comparison']['byte_relation'], 'MATCH')
        self.assertEqual([row['present_role_count'] for row in report['comparison']['artifacts'].values()], [0, 0])
        self.assertEqual(report['source_to_worker'], 'NOT VERIFIED')
        self.assertEqual(report['reproducibility'], 'NOT VERIFIED')
        self.assertEqual(report['independent_privacy_assessment'], 'NOT ASSESSED')
        self.assertEqual(report['application_and_core'], 'NO-GO')

    def test_absent_prefixes_and_different_bytes_do_not_select_equality_as_success(self):
        self.fixture.payload = {name: containers.elf(tail=name.encode()) for name in q.scanner.SELECTIONS}
        report = self.fixture.qualify()
        self.assertEqual(report['comparison']['byte_relation'], 'DIFFER')
        self.assertEqual([row['present_role_count'] for row in report['comparison']['artifacts'].values()], [0, 0])
        self.assertIn('NO ISOLATED CAUSAL CONTROL', report['historical_comparison'])

    def test_report_excludes_private_arguments_names_encodings_and_prefix_fingerprints(self):
        import hashlib
        report = self.fixture.qualify(); raw = q.check.encoded(report)
        for name in q.scanner.SELECTIONS:
            locations = self.fixture.locations(name)
            for prefix in locations.values():
                for private in (prefix, prefix.hex().encode(), hashlib.sha256(prefix).hexdigest().encode()): self.assertNotIn(private, raw)
            self.assertNotIn(q.c_flags(locations).encode(), raw)
            self.assertNotIn(q.rust.encoded_flags(locations).encode(), raw)
        self.assertNotIn(b'metadata.json', raw); self.assertNotIn(b'build-messages.jsonl', raw)

    def test_private_streams_retain_restricted_modes_and_unmodified_synthetic_bytes(self):
        self.fixture.qualify()
        for source, _ in self.fixture.pairs.values():
            for filename in ('metadata.json', 'build-messages.jsonl'):
                path = source/filename
                self.assertEqual(path.stat().st_mode & 0o077, 0)
                self.assertEqual(path.read_bytes(), b'{}\n')

    def test_build_failure_keeps_metadata_restores_c_and_rust_state_and_never_retries(self):
        before, directory = dict(os.environ), Path.cwd()
        def fail(command, request, **bounds):
            if command[1] == 'build': raise q.rust.original.WorkerError('synthetic-private-stream')
            return self.fixture.run(command, request, **bounds)
        with self.assertRaises(q.InputError) as caught: self.run_with(fail)
        self.assertEqual(str(caught.exception), q.REFUSAL)
        self.assertEqual(len(self.fixture.calls), 1)
        self.assertEqual(dict(os.environ), before); self.assertEqual(Path.cwd(), directory)
        self.assertTrue((self.fixture.pairs['first'][0]/'metadata.json').exists())
        self.assertFalse((self.fixture.pairs['first'][0]/'build-messages.jsonl').exists())

    def test_native_cancellation_restores_both_layers_and_starts_no_second_selection(self):
        before, directory = dict(os.environ), Path.cwd()
        with self.fixture.gates(), patch.object(q.rust.original, '_run', side_effect=SystemExit()) as launch:
            with self.assertRaises(SystemExit):
                q.qualify(self.fixture.root, self.fixture.pairs, self.fixture.home, self.fixture.platform, self.fixture.tools)
        self.assertEqual(launch.call_count, 1); self.assertEqual(self.fixture.calls, [])
        self.assertEqual(dict(os.environ), before); self.assertEqual(Path.cwd(), directory)

    def test_actual_cli_missing_selections_refuses_without_any_private_output(self):
        root = Path(__file__).resolve().parents[1]; environment = dict(os.environ); environment.pop('PYTHONPATH', None)
        result = subprocess.run([sys.executable, '-B', str(root/'scripts/qualify_worker_c_debug.py'), '--synthetic-unselected'],
                                cwd=root, capture_output=True, env=environment, timeout=10)
        self.assertEqual((result.returncode, result.stdout), (1, b''))
        self.assertEqual(result.stderr, ('FAIL: '+q.REFUSAL+'\n').encode())
        self.assertNotIn(str(root).encode(), result.stderr)

    def test_real_main_entry_returns_only_fixed_synthetic_observation_and_pass_marker(self):
        arguments = ['selected-driver', '--root', str(self.fixture.root), '--cargo-home', str(self.fixture.home), '--platform', self.fixture.platform]
        for name, pair in self.fixture.pairs.items(): arguments += ['--'+name+'-workspace', str(pair[0]), '--'+name+'-build-directory', str(pair[1])]
        for role, path in self.fixture.tools.items(): arguments += ['--'+role, str(path)]
        output = io.BytesIO(); error = io.StringIO()
        class Stdout:
            buffer = output
            def write(self, value): output.write(value.encode('ascii')); return len(value)
            def flush(self): pass
        with self.fixture.gates(), patch.object(sys, 'argv', arguments), patch.object(sys, 'stdout', Stdout()), patch.object(sys, 'stderr', error):
            self.assertEqual(q.main(), 0)
        self.assertEqual(error.getvalue(), '')
        self.assertTrue(output.getvalue().endswith(b'PASS: selected C debug-prefix pair; two builds; two debug-name reads; NOT ASSESSED\n'))
        for name in q.scanner.SELECTIONS:
            for prefix in self.fixture.locations(name).values(): self.assertNotIn(prefix, output.getvalue())


if __name__ == '__main__':
    unittest.main()
