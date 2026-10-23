"""Privacy and incomplete-retention controls; all event data is synthetic."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import check_nom_5cb_evidence as selected


class RetentionPrivacy(unittest.TestCase):
    def test_public_ascii_events(self):
        selected.privacy(b'{"Action":"pass","Package":"github.com/public/module/vm"}\n')

    def test_non_ascii_is_refused(self):
        with self.assertRaises((ValueError, AssertionError)):
            selected.privacy(bytes((255,)))

    def test_home_volume_temporary_and_compiler_paths_are_refused(self):
        for root in ('Users', 'home', 'Volumes', 'private', 'tmp', 'var', 'usr'):
            raw = json.dumps({'unselected': os.sep + root + '/synthetic/file'}).encode('ascii')
            with self.subTest(root=root):
                with self.assertRaises((ValueError, AssertionError)):
                    selected.privacy(raw)

    def test_windows_home_is_refused(self):
        path = 'Q:' + chr(92) + chr(92).join(('Users', 'synthetic', 'file'))
        with self.assertRaises((ValueError, AssertionError)):
            selected.privacy(path.encode('ascii'))

    def test_json_encoded_windows_home_is_refused(self):
        path = 'Q:' + chr(92) + chr(92).join(('Users', 'synthetic', 'file'))
        with self.assertRaises((ValueError, AssertionError)):
            selected.privacy(json.dumps({'Output': path}).encode('ascii'))

    def test_json_unicode_escaped_home_is_refused(self):
        value = chr(92) + 'u002f'
        raw = ('{"Output":"' + value + 'Users' + value + 'synthetic' + value + 'file"}').encode('ascii')
        with self.assertRaises((ValueError, AssertionError)):
            selected.privacy(raw)

    def test_public_ascii_html_escape_is_allowed(self):
        value = chr(92) + 'u003cpublic' + chr(92) + 'u003e'
        selected.privacy(('{"Output":"' + value + '"}').encode('ascii'))

    def test_excessive_nested_escape_layers_are_refused(self):
        value = 'Q:' + chr(92) + chr(92).join(('Users', 'synthetic', 'file'))
        for unused in range(10):
            value = value.replace(chr(92), chr(92) * 2)
        with self.assertRaises((ValueError, AssertionError)):
            selected.privacy(value.encode('ascii'))

    def test_credential_shape_is_refused(self):
        with self.assertRaises((ValueError, AssertionError)):
            selected.privacy(('gh' + 'p_' + 'A' * 40).encode('ascii'))

    def test_email_is_refused(self):
        with self.assertRaises((ValueError, AssertionError)):
            selected.privacy(('synthetic' + '@' + 'example.invalid').encode('ascii'))

    def test_key_header_is_refused(self):
        with self.assertRaises((ValueError, AssertionError)):
            selected.privacy(('-----' + 'BEGIN ' + 'PRIVATE KEY' + '-----').encode('ascii'))

    def test_local_host_identifiers_are_refused(self):
        for value in ('local' + 'host', 'synthetic' + '.local', '127' + '.0.0.1'):
            with self.subTest(value=value):
                with self.assertRaises((ValueError, AssertionError)):
                    selected.privacy(value.encode('ascii'))


class IncompleteOriginals(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(strict=True)
        (self.root / 'commands').mkdir()
        self.arguments = {'go-version': ['version']}
        self.expected = mock.patch.object(selected, 'expected_arguments', return_value=self.arguments)
        self.expected.start()
        self.addCleanup(self.expected.stop)
        self.report = dict(schema='ptlc-nom-5cb-native-attempt-v1',
            outcome='FAILURE_OR_INCOMPLETE_PRESERVED', core_commit=selected.selected.CORE,
            core_tree=selected.selected.TREE, profile='all', compiler_workspaces=1,
            source_before=dict(core_commit=selected.selected.CORE,
                core_tree=selected.selected.TREE, profile='all', upstream_files=482,
                project_producers=20, combined_files=502, content='EXACT_SELECTED_CONTENTS',
                filesystem_mode_equality='NOT_ASSERTED',
                producer_authentication='NOT_ESTABLISHED_BY_READER'),
            go_sha256='0' * 64, cc_sha256='0' * 64, platform_sdk='NOT_SELECTED',
            compiler_identity_scope='MEASURED_EXECUTABLES_ONLY; TRANSITIVE_TOOLCHAIN_NOT_AUTHENTICATED',
            selected_commands=20, free_space_floor=10 * 1024**3,
            expected_reservation=2 * 1024**3, os_filesystem_quota='NOT_CLAIMED',
            source_views=1, normal_default_vet=True,
            test_result_cache='DISABLED_BY_COUNT_ONE', automatic_native_retry=False,
            application='NO-GO', core='NO-GO', independent_assessment='UNFILLED',
            journal_source_upgrade='NOT_SELECTED', commands={},
            complete_account_admission='UNFILLED', source_build_authentication='UNFILLED',
            exception_type='SyntheticFailure', elapsed_seconds=0.2)
        self.write('native-failure.json', self.report)
        streams = {'stdout': b'go version go1.23.12 linux/amd64\n', 'stderr': b''}
        self.receipt = dict(schema='ptlc-nom-5cb-native-command-v1', label='go-version',
            argv=[str(self.root / 'unselected-private-binary'), 'version'], automatic_retry=False,
            actual_exit=0, result='RETURNED_ZERO_WITH_COMPLETE_STREAMS', cleanup_complete=True,
            complete={'stdout': True, 'stderr': True}, elapsed_seconds=0.1,
            bytes={key: len(raw) for key, raw in streams.items()},
            sha256={key: hashlib.sha256(raw).hexdigest() for key, raw in streams.items()})
        for suffix, raw in streams.items():
            (self.root / 'commands' / ('go-version.' + suffix)).write_bytes(raw)
        self.write('commands/go-version.receipt.json', self.receipt)

    def write(self, name, value):
        (self.root / name).write_bytes(json.dumps(value, sort_keys=True).encode('ascii'))

    def inspect(self):
        return selected.inspect(self.root, allow_incomplete=True)

    def test_incomplete_retention_never_credits_complete_execution(self):
        result = self.inspect()
        self.assertEqual(result['outcome'], 'INCOMPLETE_RETENTION_ONLY')
        self.assertFalse(result['full_attempt'])
        self.assertEqual(result['ci_acceptance'], 'NOT_PERFORMED')
        self.assertEqual(result['original_profile_streams'], 0)
        self.assertEqual(result['application'], 'NO-GO')

    def test_unselected_sdk_marker_is_refused(self):
        self.report['platform_sdk'] = 'SYNTHETIC_UNSELECTED_SDK'
        self.write('native-failure.json', self.report)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()

    def test_darwin_sdk_marker_cannot_describe_linux_execution(self):
        self.report['platform_sdk'] = 'DARWIN_SDKROOT_SELECTED_CONTENT_UNAUTHENTICATED'
        self.report['go_version'] = 'go version go1.23.12 linux/amd64'
        self.write('native-failure.json', self.report)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()

    def test_private_argv_and_caches_are_excluded(self):
        result = self.inspect()
        raw = json.dumps(result, sort_keys=True).encode('ascii')
        self.assertNotIn(str(self.root).encode('ascii'), raw)
        self.assertNotIn('commands/go-version.receipt.json', result['files'])
        self.assertEqual(result['commands']['go-version']['arguments'], ['version'])
        self.assertEqual(set(result['files']), {
            'native-failure.json', 'commands/go-version.stdout', 'commands/go-version.stderr'})
        self.assertTrue((self.root / 'commands/go-version.receipt.json').is_file())

    def test_failure_requires_explicit_incomplete_selection(self):
        with self.assertRaises((ValueError, AssertionError)):
            selected.inspect(self.root)

    def test_unselected_argument_cannot_be_projected_as_selected(self):
        self.receipt['argv'][1:] = ['mod', 'download']
        self.write('commands/go-version.receipt.json', self.receipt)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()

    def test_unselected_original_file_prevents_wildcard_export(self):
        original = self.root / 'commands' / 'unselected.stdout'
        original.write_bytes(b'retain-private')
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()
        self.assertEqual(original.read_bytes(), b'retain-private')

    def test_stream_digest_mismatch_refuses_without_rewriting_original(self):
        original = self.root / 'commands' / 'go-version.stdout'
        original.write_bytes(b'changed-original')
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()
        self.assertEqual(original.read_bytes(), b'changed-original')

    def test_noninteger_exit_is_refused(self):
        self.receipt['actual_exit'] = True
        self.write('commands/go-version.receipt.json', self.receipt)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()

    def test_unselected_nested_receipt_field_is_not_exported(self):
        self.receipt['bytes']['unselected'] = 'private-unselected-value'
        self.write('commands/go-version.receipt.json', self.receipt)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()

    def test_structured_elapsed_diagnostic_is_not_exported(self):
        self.receipt['elapsed_seconds'] = {'unselected': 'private-unselected-value'}
        self.write('commands/go-version.receipt.json', self.receipt)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()

    def test_missing_stream_remains_unknown_and_is_not_reconstructed(self):
        original = self.root / 'commands/go-version.stderr'
        original.unlink()
        result = self.inspect()
        self.assertFalse(result['full_attempt'])
        self.assertEqual(result['commands']['go-version']['result'], 'UNKNOWN_ORIGINAL_STREAM_MISSING')
        self.assertEqual(result['commands']['go-version']['missing_streams'], ['stderr'])
        self.assertFalse(original.exists())
        self.assertTrue((self.root / 'commands/go-version.stdout').is_file())

    def test_missing_receipt_never_establishes_an_exit_or_executed_arguments(self):
        original = self.root / 'commands/go-version.receipt.json'
        original.unlink()
        result = self.inspect()
        command = result['commands']['go-version']
        self.assertFalse(result['full_attempt'])
        self.assertEqual(command['result'], 'UNKNOWN_ORIGINAL_RECEIPT_MISSING')
        self.assertIsNone(command['actual_exit'])
        self.assertEqual(command['executed_arguments'], 'NOT_ESTABLISHED')
        self.assertEqual(command['planned_arguments'], ['version'])
        self.assertFalse(original.exists())
        self.assertEqual(set(result['files']), {
            'native-failure.json', 'commands/go-version.stdout', 'commands/go-version.stderr'})

    def test_private_diagnostic_in_report_blocks_retention(self):
        self.report['unselected_diagnostic'] = str(self.root / 'private-details')
        self.write('native-failure.json', self.report)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()

    def test_unselected_metadata_field_is_refused_even_without_a_path_pattern(self):
        self.report['unselected_private_note'] = 'unselected-value'
        self.write('native-failure.json', self.report)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()

    def test_unselected_nested_source_field_is_refused(self):
        self.report['source_before']['unselected_note'] = 'unselected-value'
        self.write('native-failure.json', self.report)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()

    def test_conflicting_terminal_reports_are_refused(self):
        self.write('native-result.json', self.report)
        with self.assertRaises((ValueError, AssertionError)):
            self.inspect()


if __name__ == '__main__':
    unittest.main()
