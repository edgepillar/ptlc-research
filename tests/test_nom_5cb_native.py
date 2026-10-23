"""Native-entry refusal controls; every compiler invocation is forbidden here.

Source identities and free-space measurements are isolated fixture inputs, not
current-machine qualification or a change to a production storage policy.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import qualify_nom_5cb_native as selected


class NativeEntryRefusals(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.source, self.workspace, self.proxy = (self.root / name
                                                  for name in ('source', 'workspace', 'proxy'))
        for path in (self.source, self.workspace, self.proxy):
            path.mkdir(mode=0o700)
        self.go = Path(sys.executable).resolve(strict=True)
        self.pin = hashlib.sha256(self.go.read_bytes()).hexdigest()
        self.plan = self.enter(mock.patch.object(selected.reproduction, 'plan',
                                               return_value=dict(units=[{} for unused in range(20)])))
        self.source_check = self.enter(mock.patch.object(selected.selected, 'compare_source',
                                                        return_value=dict(combined_files=502)))
        self.free = self.enter(mock.patch.object(selected.shutil, 'disk_usage',
            return_value=SimpleNamespace(free=selected.FLOOR + selected.RESERVATION)))
        self.spawn = self.enter(mock.patch.object(selected.capture, 'run',
                                                  side_effect=AssertionError('fixture attempted native execution')))

    def enter(self, patch):
        result = patch.start()
        self.addCleanup(patch.stop)
        return result

    def invoke(self, **changes):
        arguments = dict(source=self.source, workspace=self.workspace, go=self.go,
                         expected_go=self.pin, proxy=self.proxy, cc=self.go, root=self.root)
        arguments.update(changes)
        return selected.qualify(**arguments)

    def refused_without_allocation(self, **changes):
        with self.assertRaises((ValueError, AssertionError)):
            self.invoke(**changes)
        self.spawn.assert_not_called()
        self.assertFalse(any(self.workspace.iterdir()))

    def test_foreign_source_count_refuses(self):
        self.source_check.return_value = dict(combined_files=501)
        self.refused_without_allocation()

    def test_missing_selected_profile_refuses(self):
        self.plan.return_value = dict(units=[{} for unused in range(19)])
        self.refused_without_allocation()

    def test_foreign_compiler_pin_refuses(self):
        self.refused_without_allocation(expected_go='0' * 64)

    def test_malformed_compiler_pin_refuses(self):
        self.refused_without_allocation(expected_go='not-a-digest')

    def test_free_space_floor_includes_reservation(self):
        self.free.return_value = SimpleNamespace(free=selected.FLOOR + selected.RESERVATION - 1)
        self.refused_without_allocation()

    def test_existing_workspace_is_never_adopted(self):
        original = self.workspace / 'retained.txt'
        original.write_bytes(b'original')
        with self.assertRaises((ValueError, AssertionError)):
            self.invoke()
        self.spawn.assert_not_called()
        self.assertEqual(original.read_bytes(), b'original')
        self.assertEqual({path.name for path in self.workspace.iterdir()}, {'retained.txt'})

    def test_workspace_cannot_use_read_only_proxy_namespace(self):
        self.refused_without_allocation(proxy=self.root)

    def test_attempt_deadline_refuses_before_launch_and_preserves_intent(self):
        with mock.patch.object(selected.time, 'monotonic',
                               side_effect=[0, selected.TOTAL_SECONDS + 1,
                                            selected.TOTAL_SECONDS + 1]):
            with self.assertRaises((ValueError, AssertionError)):
                self.invoke()
        self.spawn.assert_not_called()
        intent = json.loads((self.workspace / 'native-intent.json').read_bytes())
        failure = json.loads((self.workspace / 'native-failure.json').read_bytes())
        self.assertEqual(intent['outcome'], 'UNKNOWN')
        self.assertEqual(failure['outcome'], 'FAILURE_OR_INCOMPLETE_PRESERVED')
        self.assertEqual(failure['commands'], {})
        self.assertFalse(failure['automatic_native_retry'])
        self.assertFalse(any((self.workspace / 'commands').iterdir()))

    def test_environment_does_not_inherit_secret_or_network_proxy(self):
        with mock.patch.dict(os.environ, {'PTLC_SYNTHETIC_SECRET': 'fixture-only',
                                         'HTTPS_PROXY': 'synthetic-unselected'}):
            environment = selected.selected_environment(self.workspace, self.proxy, self.go)
        self.assertNotIn('PTLC_SYNTHETIC_SECRET', environment)
        self.assertNotIn('HTTPS_PROXY', environment)
        self.assertEqual(environment['GOPROXY'], self.proxy.as_uri())
        self.assertEqual(environment['GOTOOLCHAIN'], 'local')
        self.assertEqual(environment['GOFLAGS'], '')
        self.assertEqual(environment['GOVCS'], '*:off')
        self.assertEqual(environment['GOWORK'], 'off')
        self.assertEqual(environment['GOENV'], 'off')

    def test_sdk_environment_uses_only_the_explicit_selection(self):
        sdk = self.root / 'sdk'
        with mock.patch.dict(os.environ, {'SDKROOT': 'synthetic-unselected'}):
            default = selected.selected_environment(self.workspace, self.proxy, self.go)
            explicit = selected.selected_environment(self.workspace, self.proxy, self.go, sdk)
        self.assertNotIn('SDKROOT', default)
        self.assertEqual(explicit['SDKROOT'], str(sdk))
        self.spawn.assert_not_called()

    def test_sdk_refuses_on_non_darwin_before_allocation(self):
        sdk = self.root / 'sdk'
        sdk.mkdir(mode=0o700)
        with mock.patch.object(selected.sys, 'platform', 'linux'):
            self.refused_without_allocation(sdk=sdk)

    def test_sdk_must_be_an_existing_directory(self):
        file = self.root / 'sdk-file'
        file.write_bytes(b'original')
        with mock.patch.object(selected.sys, 'platform', 'darwin'):
            for sdk in (self.root / 'missing-sdk', file):
                with self.subTest(kind=sdk.name):
                    with self.assertRaises((ValueError, AssertionError, OSError)):
                        self.invoke(sdk=sdk)
        self.assertEqual(file.read_bytes(), b'original')
        self.assertFalse(any(self.workspace.iterdir()))
        self.spawn.assert_not_called()

    def test_sdk_cannot_overlap_source_or_writable_workspace(self):
        with mock.patch.object(selected.sys, 'platform', 'darwin'):
            for sdk in (self.root, self.source, self.workspace):
                with self.subTest(kind=sdk.name):
                    self.refused_without_allocation(sdk=sdk)

    def test_sdk_alias_is_not_followed(self):
        sdk = self.root / 'sdk'
        sdk.mkdir(mode=0o700)
        original = sdk / 'retained.txt'
        original.write_bytes(b'original')
        alias = self.root / 'sdk-alias'
        alias.symlink_to(sdk, target_is_directory=True)
        with mock.patch.object(selected.sys, 'platform', 'darwin'):
            self.refused_without_allocation(sdk=alias)
        self.assertEqual(original.read_bytes(), b'original')
        self.spawn.assert_not_called()

    def test_generated_handoff_cannot_replace_an_original(self):
        with mock.patch.object(selected.reproduction, 'input_bindings', return_value={
                'PTLC_NOM_SELECTED': {'generated_json': {'value': 'public-original'}}}):
            selected.bindings('vm-verifier', {}, self.workspace, self.root)
            original = self.workspace / 'vm-verifier-PTLC_NOM_SELECTED.json'
            before = original.read_bytes()
            with self.assertRaises(FileExistsError):
                selected.bindings('vm-verifier', {}, self.workspace, self.root)
        self.assertEqual(original.read_bytes(), before)
        self.spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
