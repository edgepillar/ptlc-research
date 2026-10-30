"""Conservative scope controls; synthetic repositories grant no runtime trust."""
import base64
from copy import deepcopy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import select_public_client_ci as policy
from scripts import run_public_client_ci as producer
from scripts import read_public_client_ci as reader

ROOT = Path(__file__).resolve().parents[1]
POLICY = (ROOT / policy.POLICY_PATH).read_bytes()
SYNTHETIC_IDENTITY = dict(GIT_AUTHOR_NAME='Synthetic qualification',
    GIT_COMMITTER_NAME='Synthetic qualification', GIT_AUTHOR_EMAIL='fixture' + '@' + 'example.invalid',
    GIT_COMMITTER_EMAIL='fixture' + '@' + 'example.invalid')


def workflow_blocks():
    raw = (ROOT / '.github/workflows/offline-tests.yml').read_text('ascii')
    prefix, body = raw.split('jobs:\n', 1)
    import re
    boundaries = list(re.finditer(r'^  ([a-z0-9_\-]+):\n', body, re.M))
    blocks = {item[1]: body[item.start():(boundaries[i + 1].start()
        if i + 1 < len(boundaries) else len(body))] for i, item in enumerate(boundaries)}
    return prefix, blocks


def bootstrap_code():
    block = workflow_blocks()[1]['ci_scope']
    code = block.split("          python3 -I -B - <<'PY'\n", 1)[1].split('          PY\n', 1)[0]
    return '\n'.join(line[10:] if line.startswith(' ' * 10) else line for line in code.splitlines())


def changed(path='reference_client/plan.py', **values):
    result = dict(path=path, status='M', old_mode='100644', new_mode='100644',
        old_blob='1' * 40, new_blob='2' * 40)
    result.update(values)
    return result


class PublicClientScopePolicyTests(unittest.TestCase):
    def test_only_the_declared_component_and_documents_select_fast(self):
        for path in sorted(policy.PUBLIC_FILES | policy.TOP_DOCUMENTS | {'docs/NEW_READING_MAP.md'}):
            with self.subTest(path=path):
                self.assertEqual(policy.classify([changed(path)])[0], policy.FAST)

    def test_dependency_workflow_shared_codec_and_unknown_paths_require_full(self):
        paths = ['public_crypto/Cargo.toml', 'public_crypto/Cargo.lock', 'qualification/Cargo.toml',
            'qualification/Cargo.lock', '.github/workflows/offline-tests.yml', 'AGENTS.md',
            'qualification/tests/client_public_crypto.rs',
            'qualification/examples/verify_client_presignature.rs',
            policy.POLICY_PATH, 'scripts/run_public_client_ci.py', 'offline_session/nom_wire.py',
            'offline_session/pr138.py', 'reference_client/signer.py', 'tests/test_other.py',
            'docs/unreviewed.py', 'docs/source.json', 'README_QUALIFICATION_HISTORY.md']
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(policy.classify([changed('README.md'), changed(path)])[0], policy.FULL)

    def test_only_new_markdown_reading_material_is_an_eligible_addition(self):
        addition = changed('docs/READING.md')
        addition.update(status='A', old_mode='000000', old_blob='0' * 40)
        self.assertEqual(policy.classify([addition])[0], policy.FAST)
        addition['path'] = 'reference_client/plan.py'
        self.assertEqual(policy.classify([addition])[0], policy.FULL)
        addition['path'] = 'docs/READING.md'
        addition['old_blob'] = '1' * 40
        self.assertEqual(policy.classify([addition])[0], policy.FULL)

    def test_deletions_renames_copies_links_and_mode_changes_require_full(self):
        for field, value in [('status', 'D'), ('status', 'R100'), ('status', 'C100'),
                ('status', 'T'), ('status', 'U'), ('new_mode', '120000'),
                ('new_mode', '100755'), ('old_mode', '120000')]:
            item = changed(); item[field] = value
            with self.subTest(field=field, value=value):
                self.assertEqual(policy.classify([item])[0], policy.FULL)

    def test_unknown_incomplete_duplicate_and_oversized_change_sets_require_full(self):
        for value in (None, (), [], [changed()] * (policy.MAX_CHANGES + 1),
                [changed(), changed()], [dict(changed(), extra='untrusted')]):
            with self.subTest(kind=type(value).__name__):
                self.assertEqual(policy.classify(value)[0], policy.FULL)

    def test_ambiguous_and_nonportable_paths_require_full(self):
        for path in ('/README.md', '../README.md', 'docs//READING.md', 'docs/../README.md',
                'docs/./READING.md', 'docs/hidden\n.md', 'docs/space name.md',
                'docs\\READING.md', 'docs/.hidden.md', 'docs/README\u00e9.md', 'docs/' + 'x' * 241):
            with self.subTest(path=path):
                self.assertEqual(policy.classify([changed(path)])[0], policy.FULL)

    def test_case_collisions_and_unknown_blob_ids_do_not_select_fast(self):
        self.assertEqual(policy.classify([changed('docs/ONE.md'), changed('docs/one.md')])[0], policy.FULL)
        for blob in ('0' * 40, '2' * 39, 'Z' * 40, True, None):
            item = changed(); item['new_blob'] = blob
            with self.subTest(blob=blob):
                self.assertEqual(policy.classify([item])[0], policy.FULL)

    def test_raw_diff_needs_complete_unambiguous_records(self):
        raw = b':100644 100644 ' + b'1' * 40 + b' ' + b'2' * 40 + b' M\0README.md\0'
        self.assertEqual(policy.parse_diff(raw), [changed('README.md')])
        for malformed in (b'', raw[:-1], raw + b'unpaired\0', raw.replace(b' M\0', b' R100\0') + b'other\0',
                raw.replace(b'1' * 40, b'1' * 39), b'x' * (policy.MAX_DIFF + 1)):
            with self.subTest(length=len(malformed)), self.assertRaises(policy.SelectionUnknown):
                policy.parse_diff(malformed)

    def test_main_pushes_and_unsupported_contexts_never_select_fast(self):
        for event in ('push', 'workflow_dispatch', 'pull_request_target', 'unknown'):
            result = policy.select_source(ROOT, event=event, base='1' * 40, head='2' * 40, base_ref='main')
            self.assertEqual(result['mode'], policy.FULL)
            self.assertFalse(result['source_complete'])
        result = policy.select_source(ROOT, event='pull_request', base='1' * 40, head='2' * 40, base_ref='other')
        self.assertEqual(result['mode'], policy.FULL)

    def test_full_native_recipe_remains_exact_after_declared_tier_projection(self):
        prefix, blocks = workflow_blocks()
        selected = {'ci_scope', 'public_client_fast', 'ci_acceptance'}
        self.assertEqual(len(blocks), 12)
        guards = ("    needs: ci_scope\n"
            "    if: ${{ !cancelled() && (needs.ci_scope.result != 'success' || needs.ci_scope.outputs.mode != 'public-client') }}\n")
        original = prefix + 'jobs:\n'
        for name, body in blocks.items():
            if name in selected:
                continue
            self.assertEqual(body.count(guards), 1)
            original += body.replace(guards, '')
        # One separator newline precedes the newly appended acceptance job.
        if original.endswith('\n\n'):
            original = original[:-1]
        self.assertEqual(hashlib.sha256(original.encode('ascii')).hexdigest(),
            'e44d6111c8d4a8e20d9412367bc6ec7e72cbe3c0d0b43179a802d78fe549c37b')
        self.assertIn('if: ${{ always() }}', blocks['ci_acceptance'])
        self.assertIn("'NOT_EXECUTED'", blocks['ci_acceptance'])

    def test_actual_acceptance_script_requires_every_selected_group_and_explicit_skips(self):
        block = workflow_blocks()[1]['ci_acceptance']
        code = block.split("          python3 -B - <<'PYCODE'\n", 1)[1].split('          PYCODE\n', 1)[0]
        code = '\n'.join(line[10:] for line in code.splitlines())
        legacy = {'nom-anchor-sqlite', 'offline-tests', 'adaptor-qualification', 'nom-worker-profile',
            'go-compatibility', 'macho-object-prefix', 'pr138-compatibility', 'nom-wire-core', 'nom-current-core'}
        def execute(values):
            return subprocess.run([sys.executable, '-I', '-B', '-c', code],
                env=dict(os.environ, PTLC_CI_NEEDS=json.dumps(values)), capture_output=True, timeout=10)
        for mode in ('full', 'public-client'):
            selected = {name:dict(result='success' if mode == 'full' else 'skipped') for name in legacy}
            selected.update(ci_scope=dict(result='success', outputs=dict(mode=mode)),
                public_client_fast=dict(result='skipped' if mode == 'full' else 'success'))
            result = execute(selected)
            self.assertEqual(result.returncode, 0)
            value = json.loads(result.stdout.split(b'=', 1)[1])
            self.assertEqual(value['full_runtime_jobs'], 'PASSED_14' if mode == 'full' else 'NOT_EXECUTED')
            failures = [lambda value: value.pop('go-compatibility'),
                lambda value: value['ci_scope'].update(result='failure'),
                lambda value: value['ci_scope']['outputs'].update(mode='unknown'),
                lambda value: value['public_client_fast'].update(result='cancelled'),
                lambda value: value['nom-current-core'].update(result='failure')]
            for mutate in failures:
                value = deepcopy(selected); mutate(value)
                result = execute(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')


class PublicClientScopeGitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='public-client-scope-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'source'
        self.root.mkdir(mode=0o700)
        (self.root / 'scripts').mkdir(mode=0o700)
        (self.root / 'reference_client').mkdir(mode=0o700)
        (self.root / policy.POLICY_PATH).write_bytes(POLICY)
        (self.root / 'README.md').write_text('Synthetic source.\n', encoding='ascii')
        (self.root / 'reference_client/plan.py').write_text('VALUE = 1\n', encoding='ascii')
        self.git('init', '-q')
        self.git('add', '.')
        self.git('commit', '-qm', 'Create a synthetic source fixture')
        self.base = self.git('rev-parse', 'HEAD').strip()

    def git(self, *args):
        environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        environment.update(SYNTHETIC_IDENTITY, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT='0', LANG='C', LC_ALL='C')
        result = subprocess.run(['git', '--no-replace-objects', '-c', 'commit.gpgsign=false',
            *args], cwd=self.root, env=environment,
            capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, 'synthetic Git command failed')
        return result.stdout.decode('ascii')

    def commit(self, path='README.md', raw=b'Changed synthetic source.\n'):
        target = self.root / path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(raw)
        self.git('add', '.')
        self.git('commit', '-qm', 'Change a synthetic source fixture')
        return self.git('rev-parse', 'HEAD').strip()

    def decision(self, head):
        return policy.select_source(self.root, event='pull_request', base=self.base, head=head, base_ref='main')

    def bootstrap(self, head, event='pull_request'):
        parent = Path(self.temporary.name)
        output = parent / 'outputs'
        environment = dict(os.environ, PTLC_SCOPE_EVENT=event, PTLC_SCOPE_BASE=self.base,
            PTLC_SCOPE_HEAD=head, PTLC_SCOPE_BASE_REF='main', RUNNER_TEMP=str(parent),
            GITHUB_OUTPUT=str(output))
        result = subprocess.run([sys.executable, '-I', '-B', '-c', bootstrap_code()],
            cwd=self.root, env=environment, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'')
        rows = [line.split(b'=', 1)[1] for line in result.stdout.splitlines() if line.startswith(b'PTLC_CI_SCOPE=')]
        self.assertEqual(len(rows), 1)
        return json.loads(rows[0])

    def test_actual_complete_source_range_selects_fast_and_binds_changes(self):
        head = self.commit()
        value = self.decision(head)
        self.assertEqual(value['mode'], policy.FAST)
        self.assertTrue(value['source_complete'])
        self.assertEqual(value['head'], head)
        self.assertEqual(value['base'], self.base)
        self.assertEqual(value['policy_sha256'], hashlib.sha256(POLICY).hexdigest())
        self.assertEqual(value['change_count'], 1)

    def test_changed_policy_and_shared_code_force_full(self):
        head = self.commit(policy.POLICY_PATH, POLICY + b'\n# Synthetic policy delta.\n')
        self.assertEqual(self.decision(head)['mode'], policy.FULL)
        self.git('checkout', '-q', self.base)
        head = self.commit('offline_session/nom_wire.py')
        self.assertEqual(self.decision(head)['mode'], policy.FULL)

    def test_dirty_source_wrong_head_and_unknown_base_force_full(self):
        head = self.commit()
        self.assertEqual(self.decision(self.base)['mode'], policy.FULL)
        (self.root / 'untracked.py').write_text('VALUE = 2\n', encoding='ascii')
        self.assertEqual(self.decision(head)['mode'], policy.FULL)
        value = policy.select_source(self.root, event='pull_request', base='9' * 40, head=head, base_ref='main')
        self.assertEqual(value['mode'], policy.FULL)

    def test_a_divergent_base_and_destructive_changes_do_not_select_fast(self):
        head = self.commit()
        self.git('checkout', '-q', self.base)
        other = self.commit(raw=b'Divergent synthetic branch.\n')
        value = policy.select_source(self.root, event='pull_request', base=head, head=other, base_ref='main')
        self.assertEqual(value['mode'], policy.FULL)
        self.git('rm', '-q', 'README.md')
        self.git('commit', '-qm', 'Delete a synthetic document')
        self.assertEqual(self.decision(self.git('rev-parse', 'HEAD').strip())['mode'], policy.FULL)

    def test_git_output_cap_refuses_without_a_partial_success(self):
        self.commit('large.txt', b'x' * 8192)
        with self.assertRaises(policy.SelectionUnknown):
            policy.git(self.root, 'show', 'HEAD:large.txt', limit=128)

    def test_actual_bootstrap_runs_the_trusted_policy_and_push_stays_full(self):
        head = self.commit()
        self.assertEqual(self.bootstrap(head)['mode'], policy.FAST)
        self.assertEqual(self.bootstrap(head, 'push')['mode'], policy.FULL)

    def test_a_modified_head_policy_cannot_choose_its_own_fast_eligibility(self):
        head = self.commit(policy.POLICY_PATH, b'raise SystemExit("untrusted policy must not run")\n')
        result = self.bootstrap(head)
        self.assertEqual(result['mode'], policy.FULL)
        self.assertEqual(result['reason'], 'TRUSTED_BASE_POLICY_NOT_UNCHANGED')

    def test_first_policy_adoption_has_no_trusted_base_policy_and_stays_full(self):
        self.git('rm', '-q', policy.POLICY_PATH)
        self.git('commit', '-qm', 'Create a source baseline without a policy')
        self.base = self.git('rev-parse', 'HEAD').strip()
        head = self.commit(policy.POLICY_PATH, POLICY)
        self.assertEqual(self.bootstrap(head)['mode'], policy.FULL)


class PublicClientOriginalStreamTests(unittest.TestCase):
    """Synthetic decoder controls are never native execution receipts."""

    def setUp(self):
        self.source = dict(head='1' * 40, tree='2' * 40, files=17,
            source_bytes=1000, source_sha256='3' * 64)
        self.context = dict(head=self.source['head'], source_sha256=self.source['source_sha256'],
            run_id=123, attempt=1, platform='linux', python='3.13', authority=producer.AUTHORITY,
            build_environment=dict(producer.BUILD_ENV))
        self.scope = dict(mode=policy.FAST, base='4' * 40, source_complete=True)
        cases = producer.expected_python_cases(ROOT)
        python = ''.join(name.rsplit('.', 1)[-1] + ' (' + name + ') ... ok\n' for name in cases)
        python += '\nRan ' + str(len(cases)) + ' tests in 0.001s\n\nOK\n'
        names = (['tests::' + name for name in producer.source_names(ROOT, 'public_crypto/src/lib.rs', 5)]
            + producer.source_names(ROOT, 'qualification/tests/client_public_crypto_process.rs', 5))
        rust = ''.join('test ' + name + ' ... ok\n' for name in names)
        rust += ('test result: ok. ' + str(len(names))
            + ' passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n'
            + 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n')
        self.streams = {(i, kind): b'' for i in range(4) for kind in ('stdout', 'stderr')}
        self.streams[0, 'stderr'] = python.encode('ascii')
        self.streams[1, 'stdout'] = rust.encode('ascii')
        self.streams[3, 'stdout'] = (b'PASS: checked 34 index/worktree file versions '
            b'for ASCII and disclosure patterns\n')
        self.result = dict(schema='ptlc-public-client-fast-result-v1', context=self.context,
            source_before=self.source, source_after=self.source, source_unchanged=True,
            outcome='PASS_SELECTED_PUBLIC_CLIENT_SCOPE', error_class=None,
            scope=self.scope, automatic_retry=False, test_result_cache=False,
            application='NO-GO', core='NO-GO', independent_assessment='UNFILLED',
            full_offline_suite='NOT_EXECUTED', unrelated_native_jobs='NOT_EXECUTED',
            workspace_limit_bytes=producer.MAX_WORKSPACE, sampled_workspace_peak_bytes=1234,
            transient_sample_retries=0)

    def transport(self):
        pins = {str(i) + '.' + kind: dict(bytes=len(raw), sha256=producer.profile.sha(raw))
            for (i, kind), raw in self.streams.items()}
        children = [dict(shard=i, launched=True, output_complete=True, actual_exit=0,
            **{kind: dict(pins[str(i) + '.' + kind], eof=True, truncated=False)
                for kind in ('stdout', 'stderr')}) for i in range(4)]
        supervision = dict(schema='ptlc-offline-shard-supervision-v1', outcome='PROCESS_EXITS_ZERO',
            workers=1, peak_running=1, stop_reason=None, held_fixture_shards=[], elapsed_seconds=.01,
            case_acceptance='NOT_PERFORMED; VALIDATE EACH ORIGINAL SHARD STREAM',
            test_result_cache=False, verifier_replaced=False, automatic_retry=False,
            application='NO-GO', core='NO-GO', independent_assessment='UNFILLED', children=children)
        result = dict(self.result)
        result.setdefault('stream_pins', pins)
        result.setdefault('supervision', supervision)
        result.setdefault('accepted', producer.accept_streams(ROOT, self.streams))
        rows = [('BEGIN', dict(context=self.context, source=self.source, scope=self.scope,
            full_offline_suite='NOT_SELECTED', unrelated_native_jobs='NOT_SELECTED'))]
        for (i, kind), raw in self.streams.items():
            rows.append(('STREAM', dict(context=self.context, command=i, kind=kind, offset=0,
                data_base64=base64.b64encode(raw).decode('ascii'))))
        rows.append(('RESULT', result))
        return b''.join((producer.PREFIX + name + '=' + json.dumps(value, sort_keys=True)
            + '\n').encode('ascii') for name, value in rows)

    def decode(self, raw):
        with patch.object(policy, 'select_source', return_value=self.scope):
            return reader.decode(raw, root=ROOT, expected_context=self.context, expected_source=self.source)

    def test_complete_synthetic_originals_supply_only_selected_case_acceptance(self):
        value = self.decode(self.transport())
        self.assertEqual(value['outcome'], 'PASS_SELECTED_PUBLIC_CLIENT_ORIGINALS_ONLY')
        self.assertEqual(value['accepted']['rust_count'], 10)
        self.assertEqual(value['full_offline_suite'], 'NOT_EXECUTED')
        self.assertEqual(value['new_native_executions'], 0)

    def test_a_missing_duplicate_or_reordered_original_is_refused(self):
        rows = self.transport().splitlines(keepends=True)
        for raw in (b''.join(rows[:1] + rows[2:]), b''.join(rows[:2] + rows[1:]),
                b''.join(rows[1:] + rows[:1]), b''.join(rows[:-1])):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                self.decode(raw)

    def test_foreign_run_source_or_unavailable_original_is_refused(self):
        raw = self.transport()
        for malformed in (raw.replace(b'"run_id": 123', b'"run_id": 124', 1),
                raw.replace(b'"source_sha256": "' + b'3' * 64,
                    b'"source_sha256": "' + b'4' * 64, 1),
                raw.replace(b'FAST_STREAM=', b'FAST_STREAM_UNAVAILABLE=', 1)):
            with self.subTest(length=len(malformed)), self.assertRaises(ValueError):
                self.decode(malformed)

    def test_exit_truncation_source_or_scope_failure_cannot_become_a_pass(self):
        raw = self.transport()
        original = json.loads(raw.splitlines()[-1].split(b'=', 1)[1])
        changes = [lambda value: value['supervision']['children'][1].update(actual_exit=1),
            lambda value: value['supervision']['children'][0]['stderr'].update(truncated=True),
            lambda value: value.update(source_unchanged=False),
            lambda value: value.update(full_offline_suite='PASS'),
            lambda value: value.update(sampled_workspace_peak_bytes=producer.MAX_WORKSPACE + 1),
            lambda value: value['stream_pins']['1.stdout'].update(sha256='0' * 64),
            lambda value: value.update(automatic_retry=True)]
        for mutate in changes:
            altered = deepcopy(original); mutate(altered)
            rows = raw.splitlines(keepends=True)
            rows[-1] = (producer.PREFIX + 'RESULT=' + json.dumps(altered) + '\n').encode('ascii')
            with self.subTest(change=changes.index(mutate)), self.assertRaises(ValueError):
                self.decode(b''.join(rows))

    def test_an_original_is_checked_even_when_all_hashes_are_self_consistent(self):
        for key, replacement in [((0, 'stderr'), b'Ran 1 test in 0.01s\nOK\n'),
                ((1, 'stdout'), b'test result: ok. 10 passed\n'),
                ((3, 'stdout'), b'PASS: checked 32 index/worktree file versions for ASCII and disclosure patterns\n')]:
            with self.subTest(key=key):
                before = self.streams[key]
                self.streams[key] = replacement
                with self.assertRaises(ValueError):
                    self.decode(self.transport())
                self.streams[key] = before

    def test_skips_duplicate_cases_and_unsolicited_python_output_are_refused(self):
        for key, replacement in [((0, 'stderr'), self.streams[0, 'stderr'].replace(b' ... ok', b' ... skipped', 1)),
                ((0, 'stdout'), b'Unexpected output\n'),
                ((1, 'stdout'), self.streams[1, 'stdout'] + self.streams[1, 'stdout'])]:
            selected = dict(self.streams); selected[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                producer.accept_streams(ROOT, selected)

    def test_strict_json_and_transport_do_not_accept_duplicate_or_nonfinite_values(self):
        for raw in (b'{"mode":1,"mode":2}', b'{"mode":NaN}', b'', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                producer.document(raw)
        raw = self.transport()
        with self.assertRaises(ValueError):
            self.decode(raw.replace(b'"data_base64": "', b'"data_base64": "!', 1))


class PublicClientWorkspaceTests(unittest.TestCase):
    def test_pinned_dependency_readme_link_and_its_target_are_charged(self):
        with tempfile.TemporaryDirectory(prefix='public-client-workspace-') as name:
            root = Path(name)
            alias = root / producer.PINNED_README
            target = alias.parent / producer.PINNED_README_TARGET
            target.parent.mkdir(parents=True)
            target.write_bytes(b'synthetic')
            alias.symlink_to(producer.PINNED_README_TARGET)
            identity = root.stat().st_dev, root.stat().st_ino
            self.assertEqual(producer.workspace_size(root, identity), 9 + alias.lstat().st_size)
            self.assertEqual(os.readlink(alias), producer.PINNED_README_TARGET)

    def test_dependency_readme_alias_requires_the_exact_path_and_target(self):
        for relative, destination in [
                (producer.PINNED_README, '../README.md'),
                (producer.PINNED_README, '/synthetic-outside-readme'),
                (producer.PINNED_README, 'secp256kfun/OTHER.md'),
                (Path(str(producer.PINNED_README).replace('/74d18bb/', '/0000000/')),
                    producer.PINNED_README_TARGET)]:
            with self.subTest(relative=relative, destination=destination), \
                    tempfile.TemporaryDirectory(prefix='public-client-workspace-') as name:
                root = Path(name)
                alias = root / relative
                alias.parent.mkdir(parents=True)
                alias.symlink_to(destination)
                with self.assertRaises(ValueError):
                    producer.workspace_size(root, (root.stat().st_dev, root.stat().st_ino))

    def test_dependency_readme_target_and_parent_cannot_be_links(self):
        for linked_parent in (False, True):
            with self.subTest(linked_parent=linked_parent), \
                    tempfile.TemporaryDirectory(prefix='public-client-workspace-') as name:
                root = Path(name)
                alias = root / producer.PINNED_README
                target = alias.parent / producer.PINNED_README_TARGET
                alias.parent.mkdir(parents=True)
                alias.symlink_to(producer.PINNED_README_TARGET)
                if linked_parent:
                    (root / 'other').mkdir()
                    target.parent.symlink_to(root / 'other', target_is_directory=True)
                else:
                    target.parent.mkdir()
                    (root / 'other').write_bytes(b'synthetic')
                    target.symlink_to(root / 'other')
                with self.assertRaises(ValueError):
                    producer.workspace_size(root, (root.stat().st_dev, root.stat().st_ino))

    def test_declared_synthetic_fixture_links_are_charged_without_following(self):
        with tempfile.TemporaryDirectory(prefix='public-client-workspace-') as name:
            root = Path(name)
            (root / 'fixtures').mkdir(mode=0o700)
            alias = root / 'fixtures' / 'synthetic-alias'
            alias.symlink_to(root, target_is_directory=True)
            identity = root.stat().st_dev, root.stat().st_ino
            self.assertEqual(producer.workspace_size(root, identity), alias.lstat().st_size)

    def test_identity_links_and_nonregular_entries_refuse_a_sample(self):
        with tempfile.TemporaryDirectory(prefix='public-client-workspace-') as name:
            root = Path(name)
            guard = producer.WorkspaceGuard(root)
            self.assertEqual(producer.workspace_size(root, guard.identity), 0)
            (root / 'payload').write_bytes(b'synthetic')
            self.assertEqual(producer.workspace_size(root, guard.identity), 9)
            with self.assertRaises(ValueError):
                producer.workspace_size(root, (guard.identity[0], guard.identity[1] + 1))
            (root / 'alias').symlink_to(root / 'payload')
            with self.assertRaises(ValueError):
                producer.workspace_size(root, guard.identity)

    def test_transient_scans_retry_but_final_or_persistent_uncertainty_refuses(self):
        with tempfile.TemporaryDirectory(prefix='public-client-workspace-') as name:
            guard = producer.WorkspaceGuard(Path(name))
            with patch.object(producer, 'workspace_size', side_effect=FileNotFoundError), \
                    patch.object(producer.time, 'monotonic', side_effect=[1., 1.5, 2.1]):
                self.assertFalse(guard.cancelled())
                self.assertFalse(guard.cancelled())
                self.assertTrue(guard.cancelled())
            self.assertEqual(guard.retries, 3)
            with patch.object(producer, 'workspace_size', side_effect=FileNotFoundError):
                self.assertTrue(guard.cancelled(final=True))

    def test_free_space_floor_and_allowance_are_checked_without_partial_samples(self):
        with tempfile.TemporaryDirectory(prefix='public-client-workspace-') as name:
            guard = producer.WorkspaceGuard(Path(name))
            with patch.object(producer, 'workspace_size', return_value=100), \
                    patch.object(producer.shutil, 'disk_usage') as usage:
                usage.return_value.free = 10 * 1024**3 + producer.MAX_WORKSPACE - 100
                self.assertFalse(guard.cancelled(final=True))
                usage.return_value.free -= 1
                self.assertTrue(guard.cancelled(final=True))
                self.assertEqual(guard.peak, 100)

    def test_a_supervision_exception_still_emits_all_available_originals(self):
        with tempfile.TemporaryDirectory(prefix='public-client-workspace-') as name:
            root = Path(name)
            for directory in ('fixtures', 'streams', 'cargo-home', 'target'):
                (root / directory).mkdir(mode=0o700)
            for index in range(4):
                for kind in ('stdout', 'stderr'):
                    fd = os.open(root / 'streams' / (str(index) + '.' + kind),
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.close(fd)
            scope = dict(mode=policy.FAST, base='2' * 40, source_complete=True)
            source = dict(head='1' * 40, source_sha256='3' * 64, files=17)
            output = io.StringIO()
            with patch.object(policy, 'select_source', return_value=scope), \
                    patch.object(producer.profile, 'source', return_value=source), \
                    patch.object(producer.supervisor, 'supervise', side_effect=ValueError), \
                    patch.dict(os.environ, CARGO_HOME=str(root / 'cargo-home'),
                        CARGO_TARGET_DIR=str(root / 'target'), CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
                        **producer.BUILD_ENV), \
                    redirect_stdout(output):
                result = producer.run(root, scope, head='1' * 40, run_id=123, attempt=1, cargo='synthetic-not-executed')
            self.assertEqual(result['outcome'], 'FAILED_OR_UNKNOWN')
            self.assertIsNone(result['supervision'])
            self.assertIsNone(result['accepted'])
            self.assertEqual(len(result['stream_pins']), 8)
            self.assertEqual(sum(line.startswith(producer.PREFIX + 'STREAM=')
                for line in output.getvalue().splitlines()), 8)


if __name__ == '__main__':
    unittest.main()
