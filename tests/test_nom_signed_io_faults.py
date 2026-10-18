"""Actual fixture fault flows and adverse data controls; no native cryptography."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from scripts import nom_signed_io_faults as actor
from scripts import nom_signed_io_evidence as evidence
from scripts import qualify_nom_signed_io_faults as cli

ROOT = Path(__file__).resolve().parents[1]


class SignedIoFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name); cls.directory.chmod(0o700)
        cls.report = actor.qualify(ROOT, cls.directory)
        cli.retain_manifest(cls.directory, cls.report, None)
        cls.payloads = {name: (cls.directory/name).read_bytes() for name in evidence.original_names()}

    def setUp(self):
        self.temp_case = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_case.cleanup)
        self.case_root = Path(self.temp_case.name); self.case_root.chmod(0o700)

    def row(self, payloads, name):
        return evidence.decode(payloads[name+'/case-result.json'])

    def replace_row(self, payloads, name, row):
        payloads[name+'/case-result.json'] = evidence.canonical(row)

    def refused(self, payloads=None, report=None):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            evidence.inspect(self.payloads if payloads is None else payloads,
                self.report if report is None else report, ROOT)

    def partial_tree(self):
        directory = self.case_root/'partial'; directory.mkdir(mode=0o700)
        selected = directory/'signed-short--before-write'; selected.mkdir(mode=0o700)
        cli.write_original(selected/'journal.log', b'{"interrupted"')
        report = dict(schema='ptlc-nom-signed-io-faults-v1', outcome='FAILED_OR_INCOMPLETE',
            subject_commit=None, error_type='OSError', fixture_case_count='NOT_QUALIFIED',
            application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
        cli.retain_manifest(directory, report, None)
        return directory

    def test_actual_thirty_cases_and_ninety_three_selected_originals(self):
        self.assertEqual(self.report['cases'], 30)
        self.assertEqual(self.report['complete_image_reopens'], 25)
        self.assertEqual(self.report['torn_image_quarantines'], 5)
        self.assertEqual(self.report['explicit_unknown_retry_refusals'], 5)
        self.assertEqual(self.report['recovery_entries_on_reopen'], 0)
        self.assertEqual(len(cli.selected_artifact_names(self.directory, ROOT)), 93)
        self.assertEqual(self.report['native_mathematical_executions'], 0)

    def test_data_reader_never_calls_the_journal_transition(self):
        with patch('offline_session.nom_recovery.NomRecovery._apply', side_effect=AssertionError('writer invoked')):
            result = evidence.inspect(self.payloads, self.report, ROOT)
        self.assertEqual(result['journal_transition_calls'], 0)
        self.assertEqual(result['original_files'], 91)

    def test_torn_original_cannot_be_promoted_by_coherent_summary_changes(self):
        payloads = dict(self.payloads)
        target = 'signed-admitted--partial-write'
        source = 'signed-admitted--post-sync-error'
        payloads[target+'/journal.log'] = payloads[source+'/journal.log']
        row = self.row(payloads, source); row.update(case=target, mode='partial-write')
        self.replace_row(payloads, target, row)
        self.refused(payloads)

    def test_recovered_completion_cannot_invent_a_missing_signed_long(self):
        payloads = dict(self.payloads); name = 'signed-long--before-write'
        row = self.row(payloads, name)
        row['status']['signed_originals']['long'] = self.row(payloads, 'signed-long--post-sync-error')['status']['signed_originals']['long']
        self.replace_row(payloads, name, row)
        self.refused(payloads)

    def test_self_consistent_journal_hashes_do_not_replace_the_selected_event(self):
        payloads = dict(self.payloads); name = 'signed-admitted--complete-write-error'
        records = evidence.journal_records(payloads[name+'/journal.log'])
        records[-1]['event']['wire_sha256'] = '00'*32
        unhashed = {key: value for key, value in records[-1].items() if key != 'hash_hex'}
        records[-1]['hash_hex'] = evidence.sha(b'ptlc-nom-log-v1\0'+evidence.canonical(unhashed))
        altered = b''.join(evidence.canonical(value)+b'\n' for value in records)
        payloads[name+'/journal.log'] = altered
        row = self.row(payloads, name); row.update(after_sha256=evidence.sha(altered), after_bytes=len(altered))
        self.replace_row(payloads, name, row)
        self.refused(payloads)

    def test_boolean_reopen_counter_is_not_an_integer_zero(self):
        payloads = dict(self.payloads); name = 'signed-recovered--before-write'
        row = self.row(payloads, name); row['recovery_entries_on_reopen'] = False
        self.replace_row(payloads, name, row)
        self.refused(payloads)

    def test_boolean_report_counter_and_unknown_retry_promotion_refuse(self):
        report = copy.deepcopy(self.report); report['native_mathematical_executions'] = False
        self.refused(report=report)
        payloads = dict(self.payloads); name = 'signed-admitted--file-sync-error'
        row = self.row(payloads, name); row['explicit_unknown_retry_refused'] = False
        self.replace_row(payloads, name, row)
        self.refused(payloads)

    def test_duplicate_json_keys_refuse_without_normalization(self):
        payloads = dict(self.payloads); name = 'signed-short--before-write/case-result.json'
        payloads[name] = b'{"case":"discarded",'+payloads[name][1:]
        self.refused(payloads)

    def test_missing_and_extra_originals_are_not_selected_evidence(self):
        payloads = dict(self.payloads); payloads.pop('signed-attempt--zero-write/journal.log')
        self.refused(payloads)
        payloads = dict(self.payloads); payloads['unselected.txt'] = b'public fixture'
        self.refused(payloads)

    def test_reflected_source_hash_cannot_replace_selected_source(self):
        payloads = dict(self.payloads)
        selected = evidence.decode(payloads['source-selection.json'])
        selected['input_sha256']['offline_session/nom_signed_recovery.py'] = '00'*32
        payloads['source-selection.json'] = evidence.canonical(selected)
        self.refused(payloads)

    def test_failed_run_keeps_exact_partial_bytes_and_only_retention_permission(self):
        directory = self.case_root/'failed'; directory.mkdir(mode=0o700)
        def interrupted(root, output, subject):
            selected = output/'signed-short--before-write'; selected.mkdir(mode=0o700)
            cli.write_original(selected/'journal.log', b'{"interrupted"')
            raise OSError('synthetic unshareable diagnostic')
        out, err = io.StringIO(), io.StringIO()
        with patch.object(actor, 'qualify', side_effect=interrupted), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(['--evidence', str(directory)])
        self.assertEqual(code, 1); self.assertEqual(err.getvalue(), '')
        report = json.loads(out.getvalue())
        self.assertEqual(report['outcome'], 'FAILED_OR_INCOMPLETE')
        self.assertNotIn('synthetic unshareable diagnostic', out.getvalue())
        self.assertEqual((directory/'signed-short--before-write/journal.log').read_bytes(), b'{"interrupted"')
        with self.assertRaises(ValueError): cli.selected_artifact_names(directory, ROOT)
        self.assertEqual(len(cli.selected_artifact_names(directory, ROOT, allow_incomplete=True)), 3)

    def test_selector_retains_partial_original_without_reconstruction(self):
        directory = self.partial_tree()
        original = (directory/'signed-short--before-write/journal.log').read_bytes()
        with self.assertRaises(ValueError): cli.selected_artifact_names(directory, ROOT)
        selected = cli.selected_artifact_names(directory, ROOT, allow_incomplete=True)
        self.assertEqual(set(selected), {'signed-short--before-write/journal.log', 'qualification-result.json', 'retention-manifest.json'})
        self.assertEqual((directory/'signed-short--before-write/journal.log').read_bytes(), original)

    def test_synthetic_unsafe_file_metadata_refuses_before_payload_read(self):
        directory = self.partial_tree(); target = directory/'signed-short--before-write/journal.log'
        original = Path.lstat
        actual = original(target)
        for edit in (dict(st_nlink=2), dict(st_mode=stat.S_IFLNK|0o600), dict(st_uid=actual.st_uid+1),
                     dict(st_mode=stat.S_IFREG|0o644), dict(st_size=evidence.MAX_FILE+1)):
            values = {key: getattr(actual, key) for key in ('st_mode','st_nlink','st_uid','st_size','st_dev','st_ino','st_mtime_ns')}
            values.update(edit)
            def metadata(path):
                return types.SimpleNamespace(**values) if path == target else original(path)
            with self.subTest(edit=edit), patch.object(Path, 'lstat', metadata), \
                    patch.object(Path, 'read_bytes', side_effect=AssertionError('unsafe payload read')):
                with self.assertRaises(ValueError): cli.read_original(directory, 'signed-short--before-write/journal.log')

    def test_selector_refuses_boolean_lengths_and_forged_completeness(self):
        directory = self.partial_tree(); path = directory/'retention-manifest.json'
        original = evidence.decode(path.read_bytes())
        changes = []
        changed = copy.deepcopy(original); changed['originals_complete'] = 0; changes.append(changed)
        changed = copy.deepcopy(original); changed['originals_complete'] = True; changes.append(changed)
        changed = copy.deepcopy(original); changed['files']['signed-short--before-write/journal.log']['bytes'] = False; changes.append(changed)
        for changed in changes:
            path.write_bytes(evidence.canonical(changed))
            with self.assertRaises(ValueError): cli.selected_artifact_names(directory, ROOT, allow_incomplete=True)

    def test_nonempty_and_nonprivate_directories_refuse_without_new_evidence(self):
        directory = self.case_root/'nonempty'; directory.mkdir(mode=0o700)
        cli.write_original(directory/'retained.txt', b'public original')
        out, err = io.StringIO(), io.StringIO()
        with patch.object(actor, 'qualify', side_effect=AssertionError('actor entered')), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(['--evidence', str(directory)]), 1)
        self.assertEqual(list(directory.iterdir()), [directory/'retained.txt'])
        private = self.case_root/'wrong-mode'; private.mkdir(mode=0o755); private.chmod(0o755)
        with self.assertRaises(ValueError): cli.private_directory(private, empty=True)

    def test_optimized_entries_refuse_before_selected_input_or_evidence_access(self):
        program = '''
from pathlib import Path
from unittest.mock import patch
from scripts import nom_signed_io_faults as actor
from scripts import qualify_nom_signed_io_faults as cli
with patch.object(cli,'profile_inputs',side_effect=AssertionError('source accessed')), \\
     patch.object(Path,'is_absolute',side_effect=AssertionError('evidence accessed')):
    if cli.main(['--evidence','unselected'])!=1:raise RuntimeError('optimized CLI admitted')
    try:actor.qualify(Path('unselected'),Path('unselected'))
    except ValueError as error:
        if str(error)!='signed I/O fault qualification requires assertions enabled':raise
    else:raise RuntimeError('optimized function admitted')
print('PASS: both optimized entries refused before input or evidence access')
'''
        result = subprocess.run([sys.executable, '-B', '-O', '-c', program], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'PASS: both optimized entries refused before input or evidence access\n')
        self.assertEqual(result.stderr, b'FAIL: signed I/O fault qualification requires assertions enabled\n')

    def test_predecessor_commit_cannot_claim_new_profile_source(self):
        with self.assertRaises(ValueError): cli.verify_subject(evidence.BASE, ROOT)

    def test_workflow_fetches_subject_missing_from_shallow_merge_checkout(self):
        origin = self.case_root/'origin'; origin.mkdir(mode=0o700)
        environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
            GIT_AUTHOR_NAME='PTLC Research Contributors', GIT_AUTHOR_EMAIL='fixture.invalid',
            GIT_COMMITTER_NAME='PTLC Research Contributors', GIT_COMMITTER_EMAIL='fixture.invalid',
            GIT_AUTHOR_DATE='2000-01-01T00:00:00+00:00', GIT_COMMITTER_DATE='2000-01-01T00:00:00+00:00',
            GIT_ALLOW_PROTOCOL='file', GIT_TERMINAL_PROMPT='0')
        def git(directory, *arguments):
            result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                *arguments], cwd=directory, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))
            return result.stdout.decode('ascii').strip()
        git(origin, 'init', '-q')
        names = list(evidence.profile_inputs(ROOT)) + [evidence.MANIFEST]
        originals = {name: (ROOT/name).read_bytes() for name in names}
        for name, raw in originals.items():
            path = origin/name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(raw)
        git(origin, 'add', '--all')
        git(origin, 'commit', '-q', '-m', 'Synthetic base')
        base = git(origin, 'rev-parse', 'HEAD')
        git(origin, 'commit', '-q', '--allow-empty', '-m', 'Synthetic selected subject')
        subject = git(origin, 'rev-parse', 'HEAD')
        merge = git(origin, 'commit-tree', git(origin, 'rev-parse', 'HEAD^{tree}'),
            '-p', base, '-p', subject, '-m', 'Synthetic shallow merge')
        git(origin, 'update-ref', 'refs/heads/selected-merge', merge)
        shallow = self.case_root/'shallow'; shallow.mkdir(mode=0o700)
        git(shallow, 'init', '-q')
        git(shallow, 'remote', 'add', 'origin', origin.as_uri())
        git(shallow, 'fetch', '--no-tags', '--depth=1', 'origin', merge)
        git(shallow, 'checkout', '-q', '--detach', 'FETCH_HEAD')
        self.assertEqual(git(shallow, 'rev-parse', '--is-shallow-repository'), 'true')
        with self.assertRaises(ValueError): cli.verify_subject(subject, shallow)
        workflow = (ROOT/'.github/workflows/offline-tests.yml').read_text('ascii')
        block = workflow.split('      - name: Qualify fixture-only signed-wire I/O fault boundaries\n', 1)[1]
        block = block.split('\n      - name:', 1)[0]
        fetches = [line.strip() for line in block.splitlines() if line.lstrip().startswith('git fetch ')]
        self.assertEqual(len(fetches), 1)
        selected = "'${{ github.event.pull_request.head.sha || github.sha }}'"
        self.assertEqual(fetches[0].count(selected), 1)
        result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c',
            fetches[0].replace(selected, subject)], cwd=shallow, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))
        cli.verify_subject(subject, shallow)
        self.assertEqual({name: (shallow/name).read_bytes() for name in names}, originals)

    def test_changed_selected_source_refuses_before_fixture_import_or_evidence_creation(self):
        root = self.case_root/'source'; root.mkdir(mode=0o700)
        names = list(evidence.profile_inputs(ROOT)) + [evidence.MANIFEST]
        for name in names:
            path = root/name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes((ROOT/name).read_bytes())
        (root/'offline_session/nom_signed_recovery.py').write_bytes(b'changed public source')
        output = self.case_root/'empty'; output.mkdir(mode=0o700)
        with patch('importlib.util.spec_from_file_location', side_effect=AssertionError('fixture imported')):
            with self.assertRaises(ValueError): actor.qualify(root, output)
        self.assertEqual(list(output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
