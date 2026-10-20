"""Real bounded child streams, overlap and failure preservation controls."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_offline_shards as supervisor


class ShardSupervisorControls(unittest.TestCase):
    @contextmanager
    def workspace(self):
        # Select a physical parent for these new, synthetic, disposable fixtures.
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            root = Path(name)
            streams, fixtures = root/'streams', root/'fixtures'
            streams.mkdir(mode=0o700)
            fixtures.mkdir(mode=0o700)
            for index in range(4):
                for kind in ('stdout', 'stderr'):
                    fd = os.open(streams/(str(index)+'.'+kind), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
                    os.close(fd)
            yield streams, fixtures

    def commands(self, source='print("synthetic")'):
        return [[sys.executable, '-B', '-c', source] for unused in range(4)]

    def execute(self, streams, fixtures, commands=None, **options):
        return supervisor.supervise(self.commands() if commands is None else commands,
            streams, fixtures, timeout=10, **options)

    def test_original_non_utf8_stream_bytes_are_retained_separately(self):
        code = 'import os;os.write(1,bytes([0,255,10]));os.write(2,bytes([128,0]))'
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures, self.commands(code))
            self.assertEqual(report['outcome'], 'PROCESS_EXITS_ZERO')
            for row in report['children']:
                for kind, expected in (('stdout', bytes([0,255,10])), ('stderr', bytes([128,0]))):
                    self.assertEqual((streams/(str(row['shard'])+'.'+kind)).read_bytes(), expected)
                    self.assertEqual(row[kind]['sha256'], hashlib.sha256(expected).hexdigest())
                    self.assertTrue(row[kind]['eof'])
                self.assertTrue(row['output_complete'])
            self.assertEqual(list(fixtures.iterdir()), [])

    def test_real_children_overlap_without_exceeding_two_slots(self):
        code = ('import os,sys,time;from pathlib import Path;'
            'root=Path(os.environ["TMPDIR"]).parent;'
            '(root/("ready-"+sys.argv[1])).touch();'
            'deadline=time.monotonic()+5\n'
            'while not all((root/("ready-"+str(i))).exists() for i in (0,1)):\n'
            ' assert time.monotonic()<deadline\n'
            ' time.sleep(.005)\n')
        commands = [[sys.executable, '-B', '-c', code, str(index)] for index in range(4)]
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures, commands, workers=2)
            self.assertEqual(report['outcome'], 'PROCESS_EXITS_ZERO')
            self.assertEqual(report['peak_running'], 2)
            rows = report['children']
            self.assertLess(rows[1]['started_seconds'], rows[0]['finished_seconds'])
            self.assertGreaterEqual(rows[2]['started_seconds'],
                min(rows[0]['finished_seconds'], rows[1]['finished_seconds']))

    def test_single_slot_keeps_queued_children_sequential(self):
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures, workers=1)
            self.assertEqual(report['peak_running'], 1)
            for previous, current in zip(report['children'], report['children'][1:]):
                self.assertGreaterEqual(current['started_seconds'], previous['finished_seconds'])

    def test_four_slots_do_not_create_an_extra_child(self):
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures, self.commands('import time;time.sleep(.05)'), workers=4)
            self.assertEqual(len(report['children']), 4)
            self.assertLessEqual(report['peak_running'], 4)
            self.assertTrue(all(row['launched'] for row in report['children']))

    def test_child_failure_preserves_other_actual_exits_and_originals(self):
        commands = self.commands()
        commands[1] = self.commands('import sys;print("retained failure");sys.exit(7)')[0]
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures, commands)
            self.assertEqual(report['outcome'], 'INCOMPLETE_OR_FAILED')
            self.assertEqual([row['actual_exit'] for row in report['children']], [0,7,0,0])
            self.assertTrue(all(row['output_complete'] for row in report['children']))
            self.assertEqual((streams/'1.stdout').read_bytes(), b'retained failure\n')
            self.assertEqual(report['held_fixture_shards'], [1])
            self.assertTrue(any(fixtures.iterdir()))
            self.assertIs(report['automatic_retry'], False)

    def test_stdout_limit_stops_owned_children_and_retains_the_exact_prefix(self):
        with self.workspace() as (streams, fixtures):
            code = 'import os,time;os.write(1,b"a"*131072);time.sleep(10)'
            report = self.execute(streams, fixtures, self.commands(code), stdout_limit=4096)
            self.assertEqual(report['stop_reason'], 'STREAM_LIMIT')
            self.assertEqual(report['outcome'], 'INCOMPLETE_OR_FAILED')
            limited = [row for row in report['children'] if row['stdout']['truncated']]
            self.assertTrue(limited)
            for row in limited:
                self.assertEqual(row['stdout']['bytes'], 4096)
                self.assertEqual((streams/(str(row['shard'])+'.stdout')).read_bytes(), b'a'*4096)
                self.assertFalse(row['output_complete'])

    def test_stderr_has_its_own_independent_limit(self):
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures,
                self.commands('import os;os.write(2,b"e"*131072)'), stderr_limit=2048)
            self.assertEqual(report['stop_reason'], 'STREAM_LIMIT')
            self.assertTrue(any(row['stderr']['truncated'] and row['stderr']['bytes'] == 2048
                for row in report['children']))

    def test_both_pipe_streams_drain_without_a_full_pipe_deadlock(self):
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures, self.commands(
                'import os;os.write(1,b"a"*262144);os.write(2,b"b"*262144)'))
            self.assertEqual(report['outcome'], 'PROCESS_EXITS_ZERO')
            self.assertTrue(all(row['stdout']['bytes'] == row['stderr']['bytes'] == 262144
                for row in report['children']))

    def test_timeout_cannot_supply_success_or_start_the_queued_shards(self):
        with self.workspace() as (streams, fixtures):
            report = supervisor.supervise(self.commands('import time;time.sleep(10)'),
                streams, fixtures, workers=1, timeout=.2)
            self.assertEqual(report['stop_reason'], 'TIMEOUT')
            self.assertEqual(report['outcome'], 'INCOMPLETE_OR_FAILED')
            self.assertIsNotNone(report['children'][0]['actual_exit'])
            self.assertTrue(all(not row['launched'] and row['actual_exit'] is None
                for row in report['children'][1:]))

    def test_cancellation_before_launch_is_not_zero_exit_evidence(self):
        with self.workspace() as (streams, fixtures):
            with patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected launch')):
                report = self.execute(streams, fixtures, cancelled=lambda:True)
            self.assertEqual(report['stop_reason'], 'INTERRUPTED')
            self.assertTrue(all(row['actual_exit'] is None for row in report['children']))
            self.assertEqual(report['outcome'], 'INCOMPLETE_OR_FAILED')

    def test_exit_during_timeout_signal_still_retains_the_actual_wait_status(self):
        original = subprocess.Popen

        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            terminate = child.terminate

            def exited():
                terminate()
                raise ProcessLookupError('synthetic exit between poll and signal')

            child.terminate = exited
            return child

        with self.workspace() as (streams, fixtures):
            with patch.object(subprocess, 'Popen', side_effect=spawn):
                report = supervisor.supervise(self.commands('import time;time.sleep(10)'),
                    streams, fixtures, workers=1, timeout=.2)
            self.assertEqual(report['stop_reason'], 'TIMEOUT')
            self.assertEqual(report['outcome'], 'INCOMPLETE_OR_FAILED')
            self.assertIsNotNone(report['children'][0]['actual_exit'])

    def test_launch_refusal_is_distinct_from_an_actual_command_exit(self):
        with self.workspace() as (streams, fixtures):
            with patch.object(subprocess, 'Popen', side_effect=OSError('synthetic launch failure')):
                report = self.execute(streams, fixtures)
            self.assertEqual(report['outcome'], 'INCOMPLETE_OR_FAILED')
            self.assertTrue(all(not row['launched'] and row['actual_exit'] is None
                and row['launch_error'] == 'LAUNCH_FAILED' for row in report['children']))

    def test_each_child_uses_a_distinct_empty_fixture_directory(self):
        code = 'import os;print(os.environ["TMPDIR"]);assert not os.listdir(os.environ["TMPDIR"])'
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures, self.commands(code))
            paths = [(streams/(str(index)+'.stdout')).read_text().strip() for index in range(4)]
            self.assertEqual(len(set(paths)), 4)
            self.assertTrue(all(Path(name).parent == fixtures for name in paths))
            self.assertEqual(report['held_fixture_shards'], [])
            self.assertEqual(list(fixtures.iterdir()), [])

    def test_unexpected_fixture_contents_are_held_without_recursive_cleanup(self):
        code = 'import os;from pathlib import Path;Path(os.environ["TMPDIR"],"retained").write_bytes(b"held")'
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures, self.commands(code))
            self.assertEqual(report['outcome'], 'INCOMPLETE_OR_FAILED')
            self.assertEqual(report['held_fixture_shards'], [0,1,2,3])
            self.assertEqual([path.read_bytes() for path in fixtures.glob('*/retained')], [b'held']*4)

    def test_nonempty_output_refuses_before_any_launch_or_truncation(self):
        with self.workspace() as (streams, fixtures):
            (streams/'0.stdout').write_bytes(b'previous original')
            with patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected launch')):
                with self.assertRaises(ValueError):
                    self.execute(streams, fixtures)
            self.assertEqual((streams/'0.stdout').read_bytes(), b'previous original')

    def test_symlink_output_refuses_without_modifying_the_target(self):
        with self.workspace() as (streams, fixtures):
            (streams/'0.stdout').unlink()
            (streams/'0.stdout').symlink_to(streams/'1.stdout')
            with patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected launch')):
                with self.assertRaises(ValueError):
                    self.execute(streams, fixtures)
            self.assertEqual((streams/'1.stdout').read_bytes(), b'')

    def test_publicly_readable_stream_file_refuses_before_launch(self):
        with self.workspace() as (streams, fixtures):
            (streams/'0.stdout').chmod(0o644)
            with patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected launch')):
                with self.assertRaises(ValueError):
                    self.execute(streams, fixtures)

    def test_symlink_directory_ancestor_refuses_before_launch(self):
        with self.workspace() as (streams, fixtures):
            alias = streams.parent/'stream-alias'
            alias.symlink_to(streams, target_is_directory=True)
            with patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected launch')):
                with self.assertRaises(ValueError):
                    self.execute(alias, fixtures)
            self.assertEqual((streams/'0.stdout').read_bytes(), b'')

    def test_invalid_limits_refuse_before_output_access_or_launch(self):
        options = [dict(workers=value) for value in (True,0,5)]
        options += [dict(timeout=value) for value in (True,0,float('inf'),float('nan'))]
        options += [dict(stdout_limit=value) for value in (True,0,64*1024**2+1)]
        for values in options:
            with self.subTest(values=values):
                with patch.object(supervisor, 'outputs', side_effect=AssertionError('unexpected output access')):
                    with self.assertRaises(ValueError):
                        supervisor.supervise(self.commands(), 'unselected-streams', 'unselected-fixtures', **values)

    def test_process_success_never_claims_test_case_acceptance(self):
        with self.workspace() as (streams, fixtures):
            report = self.execute(streams, fixtures, self.commands('pass'))
            self.assertEqual(report['outcome'], 'PROCESS_EXITS_ZERO')
            self.assertTrue(report['case_acceptance'].startswith('NOT_PERFORMED'))
            self.assertFalse(report['test_result_cache'])
            self.assertFalse(report['verifier_replaced'])

    def test_optimized_cli_refuses_before_opening_any_workspace(self):
        result = subprocess.run([sys.executable, '-B', '-O', 'scripts/run_offline_shards.py'],
            cwd=supervisor.ROOT, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'offline shard supervision requires assertions enabled', result.stderr)
        self.assertNotIn(b'ImportError', result.stderr)
