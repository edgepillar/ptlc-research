"""Real CLI and ownership controls in explicitly disposable synthetic repositories.

All original CLI and child streams are emitted before assertions. An unexpected
control failure leaves its fixture for the owning qualification to hold.
"""
import base64
from collections import Counter
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

CONFIG = None
RUNS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def default_config():
    root = Path(__file__).resolve().parents[1]
    names = ('run_offline_ci_profile.py', 'run_offline_shard.py', 'run_offline_shards.py')
    inputs = {}
    for name in names:
        selected = root/'scripts'/name
        raw = selected.read_bytes()
        inputs[name] = dict(path=str(selected), bytes=len(raw), sha256=sha(raw))
    parent = Path(tempfile.gettempdir()).resolve()
    return dict(inputs=inputs, decoder=str(root/'scripts/read_offline_ci_profile.py'),
        resource_guard=lambda: shutil.disk_usage(parent).free < 10*1024**3 + 512*1024**2)


class ProfileDriverControls(unittest.TestCase):
    def setUp(self):
        global CONFIG
        if CONFIG is None:
            CONFIG = default_config()

    @contextmanager
    def workspace(self, behavior='pass', *, output_in_source=False, late_interrupt=False):
        base = Path(tempfile.mkdtemp(prefix='profile-driver-', dir=Path(tempfile.gettempdir()).resolve()))
        root, streams, fixtures = base/'source', base/'streams', base/'fixtures'
        root.mkdir(mode=0o700)
        (root/'scripts').mkdir(mode=0o700)
        (root/'tests').mkdir(mode=0o700)
        fixtures.mkdir(mode=0o700)
        if output_in_source:
            streams = root
        else:
            streams.mkdir(mode=0o700)
        for index in range(4):
            for kind in ('stdout', 'stderr'):
                fd = os.open(streams/(str(index)+'.'+kind), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
                os.close(fd)
        for name, pin in CONFIG['inputs'].items():
            raw = Path(pin['path']).read_bytes()
            self.assertEqual((len(raw), sha(raw)), (pin['bytes'], pin['sha256']))
            (root/'scripts'/name).write_bytes(raw)
        (root/'README.md').write_text('Synthetic offline profile fixture.\n', encoding='ascii')
        bodies = {
            'pass': 'self.assertEqual(2 + 2, 4)',
            'chunked': 'print("SYNTHETIC_TRANSPORT_PADDING=" + "p"*40000, flush=True)',
            'fail': 'self.fail("synthetic expected child failure")',
            'warning': 'warnings.warn("synthetic resource warning", ResourceWarning)',
            'mutate': '(Path(__file__).resolve().parents[1]/"README.md").write_text("changed synthetic source\\n")',
            'sleep': 'print("SYNTHETIC_CHILD_READY", flush=True); time.sleep(4)',
        }
        for index in range(4):
            body = bodies[behavior] if index == 0 else bodies['pass']
            code = ('import unittest, warnings, time\nfrom pathlib import Path\n'
                'class Example(unittest.TestCase):\n'
                '    def test_first(self):\n        '+body+'\n'
                '    def test_second(self):\n        self.assertTrue(True)\n')
            (root/'tests'/('test_profile_fixture_'+str(index)+'.py')).write_text(code, encoding='ascii')
        entry = root/'scripts/run_offline_ci_profile.py'
        if late_interrupt:
            entry = root/'scripts/interrupt_after_children.py'
            entry.write_text('import os, signal, sys\nfrom pathlib import Path\n'
                'sys.path.insert(0, str(Path(__file__).resolve().parents[1]))\n'
                'from scripts import run_offline_ci_profile as profile\n'
                'original = profile.supervisor.supervise\n'
                'def interrupted(*args, **kwargs):\n'
                '    value = original(*args, **kwargs)\n'
                '    os.kill(os.getpid(), signal.SIGTERM)\n'
                '    return value\n'
                'profile.supervisor.supervise = interrupted\n'
                'raise SystemExit(profile.main())\n', encoding='ascii')
        # Isolated Git input uses non-deliverable synthetic metadata.
        environment = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_SYSTEM=os.devnull, GIT_AUTHOR_NAME='Synthetic fixture', GIT_COMMITTER_NAME='Synthetic fixture',
            GIT_AUTHOR_EMAIL='fixture.invalid',
            GIT_COMMITTER_EMAIL='fixture.invalid',
            GIT_AUTHOR_DATE='1600000000 +0000', GIT_COMMITTER_DATE='1600000000 +0000',
            PYTHONDONTWRITEBYTECODE='1', REQUIRE_OPENSSL='1')
        def git(*args):
            child = subprocess.run(['git',*args], cwd=root, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(child.returncode, 0, 'synthetic Git operation failed')
            return child.stdout
        git('-c', 'init.defaultBranch=fixture', 'init', '--quiet', '--template=', '.')
        git('add', '.')
        git('-c', 'commit.gpgsign=false', 'commit', '--quiet', '--no-gpg-sign', '-m', 'Synthetic offline profile fixture')
        head = git('rev-parse', 'HEAD').decode('ascii').strip()
        self.assertEqual(git('log', '-1', '--format=%an <%ae>%n%cn <%ce>').decode().splitlines(),
            ['Synthetic fixture <fixture.invalid>']*2)
        source_names = [n.decode('ascii') for n in git('ls-files', '-z').split(b'\0') if n]
        source_map = {name:sha((root/name).read_bytes()) for name in source_names}
        selected = dict(head=head, tree=git('rev-parse', 'HEAD^{tree}').decode().strip(),
            files=len(source_names), source_bytes=sum((root/name).stat().st_size for name in source_names),
            source_sha256=sha(json.dumps(source_map, sort_keys=True).encode('ascii')))
        value = dict(base=base, root=root, streams=streams, fixtures=fixtures,
            environment=environment, head=head, source=selected, entry=entry)
        try:
            yield value
        except BaseException:
            # Preserve an unexpected control failure; only normal controls own cleanup.
            raise
        else:
            shutil.rmtree(base)

    def record(self, value, child):
        originals = {}
        for index in range(4):
            for kind in ('stdout', 'stderr'):
                path = value['streams']/(str(index)+'.'+kind)
                info = path.lstat()
                if stat.S_ISREG(info.st_mode):
                    raw = path.read_bytes()
                    self.assertLessEqual(len(raw), 4*1024**2)
                    originals[str(index)+'.'+kind] = dict(bytes=len(raw), sha256=sha(raw),
                        data_base64=base64.b64encode(raw).decode('ascii'))
        row = dict(control=self.id(), actual_exit=child.returncode,
            stdout_base64=base64.b64encode(child.stdout).decode('ascii'),
            stderr_base64=base64.b64encode(child.stderr).decode('ascii'), originals=originals,
            synthetic_head=value['head'], synthetic_source=value['source'],
            original_fixtures_retained_by_driver=sorted(p.name for p in value['fixtures'].iterdir()),
            authority='SYNTHETIC_DRIVER_CONTROL_ONLY; NO_HOSTED_OR_PUBLIC_SUITE_ACCEPTANCE')
        RUNS.append(dict(control=self.id(), actual_exit=child.returncode,
            stdout_sha256=sha(child.stdout), stderr_sha256=sha(child.stderr)))
        print('PTLC_PROFILE_DRIVER_RUN='+json.dumps(row, sort_keys=True), flush=True)
        return child

    def execute(self, value, *, expected_head=None, timeout=10, interrupt=False, fixtures=None):
        argv = [sys.executable, '-B', '-W', 'error::ResourceWarning', str(value['entry']),
            '--streams', str(value['streams']), '--fixtures', str(fixtures or value['fixtures']),
            '--expect-head', expected_head or value['head'], '--run-id', '99871', '--attempt', '1',
            '--workers', '4', '--timeout', str(timeout)]
        process = subprocess.Popen(argv, cwd=value['root'], env=value['environment'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if interrupt:
            deadline = time.monotonic()+15
            while not any(b'SYNTHETIC_CHILD_READY' in (value['streams']/(str(i)+'.stdout')).read_bytes()
                    for i in range(4)):
                self.assertIsNone(process.poll(), 'driver exited before the selected interrupt point')
                self.assertLess(time.monotonic(), deadline)
                self.assertFalse(CONFIG['resource_guard'](), 'isolated fixture resource boundary')
                time.sleep(.01)
            process.send_signal(signal.SIGTERM)
        deadline = time.monotonic()+30
        while True:
            try:
                stdout, stderr = process.communicate(timeout=.05)
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline or CONFIG['resource_guard']():
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=5)
                    self.record(value, subprocess.CompletedProcess(argv, process.returncode, stdout, stderr))
                    self.fail('isolated fixture deadline or resource boundary')
        child = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
        self.assertLessEqual(len(child.stdout), 2*1024**2)
        self.assertLessEqual(len(child.stderr), 256*1024)
        return self.record(value, child)

    def result(self, child):
        prefix = b'PTLC_OFFLINE_PROFILE_RESULT='
        rows = [json.loads(line[len(prefix):]) for line in child.stdout.splitlines() if line.startswith(prefix)]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def refused(self, child):
        self.assertEqual(child.returncode, 1)
        self.assertIn(b'PTLC_OFFLINE_PROFILE_REFUSED=', child.stdout)
        self.assertNotIn(b'PTLC_OFFLINE_PROFILE_BEGIN=', child.stdout)

    def test_real_four_children_preserve_every_case_and_original_byte(self):
        decoder = load(CONFIG['decoder'], 'profile_driver_control_decoder')
        with self.workspace() as value:
            child = self.execute(value)
            self.assertEqual(child.returncode, 0)
            report = self.result(child)
            expected_context = dict(head=value['head'], source_sha256=value['source']['source_sha256'],
                run_id=99871, attempt=1, platform=sys.platform,
                python='{}.{}'.format(sys.version_info.major, sys.version_info.minor),
                authority='CALLER_DECLARED_RUN; TRUSTED_LOCAL_SOURCE; EXTERNAL_METADATA_ACCEPTANCE_REQUIRED')
            decoded = decoder.decode(child.stdout, expected_context=expected_context,
                expected_source=value['source'], expected_workers=4, expected_cases=8)
            self.assertEqual(report['outcome'], 'PASS')
            self.assertTrue(report['source_unchanged'])
            self.assertEqual(report['actual_accepted_cases'], 8)
            self.assertEqual(report['supervision']['peak_running'], 4)
            actual = Counter()
            for index in range(4):
                for kind in ('stdout', 'stderr'):
                    raw = (value['streams']/(str(index)+'.'+kind)).read_bytes()
                    self.assertEqual(decoded['streams'][index, kind], raw)
                    if kind == 'stdout':
                        for line in raw.splitlines():
                            if line.startswith(b'PTLC_CASE='):
                                case, status = json.loads(line[len(b'PTLC_CASE='):])
                                self.assertEqual(status, 'ok')
                                actual[case] += 1
                self.assertEqual(report['shard_reports'][str(index)]['plan']['modules'],
                    ['test_profile_fixture_'+str(index)+'.py'])
            expected = Counter({'test_profile_fixture_'+str(i)+'.Example.test_'+name:1
                for i in range(4) for name in ('first', 'second')})
            self.assertEqual(actual, expected)
            self.assertFalse(report['test_result_cache'])
            self.assertEqual(report['application'], 'NO-GO')

    def test_child_assertion_failure_keeps_actual_exit_and_original_failure(self):
        with self.workspace('fail') as value:
            child = self.execute(value)
            self.assertEqual(child.returncode, 1)
            report = self.result(child)
            self.assertEqual(report['outcome'], 'FAILED_OR_UNKNOWN')
            self.assertEqual(report['supervision']['children'][0]['actual_exit'], 1)
            self.assertIn(b'synthetic expected child failure', (value['streams']/'0.stderr').read_bytes())
            self.assertEqual(report['case_acceptance'], 'NOT_ACCEPTED')
            self.assertTrue(report['supervision']['held_fixture_shards'])

    def test_resource_warning_is_an_actual_error_and_never_accepted(self):
        with self.workspace('warning') as value:
            child = self.execute(value)
            self.assertEqual(child.returncode, 1)
            self.assertIn(b'ResourceWarning', (value['streams']/'0.stderr').read_bytes())
            self.assertEqual(self.result(child)['outcome'], 'FAILED_OR_UNKNOWN')

    def test_mutation_after_successful_cases_refuses_source_acceptance(self):
        with self.workspace('mutate') as value:
            child = self.execute(value)
            self.assertEqual(child.returncode, 1)
            report = self.result(child)
            self.assertEqual(report['actual_accepted_cases'], 8)
            self.assertFalse(report['source_unchanged'])
            self.assertIsNone(report['source_after'])
            self.assertEqual(report['outcome'], 'FAILED_OR_UNKNOWN')

    def test_real_timeout_is_not_success(self):
        with self.workspace('sleep') as value:
            child = self.execute(value, timeout=.2)
            self.assertEqual(child.returncode, 1)
            report = self.result(child)
            self.assertEqual(report['supervision']['stop_reason'], 'TIMEOUT')
            self.assertEqual(report['outcome'], 'FAILED_OR_UNKNOWN')

    def test_real_sigterm_preserves_interrupted_children(self):
        with self.workspace('sleep') as value:
            child = self.execute(value, interrupt=True)
            self.assertEqual(child.returncode, 1)
            report = self.result(child)
            self.assertEqual(report['supervision']['stop_reason'], 'INTERRUPTED')
            self.assertEqual(report['outcome'], 'FAILED_OR_UNKNOWN')

    def test_interrupt_after_all_children_succeed_still_refuses_success(self):
        with self.workspace(late_interrupt=True) as value:
            child = self.execute(value)
            self.assertEqual(child.returncode, 1)
            report = self.result(child)
            self.assertEqual(report['supervision']['outcome'], 'PROCESS_EXITS_ZERO')
            self.assertEqual(report['actual_accepted_cases'], 8)
            self.assertEqual(report['outcome'], 'FAILED_OR_UNKNOWN')

    def test_wrong_selected_head_refuses_without_launch_or_stream_write(self):
        with self.workspace() as value:
            child = self.execute(value, expected_head='f'*40)
            self.refused(child)
            self.assertTrue(all(p.stat().st_size == 0 for p in value['streams'].iterdir()))

    def test_dirty_source_is_not_repaired_or_executed(self):
        with self.workspace() as value:
            (value['root']/'README.md').write_text('changed before launch\n', encoding='ascii')
            child = self.execute(value)
            self.refused(child)
            self.assertEqual((value['root']/'README.md').read_text(), 'changed before launch\n')

    def test_nonempty_output_is_not_truncated(self):
        with self.workspace() as value:
            selected = value['streams']/'0.stdout'
            selected.write_bytes(b'synthetic previous bytes')
            identity = selected.stat().st_ino
            self.refused(self.execute(value))
            self.assertEqual(selected.read_bytes(), b'synthetic previous bytes')
            self.assertEqual(selected.stat().st_ino, identity)

    def test_publicly_readable_output_is_not_repaired(self):
        with self.workspace() as value:
            selected = value['streams']/'0.stdout'
            selected.chmod(0o644)
            self.refused(self.execute(value))
            self.assertEqual(stat.S_IMODE(selected.stat().st_mode), 0o644)

    def test_symlink_output_is_not_followed_or_repaired(self):
        with self.workspace() as value:
            selected = value['streams']/'0.stdout'
            selected.unlink()
            selected.symlink_to('1.stdout')
            self.refused(self.execute(value))
            self.assertTrue(selected.is_symlink())
            self.assertEqual((value['streams']/'1.stdout').read_bytes(), b'')

    def test_output_root_equal_to_source_is_refused_before_execution(self):
        with self.workspace(output_in_source=True) as value:
            self.refused(self.execute(value))
            self.assertTrue(all((value['root']/(str(i)+'.'+k)).stat().st_size == 0
                for i in range(4) for k in ('stdout', 'stderr')))

    def test_fixture_root_equal_to_source_is_refused_before_execution(self):
        with self.workspace() as value:
            self.refused(self.execute(value, fixtures=value['root']))
