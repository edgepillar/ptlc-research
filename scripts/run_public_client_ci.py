"""Run one bounded public-client tier and retain its eight original streams.

Full offline/native qualification is NOT executed by this tier. The caller owns
the workspace, Cargo cache, target and originals; no result cache is consulted.
"""
import argparse
import base64
from collections import Counter
import json
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_offline_ci_profile as profile
from scripts import run_offline_shards as supervisor
from scripts import select_public_client_ci as policy

PREFIX = 'PTLC_PUBLIC_CLIENT_FAST_'
MAX_STREAM = 2 * 1024**2
MAX_WORKSPACE = 512 * 1024**2
AUTHORITY = 'CALLER_DECLARED_RUN; EXTERNAL_METADATA_ACCEPTANCE_REQUIRED'
BUILD_ENV = dict(CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='2',
    CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', RUSTFLAGS='',
    RUSTDOCFLAGS='', RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='')


def require(value):
    if not value:
        raise ValueError('public client tier refused')


def document(raw):
    require(type(raw) is bytes and raw.isascii() and 0 < len(raw) <= 65536)
    return json.loads(raw, object_pairs_hook=profile.pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def owned_directory(path):
    path = supervisor.directory(path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) & 0o077 == 0)
    return path


def source_names(root, filename, minimum):
    raw = (root / filename).read_bytes()
    require(raw.isascii())
    names = re.findall(r'#\[test\]\s+fn ([A-Za-z0-9_]+)\(', raw.decode('ascii'))
    require(len(names) == len(set(names)) and len(names) >= minimum)
    return names


def expected_python_cases(root):
    selected = sorted(path.name for path in (root / 'tests').glob('test_*client*.py'))
    require(selected == ['test_client_agreement.py', 'test_client_presignature.py',
        'test_public_client_ci_scope.py', 'test_reference_client.py'])
    suite = unittest.TestLoader().discover(str(root / 'tests'), pattern='test_*client*.py')
    names = []
    def visit(value):
        if isinstance(value, unittest.TestSuite):
            for item in value:
                visit(item)
        else:
            names.append(value.id())
    visit(suite)
    require(len(names) == len(set(names)) and len(names) >= 30
        and not any('_FailedTest' in name for name in names))
    return sorted(names)


def accept_streams(root, streams):
    """Select actual exact cases from complete originals; no exit-only receipt."""
    require(set(streams) == {(i, kind) for i in range(4) for kind in ('stdout', 'stderr')})
    for raw in streams.values():
        require(type(raw) is bytes and len(raw) <= MAX_STREAM)
    python = streams[0, 'stderr'].decode('ascii')
    require(streams[0, 'stdout'] == b'' and python.rstrip().endswith('OK') and 'ResourceWarning' not in python)
    summaries = re.findall(r'^Ran ([0-9]+) tests? in [0-9.]+s$', python, re.M)
    cases = re.findall(r'^\S+ \(([A-Za-z0-9_.]+)\) [.]{3} ok$', python, re.M)
    require(len(summaries) == 1 and len(cases) == len(set(cases)) == int(summaries[0])
        and len(cases) >= 30)
    require(sorted(cases) == expected_python_cases(root))
    require(all(name.startswith(('test_reference_client.', 'test_client_agreement.',
        'test_client_presignature.', 'test_public_client_ci_scope.')) for name in cases))
    rust = streams[1, 'stdout'].decode('ascii')
    expected = (['tests::' + name for name in source_names(root, 'public_crypto/src/lib.rs', 5)]
        + source_names(root, 'qualification/tests/client_public_crypto_process.rs', 5))
    actual = re.findall(r'^test ([A-Za-z0-9_:]+) [.]{3} ok$', rust, re.M)
    require(len(actual) == len(expected) and Counter(actual) == Counter(expected))
    summaries = re.findall(r'^test result: ok[.] ([0-9]+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9.]+s$', rust, re.M)
    require(len(summaries) >= 2 and sum(map(int, summaries)) == len(expected))
    require(streams[2, 'stdout'] == streams[2, 'stderr'] == b'')
    artifacts = streams[3, 'stdout'].decode('ascii')
    versions = re.fullmatch(r'PASS: checked ([0-9]+) index/worktree file versions for ASCII and disclosure patterns\n', artifacts)
    require(versions is not None and int(versions[1]) > 0 and streams[3, 'stderr'] == b'')
    return dict(python_cases=sorted(cases), python_count=len(cases),
        rust_cases=sorted(expected), rust_count=len(expected), artifact_versions=int(versions[1]))


def emit(label, value):
    print(PREFIX + label + '=' + json.dumps(value, sort_keys=True), flush=True)


def workspace_size(root, identity):
    """Strict size sample; count declared synthetic links without following them."""
    info = root.lstat()
    require((info.st_dev, info.st_ino) == identity and stat.S_ISDIR(info.st_mode))
    total = count = 0
    for current, directories, files in os.walk(root, followlinks=False):
        for name in list(directories) + files:
            path = Path(current) / name
            info = path.lstat()
            require(info.st_uid == os.getuid() and info.st_dev == identity[0])
            count += 1
            if stat.S_ISLNK(info.st_mode):
                require(path.is_relative_to(root / 'fixtures'))
                if name in directories:
                    directories.remove(name)
                total += info.st_size
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
            else:
                require(stat.S_ISDIR(info.st_mode))
            require(count <= 32768 and total <= MAX_WORKSPACE)
    return total


class WorkspaceGuard:
    """Sample at bounded intervals; one second of instability refuses work."""
    def __init__(self, root):
        self.root = root
        self.identity = root.stat().st_dev, root.stat().st_ino
        self.unstable_since = None
        self.next_sample = 0
        self.peak = 0
        self.retries = 0

    def cancelled(self, *, final=False):
        now = time.monotonic()
        if not final and now < self.next_sample:
            return False
        self.next_sample = now + .25
        try:
            total = workspace_size(self.root, self.identity)
            self.peak = max(self.peak, total)
            self.unstable_since = None
            return shutil.disk_usage(self.root).free < 10 * 1024**3 + MAX_WORKSPACE - total
        except FileNotFoundError:
            self.retries += 1
            self.unstable_since = self.unstable_since or now
            return final or now - self.unstable_since >= 1
        except (OSError, ValueError):
            return True


def captured_stream(path, identity):
    try:
        return profile.regular(path, MAX_STREAM, identity)
    except (OSError, ValueError):
        return None


def run(workspace, decision, *, head, run_id, attempt, cargo):
    workspace = owned_directory(workspace)
    require(ROOT not in workspace.parents and workspace not in ROOT.parents)
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0)
    require(type(cargo) is str and cargo and '\0' not in cargo)
    require(type(decision) is dict and decision.get('mode') == policy.FAST)
    actual = policy.select_source(ROOT, event='pull_request', base=decision.get('base'),
        head=head, base_ref='main')
    require(actual == decision and actual['source_complete'] is True)
    before = profile.source(ROOT, head)
    streams = owned_directory(workspace / 'streams')
    fixtures = owned_directory(workspace / 'fixtures')
    checked = supervisor.outputs(streams)
    for variable, name in (('CARGO_HOME', 'cargo-home'), ('CARGO_TARGET_DIR', 'target')):
        require(Path(os.environ.get(variable, '')).absolute() == workspace / name)
    require(os.environ.get('CARGO_NET_OFFLINE') == 'true'
        and os.environ.get('CARGO_TERM_COLOR') == 'never')
    require(all(os.environ.get(name) == value for name, value in BUILD_ENV.items()))
    guard = WorkspaceGuard(workspace)
    require(not guard.cancelled(final=True))
    context = dict(head=head, source_sha256=before['source_sha256'], run_id=run_id,
        attempt=attempt, platform=sys.platform, python=f'{sys.version_info.major}.{sys.version_info.minor}',
        authority=AUTHORITY, build_environment=dict(BUILD_ENV))
    emit('BEGIN', dict(context=context, source=before, scope=decision,
        full_offline_suite='NOT_SELECTED', unrelated_native_jobs='NOT_SELECTED'))
    commands = [
        [sys.executable, '-B', '-W', 'error::ResourceWarning', '-m', 'unittest',
            'discover', '-s', 'tests', '-p', 'test_*client*.py', '-v'],
        [cargo, 'test', '--manifest-path', 'public_crypto/Cargo.toml', '--locked', '--offline'],
        [cargo, 'fmt', '--manifest-path', 'public_crypto/Cargo.toml', '--', '--check'],
        [sys.executable, '-B', 'scripts/check_artifacts_batch.py'],
    ]
    stopped = False
    def interrupt(_signal, _frame):
        nonlocal stopped
        stopped = True
    handlers = {number: signal.signal(number, interrupt) for number in (signal.SIGINT, signal.SIGTERM)}
    supervision = None
    accepted = None
    after = None
    error = None
    originals = {}
    pins = {}
    try:
        try:
            try:
                supervision = supervisor.supervise(commands, streams, fixtures, workers=1, timeout=720,
                    stdout_limit=MAX_STREAM, stderr_limit=MAX_STREAM,
                    cancelled=lambda: stopped or guard.cancelled())
            except (OSError, ValueError, KeyError, TypeError, UnicodeError) as failure:
                error = type(failure).__name__
            for index in range(4):
                child = supervision['children'][index] if supervision is not None else None
                if child is not None:
                    require(child['shard'] == index)
                for kind in ('stdout', 'stderr'):
                    value = checked[index][kind]
                    raw = captured_stream(value['path'], value['identity'])
                    if raw is None:
                        emit('STREAM_UNAVAILABLE', dict(context=context, command=index, kind=kind,
                            disposition='UNKNOWN_OR_REPLACED; NOT_REPAIRED'))
                        error = error or 'OriginalStreamUnavailable'
                        continue
                    pin = dict(bytes=len(raw), sha256=profile.sha(raw))
                    if child is not None and child[kind] is not None and child[kind] != dict(pin, eof=True, truncated=False):
                        error = error or 'OriginalStreamMismatch'
                    originals[index, kind] = raw
                    pins[str(index) + '.' + kind] = pin
                    for offset in range(0, max(1, len(raw)), 16384):
                        emit('STREAM', dict(context=context, command=index, kind=kind,
                            offset=offset, data_base64=base64.b64encode(raw[offset:offset + 16384]).decode('ascii')))
            require(profile.supervision_good(supervision, 1) and not stopped)
            require(not guard.cancelled(final=True) and error is None)
            accepted = accept_streams(ROOT, originals)
            after = profile.source(ROOT, head)
            require(after == before and accepted['artifact_versions'] == 2 * before['files'])
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as failure:
            error = type(failure).__name__
        result = dict(schema='ptlc-public-client-fast-result-v1', context=context,
            outcome='PASS_SELECTED_PUBLIC_CLIENT_SCOPE' if accepted is not None and error is None else 'FAILED_OR_UNKNOWN',
            scope=decision, source_before=before, source_after=after, source_unchanged=before == after,
            supervision=supervision, accepted=accepted, stream_pins=pins, error_class=error,
            full_offline_suite='NOT_EXECUTED', unrelated_native_jobs='NOT_EXECUTED',
            workspace_limit_bytes=MAX_WORKSPACE, enforcement='SAMPLED; NOT AN OS QUOTA',
            sampled_workspace_peak_bytes=guard.peak, transient_sample_retries=guard.retries,
            automatic_retry=False, test_result_cache=False, application='NO-GO', core='NO-GO',
            independent_assessment='UNFILLED')
        emit('RESULT', result)
        return result
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--expect-head', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--attempt', type=int, required=True)
    parser.add_argument('--cargo', required=True)
    args = parser.parse_args()
    require(sys.dont_write_bytecode and not sys.flags.optimize)
    result = run(args.workspace, document(args.scope.read_bytes()), head=args.expect_head,
        run_id=args.run_id, attempt=args.attempt, cargo=args.cargo)
    return 0 if result['outcome'] == 'PASS_SELECTED_PUBLIC_CLIENT_SCOPE' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('public client tier refused; originals remain caller owned')
