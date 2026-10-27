"""Retain four original shard streams for one complete offline CI profile.

Fresh source and case checks preserve every selected test. Original streams
remain caller-owned, and no cached result supplies execution evidence.
"""
import argparse
import base64
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys

# The final script is placed in scripts/; anchor imports to that repository.
IMPORT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMPORT_ROOT))

from scripts import run_offline_shard as shard
from scripts import run_offline_shards as supervisor

MAX_STREAM = 4 * 1024**2
MAX_SOURCE = 40 * 1024**2
MAX_BLOB = 8 * 1024**2
CHUNK = 16 * 1024
PREFIX = 'PTLC_OFFLINE_PROFILE_'


class ProfileRefused(ValueError):
    """Sanitized refusal; original caller-owned files are never repaired or removed."""


def require(value):
    if not value: raise ProfileRefused('offline profile refused')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result); result[key] = value
    return result


def document(raw):
    require(type(raw) is bytes and raw.isascii())
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda unused: (_ for _ in ()).throw(ProfileRefused('nonfinite JSON refused')))


def regular(path, maximum, identity=None):
    path = Path(path); supervisor.directory(path.parent)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid())
    require(0 <= before.st_size <= maximum)
    if identity is not None: require((before.st_dev, before.st_ino) == identity)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        opened = os.fstat(fd)
        require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink) ==
            (before.st_dev, before.st_ino, before.st_size, 1))
        with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(maximum + 1)
        after = path.lstat(); final = os.fstat(fd)
        for checked in (after, final):
            require(stat.S_ISREG(checked.st_mode) and checked.st_nlink == 1 and checked.st_uid == os.getuid())
            require((checked.st_dev, checked.st_ino, checked.st_size, checked.st_mtime_ns, stat.S_IMODE(checked.st_mode)) ==
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, stat.S_IMODE(before.st_mode)))
        require(len(raw) == before.st_size and len(raw) <= maximum)
        return raw
    finally: os.close(fd)


def source(root, expected_head):
    root = supervisor.directory(root)
    require(type(expected_head) is str and re.fullmatch('[0-9a-f]{40}', expected_head) is not None)
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_TERMINAL_PROMPT='0', LANG='C', LC_ALL='C')
    def git(*args):
        result = subprocess.run(['git', '--no-lazy-fetch', '--no-replace-objects', *args],
            cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        require(result.returncode == 0 and result.stderr == b'' and len(result.stdout) <= 2 * 1024**2)
        return result.stdout
    require(git('rev-parse', '--show-toplevel').decode('ascii').strip() == str(root))
    require(git('rev-parse', 'HEAD').decode('ascii').strip() == expected_head)
    require(git('status', '--porcelain', '--untracked-files=all') == b'')
    tree = git('rev-parse', 'HEAD^{tree}').decode('ascii').strip()
    require(re.fullmatch('[0-9a-f]{40}', tree) is not None)
    entries = [row for row in git('ls-files', '--stage', '-z').split(b'\0') if row]
    require(0 < len(entries) <= 4096)
    observed, seen, total = {}, set(), 0
    for entry in entries:
        header, raw_name = entry.split(b'\t', 1); mode, blob, stage = header.split()
        name = raw_name.decode('ascii'); parsed = PurePosixPath(name)
        require(stage == b'0' and mode in (b'100644', b'100755') and re.fullmatch(b'[0-9a-f]{40}', blob) is not None)
        require(not parsed.is_absolute() and parsed.as_posix() == name and '\\' not in name and ':' not in name)
        require(all(part not in ('', '.', '..', '.git') for part in parsed.parts))
        require(name.casefold() not in seen); seen.add(name.casefold())
        require(all(32 <= ord(char) < 127 for char in name))
        raw = regular(root / name, MAX_BLOB); total += len(raw); require(total <= MAX_SOURCE)
        require(bool((root / name).lstat().st_mode & 0o111) == (mode == b'100755'))
        git_blob = hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw,
            usedforsecurity=False).hexdigest().encode('ascii')
        require(git_blob == blob)
        observed[name] = sha(raw)
    return dict(head=expected_head, tree=tree, files=len(observed), source_bytes=total,
        source_sha256=sha(json.dumps(observed, sort_keys=True).encode('ascii')))


def accept_streams(stdout, stderr, expected, plan):
    require(type(expected) is Counter and type(plan) is dict and bool(expected))
    require(all(type(name) is str and name.isascii() and type(count) is int and count == 1
        for name, count in expected.items()))
    require(type(stdout) is bytes and 0 < len(stdout) <= MAX_STREAM)
    require(type(stderr) is bytes and 0 < len(stderr) <= MAX_STREAM)
    require(stdout.isascii() and stderr.isascii() and b'ResourceWarning' not in stderr)
    require(stderr.rstrip().endswith(b'OK'))
    actual, reports = Counter(), []
    for line in stdout.splitlines():
        if line.startswith(shard.CASE_PREFIX.encode('ascii')):
            row = document(line[len(shard.CASE_PREFIX):])
            require(type(row) is list and len(row) == 2 and type(row[0]) is str and row[1] == 'ok')
            require(row[0] in expected); actual[row[0]] += 1
        elif line.startswith(shard.RESULT_PREFIX.encode('ascii')):
            reports.append(document(line[len(shard.RESULT_PREFIX):]))
    require(actual == expected and len(reports) == 1)
    report = reports[0]
    require(type(report) is dict and report['schema'] == 'ptlc-offline-module-shard-result-v1')
    require(report['outcome'] == 'PASS')
    require(json.dumps(report['plan'], sort_keys=True, separators=(',', ':')) ==
        json.dumps(plan, sort_keys=True, separators=(',', ':')))
    for name in ('actual_cases', 'finished_cases'):
        require(type(report[name]) is int and report[name] == sum(expected.values()))
    require(type(report['statuses']) is dict and set(report['statuses']) == {'ok'})
    require(type(report['statuses']['ok']) is int and report['statuses']['ok'] == sum(expected.values()))
    require(report['actual_counter_sha256'] == shard.counter_digest(actual))
    require(report['application'] == report['core'] == 'NO-GO' and report['independent_assessment'] == 'UNFILLED')
    return actual, report


def supervision_good(value, workers):
    try:
        require(type(value) is dict and value['schema'] == 'ptlc-offline-shard-supervision-v1')
        require(value['outcome'] == 'PROCESS_EXITS_ZERO')
        require(type(value['workers']) is int and value['workers'] == workers)
        require(type(value['peak_running']) is int and 1 <= value['peak_running'] <= workers)
        require(value['stop_reason'] is None and value['held_fixture_shards'] == [])
        require(type(value['elapsed_seconds']) in (int, float) and math.isfinite(value['elapsed_seconds'])
            and value['elapsed_seconds'] >= 0)
        require(value['case_acceptance'] == 'NOT_PERFORMED; VALIDATE EACH ORIGINAL SHARD STREAM')
        for name in ('test_result_cache', 'verifier_replaced', 'automatic_retry'):
            require(value[name] is False)
        require(value['application'] == value['core'] == 'NO-GO' and value['independent_assessment'] == 'UNFILLED')
        require(type(value['children']) is list and len(value['children']) == 4)
        for i, row in enumerate(value['children']):
            require(type(row) is dict and type(row['shard']) is int and row['shard'] == i)
            require(row['launched'] is True and row['output_complete'] is True)
            require(type(row['actual_exit']) is int and row['actual_exit'] == 0)
            for name in ('stdout', 'stderr'):
                pin = row[name]
                require(type(pin) is dict and set(pin) == {'sha256', 'bytes', 'eof', 'truncated'})
                require(pin['eof'] is True and pin['truncated'] is False)
                require(type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_STREAM)
                require(type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256']) is not None)
        return True
    except (KeyError, TypeError, ValueError, OverflowError): return False


def emit(label, value, stream):
    stream.write(PREFIX + label + '=' + json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')
    stream.flush()


def retain_stream(path, identity, row, kind, shard_index, context, stream):
    raw = regular(path, MAX_STREAM, identity)
    selected = None if row is None else row[kind]
    if selected is not None:
        require(type(selected) is dict and set(selected) == {'sha256', 'bytes', 'eof', 'truncated'})
        require(type(selected['bytes']) is int and selected['bytes'] == len(raw) and selected['sha256'] == sha(raw))
        require(type(selected['eof']) is type(selected['truncated']) is bool)
    base = dict(context=context, shard=shard_index, kind=kind,
        launched=None if row is None else row['launched'],
        actual_exit=None if row is None else row['actual_exit'],
        output_complete=False if row is None else row['output_complete'])
    for offset in range(0, len(raw), CHUNK):
        emit('CHUNK', dict(base, offset=offset,
            data_base64=base64.b64encode(raw[offset:offset + CHUNK]).decode('ascii')), stream)
    pin = dict(sha256=sha(raw), bytes=len(raw))
    emit('STREAM_END', dict(base, **pin, chunks=(len(raw) + CHUNK - 1) // CHUNK), stream)
    return raw, pin


def run(root, streams, fixtures, *, expected_head, run_id, attempt, workers=4, timeout=7200, stream=None):
    stream = sys.stdout if stream is None else stream
    root = supervisor.directory(root)
    require(root == shard.ROOT == supervisor.ROOT)
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0)
    require(type(workers) is int and 1 <= workers <= 4)
    require(sys.dont_write_bytecode and not sys.flags.optimize and sys.implementation.name == 'cpython')
    require(os.environ.get('REQUIRE_OPENSSL') == '1')
    outputs = supervisor.outputs(streams); supervisor.directory(fixtures)
    require(all(root != selected and root not in selected.parents
        for selected in (Path(streams).absolute(), Path(fixtures).absolute())))
    before = source(root, expected_head)
    unused, complete, unused_plan = shard.selection(root, 'all')
    plans = {i: shard.selection(root, str(i))[1:] for i in range(4)}
    require(sum((value[0] for value in plans.values()), Counter()) == complete)
    context = dict(head=before['head'], source_sha256=before['source_sha256'],
        run_id=run_id, attempt=attempt, platform=sys.platform,
        python='{}.{}'.format(sys.version_info.major, sys.version_info.minor),
        authority='CALLER_DECLARED_RUN; TRUSTED_LOCAL_SOURCE; EXTERNAL_METADATA_ACCEPTANCE_REQUIRED')
    emit('BEGIN', dict(context=context, expected_cases=sum(complete.values()), logical_shards=4,
        original_streams=8, workers=workers, source=before), stream)
    stopped = False
    def interrupt(unused_signal, unused_frame):
        nonlocal stopped
        stopped = True
    handlers = {value: signal.signal(value, interrupt) for value in (signal.SIGINT, signal.SIGTERM)}
    result, after, error, known = None, None, None, {}
    try:
        commands = [[sys.executable, '-B', '-W', 'error::ResourceWarning',
            str(root / 'scripts/run_offline_shard.py'), '--shard', str(i)] for i in range(4)]
        try:
            result = supervisor.supervise(commands, streams, fixtures, workers=workers, timeout=timeout,
                stdout_limit=MAX_STREAM, stderr_limit=MAX_STREAM, cancelled=lambda: stopped)
        except Exception as failure: error = type(failure).__name__
        pins, accepted, union = {}, {}, Counter()
        for i in range(4):
            row = None if result is None else result['children'][i]
            if row is not None: require(row['shard'] == i)
            raw = {}
            for kind in ('stdout', 'stderr'):
                try:
                    raw[kind], pin = retain_stream(outputs[i][kind]['path'], outputs[i][kind]['identity'],
                        row, kind, i, context, stream)
                    pins[str(i) + '.' + kind] = pin
                except Exception as failure:
                    error = error or type(failure).__name__
                    emit('STREAM_UNAVAILABLE', dict(context=context, shard=i, kind=kind,
                        disposition='UNKNOWN_OR_REPLACED; NOT_ADOPTED', error_class=type(failure).__name__), stream)
            if row is not None and row['actual_exit'] == 0 and row['output_complete'] is True and len(raw) == 2:
                try:
                    actual, report = accept_streams(raw['stdout'], raw['stderr'], *plans[i])
                    require(not set(union) & set(actual)); union.update(actual); accepted[str(i)] = report
                except Exception as failure: error = error or type(failure).__name__
        try: after = source(root, expected_head)
        except Exception as failure: error = error or type(failure).__name__
        good = bool(not stopped and error is None and supervision_good(result, workers)
            and len(accepted) == 4 and union == complete and before == after)
        report = dict(schema='ptlc-offline-ci-profile-v1', outcome='PASS' if good else 'FAILED_OR_UNKNOWN',
            context=context, source_before=before, source_after=after, source_unchanged=before == after,
            supervision=result, stream_pins=pins, shard_reports=accepted, error_class=error,
            actual_accepted_cases=sum(union.values()), expected_cases=sum(complete.values()),
            actual_counter_sha256=shard.counter_digest(union) if union else None,
            complete_counter_sha256=shard.counter_digest(complete),
            case_acceptance='PASS_FOUR_COMPLETE_ORIGINAL_STREAMS' if good else 'NOT_ACCEPTED',
            test_result_cache=False, verifier_replaced=False, automatic_retry=False,
            fixture_owner='CALLER; UNKNOWN_DATA_PRESERVED', source_tree_copies=0,
            application='NO-GO', core='NO-GO', recovery_action='NONE', independent_assessment='UNFILLED')
        emit('RESULT', report, stream)
        return report
    finally:
        for value, handler in handlers.items(): signal.signal(value, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--streams', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--expect-head', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--attempt', type=int, required=True)
    parser.add_argument('--workers', type=int, choices=(1, 2, 3, 4), default=4)
    parser.add_argument('--timeout', type=float, default=7200)
    args = parser.parse_args()
    try:
        result = run(Path.cwd(), args.streams, args.fixtures, expected_head=args.expect_head,
            run_id=args.run_id, attempt=args.attempt, workers=args.workers, timeout=args.timeout)
        return 0 if result['outcome'] == 'PASS' else 1
    except Exception as failure:
        emit('REFUSED', dict(error_class=type(failure).__name__, outcome='NOT_ACCEPTED',
            originals='CALLER_OWNED; NOT_REPAIRED_OR_REMOVED', application='NO-GO', core='NO-GO'), sys.stdout)
        return 1


if __name__ == '__main__': sys.exit(main())
