"""Supervise four unchanged module shards with bounded local parallelism.

The caller supplies eight empty output files and an owned temporary directory.
Original streams stay separate. Process completion is not case acceptance.
"""
import sys

if sys.flags.optimize:
    raise SystemExit('offline shard supervision requires assertions enabled')

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'PTLC_SUPERVISOR_RESULT='
SHARDS = 4


def require(value):
    if not value:
        raise ValueError('offline shard supervision refused')


def directory(path):
    path = Path(path).absolute()
    require('..' not in path.parts)
    for selected in (*reversed(path.parents), path):
        require(stat.S_ISDIR(selected.lstat().st_mode))
    return path


def outputs(path):
    root = directory(path)
    result = []
    identities = set()
    for shard in range(SHARDS):
        pair = {}
        for kind in ('stdout', 'stderr'):
            selected = root / (str(shard)+'.'+kind)
            info = selected.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0
                and stat.S_IMODE(info.st_mode) & 0o077 == 0)
            identity = info.st_dev, info.st_ino
            require(identity not in identities)
            identities.add(identity)
            pair[kind] = dict(path=selected, identity=identity)
        result.append(pair)
    return result


def supervise(commands, output_root, fixture_root, *, workers=2, timeout=3600,
              stdout_limit=4*1024**2, stderr_limit=4*1024**2, cancelled=None):
    require(type(workers) is int and 1 <= workers <= SHARDS)
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 7200)
    require(all(type(value) is int and 0 < value <= 64*1024**2
        for value in (stdout_limit, stderr_limit)))
    require(type(commands) in (tuple, list) and len(commands) == SHARDS)
    require(all(type(command) in (tuple, list) and 0 < len(command) <= 256
        and all(type(value) is str and value and '\0' not in value for value in command)
        and sum(len(value.encode()) for value in command) <= 32768 for command in commands))
    require(cancelled is None or callable(cancelled))
    commands = tuple(tuple(command) for command in commands)
    selected = outputs(output_root)
    fixture_root = directory(fixture_root)
    roots = [(path, (path.stat().st_dev, path.stat().st_ino))
        for path in (directory(output_root), fixture_root)]
    start = time.monotonic()
    deadline = start+timeout
    stop_at = None
    stop_reason = None
    peak = 0
    next_shard = 0
    children = {}
    streams = []
    temporary = {}
    rows = [dict(shard=index, launched=False, actual_exit=None,
        output_complete=False, stdout=None, stderr=None) for index in range(SHARDS)]
    selector = selectors.DefaultSelector()
    try:
        # Open only the caller's checked empty inodes, without truncation.
        for index, pair in enumerate(selected):
            for kind, value in pair.items():
                fd = os.open(value['path'], os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0))
                streams.append(fd)
                info = os.fstat(fd)
                require((info.st_dev, info.st_ino) == value['identity']
                    and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0)
                value.update(fd=fd, digest=hashlib.sha256(), bytes=0, eof=False,
                    truncated=False, limit=stdout_limit if kind == 'stdout' else stderr_limit)

        def stop(reason):
            nonlocal stop_at, stop_reason
            if stop_at is None:
                stop_at, stop_reason = time.monotonic(), reason
                for process in children.values():
                    if process.poll() is None:
                        signal_child(process, 'terminate')

        while next_shard < SHARDS or children or selector.get_map():
            now = time.monotonic()
            if cancelled is not None and cancelled():
                stop('INTERRUPTED')
            if now >= deadline:
                stop('TIMEOUT')
            if stop_at is not None and now-stop_at >= 2:
                for process in children.values():
                    if process.poll() is None:
                        signal_child(process, 'kill')
            if stop_at is not None and now-stop_at >= 5:
                for key in list(selector.get_map().values()):
                    key.data['truncated'] = True
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                if not children:
                    break
            while stop_at is None and next_shard < SHARDS and len(children) < workers:
                index = next_shard
                next_shard += 1
                scratch = Path(tempfile.mkdtemp(prefix='offline-shard-'+str(index)+'-', dir=fixture_root))
                info = scratch.lstat()
                temporary[index] = (scratch, (info.st_dev, info.st_ino))
                environment = dict(os.environ, TMPDIR=str(scratch), TEMP=str(scratch), TMP=str(scratch))
                try:
                    # Keep the outer supervisor's process group and inheritable
                    # ownership leases. No detached worker or background service.
                    process = subprocess.Popen(commands[index], cwd=ROOT, env=environment,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        close_fds=False)
                except OSError:
                    rows[index]['launch_error'] = 'LAUNCH_FAILED'
                    continue
                children[index] = process
                rows[index]['launched'] = True
                rows[index]['started_seconds'] = time.monotonic()-start
                peak = max(peak, len(children))
                for kind in ('stdout', 'stderr'):
                    selector.register(getattr(process, kind), selectors.EVENT_READ, selected[index][kind])
            for key, unused in selector.select(.05):
                value = key.data
                raw = os.read(key.fileobj.fileno(), 65536)
                if not raw:
                    value['eof'] = True
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                permitted = min(len(raw), value['limit']-value['bytes'])
                data = memoryview(raw)[:permitted]
                while data:
                    written = os.write(value['fd'], data)
                    require(written > 0)
                    value['digest'].update(data[:written])
                    value['bytes'] += written
                    data = data[written:]
                if permitted != len(raw):
                    value['truncated'] = True
                    stop('STREAM_LIMIT')
            for index, process in list(children.items()):
                actual = process.poll()
                if actual is not None:
                    rows[index]['actual_exit'] = actual
                    rows[index]['finished_seconds'] = time.monotonic()-start
                    del children[index]
            if stop_at is not None and not children and not selector.get_map():
                break
        for path, identity in roots:
            current = directory(path).stat()
            require((current.st_dev, current.st_ino) == identity)
        for index, pair in enumerate(selected):
            for kind, value in pair.items():
                os.fsync(value['fd'])
                info = os.fstat(value['fd'])
                current = value['path'].lstat()
                require((info.st_dev, info.st_ino) == value['identity']
                    == (current.st_dev, current.st_ino) and info.st_nlink == 1
                    and current.st_size == info.st_size == value['bytes'])
                rows[index][kind] = dict(sha256=value['digest'].hexdigest(), bytes=value['bytes'],
                    eof=value['eof'], truncated=value['truncated'])
            rows[index]['output_complete'] = bool(rows[index]['launched']
                and rows[index]['actual_exit'] is not None
                and all(value['eof'] and not value['truncated'] for value in pair.values()))
        held = []
        for index, (scratch, identity) in temporary.items():
            info = scratch.lstat()
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity)
            if stop_reason is None and rows[index]['actual_exit'] == 0 and not any(scratch.iterdir()):
                scratch.rmdir()
            else:
                held.append(index)
        good = stop_reason is None and not held and all(row['actual_exit'] == 0
            and row['output_complete'] for row in rows)
        return dict(schema='ptlc-offline-shard-supervision-v1',
            outcome='PROCESS_EXITS_ZERO' if good else 'INCOMPLETE_OR_FAILED',
            workers=workers, peak_running=peak, children=rows, stop_reason=stop_reason,
            held_fixture_shards=held, elapsed_seconds=time.monotonic()-start,
            case_acceptance='NOT_PERFORMED; VALIDATE EACH ORIGINAL SHARD STREAM',
            test_result_cache=False, verifier_replaced=False, automatic_retry=False,
            application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
    finally:
        # Terminate only this supervisor's direct children. Uncertain descendant
        # or fixture ownership remains with the enclosing task manager.
        for process in children.values():
            if process.poll() is None:
                signal_child(process, 'kill')
            process.wait()
        for key in list(selector.get_map().values()):
            key.fileobj.close()
        selector.close()
        for fd in streams:
            os.close(fd)


def signal_child(process, operation):
    try:
        getattr(process, operation)()
    except ProcessLookupError:
        # The owned child may exit between poll and signal. Its actual wait
        # status still has to be collected; this race is not a new success.
        process.poll()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--streams', type=Path, required=True,
        help='Owned directory containing empty 0.stdout/0.stderr through 3.stdout/3.stderr')
    parser.add_argument('--fixtures', type=Path, required=True, help='Explicit owned temporary parent')
    parser.add_argument('--workers', type=int, choices=(1, 2, 3, 4), default=2)
    parser.add_argument('--timeout', type=float, default=3600)
    args = parser.parse_args()
    interrupted = False

    def interrupt(unused_signal, unused_frame):
        nonlocal interrupted
        interrupted = True

    previous = {number:signal.signal(number, interrupt) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        commands = [[sys.executable, '-B', '-W', 'error::ResourceWarning',
            str(ROOT/'scripts/run_offline_shard.py'), '--shard', str(index)] for index in range(SHARDS)]
        result = supervise(commands, args.streams, args.fixtures, workers=args.workers,
            timeout=args.timeout, cancelled=lambda:interrupted)
        print(PREFIX+json.dumps(result, sort_keys=True), flush=True)
        if result['outcome'] != 'PROCESS_EXITS_ZERO':
            raise SystemExit(1)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == '__main__':
    main()
