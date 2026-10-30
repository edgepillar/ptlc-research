"""Capture one selected offline 821bdd2 command without publishing diagnostics.

The caller owns a new workspace, a trusted compiler and the complete selected
environment. This is bounded qualification transport, not a process sandbox or
an execution-origin attestation. Escaped descendants are not contained.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import subprocess
import time

from offline_session.public_worker import WorkerError, _cleanup, _close


LABELS = frozenset((
    'go-version', 'cold-build', 'module-verify', 'upstream-definition',
    'upstream-per-entity', 'upstream-final-tally',
    'pr138-corpus', 'wire-corpus', 'vm-path', 'vm-verifier',
    'account-authorization', 'account-context', 'bilateral-graph',
    'supervisor-plasma', 'account-pool', 'pool-forks', 'pool-dependencies',
    'momentum-admission', 'batched-rollback', 'content-cap', 'multi-rollback',
    'rollback-refusal', 'receive-data', 'abi-boundary', 'send-caller',
    'keyless-supervisor', 'reclaim-current', 'runtime-manager-guards', 'runtime-node-stop', 'runtime-spork-tombstone', 'runtime-decode-limits', 'runtime-manager-close', 'runtime-cache-close', 'runtime-request-budget', 'argument-pricing', 'runtime-embedded-pricing', 'runtime-quote-snapshot', 'upstream-guardians', 'upstream-reward-bounds', 'upstream-bridge-json', 'fee-original-boundary', 'fee-module-verify',
))
MAX_STDOUT = 16 * 1024**2
MAX_STDERR = 4 * 1024**2


def private_create(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                            | os.O_NOFOLLOW, 0o600), 'wb')


def run(command, *, environment, directory, evidence, label, timeout):
    """Run once, preserving original bounded streams and an honest receipt.

    A nonzero exit, timeout, truncation or interruption never counts as a pass.
    A caller must inspect a failed receipt rather than launch a replacement.
    Exact arguments and all original output stay in the private evidence area.
    """
    if (type(command) is not list or not command or len(command) > 32
            or any(type(item) is not str or not item or len(item) > 8192
                   or '\0' in item for item in command)
            or not Path(command[0]).is_absolute()
            or type(environment) is not dict
            or any(type(k) is not str or type(v) is not str or not k
                   or '=' in k or '\0' in k or '\0' in v
                   for k, v in environment.items())
            or type(label) is not str or label not in LABELS
            or type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 < timeout <= 1200):
        raise WorkerError('invalid selected 821bdd2 command')
    evidence = Path(evidence)
    paths = {name: evidence / (label + '.' + name)
             for name in ('stdout', 'stderr', 'receipt.json')}
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise WorkerError('selected 821bdd2 command already has evidence')
    process = selection = None
    started = time.monotonic()
    record = dict(schema='ptlc-nom-821bdd2-native-command-v1', label=label,
        argv=command, result='UNKNOWN', actual_exit=None, cleanup_complete=None,
        process_group=None,
        bytes={'stdout': 0, 'stderr': 0},
        complete={'stdout': False, 'stderr': False}, automatic_retry=False)
    hashes = {name: hashlib.sha256() for name in ('stdout', 'stderr')}
    try:
        with private_create(paths['stdout']) as output, private_create(paths['stderr']) as error:
            try:
                process = subprocess.Popen(command, cwd=directory, env=environment,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
                    bufsize=0)
                # This stays in the private original receipt for owned-workspace
                # liveness checks. Public retention does not export process IDs.
                record['process_group'] = process.pid
                selection = selectors.DefaultSelector()
                for stream, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
                    os.set_blocking(stream.fileno(), False)
                    selection.register(stream, selectors.EVENT_READ, name)
                while selection.get_map():
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        record['failure'] = 'DEADLINE_EXCEEDED'
                        raise WorkerError('selected 821bdd2 deadline exceeded')
                    for key, unused in selection.select(remaining):
                        name = key.data
                        try:
                            chunk = key.fileobj.read(65536)
                        except BlockingIOError:
                            continue
                        if chunk is None:
                            continue
                        if not chunk:
                            record['complete'][name] = True
                            selection.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        bound = MAX_STDOUT if name == 'stdout' else MAX_STDERR
                        accepted = chunk[:bound-record['bytes'][name]]
                        (output if name == 'stdout' else error).write(accepted)
                        hashes[name].update(accepted)
                        record['bytes'][name] += len(accepted)
                        if len(accepted) != len(chunk):
                            record['failure'] = 'STREAM_LIMIT_EXCEEDED'
                            record['truncated_stream'] = name
                            raise WorkerError('selected 821bdd2 stream limit exceeded')
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    record['failure'] = 'DEADLINE_EXCEEDED'
                    raise WorkerError('selected 821bdd2 deadline exceeded')
                try:
                    record['actual_exit'] = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    record['failure'] = 'DEADLINE_EXCEEDED'
                    raise WorkerError('selected 821bdd2 deadline exceeded') from None
                if record['actual_exit'] != 0:
                    record['failure'] = 'NONZERO_EXIT'
                    raise WorkerError('selected 821bdd2 command failed')
                record['cleanup_complete'] = True
                record['result'] = 'RETURNED_ZERO_WITH_COMPLETE_STREAMS'
            finally:
                for stream in (output, error):
                    stream.flush()
                    os.fsync(stream.fileno())
    except BaseException as failure:
        record['failure'] = record.get('failure', type(failure).__name__)
        record['result'] = 'FAILURE_OR_INCOMPLETE'
        record['cleanup_complete'] = _cleanup(process)
        if not record['cleanup_complete']:
            record['result'] = 'UNKNOWN_CLEANUP_UNRESOLVED'
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise
        raise WorkerError('selected 821bdd2 command failed; private originals retained') from None
    finally:
        if selection is not None:
            selection.close()
        if process is not None:
            record['actual_exit'] = process.returncode
            for stream in (process.stdin, process.stdout, process.stderr):
                _close(stream)
        record['sha256'] = {name: value.hexdigest() for name, value in hashes.items()}
        record['elapsed_seconds'] = round(time.monotonic() - started, 6)
        with private_create(paths['receipt.json']) as handle:
            handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True).encode('ascii'))
            handle.flush()
            os.fsync(handle.fileno())
    return record
