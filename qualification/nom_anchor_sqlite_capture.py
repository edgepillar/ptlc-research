"""Bounded original streams for one trusted finite SQLite CLI invocation.

This is a test transport, with no application service, retry or arbitrary process
containment claim. The caller supplies resource-controlled process supervision.
"""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import threading
import time

MAX_SQL_BYTES = 16 * 1024**2
MAX_STDOUT = 4 * 1024**2
MAX_STDERR = 64 * 1024
TIMEOUT = 20


def capture(arguments):
    assert len(arguments) in (6, 7)
    binary, binary_pin, database, script, mode, cut = arguments[:6]
    assert re.fullmatch('[0-9a-f]{64}', binary_pin)
    assert mode in ('rw', 'ro') and cut in ('none', 'kill_at_marker', 'contend_at_marker')
    assert len(arguments) == (7 if cut == 'contend_at_marker' else 6)
    contender_script = arguments[6] if cut == 'contend_at_marker' else None
    assert hashlib.sha256(Path(binary).read_bytes()).hexdigest() == binary_pin
    sql = Path(script).read_bytes()
    assert 0 < len(sql) <= MAX_SQL_BYTES and sql.isascii()
    workspace = Path(database).parent
    assert workspace.is_dir() and not Path(database).is_symlink()
    assert re.fullmatch(r'[a-z0-9][a-z0-9_-]*\.db', Path(database).name)
    uri = 'file:' + Path(database).name + '?mode=' + mode
    argv = [binary, '-init', '/dev/null', '-batch', '-bail', '-noheader', '-list', uri]
    process = subprocess.Popen(argv, cwd=workspace, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=dict(PATH='/usr/bin:/bin', LC_ALL='C', TMPDIR=str(workspace)), close_fds=True)
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    stop = threading.Event()
    marker = threading.Event()
    errors = []
    written = [0]

    def read_stream(name, pipe, cap):
        try:
            while True:
                block = pipe.read1(65536)
                if not block:
                    break
                available = cap - len(streams[name])
                streams[name].extend(block[:available])
                if name == 'stdout' and b'PTLC_SQL_SELECTED_CUT\n' in streams[name]:
                    marker.set()
                if len(block) > available:
                    errors.append(name + '_cap')
                    stop.set()
                    break
        except BaseException as error:
            errors.append(name + '_' + type(error).__name__)
            stop.set()
        finally:
            pipe.close()

    def write_input():
        try:
            for start in range(0, len(sql), 65536):
                block = sql[start:start + 65536]
                process.stdin.write(block)
                process.stdin.flush()
                written[0] += len(block)
            if cut == 'none':
                process.stdin.close()
        except BrokenPipeError:
            pass
        except BaseException as error:
            errors.append('stdin_' + type(error).__name__)
            stop.set()

    threads = [threading.Thread(target=read_stream, args=('stdout', process.stdout, MAX_STDOUT)),
               threading.Thread(target=read_stream, args=('stderr', process.stderr, MAX_STDERR)),
               threading.Thread(target=write_input)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + TIMEOUT
    selected_death = False
    timed_out = False
    contender = None
    failed_contender_wrapper = None
    continuation = b''
    try:
        while process.poll() is None:
            if cut == 'kill_at_marker' and marker.is_set():
                process.kill()
                selected_death = True
                break
            if cut == 'contend_at_marker' and contender is None and marker.is_set():
                # This exact source-pinned wrapper emits at most the declared native
                # stream caps plus JSON hex expansion. It is not a hostile runner.
                second = subprocess.run([sys.executable, '-B', __file__, binary, binary_pin,
                    database, contender_script, 'rw', 'none'], capture_output=True, timeout=TIMEOUT + 10)
                if second.returncode != 0 or len(second.stdout) > 10 * 1024**2 or second.stderr:
                    failed_contender_wrapper = dict(actual_exit=second.returncode,
                        stdout_hex=second.stdout.hex(), stderr_hex=second.stderr.hex())
                assert second.returncode == 0 and len(second.stdout) <= 10 * 1024**2 and not second.stderr
                contender = json.loads(second.stdout)
                continuation = b'COMMIT;\n'
                process.stdin.write(continuation)
                process.stdin.flush()
                written[0] += len(continuation)
                process.stdin.close()
            if stop.wait(.005):
                process.kill()
                break
            if time.monotonic() >= deadline:
                process.kill()
                timed_out = True
                break
        process.wait(timeout=5)
    except BaseException as error:
        errors.append('supervision_' + type(error).__name__)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if not process.stdin.closed:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass
        for thread in threads:
            thread.join(timeout=5)
        assert not any(thread.is_alive() for thread in threads)

    out, err = bytes(streams['stdout']), bytes(streams['stderr'])
    complete = not errors and not timed_out
    result = dict(schema='ptlc-selected-native-sql-capture-v1', actual_exit=process.returncode,
        output_complete=complete, timed_out=timed_out, selected_sigkill=selected_death,
        input_sha256=hashlib.sha256(sql + continuation).hexdigest(), input_bytes=len(sql + continuation), written_bytes=written[0],
        initial_input_sha256=hashlib.sha256(sql).hexdigest(), continuation_hex=continuation.hex(), contender=contender,
        failed_contender_wrapper=failed_contender_wrapper,
        stdout_hex=out.hex(), stderr_hex=err.hex(), stdout_bytes=len(out), stderr_bytes=len(err),
        stdout_sha256=hashlib.sha256(out).hexdigest(), stderr_sha256=hashlib.sha256(err).hexdigest(),
        capture_errors=errors, binary_unchanged=hashlib.sha256(Path(binary).read_bytes()).hexdigest() == binary_pin,
        scope='ONE TRUSTED NONFORKING NATIVE CLI; EXPECTED REFUSAL AND SELECTED DEATH EXITS ARE RETAINED')
    result['processes_reaped'] = (process.returncode is not None and failed_contender_wrapper is None
        and (contender is None or contender.get('processes_reaped') is True))
    result['numeric_sqlite_error_code'] = 'NOT_CAPTURED_BY_CLI'
    return result


def main(arguments=None):
    try:
        result = capture(sys.argv[1:] if arguments is None else arguments)
    except (AssertionError, ValueError, TypeError, OSError) as error:
        result = dict(schema="ptlc-selected-native-sql-capture-v1", actual_exit=None,
            output_complete=False, processes_reaped=False, diagnostic="SELECTED_TRANSPORT_NOT_QUALIFIED",
            error_class=type(error).__name__, numeric_sqlite_error_code="NOT_CAPTURED_BY_CLI")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    return 0 if result.get("output_complete") and result.get("processes_reaped") else 2


if __name__ == "__main__":
    sys.exit(main())
