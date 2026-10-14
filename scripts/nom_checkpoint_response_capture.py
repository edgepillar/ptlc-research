"""Bounded in-memory originals for one trusted nonforking math worker.

No output file, retry or application action is created. This is qualification
transport, not a hostile-process sandbox or a hard process-creation time bound.
"""
import os
from pathlib import Path
import selectors
import subprocess
import time

from offline_session.public_worker import _cleanup, _close
from scripts.nom_cut_capture import sha


def capture_original(executable, wire, *, expected_pin, timeout=5,
                     max_input_bytes=8192, max_output_bytes=512):
    path = Path(executable)
    if (type(wire) is not bytes or not 0 < len(wire) <= max_input_bytes <= 8192
            or timeout != 5 or max_output_bytes != 512 or sha(path.read_bytes()) != expected_pin):
        raise ValueError("selected public math capture refused")
    streams = dict(stdout=bytearray(), stderr=bytearray())
    process = selection = None
    complete = False
    reason = "UNKNOWN"
    try:
        deadline = time.monotonic()+timeout
        process = subprocess.Popen([str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={}, close_fds=True, start_new_session=True, bufsize=0)
        selection = selectors.DefaultSelector()
        for stream, name, event in ((process.stdin,"stdin",selectors.EVENT_WRITE),
            (process.stdout,"stdout",selectors.EVENT_READ), (process.stderr,"stderr",selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(),False)
            selection.register(stream,event,name)
        offset = 0
        while selection.get_map():
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise TimeoutError
            for key,_ in selection.select(remaining):
                if time.monotonic() >= deadline: raise TimeoutError
                if key.data == "stdin":
                    try: count=os.write(key.fd,wire[offset:offset+4096])
                    except BlockingIOError: continue
                    if count <= 0: raise OSError("input delivery refused")
                    offset += count
                    if offset == len(wire): selection.unregister(key.fileobj);_close(key.fileobj)
                else:
                    target=streams[key.data]
                    limit=max_output_bytes if key.data == "stdout" else 4096
                    try: part=os.read(key.fd,min(4096,limit+1-len(target)))
                    except BlockingIOError: continue
                    if not part: selection.unregister(key.fileobj);_close(key.fileobj)
                    else:
                        target.extend(part)
                        if len(target)>limit: raise OverflowError
        process.wait(timeout=max(.001,deadline-time.monotonic()))
        if sha(path.read_bytes()) != expected_pin: raise ValueError("selected math executable changed")
        complete = True
        reason = "COMPLETE"
    except (OSError, ValueError, OverflowError, TimeoutError, subprocess.SubprocessError):
        reason = "INTERRUPTED_OR_INCOMPLETE; NOT_QUALIFIED"
    finally:
        if selection is not None: selection.close()
        if process is not None:
            _cleanup(process)
            _close(process.stderr)
    output,error=bytes(streams["stdout"]),bytes(streams["stderr"])
    return dict(request_hex=wire.hex(),request_sha256=sha(wire),stdout_hex=output.hex(),stderr_hex=error.hex(),
        stdout_sha256=sha(output),stderr_sha256=sha(error),exit_code=None if process is None else process.returncode,
        stream_completeness="COMPLETE" if complete else "PARTIAL; NOT_ESTABLISHED",reason=reason)
