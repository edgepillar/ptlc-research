"""Short-lived synthetic subprocess behavior for public-worker boundary tests."""

import json
import os
from pathlib import Path
import signal
import sys
import time


def write_all(descriptor, value):
    offset = 0
    while offset < len(value):
        offset += os.write(descriptor, value[offset:])


def main():
    # Every actor terminates even if the runner under test fails to clean up.
    signal.alarm(3)
    mode, marker = sys.argv[1], Path(sys.argv[2])
    if mode == "duplex":
        write_all(1, b"o" * 4096)
        return 0 if sys.stdin.buffer.read() == b"i" * 65536 else 2
    if mode == "flood":
        # Exceeds pipe capacity before reading a similarly large request.
        for _ in range(1024):
            write_all(1, b"o" * 65536)
        return 0
    if mode == "early-close":
        os.close(0)
        marker.write_text("closed", encoding="ascii")
        write_all(1, b"ok")
        time.sleep(0.3)
        return 0
    if mode == "never-read":
        time.sleep(2)
        return 0
    sys.stdin.buffer.read()
    if mode.startswith("output-"):
        write_all(1, b"o" * int(mode.split("-")[1]))
    elif mode == "stderr-flood":
        write_all(2, b"SYNTHETIC_STDERR_MARKER\n" * 16384)
        write_all(1, b"ok")
    elif mode == "nonzero":
        write_all(2, b"SYNTHETIC_STDERR_MARKER")
        write_all(1, b"apparently-successful")
        return 23
    elif mode == "timeout":
        time.sleep(2)
    elif mode == "eof-alive":
        os.close(1)
        time.sleep(2)
    elif mode == "inherited-stdout":
        child = os.fork()
        if child == 0:
            signal.alarm(2)
            heartbeat = marker.with_suffix(".heartbeat")
            count = 0
            while True:
                heartbeat.write_text(str(count), encoding="ascii")
                count += 1
                time.sleep(0.02)
        marker.write_text(json.dumps({"parent": os.getpid(), "child": child}), encoding="ascii")
        os._exit(0)
    else:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
