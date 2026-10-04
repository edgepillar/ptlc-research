"""Controlled nonforking public worker; it proves leases, not signature math."""

import json
import os
from pathlib import Path
import sys
import time


def main():
    mode, marker, release, first, second, unrelated = sys.argv[1:]
    expected = {(Path(value).stat().st_dev, Path(value).stat().st_ino) for value in (first, second)}
    forbidden = (Path(unrelated).stat().st_dev, Path(unrelated).stat().st_ino)
    retained, leaked = [], False
    for descriptor in range(3, 256):
        try:
            value = os.fstat(descriptor)
        except OSError:
            continue
        identity = (value.st_dev, value.st_ino)
        if identity in expected:
            retained.append(descriptor)
        leaked = leaked or identity == forbidden
    if mode != "never-read":
        sys.stdin.buffer.read()
    if mode == "eof-held":
        os.close(sys.stdout.fileno())
    target = Path(marker)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(json.dumps({"worker": os.getpid(), "guard": os.getppid(),
        "leases": len(retained), "unrelated_leaked": leaked}), encoding="ascii")
    os.replace(temporary, target)
    heartbeat = target.with_name(target.name + ".heartbeat")
    sequence = 0
    while not Path(release).exists():
        sequence += 1
        heartbeat.write_text(str(sequence), encoding="ascii")
        time.sleep(0.005)
    # Let the legacy control wait until the loop has stopped before removing
    # its temporary directory. No filesystem access follows this marker.
    target.with_name(target.name + ".released").touch()
    if mode != "eof-held":
        sys.stdout.buffer.write(b"synthetic-public-output")
        sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
