"""Controlled nonforking public worker; it proves leases, not signature math."""

import json
import os
from pathlib import Path
import resource
import signal
import sys
import time


def main():
    mode, marker, release, first, second, unrelated, pool = sys.argv[1:]
    expected = {(Path(value).stat().st_dev, Path(value).stat().st_ino) for value in (first, second)}
    forbidden = (Path(unrelated).stat().st_dev, Path(unrelated).stat().st_ino)
    admission = set() if pool == "-" else {(path.stat().st_dev, path.stat().st_ino)
                                          for path in Path(pool).glob("slot-*.lock")}
    retained, admitted, leaked = [], [], False
    for descriptor in range(3, 256):
        try:
            value = os.fstat(descriptor)
        except OSError:
            continue
        identity = (value.st_dev, value.st_ino)
        if identity in expected:
            retained.append(descriptor)
        if identity in admission:
            admitted.append(descriptor)
        leaked = leaked or identity == forbidden
    if mode != "never-read":
        sys.stdin.buffer.read()
    if mode == "eof-held":
        os.close(sys.stdout.fileno())
    target = Path(marker)
    temporary = target.with_name(target.name + ".tmp")
    value = {"worker": os.getpid(), "guard": os.getppid(), "leases": len(retained),
             "admission_leases": len(admitted), "unrelated_leaked": leaked}
    if mode in ("cpu-burn", "address-space"):
        value["resource_limits"] = {"cpu": resource.getrlimit(resource.RLIMIT_CPU),
            "address_space": resource.getrlimit(resource.RLIMIT_AS),
            "core": resource.getrlimit(resource.RLIMIT_CORE)}
    if mode == "address-space":
        import mmap
        try:
            block = mmap.mmap(-1, 256 * 1024 * 1024)
            block.close()
            value["oversized_mapping_rejected"] = False
        except (OSError, MemoryError):
            value["oversized_mapping_rejected"] = True
    temporary.write_text(json.dumps(value), encoding="ascii")
    os.replace(temporary, target)
    heartbeat = target.with_name(target.name + ".heartbeat")
    sequence = 0
    while mode != "address-space" and not Path(release).exists():
        sequence += 1
        heartbeat.write_text(str(sequence), encoding="ascii")
        time.sleep(0.005)
    if mode == "cpu-burn":
        signal.signal(signal.SIGXCPU, signal.SIG_IGN)
        while True:
            pass
    # Let the legacy control wait until the loop has stopped before removing
    # its temporary directory. No filesystem access follows this marker.
    target.with_name(target.name + ".released").touch()
    if mode != "eof-held":
        sys.stdout.buffer.write(b"synthetic-public-output")
        sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
