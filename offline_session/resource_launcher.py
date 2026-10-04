"""Internal single-process Linux limit installer; exec preserves owned leases.

No selected entry runs unless both finite limits and disabled core dumps have
exact readback. No preexec_fn, post-launch PID update, fork or store access is
used. Interpreter/modules and selected entry remain trusted local components.
"""

import os
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.observation_verifier import _file_digest
from offline_session.public_worker import (WorkerError, _admission_descriptor,
                                          _lease_descriptors, _validate, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES)
from offline_session.worker_resources import _decode, _install


def main():
    try:
        if len(sys.argv) != 6:
            raise WorkerError("invalid public worker resource arguments")
        entry, pin, raw_limits, raw_owners, raw_admission = sys.argv[1:]
        limits = _decode(raw_limits)
        _validate(entry, b"", 30, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES)
        owners = tuple(int(value) for value in raw_owners.split(","))
        if ",".join(str(value) for value in owners) != raw_owners:
            raise WorkerError("invalid public worker resource ownership encoding")
        owners = _lease_descriptors(owners)
        admission = int(raw_admission)
        if str(admission) != raw_admission:
            raise WorkerError("invalid public worker resource admission encoding")
        leases = owners + (_admission_descriptor(admission, owners),)
        if any(not os.get_inheritable(fd) for fd in leases):
            raise WorkerError("public worker resource leases cannot survive exec")
        if _file_digest(Path(entry)) != pin:
            raise WorkerError("selected resource-limited entry changed")
        signal.signal(signal.SIGXCPU, signal.SIG_DFL)
        _install(limits)
        # The same tracked PID, group and inherited capabilities survive exec.
        os.execv(entry, [entry])
        raise WorkerError("public worker resource exec returned")
    except BaseException:
        sys.stderr.write("public worker resources unavailable\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
