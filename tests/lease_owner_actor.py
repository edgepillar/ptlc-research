"""Real lease owner and guard-fault controller; no network or secret material."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import selectors
import shlex
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.observation_store import ObservationStore
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.public_worker import run_guarded_public_worker, run_public_worker
from observation_store_test_support import STORE_ID, synthetic_pool


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("store", "raw", "legacy"))
    parser.add_argument("root")
    parser.add_argument("checkpoint")
    parser.add_argument("marker")
    parser.add_argument("release")
    parser.add_argument("--target")
    parser.add_argument("--worker", choices=("hold", "never-read", "eof-held"), default="hold")
    parser.add_argument("--pause-after-guard", action="store_true")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--pool")
    parser.add_argument("--pool-slots", type=int, default=2)
    options = parser.parse_args()
    root = Path(options.root)
    root.mkdir(mode=0o700, exist_ok=True)
    first = root / ("observations.lock" if options.mode == "store" else "lease-a.lock")
    second = Path(options.checkpoint + ".lock")
    unrelated = root / "unrelated.data"
    unrelated.write_bytes(b"synthetic unrelated data")
    unrelated.chmod(0o600)
    extra_descriptor = os.open(unrelated, os.O_RDONLY)
    executable = root / "controlled-worker"
    actor = Path(__file__).with_name("lease_worker_actor.py").resolve()
    pool_directory = Path(options.pool) if options.pool else root.parent / "worker-pool"
    arguments = (sys.executable, "-B", str(actor), options.worker, options.marker,
                 options.release, str(first), str(second), str(unrelated),
                 str(pool_directory) if options.mode == "store" else "-")
    executable.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(value) for value in arguments) + "\n", encoding="ascii")
    executable.chmod(0o700)
    actual_spawn = subprocess.Popen
    actual_selector = selectors.DefaultSelector
    children = []

    def spawn(*args, **kwargs):
        child = actual_spawn(*args, **kwargs)
        children.append(child)
        if options.pause_after_guard:
            print("guard-started", flush=True)
            command = sys.stdin.buffer.readline().strip()
            if command == b"kill-guard":
                child.kill()
        return child

    class ControlSelector:
        def __init__(self):
            self.actual = actual_selector()
        def register(self, *args):
            return self.actual.register(*args)
        def unregister(self, *args):
            return self.actual.unregister(*args)
        def get_map(self):
            return self.actual.get_map()
        def close(self):
            return self.actual.close()
        def select(self, timeout=None):
            if select.select([sys.stdin], [], [], 0)[0]:
                command = os.read(sys.stdin.fileno(), 128).strip()
                if command == b"kill-guard" and children and children[0].returncode is None:
                    # Single-threaded owner; the guarded child is blocked and
                    # this runner has not entered its wait/reap phase.
                    children[0].kill()
                elif command == b"cancel":
                    raise KeyboardInterrupt
            return self.actual.select(min(timeout, 0.02) if timeout is not None else 0.02)

    descriptors = []
    try:
        with patch("offline_session.public_worker.subprocess.Popen", side_effect=spawn), \
                patch("offline_session.public_worker.selectors.DefaultSelector", ControlSelector):
            if options.mode == "store":
                value = json.loads(Path(options.target).read_bytes())
                verifier = SubprocessObservation(executable.resolve(), expected_executable_sha256_hex=_file_digest(executable), timeout=options.timeout)
                with ObservationStore.open(root, options.checkpoint, store_id_hex=STORE_ID, verifier=verifier,
                        worker_pool=synthetic_pool(root.parent, directory=pool_directory, slot_limit=options.pool_slots),
                        attempt_limit=2, target_limit=2) as store:
                    statement = store.observe(value["state"], bytes.fromhex(value["signature_hex"]))
                    print(json.loads(statement)["outcome"], flush=True)
            else:
                for path in (first, second):
                    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    descriptors.append(descriptor)
                request = b"i" * 65536 if options.worker == "never-read" else b"synthetic-public-input"
                if options.mode == "legacy":
                    run_public_worker(str(executable.resolve()), request, timeout=options.timeout, max_input_bytes=65536)
                else:
                    run_guarded_public_worker(str(executable.resolve()), request, timeout=options.timeout, max_input_bytes=65536,
                        expected_executable_sha256_hex=_file_digest(executable), ownership_descriptors=tuple(descriptors))
                print("completed", flush=True)
        return 0
    except BaseException as error:
        print(type(error).__name__, flush=True)
        return 20
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        os.close(extra_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
