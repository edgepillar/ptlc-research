"""Owned v3/v4 crash actor; synthetic host selection never enforces caps."""

import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import sqlite3
import signal
import sys
from unittest.mock import patch

try:
    import resource
except ImportError:
    resource = None

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session import exchange
from offline_session.observation_store import ObservationStore
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.worker_resources import WorkerResourceLimits
from observation_store_test_support import STORE_ID, synthetic_pool, synthetic_verifier


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("crash", "recover", "initialize", "hold", "probe"))
    parser.add_argument("root")
    parser.add_argument("checkpoint")
    parser.add_argument("--point")
    parser.add_argument("--target")
    parser.add_argument("--marker")
    parser.add_argument("--recheck", action="store_true")
    parser.add_argument("--forbid-connect", action="store_true")
    parser.add_argument("--actual-observation")
    parser.add_argument("--limited", action="store_true")
    parser.add_argument("--cpu-seconds", type=int, default=2)
    parser.add_argument("--address-space-bytes", type=int, default=128 * 1024 * 1024)
    parser.add_argument("--attempt-limit", type=int, default=2)
    parser.add_argument("--pool-slots", type=int, default=2)
    parser.add_argument("--spill-cache", action="store_true")
    parser.add_argument("--synthetic-policy-host", action="store_true")
    parser.add_argument("--file-size-at", choices=("admission", "result"))
    args = parser.parse_args()
    if args.synthetic_policy_host and (not args.limited or args.actual_observation
            or sys.platform not in {"linux", "darwin"} or os.geteuid() == 0):
        parser.error("synthetic host selection requires a synthetic unprivileged POSIX actor")
    if args.spill_cache and (args.point is None or not args.point.endswith(".before_db_commit")):
        parser.error("synthetic cache pressure requires a pre-commit crash cut")
    armed = args.mode in {"recover", "initialize"}
    controlled_connection = None

    def file_size_failure():
        if resource is None or not hasattr(resource, "RLIMIT_FSIZE") or not hasattr(signal, "SIGXFSZ"):
            raise ValueError("synthetic file-size probe unsupported")
        # Restrict only this disposable writer, never the controller or a signer.
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        assert resource.getrlimit(resource.RLIMIT_FSIZE) == (0, 0)
        descriptor = os.open(Path(args.root).parent / "synthetic-fsize-probe",
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            try:
                os.write(descriptor, b"1")
            except OSError as error:
                if error.errno != errno.EFBIG:
                    raise
            else:
                raise AssertionError("native file-size refusal required")
        finally:
            os.close(descriptor)
        print("fsize-refused", flush=True)

    def hook(name):
        if armed and args.file_size_at == "result" and name == "worker.returned":
            file_size_failure()
        if armed and name == args.point:
            if args.spill_cache:
                # Tiny managed rows can remain below SQLite's minimum cache.
                # Uncommitted fixture pages force real journal/database I/O;
                # the tracked owner's SIGKILL leaves this table to roll back.
                controlled_connection.execute("CREATE TABLE synthetic_cache_pressure (data BLOB)")
                controlled_connection.execute("INSERT INTO synthetic_cache_pressure VALUES (zeroblob(131072))")
            print("paused", flush=True)
            sys.stdin.buffer.read(1)

    def mark(payload=b"1"):
        descriptor = os.open(args.marker, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def work(state, signature, *, ownership_descriptors, admission_descriptor, resource_limits=None):
        mark()
        return exchange.canonical(target["statement"])

    def run():
        nonlocal armed, target
        verifier = synthetic_verifier()
        if args.actual_observation:
            path = Path(args.actual_observation).resolve()
            verifier = SubprocessObservation(path, expected_executable_sha256_hex=_file_digest(path))
        options = dict(store_id_hex=STORE_ID, verifier=verifier,
            worker_pool=synthetic_pool(Path(args.root).parent, slot_limit=args.pool_slots),
            attempt_limit=args.attempt_limit, target_limit=2, hook=hook)
        opener = ObservationStore.open_limited if args.limited else ObservationStore.open
        if args.limited:
            options["resource_limits"] = WorkerResourceLimits(args.cpu_seconds, args.address_space_bytes)
        with opener(args.root, args.checkpoint, **options) as store:
            if args.mode in {"probe", "recover", "initialize"}:
                print("opened", flush=True)
                return
            if args.mode == "hold":
                print("held", flush=True)
                sys.stdin.buffer.read(1)
                return
            target = json.loads(Path(args.target).read_bytes())
            armed = True
            if args.file_size_at == "admission":
                file_size_failure()
            method = "observe_limited" if args.limited else "observe_admitted"
            if args.actual_observation:
                actual_call = getattr(SubprocessObservation, method)
                def actual_work(state, signature, **selected):
                    statement = actual_call(verifier, state, signature, **selected)
                    mark(json.loads(statement)["outcome"].encode("ascii"))
                    return statement
                with patch.object(SubprocessObservation, method, side_effect=actual_work):
                    store.observe(target["state"], bytes.fromhex(target["signature_hex"]), recheck=args.recheck)
            else:
                with patch.object(SubprocessObservation, method, side_effect=work):
                    store.observe(target["state"], bytes.fromhex(target["signature_hex"]), recheck=args.recheck)
            print("completed", flush=True)

    target = None
    actual_connect = sqlite3.connect
    def configured_connect(*arguments, **options):
        nonlocal controlled_connection
        connection = actual_connect(*arguments, **options)
        # Test-only pressure creates real dirty-page spill, not a fabricated journal.
        connection.execute("PRAGMA cache_size=1")
        connection.execute("PRAGMA cache_spill=1")
        assert connection.execute("PRAGMA cache_size").fetchone() == (1,)
        assert connection.execute("PRAGMA cache_spill").fetchone()[0] > 0
        controlled_connection = connection
        return connection
    def forbidden_connect(*arguments, **options):
        # Store sanitization can hide an assertion; this visible marker cannot.
        print("sqlite-connect-forbidden", flush=True)
        raise AssertionError("synthetic forbidden database access")
    try:
        with ExitStack() as controls:
            if args.synthetic_policy_host:
                controls.enter_context(patch("offline_session.worker_resources.sys.platform", "linux"))
            if args.forbid_connect:
                controls.enter_context(patch("sqlite3.connect", side_effect=forbidden_connect))
            elif args.spill_cache:
                controls.enter_context(patch("sqlite3.connect", side_effect=configured_connect))
            run()
    except BaseException as error:
        print(type(error).__name__, flush=True)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
