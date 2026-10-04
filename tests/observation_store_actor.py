"""Real owner-death actor with a clearly synthetic public worker oracle."""

import argparse
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session import exchange
from offline_session.observation_store import ObservationStore
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from observation_store_test_support import STORE_ID, synthetic_pool, synthetic_verifier


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("crash", "hold", "probe"))
    parser.add_argument("root")
    parser.add_argument("checkpoint")
    parser.add_argument("--point")
    parser.add_argument("--target")
    parser.add_argument("--marker")
    parser.add_argument("--recheck", action="store_true")
    parser.add_argument("--forbid-connect", action="store_true")
    parser.add_argument("--actual-observation")
    args = parser.parse_args()
    armed = False

    def hook(name):
        if armed and name == args.point:
            print("paused", flush=True)
            sys.stdin.buffer.read(1)

    def mark(payload=b"1"):
        descriptor = os.open(args.marker, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def work(state, signature, *, ownership_descriptors, admission_descriptor):
        mark()
        return exchange.canonical(target["statement"])

    def run():
        nonlocal armed, target
        verifier = synthetic_verifier()
        if args.actual_observation:
            path = Path(args.actual_observation).resolve()
            verifier = SubprocessObservation(path, expected_executable_sha256_hex=_file_digest(path))
        with ObservationStore.open(args.root, args.checkpoint, store_id_hex=STORE_ID,
                verifier=verifier, worker_pool=synthetic_pool(Path(args.root).parent),
                attempt_limit=2, target_limit=2, hook=hook) as store:
            if args.mode == "probe":
                print("opened", flush=True)
                return
            if args.mode == "hold":
                print("held", flush=True)
                sys.stdin.buffer.read(1)
                return
            target = json.loads(Path(args.target).read_bytes())
            armed = True
            if args.actual_observation:
                actual_call = SubprocessObservation.observe_admitted
                def actual_work(state, signature, *, ownership_descriptors, admission_descriptor):
                    statement = actual_call(verifier, state, signature, ownership_descriptors=ownership_descriptors, admission_descriptor=admission_descriptor)
                    mark(json.loads(statement)["outcome"].encode("ascii"))
                    return statement
                with patch.object(SubprocessObservation, "observe_admitted", side_effect=actual_work):
                    store.observe(target["state"], bytes.fromhex(target["signature_hex"]), recheck=args.recheck)
            else:
                with patch.object(SubprocessObservation, "observe_admitted", side_effect=work):
                    store.observe(target["state"], bytes.fromhex(target["signature_hex"]), recheck=args.recheck)
            print("completed", flush=True)

    target = None
    try:
        if args.forbid_connect:
            with patch("sqlite3.connect", side_effect=AssertionError("database read before ownership")):
                run()
        else:
            run()
    except BaseException as error:
        print(type(error).__name__, flush=True)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
