"""Process checkpoints with public fixture producers, never private signing."""

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.journal import Journal
from offline_session.completion import observation_digest
from completion_test_support import alice_packet, completion_accepted, final_signatures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("alice", "bob", "reconcile"))
    parser.add_argument("root")
    parser.add_argument("anchor")
    parser.add_argument("session")
    parser.add_argument("checkpoint")
    parser.add_argument("marker")
    args = parser.parse_args()
    recovery_returned = False

    def hook(name):
        nonlocal recovery_returned
        if name == "after_bitcoin_reconciliation_recoverer":
            recovery_returned = True
        target = args.checkpoint
        if target.startswith("completion:"):
            if not recovery_returned:
                return
            target = target.split(":", 1)[1]
        if name == target:
            print("paused", flush=True)
            sys.stdin.buffer.read(1)

    def count():
        descriptor = os.open(args.marker, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, b"1")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def producer():
        count()
        return final_signatures()[0]

    def recoverer(request):
        count()
        if args.mode == "reconcile":
            hook("during_reconciliation_recoverer")
        return completion_accepted(request)

    try:
        with Journal.open(args.root, args.anchor, hook=hook) as journal:
            if args.mode == "alice":
                journal.complete_alice(args.session, producer=producer, verifier=completion_accepted)
            elif args.mode == "bob":
                journal.complete_exchange_bitcoin(args.session, alice_packet(), recoverer=recoverer)
            else:
                previous = bytes.fromhex(journal.get_exchange(args.session)["zenon_completion_packet_hex"])
                journal.reconcile_exchange_bitcoin(
                    args.session, alice_packet(), expected_observation_digest=observation_digest(previous),
                    recoverer=recoverer,
                )
        print("returned", flush=True)
    except BaseException as error:
        print(type(error).__name__, flush=True)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
