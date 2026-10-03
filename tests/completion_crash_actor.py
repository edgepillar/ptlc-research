"""Process checkpoints with public fixture producers, never private signing."""

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.journal import Journal
from completion_test_support import alice_packet, completion_accepted, final_signatures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("alice", "bob"))
    parser.add_argument("root")
    parser.add_argument("anchor")
    parser.add_argument("session")
    parser.add_argument("checkpoint")
    parser.add_argument("marker")
    args = parser.parse_args()

    def hook(name):
        if name == args.checkpoint:
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
        return completion_accepted(request)

    try:
        with Journal.open(args.root, args.anchor, hook=hook) as journal:
            if args.mode == "alice":
                journal.complete_alice(args.session, producer=producer, verifier=completion_accepted)
            else:
                journal.complete_exchange_bitcoin(args.session, alice_packet(), recoverer=recoverer)
        print("returned", flush=True)
    except BaseException as error:
        print(type(error).__name__, flush=True)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
