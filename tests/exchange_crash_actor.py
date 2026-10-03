"""Process actor for public-output release, with no signer or network."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.journal import Journal
from exchange_test_support import accepted, artifacts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("anchor")
    parser.add_argument("session")
    parser.add_argument("checkpoint")
    parser.add_argument("--retain", action="store_true")
    args = parser.parse_args()

    def hook(name):
        if name == args.checkpoint:
            print("paused", flush=True)
            sys.stdin.buffer.read(1)

    try:
        with Journal.open(args.root, args.anchor, hook=hook) as journal:
            if args.retain:
                journal.retain_exchange_zenon(args.session, artifacts()[4], verifier=accepted)
            else:
                journal.release_exchange_zenon(args.session)
        print("returned", flush=True)
    except BaseException as error:
        print(type(error).__name__, flush=True)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
