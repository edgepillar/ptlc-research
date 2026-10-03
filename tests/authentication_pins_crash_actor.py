"""Synthetic pin checkpoints for process-death tests, without private signing."""

import argparse
import json
import signal
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session import exchange
from offline_session.journal import Journal
from exchange_test_support import artifacts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("start", "authenticate"))
    parser.add_argument("root")
    parser.add_argument("anchor")
    parser.add_argument("session")
    parser.add_argument("checkpoint")
    args = parser.parse_args()
    signal.alarm(30)
    fixture = json.loads((Path(__file__).resolve().parents[1]
                         / "qualification/fixtures/authentication.json").read_text("ascii"))
    pins = {key: fixture["envelope"]["context"][key] for key in ("alice_auth_key_hex", "bob_auth_key_hex")}

    def pause(name):
        if name == args.checkpoint:
            print("paused", flush=True)
            sys.stdin.buffer.read(1)

    def verifier(request):
        pause("during_authentication_verifier")
        return fixture["result"].copy()

    try:
        with Journal.open(args.root, args.anchor, hook=pause) as journal:
            if args.mode == "start":
                journal.start_exchange(args.session, artifacts()[1], recovery_limit=8, authentication_pins=pins)
            else:
                journal.authenticate_exchange_envelope(
                    args.session, exchange.canonical(fixture["envelope"]), verifier=verifier,
                )
        print("returned", flush=True)
    except BaseException as error:
        print(type(error).__name__, flush=True)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
