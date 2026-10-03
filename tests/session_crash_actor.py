"""Subprocess actor for real process-death tests; no secret or network activity."""

import argparse
import os
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.journal import Journal
from session_test_support import NONCE_TAG, OPERATION_ID, PUBLIC_OUTPUT, session_context


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("crash", "probe", "hold"))
    parser.add_argument("root")
    parser.add_argument("anchor")
    parser.add_argument("--checkpoint", default="after_consume")
    parser.add_argument("--marker")
    parser.add_argument("--forbid-connect", action="store_true")
    parser.add_argument("--dynamic", action="store_true")
    args = parser.parse_args()
    terms, context = session_context(dynamic=args.dynamic)
    armed = False

    def hook(name):
        if armed and name == args.checkpoint:
            print("paused", flush=True)
            sys.stdin.buffer.read(1)

    def produce():
        if args.marker:
            descriptor = os.open(args.marker, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, b"1")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return PUBLIC_OUTPUT

    def run():
        nonlocal armed
        with Journal.open(args.root, args.anchor, hook=hook) as journal:
            if args.mode == "probe":
                print("opened", flush=True)
                return
            if args.mode == "hold":
                print("held", flush=True)
                sys.stdin.buffer.read(1)
                return
            journal.reserve(terms.session_id, OPERATION_ID, context, NONCE_TAG)
            armed = True
            journal.produce_once(
                terms.session_id, OPERATION_ID, expected_context=context, callback=produce,
            )
            print("completed", flush=True)

    try:
        if args.forbid_connect:
            with patch("sqlite3.connect", side_effect=AssertionError("state read before ownership")):
                run()
        else:
            run()
    except BaseException as error:
        # Deliberately report only the type. Never expose local paths or state.
        print(type(error).__name__, flush=True)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
