"""Fixture-only partial-output crash actor; no cryptographic signing or network."""

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.journal import Journal
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round, reveal_nonce_round,
    signing_context,
)
from session_test_support import NONCE_TAG, OPERATION_ID, PUBLIC_OUTPUT


PARTIAL_SCOPES = tuple((leg, role) for leg in ("bitcoin", "zenon") for role in ("alice", "bob"))


def partial_context(leg, role):
    """Reconstruct one existing public fixture round, without generating a nonce."""
    fixture = Path(__file__).parent / "fixtures" / "session_terms.json"
    data = json.loads(fixture.read_text("ascii"))
    terms = agree_terms(data["terms"])
    bitcoin = bind_bitcoin(terms, data["bitcoin_binding"])
    binding = bind_zenon(bitcoin, data["zenon_binding"]) if leg == "zenon" else bitcoin
    vectors = json.loads((Path(__file__).resolve().parents[1] / "qualification" / "fixtures"
                          / "nonce_rounds.json").read_text("ascii"))["vectors"]
    vector = next(item for item in vectors if item["leg"] == leg)
    committed = commit_nonce_round(binding, vector["round_id_hex"], *vector["nonce_commitments_hex"])
    revealed = reveal_nonce_round(committed, *vector["public_nonces_hex"])
    return terms, signing_context(binding, role, leg + "-claim-partial", nonce_round=revealed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("anchor")
    parser.add_argument("--leg", choices=("bitcoin", "zenon"), required=True)
    parser.add_argument("--role", choices=("alice", "bob"), required=True)
    parser.add_argument("--checkpoint", choices=("before_db_commit", "after_db_commit",
                        "after_anchor_replace", "after_anchor_commit", "after_consume",
                        "after_callback", "after_output_commit"), required=True)
    parser.add_argument("--occurrence", type=int, choices=(1, 2), default=1)
    parser.add_argument("--marker", required=True)
    args = parser.parse_args()
    terms, context = partial_context(args.leg, args.role)
    armed = False
    seen = 0

    def hook(name):
        nonlocal seen
        if armed and name == args.checkpoint:
            seen += 1
            if seen == args.occurrence:
                print("paused", flush=True)
                sys.stdin.buffer.read(1)

    def synthetic_producer():
        descriptor = os.open(args.marker, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            if os.write(descriptor, b"1") != 1:
                raise OSError("synthetic invocation marker is incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return PUBLIC_OUTPUT

    try:
        with Journal.open(args.root, args.anchor, hook=hook) as journal:
            journal.reserve(terms.session_id, OPERATION_ID, context, NONCE_TAG)
            armed = True
            journal.produce_once(terms.session_id, OPERATION_ID, expected_context=context,
                                 callback=synthetic_producer)
            print("completed", flush=True)
    except BaseException as error:
        print(type(error).__name__, flush=True)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
