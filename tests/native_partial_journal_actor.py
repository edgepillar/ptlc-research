"""Test-only journal peer for fixed public Rust partial-signing fixtures."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.journal import Conflict, Journal, OutcomeUnknown
from partial_journal_actor import partial_context
from session_test_support import NONCE_TAG, OPERATION_ID


class PublicResultLost(Exception):
    pass


class NativeAttemptRefused(Exception):
    pass


def receive():
    wire = sys.stdin.buffer.readline(257)
    if not wire.endswith(b"\n") or len(wire) > 256:
        raise ValueError("test command is incomplete or oversized")
    return wire[:-1].decode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--leg", choices=("bitcoin", "zenon"), required=True)
    parser.add_argument("--role", choices=("alice", "bob"), required=True)
    parser.add_argument("--scenario", choices=("recorded", "lost", "refused", "copy", "restore"), required=True)
    args = parser.parse_args()
    base = Path(args.root)
    terms, context = partial_context(args.leg, args.role)
    round_digest = context.as_dict()["nonce_round_digest_hex"]
    fixture = Path(__file__).resolve().parents[1] / "qualification" / "fixtures" / "nonce_rounds.json"
    vector = next(v for v in json.loads(fixture.read_text("ascii"))["vectors"] if v["leg"] == args.leg)
    expected = bytes.fromhex(vector["partial_signatures_hex"][0 if args.role == "alice" else 1])
    recorded = args.scenario not in ("lost", "refused")

    def emit(event, history, status, **extra):
        value = dict(event=event, history=history, leg=args.leg, role=args.role,
                     status=status, round_digest_hex=round_digest)
        value.update(extra)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)

    def initialize(root, anchor):
        with Journal.open(root, anchor) as journal:
            journal.create_session(terms.session_id, terms.digest_hex)

    def check_spent(journal, history, event, status):
        operation = journal.get_operation(terms.session_id, OPERATION_ID)
        assert operation["status"] == status
        assert operation["nonce_round_digest"] == round_digest
        assert not journal.get_session(terms.session_id)["possible_exposure"]
        attempted = []
        try:
            journal.produce_once(terms.session_id, OPERATION_ID, expected_context=context,
                                 callback=lambda: attempted.append(1) or expected)
        except OutcomeUnknown:
            pass
        else:
            raise AssertionError("spent journal allowed another producer")
        # This assertion stays outside the producer exception wrapper.
        assert attempted == []
        for tag in ("43" * 32, NONCE_TAG):
            try:
                journal.reserve(terms.session_id, "32" * 32, context, tag)
            except Conflict:
                pass
            else:
                raise AssertionError("spent scope allowed another reservation")
        before = journal.get_session(terms.session_id)
        if recorded:
            assert journal.replay(terms.session_id, OPERATION_ID, expected_context=context) == expected
            assert journal.replay(terms.session_id, OPERATION_ID, expected_context=context) == expected
        else:
            try:
                journal.replay(terms.session_id, OPERATION_ID, expected_context=context)
            except OutcomeUnknown:
                pass
            else:
                raise AssertionError("unknown operation replayed an output")
        assert journal.get_session(terms.session_id) == before
        emit(event, history, status, output_hex=expected.hex() if recorded else None,
             replays=2 if recorded else 0, forbidden_calls=len(attempted))

    def produce(journal, history):
        journal.reserve(terms.session_id, OPERATION_ID, context, NONCE_TAG)
        emit("reserved", history, "RESERVED")
        assert receive() == "produce"
        responses = []

        def native_handoff():
            assert journal.get_operation(terms.session_id, OPERATION_ID)["status"] == "CONSUMED"
            emit("invoke", history, "CONSUMED")
            response = receive()
            responses.append(response)
            if response == "lost":
                raise PublicResultLost()
            if response == "refused":
                raise NativeAttemptRefused()
            assert len(response) == 64 and response == expected.hex()
            return bytes.fromhex(response)

        if recorded:
            output = journal.produce_once(terms.session_id, OPERATION_ID, expected_context=context,
                                          callback=native_handoff)
            assert output == expected and responses == [expected.hex()]
        else:
            try:
                journal.produce_once(terms.session_id, OPERATION_ID, expected_context=context,
                                     callback=native_handoff)
            except OutcomeUnknown:
                pass
            else:
                raise AssertionError("lost or refused native attempt produced output")
            assert responses == [args.scenario]
        check_spent(journal, history, "produced", "OUTPUT_RECORDED" if recorded else "CONSUMED")

    def recover(root, anchor, history):
        with Journal.open(root, anchor) as journal:
            check_spent(journal, history, "recovered", "OUTPUT_RECORDED" if recorded else "OUTCOME_UNKNOWN")

    first, first_anchor = base / "first", base / "first-anchor"
    initialize(first, first_anchor)
    if args.scenario == "copy":
        second, second_anchor = base / "second", base / "second-anchor"
        second.mkdir(mode=0o700)
        database = second / "journal.sqlite3"
        database.write_bytes((first / "journal.sqlite3").read_bytes())
        database.chmod(0o600)
        second_anchor.write_bytes(first_anchor.read_bytes())
        second_anchor.chmod(0o600)
        # Both journals are open together, on distinct local locks.
        with Journal.open(first, first_anchor) as a, Journal.open(second, second_anchor) as b:
            produce(a, 1)
            produce(b, 2)
        recover(first, first_anchor, 1)
        recover(second, second_anchor, 2)
    elif args.scenario == "restore":
        database = first / "journal.sqlite3"
        before_database, before_anchor = database.read_bytes(), first_anchor.read_bytes()
        with Journal.open(first, first_anchor) as journal:
            produce(journal, 1)
        recover(first, first_anchor, 1)
        database.write_bytes(before_database)
        first_anchor.write_bytes(before_anchor)
        with Journal.open(first, first_anchor) as journal:
            assert journal.get_session(terms.session_id)["operations"] == {}
            produce(journal, 2)
        recover(first, first_anchor, 2)
    else:
        with Journal.open(first, first_anchor) as journal:
            produce(journal, 1)
        recover(first, first_anchor, 1)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps(dict(event="refused", kind=type(error).__name__)), flush=True)
        raise SystemExit(20)
