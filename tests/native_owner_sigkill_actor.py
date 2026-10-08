"""Test-only native-owner SIGKILL coordinator; all signing inputs are public."""

import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offline_session.journal import Conflict, Journal, OutcomeUnknown
from partial_journal_actor import partial_context
from session_test_support import NONCE_TAG, OPERATION_ID


class NativeOwnerDied(Exception):
    pass


class NativePeer:
    """One fixed-scope libtest child, with bounded public frames and waits."""

    def __init__(self, executable, leg, role, round_digest, expected):
        environment = dict(os.environ)
        environment["PTLC_PUBLIC_SYNTHETIC_OWNER_SCOPE"] = leg + "-" + role
        self.child = subprocess.Popen(
            [executable, "--exact", "public_synthetic_native_owner_child", "--nocapture",
             "--quiet", "--test-threads=1", "--color=never"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment,
        )
        self.leg, self.role = leg, role
        self.round_digest, self.expected = round_digest, expected
        self.buffer = b""
        self.headers = 0
        self.backend_entries = self.completed_partials = self.delivered_partials = 0
        self.sigkill = 0

    def send(self, command):
        assert command in ("sign", "release")
        self.child.stdin.write(command.encode("ascii") + b"\n")
        self.child.stdin.flush()

    def read_event(self):
        if self.child.poll() is not None:
            raise NativeOwnerDied()
        deadline = time.monotonic() + 10
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ)
            while True:
                if b"\n" in self.buffer:
                    line, self.buffer = self.buffer.split(b"\n", 1)
                    if line.startswith(b"PTLC_NATIVE_OWNER "):
                        return json.loads(line[len(b"PTLC_NATIVE_OWNER "):].decode("ascii"))
                    assert line in (b"", b"running 1 test")
                    self.headers += 1
                    assert self.headers <= 8
                    continue
                remaining = deadline - time.monotonic()
                assert remaining > 0 and selector.select(timeout=remaining)
                assert len(self.buffer) < 2048
                part = os.read(self.child.stdout.fileno(), 2048 - len(self.buffer))
                if not part:
                    raise NativeOwnerDied()
                self.buffer += part

    def expect(self, event):
        value = self.read_event()
        computed = event != "prepared"
        expected = dict(event=event, leg=self.leg, role=self.role,
                        round_digest_hex=self.round_digest,
                        backend_entries=int(computed), nonce_present=not computed)
        if event == "partial":
            expected["partial_hex"] = self.expected.hex()
        assert type(value) is dict and value == expected
        assert type(value["backend_entries"]) is int
        assert type(value["nonce_present"]) is bool
        if event == "computed":
            self.backend_entries = self.completed_partials = 1
        if event == "partial":
            self.delivered_partials = 1
        return value

    def kill_and_reap(self):
        assert self.sigkill == 0 and self.child.poll() is None
        self.child.kill()
        remaining, error = self.child.communicate(timeout=10)
        assert self.child.returncode == -signal.SIGKILL
        assert error == b"" and not remaining.strip() and not self.buffer.strip()
        self.sigkill = 1

    def close(self):
        if self.child.poll() is None:
            self.child.kill()
        self.child.communicate(timeout=10)

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        self.close()


def assert_spent(journal, terms, context, expected, recorded, status):
    operation = journal.get_operation(terms.session_id, OPERATION_ID)
    assert operation["status"] == status
    assert operation["nonce_round_digest"] == context.as_dict()["nonce_round_digest_hex"]
    assert not journal.get_session(terms.session_id)["possible_exposure"]
    forbidden = []
    try:
        journal.produce_once(terms.session_id, OPERATION_ID, expected_context=context,
                             callback=lambda: forbidden.append(1) or expected)
    except OutcomeUnknown:
        pass
    else:
        raise AssertionError("spent native admission allowed another producer")
    # Producer exceptions are wrapped; check this outside the wrapper.
    assert forbidden == []
    for nonce_tag in ("43" * 32, NONCE_TAG):
        try:
            journal.reserve(terms.session_id, "32" * 32, context, nonce_tag)
        except Conflict:
            pass
        else:
            raise AssertionError("spent native scope allowed replacement")
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
            raise AssertionError("unretained native output replayed")
    assert journal.get_session(terms.session_id) == before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--owner-test", required=True)
    parser.add_argument("--leg", choices=("bitcoin", "zenon"), required=True)
    parser.add_argument("--role", choices=("alice", "bob"), required=True)
    parser.add_argument("--cut", choices=("reserved", "consumed", "computed", "delivered", "retained"), required=True)
    args = parser.parse_args()
    assert os.name == "posix"
    terms, context = partial_context(args.leg, args.role)
    round_digest = context.as_dict()["nonce_round_digest_hex"]
    vectors = json.loads((Path(__file__).resolve().parents[1] / "qualification" / "fixtures"
                          / "nonce_rounds.json").read_text("ascii"))["vectors"]
    vector = next(v for v in vectors if v["leg"] == args.leg)
    expected = bytes.fromhex(vector["partial_signatures_hex"][0 if args.role == "alice" else 1])
    root, anchor = Path(args.root) / "state", Path(args.root) / "anchor"
    recorded = args.cut in ("delivered", "retained")
    callbacks = []
    with NativePeer(args.owner_test, args.leg, args.role, round_digest, expected) as native:
        native.expect("prepared")
        with Journal.open(root, anchor) as journal:
            journal.create_session(terms.session_id, terms.digest_hex)
            journal.reserve(terms.session_id, OPERATION_ID, context, NONCE_TAG)

            def produce():
                assert journal.get_operation(terms.session_id, OPERATION_ID)["status"] == "CONSUMED"
                callbacks.append(1)
                if args.cut == "consumed":
                    native.kill_and_reap()
                    # The selected native child is dead; there is no lost-result command.
                    native.read_event()
                native.send("sign")
                native.expect("computed")
                if args.cut == "computed":
                    native.kill_and_reap()
                    native.read_event()
                native.send("release")
                value = native.expect("partial")
                if args.cut == "delivered":
                    native.kill_and_reap()
                    assert journal.get_operation(terms.session_id, OPERATION_ID)["status"] == "CONSUMED"
                return bytes.fromhex(value["partial_hex"])

            if args.cut == "reserved":
                native.kill_and_reap()
                assert journal.get_operation(terms.session_id, OPERATION_ID)["status"] == "RESERVED"
                # Closing/reopening retires this reservation; death alone does not.
            elif recorded:
                assert journal.produce_once(terms.session_id, OPERATION_ID,
                                            expected_context=context, callback=produce) == expected
                if args.cut == "retained":
                    native.kill_and_reap()
                assert_spent(journal, terms, context, expected, True, "OUTPUT_RECORDED")
            else:
                try:
                    journal.produce_once(terms.session_id, OPERATION_ID,
                                         expected_context=context, callback=produce)
                except OutcomeUnknown:
                    pass
                else:
                    raise AssertionError("dead native owner produced a retained output")
                assert_spent(journal, terms, context, expected, False, "CONSUMED")

        # Callback wrapping cannot substitute an assertion failure for the expected death.
        assert native.sigkill == 1 and native.child.returncode == -signal.SIGKILL
        assert callbacks == ([] if args.cut == "reserved" else [1])
        computed = args.cut in ("computed", "delivered", "retained")
        assert native.backend_entries == native.completed_partials == int(computed)
        assert native.delivered_partials == int(recorded)
        status = "OUTPUT_RECORDED" if recorded else "RETIRED" if args.cut == "reserved" else "OUTCOME_UNKNOWN"
        with Journal.open(root, anchor) as recovered:
            assert_spent(recovered, terms, context, expected, recorded, status)
        assert native.sigkill == 1 and native.child.returncode == -signal.SIGKILL
        print(json.dumps(dict(event="qualified", leg=args.leg, role=args.role, cut=args.cut,
                              round_digest_hex=round_digest, native_launches=1, native_sigkill=1,
                              native_exit_signal=signal.SIGKILL, native_backend_entries=native.backend_entries,
                              completed_partials=native.completed_partials, delivered_partials=native.delivered_partials,
                              callback_entries=len(callbacks), reopen_status=status,
                              replays_after_reopen=2 if recorded else 0, forbidden_calls=0,
                              coordinator_survived=True, output_hex=expected.hex() if recorded else None),
                         sort_keys=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps(dict(event="refused", kind=type(error).__name__)), flush=True)
        raise SystemExit(20)
