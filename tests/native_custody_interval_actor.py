"""Public-synthetic suspension qualification; policy labels are coordinator assumptions."""

import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

from native_nonce_boundary_actor import NativeOwnerDied, NativePeer, assert_spent
from offline_session.journal import Journal, OutcomeUnknown
from partial_journal_actor import partial_context
from session_test_support import NONCE_TAG, OPERATION_ID


class SyntheticFence:
    """Local ordering labels, not an authenticated or nonrewinding authority."""

    def __init__(self):
        self.pending = False
        self.epoch = 0
        self.release_attempts = 0
        self.release_admissions = 0

    def accept(self):
        assert not self.pending and self.epoch == 0
        self.pending = True

    def commit(self):
        assert self.pending and self.epoch == 0
        self.epoch = 1

    def attempt_release(self):
        self.release_attempts += 1
        if self.pending or self.epoch:
            return False
        self.release_admissions += 1
        return True


class IntervalPeer(NativePeer):
    """One actual native child with fixed, completely public signing inputs."""

    def __init__(self, executable, leg, role, round_digest, expected):
        environment = dict(os.environ)
        environment["PTLC_PUBLIC_SYNTHETIC_INTERVAL_SCOPE"] = leg + "-" + role
        self.child = subprocess.Popen(
            [executable, "--exact", "public_synthetic_custody_interval_child_and_pending_completion",
             "--nocapture", "--quiet", "--test-threads=1", "--color=never"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment,
        )
        self.leg, self.role = leg, role
        self.round_digest, self.expected = round_digest, expected
        self.buffer = b""
        self.headers = 0
        self.backend_entries = self.completed_partials = self.delivered_partials = 0
        self.sigkill = self.normal_exit = 0
        self.pauses = []
        self.stop_acknowledged = self.synthetic_deadline_elapsed = False

    def stop_and_observe_deadline(self):
        assert self.pauses == ["nonce-removed", "before-backend"]
        assert self.backend_entries == self.completed_partials == 0
        assert self.child.poll() is None and not self.buffer.strip()
        os.kill(self.child.pid, signal.SIGSTOP)
        end = time.monotonic() + 10
        while True:
            pid, status = os.waitpid(self.child.pid, os.WUNTRACED | os.WNOHANG)
            if pid:
                assert pid == self.child.pid and os.WIFSTOPPED(status)
                assert os.WSTOPSIG(status) == signal.SIGSTOP
                break
            assert time.monotonic() < end
            time.sleep(0.001)
        self.stop_acknowledged = True
        # This finite harness deadline models a timeout, not a real policy lease.
        started = time.monotonic()
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ)
            assert not selector.select(timeout=0.02)
        assert time.monotonic() - started >= 0.02
        assert self.child.poll() is None
        self.synthetic_deadline_elapsed = True

    def resume(self):
        assert self.stop_acknowledged and self.synthetic_deadline_elapsed
        assert self.child.poll() is None and self.sigkill == 0
        self.send("continue")
        os.kill(self.child.pid, signal.SIGCONT)

    def retain_computed_frame(self):
        value = self.read_event()
        expected = dict(event="computed", leg=self.leg, role=self.role,
                        round_digest_hex=self.round_digest, backend_entries=1,
                        nonce_present=False, partial_hex=self.expected.hex())
        assert type(value) is dict and value == expected
        assert type(value["backend_entries"]) is int
        assert type(value["nonce_present"]) is bool
        actual = bytes.fromhex(value["partial_hex"])
        assert actual == self.expected and len(actual) == 32
        self.backend_entries = self.completed_partials = 1
        # Public bytes cross an internal harness pipe. No outward release occurs.
        return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--owner-test", required=True)
    parser.add_argument("--leg", choices=("bitcoin", "zenon"), required=True)
    parser.add_argument("--role", choices=("alice", "bob"), required=True)
    parser.add_argument("--mode", choices=("early-commit", "pending-completion", "kill-before-commit"), required=True)
    args = parser.parse_args()
    assert os.name == "posix"
    terms, context = partial_context(args.leg, args.role)
    round_digest = context.as_dict()["nonce_round_digest_hex"]
    vectors = json.loads((Path(__file__).resolve().parents[1] / "qualification" / "fixtures"
                          / "nonce_rounds.json").read_text("ascii"))["vectors"]
    vector = next(v for v in vectors if v["leg"] == args.leg)
    expected = bytes.fromhex(vector["partial_signatures_hex"][0 if args.role == "alice" else 1])
    root, anchor = Path(args.root) / "state", Path(args.root) / "anchor"
    fence = SyntheticFence()
    recorded = args.mode != "kill-before-commit"
    callbacks, order, computed_epochs = [], [], []
    with IntervalPeer(args.owner_test, args.leg, args.role, round_digest, expected) as native:
        native.expect("prepared")
        with Journal.open(root, anchor) as journal:
            journal.create_session(terms.session_id, terms.digest_hex)
            journal.reserve(terms.session_id, OPERATION_ID, context, NONCE_TAG)

            def produce():
                assert journal.get_operation(terms.session_id, OPERATION_ID)["status"] == "CONSUMED"
                callbacks.append(1)
                native.send("sign")
                native.expect("nonce-removed")
                native.send("continue")
                native.expect("before-backend")
                native.stop_and_observe_deadline()
                order.extend(("native-stopped", "synthetic-deadline-elapsed"))
                fence.accept()
                order.append("synthetic-fence-accepted")
                assert not fence.attempt_release()
                if args.mode == "kill-before-commit":
                    native.kill_and_reap()
                    order.append("native-killed-and-reaped")
                    fence.commit()
                    order.append("synthetic-commit")
                    native.read_event()
                    raise AssertionError("dead native child produced a frame")
                if args.mode == "early-commit":
                    fence.commit()
                    order.append("synthetic-commit")
                else:
                    assert fence.pending and fence.epoch == 0
                native.resume()
                order.append("native-resumed")
                actual = native.retain_computed_frame()
                computed_epochs.append(fence.epoch)
                order.append("native-computed")
                return actual

            if recorded:
                assert journal.produce_once(terms.session_id, OPERATION_ID,
                                            expected_context=context, callback=produce) == expected
                order.append("original-retained")
                assert not fence.attempt_release()
                native.finish_and_reap()
                order.append("native-finished-and-reaped")
                if args.mode == "pending-completion":
                    assert fence.epoch == 0
                    fence.commit()
                    order.append("synthetic-commit")
                assert_spent(journal, terms, context, expected, True, "OUTPUT_RECORDED")
            else:
                try:
                    journal.produce_once(terms.session_id, OPERATION_ID,
                                         expected_context=context, callback=produce)
                except OutcomeUnknown:
                    pass
                else:
                    raise AssertionError("killed interval retained output")
                assert_spent(journal, terms, context, expected, False, "CONSUMED")

        # Check outside the journal's callback wrapper, so an unrelated failure
        # cannot masquerade as a qualified unknown/spent outcome.
        assert callbacks == [1] and native.pauses == ["nonce-removed", "before-backend"]
        assert native.stop_acknowledged and native.synthetic_deadline_elapsed
        assert native.sigkill == int(not recorded) and native.normal_exit == int(recorded)
        assert native.child.returncode == (0 if recorded else -signal.SIGKILL)
        assert native.backend_entries == native.completed_partials == int(recorded)
        assert native.delivered_partials == 0 and fence.pending and fence.epoch == 1
        assert computed_epochs == ([int(args.mode == "early-commit")] if recorded else [])
        prefix = ["native-stopped", "synthetic-deadline-elapsed", "synthetic-fence-accepted"]
        suffixes = {
            "early-commit": ["synthetic-commit", "native-resumed", "native-computed",
                             "original-retained", "native-finished-and-reaped"],
            "pending-completion": ["native-resumed", "native-computed", "original-retained",
                                   "native-finished-and-reaped", "synthetic-commit"],
            "kill-before-commit": ["native-killed-and-reaped", "synthetic-commit"],
        }
        assert order == prefix + suffixes[args.mode]
        assert not fence.attempt_release()
        assert fence.release_attempts == (3 if recorded else 2) and fence.release_admissions == 0
        status = "OUTPUT_RECORDED" if recorded else "OUTCOME_UNKNOWN"
        with Journal.open(root, anchor) as recovered:
            assert_spent(recovered, terms, context, expected, recorded, status)
        print(json.dumps(dict(event="qualified", leg=args.leg, role=args.role, mode=args.mode,
                              round_digest_hex=round_digest, native_launches=1,
                              native_sigstop_acknowledged=True, synthetic_deadline_elapsed=True,
                              synthetic_policy_epoch=1, order=order,
                              computation_after_synthetic_commit=args.mode == "early-commit",
                              native_sigkill=native.sigkill, native_normal_exit=native.normal_exit,
                              native_exit_code=native.child.returncode, acknowledged_pauses=native.pauses,
                              nonce_present_at_pauses=[False, False], native_backend_entries=native.backend_entries,
                              completed_partials=native.completed_partials, outward_releases=0,
                              callback_entries=1, release_attempts=fence.release_attempts, release_admissions=0,
                              reopen_status=status, replays_after_reopen=2 if recorded else 0,
                              forbidden_calls=0, coordinator_survived=True,
                              output_hex=expected.hex() if recorded else None),
                         sort_keys=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print('{"event":"refused","kind":"public-interval-qualification"}', flush=True)
        raise SystemExit(20)
