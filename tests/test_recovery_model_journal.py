"""Selected model traces against public journals, not a refinement proof.

Discovery uses explicit fixture oracles. The separate qualification command
replays the behavioral cases with the actual artifact/completion executables.
Model authorization/authentication remain external premises, not journal policy.
"""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from offline_session import completion
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from scripts.model_recovery_admission import (
    Action, Bounds, State, availability_violations, explore, safety_violations,
    step, transition_violations,
)
from completion_test_support import completion_accepted, final_signatures
from exchange_test_support import accepted, prepare


def fixture_recovery(request):
    """A fixed synthetic oracle; this is deliberately not signature verification."""
    if request["zenon_signature_hex"] != final_signatures()[0].hex():
        raise ValueError("synthetic invalid candidate")
    return completion_accepted(request)


class RecoveryModelJournalTests(unittest.TestCase):
    verifier = staticmethod(accepted)
    recoverer = staticmethod(fixture_recovery)

    def plan(self, actions, limit):
        """Validate the entire selected trace before creating a journal."""
        bounds = Bounds(limit)
        bounds.validate()
        if type(actions) is not tuple or len(actions) > 256:
            raise ValueError("a bounded exact action tuple is required")
        states = [State()]
        need_outcome = False
        for action in actions:
            if type(action) is not Action or action.kind == "worker_crash":
                raise ValueError("process death is outside this trace bridge")
            outcome = action.kind in ("worker_verify", "worker_fail", "worker_cancel")
            if need_outcome != outcome:
                raise ValueError("admission must be immediately paired with an outcome")
            following = step(states[-1], action, bounds=bounds)
            self.assertEqual(transition_violations(states[-1], action, following, bounds=bounds), ())
            self.assertEqual(safety_violations(following, bounds=bounds), ())
            states.append(following)
            need_outcome = action.kind in ("begin", "retry", "reconcile")
        if need_outcome:
            raise ValueError("a pending admission is not a completed trace")
        return bounds, states

    def assert_projection(self, journal, session, modeled, packets, root, anchor, release, limit):
        """Compare exact retained bytes and independently read durable fields."""
        actual = journal.get_session(session)
        exchange = actual["exchange"]
        self.assertEqual(actual["recovery_budget"], {"limit": limit, "consumed": modeled.consumed})
        expected = lambda candidate: packets[candidate].hex() if candidate else None
        self.assertEqual(exchange["zenon_completion_packet_hex"], expected(modeled.retained))
        self.assertEqual(exchange["superseded_zenon_completion_packet_hex"], expected(modeled.archive))
        original = modeled.archive or modeled.retained
        self.assertEqual(original, modeled.original)
        # Public disclosure in the model is external to Bob's local marker.
        self.assertEqual(actual["possible_exposure"], modeled.consumed > 0)
        self.assertIsNone(actual["alice"])
        self.assertEqual(exchange["stage"], "BTC_COMPLETION_RECORDED" if modeled.completed else "RELEASE_RECORDED")
        self.assertEqual(exchange["completion_receipt_hex"] is not None, bool(modeled.completed))
        if modeled.completed:
            output = journal.replay_exchange_bitcoin(session)
            self.assertEqual(output.hex(), exchange["bitcoin_completion_packet_hex"])
            self.assertEqual(json.loads(output)["signature_hex"], final_signatures()[1].hex())
        else:
            self.assertIsNone(exchange["bitcoin_completion_packet_hex"])
        self.assertEqual(journal.replay_exchange_release(session), release)
        with closing(sqlite3.connect(str(root / "journal.sqlite3"))) as connection:
            connection.execute("PRAGMA query_only = ON")
            raw, sequence = connection.execute("SELECT state_json, sequence FROM checkpoint").fetchone()
        stored = json.loads(raw)
        self.assertEqual(stored["sessions"][session], actual)
        self.assertEqual(sequence, json.loads(anchor.read_bytes())["sequence"])
        self.assertEqual(sequence, journal._sequence)

    def replay_trace(self, actions, *, limit=2, exhausted=False, recoverer=None):
        bounds, states = self.plan(actions, limit)
        recoverer = self.recoverer if recoverer is None else recoverer
        with tempfile.TemporaryDirectory(prefix="synthetic-model-journal-") as directory:
            base = Path(directory)
            root, anchor = base / "state", base / "head.json"
            with Journal.open(root, anchor) as journal:
                session = prepare(journal, recovery_limit=limit, verifier=self.verifier)
                release = journal.release_exchange_zenon(session)
                context = journal.get_exchange(session)
                packets = {
                    "valid": completion.bob_candidate_from_signature(context, final_signatures()[0]),
                    "invalid": completion.bob_candidate_from_signature(context, bytes(64)),
                }
                self.assertNotEqual(packets["valid"], packets["invalid"])
                self.assert_projection(journal, session, states[0], packets, root, anchor, release, limit)
            calls = []
            index = 0
            while index < len(actions):
                action = actions[index]
                with Journal.open(root, anchor) as journal:
                    self.assert_projection(journal, session, states[index], packets, root, anchor, release, limit)
                    if action.kind in ("begin", "retry", "reconcile"):
                        outcome = actions[index + 1]
                        admitted, following = states[index + 1:index + 3]
                        calls_before = len(calls)

                        def worker(request):
                            # This callback must see the matched durable admission.
                            self.assert_projection(journal, session, admitted, packets, root, anchor, release, limit)
                            self.assertEqual(request["zenon_signature_hex"],
                                             json.loads(packets[admitted.pending.candidate])["signature_hex"])
                            calls.append(outcome.kind)
                            if outcome.kind == "worker_fail":
                                raise RuntimeError("injected public worker failure")
                            if outcome.kind == "worker_cancel":
                                raise KeyboardInterrupt("injected cancellation")
                            return recoverer(request)

                        def invoke():
                            if action.kind == "reconcile":
                                return journal.reconcile_exchange_bitcoin(
                                    session, packets[action.candidate],
                                    expected_observation_digest=completion.observation_digest(packets[action.expected_candidate]),
                                    recoverer=worker,
                                )
                            packet = None if action.kind == "retry" else packets[action.candidate]
                            return journal.complete_exchange_bitcoin(session, packet, recoverer=worker)

                        # The current completion adapter sanitizes BaseException,
                        # including injected cancellation, into journal Conflict.
                        if not following.completed:
                            with self.assertRaises(Conflict):
                                invoke()
                        else:
                            self.assertEqual(invoke(), journal.replay_exchange_bitcoin(session))
                        self.assertEqual(len(calls), calls_before + 1)
                        self.assert_projection(journal, session, following, packets, root, anchor, release, limit)
                        index += 2
                    else:
                        before = journal.get_session(session), journal._sequence, (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()
                        if action.kind == "replay":
                            self.assertEqual(journal.replay_exchange_bitcoin(session).hex(),
                                             journal.get_exchange(session)["bitcoin_completion_packet_hex"])
                        # Observation/authorization/inclusion/reorg are model events
                        # only; no journal source policy or chain event is fabricated.
                        self.assertEqual((journal.get_session(session), journal._sequence,
                                          (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()), before)
                        self.assert_projection(journal, session, states[index + 1], packets, root, anchor, release, limit)
                        index += 1
            with Journal.open(root, anchor) as journal:
                self.assert_projection(journal, session, states[-1], packets, root, anchor, release, limit)
                if exhausted:
                    self.assertIn("recovery_allowance_exhausted", availability_violations(states[-1], bounds=bounds))
                    before = journal.get_session(session), journal._sequence, (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()
                    unexpected = []

                    def forbidden(request):
                        unexpected.append(True)
                        return recoverer(request)

                    if states[-1].retained == "valid":
                        with self.assertRaises(RecoveryExhausted):
                            journal.complete_exchange_bitcoin(session, recoverer=forbidden)
                    else:
                        with self.assertRaises(RecoveryExhausted):
                            journal.reconcile_exchange_bitcoin(
                                session, packets["valid"],
                                expected_observation_digest=completion.observation_digest(packets[states[-1].retained]),
                                recoverer=forbidden,
                            )
                    self.assertEqual(unexpected, [])
                    self.assertEqual((journal.get_session(session), journal._sequence,
                                      (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()), before)
            return states[-1], tuple(calls)

    def test_generated_shortest_exhaustion_traces_match_pending_and_reopened_state(self):
        for limit in (1, 2, 3):
            with self.subTest(limit=limit):
                result = explore(bounds=Bounds(limit))
                self.assertTrue(result.complete)
                self.assertEqual(result.safety_findings, ())
                finding, = result.availability_findings
                self.assertEqual(finding.name, "recovery_allowance_exhausted")
                modeled, calls = self.replay_trace(finding.trace, limit=limit, exhausted=True)
                self.assertEqual(modeled, finding.state)
                self.assertEqual(len(calls), limit)

    def test_rejected_invalid_retry_blocks_later_authorized_public_reconciliation(self):
        self.replay_trace((Action("begin", "invalid", "peer", True), Action("worker_verify"),
                           Action("retry"), Action("worker_verify"), Action("observe_public"),
                           Action("authorize_public")), exhausted=True)

    def test_valid_failure_retry_success_and_replay_survive_external_reorg(self):
        self.replay_trace((Action("begin", "valid", "peer", True), Action("worker_fail"),
                           Action("retry"), Action("worker_verify"), Action("observe_public"),
                           Action("claim_inclusion"), Action("reorg"), Action("replay"), Action("replay")))

    def test_authorized_public_witness_without_envelope_completes(self):
        self.replay_trace((Action("observe_public"), Action("authorize_public"),
                           Action("begin", "valid", "public"), Action("worker_verify"), Action("replay")), limit=1)

    def test_positive_public_reconciliation_archives_the_exact_original(self):
        self.replay_trace((Action("begin", "invalid", "peer", True), Action("worker_verify"),
                           Action("observe_public"), Action("authorize_public"),
                           Action("reconcile", "valid", "public", False, "invalid"),
                           Action("worker_verify"), Action("replay")))

    def test_reconciliation_failure_keeps_original_before_later_positive_replacement(self):
        self.replay_trace((Action("begin", "invalid", "peer", True), Action("worker_verify"),
                           Action("observe_public"), Action("authorize_public"),
                           Action("reconcile", "valid", "public", False, "invalid"), Action("worker_fail"),
                           Action("reconcile", "valid", "public", False, "invalid"), Action("worker_verify")), limit=3)

    def test_cancelled_valid_work_consumes_final_admission_across_reopen(self):
        self.replay_trace((Action("observe_public"), Action("authorize_public"),
                           Action("begin", "valid", "peer", True), Action("worker_cancel")), limit=1, exhausted=True)

    def test_cancelled_reconciliation_preserves_original_and_remaining_recovery(self):
        self.replay_trace((Action("begin", "invalid", "peer", True), Action("worker_verify"),
                           Action("observe_public"), Action("authorize_public"),
                           Action("reconcile", "valid", "public", False, "invalid"), Action("worker_cancel"),
                           Action("reconcile", "valid", "public", False, "invalid"), Action("worker_verify")), limit=3)

    def test_external_disclosure_authorization_and_inclusion_never_write_the_journal(self):
        modeled, calls = self.replay_trace((Action("observe_public", authenticated=True),
                                            Action("authorize_public"), Action("claim_inclusion"), Action("reorg")))
        self.assertTrue(modeled.possible_exposure)
        self.assertEqual(calls, ())

    def test_unauthorized_public_admission_trace_rejects_before_execution(self):
        with self.assertRaises(ValueError):
            self.plan((Action("observe_public"), Action("begin", "valid", "public"), Action("worker_verify")), 2)

    def test_pending_or_interleaved_trace_is_not_misrepresented_as_completed(self):
        with self.assertRaises(ValueError):
            self.plan((Action("begin", "valid", "peer", True),), 2)
        with self.assertRaises(ValueError):
            self.plan((Action("begin", "valid", "peer", True), Action("observe_public"), Action("worker_verify")), 2)

    def test_process_death_trace_is_outside_exception_injection_support(self):
        with self.assertRaises(ValueError):
            self.plan((Action("begin", "valid", "peer", True), Action("worker_crash")), 2)

    def test_bridge_detects_backend_accepting_an_ideal_invalid_candidate(self):
        with self.assertRaises(AssertionError):
            self.replay_trace((Action("begin", "invalid", "peer", True), Action("worker_verify")),
                              recoverer=completion_accepted)


# Only these behavioral cases are replayed by the actual-executable qualifier.
ACTUAL_CASES = (
    "test_generated_shortest_exhaustion_traces_match_pending_and_reopened_state",
    "test_rejected_invalid_retry_blocks_later_authorized_public_reconciliation",
    "test_valid_failure_retry_success_and_replay_survive_external_reorg",
    "test_authorized_public_witness_without_envelope_completes",
    "test_positive_public_reconciliation_archives_the_exact_original",
    "test_reconciliation_failure_keeps_original_before_later_positive_replacement",
    "test_cancelled_valid_work_consumes_final_admission_across_reopen",
    "test_cancelled_reconciliation_preserves_original_and_remaining_recovery",
    "test_external_disclosure_authorization_and_inclusion_never_write_the_journal",
)
