"""Actual reference journals with explicit fixture oracles, not chain evidence."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from offline_session.nom_recovery import (
    NomRecovery, RecoveryError, canonical, observation, synthetic_claim,
    synthetic_transaction_hash,
)
from offline_session.nom_recovery_snapshot import SnapshotNomRecovery
from test_nom_recovery import TERMS, PAIR, FIXTURE, FixtureVerifier


class NomRecoverySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.short = synthetic_claim(TERMS, "short", FIXTURE["short_signature_hex"])
        self.long = synthetic_claim(TERMS, "long", FIXTURE["long_signature_hex"])

    def open(self, *, role="alice", observer=None, verifier=None, name=None, historical=False):
        kind = NomRecovery if historical else SnapshotNomRecovery
        path = self.root / (name or role + ".log")
        store = kind.open(path, TERMS, PAIR, role=role,
            verifier=FixtureVerifier() if verifier is None else verifier,
            observation_verifier=(lambda _: True) if observer is None else observer)
        self.addCleanup(store.close)
        return store

    def fund(self, store):
        for leg in ("long", "short"):
            store.record_observation(observation(TERMS, leg, "funded"))

    def confirmed(self):
        return observation(TERMS, "short", "unlock-confirmed",
            transaction_hash_hex=synthetic_transaction_hash(self.short),
            send_timestamp="900", send_momentum_hash_hex="aa" * 32,
            receive_timestamp="1100", receive_momentum_hash_hex="bb" * 32)

    def test_only_the_verified_caller_snapshot_is_retained(self):
        selected = observation(TERMS, "long", "funded")
        caller = copy.deepcopy(selected)
        examined = []
        def verifier(argument):
            examined.append(copy.deepcopy(argument))
            caller.clear()
            caller.update(observation(TERMS, "short", "funded"))
            return argument == selected
        store = self.open(observer=verifier)
        store.record_observation(caller)
        self.assertEqual(examined, [selected])
        self.assertEqual(store.status()["funded"], {"long": True})
        self.assertEqual(store.status()["observations"], [selected])
        record = json.loads((self.root / "alice.log").read_bytes().splitlines()[-1])
        self.assertEqual(record["event"]["proof"], selected)

    def test_callback_argument_mutation_is_refused_without_an_append(self):
        selected = observation(TERMS, "long", "funded")
        def verifier(argument):
            argument.clear()
            argument.update(observation(TERMS, "short", "funded"))
            return True
        store = self.open(observer=verifier)
        before = (self.root / "alice.log").read_bytes()
        with self.assertRaises(RecoveryError):
            store.record_observation(selected)
        self.assertEqual((self.root / "alice.log").read_bytes(), before)
        self.assertEqual(store.status()["funded"], {})

    def test_oversized_callback_result_cannot_become_an_observation(self):
        def verifier(argument):
            argument["unselected"] = "x" * 8192
            return True
        store = self.open(observer=verifier)
        before = (self.root / "alice.log").read_bytes()
        with self.assertRaises(RecoveryError):
            store.record_observation(observation(TERMS, "long", "funded"))
        self.assertEqual((self.root / "alice.log").read_bytes(), before)

    def test_a_rejected_proof_cannot_be_substituted_by_its_caller_alias(self):
        caller = observation(TERMS, "long", "funded")
        def verifier(_):
            caller.clear()
            caller.update(observation(TERMS, "short", "funded"))
            return False
        store = self.open(observer=verifier)
        before = (self.root / "alice.log").read_bytes()
        with self.assertRaises(RecoveryError):
            store.record_observation(caller)
        self.assertEqual((self.root / "alice.log").read_bytes(), before)
        self.assertEqual(store.status()["observations"], [])

    def test_verifier_failure_preserves_the_actual_journal(self):
        def verifier(_):
            raise RecoveryError("synthetic observation failure")
        store = self.open(observer=verifier)
        before = (self.root / "alice.log").read_bytes()
        with self.assertRaises(RecoveryError):
            store.record_observation(observation(TERMS, "long", "funded"))
        self.assertEqual((self.root / "alice.log").read_bytes(), before)
        self.assertEqual(store.status()["funded"], {})

    def test_only_exact_true_admits_the_snapshot(self):
        for index, result in enumerate((False, None, 1, "true")):
            with self.subTest(result=result):
                store = self.open(observer=lambda _, value=result: value, name="refusal-" + str(index) + ".log")
                with self.assertRaises(RecoveryError):
                    store.record_observation(observation(TERMS, "long", "funded"))
                self.assertEqual(store.status()["funded"], {})

    def test_repeated_verified_snapshot_is_idempotent(self):
        selected = observation(TERMS, "long", "funded")
        caller = copy.deepcopy(selected)
        calls = []
        def verifier(argument):
            calls.append(copy.deepcopy(argument))
            caller.clear()
            caller.update(observation(TERMS, "short", "funded"))
            return True
        store = self.open(observer=verifier)
        store.record_observation(caller)
        before = (self.root / "alice.log").read_bytes()
        caller = copy.deepcopy(selected)
        store.record_observation(caller)
        self.assertEqual((self.root / "alice.log").read_bytes(), before)
        self.assertEqual(calls, [selected, selected])

    def test_reopen_preserves_the_selected_original_observation(self):
        selected = observation(TERMS, "long", "funded")
        caller = copy.deepcopy(selected)
        def verifier(_):
            caller["leg"] = "short"
            return True
        store = self.open(observer=verifier)
        store.record_observation(caller)
        store.close()
        reopened = self.open()
        self.assertEqual(reopened.status()["funded"], {"long": True})
        self.assertEqual(reopened.status()["observations"], [selected])

    def test_recovery_freezes_the_proof_before_public_verifier_calls(self):
        caller = self.confirmed()
        selected = copy.deepcopy(caller)
        class MutatingVerifier(FixtureVerifier):
            def verify_claim(self, leg, signature):
                if leg == "short":
                    caller.clear()
                    caller.update(observation(TERMS, "short", "funded"))
                return super().verify_claim(leg, signature)
        store = self.open(role="bob", verifier=MutatingVerifier())
        self.fund(store)
        self.assertEqual(store.recover_long(self.short, caller), self.long)
        self.assertEqual(store.status()["observations"][-1], selected)
        self.assertEqual(store.status()["recovery_count"], 1)
        self.assertEqual(bytes.fromhex(store.status()["remote_short_hex"]), self.short)

    def test_recovery_keeps_the_observer_verified_confirmation(self):
        caller = self.confirmed()
        selected = copy.deepcopy(caller)
        def observer(argument):
            if argument["kind"] == "unlock-confirmed":
                caller.clear()
                caller.update(observation(TERMS, "short", "funded"))
            return True
        verifier = FixtureVerifier()
        store = self.open(role="bob", observer=observer, verifier=verifier)
        self.fund(store)
        self.assertEqual(store.recover_long(self.short, caller), self.long)
        self.assertEqual(store.status()["observations"][-1], selected)
        self.assertEqual(store.prepare_attempt("long"), self.long)
        self.assertEqual(store.status()["phases"]["long"], "OUTCOME_UNKNOWN")
        store.close()
        reopened = self.open(role="bob", verifier=verifier)
        self.assertEqual(reopened.recover_long(self.short, self.confirmed()), self.long)
        self.assertEqual(verifier.recovery_calls, 1)

    def test_snapshot_does_not_authorize_a_send_acknowledgment(self):
        store = self.open(role="bob")
        self.fund(store)
        proof = self.confirmed()
        proof.update(kind="send-confirmed", receive_timestamp="0", receive_momentum_hash_hex="")
        with self.assertRaises(RecoveryError):
            store.recover_long(self.short, proof)
        self.assertEqual(store.status()["recovery_count"], 0)
        self.assertEqual(bytes.fromhex(store.status()["remote_short_hex"]), self.short)

    def test_invalid_selected_context_never_reaches_the_observer(self):
        calls = []
        store = self.open(observer=lambda proof: calls.append(proof) or True)
        for field in ("genesis_hash_hex", "entry_digest_hex", "terms_digest_hex"):
            proof = observation(TERMS, "long", "funded")
            proof[field] = "99" * 32
            with self.subTest(field=field), self.assertRaises(RecoveryError):
                store.record_observation(proof)
        self.assertEqual(calls, [])
        self.assertEqual(store.status()["observations"], [])

    def test_historical_alias_counterexample_remains_explicit(self):
        selected = observation(TERMS, "long", "funded")
        caller = copy.deepcopy(selected)
        examined = []
        def observer(argument):
            examined.append(copy.deepcopy(argument))
            caller.clear()
            caller.update(observation(TERMS, "short", "funded"))
            return True
        store = self.open(historical=True, observer=observer)
        store.record_observation(caller)
        self.assertEqual(examined, [selected])
        self.assertEqual(store.status()["funded"], {"short": True})
        self.assertNotEqual(store.status()["observations"], examined)

    def test_open_does_not_retroactively_authenticate_historical_records(self):
        caller = observation(TERMS, "long", "funded")
        def observer(_):
            caller.clear()
            caller.update(observation(TERMS, "short", "funded"))
            return True
        old = self.open(historical=True, observer=observer)
        old.record_observation(caller)
        old.close()
        before = (self.root / "alice.log").read_bytes()
        reopened = self.open(observer=lambda _: False)
        self.assertEqual((self.root / "alice.log").read_bytes(), before)
        self.assertEqual(reopened.status()["funded"], {"short": True})
        # Replay retains old semantics; it is not a migration or a new approval.


class NomSnapshotQualifierProfileTests(unittest.TestCase):
    def test_optimized_process_refuses_before_evidence_or_worker_access(self):
        program = '''
from pathlib import Path
from unittest.mock import patch
from scripts.qualify_nom_recovery_snapshot import exercise, qualify
with patch("scripts.qualify_nom_recovery_snapshot.NomPublicVerifier", side_effect=AssertionError("worker accessed")), \\
     patch("scripts.qualify_nom_recovery_snapshot.Path.is_absolute", side_effect=AssertionError("evidence accessed")), \\
     patch("scripts.qualify_nom_recovery_snapshot.Path.read_text", side_effect=AssertionError("fixture accessed")):
    for operation in (lambda: qualify(Path("unselected"), "00" * 32, Path("unselected")),
                      lambda: exercise(None, Path("unselected"))):
        try:
            operation()
        except ValueError as error:
            if str(error) != "snapshot qualification requires assertions enabled":
                raise RuntimeError("unexpected refusal") from None
        else:
            raise RuntimeError("optimized qualification was admitted")
print("PASS: both optimized entries refused before evidence, fixture or worker access")
'''
        result = subprocess.run([sys.executable, "-B", "-O", "-c", program],
            cwd=Path(__file__).resolve().parents[1], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout,
            b"PASS: both optimized entries refused before evidence, fixture or worker access\n")


if __name__ == "__main__":
    unittest.main()
