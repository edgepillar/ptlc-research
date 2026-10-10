"""Offline original-byte recovery with explicitly synthetic fixture oracles.

These tests do not substitute their oracles for actual cryptographic workers or
authenticated observation. A separate qualifier exercises the Rust executable.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from offline_session.nom_recovery import (
    NomRecovery, RecoveryError, Quarantined, MAX_RECOVERIES, canonical, decode, context,
    synthetic_claim, synthetic_transaction_hash, observation, terms_digest,
    validate_terms, verification_context_digest,
)

ROOT = Path(__file__).resolve().parents[1]
TERMS = json.loads((ROOT / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
FIXTURE = json.loads((ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
PAIR = FIXTURE["pair"]


class FixtureVerifier:
    """Public exact-fixture oracle, never a production signature verifier."""
    def __init__(self, terms=TERMS, pair=PAIR):
        self.context_digest_hex = verification_context_digest(terms, pair)
        self.pair = copy.deepcopy(pair); self.recovery_calls = 0; self.fail = False
    def verify_pair(self): return self.pair == PAIR
    def verify_claim(self, leg, signature): return signature == FIXTURE[leg + "_signature_hex"]
    def recover_long(self, signature):
        self.recovery_calls += 1
        if self.fail: raise RecoveryError("synthetic interrupted public qualifier")
        if signature != FIXTURE["short_signature_hex"]: raise RecoveryError("fixture mismatch")
        return FIXTURE["long_signature_hex"]


class NomRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.base.chmod(0o700)
        self.path = self.base / "alice.log"; self.bob_path = self.base / "bob.log"
        self.short = synthetic_claim(TERMS, "short", FIXTURE["short_signature_hex"])
        self.long = synthetic_claim(TERMS, "long", FIXTURE["long_signature_hex"])

    def open(self, *, role="alice", path=None, verifier=None, observer=None, terms=TERMS, hook=None):
        store = NomRecovery.open(path or (self.path if role == "alice" else self.bob_path), terms, PAIR,
                                 role=role, verifier=verifier or FixtureVerifier(terms),
                                 observation_verifier=observer or (lambda _: True), hook=hook)
        self.addCleanup(store.close); return store

    def fund(self, store):
        for leg in ("long", "short"): store.record_observation(observation(TERMS, leg, "funded"))

    def proof(self, leg="short", kind="unlock-confirmed", *, send="900", receive="1100"):
        wire = self.short if leg == "short" else self.long
        kwargs = {"transaction_hash_hex": synthetic_transaction_hash(wire)}
        if kind in ("send-confirmed", "unlock-confirmed"):
            kwargs.update(send_timestamp=send, send_momentum_hash_hex="aa" * 32)
        if kind == "unlock-confirmed":
            kwargs.update(receive_timestamp=receive, receive_momentum_hash_hex="bb" * 32)
        return observation(TERMS, leg, kind, **kwargs)

    def test_two_party_lost_ack_reopen_and_original_only_recovery(self):
        alice = self.open(); self.fund(alice)
        original_hash = alice.retain_original("short", self.short)
        self.assertEqual(alice.prepare_attempt("short"), self.short)
        alice.close()  # The reference transport acknowledgement was lost.
        alice = self.open()
        self.assertEqual(alice.status()["phases"]["short"], "OUTCOME_UNKNOWN")
        alice.record_observation(self.proof(kind="unseen"))
        self.assertEqual(alice.prepare_attempt("short"), self.short)
        self.assertEqual(synthetic_transaction_hash(self.short), original_hash)
        alice.record_observation(self.proof())
        self.assertEqual(alice.status()["phases"]["short"], "UNLOCK_CONFIRMED")
        verifier = FixtureVerifier(); bob = self.open(role="bob", verifier=verifier); self.fund(bob)
        self.assertEqual(bob.recover_long(self.short, self.proof()), self.long)
        self.assertEqual(bob.prepare_attempt("long"), self.long)
        bob.close(); bob = self.open(role="bob", verifier=verifier)
        self.assertEqual(bob.prepare_attempt("long"), self.long)
        self.assertEqual(bob.recover_long(self.short, self.proof()), self.long)
        self.assertEqual(verifier.recovery_calls, 1)
        self.assertTrue(bob.status()["disclosure_possible"])

    def test_send_confirmation_is_insufficient_for_reverse_leg_recovery(self):
        bob = self.open(role="bob"); self.fund(bob)
        with self.assertRaises(RecoveryError): bob.recover_long(self.short, self.proof(kind="send-confirmed"))
        self.assertNotIn("long", bob.status()["originals"])
        self.assertEqual(bob.status()["recovery_count"], 0)
        self.assertEqual(bytes.fromhex(bob.status()["remote_short_hex"]), self.short)

    def test_missing_funding_or_rejected_observer_cannot_admit_disclosure(self):
        store = self.open(); store.retain_original("short", self.short)
        with self.assertRaises(RecoveryError): store.prepare_attempt("short")
        self.assertFalse(store.status()["disclosure_possible"])
        store.close(); store = self.open(observer=lambda _: False)
        with self.assertRaises(RecoveryError): store.record_observation(observation(TERMS, "long", "funded"))
        self.assertEqual(store.status()["funded"], {})

    def test_wrong_network_entry_and_original_hash_are_refused_without_acceptance(self):
        store = self.open(); self.fund(store); store.retain_original("short", self.short)
        for field, value in (("genesis_hash_hex", "99" * 32), ("chain_id", "1"),
                             ("entry_digest_hex", "99" * 32), ("transaction_hash_hex", "99" * 32),
                             ("terms_digest_hex", "99" * 32)):
            proof = self.proof(); proof[field] = value
            with self.subTest(field=field), self.assertRaises(RecoveryError): store.record_observation(proof)
        self.assertEqual(store.status()["phases"]["short"], "ORIGINAL_RETAINED")

    def test_expiry_uses_send_confirmation_and_allows_delayed_contract_receive(self):
        store = self.open(); self.fund(store); store.retain_original("short", self.short)
        with self.assertRaises(RecoveryError): store.record_observation(self.proof(send="1000", receive="1100"))
        store.record_observation(self.proof(send="999", receive="1500"))
        self.assertEqual(store.status()["phases"]["short"], "UNLOCK_CONFIRMED")
        with self.assertRaises(RecoveryError): store.prepare_attempt("short")

    def test_reorg_and_absence_preserve_disclosure_and_forbid_replacement(self):
        store = self.open(); self.fund(store); store.retain_original("short", self.short); store.prepare_attempt("short")
        store.record_observation(self.proof()); store.record_observation(self.proof(kind="reorged"))
        state = store.status(); self.assertTrue(state["disclosure_possible"])
        self.assertEqual(state["phases"]["short"], "OUTCOME_UNKNOWN")
        self.assertEqual(bytes.fromhex(state["originals"]["short"]), self.short)
        with self.assertRaises(RecoveryError): store.prepare_attempt("short")
        store.record_observation(observation(TERMS, "short", "funded"))
        self.assertEqual(store.prepare_attempt("short"), self.short)

    def test_original_context_signature_and_role_replacement_are_refused(self):
        store = self.open(); self.fund(store); store.retain_original("short", self.short)
        changed = decode(self.short); changed["context"]["destination_hex"] = TERMS["bob_address_hex"]
        for wire in (canonical(changed), self.long, synthetic_claim(TERMS, "short", "00" * 64)):
            with self.assertRaises(RecoveryError): store.retain_original("short", wire)
        self.assertEqual(store.retain_original("short", self.short), synthetic_transaction_hash(self.short))
        with self.assertRaises(RecoveryError): store.retain_original("long", self.long)

    def test_failed_public_recovery_retains_original_and_consumes_allowance(self):
        verifier = FixtureVerifier(); verifier.fail = True
        bob = self.open(role="bob", verifier=verifier); self.fund(bob)
        for _ in range(MAX_RECOVERIES):
            with self.assertRaises(RecoveryError): bob.recover_long(self.short, self.proof())
        self.assertEqual(bob.status()["recovery_count"], MAX_RECOVERIES)
        self.assertEqual(bytes.fromhex(bob.status()["remote_short_hex"]), self.short)
        verifier.fail = False
        with self.assertRaises(RecoveryError): bob.recover_long(self.short, self.proof())
        self.assertEqual(verifier.recovery_calls, MAX_RECOVERIES)

    def test_durable_attempt_cut_before_output_recovers_unknown_original(self):
        def cut(kind):
            if kind == "attempt": raise RuntimeError("synthetic output loss")
        store = self.open(hook=cut); self.fund(store); store.retain_original("short", self.short)
        with self.assertRaises(Quarantined): store.prepare_attempt("short")
        with self.assertRaises(Quarantined): store.status()
        store.close(); reopened = self.open()
        self.assertEqual(reopened.status()["phases"]["short"], "OUTCOME_UNKNOWN")
        self.assertEqual(reopened.prepare_attempt("short"), self.short)

    def test_fsync_failure_returns_no_disclosure_bytes_and_poisons_owner(self):
        store = self.open(); self.fund(store); store.retain_original("short", self.short)
        with patch("offline_session.nom_recovery.os.fsync", side_effect=OSError("synthetic")):
            with self.assertRaises(Quarantined): store.prepare_attempt("short")
        with self.assertRaises(Quarantined): store.prepare_attempt("short")
        store.close()  # No rollback or truncation is attempted.
        self.assertIn(b'"kind":"attempt"', self.path.read_bytes())

    def test_truncated_or_changed_original_log_is_quarantined_and_preserved(self):
        store = self.open(); self.fund(store); store.retain_original("short", self.short); store.close()
        original = self.path.read_bytes()
        for changed in (original[:-1], original.replace(b'"amount":"100"', b'"amount":"101"', 1)):
            self.path.write_bytes(changed)
            with self.assertRaises(RecoveryError): self.open()
            self.assertEqual(self.path.read_bytes(), changed)

    def test_coherent_old_log_restore_is_an_explicit_counterexample(self):
        store = self.open(); self.fund(store); store.retain_original("short", self.short); old = self.path.read_bytes()
        store.prepare_attempt("short"); store.close(); self.path.write_bytes(old)
        reopened = self.open()
        self.assertFalse(reopened.status()["disclosure_possible"])
        self.assertEqual(reopened.prepare_attempt("short"), self.short)
        # This acceptance proves the absence of anti-rollback protection.

    def test_concurrent_owner_wrong_thread_and_replaced_inode_are_refused(self):
        store = self.open()
        with self.assertRaises(RecoveryError): self.open()
        results = []
        def other_thread():
            try: store.status()
            except RecoveryError: results.append("refused")
        thread = threading.Thread(target=other_thread); thread.start(); thread.join()
        self.assertEqual(results, ["refused"])
        self.path.rename(self.base / "old.log"); self.path.write_bytes(b"synthetic"); self.path.chmod(0o600)
        with self.assertRaises(RecoveryError): store.status()

    def test_symlink_hardlink_or_broad_file_permissions_are_refused(self):
        store = self.open(); store.close()
        original = self.path.read_bytes(); self.path.chmod(0o644)
        with self.assertRaises(RecoveryError): self.open()
        self.path.chmod(0o600); os.link(self.path, self.base / "link.log")
        with self.assertRaises(RecoveryError): self.open()
        (self.base / "link.log").unlink(); self.path.rename(self.base / "real.log")
        self.path.symlink_to(self.base / "real.log")
        with self.assertRaises(RecoveryError): self.open()
        self.assertEqual((self.base / "real.log").read_bytes(), original)

    def test_terms_are_frozen_and_wrong_context_or_role_cannot_reopen(self):
        mutable = copy.deepcopy(TERMS); store = self.open(terms=mutable)
        mutable["long"]["amount"] = "999"; returned = store.terms; returned["short"]["amount"] = "999"
        self.assertEqual(store.terms, TERMS); store.close()
        for field in ("amount", "token_standard_hex", "expires_at"):
            changed = copy.deepcopy(TERMS); changed["long"][field] = {"amount":"101", "token_standard_hex":"03"*10, "expires_at":"2001"}[field]
            with self.assertRaises(RecoveryError): self.open(terms=changed)
        with self.assertRaises(RecoveryError): self.open(role="bob", path=self.path)
        verifier = FixtureVerifier(); verifier.context_digest_hex = "99" * 32
        with self.assertRaises(RecoveryError): self.open(verifier=verifier)

    def test_reference_codec_refuses_noncanonical_ambiguous_and_oversized_wire(self):
        for wire in (b'{"x":1,"x":1}', b' {"x":1}', b'{"x":NaN}', b'"' + b'a'*8192 + b'"'):
            with self.assertRaises(RecoveryError): decode(wire)
        for change in (("amount", "0200"), ("expires_at", "1501"), ("recipient", "bob")):
            terms = copy.deepcopy(TERMS); terms["short"][change[0]] = change[1]
            with self.assertRaises(RecoveryError): validate_terms(terms)

    def test_term_commitment_binds_amount_token_genesis_and_safety_gap(self):
        for mutate in (lambda t:t["long"].update(amount="101"), lambda t:t["long"].update(token_standard_hex="03"*10),
                       lambda t:t.update(genesis_hash_hex="99"*32), lambda t:t.update(minimum_expiry_gap_seconds="501")):
            changed = copy.deepcopy(TERMS); mutate(changed)
            self.assertNotEqual(terms_digest(changed), terms_digest(TERMS))
        self.assertNotEqual(context(TERMS,"long"), context(TERMS,"short"))

    def test_status_and_observer_copies_cannot_mutate_retained_history(self):
        def observer(proof): proof["leg"] = "invalid"; return True
        store = self.open(observer=observer); self.fund(store)
        state = store.status(); state["funded"].clear()
        self.assertEqual(store.status()["funded"], {"long":True,"short":True})

    def test_absence_cannot_downgrade_execution_and_confirming_momentum_is_immutable(self):
        store = self.open(); self.fund(store); store.retain_original("short", self.short)
        store.record_observation(self.proof(kind="send-confirmed")); store.record_observation(self.proof())
        store.record_observation(self.proof(kind="unseen")); store.record_observation(self.proof(kind="send-confirmed"))
        self.assertEqual(store.status()["phases"]["short"], "UNLOCK_CONFIRMED")
        changed = self.proof(); changed["send_momentum_hash_hex"] = "cc" * 32
        with self.assertRaises(RecoveryError): store.record_observation(changed)
        with self.assertRaises(RecoveryError): store.record_observation(self.proof(send="901"))
        store.record_observation(self.proof(kind="reorged"))
        store.record_observation(changed)
        self.assertEqual(store.status()["confirmations"]["short"]["send_momentum_hash_hex"], "cc" * 32)

    def test_process_death_cuts_preserve_originals_and_recovery_ownership(self):
        for role, cut in (("alice", "original"), ("alice", "attempt"), ("bob", "remote-short"),
                          ("bob", "recovery-admitted"), ("bob", "recovered")):
            with self.subTest(role=role, cut=cut):
                path = self.base / (role + "-" + cut + ".log")
                result = subprocess.run([sys.executable, str(ROOT / "tests/nom_recovery_actor.py"), str(path), role, cut],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 72, "disposable actor did not reach its cut")
                verifier = FixtureVerifier(); store = self.open(role=role, path=path, verifier=verifier)
                if role == "alice":
                    self.assertEqual(bytes.fromhex(store.status()["originals"]["short"]), self.short)
                    self.assertEqual(store.prepare_attempt("short"), self.short)
                else:
                    self.assertEqual(bytes.fromhex(store.status()["remote_short_hex"]), self.short)
                    self.assertEqual(store.recover_long(self.short, self.proof()), self.long)
                    self.assertEqual(store.prepare_attempt("long"), self.long)
                    if cut == "recovered": self.assertEqual(verifier.recovery_calls, 0)
                store.close()
