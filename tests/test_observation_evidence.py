"""Evidence binding and claim parsing; fixture callbacks do not verify math."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import completion, exchange, observation_evidence as evidence
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round, nonce_commitment,
    reveal_nonce_round, signing_context,
)
from completion_test_support import completion_accepted, final_signatures, released_bob
from exchange_test_support import accepted, artifacts, prepare


class ObservationEvidenceTests(unittest.TestCase):
    profile = "11" * 32

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.fixture = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
        cls.rounds = json.loads((root / "qualification/fixtures/nonce_rounds.json").read_text("ascii"))["vectors"]
        cls.signature, cls.bitcoin_signature = final_signatures()
        cls.state = released_bob()

    def statement(self, state=None, signature=None, *, outcome="rejected", profile=None):
        """Forge explicit fixture claims; no trusted math producer is selected."""
        raw = evidence.unknown_statement(self.state if state is None else state,
                                         self.signature if signature is None else signature,
                                         verifier_profile_digest_hex=self.profile if profile is None else profile)
        value = json.loads(raw)
        value["outcome"] = outcome
        return exchange.canonical(value)

    def parse(self, raw, state=None, signature=None, *, profile=None):
        return evidence.parse_statement(self.state if state is None else state,
                                        self.signature if signature is None else signature, raw,
                                        expected_verifier_profile_digest_hex=self.profile if profile is None else profile)

    def rebound(self, *, session=False, terms=False, nonce=False, zenon_bundle=False, bitcoin_bundle=False):
        """Rebind public fixture bytes with fake structural checks, not new math."""
        raw = copy.deepcopy(self.fixture["terms"])
        if session:
            raw["session_id"] = "99" * 32
        if terms:
            raw["policy"]["minimum_claim_margin_seconds"] += 1
        agreed = agree_terms(raw)
        bitcoin = bind_bitcoin(agreed, self.fixture["bitcoin_binding"])
        bindings = (bitcoin, bind_zenon(bitcoin, self.fixture["zenon_binding"]))
        contexts = []
        for binding, vector in zip(bindings, self.rounds):
            round_id = "77" * 32 if nonce else vector["round_id_hex"]
            alice, bob = vector["public_nonces_hex"]
            committed = commit_nonce_round(binding, round_id,
                nonce_commitment(binding, round_id, "alice", alice),
                nonce_commitment(binding, round_id, "bob", bob))
            contexts.append(signing_context(binding, "bob", binding.stage + "-claim-partial",
                                           nonce_round=reveal_nonce_round(committed, alice, bob)))
        btc_bundle, znn_bundle = copy.deepcopy(artifacts()[3:])
        if bitcoin_bundle:
            btc_bundle["adaptor_presignature_hex"] = "00" * 65
        if zenon_bundle:
            znn_bundle["adaptor_presignature_hex"] = "00" * 65
        state = exchange.start(contexts[0])
        state = exchange.retain_bitcoin(state, btc_bundle, accepted)
        state = exchange.bind_zenon(state, contexts[1])
        state = exchange.retain_alice_partial(state, znn_bundle["partial_signatures_hex"][0], accepted)
        state = exchange.retain_zenon(state, znn_bundle, accepted)
        return exchange.release(state)[0]

    def test_exact_packet_request_and_independent_domain_separated_hashes(self):
        target = evidence.prepare(self.state, self.signature)
        packet = completion.bob_candidate_from_signature(self.state, self.signature)
        recovery = completion.bob_request(self.state, packet)
        verification = dict(recovery, kind="verify-zenon-completion", bitcoin=None)
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        binding = json.loads(target.binding)
        self.assertEqual(target.candidate_packet, packet)
        self.assertEqual(target.verification_request, canonical(verification))
        self.assertEqual(binding["schema"], evidence.BINDING_SCHEMA)
        self.assertEqual(binding["session_id"], json.loads(packet)["context"]["session_id"])
        self.assertEqual(binding["terms_digest_hex"], artifacts()[0].digest_hex)
        self.assertEqual(binding["candidate_digest_hex"], hashlib.sha256(b"PTLC/completion-observation/v1\0" + packet).hexdigest())
        self.assertEqual(binding["signature_digest_hex"], hashlib.sha256(b"PTLC/observed-signature/v1\0" + self.signature).hexdigest())
        self.assertEqual(binding["recovery_request_digest_hex"], hashlib.sha256(b"PTLC/completion/v1\0" + canonical(recovery)).hexdigest())
        self.assertEqual(binding["verification_request_digest_hex"], hashlib.sha256(b"PTLC/completion/v1\0" + canonical(verification)).hexdigest())
        self.assertEqual(binding["bitcoin_context_digest_hex"], recovery["bitcoin"]["context_digest_hex"])
        self.assertEqual(binding["zenon_context_digest_hex"], recovery["zenon"]["context_digest_hex"])
        digest = hashlib.sha256(b"PTLC/observation-evidence-binding/v1\0" + target.binding).hexdigest()
        self.assertEqual(target.binding_digest_hex, digest)
        key_input = canonical({"binding_digest_hex":digest, "predicate":evidence.PREDICATE,
                               "verifier_profile_digest_hex":self.profile})
        self.assertEqual(evidence.statement_key(self.state, self.signature, verifier_profile_digest_hex=self.profile),
                         hashlib.sha256(b"PTLC/observation-evidence-key/v1\0" + key_input).hexdigest())

    def test_pure_preparation_accepts_invalid_math_without_a_validity_claim(self):
        before = copy.deepcopy(self.state)
        keys = set()
        for signature in (self.signature, self.bitcoin_signature, bytes(64), b"\xff" * 64):
            target = evidence.prepare(self.state, signature)
            self.assertEqual(json.loads(target.candidate_packet)["signature_hex"], signature.hex())
            self.assertNotIn("outcome", json.loads(target.binding))
            keys.add(evidence.statement_key(self.state, signature, verifier_profile_digest_hex=self.profile))
            self.assertEqual(self.state, before)
        self.assertEqual(len(keys), 4)

    def test_same_target_has_same_key_before_and_after_different_candidate_retention(self):
        invalid = completion.bob_candidate_from_signature(self.state, bytes(64))
        retained = completion.observe_bob(self.state, invalid)
        before = copy.deepcopy(retained)
        self.assertEqual(evidence.prepare(retained, self.signature), evidence.prepare(self.state, self.signature))
        self.assertEqual(retained, before)
        self.assertEqual(retained["zenon_completion_packet_hex"], invalid.hex())

    def test_exact_retained_candidate_uses_the_same_predicate_target(self):
        packet = completion.bob_candidate_from_signature(self.state, self.signature)
        retained = completion.observe_bob(self.state, packet)
        self.assertEqual(evidence.prepare(retained, self.signature), evidence.prepare(self.state, self.signature))

    def test_unreleased_and_completed_snapshots_are_not_evidence_targets(self):
        early = exchange.start(artifacts()[1])
        packet = completion.bob_candidate_from_signature(self.state, self.signature)
        finished, _ = completion.complete_bob(self.state, packet, completion_accepted)
        for state in (None, True, [], {}, early, finished):
            with self.subTest(kind=type(state).__name__), self.assertRaises(evidence.EvidenceError):
                evidence.prepare(state, self.signature)

    def test_malformed_context_is_rejected_without_mutation_or_input_disclosure(self):
        state = copy.deepcopy(self.state)
        state["zenon_context"]["nonce_round_digest_hex"] = "99" * 32
        before = copy.deepcopy(state)
        with self.assertRaises(evidence.EvidenceError) as error:
            evidence.prepare(state, self.signature)
        self.assertEqual(str(error.exception), "observation evidence target rejected")
        self.assertEqual(state, before)

    def test_hostile_signature_and_state_types_execute_no_custom_methods(self):
        calls = []
        class HostileBytes(bytes):
            def __len__(self):
                calls.append("length")
                raise RuntimeError("synthetic detail")
            def hex(self):
                calls.append("hex")
                raise RuntimeError("synthetic detail")
        class HostileState(dict):
            def __deepcopy__(self, memo):
                calls.append("copy")
                raise RuntimeError("synthetic detail")
        for signature in (None, True, "00" * 64, bytearray(64), memoryview(bytes(64)), b"", bytes(63), bytes(65), HostileBytes(bytes(64))):
            with self.subTest(kind=type(signature).__name__), self.assertRaises(evidence.EvidenceError):
                evidence.prepare(self.state, signature)
        with self.assertRaises(evidence.EvidenceError):
            evidence.prepare(HostileState(self.state), self.signature)
        self.assertEqual(calls, [])

    def test_profile_is_an_exact_plain_local_digest(self):
        calls = []
        class HostileText(str):
            def __eq__(self, other):
                calls.append("equality")
                raise RuntimeError("synthetic detail")
        for profile in (None, True, 1, bytes(32), "", "11" * 31, "11" * 33, "AA" * 32, "gg" * 32, self.profile + "\n", HostileText(self.profile)):
            for operation in (lambda: evidence.statement_key(self.state, self.signature, verifier_profile_digest_hex=profile),
                              lambda: evidence.unknown_statement(self.state, self.signature, verifier_profile_digest_hex=profile),
                              lambda: self.parse(b"{}", profile=profile if profile is not None else "")):
                with self.subTest(kind=type(profile).__name__), self.assertRaises(evidence.EvidenceError):
                    operation()
        self.assertEqual(calls, [])

    def test_three_explicit_outcomes_are_only_structurally_bound_claims(self):
        before = copy.deepcopy(self.state)
        for outcome in evidence.OUTCOMES:
            parsed = self.parse(self.statement(outcome=outcome))
            self.assertEqual(parsed.outcome, outcome)
            self.assertEqual(self.state, before)
            self.assertEqual(parsed.request_digest_hex, json.loads(evidence.prepare(self.state, self.signature).binding)["verification_request_digest_hex"])
        # A forged success for invalid bytes also parses. The codec supplies no trust.
        self.assertEqual(self.parse(self.statement(signature=bytes(64), outcome="verified"), signature=bytes(64)).outcome, "verified")

    def test_legacy_completion_results_never_become_mathematical_rejection(self):
        packet = completion.bob_candidate_from_signature(self.state, self.signature)
        request = completion.bob_request(self.state, packet)
        for valid in (True, False):
            legacy = exchange.canonical({"schema":completion.RESULT_SCHEMA, "request_digest_hex":completion.request_digest(request),
                                         "valid":valid, "bitcoin_signature_hex":""})
            with self.assertRaises(evidence.EvidenceError):
                self.parse(legacy)
        self.assertEqual(self.parse(evidence.unknown_statement(self.state, self.signature, verifier_profile_digest_hex=self.profile)).outcome, "unknown")

    def test_a_statement_for_other_signature_bytes_is_rejected(self):
        for outcome in evidence.OUTCOMES:
            with self.subTest(outcome=outcome), self.assertRaises(evidence.EvidenceError):
                self.parse(self.statement(signature=bytes(64), outcome=outcome))

    def assert_rebinding_changes_key(self, **changes):
        state = self.rebound(**changes)
        old, new = evidence.prepare(self.state, self.signature), evidence.prepare(state, self.signature)
        self.assertNotEqual(old.binding_digest_hex, new.binding_digest_hex)
        self.assertNotEqual(evidence.statement_key(self.state, self.signature, verifier_profile_digest_hex=self.profile),
                            evidence.statement_key(state, self.signature, verifier_profile_digest_hex=self.profile))
        with self.assertRaises(evidence.EvidenceError):
            self.parse(self.statement(), state=state)
        return old, new

    def test_identical_signature_cannot_transfer_a_statement_to_another_session(self):
        old, new = self.assert_rebinding_changes_key(session=True)
        self.assertEqual(json.loads(old.candidate_packet)["signature_hex"], json.loads(new.candidate_packet)["signature_hex"])

    def test_changed_agreed_terms_invalidate_old_statement(self):
        self.assert_rebinding_changes_key(terms=True)

    def test_changed_nonce_round_invalidate_old_statement(self):
        self.assert_rebinding_changes_key(nonce=True)

    def test_changed_zenon_bundle_binds_more_than_identical_candidate_packet(self):
        old, new = self.assert_rebinding_changes_key(zenon_bundle=True)
        self.assertEqual(old.candidate_packet, new.candidate_packet)
        self.assertNotEqual(old.verification_request, new.verification_request)

    def test_changed_bitcoin_bundle_binds_more_than_identical_zenon_predicate(self):
        old, new = self.assert_rebinding_changes_key(bitcoin_bundle=True)
        self.assertEqual(old.candidate_packet, new.candidate_packet)
        self.assertEqual(old.verification_request, new.verification_request)
        self.assertNotEqual(json.loads(old.binding)["recovery_request_digest_hex"], json.loads(new.binding)["recovery_request_digest_hex"])

    def test_profile_change_separates_identical_inputs_and_prevents_receipt_reuse(self):
        changed = "22" * 32
        self.assertNotEqual(evidence.statement_key(self.state, self.signature, verifier_profile_digest_hex=self.profile),
                            evidence.statement_key(self.state, self.signature, verifier_profile_digest_hex=changed))
        with self.assertRaises(evidence.EvidenceError):
            self.parse(self.statement(), profile=changed)
        self.assertEqual(self.parse(self.statement(profile=changed), profile=changed).verifier_profile_digest_hex, changed)

    def test_each_fixed_field_and_unrecognized_outcome_is_rejected(self):
        value = json.loads(self.statement())
        for field in value:
            replacement = "99" * 32 if field.endswith("_hex") else "synthetic-mismatch"
            forged = dict(value, **{field:replacement})
            with self.subTest(field=field), self.assertRaises(evidence.EvidenceError):
                self.parse(exchange.canonical(forged))
        for outcome in (False, True, 0, None, [], {}, "invalid", "timeout", "cancelled", "error", "REJECTED"):
            with self.subTest(outcome=outcome), self.assertRaises(evidence.EvidenceError):
                self.parse(exchange.canonical(dict(value, outcome=outcome)))

    def test_missing_and_extra_fields_cannot_carry_provenance_or_authority(self):
        value = json.loads(self.statement())
        for field in value:
            missing = dict(value)
            del missing[field]
            with self.subTest(missing=field), self.assertRaises(evidence.EvidenceError):
                self.parse(exchange.canonical(missing))
        for field in ("source", "included", "authenticated", "authorized", "worker_stderr", "refund"):
            with self.subTest(extra=field), self.assertRaises(evidence.EvidenceError):
                self.parse(exchange.canonical(dict(value, **{field:True})))

    def test_noncanonical_duplicate_and_non_ascii_encodings_are_rejected(self):
        value = json.loads(self.statement())
        wire = exchange.canonical(value)
        variants = (wire + b"\n", b" " + wire, json.dumps(value, indent=2).encode("ascii"),
                    wire[:-1] + b',"outcome":"rejected"}',
                    wire.replace(b'"rejected"', b'"reje\\u0063ted"'), b'\xff', b'[]', b'null', b'{}')
        for variant in variants:
            with self.subTest(encoding=variant[:30]), patch.object(evidence, "prepare", side_effect=AssertionError("unexpected target derivation")), self.assertRaises(evidence.EvidenceError):
                self.parse(variant)

    def test_statement_bounds_and_hostile_bytes_do_not_execute_methods(self):
        calls = []
        class HostileBytes(bytes):
            def decode(self, *args):
                calls.append("decode")
                raise RuntimeError("synthetic detail")
            def __len__(self):
                calls.append("length")
                raise RuntimeError("synthetic detail")
        for raw in (None, True, "{}", bytearray(b"{}"), memoryview(b"{}"), b"", b"x" * (evidence.MAX_STATEMENT_BYTES + 1), HostileBytes(self.statement())):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(evidence.EvidenceError):
                self.parse(raw)
        self.assertEqual(calls, [])

    def test_target_and_statement_are_immutable_public_data(self):
        target = evidence.prepare(self.state, self.signature)
        statement = self.parse(self.statement())
        for field in (target.candidate_packet, target.verification_request, target.binding):
            self.assertIs(type(field), bytes)
        with self.assertRaises(FrozenInstanceError):
            target.binding = b"{}"
        with self.assertRaises(FrozenInstanceError):
            statement.outcome = "verified"
        self.assertFalse(hasattr(statement, "authorized"))
        self.assertFalse(hasattr(statement, "signature_hex"))

    def test_unknown_encoding_is_deterministic_and_accepts_no_error_or_worker_payload(self):
        one = evidence.unknown_statement(self.state, self.signature, verifier_profile_digest_hex=self.profile)
        two = evidence.unknown_statement(copy.deepcopy(self.state), self.signature, verifier_profile_digest_hex=self.profile)
        self.assertEqual(one, two)
        self.assertEqual(self.parse(one).outcome, "unknown")
        for field in ("error", "stderr", "returncode", "reason", "callback"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                evidence.unknown_statement(self.state, self.signature, verifier_profile_digest_hex=self.profile, **{field:None})

    def test_api_has_no_source_authentication_context_or_authority_overrides(self):
        for field in ("source", "included", "authenticated", "authorized", "session_id", "context", "verifier", "recoverer"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                evidence.prepare(self.state, self.signature, **{field:True})

    def test_evidence_after_exhaustion_and_reopen_preserves_all_journal_bytes(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-observation-evidence-") as directory:
            base = Path(directory)
            root, anchor = base / "state", base / "head.json"
            with Journal.open(root, anchor) as journal:
                session = prepare(journal, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, invalid, recoverer=lambda _: None)
            with Journal.open(root, anchor) as journal:
                state = journal.get_exchange(session)
                before = (copy.deepcopy(journal._state), journal._sequence,
                          (root / "journal.sqlite3").read_bytes(), anchor.read_bytes())
                for outcome in evidence.OUTCOMES:
                    self.assertEqual(self.parse(self.statement(state, outcome=outcome), state).outcome, outcome)
                evidence.prepare(state, self.signature)
                evidence.statement_key(state, self.signature, verifier_profile_digest_hex=self.profile)
                after = (copy.deepcopy(journal._state), journal._sequence,
                         (root / "journal.sqlite3").read_bytes(), anchor.read_bytes())
                self.assertEqual(after, before)
                self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)
                self.assertEqual(journal.get_exchange(session)["zenon_completion_packet_hex"], invalid.hex())

    def test_a_forged_positive_claim_cannot_replace_history_or_bypass_exhaustion(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-evidence-no-admission-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                session = prepare(journal, recovery_limit=1)
                journal.release_exchange_zenon(session)
                invalid = completion.bob_candidate_from_signature(journal.get_exchange(session), bytes(64))
                with self.assertRaises(Conflict):
                    journal.complete_exchange_bitcoin(session, invalid, recoverer=lambda _: None)
                state = journal.get_exchange(session)
                self.assertEqual(self.parse(self.statement(state, outcome="verified"), state).outcome, "verified")
                candidate = evidence.prepare(state, self.signature).candidate_packet
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, candidate,
                        expected_observation_digest=completion.observation_digest(invalid),
                        recoverer=lambda request: calls.append(request))
                self.assertEqual(calls, [])
                self.assertEqual(journal.get_exchange(session)["zenon_completion_packet_hex"], invalid.hex())
                self.assertIsNone(journal.get_exchange(session)["superseded_zenon_completion_packet_hex"])


if __name__ == "__main__":
    unittest.main()
