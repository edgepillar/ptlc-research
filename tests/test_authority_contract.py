"""Candidate message binding; forged replies are not external authority evidence."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from offline_session import authority_contract as contract, completion, exchange
from offline_session import observation_evidence as evidence
from offline_session.journal import Conflict, Journal, RecoveryExhausted
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round, nonce_commitment,
    reveal_nonce_round, signing_context,
)
from completion_test_support import completion_accepted, final_signatures, released_bob
from exchange_test_support import accepted, artifacts, prepare


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


class AuthorityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.signature = final_signatures()[0]
        cls.selection = dict(authority_id_hex="11" * 32, enrollment_id_hex="22" * 32,
            authority_epoch=1, authority_profile_digest_hex="33" * 32,
            verifier_profile_digest_hex="44" * 32, pool_profile_digest_hex="55" * 32,
            resource_profile_digest_hex="66" * 32, attempt_limit=2, target_limit=2)
        cls.scope = contract.authority_scope(cls.state, **cls.selection)

    def request(self, *, operation="reserve", head=None, signature=None, scope=None,
                state=None, request_id="77" * 32, attempt=None, statement=None):
        return contract.authority_request(self.scope if scope is None else scope,
            self.state if state is None else state, self.signature if signature is None else signature,
            operation=operation, request_id_hex=request_id,
            expected_head=contract.AuthorityHead(0, "88" * 32, 0) if head is None else head,
            attempt_id=attempt, statement=statement)

    def statement(self, *, signature=None, profile=None, outcome="unknown"):
        """Forge a bound fixture claim; no mathematical producer is selected."""
        value = json.loads(evidence.unknown_statement(self.state,
            self.signature if signature is None else signature,
            verifier_profile_digest_hex=self.selection["verifier_profile_digest_hex"] if profile is None else profile))
        value["outcome"] = outcome
        return canonical(value)

    def reply(self, request, *, status=None):
        """Construct forgeable public labels, not a real authority response."""
        value = request.as_dict()
        before = value["expected_head"]
        selected = contract.SUCCESS[value["operation"]] if status is None else status
        after, attempt = None, None
        if selected == "not-applied":
            after = copy.deepcopy(before)
        elif selected != "unresolved":
            after = dict(before, revision=before["revision"] + 1, state_digest_hex="aa" * 32)
            attempt = value["attempt_id"]
            if value["operation"] == "reserve":
                attempt = before["consumed"] + 1
                after.update(consumed=attempt, pending_attempt_id=attempt)
            elif value["operation"] == "dispatch":
                after["dispatch_recorded"] = True
            else:
                after.update(pending_attempt_id=None, dispatch_recorded=False)
        return dict(schema=contract.REPLY_SCHEMA, operation=value["operation"],
            scope_digest_hex=value["scope_digest_hex"], authority_epoch=value["authority_epoch"],
            request_id_hex=value["request_id_hex"], request_digest_hex=request.digest_hex,
            before_head=copy.deepcopy(before), status=selected, after_head=after, attempt_id=attempt)

    def rebound(self, change):
        """Change retained fixture context using structural oracles only."""
        root = Path(__file__).resolve().parents[1]
        fixture = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
        rounds = json.loads((root / "qualification/fixtures/nonce_rounds.json").read_text("ascii"))["vectors"]
        if change == "session":
            fixture["terms"]["session_id"] = "99" * 32
        if change == "terms":
            fixture["terms"]["policy"]["minimum_claim_margin_seconds"] += 1
        agreed = agree_terms(fixture["terms"])
        bitcoin = bind_bitcoin(agreed, fixture["bitcoin_binding"])
        contexts = []
        for binding, vector in zip((bitcoin, bind_zenon(bitcoin, fixture["zenon_binding"])), rounds):
            round_id = "77" * 32 if change == "nonce" else vector["round_id_hex"]
            alice, bob = vector["public_nonces_hex"]
            committed = commit_nonce_round(binding, round_id,
                nonce_commitment(binding, round_id, "alice", alice),
                nonce_commitment(binding, round_id, "bob", bob))
            contexts.append(signing_context(binding, "bob", binding.stage + "-claim-partial",
                nonce_round=reveal_nonce_round(committed, alice, bob)))
        btc_bundle, znn_bundle = copy.deepcopy(artifacts()[3:])
        if change == "bitcoin_bundle":
            btc_bundle["adaptor_presignature_hex"] = "00" * 65
        if change == "zenon_bundle":
            znn_bundle["adaptor_presignature_hex"] = "00" * 65
        state = exchange.start(contexts[0])
        state = exchange.retain_bitcoin(state, btc_bundle, accepted)
        state = exchange.bind_zenon(state, contexts[1])
        state = exchange.retain_alice_partial(state, znn_bundle["partial_signatures_hex"][0], accepted)
        state = exchange.retain_zenon(state, znn_bundle, accepted)
        return exchange.release(state)[0]

    def test_scope_hashes_bind_both_retained_legs_with_independent_domains(self):
        value = self.scope.as_dict()
        bitcoin, zenon = exchange.contexts(self.state)
        self.assertEqual(value["session_id"], bitcoin.session_id)
        self.assertEqual(value["terms_digest_hex"], artifacts()[0].digest_hex)
        self.assertEqual(value["bitcoin_context_digest_hex"], bitcoin.digest_hex)
        self.assertEqual(value["zenon_context_digest_hex"], zenon.digest_hex)
        for name in ("bitcoin", "zenon"):
            digest = hashlib.sha256(("PTLC/authority-" + name + "-bundle/v1\0").encode("ascii")
                + canonical(self.state[name + "_bundle"])).hexdigest()
            self.assertEqual(value[name + "_bundle_digest_hex"], digest)
        self.assertEqual(value["release_digest_hex"], hashlib.sha256(
            b"PTLC/authority-release/v1\0" + bytes.fromhex(self.state["release_hex"])).hexdigest())
        self.assertEqual(self.scope.canonical_bytes, canonical(value))
        self.assertEqual(self.scope.digest_hex, hashlib.sha256(
            b"PTLC/observation-authority-scope/v1\0" + canonical(value)).hexdigest())
        self.assertLessEqual(len(self.scope.canonical_bytes), contract.MAX_SCOPE_BYTES)

    def test_scope_excludes_candidate_and_local_labels_without_refreshing_selected_budget(self):
        for signature in (self.signature, bytes(64), b"\xff" * 64):
            packet = completion.bob_candidate_from_signature(self.state, signature)
            retained = completion.observe_bob(self.state, packet)
            before = copy.deepcopy(retained)
            scoped = contract.authority_scope(retained, **self.selection)
            self.assertEqual(scoped, self.scope)
            self.assertEqual(retained, before)
        for field in ("signature", "store_id", "path", "pool_path", "request_id", "worker", "enroll"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                contract.authority_scope(self.state, **self.selection, **{field:None})
        self.assertEqual(contract.authority_scope(copy.deepcopy(self.state), **self.selection), self.scope)

    def test_every_selected_external_input_separates_context_but_grants_no_enrollment(self):
        for field, old in self.selection.items():
            new = old + 1 if type(old) is int else "99" * 32
            scope = contract.authority_scope(self.state, **dict(self.selection, **{field:new}))
            with self.subTest(field=field):
                self.assertNotEqual(scope.digest_hex, self.scope.digest_hex)
                self.assertFalse(hasattr(scope, "authorized"))
                self.assertFalse(hasattr(scope, "enrolled"))
                self.assertFalse(hasattr(scope, "quota_granted"))

    def test_context_nonce_bundle_terms_and_release_changes_refuse_old_selected_scope(self):
        for change in ("session", "terms", "nonce", "bitcoin_bundle", "zenon_bundle"):
            state = self.rebound(change)
            changed = contract.authority_scope(state, **self.selection)
            with self.subTest(change=change):
                self.assertNotEqual(changed.digest_hex, self.scope.digest_hex)
                with self.assertRaises(contract.AuthorityContractError):
                    self.request(state=state)
        value = contract.authority_scope(self.rebound("zenon_bundle"), **self.selection).as_dict()
        self.assertNotEqual(value["release_digest_hex"], self.scope.as_dict()["release_digest_hex"])

    def test_scope_selection_exact_types_and_bounds_are_checked_without_state_access(self):
        for field, old in self.selection.items():
            invalid = (True, False, 0, -1, 1.0, None, contract.MAX_NUMBER + 1) if type(old) is int else (
                None, True, 1, bytes(32), "", "aa" * 31, "aa" * 33, "AA" * 32, "gg" * 32, old + "\n")
            if field in ("attempt_limit", "target_limit"):
                invalid += (contract.MAX_LIMIT + 1,)
            for new in invalid:
                with self.subTest(field=field, kind=type(new).__name__), self.assertRaises(contract.AuthorityContractError):
                    contract.authority_scope(None, **dict(self.selection, **{field:new}))
        selected = dict(self.selection, authority_epoch=contract.MAX_NUMBER,
                        attempt_limit=contract.MAX_LIMIT, target_limit=contract.MAX_LIMIT)
        self.assertEqual(contract.authority_scope(self.state, **selected).as_dict()["authority_epoch"], contract.MAX_NUMBER)

    def test_only_valid_retained_release_snapshots_can_prepare_a_scope(self):
        packet = completion.bob_candidate_from_signature(self.state, self.signature)
        finished, _ = completion.complete_bob(self.state, packet, completion_accepted)
        broken = copy.deepcopy(self.state)
        broken["zenon_context"]["nonce_round_digest_hex"] = "99" * 32
        for state in (None, [], True, {}, exchange.start(artifacts()[1]), finished, broken):
            before = copy.deepcopy(state)
            with self.subTest(kind=type(state).__name__), self.assertRaises(contract.AuthorityContractError) as error:
                contract.authority_scope(state, **self.selection)
            self.assertEqual(state, before)
            self.assertNotIn("99" * 32, str(error.exception))

    def test_scope_request_and_head_are_immutable_with_defensive_public_values(self):
        request = self.request()
        head = contract.AuthorityHead(0, "88" * 32, 0)
        for value, field, replacement in ((self.scope, "_wire", b"{}"), (request, "_wire", b"{}"), (head, "consumed", 1)):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field, replacement)
        value = self.scope.as_dict()
        value["attempt_limit"] = 64
        packet = request.as_dict()
        packet["expected_head"]["consumed"] = 64
        self.assertEqual(self.scope.as_dict()["attempt_limit"], 2)
        self.assertEqual(request.as_dict()["expected_head"]["consumed"], 0)
        for cls in (contract.AuthorityScope, contract.AuthorityRequest):
            with self.assertRaises(TypeError):
                cls()

    def test_head_partition_rejects_aliases_and_inconsistent_pending_markers(self):
        base = dict(revision=1, state_digest_hex="88" * 32, consumed=1,
                    pending_attempt_id=1, dispatch_recorded=False)
        changes = (("revision", True), ("revision", 1.0), ("revision", 0),
                   ("revision", contract.MAX_NUMBER + 1), ("consumed", True),
                   ("consumed", 1.0), ("consumed", -1), ("consumed", 65),
                   ("pending_attempt_id", True), ("pending_attempt_id", 1.0),
                   ("pending_attempt_id", 0), ("pending_attempt_id", 2),
                   ("state_digest_hex", "AA" * 32), ("dispatch_recorded", 0))
        for field, value in changes:
            with self.subTest(field=field, value=value), self.assertRaises(contract.AuthorityContractError):
                contract.AuthorityHead(**dict(base, **{field:value}))
        with self.assertRaises(contract.AuthorityContractError):
            contract.AuthorityHead(1, "88" * 32, 1, None, True)
        with self.assertRaises(contract.AuthorityContractError):
            contract.AuthorityHead(2, "88" * 32, 2, 1)

    def test_reserve_request_hash_binds_exact_evidence_and_full_selected_head(self):
        request = self.request()
        value = request.as_dict()
        target = evidence.prepare(self.state, self.signature)
        fields = evidence._fields(target, self.selection["verifier_profile_digest_hex"])
        self.assertEqual(value["target"], {key:fields[key] for key in contract._TARGET})
        self.assertEqual(value["expected_head"], contract.AuthorityHead(0, "88" * 32, 0).as_dict())
        self.assertIs(contract.parse_request(request, request.canonical_bytes), request)
        self.assertEqual(request.digest_hex, hashlib.sha256(
            b"PTLC/observation-authority-request/v1\0" + canonical(value)).hexdigest())

    def test_request_cannot_change_or_extend_any_locally_selected_field(self):
        request = self.request()
        value = request.as_dict()
        for field in value:
            changed = dict(value, **{field:None})
            if value[field] is None:
                changed[field] = True
            missing = dict(value)
            del missing[field]
            for packet in (changed, missing):
                with self.subTest(field=field), self.assertRaises(contract.AuthorityContractError):
                    contract.parse_request(request, canonical(packet))
        for field in ("source", "authenticated", "authorized", "can_start", "refund"):
            with self.subTest(field=field), self.assertRaises(contract.AuthorityContractError):
                contract.parse_request(request, canonical(dict(value, **{field:True})))

    def test_all_operations_require_their_exact_pending_phase_and_statement_partition(self):
        reserved = contract.AuthorityHead(1, "88" * 32, 1, 1)
        dispatched = contract.AuthorityHead(2, "88" * 32, 1, 1, True)
        for operation, head, statement in (("dispatch", reserved, None),
                ("publish", dispatched, self.statement()), ("resolve-unknown", reserved, None),
                ("resolve-unknown", dispatched, None)):
            request = self.request(operation=operation, head=head, attempt=1, statement=statement)
            self.assertEqual(request.as_dict()["operation"], operation)
            for attempt in (None, True, 1.0, 0, 2):
                with self.subTest(operation=operation, attempt=attempt), self.assertRaises(contract.AuthorityContractError):
                    self.request(operation=operation, head=head, attempt=attempt, statement=statement)
        invalid = (("dispatch", dispatched, None), ("publish", reserved, self.statement()),
                   ("publish", dispatched, None), ("dispatch", reserved, self.statement()),
                   ("resolve-unknown", reserved, self.statement()))
        for operation, head, statement in invalid:
            with self.subTest(operation=operation), self.assertRaises(contract.AuthorityContractError):
                self.request(operation=operation, head=head, attempt=1, statement=statement)

    def test_available_head_is_required_and_no_epoch_or_quota_reset_is_automatic(self):
        heads = (contract.AuthorityHead(1, "88" * 32, 1, 1),
                 contract.AuthorityHead(3, "88" * 32, 2),
                 contract.AuthorityHead(3, "88" * 32, 3),
                 contract.AuthorityHead(contract.MAX_NUMBER, "88" * 32, 0))
        for head in heads:
            with self.subTest(head=head), self.assertRaises(contract.AuthorityContractError):
                self.request(head=head)
        for attempt, statement in ((1, None), (None, self.statement())):
            with self.assertRaises(contract.AuthorityContractError):
                self.request(attempt=attempt, statement=statement)
        for extra in ("epoch", "reset", "refund", "retry", "worker", "enforcer"):
            with self.subTest(extra=extra), self.assertRaises(TypeError):
                contract.authority_request(self.scope, self.state, self.signature, operation="reserve",
                    request_id_hex="77" * 32, expected_head=contract.AuthorityHead(0, "88" * 32, 0), **{extra:True})

    def test_publish_binds_normal_and_unknown_claims_but_cannot_establish_verdict_truth(self):
        head = contract.AuthorityHead(2, "88" * 32, 1, 1, True)
        for outcome in evidence.OUTCOMES:
            request = self.request(operation="publish", head=head, attempt=1, statement=self.statement(outcome=outcome))
            self.assertEqual(json.loads(bytes.fromhex(request.as_dict()["statement_hex"]))["outcome"], outcome)
        for statement in (self.statement(signature=bytes(64)), self.statement(profile="99" * 32),
                          b"{}", self.statement() + b"\n", bytearray(self.statement()), "synthetic-detail"):
            with self.subTest(kind=type(statement).__name__), self.assertRaises(contract.AuthorityContractError):
                self.request(operation="publish", head=head, attempt=1, statement=statement)
        forged = self.request(operation="publish", head=head, attempt=1, signature=bytes(64),
                              statement=self.statement(signature=bytes(64), outcome="verified"))
        self.assertEqual(json.loads(bytes.fromhex(forged.as_dict()["statement_hex"]))["outcome"], "verified")

    def test_invalid_signature_math_is_only_public_request_formatting(self):
        before = copy.deepcopy(self.state)
        requests = [self.request(signature=signature) for signature in
                    (self.signature, final_signatures()[1], bytes(64), b"\xff" * 64)]
        self.assertEqual(len({request.digest_hex for request in requests}), 4)
        self.assertEqual({request.as_dict()["scope_digest_hex"] for request in requests}, {self.scope.digest_hex})
        self.assertEqual(self.state, before)
        for request in requests:
            self.assertNotIn("outcome", request.as_dict())
            self.assertFalse(hasattr(request, "can_start"))

    def test_selected_target_limit_is_a_bound_profile_field_without_a_target_set_owner(self):
        scope = contract.authority_scope(self.state, **dict(self.selection, target_limit=1))
        requests = [self.request(scope=scope, signature=signature) for signature in (bytes(64), b"\xff" * 64)]
        self.assertEqual(len({request.as_dict()["target"]["evidence_key_hex"] for request in requests}), 2)
        self.assertEqual({request.as_dict()["scope_digest_hex"] for request in requests}, {scope.digest_hex})
        # The codec owns no target set. Representing two proposals is not admission of either.
        self.assertEqual(scope.as_dict()["target_limit"], 1)

    def test_request_ids_heads_and_targets_are_bound_but_not_deduplicated(self):
        request = self.request()
        variants = (self.request(request_id="99" * 32), self.request(signature=bytes(64)),
                    self.request(head=contract.AuthorityHead(0, "99" * 32, 0)),
                    self.request(head=contract.AuthorityHead(1, "88" * 32, 0)))
        for other in variants:
            with self.assertRaises(contract.AuthorityContractError):
                contract.parse_request(request, other.canonical_bytes)
            self.assertNotEqual(request.digest_hex, other.digest_hex)
        # Reuse of the same public ID for a different body is representable, not authorized.
        self.assertEqual(variants[1].as_dict()["request_id_hex"], request.as_dict()["request_id_hex"])
        self.assertIs(contract.parse_request(request, request.canonical_bytes), request)
        self.assertIs(contract.parse_request(request, request.canonical_bytes), request)

    def test_success_reply_claims_have_single_revision_and_no_refund_transitions(self):
        requests = (self.request(), self.request(operation="dispatch", attempt=1,
            head=contract.AuthorityHead(1, "88" * 32, 1, 1)),
            self.request(operation="publish", attempt=1, statement=self.statement(),
                head=contract.AuthorityHead(2, "88" * 32, 1, 1, True)),
            self.request(operation="resolve-unknown", attempt=1,
                head=contract.AuthorityHead(1, "88" * 32, 1, 1)))
        for request in requests:
            value = self.reply(request)
            claim = contract.parse_reply(request, canonical(value))
            with self.subTest(operation=request.as_dict()["operation"]):
                self.assertEqual(claim.claimed_head.as_dict(), value["after_head"])
                self.assertEqual(claim.claimed_attempt_id, 1)
                self.assertEqual(claim.claimed_head.revision, request.as_dict()["expected_head"]["revision"] + 1)
                self.assertEqual(claim.claimed_head.consumed, 1)

    def test_reply_echo_binds_request_scope_epoch_operation_id_and_full_head(self):
        request = self.request()
        value = self.reply(request)
        for field in ("schema", "operation", "scope_digest_hex", "authority_epoch", "request_id_hex", "request_digest_hex", "before_head"):
            changed = "99" * 32 if field.endswith("_hex") else 2 if field == "authority_epoch" else None
            with self.subTest(field=field), self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(request, canonical(dict(value, **{field:changed})))
        for epoch in (True, 1.0, "1"):
            with self.subTest(epoch=epoch), self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(request, canonical(dict(value, authority_epoch=epoch)))
        for other in (self.request(request_id="99" * 32), self.request(signature=bytes(64)),
                      self.request(head=contract.AuthorityHead(1, "88" * 32, 0))):
            with self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(other, canonical(value))

    def test_before_head_echo_rejects_bool_float_aliases_in_every_status(self):
        request = self.request(operation="dispatch", head=contract.AuthorityHead(1, "88" * 32, 1, 1), attempt=1)
        for status in (None, "not-applied", "unresolved"):
            for field in ("revision", "consumed", "pending_attempt_id", "dispatch_recorded"):
                for alias in (True, 1.0) if field != "dispatch_recorded" else (0, 0.0):
                    value = self.reply(request, status=status)
                    value["before_head"][field] = alias
                    with self.subTest(status=status, field=field, alias=alias), self.assertRaises(contract.AuthorityContractError):
                        contract.parse_reply(request, canonical(value))
            value = self.reply(request, status=status)
            value["before_head"]["state_digest_hex"] = "99" * 32
            with self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(request, canonical(value))

    def test_after_head_claim_cannot_skip_charge_revision_or_refund_an_attempt(self):
        requests = (self.request(), self.request(operation="resolve-unknown", attempt=1,
                    head=contract.AuthorityHead(2, "88" * 32, 1, 1, True)))
        for request in requests:
            value = self.reply(request)
            mutations = (("revision", 0), ("revision", value["after_head"]["revision"] + 1),
                         ("consumed", 0), ("consumed", 2), ("consumed", True),
                         ("state_digest_hex", "88" * 32), ("pending_attempt_id", 2),
                         ("dispatch_recorded", True), ("revision", 1.0))
            for field, changed in mutations:
                altered = copy.deepcopy(value)
                altered["after_head"][field] = changed
                with self.subTest(operation=request.as_dict()["operation"], field=field), self.assertRaises(contract.AuthorityContractError):
                    contract.parse_reply(request, canonical(altered))
            for attempt in (None, True, 1.0, 0, 2):
                with self.subTest(attempt=attempt), self.assertRaises(contract.AuthorityContractError):
                    contract.parse_reply(request, canonical(dict(value, attempt_id=attempt)))

    def test_not_applied_only_echoes_expected_head_and_cannot_prove_no_global_charge(self):
        request = self.request()
        value = self.reply(request, status="not-applied")
        claim = contract.parse_reply(request, canonical(value))
        self.assertEqual(claim.claimed_head.as_dict(), request.as_dict()["expected_head"])
        self.assertIsNone(claim.claimed_attempt_id)
        for field in value["after_head"]:
            changed = copy.deepcopy(value)
            changed["after_head"][field] = "99" * 32 if field.endswith("_hex") else 1
            with self.subTest(field=field), self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(request, canonical(changed))
        self.assertFalse(hasattr(claim, "unspent"))
        self.assertFalse(hasattr(claim, "can_retry"))

    def test_unresolved_and_lost_reply_assert_no_head_attempt_refund_or_retry(self):
        request = self.request()
        value = self.reply(request, status="unresolved")
        claim = contract.parse_reply(request, canonical(value))
        self.assertIsNone(claim.claimed_head)
        self.assertIsNone(claim.claimed_attempt_id)
        for field, changed in (("after_head", request.as_dict()["expected_head"]), ("attempt_id", 1)):
            with self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(request, canonical(dict(value, **{field:changed})))
        for wire in (None, b"", b"{}", b"synthetic-detail"):
            with self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(request, wire)
        self.assertFalse(hasattr(claim, "can_start"))
        self.assertFalse(hasattr(claim, "refunded"))

    def test_reply_claim_refuses_extra_provenance_unknown_status_and_operation_confusion(self):
        request = self.request()
        value = self.reply(request)
        for field in value:
            missing = dict(value)
            del missing[field]
            with self.subTest(field=field), self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(request, canonical(missing))
        for field in ("authorized", "authenticated", "permit", "source", "worker_stderr", "refund"):
            with self.subTest(extra=field), self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(request, canonical(dict(value, **{field:True})))
        for status in (True, None, 0, "verified", "rejected", "timeout", "dispatch-recorded", "result-recorded", "unknown-recorded"):
            with self.subTest(status=status), self.assertRaises(contract.AuthorityContractError):
                contract.parse_reply(request, canonical(dict(value, status=status)))

    def test_noncanonical_duplicate_non_ascii_and_deep_wire_values_are_refused(self):
        request = self.request()
        for parser, wire in ((contract.parse_request, request.canonical_bytes),
                             (contract.parse_reply, canonical(self.reply(request)))):
            variants = (wire + b"\n", b" " + wire, wire + b"\r\n", json.dumps(json.loads(wire), indent=2).encode("ascii"),
                wire[:-1] + b',"schema":"duplicate"}', wire.replace(b'"reserve"', b'"re\\u0073erve"'),
                b"\xff", b"{}", b"[]", b"null", b"NaN", b"Infinity", b"[" * 1500 + b"0" + b"]" * 1500)
            for changed in variants:
                with self.subTest(parser=parser.__name__, size=len(changed)), self.assertRaises(contract.AuthorityContractError):
                    parser(request, changed)

    def test_hostile_local_input_subclasses_execute_no_custom_methods_or_disclosure(self):
        calls = []
        class HostileBytes(bytes):
            def __len__(self):
                calls.append("length")
                raise RuntimeError("synthetic-detail")
            def decode(self, *args):
                calls.append("decode")
                raise RuntimeError("synthetic-detail")
            def hex(self):
                calls.append("hex")
                raise RuntimeError("synthetic-detail")
        class HostileText(str):
            def __eq__(self, other):
                calls.append("equality")
                raise RuntimeError("synthetic-detail")
        class HostileState(dict):
            def __deepcopy__(self, memo):
                calls.append("copy")
                raise RuntimeError("synthetic-detail")
        request = self.request()
        for raw in (None, True, "{}", bytearray(b"{}"), memoryview(b"{}"), b"", b"x" * (contract.MAX_WIRE_BYTES + 1), HostileBytes(b"{}")):
            for parser in (contract.parse_request, contract.parse_reply):
                with self.subTest(parser=parser.__name__), self.assertRaises(contract.AuthorityContractError) as error:
                    parser(request, raw)
                self.assertNotIn("synthetic-detail", str(error.exception))
        for field in ("authority_id_hex", "verifier_profile_digest_hex"):
            with self.assertRaises(contract.AuthorityContractError):
                contract.authority_scope(self.state, **dict(self.selection, **{field:HostileText("11" * 32)}))
        with self.assertRaises(contract.AuthorityContractError):
            contract.authority_scope(HostileState(self.state), **self.selection)
        for changes in (dict(request_id=HostileText("77" * 32)), dict(operation=HostileText("reserve")),
                        dict(signature=HostileBytes(self.signature)), dict(statement=HostileBytes(b"{}")),
                        dict(signature=bytes(63)), dict(signature=bytes(65)), dict(signature=bytearray(64)),
                        dict(statement=b"x" * (evidence.MAX_STATEMENT_BYTES + 1))):
            with self.assertRaises(contract.AuthorityContractError):
                self.request(**changes)
        self.assertEqual(calls, [])

    def test_incomplete_and_tampered_local_objects_still_require_valid_selected_bytes(self):
        for cls in (contract.AuthorityScope, contract.AuthorityRequest, contract.AuthorityHead):
            value = object.__new__(cls)
            with self.subTest(cls=cls.__name__), self.assertRaises(contract.AuthorityContractError):
                value.as_dict()
        scope = object.__new__(contract.AuthorityScope)
        object.__setattr__(scope, "_wire", b"{}")
        with self.assertRaises(contract.AuthorityContractError):
            self.request(scope=scope)
        request = object.__new__(contract.AuthorityRequest)
        object.__setattr__(request, "_scope", self.scope)
        value = self.request().as_dict()
        value["expected_head"]["revision"] = True
        object.__setattr__(request, "_wire", canonical(value))
        for parser in (contract.parse_request, contract.parse_reply):
            with self.assertRaises(contract.AuthorityContractError):
                parser(request, b"{}")

    def test_forged_matching_reply_is_replayable_and_returns_no_worker_capability(self):
        request = self.request(signature=bytes(64))
        wire = canonical(self.reply(request))
        first = contract.parse_reply(request, wire)
        second = contract.parse_reply(request, wire)
        self.assertEqual(first, second)
        self.assertEqual(first.status, "reserved")
        self.assertEqual(first.claimed_attempt_id, 1)
        self.assertFalse(callable(first))
        for field in ("authorized", "permit", "can_start", "enforcer", "signature_hex", "enrolled"):
            self.assertFalse(hasattr(first, field))
        with self.assertRaises(FrozenInstanceError):
            first.status = "authorized"

    def test_final_json_safe_revision_can_be_claimed_but_never_silently_rolls_over(self):
        request = self.request(head=contract.AuthorityHead(contract.MAX_NUMBER - 1, "88" * 32, 0))
        claim = contract.parse_reply(request, canonical(self.reply(request)))
        self.assertEqual(claim.claimed_head.revision, contract.MAX_NUMBER)
        with self.assertRaises(contract.AuthorityContractError):
            self.request(operation="dispatch", head=claim.claimed_head, attempt=1)
        self.assertEqual(request.as_dict()["authority_epoch"], 1)
        self.assertEqual(self.scope.as_dict()["authority_epoch"], 1)

    def test_pure_claims_after_journal_exhaustion_reopen_cannot_change_bytes_or_admit_work(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-authority-contract-") as directory:
            root, anchor = Path(directory) / "state", Path(directory) / "head.json"
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
                scope = contract.authority_scope(state, **self.selection)
                self.assertEqual(scope, self.scope)
                request = self.request(state=state, scope=scope)
                contract.parse_request(request, request.canonical_bytes)
                claim = contract.parse_reply(request, canonical(self.reply(request)))
                self.assertEqual(claim.status, "reserved")
                calls = []
                with self.assertRaises(RecoveryExhausted):
                    journal.reconcile_exchange_bitcoin(session, evidence.prepare(state, self.signature).candidate_packet,
                        expected_observation_digest=completion.observation_digest(invalid),
                        recoverer=lambda value: calls.append(value))
                after = (copy.deepcopy(journal._state), journal._sequence,
                         (root / "journal.sqlite3").read_bytes(), anchor.read_bytes())
                self.assertEqual(after, before)
                self.assertEqual(calls, [])
                self.assertEqual(journal.get_session(session)["recovery_budget"]["consumed"], 1)
                self.assertEqual(journal.get_exchange(session)["zenon_completion_packet_hex"], invalid.hex())


if __name__ == "__main__":
    unittest.main()
