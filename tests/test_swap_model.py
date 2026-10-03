"""Offline schedule checks; passing this abstraction does not prove swap safety."""

from dataclasses import replace
import unittest

from scripts.model_swap import Bounds, Leg, POLICIES, Policy, State, explore, principal_loss, refund_eligible, step, successors


class SwapModelTests(unittest.TestCase):
    def _prepared(self, honest="alice", policy=Policy()):
        state = State()
        actions = (
            "alice_funds_btc", "bob_observes_btc", "bob_validates_btc",
            "alice_delivers_exact_btc_artifact", "bob_funds_znn",
            "alice_observes_znn", "alice_validates_znn",
            "alice_delivers_exact_znn_partial", "bob_retains_exact_extraction_material",
            "bob_releases_exact_znn_artifact",
        )
        for action in actions:
            state = step(state, action, honest=honest, policy=policy)
        return state

    def test_safe_policy_exhausts_both_honest_role_searches(self):
        for honest in ("alice", "bob"):
            with self.subTest(honest=honest):
                result = explore(honest)
                self.assertTrue(result.complete)
                self.assertEqual(result.counterexample, ())
                self.assertGreater(result.states, 100)
                self.assertGreater(result.horizon_states, 0)

    def test_observed_funding_is_not_validated_funding(self):
        state = step(State(), "alice_observes_znn", honest="alice")
        self.assertTrue(state.znn_observed)
        self.assertFalse(state.znn_validated)
        self.assertEqual(state.znn, Leg.UNFUNDED)
        with self.assertRaises(ValueError):
            step(state, "alice_validates_znn", honest="alice")

    def test_weakened_policies_have_ledger_counterexamples(self):
        cases = (
            ("observed-only", "alice"),
            ("forget-extraction", "bob"),
            ("late-reveal", "alice"),
            ("unbounded-response", "bob"),
        )
        for name, honest in cases:
            with self.subTest(policy=name, honest=honest):
                result = explore(honest, policy=POLICIES[name])
                self.assertTrue(result.counterexample)
                state = State()
                for entry in result.counterexample:
                    action = entry.split(": ", 1)[1]
                    state = step(state, action, honest=honest, policy=POLICIES[name])
                self.assertTrue(principal_loss(state, honest))

    def test_reorg_does_not_erase_exposure_or_extraction(self):
        state = self._prepared()
        for action in (
            "alice_publishes_revealing_znn_claim", "include_znn_claim",
            "bob_extracts_and_publishes_btc_claim",
        ):
            state = step(state, action)
        exposure = state.exposed_at
        state = step(state, "reorg_znn_claim")
        self.assertEqual(state.znn, Leg.LOCKED)
        self.assertEqual(state.exposed_at, exposure)
        self.assertTrue(state.secret_extracted)
        self.assertEqual(state.reorgs, 1)
        state = step(state, "include_znn_claim")
        self.assertNotIn("reorg_znn_claim", dict(successors(state)))

    def test_honest_disclosure_stops_after_derived_cutoff(self):
        state = self._prepared()
        for _ in range(Bounds().last_safe_reveal + 1):
            state = step(state, "tick")
        with self.assertRaises(ValueError):
            step(state, "alice_publishes_revealing_znn_claim")

    def test_exact_artifact_exchange_precedes_funding_and_disclosure(self):
        state = State()
        for action in ("alice_funds_btc", "bob_observes_btc", "bob_validates_btc"):
            state = step(state, action, honest="bob")
        with self.assertRaises(ValueError):
            step(state, "bob_funds_znn", honest="bob")
        state = step(state, "alice_delivers_exact_btc_artifact", honest="bob")
        state = step(state, "bob_funds_znn", honest="bob")
        state = step(state, "alice_delivers_exact_znn_partial", honest="bob")
        with self.assertRaises(ValueError):
            step(state, "bob_releases_exact_znn_artifact", honest="bob")
        with self.assertRaises(ValueError):
            step(state, "alice_publishes_revealing_znn_claim", honest="bob")

    def test_latest_honest_reveal_survives_maximum_modeled_rollback_delay(self):
        state = self._prepared()
        for _ in range(Bounds().last_safe_reveal):
            state = step(state, "tick")
        state = step(state, "alice_publishes_revealing_znn_claim")
        for action in (
            "bob_extracts_and_publishes_btc_claim", "include_btc_claim",
            "tick", "include_znn_claim", "tick", "reorg_znn_claim",
            "tick", "include_znn_claim",
        ):
            state = step(state, action)
        self.assertEqual(state.time, Bounds().zenon_expiry - 1)
        self.assertEqual(state.exposed_at, Bounds().last_safe_reveal)
        self.assertEqual(state.znn, Leg.CLAIMED)
        self.assertFalse(principal_loss(state, "alice"))

    def test_late_reveal_rollback_can_leave_honest_alice_without_either_principal(self):
        policy = POLICIES["late-reveal"]
        state = self._prepared(policy=policy)
        for _ in range(Bounds().zenon_expiry - 2):
            state = step(state, "tick", policy=policy)
        for action in (
            "alice_publishes_revealing_znn_claim",
            "bob_extracts_and_publishes_btc_claim", "include_btc_claim",
            "tick", "include_znn_claim", "tick", "reorg_znn_claim",
            "bob_requests_znn_refund", "include_bob_znn_refund",
        ):
            state = step(state, action, policy=policy)
        self.assertTrue(principal_loss(state, "alice"))
        self.assertGreaterEqual(state.exposed_at, 0)

    def test_zenon_equality_rejects_claim_and_allows_owner_refund(self):
        bounds = Bounds()
        state = replace(self._prepared(), time=bounds.zenon_expiry, exposed_at=0, znn_claim_due=1)
        actions = dict(successors(state))
        self.assertNotIn("include_znn_claim", actions)
        self.assertIn("bob_requests_znn_refund", actions)
        self.assertFalse(refund_eligible("znn", "alice", bounds.zenon_expiry, bounds))
        self.assertTrue(refund_eligible("znn", "bob", bounds.zenon_expiry, bounds))
        self.assertFalse(refund_eligible("btc", "bob", bounds.bitcoin_refund, bounds))

    def test_bitcoin_claim_remains_valid_after_refund_opens(self):
        # This boundary state is constructed explicitly, not claimed reachable
        # under every honest policy. Both competing spends consume one outpoint.
        state = replace(
            self._prepared(), time=Bounds().bitcoin_refund,
            exposed_at=0, secret_extracted=True, btc_claim_due=11, btc_refund_due=11,
        )
        claimed = step(state, "include_btc_claim")
        refunded = step(state, "include_alice_btc_refund")
        self.assertEqual(claimed.btc, Leg.CLAIMED)
        self.assertEqual(refunded.btc, Leg.REFUNDED)
        self.assertNotIn("include_alice_btc_refund", dict(successors(claimed)))
        self.assertNotIn("include_btc_claim", dict(successors(refunded)))

    def test_inclusion_bound_is_an_explicit_scheduler_assumption(self):
        state = step(self._prepared(), "alice_publishes_revealing_znn_claim")
        state = step(state, "tick")
        self.assertNotIn("tick", dict(successors(state)))
        state = step(state, "include_znn_claim")
        self.assertIn("tick", dict(successors(state)))

    def test_inadequate_timing_bounds_and_incomplete_search_fail_closed(self):
        with self.assertRaises(ValueError):
            explore(bounds=replace(Bounds(), bitcoin_refund=7))
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            explore(max_states=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
