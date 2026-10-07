"""Public collection shape controls only; scalar arithmetic here is test-only."""

import copy
import unittest

from offline_session import exchange
from exchange_test_support import accepted, artifacts


def collections(bundle):
    # These public fixture transformations are never application cryptography.
    order = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
    alice, bob = [int(value, 16) for value in bundle["partial_signatures_hex"]]
    values = ([alice + bob], [1, alice - 1, bob],
              [alice, order - 1, bob - (order - 1)],
              [alice, bob, 0], [alice, bob, 1, order - 1])
    for parts in values:
        assert sum(parts) % order == (alice + bob) % order
        yield {"partial_signatures_hex": [format(part % order, "064x") for part in parts],
               "adaptor_presignature_hex": bundle["adaptor_presignature_hex"]}


class PublicCollectionConsumerTests(unittest.TestCase):
    def test_equal_total_wrong_count_bundles_refuse_context_derived_requests(self):
        _, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
        for context, original in ((bitcoin, btc_bundle), (zenon, znn_bundle)):
            before = context.as_dict()
            baseline = exchange.verification_request(context, bundle=original)
            self.assertEqual(baseline["partial_signatures_hex"], original["partial_signatures_hex"])
            self.assertEqual(baseline["context_digest_hex"], context.digest_hex)
            for changed in collections(original):
                with self.subTest(leg=before["leg"], count=len(changed["partial_signatures_hex"])):
                    self.assertNotEqual(len(changed["partial_signatures_hex"]), 2)
                    with self.assertRaises(exchange.ExchangeError):
                        exchange.verification_request(context, bundle=changed)
                    self.assertEqual(context.as_dict(), before)

    def test_equal_total_wrong_count_refuses_before_callbacks_and_state_advancement(self):
        _, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
        bitcoin_state = exchange.start(bitcoin)
        # Mock receipts set up ordering only; they are not crypto certificates.
        zenon_state = exchange.bind_zenon(
            exchange.retain_bitcoin(bitcoin_state, btc_bundle, accepted), zenon)
        zenon_state = exchange.retain_alice_partial(
            zenon_state, znn_bundle["partial_signatures_hex"][0], accepted)
        for state, original, retain in (
                (bitcoin_state, btc_bundle, exchange.retain_bitcoin),
                (zenon_state, znn_bundle, exchange.retain_zenon)):
            before, called = copy.deepcopy(state), []
            for changed in collections(original):
                with self.subTest(stage=state["stage"], count=len(changed["partial_signatures_hex"])):
                    with self.assertRaises(exchange.ExchangeError):
                        retain(state, changed, lambda request: called.append(request))
                    self.assertEqual(state, before)
                    self.assertEqual(called, [])
                    exchange.validate_state(state)


if __name__ == "__main__":
    unittest.main()
