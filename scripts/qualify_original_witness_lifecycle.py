#!/usr/bin/env python3
"""Selected test-only witness lifecycle with the unchanged public math worker."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[1]/"tests")]
from qualification.original_read_response_verifier import PublicOriginalResponseCheck
from qualification import policy_effect_store as local
from original_snapshot_vectors import canonical, scenario
from test_original_witness_lifecycle import OriginalWitnessLifecycleTests
import original_witness_store as witness


class RealOriginalWitnessLifecycleTests(OriginalWitnessLifecycleTests):
    def test_actual_zero_signatures_after_committed_creation_or_cancellation_cannot_bootstrap_completion(self):
        store = self.populated()
        def interrupt(label):
            if label == "retain-compared":
                raise KeyboardInterrupt
        with patch.object(store, "_cut", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            store.retain(*self.packets["completed"])
        query, opened, packet = self.packets["completed"]
        changed = json.loads(packet)
        changed["response_signature_hex"] = "00"*64
        with self.open() as reopened:
            with self.assertRaises(witness.WitnessRefused):
                reopened.retain(query, opened, canonical(changed))
            self.assertEqual(reopened.inspect_retained().observation, "pending")
        with self.open(self.path.with_name("empty.sqlite3")) as empty:
            with self.assertRaises(witness.WitnessRefused):
                empty.retain(query, opened, canonical(changed))
            self.assertIsNone(empty.inspect_retained())

    def test_actual_cancellation_after_both_public_math_results_still_does_not_commit_extension(self):
        store = self.populated()
        calls = []
        def interrupt(packet):
            result = self.check(packet)
            calls.append(result)
            if len(calls) == 2:
                raise KeyboardInterrupt
            return result
        with patch.object(store, "_verifier", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            store.retain(*self.packets["completed"])
        self.assertEqual(len(calls), 2)
        self.assert_disposed(store)
        with self.open() as reopened:
            self.assertEqual((reopened.inspect_retained().version, reopened.inspect_retained().observation), (1, "pending"))

    def test_actual_lost_source_effect_reply_and_witness_cancellation_remain_separate_outcomes(self):
        store = self.populated()
        with scenario("pending") as actual:
            def lost(label):
                if label == "effect-after-commit":
                    raise RuntimeError("synthetic lost source reply")
            with patch.object(actual.store, "_cut", side_effect=lost), self.assertRaises(local.StoreOutcomeUnknown):
                actual.store.apply_synthetic_effect(actual.original)
            def interrupt(label):
                if label == "retain-after-commit":
                    raise KeyboardInterrupt
            with patch.object(store, "_cut", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
                store.retain(*self.packets["completed"])
            with self.open() as reopened:
                self.assertEqual(reopened.inspect_retained().observation, "completed")
            self.assertEqual((actual.store.local_view().charged_operations, actual.store.local_view().synthetic_effects), (1, 1))
            self.assertEqual(actual.store.lookup_original(actual.original).effect_sequence, 2)
            self.assert_disposed(store)
            # The fixture observation does not resolve the caller's lost
            # original result or authorize a retry, refund or protected use.


def main():
    parser = argparse.ArgumentParser(description="Offline test-only witness creation and interruption qualification")
    parser.add_argument("--original-response-verifier", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.original_response_verifier).resolve()
        pin = hashlib.sha256(entry.read_bytes()).hexdigest()
        RealOriginalWitnessLifecycleTests.check = PublicOriginalResponseCheck(entry,
            expected_executable_sha256_hex=pin)
        RealOriginalWitnessLifecycleTests.actor_mode = "actual"
        RealOriginalWitnessLifecycleTests.actor_context = dict(entry=str(entry), entry_sha256=pin)
    except (OSError, ValueError, TypeError):
        parser.exit(1, "selected public original response check unavailable\n")
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RealOriginalWitnessLifecycleTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
