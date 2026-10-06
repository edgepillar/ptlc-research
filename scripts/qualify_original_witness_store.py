#!/usr/bin/env python3
"""Test-only owned witness transactions with actual historical mathematics."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import unittest

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[1]/"tests")]
from qualification.original_read_response_verifier import PublicOriginalResponseCheck
from qualification import policy_effect_store as local
from original_snapshot_vectors import canonical, scenario
from test_original_witness_store import OriginalWitnessStoreTests
import original_witness_store as witness


class RealOriginalWitnessStoreTests(OriginalWitnessStoreTests):
    """Inherited framing, native concurrency/death and rollback boundary cases."""

    def test_actual_zero_signatures_refuse_without_bootstrap_or_completed_witness_loss(self):
        for name in ("pending", "completed"):
            query, opened, packet = self.packets[name]
            value = json.loads(packet)
            for field in ("root_signature_hex", "response_signature_hex"):
                changed = json.loads(packet)
                target = changed["root_envelope"] if field == "root_signature_hex" else changed
                target[field] = "00"*64
                with self.assertRaises(witness.WitnessRefused):
                    self.store.retain(query, opened, canonical(changed))
            if name == "pending":
                self.assertIsNone(self.store.inspect_retained())
                self.seed()
            else:
                self.assertEqual(self.store.inspect_retained().observation, "pending")

    def test_actual_stored_zero_signature_cannot_be_replaced_by_valid_extension(self):
        self.seed()
        value = json.loads(self.packets["pending"][2])
        value["response_signature_hex"] = "00"*64
        self.store._db.execute("UPDATE witness SET response=?", (canonical(value),))
        for command in (self.store.inspect_retained, lambda: self.retain("completed")):
            with self.assertRaises(witness.WitnessRefused):
                command()
        self.assertEqual(self.store._db.execute("SELECT version FROM witness").fetchone(), (1,))

    def test_actual_changed_selected_executable_measurement_refuses_inside_owned_transaction(self):
        self.seed()
        copied = self.path.with_name("synthetic-public-check")
        shutil.copy2(self.entry, copied)
        check = PublicOriginalResponseCheck(copied,
            expected_executable_sha256_hex=hashlib.sha256(copied.read_bytes()).hexdigest())
        with self.open(check=check) as store:
            copied.write_bytes(copied.read_bytes()+b"synthetic-change")
            with self.assertRaises(witness.WitnessRefused):
                self.retain("completed", store)
        self.assertEqual(self.store.inspect_retained().version, 1)

    def test_actual_historical_completion_retention_does_not_reenable_revoked_source_effect(self):
        self.seed()
        with scenario("pending") as actual:
            actual.store.replace_local_policy(0, actual.profile, active=False)
            result = self.retain("completed")
            self.assertEqual(result.observation, "completed")
            with self.assertRaises(local.StoreRefused):
                actual.store.apply_synthetic_effect(actual.original)
            self.assertEqual((actual.store.local_view().charged_operations, actual.store.local_view().synthetic_effects), (1, 0))
            self.assertFalse(actual.store.local_view().active)


def main():
    parser = argparse.ArgumentParser(description="Offline test-only owned witness transaction qualification")
    parser.add_argument("--original-response-verifier", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.original_response_verifier).resolve()
        pin = hashlib.sha256(entry.read_bytes()).hexdigest()
        RealOriginalWitnessStoreTests.entry = entry
        RealOriginalWitnessStoreTests.check = PublicOriginalResponseCheck(entry,
            expected_executable_sha256_hex=pin)
        RealOriginalWitnessStoreTests.actor_mode = "actual"
        RealOriginalWitnessStoreTests.actor_context = dict(entry=str(entry), entry_sha256=pin)
    except (OSError, ValueError, TypeError):
        parser.exit(1, "selected public original response check unavailable\n")
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RealOriginalWitnessStoreTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
