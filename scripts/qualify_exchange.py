"""Run the public exchange against an explicitly built offline Rust verifier.

This separate integration check keeps the ordinary Python suite Rust-free.
There is no signing, transport, real participant identity or chain access.
"""

import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.exchange import VerificationError, verification_request
from offline_session.journal import Conflict, Journal
from exchange_test_support import artifacts


class RealVerifierExchangeTests(unittest.TestCase):
    verifier = None

    def test_actual_verification_retention_release_and_exact_replay(self):
        terms, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
        calls = []

        def verified(request):
            result = self.verifier(request)
            calls.append((request["leg"], request["kind"]))
            return result

        with tempfile.TemporaryDirectory(prefix="ptlc-verified-exchange-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                journal.create_session(terms.session_id, terms.digest_hex)
                journal.start_exchange(terms.session_id, bitcoin, recovery_limit=8)
                with self.assertRaises(Conflict):
                    journal.bind_exchange_zenon(terms.session_id, zenon)
                journal.retain_exchange_bitcoin(terms.session_id, btc_bundle, verifier=verified)
                journal.bind_exchange_zenon(terms.session_id, zenon)
                before = journal.get_exchange(terms.session_id)
                wrong = btc_bundle["partial_signatures_hex"][0]
                with self.assertRaises(Conflict):
                    journal.retain_exchange_alice_partial(terms.session_id, wrong, verifier=self.verifier)
                self.assertEqual(journal.get_exchange(terms.session_id), before)
                journal.retain_exchange_alice_partial(terms.session_id, znn_bundle["partial_signatures_hex"][0], verifier=verified)
                with self.assertRaises(Conflict):
                    journal.release_exchange_zenon(terms.session_id)
                before = journal.get_exchange(terms.session_id)
                wrong = copy.deepcopy(znn_bundle)
                wrong["adaptor_presignature_hex"] = btc_bundle["adaptor_presignature_hex"]
                with self.assertRaises(Conflict):
                    journal.retain_exchange_zenon(terms.session_id, wrong, verifier=self.verifier)
                self.assertEqual(journal.get_exchange(terms.session_id), before)
                journal.retain_exchange_zenon(terms.session_id, znn_bundle, verifier=verified)
            # Reopen before release: the verified extraction context must survive.
            with Journal.open(base / "state", base / "head.json") as journal:
                output = journal.release_exchange_zenon(terms.session_id)
                packet = json.loads(output)
                self.assertEqual(packet["context"], zenon.as_dict())
                self.assertEqual(packet["adaptor_presignature_hex"], znn_bundle["adaptor_presignature_hex"])
                self.assertTrue(journal.get_exchange(terms.session_id)["release_may_have_escaped"])
                self.assertFalse(journal.get_session(terms.session_id)["possible_exposure"])
            with Journal.open(base / "state", base / "head.json") as journal:
                self.assertEqual(journal.replay_exchange_release(terms.session_id), output)
                with self.assertRaises(Conflict):
                    journal.release_exchange_zenon(terms.session_id)
            self.assertEqual(calls, [("bitcoin", "bundle"), ("zenon", "alice-partial"), ("zenon", "bundle")])

    def test_actual_verifier_rejects_cryptographic_substitutions(self):
        _, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
        for context, bundle in ((bitcoin, btc_bundle), (zenon, znn_bundle)):
            request = verification_request(context, bundle=bundle)
            self.verifier(request)
            for field in ("message_hex", "aggregate_key_xonly_hex", "adaptor_point_sec1_hex",
                          "adaptor_presignature_hex", "public_nonces_hex", "partial_signatures_hex", "signer_keys_sec1_hex"):
                with self.subTest(leg=context.as_dict()["leg"], field=field):
                    wrong = copy.deepcopy(request)
                    if field in ("public_nonces_hex", "partial_signatures_hex", "signer_keys_sec1_hex"):
                        wrong[field].reverse()
                    else:
                        last = "1" if wrong[field][-1] == "0" else "0"
                        wrong[field] = wrong[field][:-1] + last
                    with self.assertRaises(VerificationError):
                        self.verifier(wrong)

    # Test-only arithmetic on published scalars; never use it for signing.
    _ORDER = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

    def _equal_total_collections(self, original, *, wrong_count):
        alice, bob = (int(value, 16) for value in original["partial_signatures_hex"])
        total = (alice + bob) % self._ORDER
        if wrong_count:
            selections = (
                ("combined-singleton", [total]),
                ("split-three", [1, alice - 1, bob]),
                ("wrapped-three", [alice, self._ORDER - 1, bob + 1]),
                ("zero-padding", [alice, bob, 0]),
                ("cancelling-pair", [alice, bob, 1, self._ORDER - 1]),
            )
        else:
            selections = (
                ("positive-offset", [alice + 1, bob - 1]),
                ("negative-offset", [alice - 1, bob + 1]),
                ("combined-first", [total, 0]),
                ("combined-second", [0, total]),
            )
        result = []
        for label, scalars in selections:
            changed = copy.deepcopy(original)
            changed["partial_signatures_hex"] = [f"{value % self._ORDER:064x}" for value in scalars]
            self.assertEqual(sum(int(value, 16) for value in changed["partial_signatures_hex"])
                             % self._ORDER, total)
            self.assertEqual(changed["adaptor_presignature_hex"], original["adaptor_presignature_hex"])
            if not wrong_count:
                self.assertEqual(len(changed["partial_signatures_hex"]), 2)
                self.assertNotEqual(changed["partial_signatures_hex"][0], original["partial_signatures_hex"][0])
                self.assertNotEqual(changed["partial_signatures_hex"][1], original["partial_signatures_hex"][1])
            result.append((label, changed))
        return result

    def _initialize_collection_exchange(self, base, stage):
        terms, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
        with Journal.open(base / "state", base / "head.json") as journal:
            journal.create_session(terms.session_id, terms.digest_hex)
            journal.start_exchange(terms.session_id, bitcoin, recovery_limit=8)
            if stage != "BITCOIN_BOUND":
                journal.retain_exchange_bitcoin(terms.session_id, btc_bundle, verifier=self.verifier)
                journal.bind_exchange_zenon(terms.session_id, zenon)
            if stage == "ALICE_PARTIAL_RETAINED":
                journal.retain_exchange_alice_partial(
                    terms.session_id, znn_bundle["partial_signatures_hex"][0], verifier=self.verifier)
            state = journal.get_exchange(terms.session_id)
            self.assertEqual(state["stage"], stage)
            self.assertEqual(state["bitcoin_context"], bitcoin.as_dict())
            if stage != "BITCOIN_BOUND":
                self.assertEqual(state["zenon_context"], zenon.as_dict())
        return terms, bitcoin, zenon, btc_bundle, znn_bundle

    def _refuse_collection_without_commit(self, base, session_id, attempt):
        events = []
        with Journal.open(base / "state", base / "head.json", hook=events.append) as journal:
            before = journal.get_session(session_id)
            head = (base / "head.json").read_bytes()
            self.assertEqual(events, [])
            with self.assertRaisesRegex(Conflict, "^managed exchange transition rejected$"):
                attempt(journal)
            self.assertEqual(journal.get_session(session_id), before)
            self.assertEqual((base / "head.json").read_bytes(), head)
            self.assertEqual(events, [])
        # Reloading validates the SQLite row and its independently stored head.
        with Journal.open(base / "state", base / "head.json", hook=events.append) as journal:
            self.assertEqual(journal.get_session(session_id), before)
            self.assertEqual((base / "head.json").read_bytes(), head)
            self.assertEqual(events, [])

    def test_equal_total_wrong_counts_refuse_before_callback_and_survive_reopen(self):
        for leg, stage in (("bitcoin", "BITCOIN_BOUND"), ("zenon", "ALICE_PARTIAL_RETAINED")):
            with self.subTest(leg=leg), tempfile.TemporaryDirectory(prefix="ptlc-collection-count-") as directory:
                base = Path(directory)
                terms, _, _, btc_bundle, znn_bundle = self._initialize_collection_exchange(base, stage)
                original = btc_bundle if leg == "bitcoin" else znn_bundle
                seen = []

                def unexpected(request):
                    seen.append(copy.deepcopy(request))
                    return self.verifier(request)

                for label, changed in self._equal_total_collections(original, wrong_count=True):
                    with self.subTest(leg=leg, collection=label):
                        def attempt(journal):
                            retain = journal.retain_exchange_bitcoin if leg == "bitcoin" else journal.retain_exchange_zenon
                            retain(terms.session_id, changed, verifier=unexpected)
                        self._refuse_collection_without_commit(base, terms.session_id, attempt)
                        self.assertEqual(seen, [])
                with Journal.open(base / "state", base / "head.json") as journal:
                    retain = journal.retain_exchange_bitcoin if leg == "bitcoin" else journal.retain_exchange_zenon
                    retain(terms.session_id, original, verifier=self.verifier)
                with Journal.open(base / "state", base / "head.json") as journal:
                    self.assertEqual(journal.get_exchange(terms.session_id)["stage"],
                                     "BITCOIN_RETAINED" if leg == "bitcoin" else "ZENON_RETAINED")
                    self.assertFalse(journal.get_session(terms.session_id)["possible_exposure"])

    def test_equal_total_bitcoin_wrong_roles_reach_actual_verifier_without_retention(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-collection-bitcoin-") as directory:
            base = Path(directory)
            terms, bitcoin, _, original, _ = self._initialize_collection_exchange(base, "BITCOIN_BOUND")
            baseline = verification_request(bitcoin, bundle=original)
            self.verifier(baseline)
            for label, changed in self._equal_total_collections(original, wrong_count=False):
                with self.subTest(collection=label):
                    seen, refused = [], []

                    def actual(request):
                        seen.append(copy.deepcopy(request))
                        try:
                            return self.verifier(request)
                        except VerificationError:
                            refused.append(True)
                            raise

                    self._refuse_collection_without_commit(
                        base, terms.session_id,
                        lambda journal: journal.retain_exchange_bitcoin(terms.session_id, changed, verifier=actual))
                    expected = copy.deepcopy(baseline)
                    expected["partial_signatures_hex"] = changed["partial_signatures_hex"]
                    self.assertEqual(seen, [expected])
                    self.assertEqual(refused, [True])
            with Journal.open(base / "state", base / "head.json") as journal:
                journal.retain_exchange_bitcoin(terms.session_id, original, verifier=self.verifier)
            with Journal.open(base / "state", base / "head.json") as journal:
                retained = journal.get_exchange(terms.session_id)
                self.assertEqual(retained["stage"], "BITCOIN_RETAINED")
                self.assertEqual(retained["bitcoin_bundle"], original)

    def test_equal_total_zenon_wrong_alice_reaches_actual_verifier_without_retention(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-collection-alice-") as directory:
            base = Path(directory)
            terms, _, zenon, _, original = self._initialize_collection_exchange(base, "ZENON_BOUND")
            baseline = verification_request(zenon, alice_partial=original["partial_signatures_hex"][0])
            self.verifier(baseline)
            for label, changed in self._equal_total_collections(original, wrong_count=False):
                with self.subTest(collection=label):
                    seen, refused = [], []

                    def actual(request):
                        seen.append(copy.deepcopy(request))
                        try:
                            return self.verifier(request)
                        except VerificationError:
                            refused.append(True)
                            raise

                    self._refuse_collection_without_commit(
                        base, terms.session_id,
                        lambda journal: journal.retain_exchange_alice_partial(
                            terms.session_id, changed["partial_signatures_hex"][0], verifier=actual))
                    expected = copy.deepcopy(baseline)
                    expected["partial_signatures_hex"] = changed["partial_signatures_hex"][:1]
                    self.assertEqual(seen, [expected])
                    self.assertEqual(refused, [True])
            with Journal.open(base / "state", base / "head.json") as journal:
                journal.retain_exchange_alice_partial(
                    terms.session_id, original["partial_signatures_hex"][0], verifier=self.verifier)
            with Journal.open(base / "state", base / "head.json") as journal:
                retained = journal.get_exchange(terms.session_id)
                self.assertEqual(retained["stage"], "ALICE_PARTIAL_RETAINED")
                self.assertEqual(retained["alice_partial_hex"], original["partial_signatures_hex"][0])

    def test_equal_total_zenon_bundle_cannot_replace_retained_alice_before_callback(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-collection-retained-") as directory:
            base = Path(directory)
            terms, _, zenon, _, original = self._initialize_collection_exchange(base, "ALICE_PARTIAL_RETAINED")
            baseline = verification_request(zenon, bundle=original)
            self.verifier(baseline)
            seen = []

            def unexpected(request):
                seen.append(copy.deepcopy(request))
                return self.verifier(request)

            for label, changed in self._equal_total_collections(original, wrong_count=False):
                with self.subTest(collection=label):
                    request = verification_request(zenon, bundle=changed)
                    expected = copy.deepcopy(baseline)
                    expected["partial_signatures_hex"] = changed["partial_signatures_hex"]
                    self.assertEqual(request, expected)
                    # This direct equation refusal is separate from the journal's
                    # earlier retained-Alice check, which invokes no verifier.
                    with self.assertRaises(VerificationError):
                        self.verifier(request)
                    self._refuse_collection_without_commit(
                        base, terms.session_id,
                        lambda journal: journal.retain_exchange_zenon(terms.session_id, changed, verifier=unexpected))
                    self.assertEqual(seen, [])
            with Journal.open(base / "state", base / "head.json") as journal:
                journal.retain_exchange_zenon(terms.session_id, original, verifier=self.verifier)
            with Journal.open(base / "state", base / "head.json") as journal:
                retained = journal.get_exchange(terms.session_id)
                self.assertEqual(retained["stage"], "ZENON_RETAINED")
                self.assertEqual(retained["zenon_bundle"], original)
                self.assertFalse(retained["release_may_have_escaped"])
                self.assertFalse(journal.get_session(terms.session_id)["possible_exposure"])
    def _receipt_forger(self, base, mode="bound"):
        import shlex

        actor = Path(__file__).resolve().parents[1] / "tests" / "receipt_forgery_actor.py"
        executable = base / ("synthetic-receipt-" + mode)
        arguments = (sys.executable, "-B", str(actor), mode)
        executable.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(value) for value in arguments) + "\n",
                              encoding="ascii")
        executable.chmod(0o700)
        return SubprocessVerifier(executable.resolve())

    def _receipt_forgery_case(self, stage):
        _, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
        if stage == "BITCOIN_BOUND":
            expected = verification_request(bitcoin, bundle=btc_bundle)
            changed = self._equal_total_collections(btc_bundle, wrong_count=False)[0][1]
            request = verification_request(bitcoin, bundle=changed)
            expected["partial_signatures_hex"] = changed["partial_signatures_hex"]
            self.assertEqual(request, expected)
            return changed, request, "BITCOIN_RETAINED", "bitcoin_bundle", "bitcoin_bundle"
        if stage == "ZENON_BOUND":
            expected = verification_request(zenon, alice_partial=znn_bundle["partial_signatures_hex"][0])
            changed = self._equal_total_collections(znn_bundle, wrong_count=False)[0][1]["partial_signatures_hex"][0]
            request = verification_request(zenon, alice_partial=changed)
            expected["partial_signatures_hex"] = [changed]
            self.assertEqual(request, expected)
            return changed, request, "ALICE_PARTIAL_RETAINED", "alice_partial_hex", "zenon_alice_partial"
        self.assertEqual(stage, "ALICE_PARTIAL_RETAINED")
        expected = verification_request(zenon, bundle=znn_bundle)
        changed = copy.deepcopy(znn_bundle)
        bob = int(changed["partial_signatures_hex"][1], 16)
        changed["partial_signatures_hex"][1] = f"{(bob + 1) % self._ORDER:064x}"
        self.assertEqual(changed["partial_signatures_hex"][0], znn_bundle["partial_signatures_hex"][0])
        self.assertEqual(changed["adaptor_presignature_hex"], znn_bundle["adaptor_presignature_hex"])
        request = verification_request(zenon, bundle=changed)
        expected["partial_signatures_hex"] = changed["partial_signatures_hex"]
        self.assertEqual(request, expected)
        return changed, request, "ZENON_RETAINED", "zenon_bundle", "zenon_bundle"

    def test_actual_canonical_receipt_forgery_is_not_public_equation_verification(self):
        from offline_session.exchange import RESULT_SCHEMA, request_digest

        with tempfile.TemporaryDirectory(prefix="ptlc-receipt-forgery-") as directory:
            base = Path(directory)
            forger = self._receipt_forger(base)
            negative = [self._receipt_forger(base, mode) for mode in ("wrong-digest", "false")]
            digests = []
            for stage in ("BITCOIN_BOUND", "ZENON_BOUND", "ALICE_PARTIAL_RETAINED"):
                with self.subTest(stage=stage):
                    _, request, _, _, _ = self._receipt_forgery_case(stage)
                    before = copy.deepcopy(request)
                    with self.assertRaises(VerificationError):
                        self.verifier(request)
                    expected = {"schema": RESULT_SCHEMA, "request_digest_hex": request_digest(request), "valid": True}
                    # This is a real pipe/exit/receipt path, not a mocked runner.
                    self.assertEqual(forger(request), expected)
                    self.assertEqual(request, before)
                    digests.append(expected["request_digest_hex"])
                    for control in negative:
                        with self.assertRaises(VerificationError):
                            control(request)
                        self.assertEqual(request, before)
            self.assertEqual(len(set(digests)), 3)

    def _retain_forgery_and_reopen(self, base, stage):
        from offline_session.exchange import contexts, request_digest, validate_state

        terms, bitcoin, zenon, _, _ = self._initialize_collection_exchange(base, stage)
        changed, request, next_stage, field, receipt_field = self._receipt_forgery_case(stage)
        context = bitcoin if stage == "BITCOIN_BOUND" else zenon
        derived = (verification_request(context, alice_partial=changed) if stage == "ZENON_BOUND"
                   else verification_request(context, bundle=changed))
        self.assertEqual(request, derived)
        seen, refused = [], []

        def retain(journal, verifier):
            if stage == "BITCOIN_BOUND":
                return journal.retain_exchange_bitcoin(terms.session_id, changed, verifier=verifier)
            if stage == "ZENON_BOUND":
                return journal.retain_exchange_alice_partial(terms.session_id, changed, verifier=verifier)
            return journal.retain_exchange_zenon(terms.session_id, changed, verifier=verifier)

        def actual(value):
            seen.append(copy.deepcopy(value))
            try:
                return self.verifier(value)
            except VerificationError:
                refused.append(True)
                raise

        self._refuse_collection_without_commit(base, terms.session_id, lambda journal: retain(journal, actual))
        self.assertEqual(seen, [request])
        self.assertEqual(refused, [True])
        forger = self._receipt_forger(base)
        forged_calls, events = [], []

        def forged(value):
            forged_calls.append(copy.deepcopy(value))
            return forger(value)

        with Journal.open(base / "state", base / "head.json", hook=events.append) as journal:
            expected = journal.get_session(terms.session_id)
            expected["exchange"]["stage"] = next_stage
            expected["exchange"][field] = copy.deepcopy(changed)
            expected["exchange"]["verification_receipts"][receipt_field] = request_digest(request)
            before_head = (base / "head.json").read_bytes()
            self.assertEqual(events, [])
            retain(journal, forged)
            self.assertEqual(journal.get_session(terms.session_id), expected)
            self.assertEqual(forged_calls, [request])
            expected_events = ["before_db_commit", "after_db_commit", "after_anchor_replace", "after_anchor_commit"]
            if stage == "ALICE_PARTIAL_RETAINED":
                expected_events.append("after_exchange_retained")
            self.assertEqual(events, expected_events)
            persisted_head = (base / "head.json").read_bytes()
            self.assertNotEqual(persisted_head, before_head)
            validate_state(journal.get_exchange(terms.session_id))
        events.clear()
        with Journal.open(base / "state", base / "head.json", hook=events.append) as journal:
            self.assertEqual(journal.get_session(terms.session_id), expected)
            self.assertEqual((base / "head.json").read_bytes(), persisted_head)
            self.assertEqual(events, [])
            self.assertEqual(forged_calls, [request])
            retained = journal.get_exchange(terms.session_id)
            restored_context = contexts(retained)[0 if stage == "BITCOIN_BOUND" else 1]
            self.assertEqual(restored_context.as_dict(), context.as_dict())
            restored_request = (verification_request(restored_context, alice_partial=retained[field]) if stage == "ZENON_BOUND"
                                else verification_request(restored_context, bundle=retained[field]))
            self.assertEqual(restored_request, request)
            validate_state(retained)
            with self.assertRaises(VerificationError):
                self.verifier(restored_request)
            self.assertFalse(retained["release_may_have_escaped"])
            self.assertFalse(journal.get_session(terms.session_id)["possible_exposure"])
            self.assertEqual(journal.get_session(terms.session_id), expected)
            self.assertEqual((base / "head.json").read_bytes(), persisted_head)
            self.assertEqual(events, [])

    def test_actual_forged_bitcoin_bundle_is_retained_through_structural_reopen(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-forged-bitcoin-") as directory:
            self._retain_forgery_and_reopen(Path(directory), "BITCOIN_BOUND")

    def test_actual_forged_zenon_alice_partial_is_retained_through_structural_reopen(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-forged-alice-") as directory:
            self._retain_forgery_and_reopen(Path(directory), "ZENON_BOUND")

    def test_actual_forged_zenon_bob_bundle_is_retained_through_structural_reopen(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-forged-bob-") as directory:
            self._retain_forgery_and_reopen(Path(directory), "ALICE_PARTIAL_RETAINED")

    def test_actual_same_adapter_path_replacement_does_not_preserve_native_program(self):
        import hashlib
        import shutil
        from offline_session.exchange import RESULT_SCHEMA, request_digest

        _, bitcoin, zenon, btc_bundle, znn_bundle = artifacts()
        stages = ("BITCOIN_BOUND", "ZENON_BOUND", "ALICE_PARTIAL_RETAINED")
        valid = (verification_request(bitcoin, bundle=btc_bundle),
                 verification_request(zenon, alice_partial=znn_bundle["partial_signatures_hex"][0]),
                 verification_request(zenon, bundle=znn_bundle))
        invalid = tuple(self._receipt_forgery_case(stage)[1] for stage in stages)
        original_requests = copy.deepcopy((valid, invalid))

        with tempfile.TemporaryDirectory(prefix="ptlc-program-continuity-") as directory:
            base = Path(directory).resolve()
            original = Path(self.verifier._executable)
            original_pin = hashlib.sha256(original.read_bytes()).digest()
            selected = base / "selected-verifier"
            shutil.copyfile(original, selected)
            selected.chmod(0o700)
            selected_pin = hashlib.sha256(selected.read_bytes()).digest()
            self.assertEqual(selected_pin, original_pin)
            identity = (selected.stat().st_dev, selected.stat().st_ino)
            adapter = SubprocessVerifier(selected)
            selected_path = adapter._executable
            self.assertEqual(selected_path, str(selected))

            def native_controls():
                for stage, good, bad in zip(stages, valid, invalid):
                    with self.subTest(stage=stage):
                        expected = {"schema": RESULT_SCHEMA, "request_digest_hex": request_digest(good), "valid": True}
                        self.assertEqual(adapter(good), expected)
                        with self.assertRaises(VerificationError):
                            adapter(bad)
                self.assertEqual((valid, invalid), original_requests)

            # Establish actual native execution before changing the selection.
            native_controls()
            retained = selected.replace(base / "retained-native")
            self.assertFalse(selected.exists())
            with self.assertRaises(VerificationError) as refused:
                adapter(invalid[0])
            self.assertNotIn(str(base), str(refused.exception))
            self.assertEqual(adapter._executable, selected_path)
            retained.replace(selected)
            self.assertEqual((selected.stat().st_dev, selected.stat().st_ino), identity)

            # The real synthetic actor replaces the file between completed calls.
            # This selects no measurement/launch race or guarded worker profile.
            replacement = Path(self._receipt_forger(base)._executable)
            selected.replace(retained)
            replacement.replace(selected)
            self.assertNotEqual((selected.stat().st_dev, selected.stat().st_ino), identity)
            self.assertNotEqual(hashlib.sha256(selected.read_bytes()).digest(), selected_pin)
            self.assertEqual(adapter._executable, selected_path)
            for stage, bad in zip(stages, invalid):
                with self.subTest(stage=stage, program="substituted"):
                    expected = {"schema": RESULT_SCHEMA, "request_digest_hex": request_digest(bad), "valid": True}
                    self.assertEqual(adapter(bad), expected)
                    # Independent original selection still refuses the same bytes.
                    with self.assertRaises(VerificationError):
                        self.verifier(bad)
            self.assertEqual((valid, invalid), original_requests)

            retained.replace(selected)
            self.assertEqual((selected.stat().st_dev, selected.stat().st_ino), identity)
            self.assertEqual(hashlib.sha256(selected.read_bytes()).digest(), selected_pin)
            self.assertEqual(adapter._executable, selected_path)
            native_controls()
            self.assertEqual(hashlib.sha256(original.read_bytes()).digest(), original_pin)


def main():
    parser = argparse.ArgumentParser(description="Offline public-verifier integration; no signing or transport")
    parser.add_argument("--verifier", required=True, help="Path to the locally built verify_exchange executable")
    args = parser.parse_args()
    try:
        RealVerifierExchangeTests.verifier = SubprocessVerifier(Path(args.verifier).resolve())
    except VerificationError:
        parser.error("verifier executable is unavailable")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RealVerifierExchangeTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
