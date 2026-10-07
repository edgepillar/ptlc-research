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
