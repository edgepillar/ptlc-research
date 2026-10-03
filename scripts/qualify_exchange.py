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
                journal.start_exchange(terms.session_id, bitcoin)
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
