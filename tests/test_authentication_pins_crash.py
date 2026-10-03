"""Real process death during durable pin setup and read-only authentication."""

import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest

from offline_session import exchange
from offline_session.journal import Journal, Quarantined
from exchange_test_support import artifacts


@unittest.skipUnless(os.name == "posix", "qualification requires POSIX process signals")
class AuthenticationPinCrashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.terms, cls.bitcoin, *_ = artifacts()
        cls.session = cls.terms.session_id
        cls.vector = json.loads((Path(__file__).resolve().parents[1]
                                 / "qualification/fixtures/authentication.json").read_text("ascii"))
        cls.pins = {key: cls.vector["envelope"]["context"][key]
                    for key in ("alice_auth_key_hex", "bob_auth_key_hex")}

    def kill(self, mode, root, anchor, checkpoint):
        actor = Path(__file__).with_name("authentication_pins_crash_actor.py")
        child = subprocess.Popen([sys.executable, "-B", str(actor), mode, str(root), str(anchor),
                                  self.session, checkpoint], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as selection:
                selection.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selection.select(timeout=20), "authentication checkpoint timed out")
            self.assertEqual(child.stdout.readline().strip(), b"paused")
            child.kill()
            stdout, stderr = child.communicate(timeout=10)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            self.assertEqual((stdout, stderr), (b"", b""))
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def test_pin_start_kill_matrix_keeps_prior_choice_commits_new_choice_or_quarantines_gap(self):
        for checkpoint in ("before_db_commit", "after_db_commit", "after_anchor_replace", "after_anchor_commit"):
            with self.subTest(checkpoint=checkpoint), \
                    tempfile.TemporaryDirectory(prefix="synthetic-pin-start-crash-") as directory:
                base = Path(directory)
                root, anchor = base / "state", base / "head.json"
                with Journal.open(root, anchor) as journal:
                    journal.create_session(self.session, self.terms.digest_hex)
                    before = journal.get_session(self.session)
                    sequence = journal._sequence
                self.kill("start", root, anchor, checkpoint)
                if checkpoint == "after_db_commit":
                    with self.assertRaises(Quarantined):
                        Journal.open(root, anchor)
                    continue
                with Journal.open(root, anchor) as journal:
                    if checkpoint == "before_db_commit":
                        self.assertEqual(journal.get_session(self.session), before)
                        self.assertEqual(journal._sequence, sequence)
                        journal.start_exchange(self.session, self.bitcoin, recovery_limit=8,
                                               authentication_pins=self.pins)
                    else:
                        # SIGKILL after rename is not a power-loss durability claim.
                        self.assertEqual(journal._sequence, sequence + 1)
                    session = journal.get_session(self.session)
                    self.assertEqual(session["authentication_pins"], self.pins)
                    self.assertEqual(session["exchange"]["stage"], "BITCOIN_BOUND")
                    self.assertEqual(session["recovery_budget"], {"limit": 8, "consumed": 0})
                    self.assertFalse(session["possible_exposure"])

    def test_kill_during_public_authentication_leaves_exact_state_and_bytes_unchanged(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-readonly-authentication-crash-") as directory:
            base = Path(directory)
            root, anchor = base / "state", base / "head.json"
            with Journal.open(root, anchor) as journal:
                journal.create_session(self.session, self.terms.digest_hex)
                journal.start_exchange(self.session, self.bitcoin, recovery_limit=8, authentication_pins=self.pins)
                before = journal.get_session(self.session), journal._sequence
            disk = (root / "journal.sqlite3").read_bytes(), anchor.read_bytes()
            self.kill("authenticate", root, anchor, "during_authentication_verifier")
            self.assertEqual(((root / "journal.sqlite3").read_bytes(), anchor.read_bytes()), disk)
            with Journal.open(root, anchor) as journal:
                self.assertEqual((journal.get_session(self.session), journal._sequence), before)
                self.assertEqual(journal.authenticate_exchange_envelope(
                    self.session, exchange.canonical(self.vector["envelope"]),
                    verifier=lambda _: self.vector["result"].copy(),
                ), bytes.fromhex(self.vector["envelope"]["payload_hex"]))
                self.assertEqual((journal.get_session(self.session), journal._sequence), before)
            self.assertEqual(((root / "journal.sqlite3").read_bytes(), anchor.read_bytes()), disk)


if __name__ == "__main__":
    unittest.main()
