"""Replay selected finite-model traces using actual public executables.

No authorization implementation, private signer, chain event or network access
is introduced. Failure/cancellation are labeled synthetic injections.
"""

import argparse
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.completion_verifier import SubprocessCompletion
from test_recovery_model_journal import ACTUAL_CASES, RecoveryModelJournalTests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--completion", required=True)
    args = parser.parse_args()
    RecoveryModelJournalTests.verifier = SubprocessVerifier(Path(args.verifier).resolve())
    RecoveryModelJournalTests.recoverer = SubprocessCompletion(Path(args.completion).resolve())
    suite = unittest.TestSuite(RecoveryModelJournalTests(name) for name in ACTUAL_CASES)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
