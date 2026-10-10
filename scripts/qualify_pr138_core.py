#!/usr/bin/env python3
"""Offline differential tests against the exact clean PR #138 node source pin.

Go's overlay adds only an independently written test driver. It edits no node
file and obtains no dependencies. Original output is retained privately, never
printed as an environment log or converted into hosted/activation evidence.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.pr138 import CORE_COMMIT  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--go", type=Path, required=True)
    args = parser.parse_args()
    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(args.checkout), *arguments], stderr=subprocess.DEVNULL).strip()
    try:
        if git("rev-parse", "HEAD").decode("ascii") != CORE_COMMIT or git("status", "--porcelain"):
            raise ValueError()
        evidence = ROOT / ".research-cache/roadmap-compat-recovery"
        evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(dir=evidence, prefix="core-overlay-") as directory:
            overlay = Path(directory) / "overlay.json"
            injected = args.checkout.resolve() / "vm/embedded/implementation/zz_research_compatibility_test.go"
            overlay.write_text(json.dumps({"Replace": {str(injected): str(ROOT / "compatibility/core_overlay_test.go.txt")}}), encoding="ascii")
            env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", PTLC_COMPAT_FIXTURE_ROOT=str(ROOT / "compatibility/fixtures"))
            log_fd, log_name = tempfile.mkstemp(prefix="core-differential-", suffix=".log", dir=evidence)
            with os.fdopen(log_fd, "wb") as output:
                result = subprocess.run([str(args.go.resolve()), "test", "-overlay", str(overlay), "-vet=off", "-mod=readonly", "-count=1", "-run", "^TestResearchPR138CompatibilityCorpus$", "./vm/embedded/implementation"],
                                        cwd=args.checkout, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=180)
            unchanged = git("rev-parse", "HEAD").decode("ascii") == CORE_COMMIT and not git("status", "--porcelain")
            record = {"schema": "zenon-pr138-core-differential-result-v1", "core_commit": CORE_COMMIT,
                      "exit_code": result.returncode, "source_unchanged": unchanged,
                      "messages": 48, "witnesses": 26, "destinations": 15, "nom_completions": 2,
                      "overlay_vet": "NOT_PERFORMED; Go 1.23 cannot open the synthetic overlay path",
                      "hosted_core_verification": "NOT_PERFORMED", "activation": "NOT_PERFORMED"}
            Path(log_name + ".json").write_text(json.dumps(record, sort_keys=True) + "\n", encoding="ascii")
            if result.returncode != 0 or not unchanged: raise ValueError()
            print(json.dumps(record, sort_keys=True))
            return 0
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError):
        print("FAIL: pinned offline core differential; retain original private evidence", file=sys.stderr)
        return 1


if __name__ == "__main__": sys.exit(main())
