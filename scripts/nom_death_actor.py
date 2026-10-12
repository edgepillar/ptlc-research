"""Explicit process-death actor for disclosed offline reference-journal cuts.

The parent retains this selected actor, runtime, public worker and input bytes
before spawn. os._exit deliberately skips Python cleanup after a complete fsync
or after an actual public reply. This is not a power-loss or hostile-child test.
"""

import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_recovery import NomRecovery, RecoveryError, canonical  # noqa: E402
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE  # noqa: E402
from scripts.nom_cut_capture import OriginalCapture, retain, sha  # noqa: E402
from scripts import qualify_nom_recovery_cuts as prior  # noqa: E402


def run(config):
    directory = Path(config["directory"])
    executable = Path(config["executable"])
    if (sha(executable.read_bytes()) != config["executable_sha256"]
            or any(sha((ROOT / name).read_bytes()) != value
                   for name, value in config["input_sha256"].items())):
        raise ValueError("selected actor inputs changed before worker entry")
    terms, pair, short, funded, confirmed = prior.selected_inputs(ROOT)
    allowed = {canonical(proof) for proof in funded + [confirmed]}
    observed = []
    capture = OriginalCapture(directory / "worker", executable, config["executable_sha256"])
    capture.phase = config["cut"] + ":write"
    verifier = NomPublicVerifier(executable, config["executable_sha256"], terms, pair,
                                 execution_profile=CLEAN_EXECUTION_PROFILE)

    def die(hook_kind):
        receipt = dict(cut=config["cut"], hook_kind=hook_kind, method="os._exit(72)",
            recovery_worker_entries=counted.entries, recovery_worker_returns=counted.returns,
            returned_result=counted.returned_result, write_modes=counted.modes,
            observer_calls_before_cut=observed)
        # All worker original files already exist before this separate receipt.
        # Its returned_result is diagnostic custody, never journal replacement.
        retain(directory / "cut-receipt.json", canonical(receipt))
        sys.stdout.buffer.write(canonical(dict(schema="ptlc-nom-death-actor-v1",
                                               cut=config["cut"], method="os._exit(72)")) + b"\n")
        sys.stdout.buffer.flush()
        os._exit(72)

    class DeathVerifier(prior.CountedVerifier):
        def recover_long(self, signature):
            result = super().recover_long(signature)
            if config["cut"] == "after-public-reply":
                die("PUBLIC REPLY RETURNED; BEFORE RECOVERED APPEND")
            return result

    counted = DeathVerifier(verifier)
    def observer(proof):
        observed.append(canonical(proof).hex())
        return canonical(proof) in allowed

    def hook(kind):
        if config["cut"] == "after-" + kind:
            die(kind)

    with patch("offline_session.nom_verifier.run_clean_environment_public_worker", capture.run):
        with NomRecovery.open(directory / "journal.log", terms, pair, role="bob",
                verifier=counted, observation_verifier=observer, hook=hook) as store:
            for proof in funded:
                store.record_observation(proof)
            store.recover_long(short, confirmed)
    raise ValueError("selected explicit process-death boundary was not reached")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("one selected private configuration is required")
        run(json.loads(Path(sys.argv[1]).read_text("ascii")))
    except (OSError, RecoveryError, ValueError, KeyError, TypeError):
        print("FAIL: selected reference process-death actor; preserve original evidence", file=sys.stderr)
        raise SystemExit(1)
