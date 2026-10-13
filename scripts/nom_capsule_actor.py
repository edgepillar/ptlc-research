"""Selected actual process exit after ordinary capsule persistence calls.

The caller retains sources, runtime, worker and inputs before spawn. Exit 73
skips cleanup. This does not exercise power loss or interior syscall faults.
"""
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import nom_capsule as capsule, nom_journal_hold as projection  # noqa: E402
from offline_session.nom_recovery import RecoveryError, canonical  # noqa: E402
from offline_session.nom_strict_open import StrictNomRecovery  # noqa: E402
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE  # noqa: E402
from scripts.nom_cut_capture import OriginalCapture, retain, sha  # noqa: E402
from scripts import qualify_nom_journal_hold as prior  # noqa: E402


def run(config):
    directory = Path(config["directory"]); executable = Path(config["executable"])
    if (config["cut"] not in capsule.PHASES or sha(executable.read_bytes()) != config["executable_sha256"]
            or any(sha((ROOT/name).read_bytes()) != pin for name,pin in config["input_sha256"].items())):
        raise ValueError("selected capsule actor inputs changed")
    terms, pair, _, _, _ = prior.prior.prior.prior.selected_inputs(ROOT)
    capture = OriginalCapture(directory/"worker", executable, config["executable_sha256"])
    capture.phase = config["cut"] + ":strict-projection"
    verifier = NomPublicVerifier(executable, config["executable_sha256"], terms, pair,
                                 execution_profile=CLEAN_EXECUTION_PROFILE)
    counted = prior.prior.prior.prior.CountedVerifier(verifier)
    with patch("offline_session.nom_verifier.run_clean_environment_public_worker", capture.run):
        with StrictNomRecovery.open(Path(config["journal"]), terms, pair, role="bob",
                                   verifier=counted, observation_verifier=lambda _: False) as journal:
            selected = projection.project_partial_hold(journal, challenge_hex=prior.CHALLENGES[0])
    wire = capsule.encode_capsule(selected)
    def die(phase):
        if phase != config["cut"]: return
        receipt = dict(schema="ptlc-nom-capsule-actor-v1", cut=phase, method="os._exit(73)",
            expected_capsule_sha256=sha(wire), expected_capsule_bytes=len(wire),
            journal_sha256=sha(selected.journal_bytes), strict_open_modes=counted.modes,
            capsule_worker_entries=0, recovery_worker_entries=counted.entries,
            application="NO-GO", core="NO-GO", recovery_action="NONE")
        retain(directory/"cut-receipt.json", canonical(receipt))
        sys.stdout.buffer.write(canonical(receipt)+b"\n"); sys.stdout.buffer.flush()
        os._exit(73)
    with patch.object(capsule, "_phase", side_effect=die):
        with capsule.CapsuleOwner.create(directory/"owner") as owner:
            owner.store(selected)
    raise ValueError("selected capsule process cut was not reached")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2: raise ValueError("one selected private configuration is required")
        run(json.loads(Path(sys.argv[1]).read_text("ascii")))
    except (OSError, RecoveryError, ValueError, KeyError, TypeError):
        print("FAIL: selected capsule actor; preserve original evidence", file=sys.stderr)
        raise SystemExit(1)
