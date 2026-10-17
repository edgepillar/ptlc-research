#!/usr/bin/env python3
"""Exercise snapshot journals with one explicitly selected public-only worker.

OriginalCapture replaces the runner only in this single-thread qualification.
Its trusted, nonforking worker and post-collection stream bounds are not a
hostile-process sandbox. Observations are a disclosed synthetic allowlist.
"""

import argparse
import copy
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_recovery import (  # noqa: E402
    RecoveryError, canonical, observation, synthetic_claim, synthetic_transaction_hash,
)
from offline_session.nom_recovery_snapshot import SnapshotNomRecovery  # noqa: E402
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE  # noqa: E402
from scripts.nom_cut_capture import OriginalCapture, sha  # noqa: E402
from scripts.qualify_nom_recovery_cuts import CountedVerifier  # noqa: E402


def exercise(verifier, directory, *, root=ROOT):
    """The caller separately selects and qualifies the actual public verifier."""
    if sys.flags.optimize:
        raise ValueError("snapshot qualification requires assertions enabled")
    terms = json.loads((root / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
    fixture = json.loads((root / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
    short = synthetic_claim(terms, "short", fixture["short_signature_hex"])
    long = synthetic_claim(terms, "long", fixture["long_signature_hex"])
    funded = [observation(terms, leg, "funded") for leg in ("long", "short")]
    confirmed = observation(terms, "short", "unlock-confirmed",
        transaction_hash_hex=synthetic_transaction_hash(short), send_timestamp="900",
        send_momentum_hash_hex="aa" * 32, receive_timestamp="1100", receive_momentum_hash_hex="bb" * 32)
    unseen = observation(terms, "short", "unseen", transaction_hash_hex=synthetic_transaction_hash(short))
    allowed = {canonical(proof) for proof in funded + [confirmed, unseen]}
    active = {}
    changed = []
    def observer(proof):
        approved = canonical(proof) in allowed
        if active:
            changed.append(canonical(proof).hex())
            active["caller"].clear()
            active["caller"].update(copy.deepcopy(funded[1]))
        return approved
    def open_store(role, callback=observer):
        return SnapshotNomRecovery.open(directory / (role + ".log"), terms, fixture["pair"],
            role=role, verifier=verifier, observation_verifier=callback)
    with open_store("alice") as alice:
        caller = copy.deepcopy(funded[0])
        active["caller"] = caller
        alice.record_observation(caller)
        active.clear()
        assert alice.status()["funded"] == {"long": True}
        assert alice.status()["observations"] == [funded[0]]
        alice.record_observation(funded[1])
        alice.retain_original("short", short)
        assert alice.prepare_attempt("short") == short
    with open_store("alice") as alice:
        assert alice.status()["phases"]["short"] == "OUTCOME_UNKNOWN"
        alice.record_observation(unseen)
        assert alice.prepare_attempt("short") == short
        alice.record_observation(confirmed)
    with open_store("bob") as bob:
        for proof in funded:
            bob.record_observation(proof)
        caller = copy.deepcopy(confirmed)
        active["caller"] = caller
        assert bob.recover_long(short, caller) == long
        active.clear()
        assert bob.status()["observations"][-1] == confirmed
        assert bob.prepare_attempt("long") == long
    with open_store("bob") as bob:
        assert bob.status()["phases"]["long"] == "OUTCOME_UNKNOWN"
        assert bob.prepare_attempt("long") == long
        assert bob.recover_long(short, confirmed) == long
        assert bob.status()["recovery_count"] == 1
        assert bytes.fromhex(bob.status()["remote_short_hex"]) == short
    assert changed == [canonical(funded[0]).hex(), canonical(confirmed).hex()]
    def changing_observer(proof):
        proof.clear()
        proof.update(copy.deepcopy(funded[1]))
        return True
    with SnapshotNomRecovery.open(directory / "callback-control.log", terms, fixture["pair"],
            role="alice", verifier=verifier, observation_verifier=changing_observer) as control:
        before = (directory / "callback-control.log").read_bytes()
        try:
            control.record_observation(funded[0])
        except RecoveryError:
            pass
        else:
            raise ValueError("changed observation callback argument was accepted")
        assert (directory / "callback-control.log").read_bytes() == before
        assert control.status()["funded"] == {}
    for leg in ("long", "short"):
        try:
            verifier.verify_claim(leg, "00" * 64)
        except RecoveryError:
            pass
        else:
            raise ValueError("invalid public completion was accepted")
    assert verifier.entries == verifier.returns == 1
    return dict(two_journal_original_recovery="PASS", caller_alias_controls=2,
        changed_callback_argument="REFUSED_WITHOUT_APPEND", lost_reply="ORIGINAL_ONLY",
        recovery_worker_entries=verifier.entries, recovery_worker_returns=verifier.returns,
        invalid_completions="REFUSED", observation_source="DISCLOSED_SYNTHETIC_ALLOWLIST_ONLY")


def qualify(executable, expected_pin, evidence, *, root=ROOT):
    if sys.flags.optimize:
        raise ValueError("snapshot qualification requires assertions enabled")
    if (not evidence.is_absolute() or evidence.is_symlink() or not evidence.is_dir()
            or any(evidence.iterdir())):
        raise ValueError("explicit empty private evidence directory required")
    terms = json.loads((root / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
    fixture = json.loads((root / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
    selected = NomPublicVerifier(executable, expected_pin, terms, fixture["pair"],
        execution_profile=CLEAN_EXECUTION_PROFILE)
    directories = {name: evidence / name for name in ("worker", "journals")}
    for path in directories.values():
        path.mkdir(mode=0o700)
    capture = OriginalCapture(directories["worker"], executable, expected_pin)
    capture.phase = "nom-observation-snapshot"
    counted = CountedVerifier(selected)
    with patch("offline_session.nom_verifier.run_clean_environment_public_worker", capture.run):
        result = exercise(counted, directories["journals"], root=root)
    assert len(capture.calls) == len(counted.modes)
    assert all(row["stream_completeness"] == "COMPLETE" for row in capture.calls)
    assert [row["exit_code"] for row in capture.calls[-2:]] == [2, 2]
    assert all(row["exit_code"] == 0 for row in capture.calls[:-2])
    assert sha(executable.read_bytes()) == expected_pin
    return dict(schema="ptlc-nom-observation-snapshot-qualification-v1", result=result,
        execution_profile=CLEAN_EXECUTION_PROFILE, executable_sha256=expected_pin,
        public_worker_calls=len(capture.calls), original_worker_streams="RETAINED_IN_PRIVATE_EVIDENCE",
        original_capture="SINGLE_THREAD_QUALIFICATION_TRANSPORT; NOT_APPLICATION_RUNNER",
        build_and_runtime_authentication="SEPARATE_UNFILLED_GATE",
        historical_record_authentication="NOT_ADDED", actual_signed_wire="NOT_COMPOSED",
        assessment="AUTHOR_TECHNICAL_REVIEW; NOT_INDEPENDENT", independent_assessment="UNFILLED",
        application="NO-GO", core="NO-GO", recovery_action="NONE")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--expect-executable-sha256", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = qualify(args.executable, args.expect_executable_sha256, args.evidence)
    except (OSError, RecoveryError, AssertionError, ValueError):
        print("FAIL: NoM observation snapshot qualification; original evidence retained", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
