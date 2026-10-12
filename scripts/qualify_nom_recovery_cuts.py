#!/usr/bin/env python3
"""Qualify selected post-fsync journal cuts with an actual public Rust worker.

Reopen is read-only: no automatic recovery, completion-to-original conversion,
attempt, or partial-hold admission. All observation inputs are disclosed synthetic
allowlist values, never authenticated current chain facts. The reply-withheld case
keeps its actual response in separate qualification evidence; it is absent from
the original journal, not proven globally lost. Application and core remain NO-GO.
"""

import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session.nom_recovery import (  # noqa: E402
    NomRecovery, RecoveryError, Quarantined, canonical, decode, digest,
    observation, synthetic_claim, synthetic_transaction_hash,
)
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE  # noqa: E402
from scripts.nom_cut_capture import OriginalCapture, retain, sha  # noqa: E402
from scripts import qualify_nom_partial_custody as prior  # noqa: E402


PROFILE = "ptlc-nom-reference-cuts-v1"
BASE = "9cf598b2bf935d54da140a846d8886af13e0df0a"
FIXTURE = "compatibility/fixtures/nom_recovery_cuts_v1.json"
MANIFEST = "compatibility/nom_recovery_cuts_manifest.json"
SELECTED = ("scripts/nom_cut_capture.py", "scripts/qualify_nom_recovery_cuts.py",
            "tests/test_nom_recovery_cuts.py", FIXTURE)
NATIVE_INPUTS = ("offline_session/public_worker.py", "qualification/src/lib.rs")
CUTS = ("after-remote-short", "after-recovery-admitted", "worker-reply-withheld",
        "after-recovered", "after-original")
BOUNDARY = dict(application="NO-GO", core="NO-GO", recovery_action="NONE",
    hold_admission="NOT_COMPOSED", native_query_context="NOT_COMPOSED",
    observation_source="DISCLOSED SYNTHETIC ALLOWLIST ONLY",
    current_chain_authority="UNFILLED", restore_fence="UNFILLED",
    atomic_work_admission="UNFILLED", independent_runtime="UNFILLED",
    process_death="NOT_PERFORMED", interior_write_or_fsync_fault="NOT_PERFORMED",
    cut_kind="CONTROLLED POST-FSYNC EXCEPTION OR WITHHELD WORKER REPLY",
    runner="SEPARATE SINGLE-THREAD ORIGINAL-CAPTURE QUALIFICATION TRANSPORT",
    hostile_process_containment="NOT_ESTABLISHED")


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Disclosed public synthetic journal and observation inputs only",
        cases=[dict(cut=cut, charged=0 if index == 0 else 1,
                    retained_result=index >= 3, retained_long_original=index == 4,
                    recovery_worker_entries=1 if index >= 2 else 0)
               for index, cut in enumerate(CUTS)], boundary=BOUNDARY)


def inputs(root=ROOT):
    _, _, preserved = prior.inputs(root)
    selected = {name: sha((root / name).read_bytes()) for name in SELECTED}
    native = {name: sha((root / name).read_bytes()) for name in NATIVE_INPUTS}
    expected = dict(schema="ptlc-nom-reference-cuts-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected,
        preserved_file_sha256=preserved, native_file_sha256=native, boundary=BOUNDARY)
    if json.loads((root / FIXTURE).read_text("ascii")) != corpus():
        raise ValueError("selected cut corpus changed")
    if json.loads((root / MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected original cut inputs changed")
    return expected, {**preserved, **native, **selected, MANIFEST: sha((root / MANIFEST).read_bytes())}


def selected_inputs(root=ROOT):
    terms = json.loads((root / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
    fixture = json.loads((root / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
    short = synthetic_claim(terms, "short", fixture["short_signature_hex"])
    funded = [observation(terms, leg, "funded") for leg in ("long", "short")]
    confirmed = observation(terms, "short", "unlock-confirmed",
        transaction_hash_hex=synthetic_transaction_hash(short), send_timestamp="900",
        send_momentum_hash_hex="aa" * 32, receive_timestamp="1100", receive_momentum_hash_hex="bb" * 32)
    return terms, fixture["pair"], short, funded, confirmed


class WithheldReply(RecoveryError):
    """A known returned reply is deliberately not delivered to the journal."""


class CountedVerifier:
    def __init__(self, verifier, *, withhold=False):
        self.verifier = verifier
        self.context_digest_hex = verifier.context_digest_hex
        self.withhold = withhold
        self.entries = 0
        self.returns = 0
        self.returned_result = None
        self.modes = []

    def verify_pair(self):
        self.modes.append("verify-pair")
        return self.verifier.verify_pair()

    def verify_claim(self, leg, signature):
        self.modes.append("verify-" + leg)
        return self.verifier.verify_claim(leg, signature)

    def recover_long(self, signature):
        self.modes.append("recover-long")
        self.entries += 1
        result = self.verifier.recover_long(signature)
        self.returns += 1
        self.returned_result = result
        if self.withhold:
            raise WithheldReply("public reply withheld before journal retention")
        return result


def journal_records(wire):
    if not wire or not wire.endswith(b"\n"):
        raise ValueError("complete original records required")
    rows = [decode(line) for line in wire.splitlines()]
    previous = "00" * 32
    for index, row in enumerate(rows, 1):
        body = {key: value for key, value in row.items() if key != "hash_hex"}
        if (row.keys() != {"schema", "sequence", "previous_hash_hex", "event", "hash_hex"}
                or row["schema"] != "ptlc-nom-recovery-log-v1" or row["sequence"] != index
                or row["previous_hash_hex"] != previous
                or row["hash_hex"] != digest(b"ptlc-nom-log-v1", body)):
            raise ValueError("original record sequence or self-hash changed")
        previous = row["hash_hex"]
    return rows


def describe(status, wire):
    records = journal_records(wire)
    return dict(journal_sha256=sha(wire), journal_hex=wire.hex(),
        event_kinds=[row["event"]["kind"] for row in records],
        remote_short_hex=status["remote_short_hex"], charged=status["recovery_count"],
        retained_result=status["recovered_long_hex"] or None,
        retained_long_original=status["originals"].get("long"),
        disclosure_possible=status["disclosure_possible"],
        admitted_partial_profile=status["recovery_count"] > 0)


def rewrite_self_hashes(wire, change):
    """Adversarial test construction only; never replaces an original journal."""
    records = copy.deepcopy(journal_records(wire))
    change(records)
    previous = "00" * 32
    result = []
    for index, row in enumerate(records, 1):
        row.update(sequence=index, previous_hash_hex=previous)
        row.pop("hash_hex")
        row["hash_hex"] = digest(b"ptlc-nom-log-v1", row)
        previous = row["hash_hex"]
        result.append(canonical(row) + b"\n")
    return b"".join(result)


def exercise(verifier, directory, *, root=ROOT, phase=lambda value: None):
    """Selected reference scenarios; the caller separately qualifies its verifier."""
    terms, pair, short, funded, confirmed = selected_inputs(root)
    allowed = {canonical(proof) for proof in funded + [confirmed]}
    rows = []
    originals = {}
    for cut in CUTS:
        phase(cut + ":write")
        counted = CountedVerifier(verifier, withhold=cut == "worker-reply-withheld")
        observed = []
        def observer(proof):
            observed.append(canonical(proof).hex())
            return canonical(proof) in allowed
        target = cut.removeprefix("after-") if cut.startswith("after-") else None
        reached = []
        def hook(kind):
            if kind == target:
                reached.append(kind)
                raise RuntimeError("selected post-fsync cut")
        path = directory / (cut + ".log")
        with NomRecovery.open(path, terms, pair, role="bob", verifier=counted,
                              observation_verifier=observer, hook=hook) as store:
            for proof in funded:
                store.record_observation(proof)
            try:
                store.recover_long(short, confirmed)
            except (Quarantined, WithheldReply) as error:
                if type(error) is not (WithheldReply if cut == "worker-reply-withheld" else Quarantined):
                    raise ValueError("unexpected selected interruption") from None
            else:
                raise ValueError("selected interruption did not occur")
        original = path.read_bytes()
        originals[cut] = original
        before = (counted.entries, counted.returns, len(counted.modes))
        phase(cut + ":reopen")
        # Reject every observation if called. Replay does not reinvoke this
        # callback; retained funding remains history, never current authority.
        replay_observer_calls = []
        def rejecting_observer(proof):
            replay_observer_calls.append(canonical(proof).hex())
            return False
        with NomRecovery.open(path, terms, pair, role="bob", verifier=counted,
                              observation_verifier=rejecting_observer) as store:
            status = store.status()
            row = describe(status, original)
        reopen_modes = counted.modes[before[2]:]
        if path.read_bytes() != original or (counted.entries, counted.returns) != before[:2]:
            raise ValueError("reopen changed original history or admitted worker work")
        if replay_observer_calls:
            raise ValueError("selected replay callback behavior changed")
        result_check = "ABSENT; NOT SUPPLIED FROM FIXTURE"
        if row["retained_result"] is not None:
            phase(cut + ":separate-result-verification")
            if counted.verify_claim("long", row["retained_result"]) is not True:
                raise ValueError("retained public result failed separate verification")
            result_check = "SEPARATELY PUBLIC-WORKER VERIFIED AFTER REOPEN"
        row.update(cut=cut, post_fsync_hook=reached, recovery_worker_entries=before[0],
            recovery_worker_returns=before[1], reopen_modes=reopen_modes,
            observer_calls_before_cut=observed, observer_calls_on_replay=0,
            result_check=result_check, automatic_worker_entries_on_reopen=0,
            journal_unchanged_after_reopen=True, qualification_reply_retained=counted.returned_result is not None)
        rows.append(row)
    phase("invalid-result-only:reopen")
    changed = rewrite_self_hashes(originals["after-recovered"],
        lambda records: records[-1]["event"].update(signature_hex="00" * 64))
    tampered = directory / "adversarial-result-only.log"
    retain(tampered, changed)
    counted = CountedVerifier(verifier)
    with NomRecovery.open(tampered, terms, pair, role="bob", verifier=counted,
                          observation_verifier=lambda proof: False) as store:
        status = store.status()
    if status["recovered_long_hex"] != "00" * 64 or status["originals"]:
        raise ValueError("selected invalid result-only replay behavior changed")
    reopen_modes = list(counted.modes)
    phase("invalid-result-only:separate-result-verification")
    try:
        counted.verify_claim("long", status["recovered_long_hex"])
    except RecoveryError:
        pass
    else:
        raise ValueError("invalid result passed separate public verification")
    phase("coherent-old-copy:reopen")
    old = directory / "adversarial-old-prefix.log"
    retain(old, originals["after-recovery-admitted"])
    with NomRecovery.open(old, terms, pair, role="bob", verifier=verifier,
                          observation_verifier=lambda proof: False) as store:
        old_status = store.status()
    if old_status["recovered_long_hex"] or old_status["originals"] or old_status["recovery_count"] != 1:
        raise ValueError("selected old complete prefix behavior changed")
    if any((directory / (cut + ".log")).read_bytes() != value for cut, value in originals.items()):
        raise ValueError("original journal replaced by adversarial evidence")
    return dict(cases=rows, adversarial_controls=dict(
        invalid_result_only_reopen="ACCEPTED ENCODING; NO LONG MATH ON OPEN",
        invalid_result_only_reopen_modes=reopen_modes,
        separate_invalid_result_verification="REFUSED",
        coherent_old_prefix="ACCEPTED; NO RESTORE AUTHORITY",
        replayed_funding="HISTORICAL ONLY; REJECTING OBSERVER NOT REINVOKED",
        original_journals_unchanged=True), synthetic_allowlist_hex=sorted(allowed_value.hex() for allowed_value in allowed))


def check_cases(result):
    if len(result["cases"]) != len(CUTS):
        raise ValueError("missing selected interruption case")
    for row, selected in zip(result["cases"], corpus()["cases"]):
        if (row["cut"] != selected["cut"] or row["charged"] != selected["charged"]
                or (row["retained_result"] is not None) != selected["retained_result"]
                or (row["retained_long_original"] is not None) != selected["retained_long_original"]
                or row["recovery_worker_entries"] != selected["recovery_worker_entries"]
                or row["recovery_worker_returns"] != selected["recovery_worker_entries"]
                or row["automatic_worker_entries_on_reopen"] != 0
                or not row["journal_unchanged_after_reopen"] or not row["disclosure_possible"]):
            raise ValueError("selected original custody or charge changed")


def qualify(executable, *, evidence_directory, root=ROOT):
    manifest, measured = inputs(root)
    executable = executable.resolve()
    pin = sha(executable.read_bytes())
    evidence_directory.mkdir(mode=0o700)
    subject = dict(input_sha256=measured, executable_sha256=pin,
                   executable_bytes=executable.stat().st_size, before_first_spawn=True)
    retain(evidence_directory / "subject-before-first-spawn.json",
           json.dumps(subject, sort_keys=True, separators=(",", ":")).encode("ascii"))
    retain(evidence_directory / "selected-public-executable.original", executable.read_bytes())
    for index, name in enumerate(measured):
        retain(evidence_directory / f"source-{index:03d}.original", (root / name).read_bytes())
    capture = OriginalCapture(evidence_directory, executable, pin)
    terms, pair, _, _, _ = selected_inputs(root)
    verifier = NomPublicVerifier(executable, pin, terms, pair, execution_profile=CLEAN_EXECUTION_PROFILE)
    # Keep original journals even when the qualification fails. No temporary
    # cleanup may erase an interrupted first attempt or its adversarial controls.
    directory = evidence_directory / "journals"
    directory.mkdir(mode=0o700)
    with patch("offline_session.nom_verifier.run_clean_environment_public_worker", capture.run):
        result = exercise(verifier, directory, root=root,
                          phase=lambda value: setattr(capture, "phase", value))
    check_cases(result)
    if measured != inputs(root)[1] or sha(executable.read_bytes()) != pin:
        raise ValueError("selected source or executable changed")
    if any(row["stream_completeness"] != "COMPLETE" for row in capture.calls):
        raise ValueError("original selected worker streams incomplete")
    failures = [row for row in capture.calls if row["exit_code"] != 0]
    if len(failures) != 1 or failures[0]["phase"] != "invalid-result-only:separate-result-verification":
        raise ValueError("unexpected original worker failure")
    for row in capture.calls:
        request = decode(bytes.fromhex(row["request_hex"]))
        if canonical(verifier.request(request["mode"], request["completion_hex"])) != bytes.fromhex(row["request_hex"]):
            raise ValueError("actual worker request does not match the selected public context")
    return dict(schema="ptlc-nom-reference-cuts-result-v1", profile=PROFILE,
        outcome="PASS", input_sha256=measured, source_unchanged=True,
        executable_sha256=pin, execution_profile=CLEAN_EXECUTION_PROFILE,
        original_worker_calls=capture.calls, expected_worker_refusals=len(failures),
        original_capture="COMPLETE REQUEST/STDOUT/STDERR/EXIT; NO RETRIES",
        source_snapshots="BEFORE FIRST WORKER SPAWN",
        journal_custody="ORIGINAL JOURNAL BYTES; SEPARATE DIAGNOSTIC REPLY CUSTODY EXISTS",
        prior_measured_inputs=len(manifest["preserved_file_sha256"]),
        preserved_core_source_outcomes=342, new_core_source_outcomes=0, **result, **BOUNDARY)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_swap")
    parser.add_argument("--evidence-directory", type=Path)
    args = parser.parse_args()
    selected = args.evidence_directory
    if selected is None:
        parent = Path(tempfile.mkdtemp(prefix="ptlc-nom-cuts-"))
        selected = parent / "originals"
    try:
        result = qualify(args.executable, evidence_directory=selected)
    except (OSError, RecoveryError, ValueError, KeyError, TypeError):
        print("FAIL: selected actual public-worker reference-journal cuts; preserve original evidence", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
