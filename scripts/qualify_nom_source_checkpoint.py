#!/usr/bin/env python3
"""Qualify historical NoM role mathematics without source or restore admission."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import enrollment_contract as codec, nom_authority_contract as authority  # noqa: E402
from offline_session import nom_capsule_query as binding, nom_source_checkpoint as framing  # noqa: E402
from scripts import qualify_nom_capsule_query as prior  # noqa: E402
from scripts.nom_cut_capture import OriginalCapture, retain, sha  # noqa: E402
from offline_session.public_worker import WorkerError  # noqa: E402
from qualification.nom_source_checkpoint_verifier import PublicSourceCheckpointCheck  # noqa: E402

PROFILE = "ptlc-nom-source-checkpoint-qualification-v1"
BASE = "08791450c314767ba8723be0e135ddde555589ad"
UNSIGNED_FIXTURE = "qualification/fixtures/nom_source_checkpoint_unsigned.json"
SIGNED_FIXTURE = "qualification/fixtures/nom_source_checkpoint.json"
MANIFEST = "compatibility/nom_source_checkpoint_manifest.json"
RESEARCH_FIXTURE = "compatibility/fixtures/nom_source_checkpoint_v1.json"
SELECTED = ("offline_session/nom_source_checkpoint.py", "qualification/nom_source_checkpoint_verifier.py",
    "scripts/qualify_nom_source_checkpoint.py", "qualification/examples/verify_nom_source_checkpoint.rs",
    "qualification/tests/nom_source_checkpoint.rs", "qualification-go/nom_source_checkpoint_test.go",
    "tests/test_nom_source_checkpoint.py", UNSIGNED_FIXTURE, SIGNED_FIXTURE, RESEARCH_FIXTURE)
BOUNDARY = dict(application="NO-GO", core="NO-GO", recovery_action="NONE",
    root_provisioning="UNFILLED", operational_source_authentication="NOT_PERFORMED",
    source_currentness="UNFILLED", consumer_nonrollback_checkpoint="UNFILLED",
    checkpoint_storage="NOT_IMPLEMENTED", atomic_entry="NOT_IMPLEMENTED",
    signature_scope="HISTORICAL PUBLIC SELECTED-ROLE MATHEMATICS ONLY",
    prior_worker_calls=67, framing_worker_calls=0, native_query_pairing="NOT_COMPOSED",
    preserved_core_source_outcomes=342, new_core_source_outcomes=0)


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE,
        synthetic_notice="Disclosed synthetic historical role signatures; never source truth or restore admission",
        positive_contexts=["primary", "unavailable", "root_rotation", "source_rotation", "checkpoint_rotation", "new_epoch", "new_challenge"],
        signature_worker_requests=23, successful_signature_requests=9, refused_signature_requests=14,
        successful_public_signature_checks=27, independently_verified_go_contexts=7,
        callback_forgery="ZERO SIGNATURES CAN MATCH FORGED CALLBACK; ACTUAL NATIVE WORKER REFUSES",
        coherent_restore="ALL HISTORICAL SIGNATURES STILL VALID; HOLD ONLY", boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name: sha((root / name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-source-checkpoint-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected, preserved_file_sha256=preserved, boundary=BOUNDARY)
    if json.loads((root / RESEARCH_FIXTURE).read_text("ascii")) != corpus():
        raise ValueError("selected NoM role corpus changed")
    if json.loads((root / MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected NoM role inputs changed")
    return expected, {**preserved, **selected, MANIFEST:sha((root / MANIFEST).read_bytes())}


def role_keys(root=ROOT):
    """Reuse disclosed public encodings, not old enrollment role permissions."""
    old = json.loads((root / "qualification/fixtures/source_root_roles.json").read_text("ascii"))["positive_vectors"]
    primary = old["primary"]["declaration"]
    return dict(root=primary["source_context"]["provisioning_root_key_hex"],
        source=primary["delegated_keys"]["source_response_key_hex"],
        checkpoint=primary["delegated_keys"]["policy_admin_key_hex"],
        alternate_root=old["alternate_root"]["declaration"]["source_context"]["provisioning_root_key_hex"],
        alternate_source=old["alternate_response"]["declaration"]["delegated_keys"]["source_response_key_hex"],
        alternate_checkpoint=old["alternate_admin"]["declaration"]["delegated_keys"]["policy_admin_key_hex"])


def select_context(retained, *, root=ROOT, root_key=None, source_key=None, checkpoint_key=None,
                   epoch=1, challenge_hex=None, unavailable=False):
    """Public synthetic comparison selection, without trusted network provisioning."""
    keys = role_keys(root)
    root_key = keys["root"] if root_key is None else root_key
    selected = prior.read_selection(retained, root=root)
    selected["network_selection"]["provisioning_root_digest_hex"] = framing.root_key_digest(root_key)
    if challenge_hex is not None:
        selected["challenge_hex"] = challenge_hex
    query = authority.read_query(**selected)
    bound = binding.bind_read_query(retained, query)
    declaration = framing.select_declaration(network_selection=query.as_dict()["network_selection"],
        root_key_hex=root_key, source_response_key_hex=keys["source"] if source_key is None else source_key,
        consumer_checkpoint_key_hex=keys["checkpoint"] if checkpoint_key is None else checkpoint_key, epoch=epoch)
    claim = prior.claim_wire(bound, status="unknown" if unavailable else "supported",
        availability="unavailable" if unavailable else "available")
    return framing.select_transcript(declaration, bound, claim)


def unsigned_fixture(previous, *, root=ROOT):
    prior.check_cases(previous)
    cases = previous["prior_continuity_result"]["prior_capsule_result"]["journal_projection_result"]["cases"]
    original = bytes.fromhex(cases[4]["projection"]["journal_hex"])
    retained = prior.prior.from_journal(original, challenge_hex="a1" * 32)
    keys = role_keys(root)
    choices = dict(primary={}, unavailable=dict(unavailable=True), root_rotation=dict(root_key=keys["alternate_root"]),
        source_rotation=dict(source_key=keys["alternate_source"]), checkpoint_rotation=dict(checkpoint_key=keys["alternate_checkpoint"]),
        new_epoch=dict(epoch=2), new_challenge=dict(challenge_hex="42" * 32))
    return dict(schema="ptlc-nom-source-checkpoint-unsigned-vectors-v1", research_baseline_commit=BASE,
        synthetic_notice="Disclosed public synthetic source and custody statements; no source truth or nonrollback store",
        reference_public_journal_hex=original.hex(),
        cases={name: select_context(retained, root=root, **options).as_dict() for name, options in choices.items()},
        boundary=BOUNDARY)


def retained_fixture(root=ROOT):
    value = json.loads((root / UNSIGNED_FIXTURE).read_text("ascii"))
    retained = prior.prior.from_journal(bytes.fromhex(value["reference_public_journal_hex"]), challenge_hex="a1" * 32)
    return value, retained


def fixture_expectations(root=ROOT):
    value, retained = retained_fixture(root)
    keys = role_keys(root)
    choices = dict(primary={}, unavailable=dict(unavailable=True), root_rotation=dict(root_key=keys["alternate_root"]),
        source_rotation=dict(source_key=keys["alternate_source"]), checkpoint_rotation=dict(checkpoint_key=keys["alternate_checkpoint"]),
        new_epoch=dict(epoch=2), new_challenge=dict(challenge_hex="42" * 32))
    selected = {name: select_context(retained, root=root, **options) for name, options in choices.items()}
    if {name: expectation.as_dict() for name, expectation in selected.items()} != value["cases"]:
        raise ValueError("unsigned NoM role fixture differs from its complete retained inputs")
    return selected


def public_fixture(root=ROOT):
    value = json.loads((root / SIGNED_FIXTURE).read_text("ascii"))
    if value["schema"] != "ptlc-nom-source-checkpoint-public-vectors-v1":
        raise ValueError("unexpected public NoM role fixture")
    return value


def signed_envelope(expected, vector):
    return framing.envelope(expected, root_signature=bytes.fromhex(vector["request"]["root_signature_hex"]),
        source_signature=bytes.fromhex(vector["request"]["source_signature_hex"]),
        checkpoint_signature=bytes.fromhex(vector["request"]["checkpoint_signature_hex"]))


class RoleCapture(OriginalCapture):
    """Trusted qualification capture, not an application or bounded hostile runner.

    Reuse original stream custody with its documented communicate limitations;
    the selected native program is nonforking and emits only a small result.
    """
    def run(self, executable, wire, *, timeout, max_input_bytes, max_output_bytes=512):
        if max_output_bytes != 512:
            raise WorkerError("unexpected role capture output boundary")
        raw = super().run(executable, wire, timeout=timeout, max_input_bytes=max_input_bytes, max_output_bytes=4096)
        if len(raw) > 512:
            raise WorkerError("public role output exceeds selected result boundary")
        return raw


def expected_native_requests(root=ROOT):
    """Exact public request order for qualification, never fabricated observations."""
    fixture = public_fixture(root); vectors = fixture["positive_vectors"]
    rows = [(name, vectors[name]["request"], 0) for name in corpus()["positive_contexts"]]
    primary = vectors["primary"]["request"]
    alternate = copy.deepcopy(primary); alternate["source_signature_hex"] = fixture["alternate_source_signature_hex"]
    rows += [("alternate-public-source-signature", alternate, 0), ("coherent-old-historical-replay", primary, 0)]
    for field in ("root_signature_hex", "source_signature_hex", "checkpoint_signature_hex"):
        for name, signature in [("zero", "00" * 64)] + [(group,fixture[group][field])
                for group in ("wrong_domain_signatures", "wrong_role_signatures")]:
            changed = copy.deepcopy(primary); changed[field] = signature
            rows.append((name + ":" + field, changed, 1))
    for phase, change in (
        ("changed-source-binding", lambda v:v["source_statement"].update(binding_digest_hex="81" * 32)),
        ("changed-checkpoint-charge", lambda v:v["checkpoint_statement"].update(charged_work_digest_hex="82" * 32)),
        ("changed-network-pin", lambda v:v["declaration"]["network_selection"].update(authority_profile_digest_hex="83" * 32)),
        ("cross-role-source-schema", lambda v:v.update(source_statement=v["checkpoint_statement"])),
        ("cross-role-checkpoint-schema", lambda v:v.update(checkpoint_statement=v["source_statement"])),
    ):
        changed = copy.deepcopy(primary); change(changed); rows.append((phase,changed,1))
    return rows


def compare_signed(executable, directory, *, root=ROOT):
    fixture = public_fixture(root); selected = fixture_expectations(root)
    pin = sha(Path(executable).read_bytes()); capture = RoleCapture(directory, executable, pin)
    verifier = PublicSourceCheckpointCheck(Path(executable).resolve(), expected_executable_sha256_hex=pin)
    positives = []
    with patch("qualification.nom_source_checkpoint_verifier.run_public_worker", side_effect=capture.run):
        for name in corpus()["positive_contexts"]:
            capture.phase = name; expected = selected[name]; vector = fixture["positive_vectors"][name]
            request = framing.request(expected, signed_envelope(expected, vector))
            if request != vector["request"] or framing.expected_result(framing.request_digest(request)) != vector["result"]:
                raise ValueError("public vectors differ from selected retained context")
            held = framing.verify_selected_transcript(expected, signed_envelope(expected, vector), verifier=verifier)
            if held is not expected:
                raise ValueError("historical signature result replaced retained selection")
            positives.append(dict(name=name, request=request, result=vector["result"], review=held.review()))
        primary = selected["primary"]; vector = fixture["positive_vectors"]["primary"]
        alternate = copy.deepcopy(vector); alternate["request"]["source_signature_hex"] = fixture["alternate_source_signature_hex"]
        capture.phase = "alternate-public-source-signature"
        framing.verify_selected_transcript(primary, signed_envelope(primary, alternate), verifier=verifier)
        capture.phase = "coherent-old-historical-replay"
        framing.verify_selected_transcript(primary, signed_envelope(primary, vector), verifier=verifier)
        refused = []
        for field in ("root_signature_hex", "source_signature_hex", "checkpoint_signature_hex"):
            variants = [("zero", "00" * 64)] + [(group, fixture[group][field])
                for group in ("wrong_domain_signatures", "wrong_role_signatures")]
            for name, signature in variants:
                changed = copy.deepcopy(vector); changed["request"][field] = signature
                capture.phase = name + ":" + field
                try:
                    framing.verify_selected_transcript(primary, signed_envelope(primary, changed), verifier=verifier)
                except framing.SourceCheckpointRefused:
                    refused.append(capture.phase)
                else:
                    raise ValueError("actual public role verifier accepted invalid signature")
        for phase, change in (
            ("changed-source-binding", lambda v:v["source_statement"].update(binding_digest_hex="81" * 32)),
            ("changed-checkpoint-charge", lambda v:v["checkpoint_statement"].update(charged_work_digest_hex="82" * 32)),
            ("changed-network-pin", lambda v:v["declaration"]["network_selection"].update(authority_profile_digest_hex="83" * 32)),
            ("cross-role-source-schema", lambda v:v.update(source_statement=v["checkpoint_statement"])),
            ("cross-role-checkpoint-schema", lambda v:v.update(checkpoint_statement=v["source_statement"])),
        ):
            changed = copy.deepcopy(vector["request"]); change(changed); capture.phase = phase
            # Deliberately bypass the independent Python comparison for native
            # refusal controls; this is not an application entry path.
            try:
                capture.run(str(executable), codec._canonical(changed), timeout=5, max_input_bytes=8192, max_output_bytes=512)
            except WorkerError:
                refused.append(phase)
            else:
                raise ValueError("actual public role worker accepted altered native input")
    forged = framing.envelope(primary, root_signature=b"\0" * 64, source_signature=b"\0" * 64, checkpoint_signature=b"\0" * 64)
    held = framing.verify_selected_transcript(primary, forged,
        verifier=lambda value:framing.expected_result(framing.request_digest(value)))
    results = dict(positive_contexts=positives, native_calls=capture.calls, expected_refusals=refused,
        forged_callback_control=dict(zero_signatures_matched=True, worker_calls=0, review=held.review()),
        coherent_old_replay=dict(valid_historical_signatures=True, review=primary.review()),
        executable_sha256=pin)
    check_comparisons(results, root=root)
    return results


def check_comparisons(value, *, root=ROOT):
    fixture = public_fixture(root); selected = fixture_expectations(root); calls = value["native_calls"]
    requests = expected_native_requests(root)
    if len(calls) != 23 or value["expected_refusals"] != [name for name,_,exit_code in requests if exit_code == 1]:
        raise ValueError("public role native request count changed")
    for i, name in enumerate(corpus()["positive_contexts"]):
        expected = selected[name]; vector = fixture["positive_vectors"][name]
        if value["positive_contexts"][i] != dict(name=name, request=vector["request"], result=vector["result"], review=expected.review()):
            raise ValueError("historical role report changed independent selection")
    successful = 0
    for number,(row,(phase,expected_request,exit_code)) in enumerate(zip(calls,requests),1):
        request = bytes.fromhex(row["request_hex"]); stdout = bytes.fromhex(row["stdout_hex"]); stderr = bytes.fromhex(row["stderr_hex"])
        if (row["number"] != number or row["phase"] != phase or row["exit_code"] != exit_code
            or request != codec._canonical(expected_request) or row["stream_completeness"] != "COMPLETE" or sha(request) != row["request_sha256"]
            or sha(stdout) != row["stdout_sha256"] or sha(stderr) != row["stderr_sha256"] or stderr != b""):
            raise ValueError("incomplete original public role streams")
        if row["exit_code"] == 0:
            successful += 1
            expected = framing.expected_result(framing.request_digest(json.loads(request)))
            if stdout != codec._canonical(expected) + b"\n":
                raise ValueError("native public role result differs from complete request")
        elif row["exit_code"] != 1 or stdout != b"":
            raise ValueError("unexpected public role refusal outcome")
    if successful != 9 or any(row["exit_code"] != (0 if i < 9 else 1) for i,row in enumerate(calls)):
        raise ValueError("historical role success/refusal order changed")
    if value["forged_callback_control"] != dict(zero_signatures_matched=True, worker_calls=0, review=selected["primary"].review()):
        raise ValueError("forged callback promoted authority")
    if value["coherent_old_replay"] != dict(valid_historical_signatures=True, review=selected["primary"].review()):
        raise ValueError("old valid signatures promoted restore authority")


def check_cases(report, *, root=ROOT):
    prior.check_cases(report["prior_capsule_query_result"])
    check_comparisons(report["signature_comparisons"], root=root)
    if any(report[key] != value for key,value in BOUNDARY.items()):
        raise ValueError("historical NoM role report promoted capability")


def qualify(executable, role_executable, *, evidence_directory, root=ROOT):
    _, measured = inputs(root)
    directory = Path(evidence_directory).resolve(); directory.mkdir(mode=0o700)
    for index,name in enumerate(measured):
        retain(directory / f"selected-source-{index:03d}.original", (root / name).read_bytes())
    earlier = prior.qualify(executable, evidence_directory=directory / "capsule-query-originals", root=root)
    signatures = directory / "historical-role-originals"; signatures.mkdir(mode=0o700)
    compared = compare_signed(role_executable, signatures, root=root)
    report = dict(schema="ptlc-nom-source-checkpoint-result-report-v1", profile=PROFILE, outcome="PASS",
        input_sha256=measured, source_snapshots="BEFORE FIRST ACTOR OR WORKER SPAWN",
        prior_capsule_query_result=earlier, signature_comparisons=compared, **BOUNDARY)
    check_cases(report, root=root)
    if measured != inputs(root)[1]:
        raise ValueError("NoM source/checkpoint inputs changed during qualification")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_swap")
    parser.add_argument("--role-executable", type=Path, default=ROOT / "qualification/target/debug/examples/verify_nom_source_checkpoint")
    parser.add_argument("--evidence-directory", type=Path)
    args = parser.parse_args(); directory = args.evidence_directory
    if directory is None:
        directory = Path(tempfile.mkdtemp(prefix="ptlc-nom-historical-roles-")).resolve() / "originals"
    try:
        report = qualify(args.executable, args.role_executable, evidence_directory=directory)
    except (OSError, ValueError, KeyError, TypeError):
        print("FAIL: historical NoM source/checkpoint signatures; preserve original evidence", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
