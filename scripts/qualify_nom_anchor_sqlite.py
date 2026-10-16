#!/usr/bin/env python3
"""Compare one offline synthetic anchor corpus with an explicitly selected SQLite build."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import nom_anchor_sqlite_comparison as comparison  # noqa: E402
from qualification.nom_anchor_sqlite_evidence import OriginalEvidence  # noqa: E402
from scripts import prepare_nom_anchor_sqlite_engine as engine_profile  # noqa: E402
from scripts import qualify_nom_anchor_transition_journal as prior  # noqa: E402

PROFILE = "ptlc-nom-anchor-sqlite-qualification-v1"
BASE = "981a11dec4075ceb9096e4f75e74708daf971601"
MANIFEST = "compatibility/nom_anchor_sqlite_manifest.json"
FIXTURE = "compatibility/fixtures/nom_anchor_sqlite_v1.json"
SELECTED = (
    "qualification/nom_anchor_sqlite_material.py", "qualification/nom_anchor_sqlite_capture.py",
    "qualification/nom_anchor_sqlite_evidence.py", "qualification/nom_anchor_sqlite_comparison.py",
    "qualification/nom_anchor_sqlite_review.py",
    "qualification/nom_anchor_sqlite_schema.sql", "scripts/prepare_nom_anchor_sqlite_engine.py",
    "scripts/qualify_nom_anchor_sqlite.py", "tests/test_nom_anchor_sqlite_material.py",
    "tests/test_nom_anchor_sqlite_capture.py", "tests/test_nom_anchor_sqlite_evidence.py",
    "tests/test_nom_anchor_sqlite_engine.py", "tests/test_nom_anchor_sqlite_comparison.py", FIXTURE,
    "tests/test_nom_anchor_sqlite_review.py", "scripts/check_nom_anchor_sqlite_evidence.py",
)
CASES = (
    "page_limit_requires_each_connection", "wrong_configuration_refused_before_transition",
    "native_full_preserves_original_unknown", "missing_existing_never_created", "initial_complete_opening",
    "exact_complete_after_state", "stale_expected_state_refused", "conflicting_equal_request_id_refused",
    "reused_nonce_refused", "exact_lookup_is_observation_only", "retained_result_may_age_before_delivery",
    "retained_request_cannot_be_trimmed", "one_database_two_contenders", "capacity_preserves_complete_history",
    "lost_reply_before_commit", "lost_reply_after_commit", "unsafe_coherent_old_restore",
    "unsafe_independent_service_copies", "unsafe_explicit_reenrollment", "terminal_history_retained",
    "terminal_enrollment_refuses_further_transition", "unsafe_restored_pre_retirement",
)
NATIVE_CALLS = (
    "limit-probe-create", "limit-selected-connection", "limit-new-connection",
    "wrong-configuration-create", "wrong-configuration-refused", "wrong-configuration-after-head",
    "native-full-create", "native-full-page-count", "native-full-exact-request", "native-full-after-head",
    "missing-existing", "ordinary-create", "initial-head", "first-transition", "after-first-head",
    "stale-before", "after-stale-head", "conflicting-equal-id", "after-id-conflict-head", "reused-nonce",
    "after-nonce-conflict-head", "exact-request-lookup", "trim-retained-request", "contention-create",
    "two-contenders", "contention-after-head", "capacity-create", "capacity-first", "capacity-second",
    "capacity-after-head", "death-before-commit-create", "death-before-commit", "death-before-commit-reopen-head",
    "death-after-commit-create", "death-after-commit", "death-after-commit-reopen-head", "old-restore-head",
    "independent-1-commit", "independent-1-head", "independent-2-commit", "independent-2-head",
    "reenrollment-create", "reenrollment-commit", "reenrollment-head", "retirement-create", "retirement-first",
    "retirement-read", "retirement-third", "terminal-retirement", "terminal-head", "write-after-retirement",
    "terminal-after-refusal-head", "pre-retirement-restore-head",
)
ANCHORS = {
    "initial": (118936, "e7b3495f23b841e894aea7c35aa7afd7e949419816de25de8b9ce3e43410ac5c"),
    "active": (243815, "5fd09e722fc8bcb778fe724856b75bd317dabe0689f188f7e11c40c806b1bb0b"),
    "after_read": (268742, "9773093016dbb5282e93b6b9cee3371645c7d773f0822b493f10e2da8d62330b"),
    "after_third": (415631, "df96024025eb79b19035015eb1b1c5fb01b77d28dc00688bc7151843e6491459"),
    "retired": (417100, "a00bdf99a6f055625643e563cc59cf3fd04d52bd0d74f4f18e44e2503557e3f9"),
}
REQUESTS = {
    "first": "8b923b4e4f77a851957cf34842393c411b7b60cbc87c035c8b88fed41be3653e",
    "read": "af9ad6ae8ed5af51fe819b72ee9a4f684cf1338da0f35f1f5014ea11ec749661",
    "third": "313adf9e09e89140e56a0e5c40bf71378c32f283859ca043f830b0481a8a0a31",
    "retirement": "0a82b08e088a275cf08b47fedaadf38d54272788d1e022869085477ba1706dbc",
}
BOUNDARY = dict(application="NO-GO", core="NO-GO", state="HOLD", recovery_action="NONE",
    publication_outcome="UNKNOWN", service_gates_unfilled=7, original_operation_calls=0,
    signature_requests=0, new_core_outcomes=0, preserved_core_source_outcomes=342,
    authority_provisioning="UNFILLED", current_lookup_authentication="NOT_ESTABLISHED",
    nonrollback="UNPROTECTED", original_work_entry="NOT_IMPLEMENTED", physical_power_loss="UNQUALIFIED",
    independent_assessment="UNFILLED", new_work_allowed=False, automatic_retry=False,
    same_request_republication=False, replenish_work=False, replacement_original_allowed=False,
    automatic_bootstrap=False, automatic_reenrollment=False)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE, selected_cases=list(CASES),
        supervised_command_labels=list(NATIVE_CALLS),
        intended_case_count=22, intended_supervised_calls=53, intended_native_calls=54, successful_unsafe_controls=4,
        selected_engine=dict(version=engine_profile.VERSION, source_id=engine_profile.SOURCE_ID,
            source_url=engine_profile.SOURCE_URL, archive_bytes=engine_profile.ARCHIVE_BYTES,
            archive_sha256=engine_profile.ARCHIVE_SHA256, archive_sha3_256=engine_profile.ARCHIVE_SHA3,
            sqlite3_c_sha3_256=engine_profile.C_SHA3),
        golden_reference_anchors={name: dict(bytes=row[0], sha256=row[1]) for name, row in ANCHORS.items()},
        golden_reference_requests=REQUESTS, boundary=BOUNDARY,
        synthetic_notice="Finite public reference bytes; golden model output is not independent construction assessment")


def expected_manifest(root=ROOT):
    _, preserved = prior.inputs(root)
    return dict(schema="ptlc-nom-anchor-sqlite-manifest-v1", profile=PROFILE, research_baseline_commit=BASE,
        input_sha256={name: sha((root/name).read_bytes()) for name in SELECTED},
        preserved_file_sha256=preserved, boundary=BOUNDARY)


def inputs(root=ROOT):
    expected = expected_manifest(root)
    if json.loads((root/FIXTURE).read_text("ascii")) != corpus() or json.loads((root/MANIFEST).read_text("ascii")) != expected:
        raise ValueError("selected SQL comparison source inputs changed")
    return expected, {**expected["preserved_file_sha256"], **expected["input_sha256"], MANIFEST: sha((root/MANIFEST).read_bytes())}


def selected_engine_description(record):
    """Check a public build description without claiming its actual binary is present."""
    required = {"schema", "outcome", "version", "source_id", "source_url", "archive_bytes", "archive_sha256",
        "archive_sha3_256", "sqlite3_c_sha3_256", "build_flags", "license", "source_files", "platform",
        "architecture", "scope", "application", "core", "recovery_action", "service_gates_unfilled",
        "compiler_executable_sha256", "compile_actual_exit", "compile_output_complete", "binary_sha256",
        "binary_bytes", "compile_options", "probe_actual_exit", "probe_output_complete"}
    if type(record) is not dict or set(record) not in (required, required | {"sdk_version"}):
        raise ValueError("exact selected engine record required")
    if (record["schema"] != engine_profile.SCHEMA or record["outcome"] != "BUILT_AND_IDENTITY_PROBED"
            or record["version"] != engine_profile.VERSION or record["source_id"] != engine_profile.SOURCE_ID
            or record["source_url"] != engine_profile.SOURCE_URL or record["archive_bytes"] != engine_profile.ARCHIVE_BYTES
            or record["archive_sha256"] != engine_profile.ARCHIVE_SHA256 or record["archive_sha3_256"] != engine_profile.ARCHIVE_SHA3
            or record["sqlite3_c_sha3_256"] != engine_profile.C_SHA3):
        raise ValueError("selected engine source binding refused")
    expected_files = {name: dict(bytes=value[0], sha256=value[1]) for name, value in engine_profile.SOURCE_FILES.items()}
    if record["source_files"] != expected_files:
        raise ValueError("selected source file opening refused")
    if record["license"] != engine_profile.LICENSE_SCOPE or record["scope"] != engine_profile.BUILD_SCOPE:
        raise ValueError("selected build scope changed")
    for key in ("compile_actual_exit", "probe_actual_exit"):
        if type(record[key]) is not int or record[key] != 0:
            raise ValueError("native build or identity probe did not pass")
    if record["compile_output_complete"] is not True or record["probe_output_complete"] is not True:
        raise ValueError("complete original build and probe captures required")
    for key in ("binary_sha256", "compiler_executable_sha256"):
        if type(record[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", record[key]) is None:
            raise ValueError("selected build digest refused")
    if type(record["binary_bytes"]) is not int or not 0 < record["binary_bytes"] <= 8*1024**2:
        raise ValueError("selected native binary size refused")
    if (record["application"], record["core"], record["recovery_action"], record["service_gates_unfilled"]) != ("NO-GO", "NO-GO", "NONE", 7):
        raise ValueError("engine preparation grants no operational permission")
    expected_flags = list(engine_profile.FLAGS)
    if record["platform"] == "darwin":
        expected_flags.insert(0, "-isysroot SELECTED_SDK")
        if type(record.get("sdk_version")) is not str or re.fullmatch(r"[0-9]+(?:[.][0-9]+)*", record["sdk_version"]) is None:
            raise ValueError("selected SDK version refused")
    elif record["platform"] != "linux" or "sdk_version" in record:
        raise ValueError("selected native build platform refused")
    if record["build_flags"] != expected_flags or record["architecture"] not in ("arm64", "aarch64", "x86_64"):
        raise ValueError("selected native build configuration refused")
    options = record["compile_options"]
    if (type(options) is not list or not 0 < len(options) <= 128
            or any(type(value) is not str or len(value) > 128
                   or re.fullmatch(r"[A-Z0-9_]+(?:=[A-Za-z0-9_.+()-]+)?", value) is None for value in options)):
        raise ValueError("selected compile option description refused")
    if not {"THREADSAFE=1", "OMIT_LOAD_EXTENSION", "DQS=0", "MAX_MMAP_SIZE=0"} <= set(options):
        raise ValueError("selected engine compile options refused")
    raw = comparison.canonical(record)
    if not raw.isascii() or re.search(rb"/(?:Users|home|Volumes|private)/|localhost|@", raw, re.I):
        raise ValueError("engine record contains unselected sharing data")
    return record


def selected_engine(record, binary):
    """Bind the selected public description to the exact actual local binary."""
    selected_engine_description(record)
    selected_binary = Path(binary)
    info = selected_binary.lstat()
    if (not selected_binary.is_file() or selected_binary.is_symlink()
            or info.st_nlink != 1 or not 0 < info.st_size <= 8*1024**2):
        raise ValueError("selected actual binary file required")
    payload = selected_binary.read_bytes()
    if len(payload) != record["binary_bytes"] or sha(payload) != record["binary_sha256"]:
        raise ValueError("selected native binary bytes changed")
    return record


def qualify(binary, engine_record, output_directory, root=ROOT):
    if not __debug__:
        raise ValueError("unoptimized qualification runtime required")
    _, measured = inputs(root)
    engine = selected_engine(engine_record, binary)
    evidence = OriginalEvidence(output_directory)
    try:
        evidence.put("selected/engine-record", comparison.canonical(engine))
        evidence.put("selected/qualification-input-index", comparison.canonical(measured))
        material, reference_inputs, actual_custody = comparison.prepare_material(root, evidence)
        for name, (size, pin) in ANCHORS.items():
            if material["anchors"][name] != dict(sha256=pin, bytes=size):
                raise ValueError("fresh complete anchor reference differs from selected corpus")
        if {name: row["object"] for name, row in material["requests"].items()} != REQUESTS:
            raise ValueError("fresh complete request differs from selected corpus")
        result = comparison.compare_prepared(root, binary, engine, evidence, material, reference_inputs, actual_custody)
        if list(result["selected_cases"]) != list(CASES) or inputs(root)[1] != measured:
            raise ValueError("complete selected case/source closure required")
        if tuple(row["label"] for row in result["native_calls"]) != NATIVE_CALLS:
            raise ValueError("exact selected native command order required")
        result["qualification_input_sha256"] = measured
        result["qualification_inputs"] = len(measured)
        result["boundary"] = BOUNDARY
        retained = evidence.finalize("COMPLETE_FINITE_COMPARISON", result)
    except BaseException as error:
        try:
            evidence.finalize("NOT_QUALIFIED", dict(schema=PROFILE, outcome="NOT_QUALIFIED",
                error_class=type(error).__name__, boundary=BOUNDARY))
        except (ValueError, OSError):
            # Earlier intent, original streams and unknown fixture paths remain.
            # A failed disposition write must not replace the primary failure.
            pass
        raise
    return dict(schema=PROFILE, outcome="PASS_FINITE_LOCAL_COMPARISON_ONLY", research_baseline_commit=BASE,
        qualification_inputs=len(measured), preserved_reference_inputs=len(reference_inputs),
        case_count=result["case_count"], supervised_command_count=result["supervised_command_count"],
        actual_native_commands=result["actual_native_commands"], successful_unsafe_controls=4,
        engine_binary_sha256=engine["binary_sha256"], engine_source_id=engine["source_id"],
        source_archive_sha256=engine["archive_sha256"], evidence=retained, boundary=BOUNDARY)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite-cli", type=Path, required=True)
    parser.add_argument("--engine-record", type=Path, required=True)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = args.engine_record.read_bytes()
        if not 0 < len(raw) <= 64*1024:
            raise ValueError("bounded selected engine record required")
        result = qualify(args.sqlite_cli, json.loads(raw), args.evidence_directory)
    except (ValueError, OSError, AssertionError, TypeError, KeyError) as error:
        print(comparison.canonical(dict(schema=PROFILE, outcome="NOT_QUALIFIED",
            error_class=type(error).__name__, boundary=BOUNDARY)).decode("ascii"))
        return 1
    print(comparison.canonical(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
