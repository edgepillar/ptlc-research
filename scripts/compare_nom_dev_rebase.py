#!/usr/bin/env python3
"""Compare two selected c25 dev projections without changing historical corpora.

This reader performs no native execution, signing, observation or recovery.
Its inputs are public research records, not authenticated transaction custody.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import qualify_nom_account_pool as pool
from scripts import qualify_nom_pool_dependencies as dependencies

CORE_COMMIT = "c25a596436432a544325a4b2ebb0257012d04fa1"
CORE_TREE = "7803fd4673c097439a68072791a2bc2ccda8eb6c"
BASE = "02a258792a9dcf198e7349d0b517e3c69d16566b"
SOURCE_INDEX_SHA256 = "37eb2024567fb683d8b34acde3635e000bd28f1ba534be9d67e41eec82d2baef"
PROFILE_INPUTS_SHA256 = "68d7054d74256fca81ed36feaa6c4035770b64f0a1b366bbdd70148c0a0ffb4c"
MANIFEST = "compatibility/nom_dev_rebase_manifest.json"
MIB = 1024**2
COUNTS = dict(pool_cases=2, dependency_cases=3, removed_child_aliases=4,
              retained_original_patches=7, changed_pool_fields=16,
              changed_dependency_fields=7, total_changed_fields=23)
MODULES = {"account-pool": (pool, "zz_research_nom_account_pool_test.go", 4 * MIB),
           "pool-dependencies": (dependencies, "zz_research_nom_pool_dependencies_test.go", 8 * MIB)}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("nonfinite JSON constant")


def decoded(raw, maximum):
    if type(raw) is not bytes or len(raw) > maximum:
        raise ValueError("selected JSON bound exceeded")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii")


def regular_bytes(path, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise ValueError("bounded regular input required")
    raw = path.read_bytes()
    if len(raw) != info.st_size:
        raise ValueError("input changed while reading")
    return raw


def selection(root=ROOT):
    selected = decoded(regular_bytes(root / MANIFEST, MIB), MIB)
    fixed = dict(schema="zenon-nom-dev-rebase-selection-v1", profile="nom-dev-c25-rebase-v1",
        research_baseline_commit=BASE, core_commit=CORE_COMMIT, core_tree=CORE_TREE,
        core_repository="https://github.com/zenon-network/go-zenon", core_license="GPL-3.0",
        source_index_sha256=SOURCE_INDEX_SHA256, profile_inputs_sha256=PROFILE_INPUTS_SHA256,
        expected_delta=COUNTS, application="NO-GO", core="NO-GO", assessment="UNFILLED",
        mode_scope="SELECTED_GIT_MODES; FILESYSTEM_CONTENT_COMPARISON_ONLY")
    if type(selected) is not dict or set(selected) != set(fixed) | {"source_index", "profile_inputs"}:
        raise ValueError("complete immutable dev selection required")
    if any(type(selected[key]) is not type(value) or selected[key] != value for key, value in fixed.items()):
        raise ValueError("immutable dev selection differs")
    for field, pin, count in (("source_index", SOURCE_INDEX_SHA256, 441),
                              ("profile_inputs", PROFILE_INPUTS_SHA256, 133)):
        if type(selected[field]) is not dict or len(selected[field]) != count:
            raise ValueError("complete selected inventory required")
        if hashlib.sha256(canonical(selected[field])).hexdigest() != pin:
            raise ValueError("selected inventory digest differs")
    total = 0
    for name, digest in selected["profile_inputs"].items():
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or ".git" in path.parts:
            raise ValueError("unsafe selected input path")
        if any((root / Path(*path.parts[:index])).is_symlink() for index in range(1, len(path.parts) + 1)):
            raise ValueError("selected input link refused")
        raw = regular_bytes(root / path, 8 * MIB)
        total += len(raw)
        if total > 40 * MIB or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("preserved native producer input differs")
    return selected


def compare_source(source, selected):
    """Compare complete contents; Git metadata and filesystem modes are not attested."""
    if (type(selected) is not dict or selected.get("core_commit") != CORE_COMMIT
            or selected.get("core_tree") != CORE_TREE or type(selected.get("source_index")) is not dict
            or len(selected["source_index"]) != 441
            or hashlib.sha256(canonical(selected["source_index"])).hexdigest() != SOURCE_INDEX_SHA256):
        raise ValueError("complete pinned source selection required")
    if source.is_symlink() or not source.is_dir():
        raise ValueError("regular source directory required")
    seen = set()
    total = 0
    for directory, dirs, names in os.walk(source, followlinks=False):
        parent = Path(directory)
        for name in dirs[:]:
            path = parent / name
            if path.is_symlink():
                raise ValueError("source directory link refused")
            if parent == source and name == ".git":
                dirs.remove(name)
        for name in names:
            path = parent / name
            if parent == source and name == ".git":
                if path.is_symlink():
                    raise ValueError("source metadata link refused")
                continue
            relative = path.relative_to(source).as_posix()
            if relative not in selected["source_index"] or relative.casefold() in seen:
                raise ValueError("unexpected source entry")
            seen.add(relative.casefold())
            expected = selected["source_index"][relative]
            raw = regular_bytes(path, 8 * MIB)
            total += len(raw)
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            if (total > 40 * MIB or len(raw) != expected["bytes"]
                    or hashlib.sha256(raw).hexdigest() != expected["sha256"]
                    or blob != expected["git_blob_sha1"]):
                raise ValueError("selected source contents differ")
    if seen != {name.casefold() for name in selected["source_index"]}:
        raise ValueError("selected source is incomplete")
    return dict(files=len(seen), bytes=total, commit=CORE_COMMIT, tree=CORE_TREE,
                mode_equality="NOT_ASSERTED", provenance="NOT_AUTHENTICATED")


def expected_records(root=ROOT):
    """Select expectations from frozen public inputs, never from observed output."""
    selection(root)
    historical_pool = pool.inputs(root)[1]["records"]
    historical_dependencies = dependencies.inputs(root)[1]["records"]
    expected_pool = copy.deepcopy(historical_pool)
    removed = 0
    for record in expected_pool.values():
        pending = {wire for wires in record["remaining_pending_wires"].values() for wire in wires}
        child_ids = {canonical(view["requested_identifier"]) for step in record["trace"]
                     for view in step["child_views"]}
        case_removed = 0
        for view in record["post_rollback_views"]:
            if (canonical(view["requested_identifier"]) in child_ids and view["frontier"] is not None
                    and view["frontier"]["wire_hex"] not in pending):
                if view["present"] is not True or view["patch_present"] is not True or view["patch_hex"] != "":
                    raise ValueError("selected historical child alias differs")
                view.update(present=False, patch_present=False, patch_hex="", frontier=None, state_dump_hex="")
                case_removed += 1
        if case_removed != 2:
            raise ValueError("complete per-case removed child selection required")
        removed += case_removed
    expected_dependencies = copy.deepcopy(historical_dependencies)
    retained = 0
    for record in expected_dependencies.values():
        admitted = {step["label"]: step["retained_patch_hex"] for step in record["trace"]}
        for view in record["views"]:
            name = view["label"]
            if view["present"] and name in ("recipient-prefix", "unrelated-prefix", "unrelated-second"):
                original = admitted[name]
                block = record["candidates"][name]["block"]
                duplicate_frontier = pool.encode_operations(pool.frontier_operations(block)).hex()
                if view["patch_hex"] != original + duplicate_frontier:
                    raise ValueError("selected historical rebuilt patch differs")
                view["patch_hex"] = original
                retained += 1
    if removed != 4 or retained != 7:
        raise ValueError("complete selected rebase delta required")
    return {"account-pool": expected_pool, "pool-dependencies": expected_dependencies}


def exact(expected, actual):
    """Strict types preserve bool/int distinctions and complete nested membership."""
    if type(expected) is not type(actual):
        raise ValueError("selected record type differs")
    if type(expected) is dict:
        if expected.keys() != actual.keys():
            raise ValueError("selected record fields differ")
        for name in expected:
            exact(expected[name], actual[name])
    elif type(expected) is list:
        if len(expected) != len(actual):
            raise ValueError("selected record count differs")
        for left, right in zip(expected, actual):
            exact(left, right)
    elif expected != actual:
        raise ValueError("selected record value differs")


def compare_records(kind, actual, root=ROOT):
    if kind not in MODULES:
        raise ValueError("unselected comparison kind")
    exact(expected_records(root)[kind], actual)
    return dict(outcome="PASS_SELECTED_C25_RECORD_COMPARISON", kind=kind,
                cases=len(actual), core=CORE_COMMIT, application="NO-GO", recovery_action="NONE")


def native_records(kind, raw):
    if kind not in MODULES or type(raw) is not bytes or len(raw) > 16 * MIB:
        raise ValueError("bounded selected native stream required")
    module, filename, bound = MODULES[kind]
    pool.prior.vm.selected_outcome(raw, module.expected_tests())
    records = {}
    pending = {}
    for line in raw.splitlines():
        event = decoded(line, 16 * MIB)
        if type(event) is not dict or event.get("Package") != module.PACKAGE:
            raise ValueError("selected native package required")
        output, name = event.get("Output", ""), event.get("Test")
        if type(output) is not str:
            raise ValueError("native output fragment must be text")
        if pending and event.get("Action") == "output" and name not in pending:
            raise ValueError("interleaved native record")
        if module.PREFIX in output:
            if (event.get("Action") != "output" or output.count(module.PREFIX) != 1 or name in pending
                    or re.match(r"^    " + re.escape(filename) + r":[0-9]+: " + re.escape(module.PREFIX), output) is None):
                raise ValueError("ambiguous native record framing")
            pending[name] = output.split(module.PREFIX, 1)[1]
        elif name in pending:
            if event.get("Action") != "output":
                raise ValueError("truncated native record")
            pending[name] += output
        else:
            continue
        if len(pending[name]) > bound:
            raise ValueError("selected native record bound exceeded")
        if not pending[name].endswith("\n"):
            continue
        value = decoded(pending.pop(name).strip().encode("ascii"), bound)
        if (type(value) is not dict or value.get("id") not in module.CASES or value["id"] in records
                or name != module.TEST + "/" + value["id"]):
            raise ValueError("unselected or duplicate native record")
        records[value["id"]] = value
    if pending or set(records) != set(module.CASES):
        raise ValueError("complete native record set required")
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-source", type=Path, required=True)
    parser.add_argument("--expect-core-commit", required=True)
    parser.add_argument("--expect-source-index-sha256", required=True)
    parser.add_argument("--account-pool-jsonl", type=Path, required=True)
    parser.add_argument("--pool-dependencies-jsonl", type=Path, required=True)
    args = parser.parse_args()
    if args.expect_core_commit != CORE_COMMIT or args.expect_source_index_sha256 != SOURCE_INDEX_SHA256:
        raise ValueError("independently selected immutable pins required")
    source = compare_source(args.core_source, selection())
    for kind, path in (("account-pool", args.account_pool_jsonl),
                       ("pool-dependencies", args.pool_dependencies_jsonl)):
        compare_records(kind, native_records(kind, regular_bytes(path, 16 * MIB)))
    print(json.dumps(dict(outcome="PASS_PINNED_C25_DELTA_COMPARISON", source=source,
        selected_delta=COUNTS, native_execution="NOT_PERFORMED_BY_READER",
        producer_authentication="NOT_ESTABLISHED", independent_assessment="UNFILLED",
        application="NO-GO", core="NO-GO", recovery_action="NONE"), sort_keys=True))


if __name__ == "__main__":
    main()
