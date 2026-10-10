#!/usr/bin/env python3
"""Inspect the separately pinned NoM worker source subject without native work.

The full inventory identifies source, not independent review, compiled closure,
runtime provenance, a protected executable launch or application acceptance.
"""

import hashlib
import os
from pathlib import Path
import sys

if __package__:
    from . import check_observation_subject as source
    from . import check_dependency_contents as content
else:
    import check_observation_subject as source
    import check_dependency_contents as content


SUBJECT_COMMIT = "c560f5dc504818252703fdeaecc2ff96a3f86059"
SUBJECT_PATH = "review/nom-worker-subject.json"
WORKER = "verify_nom_swap"
COPY_PREFIXES = ("qualification/", "compatibility/fixtures/")
REQUIRED = ("qualification/Cargo.toml", "qualification/Cargo.lock", "qualification/src/lib.rs",
            "qualification/examples/verify_nom_swap.rs", "compatibility/fixtures/nom_terms_v1.json",
            "compatibility/fixtures/nom_completions_v1.json")
PRESERVED_REPORTS = ("docs/REVIEW_REPORT_TEMPLATE.md", "docs/OBSERVATION_REVIEW_REPORT_TEMPLATE.md",
                     "docs/WITNESS_REVIEW_REPORT_TEMPLATE.md")
SubjectError = source.SubjectError
encoded = source.encoded


def _generate(root, commit):
    source._hex(commit, 40)
    tree, rows, bodies = source._inventory(root, commit)
    if any(name not in bodies for name in REQUIRED + PRESERVED_REPORTS):
        raise SubjectError("complete NoM worker source inputs required")
    selected = [row["path"] for row in rows if row["path"].startswith(COPY_PREFIXES)]
    return dict(
        schema="ptlc-nom-worker-subject-v1", repository=source.REPOSITORY,
        commit=commit, tree=tree, file_count=len(rows), source_bytes=sum(row["bytes"] for row in rows), files=rows,
        worker=WORKER, worker_source="qualification/examples/verify_nom_swap.rs", build_source_paths=selected,
        preserved_reports=[dict(path=name, sha256=hashlib.sha256(bodies[name]).hexdigest())
                           for name in PRESERVED_REPORTS],
        boundary=dict(inventory="COMPLETE TRACKED SOURCE AT THE SELECTED IMMUTABLE COMMIT",
                      later_packaging="SEPARATE REVISION; NOT INCLUDED IN THE SOURCE SUBJECT",
                      dependency_acquisition="SEPARATE; NOT PERFORMED", installed_tools="NOT INCLUDED",
                      compiled_closure="NOT DETERMINED", loader_and_runtime="NOT AUTHENTICATED",
                      independent_assessment="NOT ASSESSED", application_and_core="NO-GO")), bodies


def generate(root, commit):
    return _generate(root, commit)[0]


def verify(root, commit, expected_sha256):
    source._hex(expected_sha256, 64)
    raw = source._regular(root / SUBJECT_PATH, source.MAX_MANIFEST_BYTES)
    if hashlib.sha256(raw).hexdigest() != expected_sha256 or source._index(root, SUBJECT_PATH) != raw:
        raise SubjectError("independently selected NoM source manifest differs")
    expected, bodies = _generate(root, commit)
    if raw != encoded(expected):
        raise SubjectError("NoM subject differs from canonical complete immutable source")
    for name in expected["build_source_paths"] + list(PRESERVED_REPORTS):
        if (source._regular(root / name, source.MAX_BLOB_BYTES) != bodies[name]
                or source._index(root, name) != bodies[name]):
            raise SubjectError("selected build input or preserved report differs")
    return expected, bodies


def selected_copy(workspace, manifest, bodies):
    for prefix in COPY_PREFIXES:
        expected = {name[len(prefix):]: dict(kind="regular", bytes=len(bodies[name]),
                                            sha256=hashlib.sha256(bodies[name]).hexdigest())
                    for name in manifest["build_source_paths"] if name.startswith(prefix)}
        content.tree_rows(workspace / prefix.rstrip("/"), expected)
    return len(manifest["build_source_paths"])


def prepare(root, destination, commit, manifest_sha256):
    manifest, bodies = verify(root, commit, manifest_sha256)
    content.directory(destination)
    status = destination.lstat()
    if status.st_uid != os.geteuid() or status.st_mode & 0o077 or any(destination.iterdir()):
        raise SubjectError("new private owned empty source directory required")
    for name in manifest["build_source_paths"]:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(bodies[name])
    selected_copy(destination, manifest, bodies)
    return manifest, bodies


def main():
    try:
        parser = source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--expect-commit", required=True)
        parser.add_argument("--expect-manifest-sha256")
        parser.add_argument("--emit", action="store_true")
        args = parser.parse_args()
        if args.emit:
            if args.expect_manifest_sha256 is not None:
                raise SubjectError("generation and selected comparison are separate")
            sys.stdout.buffer.write(encoded(generate(args.root.resolve(), args.expect_commit)))
        else:
            subject, _ = verify(args.root.resolve(), args.expect_commit, args.expect_manifest_sha256)
            print("PASS: complete NoM source subject: {} files; preserved reports unchanged; NOT ASSESSED".format(
                subject["file_count"]))
        return 0
    except (SubjectError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError, RecursionError):
        print("FAIL: NoM source subject inspection rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
