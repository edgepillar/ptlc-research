#!/usr/bin/env python3
"""Inspect a separately selected immutable witness source snapshot offline.

Complete source identity does not establish provenance, executable identity,
dependency availability, independent assessment or application authority.
The unchanged observation checker supplies the bounded local Git and tar reads.
"""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys

if __package__:
    from . import check_observation_subject as observation
else:
    import check_observation_subject as observation


SUBJECT_COMMIT = "bd4b4b523fb3453e2af191eb01973985d6431d66"
SUBJECT_PATH = "review/witness-subject.json"
OBSERVATION_SHA256 = "2f463071bc4f96ba1adaa8e8eb206d47e51845170ca2efe0f2b58182559afd6f"
CONSTRUCTION_REPORT_PATH = "docs/REVIEW_REPORT_TEMPLATE.md"
CONSTRUCTION_REPORT_SHA256 = "d0c0a66488aa4dde7ba830246a9eb92bbbed73104b94ce943df1ff6071b60d43"
OBSERVATION_REPORT_PATH = "docs/OBSERVATION_REVIEW_REPORT_TEMPLATE.md"
OBSERVATION_REPORT_SHA256 = "c70aff85784293f111d54e0b87f6306de6d10b08b84e632fc226cf9faedf438d"
SubjectError = observation.SubjectError
encoded = observation.encoded


@dataclass(frozen=True)
class Pins:
    commit: str
    observation_commit: str = observation.SUBJECT_COMMIT
    observation_sha256: str = OBSERVATION_SHA256
    baseline_commit: str = observation.BASELINE_COMMIT
    baseline_sha256: str = observation.BASELINE_SHA256
    construction_report_sha256: str = CONSTRUCTION_REPORT_SHA256
    observation_report_sha256: str = OBSERVATION_REPORT_SHA256


def generate(root, pins):
    """Inventory the whole tree; protect both prior subjects and blank reports."""
    prior = observation.generate(root, observation.Pins(
        pins.observation_commit, pins.baseline_commit, pins.baseline_sha256))
    tree, files, bodies = observation._inventory(root, pins.commit)
    protected = ((observation.ORIGINAL_PATH, pins.baseline_sha256),
                 (observation.SUBJECT_PATH, pins.observation_sha256),
                 (CONSTRUCTION_REPORT_PATH, pins.construction_report_sha256),
                 (OBSERVATION_REPORT_PATH, pins.observation_report_sha256))
    for name, digest in protected:
        observation._hex(digest, 64)
        raw = bodies.get(name)
        if raw is None or hashlib.sha256(raw).hexdigest() != digest:
            raise SubjectError("frozen prior artifact differs at selected source")
        for selected in (observation._regular(root / name, observation.MAX_MANIFEST_BYTES),
                         observation._index(root, name)):
            if selected != raw:
                raise SubjectError("frozen prior artifact differs in checkout or index")
    if bodies[observation.SUBJECT_PATH] != encoded(prior):
        raise SubjectError("prior observation inventory differs from immutable objects")
    baseline = {row["path"]: row for row in prior["files"]}
    counts = {"added": 0, "changed": 0, "unchanged": 0}
    for row in files:
        old = baseline.get(row["path"])
        if old is not None:
            old = {key: value for key, value in old.items() if key != "baseline_status"}
        status = "added" if old is None else "unchanged" if old == row else "changed"
        counts[status] += 1
        row["observation_status"] = status
    return {"schema": "ptlc-witness-review-subject-v1", "repository": observation.REPOSITORY,
            "commit": pins.commit, "tree": tree, "file_count": len(files), "files": files,
            "prior_subjects": {
                "construction": prior["baseline"],
                "observation": {"commit": pins.observation_commit, "tree": prior["tree"],
                    "file_count": prior["file_count"], "manifest_path": observation.SUBJECT_PATH,
                    "manifest_sha256": pins.observation_sha256}},
            "preserved_reports": [
                {"path": name, "sha256": digest} for name, digest in protected[2:]],
            "delta_from_observation": dict(counts, removed_paths=sorted(set(baseline) - set(bodies))),
            "boundary": {"included": "complete tracked source at the independently selected commit",
                "excluded": ["packaging added after the selected source commit",
                    "downloaded third-party source and installed dependency bytes",
                    "compiled executable bytes and toolchain installations",
                    "private cache, runtime state and hosted execution logs"],
                "assessment": "NOT ASSESSED"}}


def verify_manifest(root, pins, raw, expected_sha256):
    """Require independently selected digest and exact canonical object inventory."""
    observation._hex(expected_sha256, 64)
    observation._json(raw)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise SubjectError("selected witness manifest digest differs")
    expected = generate(root, pins)
    if raw != encoded(expected):
        raise SubjectError("witness manifest differs from canonical complete source")
    return expected


def verify_checkout(root, pins, expected_sha256):
    raw = observation._regular(root / SUBJECT_PATH, observation.MAX_MANIFEST_BYTES)
    expected = verify_manifest(root, pins, raw, expected_sha256)
    if observation._index(root, SUBJECT_PATH) != raw:
        raise SubjectError("indexed witness manifest differs")
    return expected


def main():
    try:
        parser = observation._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--expect-commit", required=True, metavar="COMMIT")
        parser.add_argument("--expect-manifest-sha256", metavar="SHA256")
        parser.add_argument("--emit", action="store_true")
        parser.add_argument("--archive", type=Path)
        arguments = parser.parse_args()
        root, pins = arguments.root.resolve(), Pins(arguments.expect_commit)
        if arguments.emit:
            if arguments.archive is not None or arguments.expect_manifest_sha256 is not None:
                raise SubjectError("manifest generation and selected inspection are separate")
            sys.stdout.buffer.write(encoded(generate(root, pins)))
            return 0
        expected = verify_checkout(root, pins, arguments.expect_manifest_sha256)
        if arguments.archive is not None:
            observation.verify_archive(arguments.archive, expected)
        print("PASS: complete witness subject: {} files; prior subjects: {} and {} files; NOT ASSESSED".format(
            expected["file_count"], expected["prior_subjects"]["observation"]["file_count"],
            expected["prior_subjects"]["construction"]["file_count"]))
        return 0
    except (SubjectError, OSError, UnicodeError, ValueError, RecursionError):
        print("FAIL: witness subject inspection rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
