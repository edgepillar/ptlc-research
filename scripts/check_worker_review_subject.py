#!/usr/bin/env python3
"""Inspect an immutable worker-profile source packet without native work.

Complete source identity is not executed build evidence, producer provenance,
privacy, independent assessment or permission to use a private signer.
"""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys

if __package__:
    from . import check_witness_subject as witness
else:
    import check_witness_subject as witness


source = witness.observation
SUBJECT_COMMIT = "a80d14f1bc223e7d20901837fe84804fc7c1bce5"
SUBJECT_PATH = "review/worker-subject.json"
WITNESS_SHA256 = "0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f"
WITNESS_REPORT_PATH = "docs/WITNESS_REVIEW_REPORT_TEMPLATE.md"
WITNESS_REPORT_SHA256 = "16d495877bfa9c7a58ddd08c3e2ce9a99da4e94fb49bc18f7550ada9eefa65f7"
SubjectError = source.SubjectError
encoded = source.encoded


@dataclass(frozen=True)
class Pins:
    commit: str
    witness_pins: witness.Pins = witness.Pins(witness.SUBJECT_COMMIT)
    witness_sha256: str = WITNESS_SHA256
    witness_report_sha256: str = WITNESS_REPORT_SHA256


def generate(root, pins):
    """Inventory all selected objects and preserve three separate old scopes."""
    source._hex(pins.commit, 40)
    source._hex(pins.witness_sha256, 64)
    source._hex(pins.witness_report_sha256, 64)
    prior = witness.generate(root, pins.witness_pins)
    tree, files, bodies = source._inventory(root, pins.commit)
    protected = (
        (source.ORIGINAL_PATH, pins.witness_pins.baseline_sha256),
        (source.SUBJECT_PATH, pins.witness_pins.observation_sha256),
        (witness.SUBJECT_PATH, pins.witness_sha256),
        (witness.CONSTRUCTION_REPORT_PATH, pins.witness_pins.construction_report_sha256),
        (witness.OBSERVATION_REPORT_PATH, pins.witness_pins.observation_report_sha256),
        (WITNESS_REPORT_PATH, pins.witness_report_sha256),
    )
    for name, digest in protected:
        raw = bodies.get(name)
        if raw is None or hashlib.sha256(raw).hexdigest() != digest:
            raise SubjectError("frozen prior artifact differs at worker subject")
        for selected in (source._regular(root / name, source.MAX_MANIFEST_BYTES),
                         source._index(root, name)):
            if selected != raw:
                raise SubjectError("frozen prior artifact differs in checkout or index")
    if bodies[witness.SUBJECT_PATH] != encoded(prior):
        raise SubjectError("prior witness inventory differs from immutable objects")
    baseline = {row["path"]: row for row in prior["files"]}
    counts = {"added": 0, "changed": 0, "unchanged": 0}
    for row in files:
        old = baseline.get(row["path"])
        if old is not None:
            old = {key: value for key, value in old.items() if key != "observation_status"}
        status = "added" if old is None else "unchanged" if old == row else "changed"
        counts[status] += 1
        row["witness_status"] = status
    return {
        "schema": "ptlc-worker-review-subject-v1", "repository": source.REPOSITORY,
        "commit": pins.commit, "tree": tree, "file_count": len(files),
        "source_bytes": sum(row["bytes"] for row in files), "files": files,
        "prior_subjects": dict(prior["prior_subjects"], witness={
            "commit": pins.witness_pins.commit, "tree": prior["tree"],
            "file_count": prior["file_count"], "manifest_path": witness.SUBJECT_PATH,
            "manifest_sha256": pins.witness_sha256}),
        "preserved_reports": [{"path": name, "sha256": digest}
                              for name, digest in protected[3:]],
        "delta_from_witness": dict(counts, removed_paths=sorted(set(baseline) - set(bodies))),
        "boundary": {
            "included": "complete tracked source at the independently selected commit",
            "excluded": ["later worker-review packaging and its checker",
                         "downloaded source, installed tools and dependency bytes",
                         "compiled artifacts, private selections, carriers and runtime state",
                         "local and hosted execution logs"],
            "assessment": "NOT ASSESSED", "privacy": "NOT ASSESSED",
            "generator_origin": "NOT AUTHENTICATED",
            "source_to_worker": "NOT VERIFIED", "reproducibility": "NOT VERIFIED",
            "application_and_core": "NO-GO",
        },
    }


def verify_manifest(root, pins, raw, expected_sha256):
    """Use externally selected pins; received metadata cannot reselect them."""
    source._hex(expected_sha256, 64)
    source._json(raw)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise SubjectError("selected worker manifest digest differs")
    expected = generate(root, pins)
    if raw != encoded(expected):
        raise SubjectError("worker inventory differs from canonical complete source")
    return expected


def verify_checkout(root, pins, expected_sha256):
    raw = source._regular(root / SUBJECT_PATH, source.MAX_MANIFEST_BYTES)
    expected = verify_manifest(root, pins, raw, expected_sha256)
    if source._index(root, SUBJECT_PATH) != raw:
        raise SubjectError("indexed worker manifest differs")
    return expected


def main():
    try:
        parser = source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--expect-commit", required=True, metavar="COMMIT")
        parser.add_argument("--expect-manifest-sha256", metavar="SHA256")
        parser.add_argument("--emit", action="store_true")
        parser.add_argument("--archive", type=Path)
        arguments = parser.parse_args()
        root, pins = arguments.root.resolve(), Pins(arguments.expect_commit)
        if arguments.emit:
            if arguments.archive is not None or arguments.expect_manifest_sha256 is not None:
                raise SubjectError("generation and selected inspection are separate")
            sys.stdout.buffer.write(encoded(generate(root, pins)))
            return 0
        expected = verify_checkout(root, pins, arguments.expect_manifest_sha256)
        if arguments.archive is not None:
            source.verify_archive(arguments.archive, expected)
        print("PASS: complete worker subject: {} files; three prior subjects and reports preserved; NOT ASSESSED".format(
            expected["file_count"]))
        return 0
    except (SubjectError, OSError, UnicodeError, ValueError, RecursionError):
        print("FAIL: worker subject inspection rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
