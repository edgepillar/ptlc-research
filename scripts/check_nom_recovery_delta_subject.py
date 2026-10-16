#!/usr/bin/env python3
"""Identify the full immutable NoM recovery delta for a separate assessment.

This offline reader identifies repository bytes. It performs no native build,
artifact execution, source acquisition or independent construction assessment.
"""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys

if __package__:
    from . import check_nom_worker_subject as nom
    from . import check_observation_subject as source
else:
    import check_nom_worker_subject as nom
    import check_observation_subject as source


SUBJECT_COMMIT = "a98dfe7b2fbfc8f8c2b378b34a524e1c1cdff8e7"
SUBJECT_PATH = "review/nom-recovery-delta-subject.json"
BASELINE_SHA256 = "59d9b134d4be55f3dc98797529aff86d121fdce3d0e2ddce8dfd7b9c171cf179"
NOM_REPORT_PATH = "docs/NOM_WORKER_REVIEW_REPORT_TEMPLATE.md"
NOM_REPORT_SHA256 = "c55d9384034d88858a2155b4fe4366f2f54eef6cb3317db7db631b5825e814d0"
PRESERVED_BASELINE = (
    "review/native-signer-subject.json", "review/observation-subject.json",
    "review/signer-nonce-handoff.json", "review/subject.json",
    "review/witness-subject.json", "review/worker-subject.json",
) + nom.PRESERVED_REPORTS
MAX_BLOB_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 40 * 1024 * 1024
MAX_TREE_BYTES = 1024 * 1024
SubjectError = source.SubjectError
encoded = source.encoded


@dataclass(frozen=True)
class Pins:
    commit: str
    baseline_commit: str = nom.SUBJECT_COMMIT
    baseline_sha256: str = BASELINE_SHA256
    nom_report_sha256: str = NOM_REPORT_SHA256


def _inventory(root, commit):
    """Use distinct finite bounds; do not change any older reader's limits."""
    source._hex(commit, 40)
    if source._git(root, "cat-file", "-t", commit).strip() != b"commit":
        raise SubjectError("immutable commit object required")
    tree = source._git(root, "rev-parse", "--verify", commit + "^{tree}").decode("ascii").strip()
    source._hex(tree, 40)
    raw_tree = source._git(root, "ls-tree", "-r", "-l", "-z", commit)
    if len(raw_tree) > MAX_TREE_BYTES:
        raise SubjectError("source tree listing exceeds bound")
    entries = [entry for entry in raw_tree.split(b"\0") if entry]
    if not 0 < len(entries) <= source.MAX_FILES:
        raise SubjectError("source file count exceeds bound")
    selections, names, total = [], set(), 0
    for entry in entries:
        try:
            header, raw_name = entry.split(b"\t", 1)
            mode, kind, oid, length = header.decode("ascii").split()
            name = source._path(raw_name.decode("ascii"))
        except (UnicodeError, ValueError):
            raise SubjectError("regular ASCII source entry required") from None
        source._hex(oid, 40)
        if mode not in {"100644", "100755"} or kind != "blob" or name.casefold() in names:
            raise SubjectError("unique regular source entries required")
        if not length.isdecimal() or not 0 <= int(length) <= MAX_BLOB_BYTES:
            raise SubjectError("source blob exceeds selected bound")
        total += int(length)
        if total > MAX_SOURCE_BYTES:
            raise SubjectError("complete source exceeds selected bound")
        names.add(name.casefold())
        selections.append((name, mode, oid, int(length)))
    rows, bodies = [], {}
    for name, mode, oid, length in selections:
        raw = source._git(root, "cat-file", "blob", oid)
        actual_oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        if len(raw) != length or actual_oid != oid:
            raise SubjectError("source blob size or Git identity differs")
        try:
            text = raw.decode("ascii")
        except UnicodeError:
            raise SubjectError("ASCII source required") from None
        if any(pattern.search(text) for _, pattern in source.PATTERNS):
            raise SubjectError("source fails limited disclosure check")
        rows.append(dict(path=name, mode=mode, git_blob=oid, bytes=length,
                         sha256=hashlib.sha256(raw).hexdigest()))
        bodies[name] = raw
    return tree, sorted(rows, key=lambda row: row["path"]), bodies


def _generate(root, pins):
    source._hex(pins.baseline_commit, 40)
    source._hex(pins.baseline_sha256, 64)
    source._hex(pins.nom_report_sha256, 64)
    prior = nom.generate(root, pins.baseline_commit)
    tree, rows, bodies = _inventory(root, pins.commit)
    prior_raw = bodies.get(nom.SUBJECT_PATH)
    if (prior_raw is None or hashlib.sha256(prior_raw).hexdigest() != pins.baseline_sha256
            or prior_raw != encoded(prior)):
        raise SubjectError("prior NoM source inventory differs from immutable objects")
    baseline = {row["path"]: row for row in prior["files"]}
    current = {row["path"]: row for row in rows}
    protected = []
    for name in PRESERVED_BASELINE:
        if name not in baseline or current.get(name) != baseline[name]:
            raise SubjectError("earlier review artifact changed at selected source")
        protected.append(dict(path=name, sha256=baseline[name]["sha256"]))
    if (NOM_REPORT_PATH not in bodies
            or hashlib.sha256(bodies[NOM_REPORT_PATH]).hexdigest() != pins.nom_report_sha256):
        raise SubjectError("separate unfilled NoM report changed at selected source")
    protected += [dict(path=nom.SUBJECT_PATH, sha256=pins.baseline_sha256),
                  dict(path=NOM_REPORT_PATH, sha256=pins.nom_report_sha256)]
    for item in protected:
        name = item["path"]
        if (source._regular(root / name, source.MAX_MANIFEST_BYTES) != bodies[name]
                or source._index(root, name) != bodies[name]):
            raise SubjectError("protected review artifact differs in checkout or index")
    counts = dict(added=0, changed=0, unchanged=0)
    for row in rows:
        old = baseline.get(row["path"])
        status = "added" if old is None else "unchanged" if old == row else "changed"
        counts[status] += 1
        row["nom_worker_status"] = status
    return dict(
        schema="ptlc-nom-recovery-delta-subject-v1", repository=source.REPOSITORY,
        commit=pins.commit, tree=tree, file_count=len(rows),
        source_bytes=sum(row["bytes"] for row in rows), files=rows,
        baseline=dict(commit=pins.baseline_commit, tree=prior["tree"], file_count=prior["file_count"],
                      manifest_path=nom.SUBJECT_PATH, manifest_sha256=pins.baseline_sha256),
        delta=dict(counts, removed_paths=sorted(set(baseline) - set(current))),
        preserved_artifacts=protected,
        limits=dict(blob_bytes=MAX_BLOB_BYTES, source_bytes=MAX_SOURCE_BYTES,
                    manifest_bytes=source.MAX_MANIFEST_BYTES, files=source.MAX_FILES),
        boundary=dict(inventory="COMPLETE TRACKED SOURCE AT THE SELECTED IMMUTABLE COMMIT",
                      later_packaging="SEPARATE REVISION AND ASSESSMENT; NOT INCLUDED",
                      dependencies_and_tools="EXTERNAL BYTES AND COMPILED CLOSURE NOT INCLUDED",
                      hosted_artifacts="SEPARATE ORIGINAL EVIDENCE; NOT INCLUDED",
                      independent_assessment="NOT ASSESSED", service_gates="AS-1 THROUGH AS-7 UNFILLED",
                      application_and_core="NO-GO", recovery_action="NONE")), bodies


def generate(root, pins):
    return _generate(root, pins)[0]


def verify_manifest(root, pins, raw, expected_sha256):
    source._hex(expected_sha256, 64)
    source._json(raw)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise SubjectError("independently selected manifest digest differs")
    expected, _ = _generate(root, pins)
    if raw != encoded(expected):
        raise SubjectError("manifest differs from canonical complete source and delta")
    return expected


def verify(root, pins, expected_sha256):
    raw = source._regular(root / SUBJECT_PATH, source.MAX_MANIFEST_BYTES)
    expected = verify_manifest(root, pins, raw, expected_sha256)
    if source._index(root, SUBJECT_PATH) != raw:
        raise SubjectError("indexed delta manifest differs")
    return expected


def main():
    try:
        parser = source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--expect-commit", required=True)
        parser.add_argument("--expect-manifest-sha256")
        parser.add_argument("--emit", action="store_true")
        args = parser.parse_args()
        root, pins = args.root.resolve(), Pins(args.expect_commit)
        if args.emit:
            if args.expect_manifest_sha256 is not None:
                raise SubjectError("generation and independently selected comparison are separate")
            sys.stdout.buffer.write(encoded(generate(root, pins)))
        else:
            subject = verify(root, pins, args.expect_manifest_sha256)
            print("PASS: complete NoM delta subject: {} files; prior subject: {} files; NOT ASSESSED".format(
                subject["file_count"], subject["baseline"]["file_count"]))
        return 0
    except (SubjectError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError, RecursionError):
        print("FAIL: NoM recovery delta source inspection rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
