"""Offline source-identity failures, not independent protocol assessment.

Synthetic Git objects use an explicitly assembled fixture identity and no refs,
hooks, installed identity or real network. The promisor negative control invokes
only a local marker helper. Source archives are inspected without extraction.
"""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_observation_subject as subject


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_observation_subject.py"


class ObservationSubjectTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-observation-subject-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "--quiet")
        self.old_files = {"docs/a.txt": ("100644", b"Public baseline.\n"),
                          "run.py": ("100755", b"Public executable fixture.\n")}
        self.baseline = self.commit(self.old_files)
        tree, files, _ = subject._inventory(self.root, self.baseline)
        self.original = subject.encoded({"schema": "ptlc-review-subject-v1", "repository": subject.REPOSITORY,
                                         "commit": self.baseline, "tree": tree, "file_count": len(files), "files": files})
        self.current_files = dict(self.old_files, **{"docs/a.txt": ("100644", b"Public changed source.\n"),
            "docs/extra.txt": ("100644", b"Public added source.\n"),
            subject.ORIGINAL_PATH: ("100644", self.original)})
        self.current = self.commit(self.current_files)
        self.pins = subject.Pins(self.current, self.baseline, hashlib.sha256(self.original).hexdigest())
        self.original_path = self.root / subject.ORIGINAL_PATH
        self.original_path.parent.mkdir()
        self.original_path.write_bytes(self.original)
        self.index(subject.ORIGINAL_PATH, self.original)
        self.expected = subject.generate(self.root, self.pins)
        self.raw = subject.encoded(self.expected)
        (self.root / subject.SUBJECT_PATH).write_bytes(self.raw)
        self.index(subject.SUBJECT_PATH, self.raw)

    @staticmethod
    def identity():
        return "fixture" + "@" + "example" + "." + "invalid"

    def git(self, *arguments, data=None, success=True):
        result = subprocess.run(["git", *arguments], cwd=self.root, env=self.environment,
                                input=data, capture_output=True, check=False, timeout=10)
        if success:
            self.assertEqual(result.returncode, 0, "synthetic Git fixture setup failed")
        return result

    def blob(self, raw):
        return self.git("hash-object", "-w", "--stdin", data=raw).stdout.decode("ascii").strip()

    def tree(self, files):
        def make(rows):
            children, leaves = {}, []
            for name, (mode, raw) in sorted(rows.items()):
                first, slash, rest = name.partition("/")
                if slash:
                    children.setdefault(first, {})[rest] = (mode, raw)
                else:
                    kind = "commit" if mode == "160000" else "blob"
                    oid = raw.decode("ascii") if kind == "commit" else self.blob(raw)
                    leaves.append((mode, kind, oid, first))
            leaves.extend(("040000", "tree", make(values), name) for name, values in children.items())
            wire = b"".join((mode + " " + kind + " " + oid + "\t" + name + "\0").encode("utf-8")
                            for mode, kind, oid, name in sorted(leaves, key=lambda row: row[3]))
            return self.git("mktree", "-z", data=wire).stdout.decode("ascii").strip()
        return make(files)

    def commit(self, files):
        tree = self.tree(files)
        owner = "Synthetic Fixture <" + self.identity() + "> 0 +0000"
        wire = ("tree " + tree + "\nauthor " + owner + "\ncommitter " + owner
                + "\n\nPublic synthetic source fixture.\n").encode("ascii")
        return self.git("hash-object", "-t", "commit", "-w", "--stdin", data=wire).stdout.decode("ascii").strip()

    def index(self, name, raw, mode="100644"):
        self.git("update-index", "--add", "--cacheinfo", mode, self.blob(raw), name)

    def reject(self, value):
        with self.assertRaises(subject.SubjectError) as error:
            subject.verify_manifest(self.root, self.pins, subject.encoded(value))
        self.assertNotIn(str(self.root), str(error.exception))

    def archive_members(self):
        result = []
        for row in self.expected["files"]:
            info = tarfile.TarInfo(row["path"])
            info.mode = 0o775 if row["mode"] == "100755" else 0o664
            raw = self.current_files[row["path"]][1]
            info.size = len(raw)
            result.append((info, raw))
        return result

    def archive(self, members):
        path = self.root / "synthetic-source.tar"
        with tarfile.open(path, "w") as handle:
            for member, raw in members:
                handle.addfile(member, io.BytesIO(raw) if member.isreg() else None)
        return path

    def reject_archive(self, members):
        with self.assertRaises(subject.SubjectError):
            subject.verify_archive(self.archive(members), self.expected)

    def test_complete_snapshot_and_baseline_delta_are_reproducible(self):
        self.assertEqual(subject.verify_checkout(self.root, self.pins), self.expected)
        self.assertEqual(subject.encoded(subject.generate(self.root, self.pins)), self.raw)
        self.assertEqual((self.expected["file_count"], self.expected["baseline"]["file_count"]), (4, 2))
        self.assertEqual(self.expected["delta"], {"added": 2, "changed": 1, "unchanged": 1, "removed_paths": []})

    def test_working_source_changes_do_not_redefine_pinned_objects(self):
        path = self.root / "docs/a.txt"
        path.parent.mkdir()
        path.write_bytes(b"Different public working file.\n")
        self.index("docs/a.txt", path.read_bytes())
        self.assertEqual(subject.generate(self.root, self.pins), self.expected)

    def test_declared_source_and_baseline_cannot_choose_trusted_pins(self):
        for field in ("commit", "tree", "baseline"):
            value = copy.deepcopy(self.expected)
            value[field] = self.baseline if field != "baseline" else dict(value[field], commit=self.current)
            with self.subTest(field=field):
                self.reject(value)
        for pin in ("HEAD", "0" * 40):
            with self.subTest(pin=pin), self.assertRaises(subject.SubjectError):
                subject.generate(self.root, subject.Pins(pin, self.baseline, self.pins.baseline_sha256))

    def test_missing_duplicate_and_extra_inventory_entries_are_rejected(self):
        for kind in ("missing", "duplicate", "extra"):
            value = copy.deepcopy(self.expected)
            if kind == "missing":
                value["files"].pop()
            else:
                row = copy.deepcopy(value["files"][0])
                if kind == "extra":
                    row["path"] = "synthetic-extra.txt"
                value["files"].append(row)
            value["file_count"] = len(value["files"])
            with self.subTest(kind=kind):
                self.reject(value)

    def test_digest_size_mode_and_status_tampering_is_rejected(self):
        for key, replacement in (("sha256", "0" * 64), ("git_blob", "0" * 40), ("bytes", 0),
                                 ("mode", "100755"), ("baseline_status", "unchanged")):
            value = copy.deepcopy(self.expected)
            row = next(row for row in value["files"] if row["path"] == "docs/a.txt")
            row[key] = replacement
            with self.subTest(key=key):
                self.reject(value)

    def test_delta_count_type_aliases_and_removed_paths_are_rejected(self):
        for key, replacement in (("added", 1), ("changed", True), ("unchanged", 2),
                                 ("removed_paths", ["docs/a.txt"])):
            value = copy.deepcopy(self.expected)
            value["delta"][key] = replacement
            if key == "changed":
                self.assertEqual(value, self.expected, "Python equality alone aliases true and one")
            with self.subTest(key=key):
                self.reject(value)

    def test_manifest_blob_and_plain_archive_size_bounds_are_enforced(self):
        with self.assertRaises(subject.SubjectError):
            subject.verify_manifest(self.root, self.pins, b" " * (subject.MAX_MANIFEST_BYTES + 1))
        path = self.root / subject.SUBJECT_PATH
        with path.open("wb") as handle:
            handle.truncate(subject.MAX_MANIFEST_BYTES + 1)
        with self.assertRaises(subject.SubjectError):
            subject.verify_checkout(self.root, self.pins)
        files = dict(self.current_files, **{"large.txt": ("100644", b"X" * (subject.MAX_BLOB_BYTES + 1))})
        pins = subject.Pins(self.commit(files), self.baseline, self.pins.baseline_sha256)
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, pins)
        archive = self.root / "oversize.tar"
        with archive.open("wb") as handle:
            handle.truncate(subject.MAX_ARCHIVE_BYTES + 1)
        with self.assertRaises(subject.SubjectError):
            subject.verify_archive(archive, self.expected)

    def test_unsafe_and_noncanonical_manifest_paths_are_rejected(self):
        for name in ("../synthetic", "/synthetic", "docs//a.txt", "./synthetic", "a\\b", "a:b", ".git/config"):
            value = copy.deepcopy(self.expected)
            value["files"][0]["path"] = name
            with self.subTest(name=name):
                self.reject(value)

    def test_duplicate_json_keys_noncanonical_encoding_and_extensions_are_rejected(self):
        variants = (b'{"files":[],"files":[]}', self.raw.rstrip(b"\n"), b"null", b"\xff",
                    subject.encoded(dict(self.expected, extra="unselected")))
        for index, raw in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(subject.SubjectError):
                subject.verify_manifest(self.root, self.pins, raw)

    def test_changed_original_working_manifest_is_rejected(self):
        self.original_path.write_bytes(b"{}\n")
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)

    def test_changed_original_index_is_rejected_behind_clean_working_manifest(self):
        self.index(subject.ORIGINAL_PATH, b"{}\n")
        self.assertEqual(self.original_path.read_bytes(), self.original)
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)

    def test_changed_original_at_source_is_rejected(self):
        files = dict(self.current_files, **{subject.ORIGINAL_PATH: ("100644", b"{}\n")})
        pins = subject.Pins(self.commit(files), self.baseline, self.pins.baseline_sha256)
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, pins)

    def test_changed_new_index_is_rejected_behind_clean_working_manifest(self):
        self.index(subject.SUBJECT_PATH, b"{}\n")
        self.assertEqual((self.root / subject.SUBJECT_PATH).read_bytes(), self.raw)
        with self.assertRaises(subject.SubjectError):
            subject.verify_checkout(self.root, self.pins)

    def test_changed_new_working_manifest_is_rejected_behind_clean_index(self):
        (self.root / subject.SUBJECT_PATH).write_bytes(b"{}\n")
        with self.assertRaises(subject.SubjectError):
            subject.verify_checkout(self.root, self.pins)

    def test_nonregular_and_unresolved_manifest_index_is_rejected(self):
        self.index(subject.ORIGINAL_PATH, self.original, mode="120000")
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)
        self.git("update-index", "--force-remove", subject.ORIGINAL_PATH)
        oid = self.blob(self.original)
        wire = ("100644 " + oid + " 1\t" + subject.ORIGINAL_PATH + "\n").encode("ascii")
        self.git("update-index", "--index-info", data=wire)
        with self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)

    def test_replacement_refs_cannot_substitute_the_subject(self):
        forged = self.commit(dict(self.current_files, **{"docs/extra.txt": ("100644", b"Public replacement.\n")}))
        self.git("replace", self.current, forged)
        self.assertEqual(subject.generate(self.root, self.pins), self.expected)

    def test_missing_promisor_blob_refuses_without_invoking_fetch_helper(self):
        helpers, marker = self.root / "helpers", self.root / "fetch-invoked"
        helpers.mkdir()
        helper = helpers / "git-remote-synthetic"
        helper.write_text("#!/usr/bin/env python3\nimport pathlib\npathlib.Path(" + repr(str(marker))
                          + ").write_bytes(b'invoked')\nraise SystemExit(1)\n", encoding="ascii")
        helper.chmod(0o700)
        self.environment["PATH"] = str(helpers) + os.pathsep + os.environ.get("PATH", "")
        for key, value in (("remote.synthetic.url", "synthetic::unused"), ("remote.synthetic.promisor", "true"),
                           ("remote.synthetic.partialclonefilter", "blob:none"), ("protocol.synthetic.allow", "always")):
            self.git("config", key, value)
        row = next(row for row in self.expected["files"] if row["path"] == "docs/extra.txt")
        object_id = row["git_blob"]
        (self.root / ".git/objects" / object_id[:2] / object_id[2:]).unlink()
        control = self.git("cat-file", "blob", object_id, success=False)
        self.assertNotEqual(control.returncode, 0)
        self.assertTrue(marker.exists(), "negative control must invoke the local promisor helper")
        marker.unlink()
        with patch.dict(os.environ, {"PATH": self.environment["PATH"]}), self.assertRaises(subject.SubjectError):
            subject.generate(self.root, self.pins)
        self.assertFalse(marker.exists(), "offline inspection must never invoke the helper")

    def test_nonregular_source_modes_are_rejected(self):
        for mode, raw in (("120000", b"synthetic-target"), ("160000", self.baseline.encode("ascii"))):
            pins = subject.Pins(self.commit(dict(self.current_files, **{"extra": (mode, raw)})),
                                self.baseline, self.pins.baseline_sha256)
            with self.subTest(mode=mode), self.assertRaises(subject.SubjectError):
                subject.generate(self.root, pins)

    def test_non_ascii_and_sensitive_source_bytes_are_rejected(self):
        for raw in (b"\xc3\xa9", self.identity().encode("ascii")):
            pins = subject.Pins(self.commit(dict(self.current_files, **{"extra.txt": ("100644", raw)})),
                                self.baseline, self.pins.baseline_sha256)
            with self.subTest(kind=raw[:1].hex()), self.assertRaises(subject.SubjectError):
                subject.generate(self.root, pins)

    def test_git_source_archive_passes_without_extraction(self):
        path = self.root / "git-source.tar"
        self.git("archive", "--format=tar", "--output=" + str(path), self.current)
        before = set(self.root.rglob("*"))
        subject.verify_archive(path, self.expected)
        self.assertEqual(set(self.root.rglob("*")), before)

    def test_archive_missing_extra_and_duplicate_files_are_rejected(self):
        for kind in ("missing", "extra", "duplicate"):
            members = self.archive_members()
            if kind == "missing":
                members.pop()
            elif kind == "duplicate":
                members.append(copy.deepcopy(members[0]))
            else:
                info = tarfile.TarInfo("extra.txt")
                members.append((info, b""))
            with self.subTest(kind=kind):
                self.reject_archive(members)

    def test_archive_unsafe_paths_links_and_special_modes_are_rejected(self):
        for kind in ("../synthetic", "/synthetic", "a//b", "a\\b", "symlink", "hardlink", "fifo", "setuid"):
            members = self.archive_members()
            info, raw = members[0]
            if kind == "setuid":
                info.mode |= 0o4000
            elif kind in {"symlink", "hardlink", "fifo"}:
                info.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[kind]
                info.linkname = "synthetic-target"
                info.size, raw = 0, b""
            else:
                info.name = kind
            members[0] = (info, raw)
            with self.subTest(kind=kind):
                self.reject_archive(members)

    def test_archive_payload_size_and_executable_class_are_rejected(self):
        for kind in ("payload", "size", "executable"):
            members = self.archive_members()
            info, raw = members[0]
            if kind == "payload":
                raw = b"X" + raw[1:]
            elif kind == "size":
                raw += b"X"
                info.size = len(raw)
            else:
                info.mode ^= 0o111
            members[0] = (info, raw)
            with self.subTest(kind=kind):
                self.reject_archive(members)

    def test_appended_archive_cannot_hide_behind_end_markers(self):
        first = self.archive(self.archive_members()).read_bytes()
        info = tarfile.TarInfo("extra.txt")
        second = self.archive([(info, b"")]).read_bytes()
        path = self.root / "appended.tar"
        path.write_bytes(first + second)
        with self.assertRaises(subject.SubjectError):
            subject.verify_archive(path, self.expected)

    def test_cli_requires_explicit_pin_and_redacts_input_paths(self):
        for extra in ([], ["--expect-commit", str(self.root)], ["--private-option", str(self.root)]):
            result = subprocess.run([sys.executable, "-B", str(CHECKER), "--root", str(self.root), *extra],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "FAIL: observation subject inspection rejected\n")
            self.assertEqual(result.stdout, "")
            self.assertNotIn(str(self.root), result.stderr)


class PinnedObservationSubjectTests(unittest.TestCase):
    def test_real_189_file_subject_preserves_the_119_file_baseline(self):
        value = subject.generate(ROOT, subject.Pins(subject.SUBJECT_COMMIT))
        self.assertEqual((value["file_count"], value["baseline"]["file_count"]), (189, 119))
        self.assertEqual(value["delta"], {"added": 70, "changed": 10, "unchanged": 109, "removed_paths": []})
        self.assertEqual(hashlib.sha256((ROOT / subject.ORIGINAL_PATH).read_bytes()).hexdigest(), subject.BASELINE_SHA256)

    def test_real_cli_emits_exact_source_without_changing_the_original_index(self):
        before = subject._index(ROOT, subject.ORIGINAL_PATH)
        result = subprocess.run([sys.executable, "-B", str(CHECKER), "--expect-commit", subject.SUBJECT_COMMIT,
                                 "--emit"], capture_output=True, timeout=20)
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(result.stdout, subject.encoded(subject.generate(ROOT, subject.Pins(subject.SUBJECT_COMMIT))))
        self.assertEqual(subject._index(ROOT, subject.ORIGINAL_PATH), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
